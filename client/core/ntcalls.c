/*
 * client/ntcalls.c  –  NT syscall loader and privilege check
 * ===========================================================
 * Implements ntcalls_load() and ntcalls_verify() declared in ntcalls.h.
 * All NT function pointer globals are defined here.
 */

#include "ntcalls.h"

/* ── Global NT function pointers (all start NULL) ───────────────────────── */
NTSTATUS (NTAPI *RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN) = NULL;
NTSTATUS (NTAPI *NtShutdownSystem)(_In_ SHUTDOWN_ACTION)                = NULL;
NTSTATUS (NTAPI *NtSetSystemPowerState)(_In_ POWER_ACTION,
                                         _In_ SYSTEM_POWER_STATE,
                                         _In_ ULONG)                    = NULL;
NTSTATUS (NTAPI *NtRaiseHardError)(NTSTATUS, ULONG, ULONG,
                                    PULONG_PTR, ULONG, PULONG)          = NULL;

ULONG g_hardErrorResponse = 0;


/* ── ntcalls_load ───────────────────────────────────────────────────────── */

BOOL ntcalls_load(void)
{
    /* ntdll is always already mapped — GetModuleHandle avoids bumping the
     * reference count (no matching FreeLibrary needed).                   */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    RtlAdjustPrivilege    = (PVOID)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    NtShutdownSystem      = (PVOID)GetProcAddress(hNtdll, "NtShutdownSystem");
    NtSetSystemPowerState = (PVOID)GetProcAddress(hNtdll, "NtSetSystemPowerState");
    NtRaiseHardError      = (PVOID)GetProcAddress(hNtdll, "NtRaiseHardError");

    if (!RtlAdjustPrivilege || !NtShutdownSystem ||
        !NtSetSystemPowerState || !NtRaiseHardError)
        return FALSE;

    return TRUE;
}


/* ── ntcalls_verify ─────────────────────────────────────────────────────── */

BOOL ntcalls_verify(void)
{
    /* All four pointers must have resolved */
    if (!RtlAdjustPrivilege)    return FALSE;
    if (!NtShutdownSystem)      return FALSE;
    if (!NtSetSystemPowerState) return FALSE;
    if (!NtRaiseHardError)      return FALSE;

    /*
     * Attempt to acquire SeShutdownPrivilege (privilege index 19).
     * This is non-fatal: if we don't have it, forceOff() and blueScreen()
     * will simply fail silently at call-time.
     * NOTE: RtlAdjustPrivilege returns STATUS_SUCCESS (0) on success.
     *       The original code checked `if (NtReceiver) return;` which
     *       exited on SUCCESS and continued on FAILURE — that was backwards.
     */
    BOOLEAN  prevState = FALSE;
    NTSTATUS ns = RtlAdjustPrivilege(19, TRUE, FALSE, &prevState);
    (void)ns; /* non-fatal; do not gate the return value on this */

    return TRUE;
}
