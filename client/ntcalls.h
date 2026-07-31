/*
 * client/ntcalls.h  –  NT syscall declarations for the remote shell client
 * =========================================================================
 * Declares the undocumented / semi-documented NTDLL functions used by the
 * client, and exports the two functions that load and verify them.
 *
 * All pointers start as NULL and are filled by ntcalls_load().
 * ntcalls_verify() confirms every pointer resolved correctly and attempts
 * to acquire SeShutdownPrivilege.
 */

#pragma once
#ifndef CLIENT_NTCALLS_H
#define CLIENT_NTCALLS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── SHUTDOWN_ACTION enum ───────────────────────────────────────────────── */
/* Required by NtShutdownSystem; not in the public SDK headers.              */
typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;

/* ── NT function pointer declarations ──────────────────────────────────── */
/* Defined (as globals) in ntcalls.c                                        */

/*
 * RtlAdjustPrivilege
 * ------------------
 * Enables or disables a privilege in the current process/thread token.
 * Privilege 19 = SE_SHUTDOWN_PRIVILEGE.
 * Returns STATUS_SUCCESS (0) on success.
 */
extern NTSTATUS (NTAPI *RtlAdjustPrivilege)(
    ULONG    ulPrivilege,
    BOOLEAN  bEnable,
    BOOLEAN  bCurrentThread,
    PBOOLEAN pbPreviousValue);

/*
 * NtShutdownSystem
 * ----------------
 * Triggers an OS shutdown.  Pass ShutdownPowerOff for a hard power-off.
 * Requires SeShutdownPrivilege.
 */
extern NTSTATUS (NTAPI *NtShutdownSystem)(
    _In_ SHUTDOWN_ACTION Action);

/*
 * NtSetSystemPowerState
 * ---------------------
 * Low-level power-state transition; used with PowerActionShutdownOff for a
 * forced hardware power-off that bypasses shutdown callbacks.
 */
extern NTSTATUS (NTAPI *NtSetSystemPowerState)(
    _In_ POWER_ACTION  SystemAction,
    _In_ SYSTEM_POWER_STATE MinSystemState,
    _In_ ULONG         Flags);

/*
 * NtRaiseHardError
 * ----------------
 * Raises a kernel-mode hard error.  When called with ResponseOption = 6
 * (OptionShutdownSystem) and STATUS_ASSERTION_FAILURE, it triggers a BSOD.
 */
extern NTSTATUS (NTAPI *NtRaiseHardError)(
    NTSTATUS   ErrorStatus,
    ULONG      NumberOfParameters,
    ULONG      UnicodeStringParameterMask OPTIONAL,
    PULONG_PTR Parameters,
    ULONG      ResponseOption,
    PULONG     Response);

/* Accumulated ULONG to receive NtRaiseHardError's response field */
extern ULONG g_hardErrorResponse;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * ntcalls_load
 * ------------
 * Resolves all NT function pointers from ntdll.dll via GetProcAddress.
 * Returns TRUE on success, FALSE if ntdll could not be loaded or any
 * pointer failed to resolve.
 * Must be called before ntcalls_verify() or any of the NT functions.
 */
BOOL ntcalls_load(void);

/*
 * ntcalls_verify
 * --------------
 * Checks that all four NT function pointers are non-NULL, then attempts
 * to acquire SeShutdownPrivilege (non-fatal if it fails — the shell will
 * still work; only forceOff/blueScreen require it at call-time).
 *
 * Returns TRUE if all pointers resolved, FALSE if any is missing.
 */
BOOL ntcalls_verify(void);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_NTCALLS_H */
