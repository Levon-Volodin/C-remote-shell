/*
 * client/obf.h  –  Compile-time XOR string obfuscation
 * =====================================================
 *
 * Approach
 * --------
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

#endif /* CLIENT_OBF_H */
