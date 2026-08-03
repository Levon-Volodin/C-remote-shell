/*
 * server/config.h  –  Server-side configuration
 * ===============================================
 * All tuneable values for the operator console server live here.
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  DEPRECATION WARNING — THIS SERVER IS NOT COMPATIBLE WITH THE C AGENT    ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║  The C agent (client/) implements a 4-layer security stack:              ║
 * ║    Layer 1  SChannel TLS 1.2/1.3                                         ║
 * ║    Layer 2  HMAC-SHA256 challenge/response authentication                ║
 * ║    Layer 3  Protocol v2 magic-byte negotiation                           ║
 * ║    Layer 4  AES-256-GCM framed messages with replay protection           ║
 * ║                                                                          ║
 * ║  THIS server speaks raw plaintext TCP with no authentication.            ║
 * ║  It CANNOT interoperate with the C agent — the agent's TLS handshake     ║
 * ║  will fail immediately because this server sends no TLS ServerHello.     ║
 * ║                                                                          ║
 * ║  Use the Python C2 (megaploit/server/) for ALL production operation.     ║
 * ║  This server exists for historical reference only and is DISABLED by     ║
 * ║  default.  Define LEGACY_C_SERVER_ACKNOWLEDGED to compile it.            ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

#pragma once
#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

/* ── Deprecation gate ────────────────────────────────────────────────────── */
/*
 * This C server is protocol-incompatible with the C agent.  It exists only
 * as a historical reference.  You MUST pass
 *   -DLEGACY_C_SERVER_ACKNOWLEDGED
 * on the compiler command line to build it.  If you are trying to operate
 * the C agent, use the Python C2:  python server.py
 */
#ifndef LEGACY_C_SERVER_ACKNOWLEDGED
#  error "C-remote-shell/server/ is DEPRECATED and incompatible with the C agent.  " \
         "The C agent speaks TLS + HMAC-SHA256 + AES-256-GCM; this server speaks raw TCP.  " \
         "Use the Python C2 (megaploit/server/) instead.  " \
         "If you know what you are doing and need to build for historical reference, " \
         "add -DLEGACY_C_SERVER_ACKNOWLEDGED to the compiler command line."
#endif

#include <netinet/in.h>

/* ── Listen address / port ───────────────────────────────────────────────── */
/* May be overridden at compile time: gcc -DLISTEN_PORT=4444 ...              */
#ifndef LISTEN_PORT
#  define LISTEN_PORT   50005     /* must match C2_PORT in client/config.h    */
#endif
#define LISTEN_ADDR   INADDR_ANY  /* 0.0.0.0 – accept on all interfaces       */

/* ── I/O buffer sizes ────────────────────────────────────────────────────── */
#define CMD_BUF_SIZE   1024       /* max length of a command read from stdin  */
#define RESP_BUF_SIZE  18384      /* max response received from the client    */

#endif /* SERVER_CONFIG_H */
