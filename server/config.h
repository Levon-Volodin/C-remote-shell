/*
 * server/config.h  –  Server-side configuration
 * ===============================================
 * All tuneable values for the operator console server live here.
 */

#pragma once
#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

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
