/*
 * server/main.c  –  Entry point for the operator console (Linux / macOS)
 * ========================================================================
 * Ties together server_listen() and run_prompt_loop():
 *   1. Open the listening socket and accept one client.
 *   2. Print the connected client's IP.
 *   3. Run the interactive prompt loop.
 *   4. Close both sockets cleanly on exit.
 *
 * Fix applied vs. original serverShell.c
 * ----------------------------------------
 *  FIX: The listening socket was never closed before the process exited —
 *       the OS would reclaim it, but SO_REUSEADDR relies on the socket
 *       being properly closed to work correctly on the next restart.
 *       Both listenFd and clientFd are now closed before return.
 */

#include "server.h"
#include "prompt.h"
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main(void)
{
    /* Ignore SIGPIPE so that write() to a disconnected agent socket returns
     * EPIPE rather than terminating the server process with no diagnostic. */
    signal(SIGPIPE, SIG_IGN);

    int                listenFd = -1;
    int                clientFd = -1;
    struct sockaddr_in clientAddr;

    if (server_listen(&listenFd, &clientFd, &clientAddr) != 0)
        return 1;

    printf("[+] Connection from %s\n", inet_ntoa(clientAddr.sin_addr));

    run_prompt_loop(clientFd, &clientAddr);

    /* FIX: always close both sockets */
    close(clientFd);
    close(listenFd);
    return 0;
}
