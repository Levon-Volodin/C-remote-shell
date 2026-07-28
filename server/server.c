/*
 * server/server.c  –  Socket setup and client accept implementation
 * ==================================================================
 * Implements server_listen() declared in server.h.
 *
 * Fixes applied vs. original serverShell.c
 * -----------------------------------------
 *  FIX 1: sAddress.sin_addr.s_addr was never initialised — bind() silently
 *          fell back to INADDR_ANY via uninitialised memory.  The assignment
 *          was mistakenly placed on cAddress (the accept() output struct).
 *          Now explicitly set on sAddress with htonl(LISTEN_ADDR).
 *
 *  FIX 2: socket() and accept() return values were unchecked.
 *         Both now compared to -1 with a perror() + cleanup on failure.
 */

#include "server.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int server_listen(int *pListenFd, int *pClientFd,
                  struct sockaddr_in *pClientAddr)
{
    int optval = 1;

    /* FIX 2: check socket() result */
    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0) {
        perror("socket");
        return 1;
    }

    if (setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR,
                   &optval, sizeof(optval)) < 0) {
        perror("setsockopt");
        close(listenFd);
        return 1;
    }

    /* FIX 1: assign the bind address on sAddress, not cAddress */
    struct sockaddr_in sAddress;
    memset(&sAddress, 0, sizeof(sAddress));
    sAddress.sin_family      = AF_INET;
    sAddress.sin_addr.s_addr = htonl(LISTEN_ADDR);  /* was on cAddress — wrong */
    sAddress.sin_port        = htons(LISTEN_PORT);

    if (bind(listenFd, (struct sockaddr *)&sAddress, sizeof(sAddress)) != 0) {
        perror("bind");
        close(listenFd);
        return 1;
    }

    listen(listenFd, 5);
    printf("[*] Listening on port %d ...\n", LISTEN_PORT);

    socklen_t cLen = sizeof(*pClientAddr);
    int clientFd = accept(listenFd,
                          (struct sockaddr *)pClientAddr, &cLen);
    /* FIX 2: check accept() result */
    if (clientFd < 0) {
        perror("accept");
        close(listenFd);
        return 1;
    }

    *pListenFd = listenFd;
    *pClientFd = clientFd;
    return 0;
}
