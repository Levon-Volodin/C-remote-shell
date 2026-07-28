/*
 * server/server.h  –  Socket setup and client accept
 * ====================================================
 * Declares server_listen() which creates the listening socket, binds,
 * and blocks on accept() until a client connects.
 */

#pragma once
#ifndef SERVER_SERVER_H
#define SERVER_SERVER_H

#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * server_listen
 * -------------
 * Creates a TCP socket, sets SO_REUSEADDR, binds to LISTEN_ADDR:LISTEN_PORT,
 * and blocks until exactly one client connects.
 *
 * Parameters
 *   pListenFd   – receives the listening socket fd (caller closes on exit)
 *   pClientFd   – receives the accepted client socket fd
 *   pClientAddr – populated with the client's address by accept()
 *
 * Returns  0 on success, non-zero on any socket/bind/accept error.
 * On error, any opened fd is closed before returning.
 */
int server_listen(int *pListenFd, int *pClientFd,
                  struct sockaddr_in *pClientAddr);

#ifdef __cplusplus
}
#endif
#endif /* SERVER_SERVER_H */
