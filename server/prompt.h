/*
 * server/prompt.h  –  Operator prompt loop declaration
 * ======================================================
 * Declares run_prompt_loop() which prints a prompt, reads commands
 * from stdin, sends them to the remote client, and prints responses.
 */

#pragma once
#ifndef SERVER_PROMPT_H
#define SERVER_PROMPT_H

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * run_prompt_loop
 * ---------------
 * Enters the interactive command loop for a single connected client.
 *
 * Parameters
 *   clientFd    – connected client socket (already accepted)
 *   clientAddr  – client's sockaddr_in (used to print the IP in the prompt)
 *
 * Returns when the operator sends "q", "blueScreen()", or "forceOff()",
 * or when a socket error occurs.
 */
void run_prompt_loop(int clientFd, const struct sockaddr_in *clientAddr);

#ifdef __cplusplus
}
#endif
#endif /* SERVER_PROMPT_H */
