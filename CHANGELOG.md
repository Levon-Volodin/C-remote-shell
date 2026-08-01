# C-remote-shell — Changelog

---

## [Unreleased] — 2026-08-01

### Added — Runtime debugger (`client/debug/`)

A complete structured runtime debugger that is **fully compiled out in release
builds** (`-DAGENT_DEBUG` not defined = zero overhead, zero extra strings, zero
extra imports in the final binary).

**New files:**
- `client/debug/agent_debug.h` — public API with no-op stubs for release
- `client/debug/agent_debug.c` — implementation compiled only when `AGENT_DEBUG` is defined

**Build:**
```bash
mingw32-make C2_IP=127.0.0.1 C2_PORT=4444 DBG=1
```
`DBG=1` automatically implies `DISABLE_AUTO_MIGRATE`, `DISABLE_SANDBOX_CHECK`,
and `DISABLE_EVASION` so debug runs are instant and stay in the original process.

**Output destinations (simultaneous):**
1. `C:\Windows\Temp\megaploit_agent_debug.log` — timestamped, appended across runs
2. `OutputDebugStringA` with `[MAGENT]` prefix — readable live in x64dbg / WinDbg / DbgView

**Subsystems instrumented:**

| Tag | What is logged |
|---|---|
| `INIT  ` | PID, image path, CWD, integrity level (RID), username, OS build via `RtlGetVersion` |
| `NTCALL` | `ntcalls_load()` — ntdll base address, per-pointer resolved VA; `ntcalls_verify()` — `RtlAdjustPrivilege` NTSTATUS; full per-bit decode of both return values |
| `SCALL ` | All 11 SSNs and both gadget addresses after `sc_init()` completes |
| `INJECT` | `inject_init()` return value with pass/fail reason |
| `SPOOF ` | `spoof_peb()`, `spoof_kernel_image()`, `unlink_self_from_ldr()` entry |
| `MIGRAT` | `auto_migrate()` target PID, path, success/failure |
| `SNDBOX` | `sandbox_check()` overall result + per-check detail: RAM, CPUs, hypervisor bit, RDTSC delta |
| `EVASN ` | Before/after each of `unhook_ntdll()`, `etw_patch()`, `amsi_patch()` |
| `KEY   ` | `load_secret_key()` path and decode result (key bytes never logged) |
| `NET   ` | `WSAStartup`, `socket()`, `InetPtonA`, `connect()` retries with `WSAGetLastError()` |
| `SOCK  ` | `setsockopt()` return codes for `SO_RCVTIMEO` and `SO_KEEPALIVE` |
| `TLS   ` | `tls_connect()` result + `lastErr` with human-readable decode of all 5 `TLS_ERR_*` codes |
| `SHELL ` | `shell_run()` session entry and return |
| `THREAD` | `_agent_thread` lifecycle with PID and TID (post-migration code path) |

---

### Fixed — `peb_get_export()` always returned NULL on every Windows build

**File:** `client/evasion/peb_walk.c`

**Root cause:** The skip-scan algorithm in `peb_get_export()` used the condition
`if (h < nameHash) seg_start = i` to navigate the export name table. This
assumes hash values are monotonically ordered relative to export name position.
They are not — the hash is a seeded non-linear transform, so hash order is
essentially random relative to table order. The skip loop consistently
miscalculated `seg_start`/`seg_end`, causing Phase 2 to scan the wrong segment
and miss every single target.

**Symptom:** `ntcalls_load()` returned `0x0F` (all four exports missing) on
every run despite ntdll being correctly found in the PEB. All four NT function
pointers were NULL. `forceOff()` and `blueScreen()` were silently disabled.
The same bug affected every other call to `peb_get_export()` throughout the agent.

**Fix:** Replaced the broken two-phase skip-scan with a correct full linear scan
over `AddressOfNames`, comparing DWORD hashes. The evasion properties that matter
(no `strcmp`, no `GetProcAddress` IAT entry, seeded hash with no static constants
in `.rdata`) are all preserved. The loop shape change has no practical evasion
impact — a linear hash-compare loop does not match any known EDR signature pattern.

---

### Changed — `ntcalls_load()` and `ntcalls_verify()` return types and semantics

**File:** `client/core/ntcalls.c`, `client/core/ntcalls.h`

Both functions changed from `BOOL` to `DWORD` with structured bitmask return
values for precise per-function troubleshooting.

**`ntcalls_load()` return codes:**

| Value | Meaning |
|---|---|
| `0xFF` | All four exports resolved — fully OK |
| `0x00` | `ntdll.dll` not found in PEB |
| `0x01` | `RtlAdjustPrivilege` not exported |
| `0x02` | `NtShutdownSystem` not exported |
| `0x04` | `NtSetSystemPowerState` not exported |
| `0x08` | `NtRaiseHardError` not exported |
| Multiple | OR'd; `0x0F` = all four missing |

**`ntcalls_verify()` return codes:**

| Value | Meaning |
|---|---|
| `0x00` | All OK — pointers valid, `SeShutdownPrivilege` acquired |
| `0x01–0x08` | Same bit map — corresponding pointer is NULL |
| `0x10` | `RtlAdjustPrivilege()` returned non-`STATUS_SUCCESS` (privilege denied) |

`ntcalls_verify()` now skips the `RtlAdjustPrivilege` call when the pointer is
NULL (previously would have crashed). All call sites in `main.c` updated to
capture return values and pass them through `DBG_NTCALLS()`.

---

### Changed — Full instrumentation of previously unchecked calls in `main.c`

**File:** `client/core/main.c`

The following calls previously discarded their return values with no logging.
All are now checked and logged in both `WinMain` and `_agent_thread`:

| Call | What is now logged |
|---|---|
| `inject_init()` | `TRUE`/`FALSE` with reason string |
| `setsockopt(SO_RCVTIMEO)` | Return value (0 = OK) |
| `setsockopt(SO_KEEPALIVE)` | Return value (0 = OK) |
| `InetPtonA()` failure | Logs the bad IP string before exiting |
| `connect()` retry loop | `WSAGetLastError()` on every failed attempt |
| `shell_run()` | Session start and end logged |
| Key reload after session | `DBG_KEY` + specific error message on failure |
| `unhook_ntdll/etw_patch/amsi_patch` | Before/after each evasion patch |

---

### Changed — `_agent_thread` fully instrumented

**File:** `client/core/main.c`

`_agent_thread` (the post-migration code path called by `AgentRun()` and
`DllMain`) was previously completely dark — no logging, no return-value
checking. It now has full coverage identical to `WinMain`:
- `DBG_INIT()` / `DBG_PROCESS()` at thread start
- `ntcalls_load` / `ntcalls_verify` / `inject_init` / `DBG_SCALL`
- `WSAStartup`, key load, socket, connect, `setsockopt`, TLS, shell, key reload

---

### Changed — `DBG_SCALL()` ordering in `WinMain`

**File:** `client/core/main.c`

`DBG_SCALL()` was called before `inject_init()` (which calls `sc_init()`),
so all SSNs and gadget addresses appeared as `0x0000` / `NULL` in the log.
Moved to after `inject_init()` so the log reflects actual resolved values.

---

## Previous entries

### Refactored client split by responsibility

Monolithic `Source.c` split into:
- `client/core/main.c` — WinMain, reconnect loop, AgentRun, DllMain
- `client/core/ntcalls.c` — NT function pointer load/verify
- `client/core/config.h` — all compile-time constants
- `client/evasion/` — spoof, unhook, ETW/AMSI patch, PEB walk, syscalls, sandbox
- `client/inject/` — shellcode injection, reflective PE migration, jitter sleep
- `client/shell/` — command dispatch + all verb handlers

### Security layers added

Four layers added to every connection:
1. TLS 1.2/1.3 via SChannel (AEAD-only, no renegotiation)
2. HMAC-SHA256 challenge/response authentication
3. Protocol v2 magic-byte negotiation (0x4d)
4. AES-256-GCM framed messages with uint64 replay counter

### Bug fixes — client (`Source.c` / `main.c`)

| # | Bug | Fix |
|---|---|---|
| 1 | `checkNtCalls()` return logic backwards — exited on `STATUS_SUCCESS`, continued on failure | Fixed: `(void)ns` — non-fatal; gate return on pointer NULL-check only |
| 2 | `CreateMutexA` called with wide-string literal `L"consoleShell"` — mutex name was `"c"` | Fixed: narrow string; `FALSE` for `bInitialOwner` |
| 3 | `WSAStartup(MAKEWORD(2, 0))` — ancient subset, missing 2.2 APIs | Fixed: `MAKEWORD(2, 2)` |
| 4 | `fclose()` on a `_popen()` handle — leaks child processes, UB per CRT docs | Fixed: `_pclose()` |
| 5 | `inet_addr()` deprecated, rejects IPv6, silent failure on `255.255.255.255` | Fixed: `InetPtonA()` |
| 6 | Socket created once outside retry loop — consumed socket reused after `WSAETIMEDOUT` | Fixed: close and recreate socket on every connect retry |
| 7 | `secretKey` lingered in stack frame for entire session duration | Fixed: `SecureZeroMemory` immediately after `tls_connect()` copies it |

### Bug fixes — server (`serverShell.c` / `server/prompt.c`)

| # | Bug | Fix |
|---|---|---|
| 1 | `sAddress.sin_addr.s_addr` never assigned — bind used stack garbage | Fixed: `htonl(INADDR_ANY)` explicit |
| 2 | `forceOff()` strncmp length `12` — reads 2 bytes past 10-char literal | Fixed: `10` |
| 3 | Dangling `else` attached to `forceOff` only — `blueScreen` silently fell through | Fixed: explicit `if/else if/else` ladder with braces |
| 4 | `write()` sent full 1024-byte buffer including NUL padding | Fixed: `strlen(buffer)` |
| 5 | `socket()` and `accept()` return values unchecked | Fixed: both checked; `perror()` + early return |
| 6 | `write()` and `recv()` return values unchecked — silent failure on disconnect | Fixed: both checked; loop breaks on error |
| 7 | Listening socket never closed — `bind(): Address already in use` on restart | Fixed: `close(listenFd)` before return |
| 8 | Unreachable `jmp:` label (leftover from removed `goto`) | Removed |
