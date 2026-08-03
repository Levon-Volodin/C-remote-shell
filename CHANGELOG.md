# C-remote-shell — Changelog

---

## [Unreleased] — fix/c-agent-connect-and-hardening

### Fixed — `g_key_path` wiped before reconnect reload (HIGH)

**File:** `client/core/main.c` · `WinMain()`, `_agent_reconnect_loop()`

`SecureZeroMemory(g_key_path, sizeof(g_key_path))` ran 100 lines before
`load_secret_key(g_key_path, secretKey)`. In MODE B (file-based key) this
caused a silent infinite reconnect loop — `fopen("")` always fails. Fixed by
removing the `g_key_path` wipe entirely; only `secretKey` (the 32-byte buffer)
is zeroed immediately after `tls_connect()` copies it.

---

### Fixed — `_agent_thread` same wipe-then-reload sequence (HIGH)

**File:** `client/core/main.c` · `_agent_thread()`

The same pattern existed in the thread entry point. Fixed as part of the
`_agent_reconnect_loop` extraction — both `WinMain` and `_agent_thread` now
delegate to the shared loop which never wipes `g_key_path`.

---

### Fixed — Infinite loop on `INVALID_SOCKET` after connect retry (HIGH)

**File:** `client/core/main.c` · inner `for(;;)` retry loop

`socket()` returning `INVALID_SOCKET` was logged and slept but then continued
the loop, calling `connect()` on an invalid handle. After 3 consecutive
`socket()` failures the inner loop now breaks out to the outer `while(1)`.

---

### Fixed — `g_key_path` race condition between entry points (MEDIUM)

**File:** `client/core/main.c` · `resolve_key_path()`, `AgentRun()`, `DllMain()`

All three write sites now acquire `g_key_path_cs` (a `CRITICAL_SECTION`
initialised once by `_key_path_lock_init()`) before writing `g_key_path`.

---

### Fixed — `spoof_peb()` set `ImageBaseAddress` to a non-PE buffer (MEDIUM)

**File:** `client/evasion/spoof.c`, `client/evasion/spoof_obf.c`

`peb->ImageBaseAddress` was overwritten with `s_image` (a heap `WCHAR`
string). Any subsequent `GetModuleHandleA(NULL)` returned a non-PE pointer,
silently corrupting the reflective injector's `_read_self_pe()`. The
overwrite is now removed entirely — `ImageBaseAddress` is left unchanged.
`ProcessParameters->ImagePathName` still shows the spoofed path.

---

### Fixed — `_dump_lsass_snapshot` used wrong `SEC_IMAGE_NO_EXECUTE` constant (MEDIUM)

**File:** `client/shell/handlers_lateral.c` · `_dump_lsass_snapshot()`

The first snapshot attempt used `0x08000000 | 0x00400000`
(`SEC_COMMIT | SEC_LARGE_PAGES`), not `SEC_IMAGE_NO_EXECUTE`. This generated
a guaranteed failed kernel event before the correct fallback (`0x11000000`)
was tried. The wrong first call is removed; only the correct constant remains.

---

### Fixed — `_job_kill` marked slot FREE before worker stopped writing (MEDIUM)

**File:** `client/shell/shell.c` · `_job_kill()`

For the threadpool path (`hTh == INVALID_HANDLE_VALUE`) the slot was freed
immediately, creating a use-after-free window. Fixed with a `kill_pending`
field in `_Job`: the slot is only marked `JOB_FREE` after `TerminateProcess`
and a bounded `WaitForSingleObject` (5 s for thread handles, 500 ms for
threadpool path). `_job_worker` checks `kill_pending` under the lock before
writing output back into the slot.

---

### Fixed — `_handle_lateral_sc` spawned `cmd.exe` (OPSEC·HIGH)

**File:** `client/shell/handlers_lateral.c` · `_handle_lateral_sc()`

The handler called `_shell_exec(pTls, "sc \\\\... create ...")`, producing a
Sysmon EID 1 event with full command-line arguments. Rewritten to use the SCM
API directly (`OpenSCManagerA`, `CreateServiceA`, `StartServiceA`,
`DeleteService`) resolved via `peb_get_export()` — no `cmd.exe`, no child
process, no command-line telemetry.

---

### Fixed — `_handle_lateral_wmi` used `LoadLibraryA`/`GetProcAddress` (OPSEC·MEDIUM)

**File:** `client/shell/handlers_lateral.c` · `_handle_lateral_wmi()`

The handler called `LoadLibraryA("ole32.dll")` and `GetProcAddress(hOle32, ...)`
directly, undoing the IAT hygiene of the rest of the file. Rewritten to use
`_peb_load_library()` + `peb_get_export()` + `peb_hash_str()` for all COM
function resolution. The strings `"ole32.dll"`, `"CoInitializeEx"` etc. no
longer appear verbatim in the binary.

---

### Fixed — `getsystem` used a predictable service name (OPSEC·MEDIUM)

**File:** `client/shell/handlers_lateral.c` · `_handle_getsystem()`

`WinNetSvc%08lX` seeded from `GetTickCount() ^ GetCurrentProcessId()` was
trivially matched by Sysmon EID 17 pattern rules. The prefix is now a
more benign-looking name with the numeric suffix derived from `RDTSC` XOR'd
into the seed, reducing static-pattern detectability.

---

### Fixed — Module-stomping used a single predictable candidate DLL (OPSEC·MEDIUM)

**File:** `client/inject/inject.c` · `_alloc_stomped()`

`xpsprint.dll` is specifically listed in threat-hunting playbooks as a
module-stomping candidate. Replaced with a 4-entry pool
(`xpsprint.dll`, `msls31.dll`, `tsprint.dll`, `npsm.dll`) selected randomly
per invocation via `RDTSC`.

---

### Fixed — Sandbox username/hostname lists were plaintext in `.rdata` (OPSEC·LOW)

**File:** `client/evasion/sandbox.c`

The `_sb_usernames[]` and `_sb_hostnames[]` static arrays were `const char *`
literals, trivially matchable by YARA. Replaced with inline `SLIT_BUF()`
stack-decoded strings using the existing obfuscation infrastructure.

---

### Added — `_agent_reconnect_loop()` shared function (DESIGN)

**File:** `client/core/main.c`

`WinMain` and `_agent_thread` contained ~95% identical TCP/TLS/shell retry
loops. Extracted into `static int _agent_reconnect_loop(const char *logPrefix,
BOOL wsaCleanOnExit)`. Both callers reduced to setup + a single delegating call.
Any future change to reconnect logic requires one edit, not two.

---

### Added — `client/evasion/nt_offsets.h` — canonical NT struct offset constants (DESIGN)

**File:** `client/evasion/nt_offsets.h` (new)

Hard-coded byte offsets for `PEB->ImageBaseAddress`, `PEB->OSBuildNumber`,
`PEB->NtGlobalFlag`, `LDR_ENTRY->HashLinks`, `SYSTEM_PROCESS_INFORMATION->`
`ImageName.{Length,Buffer}`, and `UniqueProcessId` appeared in seven separate
source files. Consolidated into a single header included by `spoof.c`,
`inject.c`, `sandbox.c`, and `sleep_obf.c`.

---

### Changed — Sleep obfuscation enabled by default (DESIGN)

**File:** `Makefile`

`SLEEP_OBF_ENABLE` was opt-in via `CFLAGS_EXTRA="-DSLEEP_OBF_ENABLE"`. The
most impactful evasion feature should not require the operator to know a
compile-time flag exists. Now enabled by default; opt out with `SLEEP_OBF=0`.

---

### Changed — Shell verb dispatcher replaced with O(1) table (DESIGN)

**File:** `client/shell/shell.c`

The ~700-line sequential `strncmp` if-else chain in `shell_run()` is replaced
by a `_DispEntry` dispatch table and `_dispatch_verb()`. The table covers the
large majority of verbs; the ~8 genuinely special-cased verbs (`ls`, `env`,
`services`, `dns_query`, `find_files`, `tail`, `write_file`, `migrate`,
`dll_inject`, `forceOff`, `blueScreen`, `exec_bof`, `stage_load`, `_NS`
stubs) remain as explicit `if` blocks. All dead if-else branches (verbs
now handled by the table) were removed — net reduction of ~270 lines.

---

### Fixed — `spoof_obf.c` missing `s_image_get()`/`s_cmdline_get()` (BUILD)

**File:** `client/evasion/spoof.c`, `client/evasion/spoof_obf.c`

`gen_obf.py` step 5 substitutes bare `s_image` references with `s_image_get()`
calls, but because `spoof.c` uses heap pointer variables (not `static WCHAR
arr[] = L"..."` literals), step 4 never generated the accessor functions,
leaving dangling calls in the generated output. Added `s_image_get()` and
`s_cmdline_get()` static inline accessors to `spoof.c`; all call-sites updated.

---

### Fixed — `sleep_obf.c` `peb->ImageBaseAddress` not a named field on MinGW (BUILD)

**File:** `client/evasion/sleep_obf.c`

MinGW's `winternl.h` `PEB` struct does not expose `ImageBaseAddress` as a named
field. Added `#include "nt_offsets.h"` and replaced the bare field access with
`*(PVOID *)((BYTE *)peb + PEB_ImageBaseAddress)`.

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
