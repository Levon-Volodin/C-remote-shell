# fix: C agent ↔ Megaploit C2 connection stack — bugs, hardening, new evasion modules

## Summary

This PR fixes every known issue preventing the C agent from establishing a
session with the Megaploit C2 server, adds a full runtime debug subsystem,
ships five new evasion/hardening modules, and rewrites the operator-facing
documentation to reflect the current build and connection workflow.

---

## Bugs Fixed

### Critical — `peb_get_export()` always returned NULL on every Windows build

**File:** `client/evasion/peb_walk.c`

The two-phase skip-scan in `peb_get_export()` navigated the PE export name table
using `if (h < nameHash) seg_start = i`, assuming hash values are monotonically
ordered relative to table position. They are not — the seeded djb2-xorshift hash
produces values that are essentially random relative to alphabetical export order.
The algorithm consistently miscalculated `seg_start`/`seg_end` and scanned the
wrong segment, missing every target.

**Symptom:** `ntcalls_load()` returned `0x0F` (all four NT function pointers NULL)
on every run. `forceOff()`, `blueScreen()`, and all NT-syscall-based operations
were silently disabled.

**Fix:** Replaced the broken skip-scan with a correct full linear scan over
`AddressOfNames`, comparing DWORD hashes. All evasion properties are preserved
(no `strcmp`, no `GetProcAddress` IAT entry, seeded runtime hash).

---

### Critical — `crs_build` compiled the wrong source files

**File:** `plugins/c_remote_shell.py` (Megaploit repo)

The `crs_build` plugin's `_client_srcs` list referenced the **plain** source
files (`spoof.c`, `syscall.c`, `evasion.c`, `handlers_system.c`,
`handlers_lateral.c`) instead of the **obfuscated** `_obf.c` variants that
replace them in the current layout. This produced a binary with all API and
DLL name strings in plaintext in `.rdata`, defeating the entire obfuscation
layer.

Additionally, two required new modules were absent from the list:
- `client/evasion/sandbox.c`
- `client/evasion/sleep_obf.c`

**Fix:** `_client_srcs` updated to exactly mirror `CLIENT_SRCS` in the Makefile.

---

### Critical — `secret.key` key mismatch between server and agent

**Files:** `plugins/c_remote_shell.py`, `secret.key`, `C-remote-shell/secret.key`

`crs_build` wrote the freshly generated key only to `./secret.key` (Megaploit
repo root). The C-remote-shell submodule directory kept its own stale
`C-remote-shell/secret.key` from a previous session. Any agent built by
`make` inside the submodule read the old key; the server read the new key.
Every connection produced `REJECTED reason=auth_failed` in the audit log.

**Fix:** `crs_build` now writes the key to both `./secret.key` (server) and
`C-remote-shell/secret.key` (submodule) atomically in a single call.

---

### Critical — C agent TLS handshake rejected when server started without `--tls`

**File:** `megaploit/server/cli.py` (Megaploit repo)

The C agent **always** performs a SChannel TLS handshake immediately after TCP
connect — there is no plaintext mode on the C side. The server's
`_start_listener()` only enabled TLS when `--tls` / `--cert` flags were
supplied. Without those flags the server handed the raw socket to
`server_authenticate()`, which sent a 16-byte HMAC challenge. The agent's TLS
`ClientHello` was read as the HMAC response — it never matched — the server
logged `REJECTED reason=auth_failed` and closed the socket. The agent retried
every 60 seconds, always failing the same way.

**Fix:** `_start_listener()` now always auto-generates a self-signed TLS
certificate (reusing `loot/tls/megaploit.crt` if it already exists). The
`--tls` flag is no longer required; it is accepted for backward compatibility
but has no additional effect. Operators running `python server.py -lh <ip> -p
<port>` with no flags now get TLS automatically.

---

### Bug — MinGW link line missing `-liphlpapi`

**File:** `plugins/c_remote_shell.py`

The MinGW `libs` list in `crs_build` omitted `-liphlpapi` (IP Helper API),
required by `GetAdaptersInfo`, `GetIpNetTable2`, and related calls in
`handlers_system.c`. The link either failed or produced a binary that crashed
at runtime on any network-enumeration verb.

**Fix:** Added `-liphlpapi` to match the Makefile's `MINGW_LIBS` exactly.

---

### Bug — `ntcalls_load()` / `ntcalls_verify()` return types too coarse

**File:** `client/core/ntcalls.c`, `client/core/ntcalls.h`

Both functions returned `BOOL`, providing no information about which specific
export was missing. A single missing pointer was indistinguishable from all
four missing.

**Fix:** Both functions now return `DWORD` bitmasks.

`ntcalls_load()`:
- `0xFF` — all four exports resolved
- `0x01` / `0x02` / `0x04` / `0x08` — each bit maps to one missing export
- `0x00` — ntdll not found in PEB
- Values OR'd; `0x0F` = all four missing

`ntcalls_verify()`:
- `0x00` — OK
- `0x01–0x08` — same bit map; pointer is NULL
- `0x10` — `RtlAdjustPrivilege()` returned non-`STATUS_SUCCESS`

`ntcalls_verify()` now also guards the `RtlAdjustPrivilege` call against a
NULL pointer (previously would have crashed).

---

### Bug — `DBG_SCALL()` logged before `sc_init()` ran

**File:** `client/core/main.c`

`DBG_SCALL()` was called before `inject_init()` (which internally calls
`sc_init()` to resolve syscall service numbers). All 11 SSNs and gadget
addresses appeared as `0x0000` / `NULL` in the debug log.

**Fix:** `DBG_SCALL()` moved to after `inject_init()`.

---

## New Features

### Runtime debugger (`client/debug/`)

A structured debug subsystem that is **completely absent from release builds**
— zero overhead, zero extra strings, zero extra IAT entries when `AGENT_DEBUG`
is not defined.

**New files:**
- `client/debug/agent_debug.h` — public API with compile-time no-op stubs
- `client/debug/agent_debug.c` — implementation, compiled only with `DBG=1`

**Enable:**
```bash
mingw32-make C2_IP=127.0.0.1 C2_PORT=4444 DBG=1
```

`DBG=1` also implies `DISABLE_AUTO_MIGRATE`, `DISABLE_SANDBOX_CHECK`, and
`DISABLE_EVASION` so debug runs connect instantly without relocating.

**Output destinations (simultaneous):**
1. `%TEMP%\megaploit_agent_<tag>.log` — timestamped, appended; tag is a
   4-hex-char suffix randomised per build (avoids a static YARA-matchable path)
2. `OutputDebugStringA` with `[MAGENT]` prefix — live in x64dbg / WinDbg / DbgView

**Subsystems instrumented:** `INIT`, `NTCALL`, `SCALL`, `INJECT`, `SPOOF`,
`MIGRAT`, `SNDBOX`, `EVASN`, `KEY`, `NET`, `SOCK`, `TLS`, `SHELL`, `THREAD`

---

### Sleep obfuscation — Ekko variant (`client/evasion/sleep_obf.c`)

**New files:** `client/evasion/sleep_obf.c`, `client/evasion/sleep_obf.h`

When `SLEEP_OBF_ENABLE` is defined, `sleep_obf_delay()` RC4-encrypts the
agent's own `.text` and `.data` sections before each sleep and decrypts on
wake. Key = SHA-256(`RDTSC_seed || module_base || image_size`) truncated to
16 bytes — changes every execution. Writes through `SC_NtWriteVirtualMemory`
on the current process handle, bypassing page-protection checks without
flipping pages to RW. Memory scanners during the sleep interval see only
ciphertext.

Enable:
```bash
CFLAGS_EXTRA="-DSLEEP_OBF_ENABLE"
```

---

### IAT-free kernel32 wrappers (`client/evasion/k32_walk.h`)

**New file:** `client/evasion/k32_walk.h`

Thin inline wrappers — `k32_CreateMutexA`, `k32_CreateThread`,
`k32_CreateProcessA`, `k32_OpenProcess`, `k32_TerminateProcess`,
`k32_OpenProcessToken`, `k32_DuplicateTokenEx`, `k32_ImpersonateLoggedOnUser`
— that resolve through `peb_get_export()` at runtime. None appear in the IAT.

---

### Obfuscated handler sources (`client/shell/handlers_*_obf.c`)

**New files:**
- `client/shell/handlers_system_obf.c`
- `client/shell/handlers_lateral_obf.c`

Auto-generated by `client/evasion/gen_obf.py`. All DLL name and NT function
name string literals are replaced by XOR-encoded blobs decoded on the stack at
runtime. These files replace the plain source files in the build — no plaintext
strings appear in `.rdata` or `.data` in the final binary.

---

### C2 address XOR obfuscation (`tools/gen_c2_obf.py`)

**New file:** `tools/gen_c2_obf.py`

Called by the Makefile's `_C2_OBF_FLAGS` variable. Emits
`-DC2_IP_OBF_BYTES=... -DC2_IP_OBF_KEY=... -DC2_PORT_OBF=...` so `C2_IP`
and `C2_PORT` never appear as plaintext in `.rdata` or `.data`. Decoded at
runtime by `c2_ip_decode()` / `c2_port_decode()` in `client/core/config.h`.

---

## Changed

### `client/core/main.c` — full instrumentation

All previously unchecked calls now capture and log return values in both
`WinMain` and `_agent_thread`: `inject_init`, both `setsockopt` calls,
`InetPtonA` failure path, every `connect()` retry, `shell_run` session
start/end, and key reload after session end.

### `client/core/main.c` — `_agent_thread` full coverage

`_agent_thread` (the post-migration code path) was previously completely dark.
It now has instrumentation coverage identical to `WinMain`.

### `server/config.h` — deprecation gate

Added a hard compile error (`#error`) unless
`-DLEGACY_C_SERVER_ACKNOWLEDGED` is defined. The C server in `server/` speaks
raw TCP with no authentication and is protocol-incompatible with the current C
agent (which requires TLS + HMAC + AES-GCM). The gate prevents accidental
builds that look correct but silently fail to interoperate.

### `tls/tls_client.c` — cached BCrypt key handles

Pre-computed `BCRYPT_KEY_HANDLE` instances (`hAesKeyEnc`, `hAesKeyDec`) stored
in `TLS_CONTEXT` after connect. Per-message crypto overhead drops from ~20 µs
(open + generate + encrypt + destroy) to < 2 µs (encrypt only with cached handle).

### `tls/tls_client.c` — `_tls_raw_recv` receive buffer cap

Added `TLS_RECV_BUF_MAX` (256 KB) guard to prevent unbounded heap growth when
a MITM or malfunctioning peer streams junk incomplete TLS records.

### `Makefile` — new build targets and guards

- `blob` / `blob-verify` targets for reflective loader blob regeneration and CI verification
- `DBG=1` guard: hard error if `SECRET_KEY=` is also set
- `DISABLE_AUTO_MIGRATE` guard: hard error in non-`DBG` builds
- MSYS2 UCRT64 detection (`C:\msys64\ucrt64\bin\gcc.exe`) preferred over MinGW cross-compiler
- `_INCLUDE_FLAG` mechanism: auto-injects `megaploit_build_config.h` when present,
  allowing `crs_build` to pass all defines via a header file instead of shell-quoted `-D` flags

---

## Documentation

### `README.md`

Quick Start rewritten end-to-end:
- Numbered steps 1–4 matching the actual workflow
- Explicit instructions for writing the key to **both** locations
- Step 3 covers starting the server — shows expected TLS auto-cert output
- Inline troubleshooting table for the five most common failure modes
- Cross-compile example added for Linux / macOS operators
- `--tls` no longer shown as required (TLS is automatic)

### `docs/QUICKSTART.md` (Megaploit repo)

Section 4 "Start the Server" rewritten:
- Correct `python server.py -lh <ip> -p <port>` command replacing stale `python3 -m megaploit` form
- TLS auto-cert explained
- `--cert`/`--key` and `--allow-ip` sections added
- VPS example corrected

### `docs/TROUBLESHOOTING.md` (Megaploit repo)

Section 4 "No Session" expanded from 6 steps to 10:
- New Step 2: audit log interpretation table (`ACCEPTED`, `REJECTED reason=auth_failed`, `REJECTED reason=tls_error`)
- New Step 5: key mismatch fix with exact commands for each platform
- New Step 6: TLS failure guide and cert regeneration
- New Step 7: C2_IP/C2_PORT mismatch rebuild
- New Step 9: sandbox detection bypass with `DBG=1`

Section 12 "TLS Issues" rewritten:
- C agent TLS requirement explained
- Cert regeneration procedure
- Optional cert pinning (`C2_CERT_PIN`) added

---

## Files Changed

| File | Change |
|---|---|
| `client/core/main.c` | Instrumentation, `DBG_SCALL` ordering, full `_agent_thread` coverage |
| `client/core/config.h` | C2 obfuscation decode API, sleep-obf mask, SC_SVC_NAME obfuscation |
| `client/core/ntcalls.c` / `.h` | `DWORD` bitmask return types |
| `client/debug/agent_debug.c` / `.h` | **New** — runtime debugger |
| `client/evasion/peb_walk.c` | Fix `peb_get_export()` linear scan |
| `client/evasion/sleep_obf.c` / `.h` | **New** — Ekko-variant sleep obfuscation |
| `client/evasion/k32_walk.h` | **New** — IAT-free kernel32 wrappers |
| `client/evasion/evasion_obf.c` | Obfuscated build of `evasion.c` |
| `client/evasion/sandbox.c` / `.h` | 10-check sandbox detection + startup delay |
| `client/evasion/syscall_obf.c` | Obfuscated build of `syscall.c` |
| `client/evasion/spoof_obf.c` | Obfuscated build of `spoof.c` |
| `client/evasion/obf.h` | `OBF_S` / `OBF_W` stack-decode macros |
| `client/evasion/gen_obf.py` | Generates `*_obf.c` from source files |
| `client/shell/handlers_system_obf.c` | **New** — obfuscated handlers_system |
| `client/shell/handlers_lateral_obf.c` | **New** — obfuscated handlers_lateral |
| `client/shell/shell.c` | Background job table, `_json_unwrap`, dispatch |
| `client/shell/handlers_system.c` | `netstat`, `arp`, `ifconfig`, `routes` native C implementations |
| `client/shell/handlers_lateral.c` | `getsystem`, UAC bypass variants, lateral movement handlers |
| `client/shell/handlers_ui.c` | `clip_watch`, `open_url`, `set_wallpaper`, `mouse_move`, `type_keys` |
| `client/shell/shell_internal.h` | Forward declarations for new handlers |
| `client/inject/inject.c` | Thread-pool dispatch, two-tier auto-migrate, `jitter_sleep` |
| `client/inject/loader.c` / `loader_blob.h` | Reflective PE loader blob update |
| `tls/tls_client.c` | Cached BCrypt handles, recv buffer cap |
| `tls/http_profile.h` | Malleable HTTP transport profile |
| `server/config.h` | Deprecation gate |
| `tools/gen_key.py` | `--embed` flag for Makefile integration |
| `tools/gen_c2_obf.py` | **New** — C2 address XOR obfuscation |
| `Makefile` | New targets, guards, UCRT64 detection, `_INCLUDE_FLAG` |
| `README.md` | Quick Start rewrite, troubleshooting table |

---

## Testing

Verified with:
- Release build: `mingw32-make C2_IP=<ip> C2_PORT=4444 SECRET_KEY=<64-hex>`
- Debug build: `mingw32-make C2_IP=127.0.0.1 C2_PORT=4444 DBG=1`
- `crs_probe` compliance check: all 30 required signals pass
- Session established and verified against `loot/audit.log` `ACCEPTED` entry
- `peb_get_export()` verified: `ntcalls_load()` returns `0xFF` on Windows 10/11

---

## Checklist

- [x] `client/evasion/gen_obf.py` re-run after `handlers_system.c` and `handlers_lateral.c` changes
- [x] `README.md` updated
- [x] `CHANGELOG.md` entry added under `[Unreleased]`
- [x] No plaintext API / DLL name strings without OBF macro coverage
- [x] No new `GetProcAddress` / `LoadLibraryA` IAT entries
- [x] `DBG=1` + `SECRET_KEY=` guard active in Makefile
- [x] `DISABLE_AUTO_MIGRATE` blocked in non-debug builds
