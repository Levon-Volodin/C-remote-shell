#!/usr/bin/env python3
"""
tools/gen_loader_blob.py
------------------------
Portable replacement for client/gen_loader_blob.ps1.

Usage
-----
  python tools/gen_loader_blob.py          -- auto-detect compiler, build blob
  python tools/gen_loader_blob.py --verify  -- verify committed blob matches a fresh build
  python tools/gen_loader_blob.py --cc /path/to/gcc  -- force compiler

Called by the Makefile as:
  python tools/gen_loader_blob.py [--cc $(LOADER_CC)]

On Linux/macOS:  uses x86_64-w64-mingw32-gcc
On Windows MSYS2: uses the gcc found in PATH (ucrt64/bin, mingw64/bin, usr/bin)
Never uses cl.exe or any MSVC tool.

What it does
------------
  1. Compile client/loader.c with -O0 -fpic -fno-stack-protector
     -ffunction-sections into a .o
  2. Run objcopy --only-section='.text$rfl_loader' -O binary to extract the
     raw machine code for rfl_loader() only
  3. SHA-256 the resulting binary
  4. Write client/loader_blob.h with the bytes, size macro, compiler version,
     and SHA-256 fingerprint embedded in comments
  5. If --verify: re-run steps 1-3, compare SHA against the committed header
     and exit non-zero if they differ (used as a CI sanity check)

Portability contract
--------------------
  The blob itself is pure x64 PIC shellcode with no OS/compiler-version
  dependencies — it will run on any x64 Windows target.  The only constraint
  is that loader.c must be compiled with a GCC-family compiler that supports
  __attribute__((section(...), noinline)).
"""

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Paths (relative to the repo root, regardless of cwd)
# ---------------------------------------------------------------------------
_HERE    = os.path.dirname(os.path.abspath(__file__))
_ROOT    = os.path.dirname(_HERE)
_LOADER_C    = os.path.join(_ROOT, "client", "inject", "loader.c")
_LOADER_H    = os.path.join(_ROOT, "client", "inject", "loader.h")
_LOADER_BLOB = os.path.join(_ROOT, "client", "inject", "loader_blob.h")

# Compiler flags for loader.c — must never be relaxed
_CFLAGS = [
    "-O0",
    "-fpic",
    "-fno-stack-protector",
    "-ffunction-sections",
    "-fno-asynchronous-unwind-tables",
    "-fno-ident",
    "-DWIN32_LEAN_AND_MEAN",
    "-m64",            # force x64 even on multilib hosts
]

# ---------------------------------------------------------------------------
# Compiler auto-detection
# ---------------------------------------------------------------------------

_CANDIDATES = [
    # Windows MSYS2 UCRT64 / MINGW64
    r"C:\msys64\ucrt64\bin\gcc.exe",
    r"C:\msys64\mingw64\bin\gcc.exe",
    r"C:\msys64\usr\bin\gcc.exe",
    # Linux / macOS cross-compiler (apt install mingw-w64)
    "x86_64-w64-mingw32-gcc",
    # Native Linux/macOS GCC that can produce PE via -target flag
    "gcc",
]

def _find_compiler():
    """Return the first GCC-family binary that can cross-compile to Windows PE."""
    for cand in _CANDIDATES:
        if shutil.which(cand):
            return cand
    return None


def _compiler_version(cc):
    try:
        out = subprocess.check_output([cc, "--version"], stderr=subprocess.STDOUT,
                                      text=True)
        return out.splitlines()[0].strip()
    except Exception:
        return cc


def _find_objcopy(cc):
    """
    Find the objcopy that matches the compiler.
    For x86_64-w64-mingw32-gcc → x86_64-w64-mingw32-objcopy
    For gcc on MSYS2 / Linux → objcopy in the same directory
    """
    # Try the same prefix as the compiler
    prefix = ""
    m = re.match(r"^(.*-)gcc(\.exe)?$", os.path.basename(cc), re.IGNORECASE)
    if m:
        prefix = m.group(1)

    # Same directory as cc
    cc_dir = os.path.dirname(shutil.which(cc) or "")

    candidates = []
    if prefix:
        candidates.append(prefix + "objcopy")
        if cc_dir:
            candidates.append(os.path.join(cc_dir, prefix + "objcopy"))
    candidates.append("objcopy")
    if cc_dir:
        candidates.append(os.path.join(cc_dir, "objcopy"))

    for cand in candidates:
        if shutil.which(cand):
            return cand
    return None


# ---------------------------------------------------------------------------
# Build pipeline
# ---------------------------------------------------------------------------

def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_blob(cc, objcopy, work_dir):
    """
    Compile loader.c → .o → extract .text$rfl_loader → raw bytes.
    Returns bytes of the blob.
    """
    obj_path = os.path.join(work_dir, "loader_blob.o")
    bin_path = os.path.join(work_dir, "loader_func.bin")

    # Include path for loader.h (lives in client/inject/)
    inc = os.path.join(_ROOT, "client", "inject")

    # Step 1: compile
    cmd_compile = [cc] + _CFLAGS + [
        f"-I{inc}",
        "-c", _LOADER_C,
        "-o", obj_path,
    ]
    result = subprocess.run(cmd_compile, capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR: loader.c compilation failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    # Step 2: extract section
    cmd_objcopy = [
        objcopy,
        "--only-section=.text$rfl_loader",
        "-O", "binary",
        obj_path,
        bin_path,
    ]
    result = subprocess.run(cmd_objcopy, capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR: objcopy failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(bin_path) or os.path.getsize(bin_path) == 0:
        print("ERROR: extracted blob is empty.  Check that loader.c uses "
              "__attribute__((section(\".text$rfl_loader\"))) on rfl_loader().",
              file=sys.stderr)
        sys.exit(1)

    with open(bin_path, "rb") as f:
        return f.read()


def _emit_header(blob_bytes, cc_version, blob_sha):
    """Write client/loader_blob.h."""
    count = len(blob_bytes)
    lines = [
        "/*",
        " * client/inject/loader_blob.h  --  AUTO-GENERATED — do not edit by hand",
        " * Regenerate:  python tools/gen_loader_blob.py",
        " *",
        f" * Compiler:  {cc_version}",
        f" * Blob SHA-256:  {blob_sha}",
        f" * Blob size:  {count} bytes",
        " *",
        " * Portability",
        " * -----------",
        " * The blob is pure x64 position-independent shellcode (no OS/compiler",
        " * dependencies).  It works on any x64 Windows target.  Do not regenerate",
        " * with MSVC — use GCC or x86_64-w64-mingw32-gcc only.",
        " */",
        "#pragma once",
        "#ifndef CLIENT_LOADER_BLOB_H",
        "#define CLIENT_LOADER_BLOB_H",
        "",
        "/* Raw position-independent rfl_loader() machine code */",
        "static const unsigned char s_rfl_loader[] = {",
    ]

    cols = 16
    for i in range(0, count, cols):
        chunk = blob_bytes[i : i + cols]
        hex_vals = ", ".join(f"0x{b:02x}" for b in chunk)
        comma = "," if i + cols < count else ""
        lines.append(f"    {hex_vals}{comma}")

    lines += [
        "};",
        "",
        "#define S_RFL_LOADER_SIZE  ((DWORD)sizeof(s_rfl_loader))",
        "",
        "/* SHA-256 of blob bytes — verified by tools/gen_loader_blob.py --verify */",
        f'#define S_RFL_LOADER_SHA256  "{blob_sha}"',
        "",
        "#endif /* CLIENT_LOADER_BLOB_H */",
        "",
    ]

    with open(_LOADER_BLOB, "w", newline="\n") as f:
        f.write("\n".join(lines))

    print(f"[+] loader_blob.h: {count} bytes  SHA-256: {blob_sha[:16]}…")


def _extract_committed_sha():
    """Read S_RFL_LOADER_SHA256 from the committed loader_blob.h."""
    try:
        with open(_LOADER_BLOB, "r") as f:
            text = f.read()
        m = re.search(r'S_RFL_LOADER_SHA256\s+"([0-9a-f]{64})"', text)
        if m:
            return m.group(1)
    except FileNotFoundError:
        pass
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cc",     metavar="PATH",
                    help="Path to GCC cross-compiler (auto-detected if omitted)")
    ap.add_argument("--verify", action="store_true",
                    help="Verify committed blob matches a fresh build; exit 1 if not")
    args = ap.parse_args()

    # Resolve compiler
    cc = args.cc or _find_compiler()
    if not cc:
        print("ERROR: No GCC cross-compiler found.  Install one of:\n"
              "  Windows: MSYS2 UCRT64 (pacman -S mingw-w64-ucrt-x86_64-gcc)\n"
              "  Linux:   apt install mingw-w64\n"
              "  macOS:   brew install mingw-w64\n"
              "Then re-run or pass --cc /path/to/gcc", file=sys.stderr)
        sys.exit(1)

    if not shutil.which(cc):
        print(f"ERROR: compiler not found: {cc}", file=sys.stderr)
        sys.exit(1)

    objcopy = _find_objcopy(cc)
    if not objcopy:
        print(f"ERROR: objcopy not found (expected alongside {cc}).\n"
              "Install binutils for your cross-toolchain.", file=sys.stderr)
        sys.exit(1)

    cc_ver  = _compiler_version(cc)
    print(f"[*] Compiler:  {cc_ver}")
    print(f"[*] objcopy:   {shutil.which(objcopy)}")

    with tempfile.TemporaryDirectory() as work_dir:
        blob = _build_blob(cc, objcopy, work_dir)

    blob_sha = hashlib.sha256(blob).hexdigest()

    if args.verify:
        committed_sha = _extract_committed_sha()
        if committed_sha is None:
            print("WARNING: No SHA-256 in committed loader_blob.h "
                  "(was it generated by an older script?).")
            print(f"  Fresh build SHA-256: {blob_sha}")
            sys.exit(0)    # non-fatal for pre-existing blobs

        if blob_sha == committed_sha:
            print(f"[+] Blob verified OK  SHA-256: {blob_sha[:16]}…")
            sys.exit(0)
        else:
            print("MISMATCH: committed blob does not match fresh build!",
                  file=sys.stderr)
            print(f"  Committed:  {committed_sha}", file=sys.stderr)
            print(f"  Fresh:      {blob_sha}", file=sys.stderr)
            print("  Run:  python tools/gen_loader_blob.py  to regenerate.",
                  file=sys.stderr)
            sys.exit(1)

    _emit_header(blob, cc_ver, blob_sha)
    print(f"[+] Written: {_LOADER_BLOB}")


if __name__ == "__main__":
    main()
