#!/usr/bin/env python3
"""
tools/gen_spoof_obf.py — Generate XOR-obfuscated wide-string macros for spoof.c
================================================================================
Usage (called by the Makefile or manually):
    python tools/gen_spoof_obf.py [image_path] [cmdline]

Outputs two sets of C macros:
    SPOOF_IMAGE_OBF_BYTES  / SPOOF_IMAGE_OBF_LEN  / SPOOF_IMAGE_OBF_KEY
    SPOOF_CMDLINE_OBF_BYTES / SPOOF_CMDLINE_OBF_LEN / SPOOF_CMDLINE_OBF_KEY

Each wide string is encoded as (lo_byte ^ key, hi_byte ^ key) for every WCHAR,
including the NUL terminator.  The key is a single non-zero byte chosen from
the string hash so it varies per string.

With no arguments, prints default values for svchost.exe identity.
With --emit-flags, prints compiler -D flags suitable for pasting into CFLAGS.
"""

import sys, struct

DEFAULTS = {
    "image":   r"C:\Windows\System32\svchost.exe",
    "cmdline": r"C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule",
}


def encode_wide(s: str, key: int) -> bytes:
    """Encode a Python str as UTF-16LE, XOR each byte with key."""
    raw = (s + "\x00").encode("utf-16-le")   # includes NUL terminator
    return bytes(b ^ key for b in raw)


def pick_key(s: str) -> int:
    """Non-zero key derived from string content (simple djb2 variant)."""
    h = 5381
    for c in s:
        h = ((h * 33) ^ ord(c)) & 0xFFFFFFFF
    key = (h & 0xFF) or 0x5E   # never zero
    return key


def c_byte_array(data: bytes) -> str:
    return "{" + ",".join(f"0x{b:02X}" for b in data) + "}"


def emit_flags(image: str, cmdline: str) -> str:
    parts = []
    for name, val in [("SPOOF_IMAGE", image), ("SPOOF_CMDLINE", cmdline)]:
        key = pick_key(val)
        enc = encode_wide(val, key)
        arr = c_byte_array(enc)
        parts.append(f'-D{name}_OBF_BYTES="{arr}"')
        parts.append(f'-D{name}_OBF_LEN={len(enc)}')
        parts.append(f'-D{name}_OBF_KEY={key}')
    return " ".join(parts)


def emit_header(image: str, cmdline: str) -> None:
    for label, name, val in [
        ("image path",   "SPOOF_IMAGE",   image),
        ("command line", "SPOOF_CMDLINE", cmdline),
    ]:
        key = pick_key(val)
        enc = encode_wide(val, key)
        arr = c_byte_array(enc)
        print(f"/* {label}: {val!r} */")
        print(f"#define {name}_OBF_BYTES  {arr}")
        print(f"#define {name}_OBF_LEN    {len(enc)}")
        print(f"#define {name}_OBF_KEY    0x{key:02X}u")
        print()


if __name__ == "__main__":
    args = sys.argv[1:]
    emit_flags_mode = "--emit-flags" in args
    args = [a for a in args if a != "--emit-flags"]

    image   = args[0] if len(args) > 0 else DEFAULTS["image"]
    cmdline = args[1] if len(args) > 1 else DEFAULTS["cmdline"]

    if emit_flags_mode:
        print(emit_flags(image, cmdline))
    else:
        emit_header(image, cmdline)
