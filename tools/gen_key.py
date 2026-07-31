#!/usr/bin/env python3
"""
tools/gen_key.py — Megaploit C-agent key helper
================================================

Without arguments: generate a fresh random 32-byte key, print:
  • The raw hex string (copy this into the Megaploit server's secret.key)
  • The make invocation to embed it into the agent binary

With --embed <hex>: read an existing 64-char hex key, XOR it against
  the compile-time mask defined in client/config.h, and print the
  -DSECRET_KEY_BYTES=... flag that the Makefile passes to the compiler.
  This is called automatically by the Makefile — not meant for humans.

XOR mask
--------
The mask matches SECRET_KEY_MASK in client/config.h exactly.
If you ever change the mask in config.h you must change it here too.
"""

import os
import sys
import struct

# Must match SECRET_KEY_MASK in client/config.h
MASK = bytes([
    0x5A, 0x3C, 0xF1, 0x07, 0x9B, 0xE4, 0x2D, 0x60,
    0xA8, 0x14, 0x77, 0xCC, 0x3E, 0x91, 0x55, 0xD2,
    0x0F, 0xB3, 0x6A, 0x48, 0xFE, 0x22, 0x89, 0x71,
    0xC5, 0x4B, 0x1D, 0xA0, 0x36, 0xE7, 0x8C, 0x59,
])

assert len(MASK) == 32, "Mask must be exactly 32 bytes"


def _obfuscate(raw_key: bytes) -> bytes:
    """XOR raw_key with MASK, producing the obfuscated byte sequence."""
    return bytes(b ^ m for b, m in zip(raw_key, MASK))


def _to_c_bytes_literal(data: bytes) -> str:
    """Convert bytes to a C initialiser list string: {\\xAA,\\xBB,...}"""
    return "{" + ",".join(f"\\x{b:02X}" for b in data) + "}"


def _embed_flag(hex_key: str) -> str:
    """
    Given a 64-char hex key, return the compiler -D flag string:
      -DSECRET_KEY_BYTES={\\xAA,...}
    The Makefile passes this directly to the C compiler.
    """
    hex_key = hex_key.strip()
    if len(hex_key) != 64:
        print(
            f"error: SECRET_KEY must be exactly 64 hex characters ({len(hex_key)} given)",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        raw = bytes.fromhex(hex_key)
    except ValueError as exc:
        print(f"error: invalid hex key — {exc}", file=sys.stderr)
        sys.exit(1)

    obf = _obfuscate(raw)
    literal = _to_c_bytes_literal(obf)

    # MSVC uses /D, MinGW/GCC uses -D; the Makefile uses -D so we emit that.
    # The literal must be wrapped in double-quotes for the shell, but make
    # already handles quoting when it calls $(shell ...).
    return f'-DSECRET_KEY_BYTES="{literal}"'


def _generate() -> None:
    """Generate a new key, print instructions."""
    raw = os.urandom(32)
    hex_key = raw.hex()
    obf = _obfuscate(raw)
    literal = _to_c_bytes_literal(obf)

    print("=" * 66)
    print("  Megaploit C Agent — Key Generator")
    print("=" * 66)
    print()
    print("1. Copy this hex string to your Megaploit server's secret.key:")
    print()
    print(f"   {hex_key}")
    print()
    print("2. Build the agent with the key embedded (no secret.key on target):")
    print()
    print(f"   make SECRET_KEY={hex_key}")
    print()
    print("   Or, to cross-compile from Linux targeting a specific IP:")
    print()
    print(f"   make CC=x86_64-w64-mingw32-gcc C2_IP=<YOUR_IP> SECRET_KEY={hex_key}")
    print()
    print("NOTE: the hex string above IS the secret — treat it like a password.")
    print("      Do NOT commit it to source control.")
    print()


def main() -> None:
    args = sys.argv[1:]

    if not args:
        _generate()
        return

    if len(args) == 2 and args[0] == "--embed":
        # Called by the Makefile — print just the -D flag, nothing else
        print(_embed_flag(args[1]), end="")
        return

    print(__doc__)
    sys.exit(1)


if __name__ == "__main__":
    main()
