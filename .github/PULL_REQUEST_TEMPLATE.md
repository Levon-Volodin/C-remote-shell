## Summary

<!-- One-line: what does this PR do? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Documentation
- [ ] Security fix

## Testing

- [ ] Debug build (`DBG=1`) tested locally
- [ ] Release build with embedded key tested locally
- [ ] `crs_probe` compliance check passes

## Checklist

- [ ] `client/evasion/gen_obf.py` re-run if `handlers_system.c` or `handlers_lateral.c` changed
- [ ] `README.md` updated if behaviour visible to the operator changed
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] No plaintext API / DLL name strings introduced without OBF macro coverage
- [ ] No new `GetProcAddress` / `LoadLibraryA` IAT entries
- [ ] `DBG=1` guard: no operational key (`SECRET_KEY=`) combined with debug build
