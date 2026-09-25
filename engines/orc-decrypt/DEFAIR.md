# orc-decrypt in DEFAIR

Vendored, unmodified, from https://github.com/DFIR-ORC/orc-decrypt at commit
`dd19f7380e6e4c1883f45099838b72ac5503b6ed` (ANSSI, LGPL-2.1-or-later — see
`LICENSE.txt`).

DEFAIR uses it to decrypt DFIR-ORC `*.7z.p7b` archives
(`defair.sources.archives.decrypt_orc`): the Python PKCS#7 implementation
(`method="python"`, no size limit) plus the compiled `unstream` helper, built
by CMake when the package is installed (`pip install ./engines/orc-decrypt`).
Its official `test_data/` and test keys are used by `tests/test_sources.py`.
