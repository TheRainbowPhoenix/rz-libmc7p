#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Differential harness: rz-libmc7 C dis_mc7plus vs zymatik python disasm.

For every raw MC7+ .bin under the zymatik corpus tree:
  1. decode + render with zymatik (reference)
  2. decode + render with the C dis_mc7plus CLI
  3. byte-compare the two statement texts

Usage (from anywhere):  python3 vendor/rz-libmc7/scripts/diff_mc7plus_corpus.py
Exits nonzero when any file mismatches.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RZROOT = HERE.parent
ZROOT = RZROOT.parent / "zymatik"
sys.path.insert(0, str(ZROOT))

from zymatik.mc7plus.asm.disasm import decode_code           # noqa: E402
from zymatik.mc7plus.asm.text import render_statements       # noqa: E402

DIS = RZROOT / "build" / "dis_mc7plus"


def main() -> int:
    if not DIS.exists():
        print("ERROR: %s not found -- build first (ninja -C build)" % DIS)
        return 2
    bins = sorted((ZROOT / "tests").rglob("*.bin"))
    if not bins:
        print("ERROR: no .bin corpus files under %s" % (ZROOT / "tests"))
        return 2
    ok = bad = 0
    failures = []
    for p in bins:
        code = p.read_bytes()
        try:
            expected = render_statements(decode_code(code))
        except Exception as e:
            expected = None
            print("SKIP(python-err) %s: %s" % (p.name, e))
            continue
        r = subprocess.run([str(DIS), str(p)], capture_output=True, text=True)
        if r.returncode != 0:
            bad += 1
            failures.append((p.name, "C exit %d: %s"
                             % (r.returncode, r.stderr.strip())))
            continue
        got = r.stdout.rstrip("\n")
        if got == expected:
            ok += 1
        else:
            bad += 1
            el = expected.splitlines()
            gl = got.splitlines()
            first = next((i for i in range(max(len(el), len(gl)))
                          if i >= len(el) or i >= len(gl)
                          or el[i] != gl[i]), -1)
            failures.append((p.name,
                             "line %d differs:\n  py: %s\n  c : %s"
                             % (first + 1,
                                el[first] if first < len(el) else "<eof>",
                                gl[first] if first < len(gl) else "<eof>")))
    print("MC7+ differential: %d files, %d MATCH, %d MISMATCH"
          % (ok + bad, ok, bad))
    for name, why in failures[:20]:
        print("--- %s\n%s" % (name, why))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
