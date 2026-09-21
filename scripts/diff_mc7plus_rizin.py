#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Differential harness: rizin plugin (asm.arch=mc7plus) vs dis_mc7plus CLI.

While diff_mc7plus_corpus.py proves the C decoder matches the zymatik
python reference, this harness proves the *rizin arch plugin* (the code
path real rizin/Cutter actually executes) matches the very same decoder:

  1. for every raw MC7+ .bin under the zymatik tests corpus
  2. disassemble inside a real rizin process:  rizin -a mc7plus pD <size>
  3. disassemble with the standalone dis_mc7plus CLI
  4. compare the statement texts (offset column stripped from pD output)

Usage:
  RIZIN_BIN=/path/to/rizin DIS_BIN=/path/to/dis_mc7plus \
      python3 vendor/rz-libmc7/scripts/diff_mc7plus_rizin.py

Exits nonzero when any file mismatches.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RZROOT = HERE.parent
ZROOT = RZROOT.parent / "zymatik"

RIZIN = os.environ.get("RIZIN_BIN", shutil.which("rizin") or "rizin")
DIS = os.environ.get("DIS_BIN", str(RZROOT / "build-plugin" / "dis_mc7plus"))

PD_LINE = re.compile(r"^\s*0x[0-9a-fA-F]+\s+(.+?)\s*$")
# GUI-marker lines printed by pD when functions/flags exist at an address
# (LABEL<n>() markers, fcn entries, comments after the box prefixes are
# stripped).
MARKER_LINE = re.compile(r"^[A-Za-z0-9_.]+\s*\(\);\s*$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# asm.lines arrow/box decorations pD puts in front of instruction lines
# ("┌─<", "│", "└─>", "────────<", ...) when a jump target is known.
BOX_PREFIX = "│┌└├┤─<>v^╒╞═ \t"


def rizin_disasm(p: Path, size: int, color: bool = False):
    cmds = "e asm.tabs=0;"
    if color:
        cmds = "e scr.color=3;" + cmds
    cmds += " pD %d" % size
    r = subprocess.run(
        [RIZIN, "-q", "-n", "-a", "mc7plus", "-b", "32", "-c", cmds, str(p)],
        capture_output=True, text=True,
        env={**os.environ,
             "LD_LIBRARY_PATH": os.environ.get("LD_LIBRARY_PATH", "")},
    )
    if r.returncode != 0:
        return None, "rizin exit %d: %s" % (r.returncode, r.stderr.strip()[:120])
    out = []
    for line in r.stdout.splitlines():
        text = ANSI.sub("", line) if color else line
        text = text.lstrip(BOX_PREFIX)
        m = PD_LINE.match(text)
        if m:
            out.append(m.group(1))
        elif text.startswith(";") or MARKER_LINE.match(text.strip()):
            continue  # xref comments, fcn/flag signature lines
        elif text.strip():
            out.append(text.strip())
    return out, None


def cli_disasm(p: Path):
    r = subprocess.run([DIS, str(p)], capture_output=True, text=True)
    if r.returncode != 0:
        return None, "cli exit %d: %s" % (r.returncode, r.stderr.strip()[:120])
    return r.stdout.rstrip("\n").splitlines(), None


def main() -> int:
    bins = sorted((ZROOT / "tests").rglob("*.bin"))
    if not bins:
        print("ERROR: no .bin corpus under %s" % (ZROOT / "tests"))
        return 2
    ok = bad = skip = 0
    failures = []
    for p in bins:
        exp, err = cli_disasm(p)
        if exp is None:
            skip += 1
            continue  # invalid/ambiguous blob: reference CLI refuses it
        # 1) plain-text differential (color off)
        got, err = rizin_disasm(p, p.stat().st_size)
        if got is None:
            bad += 1
            failures.append((p.name, err))
            continue
        if got != exp:
            bad += 1
            first = next((i for i in range(max(len(exp), len(got)))
                          if i >= len(exp) or i >= len(got)
                          or exp[i] != got[i]), 0)
            failures.append((p.name, "line %d: rizin=%r cli=%r"
                             % (first + 1,
                                got[first] if first < len(got) else None,
                                exp[first] if first < len(exp) else None)))
            continue
        # 2) token-coverage differential: with color forced on rizin
        #    renders the statement from the plugin's asm_toks spans only,
        #    so any text dropped between spans shows up here (this caught
        #    the MOVE1600 regression).
        got_c, err = rizin_disasm(p, p.stat().st_size, color=True)
        if got_c is None:
            bad += 1
            failures.append((p.name, "color: " + err))
            continue
        if got_c != exp:
            bad += 1
            first = next((i for i in range(max(len(exp), len(got_c)))
                          if i >= len(exp) or i >= len(got_c)
                          or exp[i] != got_c[i]), 0)
            failures.append((p.name,
                             "color line %d: rizin=%r cli=%r"
                             % (first + 1,
                                got_c[first] if first < len(got_c) else None,
                                exp[first] if first < len(exp) else None)))
            continue
        ok += 1
    print("rizin-plugin differential: %d OK, %d FAIL, %d skip "
          "(%s vs %s)" % (ok, bad, skip, Path(RIZIN).name, Path(DIS).name))
    for name, msg in failures[:10]:
        print("  FAIL %s: %s" % (name, msg))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
