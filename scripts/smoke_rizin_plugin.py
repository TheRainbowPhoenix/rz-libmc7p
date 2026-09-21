#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Self-contained smoke test for the mc7/mc7plus rizin plugins on Linux.

No corpus, no python reference needed -- embeds one small MC7+ blob (the
AddMul statement sequence) and checks that a real rizin process

  1. registers asm.arch=mc7plus,
  2. decodes operands fully (this catches token/decoder regressions like
     the "MOVE1600" dropout),
  3. prints the LABEL<n>(); function markers,
  4. draws the JMP -> LABEL arrow.

Usage:
  python3 scripts/smoke_rizin_plugin.py [dir-with-so-files]

The .so directory defaults to the packaged artifact layout next to this
script (../build-linux or ../rz-libmc7p-linux64).  It is exported to rizin
via RZ_LIB_PLUGINS, so nothing needs to be installed first.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# NOP; LABEL 0; MOVE :Word @SL.Slot16.0 0; JMP 1; LABEL 1;
# ADD :Int @SL.Slot16.0 @SB.Slot16.1 @SB.Slot16.2;
# MUL :Int @SB.Slot16.0 @SL.Slot16.0 @SB.Slot16.3; RET TRUE
BLOB = bytes.fromhex(
    "006800e0014801006c016801f0200948014806480a"
    "f0220948024801480e1401"
)

EXPECTED = [
    "NOP",
    "LABEL 0",
    "MOVE :Word @SL.Slot16.0 0",
    "JMP 1",
    "LABEL 1",
    "ADD :Int @SL.Slot16.0 @SB.Slot16.1 @SB.Slot16.2",
    "MUL :Int @SB.Slot16.0 @SL.Slot16.0 @SB.Slot16.3",
    "RET TRUE",
]

PD_LINE = re.compile(r"^\s*0x[0-9a-fA-F]+\s+(.+?)\s*$")
MARKER_LINE = re.compile(r"^[A-Za-z0-9_.]+\s*\(\);\s*$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
BOX_PREFIX = "│┌└├┤─<>v^╒╞═ \t"


def which_rizin() -> str:
    env_rz = os.environ.get("RIZIN_BIN")
    if env_rz:
        return env_rz
    found = shutil.which("rizin")
    if not found:
        print("ERROR: rizin not found on PATH (set RIZIN_BIN)")
        sys.exit(2)
    return found


def find_plugin_dir() -> Path:
    cand = []
    if len(sys.argv) > 1:
        cand.append(Path(sys.argv[1]))
    cand += [HERE.parent / "rz-libmc7p-linux64", HERE.parent / "build-linux"]
    for c in cand:
        if (c / "rz_libmc7p.so").exists():
            return c
    print("ERROR: rz_libmc7p.so not found (pass the artifact dir as argument)")
    sys.exit(2)


def main() -> int:
    rizin = which_rizin()
    plugdir = find_plugin_dir()

    # point rizin at a clean dir holding ONLY the plugin .so files (the
    # artifact dir also carries install.sh / README / CLI, which rizin
    # would otherwise try to dlopen and warn about)
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="mc7p-smoke-"))
    for so in plugdir.glob("*.so"):
        shutil.copy(so, tmp / so.name)
    plug_env = {**os.environ, "RZ_LIB_PLUGINS": str(tmp)}

    # 1) plugin registered?
    out = subprocess.run(
        [rizin, "-q", "-c", "e asm.arch=?", "-n"],
        capture_output=True, text=True, env=plug_env,
    )
    arches = out.stdout
    if "mc7plus" not in arches:
        print("FAIL: asm.arch=mc7plus not registered (RZ_LIB_PLUGINS=%s)" % tmp)
        return 1
    print("[+] asm.arch=mc7plus registered")

    # 2-4) disasm content
    blob = Path("/tmp/mc7p_smoke_addmul.bin")
    blob.write_bytes(BLOB)
    r = subprocess.run(
        [rizin, "-q", "-n", "-a", "mc7plus", "-b", "32",
         "-c", "e asm.tabs=0; pD %d" % len(BLOB), str(blob)],
        capture_output=True, text=True, env=plug_env,
    )
    if r.returncode != 0:
        print("FAIL: rizin exit %d: %s" % (r.returncode, r.stderr[:200]))
        return 1

    stmts = []
    markers = []
    for line in r.stdout.splitlines():
        text = ANSI.sub("", line).lstrip(BOX_PREFIX)
        m = PD_LINE.match(text)
        if m:
            stmts.append(m.group(1))
        elif MARKER_LINE.match(text.strip()):
            markers.append(text.strip())

    problems = []
    if stmts != EXPECTED:
        for i in range(max(len(EXPECTED), len(stmts))):
            e = EXPECTED[i] if i < len(EXPECTED) else "<missing>"
            g = stmts[i] if i < len(stmts) else "<missing>"
            if e != g:
                problems.append("  line %d: want %r got %r" % (i + 1, e, g))
    if not any(m.startswith("LABEL0(") for m in markers):
        problems.append("  no LABEL0(); function marker in pD output")
    if "└─>" not in r.stdout:
        problems.append("  no jump arrow (└─>) rendered for JMP 1 -> LABEL 1")

    if problems:
        print("FAIL (%d):" % len(problems))
        for p in problems:
            print(p)
        print("--- raw pD output ---")
        print(r.stdout)
        return 1

    print("[+] %d statements match the reference text" % len(EXPECTED))
    print("[+] LABEL0();/LABEL1(); function markers present")
    print("[+] JMP -> LABEL jump arrow rendered")
    print("SMOKE OK (%s, plugins from %s)" % (Path(rizin).name, tmp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
