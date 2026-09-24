#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Self-contained smoke test for the mc7/mc7plus rizin plugins on Linux.

No corpus, no python reference needed -- embeds one small MC7+ blob (the
AddMul statement sequence) and checks that a real rizin process

  1. registers asm.arch=mc7plus,
  2. decodes operands fully (this catches token/decoder regressions like
     the "MOVE1600" dropout),
  3. prints the LABEL<n>(); function markers,
  4. draws the JMP -> LABEL arrow (checked structurally, not by an exact
     byte match: rizin renders the gutter differently depending on
     scr.utf8 / scr.utf8.curvy / scr.color and locale, and with color on
     it wraps every gutter char in its own escape sequence).

Usage:
  python3 scripts/smoke_rizin_plugin.py [dir-with-so-files]

The .so directory defaults to the packaged artifact layout next to this
script (../build-linux or ../rz-libmc7p-linux64).  It is exported to rizin
via RZ_LIB_PLUGINS, so nothing needs to be installed first.

The rizin commands force scr.color=0 / scr.utf8=true / scr.utf8.curvy=false
so the rendering is deterministic on any CI runner; the checks are still
glyph-table agnostic (UTF-8 straight/curvy and ASCII fallbacks accepted).
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
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

# deterministic rendering on any runner (order: utf8 first so curvy=false
# is meaningful, color last so nothing can re-enable it afterwards)
DET_FLAGS = "e scr.utf8=true; e scr.utf8.curvy=false; e scr.color=0;"

PD_LINE = re.compile(r"^\s*0x[0-9a-fA-F]+\s+(.+?)\s*$")
MARKER_LINE = re.compile(r"^[A-Za-z0-9_.]+\s*\(\);\s*$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# asm.lines arrow/box decorations pD puts in front of instruction lines.
# Covers all three vline tables of rizin 0.9.1 (rz_vline_a / _u / _uc):
# UTF-8 straight, UTF-8 curvy and the ASCII fallback.
BOX_PREFIX = "│┌└├┤─<>v^╒╞═╰╮╭╯╌┄└ \t"
# arrow at the jump target: corner (└ / ` / ╰) + dashes + head (> / ᐳ)
ARROW_TO_TARGET = re.compile(r"[└`╰][─╌┄-]*[>ᐳ]")
# arrow at the jump site: corner (┌ / , / ╭) + dashes + head (< / ᐸ)
ARROW_FROM_JUMP = re.compile(r"[┌,╭][─╌┄-]*[<ᐸ]")


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


def gutter_of(raw_line: str) -> str:
    """ANSI-stripped gutter of a pD line: everything before the 0x column."""
    t = ANSI.sub("", raw_line)
    i = t.find("0x")
    return t[:i] if i >= 0 else ""


def main() -> int:
    rizin = which_rizin()
    plugdir = find_plugin_dir()

    # point rizin at a clean dir holding ONLY the plugin .so files (the
    # artifact dir also carries install.sh / README / CLI, which rizin
    # would otherwise try to dlopen and warn about)
    tmp = Path(tempfile.mkdtemp(prefix="mc7p-smoke-"))
    for so in plugdir.glob("*.so"):
        shutil.copy(so, tmp / so.name)
    plug_env = {**os.environ, "RZ_LIB_PLUGINS": str(tmp)}

    # 1) plugin registered?
    out = subprocess.run(
        [rizin, "-q", "-c", DET_FLAGS + " e asm.arch=?", "-n"],
        capture_output=True, text=True, env=plug_env,
    )
    if "mc7plus" not in out.stdout:
        print("FAIL: asm.arch=mc7plus not registered (RZ_LIB_PLUGINS=%s)" % tmp)
        return 1
    print("[+] asm.arch=mc7plus registered")

    # 2-4) disasm content
    blob = Path(tempfile.mkdtemp(prefix="mc7p-smoke-blob-")) / "addmul.bin"
    blob.write_bytes(BLOB)
    r = subprocess.run(
        [rizin, "-q", "-n", "-a", "mc7plus", "-b", "32",
         "-c", DET_FLAGS + " e asm.tabs=0; pD %d" % len(BLOB), str(blob)],
        capture_output=True, text=True, env=plug_env,
    )
    if r.returncode != 0:
        print("FAIL: rizin exit %d: %s" % (r.returncode, r.stderr[:200]))
        return 1

    stmts = []
    markers = []
    jmp_gutters = []
    tgt_gutters = []
    for line in r.stdout.splitlines():
        text = ANSI.sub("", line)
        stripped = text.lstrip(BOX_PREFIX)
        m = PD_LINE.match(stripped)
        if m:
            stmts.append(m.group(1))
            if m.group(1) == "JMP 1":
                jmp_gutters.append(gutter_of(line))
            elif m.group(1) == "LABEL 1":
                tgt_gutters.append(gutter_of(line))
        elif MARKER_LINE.match(stripped.strip()):
            markers.append(stripped.strip())

    problems = []
    if stmts != EXPECTED:
        for i in range(max(len(EXPECTED), len(stmts))):
            e = EXPECTED[i] if i < len(EXPECTED) else "<missing>"
            g = stmts[i] if i < len(stmts) else "<missing>"
            if e != g:
                problems.append("  line %d: want %r got %r" % (i + 1, e, g))
    if not any(m.startswith("LABEL0(") for m in markers):
        problems.append("  no LABEL0(); function marker in pD output")
    # structural arrow check: the LABEL 1 line's gutter must carry
    # corner+dashes+arrowhead (and the JMP 1 line the mirrored one)
    if not any(ARROW_TO_TARGET.search(g) for g in tgt_gutters):
        problems.append("  no jump arrow at the LABEL 1 target line "
                        "(want corner+dashes+head, e.g. `-+>")
    if not any(ARROW_FROM_JUMP.search(g) for g in jmp_gutters):
        problems.append("  no mirrored arrow at the JMP 1 line "
                        "(want corner+dashes+head, e.g. ,-=<)")

    if problems:
        print("FAIL (%d):" % len(problems))
        for p in problems:
            print(p)
        # ---- rich diagnostics: exact codepoints + env + config ----
        print("--- diagnostics ---")
        v = subprocess.run([rizin, "-v"], capture_output=True, text=True)
        print("rizin: %s" % (v.stdout.splitlines() or ["?"])[0])
        for k in ("TERM", "LANG", "LC_ALL", "COLORTERM", "COLUMNS",
                  "NO_COLOR", "CI", "GITHUB_ACTIONS"):
            if k in os.environ:
                print("env %s=%r" % (k, os.environ[k]))
        cfg = subprocess.run(
            [rizin, "-q", "-n", "-c", "e scr.color; e scr.utf8; e scr.utf8.curvy"],
            capture_output=True, text=True, env=plug_env,
        )
        print("rizin cfg (scr.color/utf8/curvy): %s" %
              " ".join(cfg.stdout.split()))
        print("--- raw pD output, one repr per line (exact codepoints) ---")
        for line in r.stdout.splitlines():
            print(repr(line))
        print("--- raw stdout bytes, hex ---")
        print(r.stdout.encode("utf-8", "replace").hex())
        return 1

    print("[+] %d statements match the reference text" % len(EXPECTED))
    print("[+] LABEL0();/LABEL1(); function markers present")
    print("[+] JMP -> LABEL jump arrow rendered (structural check)")
    print("SMOKE OK (%s, plugins from %s)" % (Path(rizin).name, tmp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
