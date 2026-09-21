#!/bin/sh
# Cross-compile the libmc7 rizin plugins + standalone CLI for Windows x64.
#
# Requirements:
#   - zig >= 0.14 (zig cc as the cross compiler, mingw-w64 target)
#   - official rizin Windows shared release zip (same version as the host
#     rizin/Cutter that will load the plugin -- ABI + RZ_VERSION must match):
#       https://github.com/rizinorg/rizin/releases/download/v<VER>/
#           rizin-windows-shared64-v<VER>.zip
#     extracted somewhere; point RZ_WIN_SDK at the directory that contains
#     include/ and lib/ (e.g. rizin-win-installer-clang_cl-64/).
#
# Usage:
#   RZ_WIN_SDK=/path/to/rizin-win-installer-clang_cl-64 [ZIG=/path/zig] \
#       sh scripts/build_win_plugin.sh [outdir]
#
# Outputs (in <outdir>/rz-libmc7p-win64/):
#   rz_libmc7p.dll      MC7+ (S7-1200/1500) arch plugin  -> asm.arch=mc7plus
#   libmc7_arch.dll     classic MC7 arch plugin          -> asm.arch=mc7
#   libmc7_bin.dll      classic MC7 bin loader (0x7070 'pp' containers)
#   dis_mc7plus.exe     standalone MC7+ disassembler CLI (no rizin needed)
#
# Plugin ABI note: the DLL imports from rz_*-0.9.dll-style shippers that
# already sit next to rizin.exe / cutter.exe, so no runtime redistribution
# of rizin DLLs is needed.  rizin resolves the fixed `rizin_plugin` symbol
# exported by every plugin DLL.
set -eu

ZIG="${ZIG:-zig}"
RZ_WIN_SDK="${RZ_WIN_SDK:?set RZ_WIN_SDK to the extracted rizin-windows-shared64 dir}"
OUT="${1:-build-win}"
OUTDIR="$OUT/rz-libmc7p-win64"

TARGET="x86_64-windows-gnu"
INC="-I$RZ_WIN_SDK/include/librz -I$RZ_WIN_SDK/include/librz/sdb -Isrc -Iinclude"
LIBS="$RZ_WIN_SDK/lib/rz_core.lib $RZ_WIN_SDK/lib/rz_arch.lib $RZ_WIN_SDK/lib/rz_util.lib \
$RZ_WIN_SDK/lib/rz_cons.lib $RZ_WIN_SDK/lib/rz_config.lib $RZ_WIN_SDK/lib/rz_io.lib \
$RZ_WIN_SDK/lib/rz_bin.lib $RZ_WIN_SDK/lib/rz_magic.lib"
EXP="-Wl,--export-all-symbols"

mkdir -p "$OUTDIR"

echo "[*] rz_libmc7p.dll (MC7+ arch plugin)"
"$ZIG" cc -target $TARGET -O2 -shared $EXP $INC \
        src/mc7plus_isa.c src/mc7plus.c src/plugin_arch_mc7plus.c \
        $LIBS -o "$OUTDIR/rz_libmc7p.dll"

echo "[*] libmc7_arch.dll (classic MC7 arch plugin)"
"$ZIG" cc -target $TARGET -O2 -shared $EXP $INC \
        src/simatic.c src/plugin_arch.c \
        $LIBS -o "$OUTDIR/libmc7_arch.dll"

echo "[*] libmc7_bin.dll (classic MC7 bin plugin)"
"$ZIG" cc -target $TARGET -O2 -shared $EXP $INC \
        src/simatic.c src/plugin_bin.c \
        $LIBS -o "$OUTDIR/libmc7_bin.dll"

echo "[*] dis_mc7plus.exe (standalone CLI, no rizin dependency)"
"$ZIG" cc -target $TARGET -O2 $INC \
        unit/dis_mc7plus.c src/mc7plus_isa.c src/mc7plus.c \
        -o "$OUTDIR/dis_mc7plus.exe"

echo "[+] done: $OUTDIR"
