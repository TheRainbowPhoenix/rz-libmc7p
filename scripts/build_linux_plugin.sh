#!/bin/sh
# Build the libmc7 rizin plugins + standalone CLI for Linux x64 and package
# a self-contained install tree.
#
# Requirements:
#   - gcc/clang, pkg-config, meson >= 0.61, ninja
#   - rizin installed with the SAME version the plugin will be loaded by
#     (plugin ABI + RZ_VERSION must match, e.g. v0.9.1).  Its pkg-config
#     files (rz_core.pc ...) must be findable; set RZ_PREFIX to the rizin
#     install prefix (default /usr/local).
#
# Usage:
#   RZ_PREFIX=/usr/local sh scripts/build_linux_plugin.sh [outdir]
#
# Outputs (in <outdir>/rz-libmc7p-linux64/):
#   rz_libmc7p.so      MC7+ (S7-1200/1500) arch plugin  -> asm.arch=mc7plus
#   libmc7_arch.so     classic MC7 arch plugin          -> asm.arch=mc7
#   libmc7_bin.so      classic MC7 bin loader (0x7070 'pp' containers)
#   dis_mc7plus        standalone MC7+ disassembler CLI (no rizin needed)
#   install.sh         copies the plugins into the rizin plugdir
#   README_LINUX.md    install + usage instructions
set -eu

RZ_PREFIX="${RZ_PREFIX:-/usr/local}"
OUT="${1:-dist}"
OUTDIR="$OUT/rz-libmc7p-linux64"
BUILDDIR="build-linux"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# ---- locate rizin's pkg-config files (Debian multiarch aware) -------------
PKG_DIRS="$RZ_PREFIX/lib/pkgconfig"
for d in "$RZ_PREFIX"/lib/*/pkgconfig; do
        [ -d "$d" ] && PKG_DIRS="$PKG_DIRS:$d"
done
if [ -n "${PKG_CONFIG_PATH:-}" ]; then
        PKG_CONFIG_PATH="$PKG_CONFIG_PATH:$PKG_DIRS"
else
        PKG_CONFIG_PATH="$PKG_DIRS"
fi
export PKG_CONFIG_PATH

if ! pkg-config --exists rz_core; then
        echo "ERROR: rz_core.pc not found under $RZ_PREFIX." >&2
        echo "       Set RZ_PREFIX to your rizin install prefix, e.g.:" >&2
        echo "         RZ_PREFIX=\$(dirname \$(dirname \$(which rizin))) \\" >&2
        echo "             sh scripts/build_linux_plugin.sh dist" >&2
        exit 1
fi
RZ_VERSION=$(pkg-config --modversion rz_core)
echo "[*] building against rizin $RZ_VERSION at $RZ_PREFIX"

# ---- build ----------------------------------------------------------------
RECONF=""
[ -d "$BUILDDIR" ] && RECONF="--reconfigure"
meson setup "$BUILDDIR" -Dbuild_shared_libs=true --prefix="$RZ_PREFIX" $RECONF
ninja -C "$BUILDDIR"

# ---- package --------------------------------------------------------------
mkdir -p "$OUTDIR"
cp "$BUILDDIR/rz_libmc7p.so" "$OUTDIR/"
cp "$BUILDDIR/liblibmc7_arch.so" "$OUTDIR/libmc7_arch.so"
cp "$BUILDDIR/liblibmc7_bin.so" "$OUTDIR/libmc7_bin.so"
cp "$BUILDDIR/dis_mc7plus" "$OUTDIR/"
cp "$HERE/install_linux.sh" "$OUTDIR/install.sh"
[ -f "$HERE/../README_LINUX.md" ] && cp "$HERE/../README_LINUX.md" "$OUTDIR/"
chmod +x "$OUTDIR"/dis_mc7plus "$OUTDIR"/install.sh

echo "[+] packaged: $OUTDIR"
ls -l "$OUTDIR"
