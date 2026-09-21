#!/bin/sh
# Install the rz-libmc7 plugin files into a rizin plugin directory.
#
# Usage:
#   sh install.sh [plugdir]
#
# Without an argument the target directory is picked automatically:
#   1. $RZ_USER_PLUGINS  (rizin's per-user plugdir, e.g.
#                         ~/.local/lib/x86_64-linux-gnu/rizin/plugins)
#   2. $RZ_LIB_PLUGINS   (rizin's system plugdir, needs write rights)
#
# The plugin files must sit next to this script (as in the rz-libmc7p-linux64
# artifact): rz_libmc7p.so libmc7_arch.so libmc7_bin.so
set -eu

SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for f in rz_libmc7p.so libmc7_arch.so libmc7_bin.so; do
        if [ ! -f "$SRC/$f" ]; then
                echo "ERROR: $SRC/$f not found (run install.sh from the artifact directory)" >&2
                exit 1
        fi
done

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
        if command -v rizin >/dev/null 2>&1; then
                TARGET=$(rizin -H RZ_USER_PLUGINS 2>/dev/null || true)
        fi
        if [ -z "$TARGET" ]; then
                if command -v rizin >/dev/null 2>&1; then
                        TARGET=$(rizin -H RZ_LIB_PLUGINS 2>/dev/null || true)
                fi
        fi
        if [ -z "$TARGET" ]; then
                TARGET="$HOME/.local/lib/rizin/plugins"
                echo "[i] rizin not found on PATH -- falling back to $TARGET" >&2
                echo "    (that is only correct for rizin builds without multiarch libdir)" >&2
        fi
fi

mkdir -p "$TARGET"
if ! cp "$SRC/rz_libmc7p.so" "$SRC/libmc7_arch.so" "$SRC/libmc7_bin.so" "$TARGET/" 2>/dev/null; then
        echo "ERROR: cannot write to $TARGET (permissions?)" >&2
        echo "  try: sudo sh install.sh \"$TARGET\"" >&2
        echo "  or install into your user plugdir: sh install.sh \"\$(rizin -H RZ_USER_PLUGINS)\"" >&2
        exit 1
fi

echo "[+] installed into $TARGET:"
ls -l "$TARGET"/rz_libmc7p.so "$TARGET"/libmc7_arch.so "$TARGET"/libmc7_bin.so
cat <<'EOF'

Verify:
  rizin -q -n -a mc7plus -b 32 -c 'e asm.tabs=0; pD 32' <your MC7+ blob>
  (mc7plus must appear in the output of: rizin -q -c 'e asm.arch=?')
EOF
