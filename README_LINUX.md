# Installing on Linux (rizin / Cutter)

This directory builds two kinds of Linux artifacts:

| file | what it is |
|------|------------|
| `rz_libmc7p.so`      | **MC7+** (S7-1200/1500) arch + analysis plugin -- `e asm.arch=mc7plus`; full operand decoding, typed mnemonics, colored tokens, LABEL functions, jump arrows |
| `libmc7_arch.so`     | classic **MC7** (S7-300/400) arch plugin -- `e asm.arch=mc7` |
| `libmc7_bin.so`      | classic MC7 bin loader (0x7070 `pp` containers) |
| `dis_mc7plus`        | standalone MC7+ disassembler CLI, **no rizin needed** |

**Version rule:** a rizin plugin must be built against the SAME rizin version
it is loaded by (ABI + `RZ_VERSION` check at load). All plugin artifacts are
built against **rizin v0.9.1** -- the version bundled by Cutter 2.5.0. If
your rizin is older/newer, rebuild the plugin from source against it
(section 2).

---

## 1. Install from the CI artifact (`rz-libmc7p-linux64`)

The CI builds and uploads a ready-to-use artifact on every push. It is
compiled on `ubuntu-latest` (glibc >= 2.39); for older distros use section 2.

```sh
unzip rz-libmc7p-linux64.zip -d mc7p
cd mc7p/rz-libmc7p-linux64

# a) automatic: copies into rizin's per-user plugdir (no root needed)
sh install.sh

# or b) manual: explicit directory
sh install.sh ~/.local/lib/x86_64-linux-gnu/rizin/plugins

# or c) no copy at all -- point rizin at the artifact directory:
RZ_LIB_PLUGINS=$PWD rizin <file>
```

Where the plugins end up -- rizin looks in (in this order):

```
$RZ_LIB_PLUGINS                                  (env var, added first)
~/.local/lib/<multiarch>/rizin/plugins           (user, survives updates)
<prefix>/lib/<multiarch>/rizin/plugins           (system, needs root)
```

Query the exact paths on YOUR machine (multiarch differs between distros):

```sh
rizin -H RZ_USER_PLUGINS     # user plugdir
rizin -H RZ_LIB_PLUGINS      # system plugdir
```

If rizin was built/installed into a non-standard prefix and its libraries
are not picked up when loading the plugin, export the lib dir as well:

```sh
export LD_LIBRARY_PATH=<rizin prefix>/lib:<rizin prefix>/lib/x86_64-linux-gnu
```

## 2. Build from source

Requirements: `gcc`, `pkg-config`, `meson >= 0.61`, `ninja`
(`pip install meson ninja`), and a rizin dev install (its `rz_core.pc`).

### 2a. If you do not have rizin v0.9.1 yet

Distro packages are usually too old; build the exact version first:

```sh
git clone --depth 1 --branch v0.9.1 --recurse-submodules \
    --shallow-submodules https://github.com/rizinorg/rizin.git
meson setup rzbuild rizin -Ddefault_library=shared --prefix=$HOME/.local
ninja -C rzbuild && ninja -C rzbuild install
export PATH="$HOME/.local/bin:$PATH"
```

### 2b. One-shot: build + package (same artifact the CI produces)

```sh
RZ_PREFIX=$(dirname $(dirname $(which rizin))) \
    sh scripts/build_linux_plugin.sh dist
# -> dist/rz-libmc7p-linux64/{rz_libmc7p.so,libmc7_arch.so,libmc7_bin.so,
#                             dis_mc7plus,install.sh,README_LINUX.md}
sh dist/rz-libmc7p-linux64/install.sh
```

### 2c. Or the plain meson flow

```sh
# point pkg-config at the rizin you will load the plugin with
export RZ_PREFIX=$(dirname $(dirname $(which rizin)))
export PKG_CONFIG_PATH=$RZ_PREFIX/lib/pkgconfig:$RZ_PREFIX/lib/*/pkgconfig

meson setup build-plugin -Dbuild_shared_libs=true --prefix=$RZ_PREFIX
ninja -C build-plugin

# installs the .so files into rizin's plugdir (no root needed when the
# prefix is yours; add sudo otherwise)
meson install -C build-plugin
# or copy by hand:
#   cp build-plugin/rz_libmc7p.so ~/.local/lib/x86_64-linux-gnu/rizin/plugins/
```

`-Dbuild_shared_libs=false` builds only the rizin-independent parts
(`dis_mc7plus` CLI + unit tests) -- useful when you only want the CLI.

## 3. Cutter (Linux)

Cutter bundles its own rizin, so the plugin must match THAT version
(Cutter 2.5.0 bundles rizin v0.9.1 -- the artifact from section 1 matches).
Two ways:

- **Env var (no modification of the AppImage):** point `RZ_LIB_PLUGINS` at
  a directory containing the three `.so` files and launch Cutter from that
  shell. Cutter's embedded rizin honors the same env var.

  ```sh
  RZ_LIB_PLUGINS=~/mc7p/rz-libmc7p-linux64 cutter
  ```

- **AppImage, permanent install:** extract the AppImage and drop the
  plugins into the bundled rizin plugdir:

  ```sh
  ./Cutter-*.AppImage --appimage-extract          # -> squashfs-root/
  PLUGDIR=$(find squashfs-root -type d -name plugins -path '*rizin*' | head -1)
  cp rz-libmc7p-linux64/*.so "$PLUGDIR/"
  ./squashfs-root/AppRun                          # run the extracted build
  ```

  If the plugin is not picked up, check `Help -> About` for the bundled
  rizin version and rebuild the plugin against it (section 2).

## 4. Verify

Self-contained smoke test (no corpus needed, embeds a known MC7+ blob):

```sh
python3 scripts/smoke_rizin_plugin.py dist/rz-libmc7p-linux64
```

Manual check with any raw MC7+ blob (e.g. `AddMul@1_FC17.bin`):

```sh
rizin -q -n -a mc7plus -b 32 -c 'e asm.tabs=0; pD 32' AddMul@1_FC17.bin
```

Expected (typed operands, `LABEL<n>();` function markers, JMP arrow):

```
            0x00000000      NOP
┌ LABEL0();
            0x00000001      LABEL 0
            0x00000003      MOVE :Word @SL.Slot16.0 0
        ┌─< 0x00000008      JMP 1
┌ LABEL1();
        └─> 0x0000000a      LABEL 1
            0x0000000c      ADD :Int @SL.Slot16.0 @SB.Slot16.1 @SB.Slot16.2
            0x00000015      MUL :Int @SB.Slot16.0 @SL.Slot16.0 @SB.Slot16.3
            0x0000001e      RET TRUE
```

Colors in the terminal: `e scr.color=1` (mnemonic by instruction type,
slot refs, numbers, type tags) -- inside Cutter the same tokens follow the
active theme.

## 5. Uninstall

Remove the three `.so` files from the plugdir they were installed to:

```sh
rm $(rizin -H RZ_USER_PLUGINS)/{rz_libmc7p.so,libmc7_arch.so,libmc7_bin.so}
```

## Troubleshooting

- **Plugin loads but `asm.arch=?` has no mc7plus** -- the file was not
  loaded: check the path in `rizin -H RZ_USER_PLUGINS`, and that the
  plugin was built for the same rizin version (`rizin -v` vs. the version
  the artifact/README states).
- **`RZ_VERSION mismatch` warning on start** -- host rizin and plugin were
  built against different versions; rebuild per section 2.
- **`cannot open shared object file librz_core...`** -- rizin's libraries
  are not in the loader path; `export LD_LIBRARY_PATH=<rizin prefix>/lib`
  (see section 1).
