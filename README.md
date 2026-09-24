<h1 align="center">
  <img src="assets/logo.svg#gh-light-mode-only" width="144px"/><br/>
  <img src="assets/logo.svg#gh-dark-mode-only" width="144px"/><br/>
</h1>

# Rizin MC7+ disassembler

A Rizin/Cutter plugin for disassembling and assembling **MC7+ bytecode** used by Siemens SIMATIC S7-1200 and S7-1500 PLCs. It adds MC7+ alongside the original classic MC7 (S7-300/400) decoder.

## Get started in Cutter (Windows)

Download the prebuilt **Windows x64** plugin below. You don't need to build the project.

<a href="https://github.com/TheRainbowPhoenix/rz-libmc7p/releases/download/mc7p-rolling/rz-libmc7p-win64.zip">
  <img src="assets/download-windows.svg" alt="Download MC7+ plugin for Windows (64-bit ZIP)" width="420">
</a>

1. Click **Download for Windows** and extract the ZIP.
2. Copy the plugin DLLs (`rz_libmc7p.dll`, `libmc7_arch.dll`, `libmc7_bin.dll`) into the folder below. You can paste the path directly into **File Explorer's address bar**; create the folder if necessary:

   ```text
   %USERPROFILE%\.local\lib\rizin\plugins\
   ```

3. Restart Cutter. When opening an MC7+ binary, select **`mc7plus`** as the architecture (not `mc7`):

<img width="687" height="282" alt="Select the mc7plus architecture when opening a file in Cutter" src="https://github.com/user-attachments/assets/ab229bd8-8746-456a-903a-289e7b2ac63a" />

> **Version compatibility:** The DLLs must be built against the same Rizin version as your installed Rizin/Cutter. For example, Cutter 2.5.0 bundles Rizin 0.9.1. If a plugin does not load, check the versions first.

## What you can do

- **Disassemble and edit MC7+** directly in Cutter. The plugin enables **Edit → Instruction**, letting you assemble your own MC7+ instructions on the fly to patch code.
- **Navigate more easily:** improved mnemonic listings, searching and autocomplete. Jump to labels from the address bar.
- **Follow control flow:** jump arrows are supported in graph view.

### Graph view

Control-flow graphs show supported jump arrows:

<img width="1105" height="838" alt="MC7+ control-flow graph view in Cutter" src="https://github.com/user-attachments/assets/bd9e8dff-2438-449d-80ae-8e9dc685d759" />

### Disassembly view

Browse, search, navigate and edit MC7+ instructions:

<img width="744" height="833" alt="MC7+ disassembly view in Cutter" src="https://github.com/user-attachments/assets/ccc30e13-ccd6-4e30-9104-39ae0dc77132" />

## MC7+ support

The original plugin decodes classic MC7 (S7-300/400-style wire format, `pp` container). This fork adds MC7+ as a separate architecture. Because raw byte streams can be ambiguous, **select `mc7plus` explicitly** (`e asm.arch=mc7plus` in Rizin); `mc7` remains the classic dialect.

The recovered decoder covers immediates (including int/real forms), direct and indirect memory operands, native slots and pointers, DB addressing, in-operation type encodings, instruction flags and repeated-parameter MUX/JL forms.

### Installation on Linux

See [README_LINUX.md](README_LINUX.md) for prebuilt CI artifacts (`rz-libmc7p-linux64`), installation, building from source, plugin paths, Cutter AppImage and troubleshooting.

Without install rights, put `rz_libmc7p.so` in `~/.local/lib/rizin/plugins/` or point `RZ_LIB_PLUGINS` to a directory containing it.

## Building from source

**Standalone decoder (no Rizin required):**

```sh
meson -Dbuild_shared_libs=false build && ninja -C build
./build/dis_mc7plus tests/corpus/bins2/mc7plus-lab2.AddMul@1_FC17.bin
# NOP
# LABEL 0
# MOVE :Word @SL.Slot16.0 0
# ...
```

**Rizin plugin on Linux:** The shared library is installed to the Rizin plugin directory reported by pkg-config.

```sh
PKG_CONFIG_PATH=<rizin prefix>/lib/x86_64-linux-gnu/pkgconfig \
    meson setup build-plugin -Dbuild_shared_libs=true --prefix=<rizin prefix>
ninja -C build-plugin && meson install -C build-plugin
```

**Windows x64 cross-build** (zig cc and the official Rizin shared ZIP):

```sh
RZ_WIN_SDK=<extracted rizin-windows-shared64-v<VER>> \
    sh scripts/build_win_plugin.sh out/
# out/rz-libmc7p-win64/ contains rz_libmc7p.dll, libmc7_arch.dll,
# libmc7_bin.dll and dis_mc7plus.exe
```

Rizin checks `RZ_VERSION` when loading plugins, so build against your target Rizin version. Rizin resolves the `rizin_plugin` export symbol; the filename is not itself the plugin identifier.

### Code layout and tests

- `src/mc7plus_isa.{h,c}`: generated ISA tables (456 ops, 1869 wire-order parameter descriptors). Regenerate from the vendored zymatik reference with `python3 tools/gen_mc7plus_isa.py`.
- `src/mc7plus.{h,c}`: decoder and assembler-text renderer, a C port of the zymatik Python reference (`asm/disasm.py` and `asm/text.py`).
- `unit/dis_mc7plus.c`: standalone disassembly CLI; no Rizin required.
- `unit/test_mc7plus.c`: reference-generated test vectors, run with `ninja -C build test`.
- `scripts/diff_mc7plus_corpus.py`: differential testing against the zymatik Python disassembler; 113/113 corpus files matched statement-for-statement (bins2 38, mc7 corpus 67, mc7asm fixtures 8).
- `scripts/diff_mc7plus_rizin.py`: checks actual `rizin -a mc7plus pD` output against `dis_mc7plus` (validated on Rizin 0.9.1).

## Roadmap

- [ ] Cross-references (xrefs)
- [ ] Register profile for slots and locals
- [ ] RzIL support (long-term)
- [ ] VM debugger support (much longer-term)

## Research status and contributions

Newer Siemens PLCs use MC7+ bytecode, related to classic MC7, with an Adonis JIT translation path. Exploration of the Adonis JIT VM is ongoing; this repository will be updated as major findings emerge. The MC7+ VM, compiler, assembler, linker and SPS7-OMS+ bytecode dumper are maintained in a separate repository.

Have access to an S7-1200/1500 and want to help capture samples, a newer PLC bootloader, or knowledge about Adonis? Please [open an issue](https://github.com/TheRainbowPhoenix/rz-libmc7p/issues).
