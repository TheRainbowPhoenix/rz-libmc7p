# Rizin MC7+ disassembler

Library to disassemble MC7+ bytecode for Siemens PLC SIMATIC S7-1200 and S7-1500

<img width="687" height="282" alt="image" src="https://github.com/user-attachments/assets/ab229bd8-8746-456a-903a-289e7b2ac63a" />

<img width="1105" height="838" alt="image" src="https://github.com/user-attachments/assets/bd9e8dff-2438-449d-80ae-8e9dc685d759" />


<img width="1319" height="247" alt="image" src="https://github.com/user-attachments/assets/326a8e31-3f88-496e-ad24-84e8dbd50c4b" />


## MC7+ support (this fork)

The original plugin disassembles classic MC7 (S7-300/400 style wire, `pp`
container).  This copy adds **MC7+**, the S7-1200/1500 bytecode executed by
the Adonis JIT VM, as a second decoder that coexists with the classic one:

- `src/mc7plus_isa.{h,c}`  -- generated ISA tables (456 ops, 1869 wire-order
  parameter descriptors).  Regenerate from the vendored zymatik reference
  with `python3 tools/gen_mc7plus_isa.py`.
- `src/mc7plus.{h,c}`      -- decoder + assembler-text renderer, faithful C
  port of the zymatik python reference (`asm/disasm.py` + `asm/text.py`).
- `unit/dis_mc7plus.c`     -- standalone CLI, no rizin needed:

```
meson -Dbuild_shared_libs=false build && ninja -C build
./build/dis_mc7plus tests/corpus/bins2/mc7plus-lab2.AddMul@1_FC17.bin
NOP
LABEL 0
MOVE :Word @SL.Slot16.0 0
...
```

- `unit/test_mc7plus.c`    -- vectors generated from the reference decoder;
  runs in CI (`ninja -C build test`).
- `scripts/diff_mc7plus_corpus.py` -- differential harness against the
  zymatik python disasm over the whole corpus: 113/113 files match
  statement-for-statement (bins2 38, mc7 corpus 67, mc7asm fixtures 8).
- rizin: with the shared libs (`-Dbuild_shared_libs=true`) the MC7+ arch
  plugin `rz_libmc7p` is installed -- `e asm.arch=mc7plus`
  (`mc7` remains the classic dialect; a raw blob is ambiguous between the
  two ISAs, so pick the arch explicitly).

### Installing the plugin into a real rizin / Cutter

**Linux:** see [README_LINUX.md](README_LINUX.md) -- covers the CI artifact
(`rz-libmc7p-linux64`) + `install.sh`, building from source, plugin search
paths (`rizin -H RZ_USER_PLUGINS`), Cutter AppImage and troubleshooting.

Quick commands (Linux, plugin `.so` lands in the rizin plugdir reported by
pkg-config):

```
PKG_CONFIG_PATH=<rizin prefix>/lib/x86_64-linux-gnu/pkgconfig \
    meson setup build-plugin -Dbuild_shared_libs=true --prefix=<rizin prefix>
ninja -C build-plugin && meson install -C build-plugin
```

Without install rights, drop `rz_libmc7p.so` into `~/.local/lib/rizin/plugins/`
or point `RZ_LIB_PLUGINS` at any directory holding it.  On Windows the DLL
goes to `%USERPROFILE%\.local\lib\rizin\plugins\` (same lookup for the
rizin.exe shipped inside Cutter) or any dir set via `RZ_LIB_PLUGINS`.

Windows x64 cross-build (zig cc against the official shared zip):

```
RZ_WIN_SDK=<extracted rizin-windows-shared64-v<VER>> \
    sh scripts/build_win_plugin.sh out/
# -> out/rz-libmc7p-win64/{rz_libmc7p.dll,libmc7_arch.dll,libmc7_bin.dll,
#                         dis_mc7plus.exe}
```

The DLL must be built against the SAME rizin version as the host: Cutter
2.5.0 bundles rizin v0.9.1 (rizin checks RZ_VERSION at plugin load).
rizin resolves the fixed `rizin_plugin` export symbol, so the file name
only matters for your own bookkeeping.

### Validating the plugin inside real rizin

`scripts/diff_mc7plus_rizin.py` drives a real `rizin -a mc7plus pD` process
per corpus file and diffs the statement text against the standalone
`dis_mc7plus` (validated on rizin v0.9.1).

The MC7+ decoder covers the full recovered operand grammar: immediates
(tiny/-1/ANY/int/real incl. the bare-`30` 0.0-vs-trimmed ambiguity),
memory (direct 0x60/0x80 + address-style 0xA0), native slots/pointers
(0x40/0x58/system 0x08), DB direct/extended (0xA8/0xC0/0xD0/0xB0/0xB8),
indirect (0xE0/0xE8/0xF0/0xF8), in-operation type codings, flag bits
(COND/ENO/STW/NOINT/NEGATED) and the MUX/JL repeated-parameter forms.

**this is based on a MC7 disassembler. newer Siemens plc use a MC7+ bytecode similar to the old MC7, but have a jit VM transpiler in Adonis to make it much faster to run. the jit VM is still wip exploration, and this repo would be updated once major findings have been done. Please note that the MC7+ byte code vm, MC7+ compiler, MC7+ assembler, MC7+ linker ans SPS7-OMS+ byte code dumper are part of a separate repository**

**if you have access to a real PLC (s7-1200 or 1500) and want to help dumping its content, if you have a bootloader of a new plc, or if you wish to help reversing more about Adonis, please open an issue in this repo**

