# Rizin MC7+ disassembler 

Library to disassemble MC7+ bytecode for Siemens PLC SIMATIC S7-1200 and S7-1500

**this is based on a MC7 disassembler. newer Siemens plc use a MC7+ bytecode similar to the old MC7, but have a jit VM transpiler in Adonis to make it much faster to run. the jit VM is still wip exploration, and this repo would be updated once major findings have been done. Please note that the MC7+ byte code vm, MC7+ compiler, MC7+ assembler, MC7+ linker ans SPS7-OMS+ byte code dumper are part of a separate repository**

**if you have access to a real PLC (s7-1200 or 1500) and want to help dumping its content, if you have a bootloader of a new plc, or if you wish to help reversing more about Adonis, please open an issue in this repo**

below is the original readme:

**please report any bug. this is experimental for now**

## Install

```bash
meson build
ninja -C build
sudo ninja -C build install
```

## Usage

```
$ rizin sample.mc7.bin
[0x00000000]> e asm.arch=mc7
[0x00000000]> pd 5 @ 0x24
0x00000024                 600d  +D
0x00000026                 6009  -D
0x00000028                 600a  *D
0x0000002a                 600e  /D
0x0000002c                 6001  MOD
```
