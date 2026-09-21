#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Generate MC7+ ISA tables (C) from the zymatik reference implementation.

The zymatik package (../../zymatik, vendored in tia-tools) carries a faithful
port of the decompiled Siemens.Simatic.Lang.Mc7PlusAssembler BinaryCoding
tables.  This script collapses those Python structures into C arrays:

  mc7p_ops[]            one entry per PlusOperator number (name/code/params)
  mc7p_params[]         flat per-op parameter descriptors (wire order)
  mc7p_type_coding[]    (OperandType -> enc) pairs for in-operation codings
  name tables           OperandType / MC7PlusArea / OperandScope /
                        NativeRange / Condition / MC7PlusFlag / ParamMode
  mc7p_type_byte_to_ot  PlusDataType/PlusBlockType byte -> OperandType
  mc7p_relcond_to_cond  PlusRelationsCondition byte -> assembler Condition

Everything numeric is introspected from the zymatik modules so the C decoder
can never drift from the reference.  Regenerate after pulling a new zymatik:

    python3 tools/gen_mc7plus_isa.py            # from the rz-libmc7 root
"""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ZYMATIK = HERE.parent.parent / "zymatik"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zymatik", default=str(DEFAULT_ZYMATIK),
                    help="path to the zymatik package root")
    ap.add_argument("--outdir", default=str(HERE.parent / "src"))
    args = ap.parse_args()

    zroot = Path(args.zymatik).resolve()
    sys.path.insert(0, str(zroot))

    from zymatik.mc7plus.enc_table import PLUS_ENC           # noqa: E402
    from zymatik.mc7plus.opcodes import PlusOperator         # noqa: E402
    from zymatik.mc7plus.asm import operand_type as OT       # noqa: E402
    from zymatik.mc7plus.asm import helper as H              # noqa: E402
    from zymatik.mc7plus.asm.encode import ParamType, ParamMode  # noqa: E402

    # ---- op numbers (name -> num), Python dict-overwrite semantics kept
    op_by_name = {}
    op_max = -1
    for k, v in PlusOperator.__dict__.items():
        if isinstance(v, int) and not k.startswith("_"):
            op_max = max(op_max, v)
            op_by_name[k] = v
    op_count = op_max + 1

    flag_by_name = {n: i for i, n in enumerate(
        ("UNDEF", "NEGATED", "COND", "ENO", "WRITE", "NOINT", "STW"))}

    # ---- collect per-op entries (sorted by op number)
    op_entries = []  # (num, name, entry)
    missing = []
    for name, num in op_by_name.items():
        entry = PLUS_ENC.get(name)
        if entry is None:
            missing.append(name)
            continue
        op_entries.append((num, name, entry))
    op_entries.sort(key=lambda t: t[0])
    row_by_num = {num: (name, entry) for num, name, entry in op_entries}

    # ---- flatten params (exact wire order per op) + codings
    params = []
    codings = []  # (ot_num, enc) pairs
    for num, name, entry in op_entries:
        for p in entry["params"]:
            kind = p[0]
            if kind == "flag":
                params.append({
                    "kind": "FLAG", "flag": flag_by_name[p[1]],
                    "byte_pos": p[2], "bit_pos": p[3]})
            elif kind == "coding":
                pairs = []
                for tn, enc in p[3].items():
                    ot_num = OT.BY_NAME.get(tn)
                    if ot_num is None:
                        raise SystemExit("unknown OperandType %r" % tn)
                    pairs.append(len(codings))
                    codings.append((ot_num, enc))
                params.append({
                    "kind": "CODING", "byte_pos": p[1], "bit_pos": p[2],
                    "coding_off": pairs[0], "coding_len": len(pairs)})
            elif kind == "type":
                params.append({"kind": "TYPE"})
            elif kind == "cond":
                params.append({"kind": "COND"})
            elif kind == "ident":
                _, direction, otn, ref_no, mode_name = p
                ref = ref_no if ref_no is not None else -1
                predef = OT.Undef
                if ref == -1 and otn is not None:
                    predef = OT.BY_NAME.get(otn, OT.Undef)
                mode = ParamMode.by_name(mode_name) if mode_name else \
                    ParamMode.undef
                params.append({
                    "kind": "IDENT", "ref": ref, "predef": predef,
                    "mode": mode})
            else:
                raise SystemExit("unknown table param %r" % (p,))

    # ---- type byte -> OperandType (data-type priority, then block types)
    type_by_pdt = {v: k for k, v in H._DATA_TYPE_MAP.items()}
    type_by_pbt = {v: k for k, v in H._BLOCK_TYPE_MAP.items()}
    type_byte_to_ot = []
    for b in range(64):
        if b in type_by_pdt:
            type_byte_to_ot.append(type_by_pdt[b])
        elif b in type_by_pbt:
            type_byte_to_ot.append(type_by_pbt[b])
        else:
            type_byte_to_ot.append(-1)

    # ---- relcond byte -> assembler Condition value
    relcond_to_cond = []
    for b in range(32):
        name = H.REL_COND_BY_VALUE.get(b)
        relcond_to_cond.append(-1 if name is None
                               else getattr(H.Condition, name))

    # ---- emit header --------------------------------------------------
    out = []
    w = out.append
    w("/* AUTO-GENERATED by tools/gen_mc7plus_isa.py -- DO NOT EDIT.")
    w(" *")
    w(" * Source of truth: the vendored zymatik reference implementation")
    w(" * (port of the decompiled Siemens Mc7PlusAssembler BinaryCoding).")
    w(" * Regenerate with:  python3 tools/gen_mc7plus_isa.py")
    w(" */")
    w("#ifndef LIB_MC7PLUS_ISA_H")
    w("#define LIB_MC7PLUS_ISA_H")
    w("")
    w("#include <stdint.h>")
    w("#include <stddef.h>")
    w("")
    w("#ifdef __cplusplus")
    w("extern \"C\" {")
    w("#endif")
    w("")
    w("/* ---- assembler-side OperandType (zymatik operand_type.py) ---- */")
    w("enum {")
    for name in sorted(OT.BY_NAME, key=lambda n: OT.BY_NAME[n]):
        w("\tMC7P_OT_%s = %d," % (name.upper(), OT.BY_NAME[name]))
    w("\tMC7P_OT_Undef = %d," % OT.Undef)
    w("\tMC7P_OT_NotChosen = %d," % OT.NotChosen)
    w("};")
    w("")
    w("/* ---- MC7PlusFlag ---- */")
    w("enum {")
    for i, n in enumerate(("UNDEF", "NEGATED", "COND", "ENO", "WRITE",
                           "NOINT", "STW")):
        w("\tMC7P_FLAG_%s = %d," % (n, i))
    w("};")
    w("")
    w("/* ---- MC7PlusArea ---- */")
    w("enum {")
    for i, n in enumerate(H.MC7PlusArea.NAMES):
        w("\tMC7P_AREA_%s = %d," % (n.upper(), i))
    w("\tMC7P_AREA_COUNT = %d" % len(H.MC7PlusArea.NAMES))
    w("};")
    w("")
    w("/* ---- OperandScope ---- */")
    w("enum {")
    for i, n in enumerate(H.OperandScope.NAMES[:9]):
        w("\tMC7P_SCOPE_%s = %d," % (n.upper(), i))
    w("\tMC7P_SCOPE_NativeSystem = %d," % H.OperandScope.NativeSystem)
    for i, n in enumerate(H.OperandScope.NAMES[10:]):
        w("\tMC7P_SCOPE_%s = %d," % (n.upper(), 11 + i))
    w("};")
    w("")
    w("/* ---- NativeRange ---- */")
    w("enum {")
    for i, n in enumerate(H.NativeRange.NAMES):
        w("\tMC7P_RANGE_%s = %d," % (n.upper(), i))
    w("};")
    w("")
    w("/* ---- Condition (assembler side) ---- */")
    w("enum {")
    for i, n in enumerate(H.Condition.NAMES):
        w("\tMC7P_COND_%s = %d," % (n, i))
    w("};")
    w("")
    w("/* ---- ParamMode ---- */")
    w("enum {")
    for i, n in enumerate(ParamMode.NAMES):
        w("\tMC7P_MODE_%s = %d," % (n.upper(), i))
    w("};")
    w("")
    w("/* ---- PlusAreaDirect (BinaryCoding byte codings) ---- */")
    w("enum {")
    for i, n in enumerate(("Undef", "I", "Q", "M", "PI", "PO", "L", "TsL")):
        w("\tMC7P_ADIRECT_%s = %d," % (n.upper(), i))
    w("};")
    w("/* ---- PlusLocation ---- */")
    w("enum {")
    for i, n in enumerate(("BIT", "SLOT8", "SLOT16", "SLOT32", "SLOT64",
                           "REAL", "POINTER")):
        w("\tMC7P_LOC_%s = %d," % (n, i))
    w("};")
    w("/* ---- PlusScope ---- */")
    w("enum {")
    for i, n in enumerate(("GLOBAL", "LOCAL", "BLOCK", "CALL")):
        w("\tMC7P_PSCOPE_%s = %d," % (n, i))
    w("};")
    w("")
    w("/* ---- param kinds ---- */")
    w("enum {")
    w("\tMC7P_PARAM_FLAG = 0,")
    w("\tMC7P_PARAM_TYPE,")
    w("\tMC7P_PARAM_COND,")
    w("\tMC7P_PARAM_CODING,")
    w("\tMC7P_PARAM_IDENT")
    w("};")
    w("")
    w("typedef struct {")
    w("\tuint8_t ot;      /* OperandType value */")
    w("\tuint8_t enc;     /* coded bits */")
    w("} mc7p_type_coding_t;")
    w("")
    w("typedef struct {")
    w("\tuint8_t kind;")
    w("\tuint8_t flag_type;       /* FLAG */")
    w("\tuint8_t byte_pos;        /* FLAG | CODING */")
    w("\tuint8_t bit_pos;         /* FLAG | CODING */")
    w("\tuint8_t in_operation;    /* CODING == 1 */")
    w("\tint16_t ref_type;        /* IDENT: type-access index or -1 */")
    w("\tint16_t predefined_type; /* IDENT: OperandType */")
    w("\tuint8_t mode;            /* IDENT: ParamMode */")
    w("\tuint16_t coding_off;     /* CODING: index into coding table */")
    w("\tuint8_t coding_len;      /* CODING: pair count */")
    w("} mc7p_param_t;")
    w("")
    w("typedef struct {")
    w("\tconst char *name;        /* NULL when the op has no table entry */")
    w("\tuint8_t code_len;")
    w("\tuint8_t code[2];")
    w("\tuint8_t multi;           /* HasMultipleParameter (JL/MUX/MUX_2) */")
    w("\tuint16_t param_off;")
    w("\tuint8_t param_count;")
    w("} mc7p_op_t;")
    w("")
    w("#define MC7P_OP_COUNT %d" % op_count)
    w("#define MC7P_PARAM_COUNT %d" % len(params))
    w("#define MC7P_CODING_COUNT %d" % len(codings))
    w("#define MC7P_AREA_NAME_COUNT %d" % len(H.MC7PlusArea.NAMES))
    w("#define MC7P_OT_NAME_COUNT %d" % (OT.NotChosen + 1))
    w("#define MC7P_MAX_OPERANDS 1024")
    w("")
    w("extern const mc7p_op_t mc7p_ops[MC7P_OP_COUNT];")
    w("extern const mc7p_param_t mc7p_params[MC7P_PARAM_COUNT];")
    w("extern const mc7p_type_coding_t "
      "mc7p_type_codings[MC7P_CODING_COUNT];")
    w("extern const char *const mc7p_ot_names[MC7P_OT_NAME_COUNT];")
    w("extern const char *const mc7p_area_names[MC7P_AREA_NAME_COUNT];")
    w("extern const char *const mc7p_scope_names[17];")
    w("extern const char *const mc7p_range_names[8];")
    w("extern const char *const mc7p_cond_names[33];")
    w("extern const char *const mc7p_flag_names[7];")
    w("extern const int16_t mc7p_type_byte_to_ot[64];")
    w("extern const int16_t mc7p_relcond_to_cond[32];")
    w("")
    w("#ifdef __cplusplus")
    w("}")
    w("#endif")
    w("#endif /* LIB_MC7PLUS_ISA_H */")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "mc7plus_isa.h").write_text("\n".join(out) + "\n")

    # ---- emit C -------------------------------------------------------
    out = []
    w = out.append
    w("/* AUTO-GENERATED by tools/gen_mc7plus_isa.py -- DO NOT EDIT. */")
    w('#include "mc7plus_isa.h"')
    w("")
    w("const mc7p_op_t mc7p_ops[MC7P_OP_COUNT] = {")
    flat_i = 0
    for num in range(op_count):
        if num not in row_by_num:
            w("\t{ NULL, 0, {0, 0}, 0, 0, 0 },")
            continue
        name, entry = row_by_num[num]
        cnt = len(entry["params"])
        code = entry["code"]
        cbytes = ",".join("0x%02x" % b for b in code)
        pad = ",0" * (2 - len(code))
        w('\t{ "%s", %d, {%s%s}, %d, %d, %d },' % (
            name, len(code), cbytes, pad, 1 if entry["multi"] else 0,
            flat_i, cnt))
        flat_i += cnt
    w("};")
    w("")
    w("const mc7p_param_t mc7p_params[MC7P_PARAM_COUNT] = {")
    for p in params:
        w("\t{ MC7P_PARAM_%s, %d, %d, %d, %d, %d, %d, %d, %d, %d }," % (
            p["kind"],
            p.get("flag", 0), p.get("byte_pos", 0), p.get("bit_pos", 0),
            1 if p["kind"] == "CODING" else 0,
            p.get("ref", -1), p.get("predef", 0), p.get("mode", 0),
            p.get("coding_off", 0), p.get("coding_len", 0)))
    w("};")
    w("")
    w("const mc7p_type_coding_t mc7p_type_codings[MC7P_CODING_COUNT] = {")
    for ot, enc in codings:
        w("\t{ %d, %d }," % (ot, enc))
    w("};")
    w("")
    w("const char *const mc7p_ot_names[MC7P_OT_NAME_COUNT] = {")
    for i in range(OT.NotChosen + 1):
        n = OT.NAMES.get(i)
        w('\t%s,' % ('"%s"' % n if n else "NULL"))
    w("};")
    w("")
    w("const char *const mc7p_area_names[MC7P_AREA_NAME_COUNT] = {")
    for n in H.MC7PlusArea.NAMES:
        w('\t"%s",' % n)
    w("};")
    w("")
    w("const char *const mc7p_scope_names[17] = {")
    _scope_by_val = ["NULL"] * 17
    for _i, _n in enumerate(H.OperandScope.NAMES[:9]):
        _scope_by_val[_i] = '"%s"' % _n
    _scope_by_val[H.OperandScope.NativeSystem] = '"NativeSystem"'
    for _i, _n in enumerate(H.OperandScope.NAMES[10:]):
        _scope_by_val[11 + _i] = '"%s"' % _n
    for _v in range(17):
        w("\t%s," % _scope_by_val[_v])
    w("};")
    w("")
    w("const char *const mc7p_range_names[8] = {")
    for n in H.NativeRange.NAMES:
        w('\t"%s",' % n)
    w("};")
    w("")
    w("const char *const mc7p_cond_names[33] = {")
    for n in H.Condition.NAMES:
        w('\t"%s",' % n)
    w("};")
    w("")
    w("const char *const mc7p_flag_names[7] = {")
    for n in ("UNDEF", "NEGATED", "COND", "ENO", "WRITE", "NOINT", "STW"):
        w('\t"%s",' % n)
    w("};")
    w("")
    w("const int16_t mc7p_type_byte_to_ot[64] = {")
    for v in type_byte_to_ot:
        w("\t%d," % v)
    w("};")
    w("")
    w("const int16_t mc7p_relcond_to_cond[32] = {")
    for v in relcond_to_cond:
        w("\t%d," % v)
    w("};")

    (outdir / "mc7plus_isa.c").write_text("\n".join(out) + "\n")

    print("generated mc7plus_isa.h/.c: ops=%d (table %d) params=%d "
          "codings=%d missing_enc=%s"
          % (len(op_entries), op_count, len(params), len(codings), missing))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
