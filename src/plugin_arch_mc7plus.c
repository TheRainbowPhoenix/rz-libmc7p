// SPDX-License-Identifier: LGPL-3.0-only
/*
 * MC7+ (S7-1200/1500) rizin arch plugin.
 *
 * Mirrors the classic-mc7 plugin pair (plugin_asm.c + plugin_analysis.c
 * wrapped by plugin_arch.c) but drives the MC7+ decoder (mc7plus.c).
 * Select in rizin with:
 *
 *     e asm.arch=mc7plus
 *
 * Classic MC7 stays available as asm.arch=mc7; the two dialects coexist.
 * Note: a raw code blob is ambiguous between the two ISAs -- pick the
 * arch explicitly (the 0x7070 'pp' container of classic MC7 blocks is
 * detected by the mc7 bin plugin).
 *
 * QoL features beyond raw text:
 *  - asm_toks: mnemonic + number tokens are handed to rizin so the GUI
 *    (Cutter included) colorizes the mnemonic by instruction type
 *    (jumps/branches/calls/rets/math...) and highlights numbers.
 *  - the analysis plugin classifies JMP/JMP_* (label targets), CALL_*
 *    and RET statements, resolving jump label ids to in-blob addresses
 *    so Cutter draws jump arrows for them.
 */
#include <rz_arch.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_types.h>
#include <rz_vector.h>

#include "mc7plus.h"

#define MC7P_ASM_BUF 256

/* Maximum statements scanned when resolving a jump label target. */
#define MC7P_LABEL_SCAN_MAX 4096

/* ----------------------------------------------------- opcode semantics */

/* Map a statement (flow class + rendered name) to the rizin analysis op
 * type.  The same mapping drives the mnemonic COLOR (asm_toks->op_type)
 * and the analysis semantics (arrows, block ends). */
static ut32 mc7p_op_type(const mc7p_flow_t *flow, const char *name) {
        switch (flow->kind) {
        case MC7P_FLOW_JMP:
                return RZ_ANALYSIS_OP_TYPE_JMP;
        case MC7P_FLOW_CJMP:
                return RZ_ANALYSIS_OP_TYPE_CJMP;
        case MC7P_FLOW_CALL:
                return RZ_ANALYSIS_OP_TYPE_UCALL; /* target is a block index */
        case MC7P_FLOW_RET:
                return RZ_ANALYSIS_OP_TYPE_RET;
        case MC7P_FLOW_LABEL:
                return RZ_ANALYSIS_OP_TYPE_NOP;
        default:
                break;
        }
        if (name) {
                /* arithmetic / logic mnemonics -> matching palette colors */
                if (!strncmp(name, "MOVE", 4)) {
                        return RZ_ANALYSIS_OP_TYPE_MOV;
                }
                if (!strncmp(name, "ADD", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_ADD;
                }
                if (!strncmp(name, "SUB", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_SUB;
                }
                if (!strncmp(name, "MUL", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_MUL;
                }
                if (!strncmp(name, "DIV", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_DIV;
                }
                if (!strncmp(name, "MOD", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_MOD;
                }
                if (!strncmp(name, "AND", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_AND;
                }
                if (!strncmp(name, "OR", 2)) {
                        return RZ_ANALYSIS_OP_TYPE_OR;
                }
                if (!strncmp(name, "XOR", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_XOR;
                }
                if (!strncmp(name, "NOT", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_NOT;
                }
                if (!strncmp(name, "NEG", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_NOT;
                }
                if (!strncmp(name, "CMP", 3) || strstr(name, "_CMP") ||
                    !strncmp(name, "LD_CMP", 6)) {
                        return RZ_ANALYSIS_OP_TYPE_CMP;
                }
                if (!strncmp(name, "CONVERT", 7) || !strncmp(name, "ROUND", 5) ||
                    !strncmp(name, "TRUNC", 5) || !strncmp(name, "FLOOR", 5) ||
                    !strncmp(name, "CEIL", 4)) {
                        return RZ_ANALYSIS_OP_TYPE_CAST;
                }
                if (!strncmp(name, "NOP", 3)) {
                        return RZ_ANALYSIS_OP_TYPE_NOP;
                }
        }
        return RZ_ANALYSIS_OP_TYPE_UNK;
}

/* Rendered name without the trailing "{FLAG,...}" suffix. */
static void mc7p_base_name(const char *asm_str, char *out, size_t outlen) {
        size_t i;
        for (i = 0; asm_str[i] && asm_str[i] != ' ' && asm_str[i] != '{' &&
                    i + 1 < outlen;
             i++) {
                out[i] = asm_str[i];
        }
        out[i] = 0;
}

/* --------------------------------------------------- asm token colorizing */

static void mc7p_push_tok(RzAsmTokenString *toks, size_t start, size_t len,
                          RzAsmTokenType type, ut64 num) {
        RzAsmToken *t = RZ_NEW0(RzAsmToken);
        if (!t) {
                return;
        }
        t->start = start;
        t->len = len;
        t->type = type;
        t->val.number = num;
        rz_pvector_push(toks->tokens, t);
}

/* Tokenize the rendered statement for rizin's colorizer: the mnemonic
 * (colored by op type) and every decimal run (label ids, immediates;
 * matched against the highlight address).  Operands such as
 * @SL.Slot16.0 / [@PB.4 + 8] keep the default color. */
static void mc7p_fill_toks(RzAsmOp *op, ut32 op_type) {
        const char *s = rz_asm_op_get_asm(op);
        RzAsmTokenString *toks;
        size_t i, n, mlen;

        if (!s) {
                return;
        }
        toks = rz_asm_token_string_new(s);
        if (!toks) {
                return;
        }
        n = strlen(s);
        mlen = 0;
        while (mlen < n && s[mlen] != ' ') {
                mlen++;
        }
        if (mlen > 0) {
                mc7p_push_tok(toks, 0, mlen, RZ_ASM_TOKEN_MNEMONIC, 0);
        }
        for (i = mlen; i < n; i++) {
                if (s[i] >= '0' && s[i] <= '9') {
                        size_t j = i;
                        ut64 v = 0;
                        while (j < n && s[j] >= '0' && s[j] <= '9') {
                                v = v * 10 + (ut64)(s[j] - '0');
                                j++;
                        }
                        mc7p_push_tok(toks, i, j - i, RZ_ASM_TOKEN_NUMBER, v);
                        i = j - 1;
                }
        }
        toks->op_type = op_type;
        op->asm_toks = toks;
}

static int disassemble_mc7plus(const RzAsm *a, RzAsmOp *op, const ut8 *buf,
                               int len) {
        char asm_buf[MC7P_ASM_BUF];
        char name[48];
        mc7p_flow_t flow;
        ut32 op_type;
        int read = mc7p_disassemble_one(buf, (size_t)len, asm_buf,
                                        sizeof(asm_buf), NULL);
        if (read < 0) {
                rz_asm_op_set_asm(op, "invalid");
                op->size = 1;
                return op->size;
        }
        rz_asm_op_set_asm(op, asm_buf);
        op->size = read;
        if (mc7p_flow_one(buf, (size_t)len, 0, &flow) >= 0) {
                mc7p_base_name(asm_buf, name, sizeof(name));
                op_type = mc7p_op_type(&flow, name);
        } else {
                op_type = RZ_ANALYSIS_OP_TYPE_UNK;
        }
        mc7p_fill_toks(op, op_type);
        return op->size;
}

static RzAsmPlugin rz_asm_plugin_mc7plus = {
        .name = "mc7plus",
        .desc = "Simatic S7-1200/1500 MC7+ disassembler",
        .license = "LGPL",
        .author = "xania.fr glm",
        .arch = "mc7plus",
        .cpus = "s7-1200,s7-1500",
        .bits = 32,
        .endian = RZ_SYS_ENDIAN_BIG,
        .disassemble = &disassemble_mc7plus,
};

/* ------------------------------------------------------------- analysis */

/* Scan forward from off for the LABEL statement carrying id.
 * Returns its offset, or -1. */
static int mc7p_resolve_label(const ut8 *data, int len, int off, long id) {
        int steps = 0;
        while (off < len && steps++ < MC7P_LABEL_SCAN_MAX) {
                mc7p_flow_t f;
                int n = mc7p_flow_one(data, (size_t)len, (size_t)off, &f);
                if (n < 0) {
                        return -1;
                }
                if (f.kind == MC7P_FLOW_LABEL && f.label_id == id) {
                        return off;
                }
                off += n;
        }
        return -1;
}

static int analysis_op_mc7plus(RzAnalysis *analysis, RzAnalysisOp *op,
                               ut64 addr, const ut8 *data, int len,
                               RzAnalysisOpMask mask) {
        char asm_buf[MC7P_ASM_BUF];
        char name[48];
        mc7p_flow_t flow;
        int is_return = 0;
        int read = mc7p_disassemble_one(data, (size_t)len, asm_buf,
                                        sizeof(asm_buf), &is_return);
        if (read <= 0) {
                return op->size;
        }
        op->size = read;
        op->eob = is_return;
        if (mc7p_flow_one(data, (size_t)len, 0, &flow) < 0) {
                return op->size;
        }
        mc7p_base_name(asm_buf, name, sizeof(name));
        op->type = mc7p_op_type(&flow, name);
        switch (flow.kind) {
        case MC7P_FLOW_JMP:
        case MC7P_FLOW_CJMP:
                op->eob = true;
                if (flow.kind == MC7P_FLOW_CJMP) {
                        op->fail = addr + read;
                }
                if (flow.label_id >= 0) {
                        int loff = mc7p_resolve_label(data, len, read,
                                                      flow.label_id);
                        if (loff >= 0) {
                                op->jump = addr + loff;
                        }
                }
                break;
        case MC7P_FLOW_RET:
                op->eob = true;
                break;
        default:
                break;
        }
        return op->size;
}

static int archinfo_mc7plus(RzAnalysis *a, RzAnalysisInfoType q) {
        switch (q) {
        case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
                return 1;
        case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
                return 64;
        case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
                /* fall-thru */
        case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
                return 0;
        case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
                return true;
        default:
                return -1;
        }
}

static RzAnalysisPlugin rz_analysis_plugin_mc7plus = {
        .name = "mc7plus",
        .desc = "Simatic S7-1200/1500 MC7+ analysis plugin",
        .arch = "mc7plus",
        .license = "LGPL3",
        .bits = 32,
        .archinfo = archinfo_mc7plus,
        .op = &analysis_op_mc7plus,
};

static RzArchPlugin rz_arch_plugin_mc7plus = {
        .p_asm = &rz_asm_plugin_mc7plus,
        .p_analysis = &rz_analysis_plugin_mc7plus,
        .p_parse = NULL,
};

RZ_API RzLibStruct rizin_plugin = {
        .type = RZ_LIB_TYPE_ARCH,
        .data = &rz_arch_plugin_mc7plus,
        .version = RZ_VERSION
};
