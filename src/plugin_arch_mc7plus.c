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
 *  - asm_toks: FULL-coverage tokens (mnemonic, numbers, slot/memory
 *    refs, type tags, flags) are handed to rizin.  With color enabled
 *    rizin renders the text from the token spans only, so every byte
 *    of the statement must be covered by a token; Cutter colorizes
 *    mnemonics by instruction type (jumps/branches/calls/rets/math...)
 *    and highlights slot references, numbers and type tags.
 *  - the analysis plugin classifies JMP/JMP_* (label targets), CALL_*
 *    and RET statements, resolving jump label ids to in-blob addresses
 *    so Cutter draws jump arrows for them.
 *  - LABEL statements are valid jump targets; JMP/JMP_* references to them
 *    split basic blocks inside the analyzed function.
 */
#include <rz_arch.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_types.h>
#include <rz_vector.h>

#include <limits.h>
#include <stdint.h>

#include "mc7plus.h"

#define MC7P_ASM_BUF 256

/* Maximum statements scanned when resolving a jump label target. */
#define MC7P_LABEL_SCAN_MAX 4096

/* Maximum mapped bytes scanned when resolving LABEL targets through rizin IO.
 * MC7+ code blobs in this plugin are normally compact FC/FB bodies; this keeps
 * analysis bounded while still covering long forward/backward arrows. */
#define MC7P_LABEL_SCAN_BYTES (4 * 1024 * 1024)

/* Enough bytes to decode any single MC7+ statement during label scans. */
#define MC7P_LABEL_SCAN_WINDOW 64

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

static bool mc7p_is_ident_char(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '.';
}

static bool mc7p_is_word_char(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_';
}

static bool mc7p_is_digit(char c) {
        return c >= '0' && c <= '9';
}

/* Classify one identifier run (letters/digits/_/#/.).  Slot references
 * (DB1.DBW2), hex / typed immediates (W#16#FF, T#100ms) and boolean
 * literals (TRUE/FALSE) get a dedicated color; everything else keeps
 * the default one.  Returns the offset just past the run. */
static size_t mc7p_tok_ident(RzAsmTokenString *toks, const char *s,
                             size_t n, size_t i) {
        size_t j = i;
        while (j < n && (mc7p_is_word_char(s[j]) || s[j] == '#')) {
                j++;
        }
        /* dotted memory refs like DB5.DBW2 / DBR1.DBX3.1 */
        while (j < n && s[j] == '.' && j + 1 < n && mc7p_is_word_char(s[j + 1])) {
                j++;
                while (j < n && (mc7p_is_word_char(s[j]) || s[j] == '#')) {
                        j++;
                }
        }
        RzAsmTokenType type = RZ_ASM_TOKEN_UNKNOWN;
        ut64 num = 0;
        if (memchr(s + i, '#', j - i)) {
                type = RZ_ASM_TOKEN_NUMBER; /* W#16#FF, L#5, T#100ms, ... */
        } else if (j > i + 1 && s[i] == 'D' && s[i + 1] == 'B' &&
                   mc7p_is_digit(s[i + 2])) {
                type = RZ_ASM_TOKEN_REGISTER; /* DB1.DBW2 family */
        } else if (j - i == 4 && !strncmp(s + i, "TRUE", 4)) {
                type = RZ_ASM_TOKEN_NUMBER;
                num = 1;
        } else if (j - i == 5 && !strncmp(s + i, "FALSE", 5)) {
                type = RZ_ASM_TOKEN_NUMBER;
                num = 0;
        }
        mc7p_push_tok(toks, i, j - i, type, num);
        return j;
}

/* Tokenize the rendered statement for rizin's colorizer.
 *
 * IMPORTANT: when asm_toks is present rizin renders the disasm text
 * from the token spans ONLY (rz_print_colorize_asm_str walks the token
 * list and drops everything between spans), so the tokens must cover
 * the whole string to reproduce the text byte-for-byte.  Span types:
 *   - mnemonic (first word)                  -> MNEMONIC (op-type color)
 *   - :Type tags and {FLAG,...} groups       -> META
 *   - @SL.Slot16.0 / @PSYS.1 / %IW0 / DB refs -> REGISTER
 *   - numeric literals (sign, float, suffix) -> NUMBER
 *   - string literals '...'                  -> META
 *   - everything else (spaces, [], +, , ...) -> UNKNOWN (default color)
 */
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
        while (mlen < n && s[mlen] != ' ' && s[mlen] != '{') {
                mlen++;
        }
        if (mlen > 0) {
                mc7p_push_tok(toks, 0, mlen, RZ_ASM_TOKEN_MNEMONIC, 0);
        }
        i = mlen;
        while (i < n) {
                char c = s[i];
                size_t j;
                if (c == '@') {
                        j = i + 1;
                        while (j < n && mc7p_is_ident_char(s[j])) {
                                j++;
                        }
                        /* @SL.Slot16.0, @SB.Slot16.1, @PSYS.1, ... */
                        mc7p_push_tok(toks, i, j - i, RZ_ASM_TOKEN_REGISTER, 0);
                        i = j;
                } else if (c == '%') {
                        j = i + 1;
                        while (j < n && mc7p_is_ident_char(s[j])) {
                                j++;
                        }
                        /* %I0.0, %QW4, %MD8:DWord -- the trailing :Type
                         * suffix is left for the ':' branch below */
                        mc7p_push_tok(toks, i, j - i, RZ_ASM_TOKEN_REGISTER, 0);
                        i = j;
                } else if (c == ':') {
                        j = i + 1;
                        while (j < n && mc7p_is_word_char(s[j])) {
                                j++;
                        }
                        mc7p_push_tok(toks, i, j - i, RZ_ASM_TOKEN_META, 0);
                        i = j;
                } else if (c == '=') {
                        j = i + 1;
                        while (j < n && mc7p_is_word_char(s[j])) {
                                j++;
                        }
                        /* condition refs like =COND */
                        mc7p_push_tok(toks, i, j - i, RZ_ASM_TOKEN_META, 0);
                        i = j;
                } else if (c == '{') {
                        j = i + 1;
                        while (j < n && s[j] != '}') {
                                j++;
                        }
                        if (j < n) {
                                j++;
                        }
                        mc7p_push_tok(toks, i, j - i, RZ_ASM_TOKEN_META, 0);
                        i = j;
                } else if (c == '\'') {
                        j = i + 1;
                        while (j < n && s[j] != '\'') {
                                j++;
                        }
                        if (j < n) {
                                j++;
                        }
                        mc7p_push_tok(toks, i, j - i, RZ_ASM_TOKEN_META, 0);
                        i = j;
                } else if (mc7p_is_digit(c) ||
                           ((c == '-' || c == '+' || c == '.') &&
                            i + 1 < n && mc7p_is_digit(s[i + 1]))) {
                        /* numeric literal: sign, digits, optional .frac,
                         * optional exponent, optional L suffix (2.0L) */
                        size_t k = i;
                        ut64 v = 0;
                        if (s[k] == '-' || s[k] == '+') {
                                k++;
                        }
                        while (k < n && mc7p_is_digit(s[k])) {
                                v = v * 10 + (ut64)(s[k] - '0');
                                k++;
                        }
                        j = k;
                        if (j < n && s[j] == '.') {
                                j++;
                                while (j < n && mc7p_is_digit(s[j])) {
                                        j++;
                                }
                        }
                        if (j < n && (s[j] == 'e' || s[j] == 'E')) {
                                size_t k2 = j + 1;
                                if (k2 < n && (s[k2] == '+' || s[k2] == '-')) {
                                        k2++;
                                }
                                if (k2 < n && mc7p_is_digit(s[k2])) {
                                        j = k2;
                                        while (j < n && mc7p_is_digit(s[j])) {
                                                j++;
                                        }
                                }
                        }
                        if (j < n && s[j] == 'L') {
                                j++; /* LReal suffix */
                        }
                        mc7p_push_tok(toks, i, j - i, RZ_ASM_TOKEN_NUMBER, v);
                        i = j;
                } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           c == '_') {
                        i = mc7p_tok_ident(toks, s, n, i);
                } else {
                        /* separators: spaces, brackets, commas, ... */
                        mc7p_push_tok(toks, i, 1, RZ_ASM_TOKEN_UNKNOWN, 0);
                        i++;
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

static bool mc7p_io_scan_bounds(RzIOBind *iob, ut64 addr, ut64 *base,
                                ut64 *size) {
        ut64 from = 0;
        ut64 to = UT64_MAX;
        if (!iob || !iob->read_at) {
                return false;
        }
        if (iob->map_get) {
                RzIOMap *map = iob->map_get(iob->io, addr);
                if (map) {
                        from = rz_io_map_get_from(map);
                        to = rz_io_map_get_to(map);
                }
        }
        if (from > addr) {
                from = 0;
        }
        if (to == UT64_MAX || to < addr) {
                to = addr + MC7P_LABEL_SCAN_BYTES - 1;
        }
        if (to < from) {
                return false;
        }
        *base = from;
        *size = RZ_MIN(to - from + 1, (ut64)MC7P_LABEL_SCAN_BYTES);
        return *size > 0;
}

static bool mc7p_read_analysis_at(RzAnalysis *analysis, RzIOBind *iob,
                                  ut64 addr, ut8 *buf, size_t size) {
        RzAnalysisCallbacks *cb = rz_analysis_get_callbacks(analysis);
        if (cb && cb->read_at && size <= (size_t)INT_MAX &&
            cb->read_at(analysis, addr, buf, (int)size)) {
                return true;
        }
        return iob && iob->read_at && iob->read_at(iob->io, addr, buf, size);
}

static size_t mc7p_read_scan_window(RzAnalysis *analysis, RzIOBind *iob,
                                    ut64 addr, ut8 *buf) {
        size_t size = MC7P_LABEL_SCAN_WINDOW;
        while (size > 0) {
                if (mc7p_read_analysis_at(analysis, iob, addr, buf, size)) {
                        return size;
                }
                size /= 2;
        }
        return 0;
}

/* Resolve a label by scanning the complete mapped code stream from its start.
 * MC7+ instructions are variable length, so backwards resolution cannot start
 * at the current instruction and decode in reverse. */
static bool mc7p_resolve_label_io(RzAnalysis *analysis, ut64 addr, long id,
                                  ut64 *target) {
        RzIOBind *iob;
        ut64 base = 0, size = 0;
        ut64 off = 0;
        int steps = 0;

        if (!analysis) {
                return false;
        }
        iob = rz_analysis_get_io_bind(analysis);
        if (!mc7p_io_scan_bounds(iob, addr, &base, &size) ||
            size > (ut64)SIZE_MAX) {
                return false;
        }
        while (off < size && steps++ < MC7P_LABEL_SCAN_MAX) {
                ut8 buf[MC7P_LABEL_SCAN_WINDOW];
                mc7p_flow_t f;
                size_t nread = mc7p_read_scan_window(analysis, iob,
                                                     base + off, buf);
                int n;
                if (nread == 0) {
                        return false;
                }
                n = mc7p_flow_one(buf, nread, 0, &f);
                if (n < 0) {
                        break;
                }
                if (f.kind == MC7P_FLOW_LABEL && f.label_id == id) {
                        *target = base + off;
                        return true;
                }
                off += (ut64)n;
        }
        return false;
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
        case MC7P_FLOW_LABEL:
                break;
        case MC7P_FLOW_JMP:
        case MC7P_FLOW_CJMP:
                op->eob = true;
                if (flow.kind == MC7P_FLOW_CJMP) {
                        op->fail = addr + read;
                }
                if (flow.label_id >= 0) {
                        ut64 target = UT64_MAX;
                        if (mc7p_resolve_label_io(analysis, addr,
                                                  flow.label_id, &target)) {
                                op->jump = target;
                        } else {
                                int loff = mc7p_resolve_label(data, len, read,
                                                              flow.label_id);
                                if (loff >= 0) {
                                        op->jump = addr + loff;
                                }
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
