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

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

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

#define MC7P_ASM_MAX_OPERANDS 32
#define MC7P_ASM_MAX_BYTES 256

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

/* ----------------------------------------------------------- assembler */

static bool mc7p_parse_label_id(const char *s, unsigned long long *out) {
        char *end = NULL;
        unsigned long long v;
        while (*s && isspace((unsigned char)*s)) {
                s++;
        }
        if (!*s || *s == '-') {
                return false;
        }
        v = strtoull(s, &end, 0);
        while (end && *end && isspace((unsigned char)*end)) {
                end++;
        }
        if (!end || *end || v > 0xffffffffULL) {
                return false;
        }
        *out = v;
        return true;
}

static int mc7p_encode_positive_immediate(ut8 *out, unsigned long long v) {
        int n = 0;
        int i;
        if (v <= 2) {
                out[0] = (ut8)v;
                return 1;
        }
        for (i = 7; i >= 0; i--) {
                if ((v >> (i * 8)) & 0xff) {
                        n = i + 1;
                        break;
                }
        }
        if (n <= 0 || n > 8) {
                return -1;
        }
        out[0] = 0x20 | (ut8)(n - 1);
        for (i = 0; i < n; i++) {
                out[1 + i] = (ut8)(v >> ((n - 1 - i) * 8));
        }
        return n + 1;
}

static bool mc7p_has_flag_text(const char *s, const char *flag) {
        const char *open = strchr(s, '{');
        const char *close = strchr(s, '}');
        size_t flen = strlen(flag);
        if (!open || !close || close < open) {
                return false;
        }
        for (const char *p = open + 1; p + flen <= close; p++) {
                if (!strncmp(p, flag, flen)) {
                        return true;
                }
        }
        return false;
}

static bool mc7p_startswith_ci(const char *s, const char *prefix) {
        while (*prefix) {
                if (toupper((unsigned char)*s) != toupper((unsigned char)*prefix)) {
                        return false;
                }
                s++;
                prefix++;
        }
        return true;
}

static int mc7p_name_to_op(const char *name) {
        int i;
        for (i = 0; i < MC7P_OP_COUNT; i++) {
                if (mc7p_ops[i].name && !strcmp(mc7p_ops[i].name, name)) {
                        return i;
                }
        }
        return -1;
}

static int mc7p_type_by_name(const char *name) {
        int i;
        for (i = 0; i < MC7P_OT_NAME_COUNT; i++) {
                if (mc7p_ot_names[i] && !_stricmp(mc7p_ot_names[i], name)) {
                        return i;
                }
        }
        return -1;
}

static int mc7p_type_to_wire(int type) {
        int i;
        for (i = 0; i < 64; i++) {
                if (mc7p_type_byte_to_ot[i] == type) {
                        return i;
                }
        }
        return -1;
}

static int mc7p_cond_by_name(const char *name) {
        int i;
        for (i = 0; i < 33; i++) {
                if (mc7p_cond_names[i] && !strcmp(mc7p_cond_names[i], name)) {
                        return i;
                }
        }
        return -1;
}

static int mc7p_cond_to_wire(int cond) {
        int i;
        for (i = 0; i < 32; i++) {
                if (mc7p_relcond_to_cond[i] == cond) {
                        return i;
                }
        }
        return -1;
}

static int mc7p_flag_by_name(const char *name) {
        int i;
        for (i = 0; i < 7; i++) {
                if (mc7p_flag_names[i] && !strcmp(mc7p_flag_names[i], name)) {
                        return i;
                }
        }
        if (!strcmp(name, "N")) {
                return MC7P_FLAG_NEGATED;
        }
        return -1;
}

static int mc7p_area_direct_code(int area) {
        switch (area) {
        case MC7P_AREA_INPUT: return 1;
        case MC7P_AREA_OUTPUT: return 2;
        case MC7P_AREA_MEMORY: return 3;
        case MC7P_AREA_PINPUT: return 4;
        case MC7P_AREA_POUTPUT: return 5;
        case MC7P_AREA_LOCAL: return 6;
        case MC7P_AREA_TSLOCAL: return 7;
        default: return 0;
        }
}

static int mc7p_area_address_code(int area) {
        if (area >= MC7P_AREA_TSH0 && area <= MC7P_AREA_TSH63) {
                return 64 + (area - MC7P_AREA_TSH0);
        }
        if (area >= MC7P_AREA_H0 && area <= MC7P_AREA_H63) {
                return 192 + (area - MC7P_AREA_H0);
        }
        switch (area) {
        case MC7P_AREA_OB_N: return 6;
        case MC7P_AREA_FC_N: return 7;
        case MC7P_AREA_FB_N: return 8;
        case MC7P_AREA_OB_C: return 11;
        case MC7P_AREA_FC_C: return 12;
        case MC7P_AREA_FB_C: return 13;
        case MC7P_AREA_PINPUT: return 128;
        case MC7P_AREA_INPUT: return 129;
        case MC7P_AREA_OUTPUT: return 130;
        case MC7P_AREA_MEMORY: return 131;
        case MC7P_AREA_DATA: return 132;
        case MC7P_AREA_XDATA: return 133;
        case MC7P_AREA_LOCAL: return 134;
        case MC7P_AREA_FATHER: return 135;
        case MC7P_AREA_DBRETAIN: return 138;
        case MC7P_AREA_DBVOLATILE: return 139;
        case MC7P_AREA_TSLOCAL: return 142;
        case MC7P_AREA_TSFATHER: return 143;
        default: return -1;
        }
}

static bool mc7p_area_is_address(int area) {
        return mc7p_area_address_code(area) >= 0;
}

static int mc7p_scope_code(int scope) {
        switch (scope) {
        case MC7P_SCOPE_NATIVEGLOBAL: return 0;
        case MC7P_SCOPE_NATIVELOCAL: return 1;
        case MC7P_SCOPE_NATIVEBLOCK: return 2;
        case MC7P_SCOPE_NATIVECALL: return 3;
        default: return -1;
        }
}

static int mc7p_location_code(int range) {
        switch (range) {
        case MC7P_RANGE_POINTER: return MC7P_LOC_POINTER;
        case MC7P_RANGE_SLOTBIT: return MC7P_LOC_BIT;
        case MC7P_RANGE_SLOT8: return MC7P_LOC_SLOT8;
        case MC7P_RANGE_SLOT16: return MC7P_LOC_SLOT16;
        case MC7P_RANGE_SLOT32: return MC7P_LOC_SLOT32;
        case MC7P_RANGE_SLOT64: return MC7P_LOC_SLOT64;
        case MC7P_RANGE_SLOTREAL: return MC7P_LOC_REAL;
        default: return -1;
        }
}

static bool mc7p_is_direct_bit_type(int type, unsigned long long off) {
        return (type == MC7P_OT_BOOL || type == MC7P_OT_UNDEF ||
                type == MC7P_OT_VOID) && (off % 8) != 0;
}

static int mc7p_write_offset(ut8 *out, size_t cap, unsigned long long value) {
        int n = 1;
        int i;
        while (n < 8 && (value >> (n * 8))) {
                n++;
        }
        if ((size_t)n > cap) {
                return -1;
        }
        for (i = 0; i < n; i++) {
                out[i] = (ut8)(value >> ((n - 1 - i) * 8));
        }
        return n - 1;
}

static int mc7p_write_slot_no(ut8 *out, size_t cap, unsigned long long value,
                              int fraction) {
        static const unsigned long long maxv[8] = {
                252ULL, 65532ULL, 16777212ULL, 4294967292ULL,
                1099511627772ULL, 281474976710652ULL,
                72057594037927932ULL, 18446744073709551612ULL
        };
        unsigned long long wire = value << 2;
        int add;
        for (add = 0; add < 8; add++) {
                if (wire <= maxv[add]) {
                        break;
                }
        }
        if (add >= 8 || (size_t)(add + 1) > cap) {
                return -1;
        }
        for (int i = 0; i <= add; i++) {
                out[i] = (ut8)(wire >> ((add - i) * 8));
        }
        out[add] |= (ut8)(fraction & 3);
        return add;
}

static int mc7p_parse_uint(const char *s, unsigned long long *out) {
        return mc7p_parse_label_id(s, out) ? 0 : -1;
}

static int mc7p_parse_width_type(char letter) {
        switch (toupper((unsigned char)letter)) {
        case 'B': return MC7P_OT_BYTE;
        case 'W': return MC7P_OT_WORD;
        case 'D': return MC7P_OT_DWORD;
        case 'L': return MC7P_OT_LWORD;
        default: return -1;
        }
}

static int mc7p_parse_slot_type(const char *s) {
        int i;
        if (!_stricmp(s, "BIT")) {
                return MC7P_RANGE_SLOTBIT;
        }
        for (i = 0; i < 8; i++) {
                if (mc7p_range_names[i] && !_stricmp(s, mc7p_range_names[i])) {
                        return i;
                }
        }
        return -1;
}

static int mc7p_slot_type_to_dt(int range) {
        switch (range) {
        case MC7P_RANGE_SLOTBIT: return MC7P_OT_BOOL;
        case MC7P_RANGE_SLOT8: return MC7P_OT_BYTE;
        case MC7P_RANGE_SLOT16: return MC7P_OT_WORD;
        case MC7P_RANGE_SLOT32: return MC7P_OT_DWORD;
        case MC7P_RANGE_SLOT64: return MC7P_OT_LWORD;
        case MC7P_RANGE_SLOTREAL: return MC7P_OT_REAL;
        case MC7P_RANGE_POINTER: return MC7P_OT_POINTER;
        default: return MC7P_OT_VOID;
        }
}

static int mc7p_scope_from_short(char c) {
        switch (toupper((unsigned char)c)) {
        case 'L': return MC7P_SCOPE_NATIVELOCAL;
        case 'G': return MC7P_SCOPE_NATIVEGLOBAL;
        case 'C': return MC7P_SCOPE_NATIVECALL;
        case 'B': return MC7P_SCOPE_NATIVEBLOCK;
        default: return -1;
        }
}

static int mc7p_parse_operand(const char *tok, mc7p_access_t *a) {
        memset(a, 0, sizeof(*a));
        a->data_type = MC7P_OT_VOID;
        if (!tok || !*tok) {
                return -1;
        }
        if (tok[0] == ':') {
                int t = mc7p_type_by_name(tok + 1);
                if (t < 0) {
                        return -1;
                }
                a->kind = MC7P_ACC_TYPE;
                a->data_type = t;
                a->type_val = t;
                return 0;
        }
        if (tok[0] == '=') {
                char name[32];
                size_t i;
                for (i = 0; tok[i + 1] && i + 1 < sizeof(name); i++) {
                        name[i] = (char)toupper((unsigned char)tok[i + 1]);
                }
                name[i] = 0;
                a->cond_val = mc7p_cond_by_name(name);
                if (a->cond_val < 0) {
                        return -1;
                }
                a->kind = MC7P_ACC_CONDITION;
                a->data_type = MC7P_OT_VOID;
                return 0;
        }
        if (tok[0] == '@' && toupper((unsigned char)tok[1]) == 'S') {
                char sc = tok[2];
                char range[32];
                unsigned long long num;
                const char *dot1 = strchr(tok + 3, '.');
                const char *dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
                if (!dot1 || !dot2 || dot2 - dot1 - 1 >= (int)sizeof(range)) {
                        return -1;
                }
                memcpy(range, dot1 + 1, (size_t)(dot2 - dot1 - 1));
                range[dot2 - dot1 - 1] = 0;
                if (mc7p_parse_uint(dot2 + 1, &num)) {
                        return -1;
                }
                a->kind = MC7P_ACC_SLOT;
                a->scope = mc7p_scope_from_short(sc);
                a->slot_type = mc7p_parse_slot_type(range);
                a->slot_number = (int)num;
                a->data_type = mc7p_slot_type_to_dt(a->slot_type);
                return (a->scope < 0 || a->slot_type < 0) ? -1 : 0;
        }
        if (tok[0] == '@' && toupper((unsigned char)tok[1]) == 'P') {
                unsigned long long num;
                if (!_strnicmp(tok, "@PSYS.", 6)) {
                        if (mc7p_parse_uint(tok + 6, &num)) {
                                return -1;
                        }
                        a->kind = MC7P_ACC_POINTER;
                        a->scope = MC7P_SCOPE_NativeSystem;
                        a->ptr_area = (int)num;
                        a->data_type = MC7P_OT_POINTER;
                        return 0;
                }
                if (tok[3] != '.' || mc7p_parse_uint(tok + 4, &num)) {
                        return -1;
                }
                a->kind = MC7P_ACC_POINTER;
                a->scope = mc7p_scope_from_short(tok[2]);
                a->pointer_number = (int)num;
                a->data_type = MC7P_OT_POINTER;
                return a->scope < 0 ? -1 : 0;
        }
        if (tok[0] == '%') {
                char area_name[8] = {0};
                int ai = 1, oi = 0, area = -1, type = MC7P_OT_BOOL;
                unsigned long long byte = 0, bit = 0;
                while (tok[ai] && isalpha((unsigned char)tok[ai]) &&
                       oi + 1 < (int)sizeof(area_name)) {
                        area_name[oi++] = (char)toupper((unsigned char)tok[ai++]);
                }
                if (oi > 1) {
                        type = mc7p_parse_width_type(area_name[oi - 1]);
                        if (type >= 0) {
                                area_name[--oi] = 0;
                        }
                }
                if (!strcmp(area_name, "I")) area = MC7P_AREA_INPUT;
                else if (!strcmp(area_name, "Q")) area = MC7P_AREA_OUTPUT;
                else if (!strcmp(area_name, "M")) area = MC7P_AREA_MEMORY;
                else if (!strcmp(area_name, "L")) area = MC7P_AREA_LOCAL;
                else if (!strcmp(area_name, "PI")) area = MC7P_AREA_PINPUT;
                else if (!strcmp(area_name, "PQ")) area = MC7P_AREA_POUTPUT;
                {
                        char *end = NULL;
                        byte = strtoull(tok + ai, &end, 10);
                        if (end == tok + ai) {
                                return -1;
                        }
                }
                if (area < 0) {
                        return -1;
                }
                const char *dot = strchr(tok + ai, '.');
                if (dot) {
                        bit = strtoull(dot + 1, NULL, 10);
                        type = MC7P_OT_BOOL;
                }
                a->kind = MC7P_ACC_MEMORY;
                a->area = area;
                a->offset = byte * 8 + bit;
                a->data_type = type;
                return 0;
        }
        if (!_strnicmp(tok, "DB", 2)) {
                int range = MC7P_AREA_DATA;
                const char *p = tok + 2;
                const char *dbp = NULL;
                unsigned long long num, byte, bit = 0;
                char width = 0;
                if (toupper((unsigned char)*p) == 'R') {
                        range = MC7P_AREA_DBRETAIN;
                        p++;
                } else if (toupper((unsigned char)*p) == 'V') {
                        range = MC7P_AREA_DBVOLATILE;
                        p++;
                }
                {
                        char *end = NULL;
                        num = strtoull(p, &end, 10);
                        if (end == p) {
                                return -1;
                        }
                }
                if (num > INT_MAX) {
                        return -1;
                }
                for (const char *q = p; *q; q++) {
                        if (q[0] == '.' &&
                            toupper((unsigned char)q[1]) == 'D' &&
                            toupper((unsigned char)q[2]) == 'B') {
                                dbp = q;
                                break;
                        }
                }
                p = dbp;
                if (!p || !p[3]) {
                        return -1;
                }
                width = (char)toupper((unsigned char)p[3]);
                {
                        char *end = NULL;
                        byte = strtoull(p + 4, &end, 10);
                        if (end == p + 4) {
                                return -1;
                        }
                }
                if (width == 'X') {
                        const char *dot = strchr(p + 4, '.');
                        if (!dot) {
                                return -1;
                        }
                        bit = strtoull(dot + 1, NULL, 10);
                }
                a->kind = MC7P_ACC_DBPI;
                a->range = range;
                a->number = (int)num;
                a->offset = byte * 8 + bit;
                a->data_type = width == 'X' ? MC7P_OT_BOOL : mc7p_parse_width_type(width);
                return a->data_type < 0 ? -1 : 0;
        }
        if (!_stricmp(tok, "TRUE") || !_stricmp(tok, "FALSE")) {
                a->kind = MC7P_ACC_IMMEDIATE;
                a->data_type = MC7P_OT_BOOL;
                a->value = !_stricmp(tok, "TRUE") ? 1 : 0;
                a->bool_value = (int)a->value;
                return 0;
        }
        {
                char *end = NULL;
                unsigned long long v = strtoull(tok, &end, 0);
                if (!end || *end) {
                        return -1;
                }
                a->kind = MC7P_ACC_IMMEDIATE;
                a->data_type = MC7P_OT_UNDEF;
                a->value = v;
                return 0;
        }
}

static int mc7p_split_operands(char *s, char **tokens, int max_tokens) {
        int n = 0;
        while (*s) {
                while (*s && isspace((unsigned char)*s)) {
                        *s++ = 0;
                }
                if (!*s) {
                        break;
                }
                if (n >= max_tokens) {
                        return -1;
                }
                tokens[n++] = s;
                while (*s && !isspace((unsigned char)*s)) {
                        s++;
                }
        }
        return n;
}

static int mc7p_encode_immediate_typed(ut8 *out, size_t cap,
                                       const mc7p_access_t *a, int ref_type,
                                       int mode) {
        int type = a->data_type;
        int bytes = 4;
        bool minus_one = mode != MC7P_MODE_ID && mode != MC7P_MODE_LEN;
        unsigned long long v = a->value;
        if (type == MC7P_OT_UNDEF && ref_type != MC7P_OT_UNDEF) {
                type = ref_type;
        }
        if (type == MC7P_OT_BOOL) {
                v = a->bool_value ? 1 : 0;
                bytes = 1;
        } else if (type == MC7P_OT_BYTE || type == MC7P_OT_CHAR ||
                   type == MC7P_OT_BBOOL || type == MC7P_OT_USINT ||
                   type == MC7P_OT_SINT) {
                bytes = 1;
        } else if (type == MC7P_OT_WORD || type == MC7P_OT_INT ||
                   type == MC7P_OT_DATE || type == MC7P_OT_S5TIME ||
                   type == MC7P_OT_UINT || type == MC7P_OT_WCHAR) {
                bytes = 2;
        } else if (type == MC7P_OT_DWORD || type == MC7P_OT_DINT ||
                   type == MC7P_OT_TIME || type == MC7P_OT_TIME_OF_DAY ||
                   type == MC7P_OT_OFFSET || type == MC7P_OT_UDINT ||
                   type == MC7P_OT_AREF || type == MC7P_OT_UNDEF ||
                   type == MC7P_OT_VOID) {
                bytes = 4;
        } else if (type == MC7P_OT_LWORD || type == MC7P_OT_LINT ||
                   type == MC7P_OT_ULINT || type == MC7P_OT_LTIME ||
                   type == MC7P_OT_LTOD || type == MC7P_OT_LDT) {
                bytes = 8;
        }
        if (v <= 2) {
                if (cap < 1) return -1;
                out[0] = (ut8)v;
                return 1;
        }
        if (minus_one &&
            ((bytes == 1 && (v & 0xff) == 0xff) ||
             (bytes == 2 && (v & 0xffff) == 0xffff) ||
             (bytes == 4 && (v & 0xffffffffULL) == 0xffffffffULL) ||
             (bytes == 8 && v == 0xffffffffffffffffULL))) {
                if (cap < 1) return -1;
                out[0] = 3;
                return 1;
        }
        return mc7p_encode_positive_immediate(out, v);
}

static int mc7p_encode_type_access(ut8 *out, size_t cap, int type) {
        int wire = mc7p_type_to_wire(type);
        if (wire < 0 || cap < 1) {
                return -1;
        }
        out[0] = (ut8)wire;
        return 1;
}

static int mc7p_encode_memory(ut8 *out, size_t cap, const mc7p_access_t *a,
                              bool force_address) {
        unsigned long long off = a->offset;
        bool direct_bit = mc7p_is_direct_bit_type(a->data_type, off);
        if (!direct_bit) {
                if (off % 8) {
                        return -1;
                }
                off /= 8;
        }
        if (force_address || !mc7p_area_direct_code(a->area)) {
                int area = mc7p_area_address_code(a->area);
                int L;
                if (area < 0 || area == 128 || area == 132 || area == 133 ||
                    cap < 3) {
                        return -1;
                }
                out[1] = (ut8)area;
                L = mc7p_write_offset(out + 2, cap - 2, off);
                if (L < 0) {
                        return -1;
                }
                out[0] = (direct_bit ? 0xa0 : 0xa4) | (ut8)L;
                return 2 + L + 1;
        } else {
                int area = mc7p_area_direct_code(a->area);
                int L;
                if (!area || cap < 2) {
                        return -1;
                }
                L = mc7p_write_offset(out + 1, cap - 1, off);
                if (L < 0) {
                        return -1;
                }
                out[0] = (direct_bit ? 0x60 : 0x80) |
                         (ut8)((area << 2) & 0x1c) | (ut8)L;
                return 1 + L + 1;
        }
}

static int mc7p_encode_native(ut8 *out, size_t cap, const mc7p_access_t *a) {
        int loc, scope, L;
        if (a->kind == MC7P_ACC_POINTER &&
            a->scope == MC7P_SCOPE_NativeSystem) {
                int area = mc7p_area_direct_code(a->ptr_area);
                if (!area || cap < 1) {
                        return -1;
                }
                out[0] = 0x08 | (ut8)area;
                return 1;
        }
        if (cap < 2) {
                return -1;
        }
        loc = a->kind == MC7P_ACC_POINTER ? MC7P_LOC_POINTER :
              mc7p_location_code(a->slot_type);
        scope = mc7p_scope_code(a->scope);
        if (loc < 0 || scope < 0) {
                return -1;
        }
        L = mc7p_write_slot_no(out + 1, cap - 1,
                               a->kind == MC7P_ACC_POINTER ?
                               (unsigned long long)a->pointer_number :
                               (unsigned long long)a->slot_number,
                               scope);
        if (L < 0) {
                return -1;
        }
        out[0] = 0x40 | (ut8)((loc << 2) & 0x1c) | (ut8)L;
        return 1 + L + 1;
}

static int mc7p_encode_db(ut8 *out, size_t cap, const mc7p_access_t *a) {
        int range = -1, L, L2;
        unsigned long long off = a->offset;
        bool direct_bit = mc7p_is_direct_bit_type(a->data_type, off);
        if (!direct_bit) {
                if (off % 8) {
                        return -1;
                }
                off /= 8;
        }
        if (a->range == MC7P_AREA_DATA) range = 0;
        else if (a->range == MC7P_AREA_DBRETAIN) range = 1;
        else if (a->range == MC7P_AREA_DBVOLATILE) range = 2;
        if (range < 0 || cap < 3) {
                return -1;
        }
        L = mc7p_write_slot_no(out + 1, cap - 1,
                               (unsigned long long)a->number, range);
        if (L < 0) {
                return -1;
        }
        if (off == 0 && !direct_bit) {
                out[0] = 0xa8 | (ut8)L;
                return 1 + L + 1;
        }
        L2 = mc7p_write_offset(out + 1 + L + 1, cap - (size_t)(1 + L + 1),
                               off);
        if (L2 < 0) {
                return -1;
        }
        out[0] = (direct_bit ? 0xc0 : 0xd0) | (ut8)(L << 2) | (ut8)L2;
        return 1 + L + 1 + L2 + 1;
}

static int mc7p_operand_ref_type(const mc7p_access_t *operands, int op_count,
                                 int ref) {
        int i, seen = 0;
        if (ref < 0) {
                return MC7P_OT_UNDEF;
        }
        for (i = 0; i < op_count; i++) {
                if (operands[i].kind == MC7P_ACC_TYPE) {
                        if (seen == ref) {
                                return operands[i].data_type;
                        }
                        seen++;
                }
        }
        return MC7P_OT_UNDEF;
}

static int mc7p_encode_operand(ut8 *out, size_t cap, const mc7p_access_t *a,
                               const mc7p_param_t *p, int ref_type) {
        if (a->kind == MC7P_ACC_IMMEDIATE) {
                int type = p->predefined_type >= 0 ? p->predefined_type : ref_type;
                return mc7p_encode_immediate_typed(out, cap, a, type, p->mode);
        }
        if (a->kind == MC7P_ACC_TYPE) {
                return mc7p_encode_type_access(out, cap, a->data_type);
        }
        if (a->kind == MC7P_ACC_CONDITION) {
                int c = mc7p_cond_to_wire(a->cond_val);
                if (c < 0 || cap < 1) {
                        return -1;
                }
                out[0] = (ut8)c;
                return 1;
        }
        if (a->kind == MC7P_ACC_SLOT || a->kind == MC7P_ACC_POINTER) {
                return mc7p_encode_native(out, cap, a);
        }
        if (a->kind == MC7P_ACC_MEMORY) {
                return mc7p_encode_memory(out, cap, a,
                                          p->mode == MC7P_MODE_DIRECT);
        }
        if (a->kind == MC7P_ACC_DBPI) {
                return mc7p_encode_db(out, cap, a);
        }
        return -1;
}

static int mc7p_assemble_table(const char *buf, ut8 *out, size_t cap) {
        char tmp[512];
        char mnemonic[80];
        char *flags = NULL, *rest, *tokens[MC7P_ASM_MAX_OPERANDS];
        mc7p_access_t operands[MC7P_ASM_MAX_OPERANDS];
        int flag_values[8], flag_count = 0;
        int operand_count, opnum, ti = 0, oi = 0;
        const mc7p_op_t *op;
        size_t len;

        snprintf(tmp, sizeof(tmp), "%s", buf);
        rest = tmp;
        while (*rest && isspace((unsigned char)*rest)) {
                rest++;
        }
        len = 0;
        while (rest[len] && !isspace((unsigned char)rest[len])) {
                len++;
        }
        if (len >= sizeof(mnemonic)) {
                return -1;
        }
        memcpy(mnemonic, rest, len);
        mnemonic[len] = 0;
        rest += len;
        flags = strchr(mnemonic, '{');
        if (flags) {
                char *end = strchr(flags, '}');
                if (!end) {
                        return -1;
                }
                *flags++ = 0;
                *end = 0;
                for (char *f = strtok(flags, ","); f; f = strtok(NULL, ",")) {
                        int fv;
                        while (*f && isspace((unsigned char)*f)) f++;
                        for (char *q = f; *q; q++) {
                                *q = (char)toupper((unsigned char)*q);
                        }
                        fv = mc7p_flag_by_name(f);
                        if (fv < 0 || flag_count >= 8) {
                                return -1;
                        }
                        flag_values[flag_count++] = fv;
                }
        }
        for (char *q = mnemonic; *q; q++) {
                *q = (char)toupper((unsigned char)*q);
        }
        opnum = mc7p_name_to_op(mnemonic);
        if (opnum < 0) {
                return -1;
        }
        op = &mc7p_ops[opnum];
        if (op->code_len > cap) {
                return -1;
        }
        memcpy(out, op->code, op->code_len);
        ti = (int)op->code_len;
        operand_count = mc7p_split_operands(rest, tokens, MC7P_ASM_MAX_OPERANDS);
        if (operand_count < 0) {
                return -1;
        }
        for (int i = 0; i < operand_count; i++) {
                if (mc7p_parse_operand(tokens[i], &operands[i])) {
                        return -1;
                }
        }
        for (int i = 0; i < op->param_count; i++) {
                const mc7p_param_t *p = &mc7p_params[op->param_off + i];
                if (p->kind == MC7P_PARAM_FLAG) {
                        for (int f = 0; f < flag_count; f++) {
                                if (flag_values[f] == p->flag_type &&
                                    p->byte_pos < op->code_len) {
                                        out[p->byte_pos] |= (ut8)(1u << p->bit_pos);
                                }
                        }
                        continue;
                }
                if (p->kind == MC7P_PARAM_CODING) {
                        int by = -1;
                        if (oi >= operand_count || operands[oi].kind != MC7P_ACC_TYPE ||
                            p->byte_pos >= op->code_len) {
                                return -1;
                        }
                        for (int j = 0; j < p->coding_len; j++) {
                                const mc7p_type_coding_t *tc =
                                        &mc7p_type_codings[p->coding_off + j];
                                if (tc->ot == operands[oi].data_type) {
                                        by = tc->enc;
                                        break;
                                }
                        }
                        if (by < 0) {
                                return -1;
                        }
                        out[p->byte_pos] |= (ut8)(by << p->bit_pos);
                        oi++;
                        continue;
                }
                if (oi >= operand_count) {
                        return -1;
                }
                if (p->kind == MC7P_PARAM_TYPE) {
                        int n;
                        if (operands[oi].kind != MC7P_ACC_TYPE) {
                                return -1;
                        }
                        n = mc7p_encode_type_access(out + ti, cap - (size_t)ti,
                                                    operands[oi].data_type);
                        if (n < 0) {
                                return -1;
                        }
                        ti += n;
                        oi++;
                } else if (p->kind == MC7P_PARAM_COND) {
                        int c;
                        if (operands[oi].kind != MC7P_ACC_CONDITION) {
                                return -1;
                        }
                        c = mc7p_cond_to_wire(operands[oi].cond_val);
                        if (c < 0 || (size_t)ti >= cap) {
                                return -1;
                        }
                        out[ti++] = (ut8)c;
                        oi++;
                } else if (p->kind == MC7P_PARAM_IDENT) {
                        int ref_type = p->ref_type >= 0 ?
                                mc7p_operand_ref_type(operands, operand_count,
                                                      p->ref_type) :
                                MC7P_OT_UNDEF;
                        int n = mc7p_encode_operand(out + ti, cap - (size_t)ti,
                                                    &operands[oi], p, ref_type);
                        if (n < 0) {
                                return -1;
                        }
                        ti += n;
                        oi++;
                }
        }
        return oi == operand_count ? ti : -1;
}

static int mc7p_parse_head_operands(const char *buf, char *mnemonic,
                                    size_t mnemonic_len, int *flags,
                                    int *flag_count, mc7p_access_t *operands,
                                    int *operand_count) {
        char tmp[512];
        char *rest, *flag_text, *tokens[MC7P_ASM_MAX_OPERANDS];
        size_t len;
        snprintf(tmp, sizeof(tmp), "%s", buf);
        rest = tmp;
        while (*rest && isspace((unsigned char)*rest)) {
                rest++;
        }
        len = 0;
        while (rest[len] && !isspace((unsigned char)rest[len])) {
                len++;
        }
        if (!len || len >= mnemonic_len) {
                return -1;
        }
        memcpy(mnemonic, rest, len);
        mnemonic[len] = 0;
        rest += len;
        *flag_count = 0;
        flag_text = strchr(mnemonic, '{');
        if (flag_text) {
                char *end = strchr(flag_text, '}');
                if (!end) {
                        return -1;
                }
                *flag_text++ = 0;
                *end = 0;
                for (char *f = strtok(flag_text, ","); f; f = strtok(NULL, ",")) {
                        int fv;
                        while (*f && isspace((unsigned char)*f)) {
                                f++;
                        }
                        for (char *q = f; *q; q++) {
                                *q = (char)toupper((unsigned char)*q);
                        }
                        fv = mc7p_flag_by_name(f);
                        if (fv < 0 || *flag_count >= 8) {
                                return -1;
                        }
                        flags[(*flag_count)++] = fv;
                }
        }
        for (char *q = mnemonic; *q; q++) {
                *q = (char)toupper((unsigned char)*q);
        }
        *operand_count = mc7p_split_operands(rest, tokens, MC7P_ASM_MAX_OPERANDS);
        if (*operand_count < 0) {
                return -1;
        }
        for (int i = 0; i < *operand_count; i++) {
                if (mc7p_parse_operand(tokens[i], &operands[i])) {
                        return -1;
                }
        }
        return 0;
}

static bool mc7p_flag_present(const int *flags, int flag_count, int flag) {
        for (int i = 0; i < flag_count; i++) {
                if (flags[i] == flag) {
                        return true;
                }
        }
        return false;
}

static int mc7p_encode_ident_ref(ut8 *out, size_t cap, const mc7p_access_t *a,
                                 int ref_type, int mode) {
        mc7p_param_t p;
        memset(&p, 0, sizeof(p));
        p.kind = MC7P_PARAM_IDENT;
        p.predefined_type = MC7P_OT_UNDEF;
        p.mode = (ut8)mode;
        return mc7p_encode_operand(out, cap, a, &p, ref_type);
}

static int mc7p_assemble_selected(const char *buf, ut8 *out, size_t cap) {
        char mnemonic[80];
        int flags[8], flag_count = 0, operand_count = 0;
        mc7p_access_t operands[MC7P_ASM_MAX_OPERANDS];
        int pos = 0;
        if (mc7p_parse_head_operands(buf, mnemonic, sizeof(mnemonic), flags,
                                     &flag_count, operands, &operand_count)) {
                return -1;
        }
        if (!strcmp(mnemonic, "MOVE")) {
                int n;
                if (operand_count != 3 || operands[0].kind != MC7P_ACC_TYPE ||
                    cap < 2) {
                        return -1;
                }
                out[pos++] = 0xe0;
                if (mc7p_flag_present(flags, flag_count, MC7P_FLAG_COND)) {
                        out[0] |= 1;
                }
                if (mc7p_flag_present(flags, flag_count, MC7P_FLAG_ENO)) {
                        out[0] |= 2;
                }
                n = mc7p_encode_type_access(out + pos, cap - (size_t)pos,
                                            operands[0].data_type);
                if (n < 0) return -1;
                pos += n;
                n = mc7p_encode_ident_ref(out + pos, cap - (size_t)pos,
                                          &operands[1], operands[0].data_type,
                                          MC7P_MODE_DEST);
                if (n < 0) return -1;
                pos += n;
                n = mc7p_encode_ident_ref(out + pos, cap - (size_t)pos,
                                          &operands[2], operands[0].data_type,
                                          MC7P_MODE_SRC);
                if (n < 0) return -1;
                return pos + n;
        }
        if (!strcmp(mnemonic, "ADD") || !strcmp(mnemonic, "SUB") ||
            !strcmp(mnemonic, "MUL") || !strcmp(mnemonic, "DIV") ||
            !strcmp(mnemonic, "MOD") || !strcmp(mnemonic, "AND") ||
            !strcmp(mnemonic, "OR") || !strcmp(mnemonic, "XOR")) {
                static const struct { const char *name; ut8 code; } ops[] = {
                        { "ADD", 0x20 }, { "SUB", 0x21 }, { "MUL", 0x22 },
                        { "DIV", 0x23 }, { "MOD", 0x24 }, { "AND", 0x28 },
                        { "OR", 0x29 }, { "XOR", 0x2a },
                };
                int n, opi;
                if (operand_count != 4 || operands[0].kind != MC7P_ACC_TYPE ||
                    cap < 3) {
                        return -1;
                }
                for (opi = 0; opi < (int)(sizeof(ops) / sizeof(ops[0])); opi++) {
                        if (!strcmp(mnemonic, ops[opi].name)) {
                                break;
                        }
                }
                if (opi >= (int)(sizeof(ops) / sizeof(ops[0]))) {
                        return -1;
                }
                out[pos++] = 0xf0;
                out[pos++] = ops[opi].code;
                if (mc7p_flag_present(flags, flag_count, MC7P_FLAG_COND)) out[0] |= 1;
                if (mc7p_flag_present(flags, flag_count, MC7P_FLAG_ENO)) out[0] |= 2;
                if (mc7p_flag_present(flags, flag_count, MC7P_FLAG_STW)) out[0] |= 4;
                n = mc7p_encode_type_access(out + pos, cap - (size_t)pos,
                                            operands[0].data_type);
                if (n < 0) return -1;
                pos += n;
                for (int i = 1; i < 4; i++) {
                        n = mc7p_encode_ident_ref(out + pos, cap - (size_t)pos,
                                                  &operands[i],
                                                  operands[0].data_type,
                                                  i == 1 ? MC7P_MODE_DEST :
                                                           MC7P_MODE_SRC);
                        if (n < 0) return -1;
                        pos += n;
                }
                return pos;
        }
        if (!strcmp(mnemonic, "LD_CMP")) {
                int n, c;
                if (operand_count != 4 || operands[0].kind != MC7P_ACC_CONDITION ||
                    operands[1].kind != MC7P_ACC_TYPE || cap < 4) {
                        return -1;
                }
                out[pos++] = 0xf8;
                out[pos++] = 0x70;
                if (mc7p_flag_present(flags, flag_count, MC7P_FLAG_STW)) {
                        out[1] |= 1;
                }
                c = mc7p_cond_to_wire(operands[0].cond_val);
                if (c < 0) return -1;
                out[pos++] = (ut8)c;
                n = mc7p_encode_type_access(out + pos, cap - (size_t)pos,
                                            operands[1].data_type);
                if (n < 0) return -1;
                pos += n;
                for (int i = 2; i < 4; i++) {
                        n = mc7p_encode_ident_ref(out + pos, cap - (size_t)pos,
                                                  &operands[i],
                                                  operands[1].data_type,
                                                  MC7P_MODE_SRC);
                        if (n < 0) return -1;
                        pos += n;
                }
                return pos;
        }
        return -1;
}

static int assemble_mc7plus(const RzAsm *a, RzAsmOp *op, const char *buf) {
        ut8 out[16];
        char word[64];
        const char *p = buf;
        size_t wlen = 0;

        {
                ut8 table_out[MC7P_ASM_MAX_BYTES];
                int table_len = mc7p_assemble_selected(buf, table_out,
                                                       sizeof(table_out));
                if (table_len < 0) {
                        table_len = mc7p_assemble_table(buf, table_out,
                                                        sizeof(table_out));
                }
                if (table_len > 0) {
                        rz_asm_op_set_buf(op, table_out, table_len);
                        return table_len;
                }
        }

        while (*p && isspace((unsigned char)*p)) {
                p++;
        }
        while (p[wlen] && !isspace((unsigned char)p[wlen]) && wlen + 1 < sizeof(word)) {
                word[wlen] = (char)toupper((unsigned char)p[wlen]);
                wlen++;
        }
        word[wlen] = 0;
        p += wlen;

        if (!strcmp(word, "NOP")) {
                out[0] = 0x00;
                rz_asm_op_set_buf(op, out, 1);
                return 1;
        }
        if (!strcmp(word, "NOT")) {
                out[0] = 0x01;
                rz_asm_op_set_buf(op, out, 1);
                return 1;
        }
        if (!strcmp(word, "SET_RLO")) {
                out[0] = 0x02;
                rz_asm_op_set_buf(op, out, 1);
                return 1;
        }
        if (!strcmp(word, "STATION")) {
                out[0] = 0x05;
                rz_asm_op_set_buf(op, out, 1);
                return 1;
        }
        if (!strcmp(word, "NOP_FF")) {
                out[0] = 0xff;
                out[1] = 0xff;
                rz_asm_op_set_buf(op, out, 2);
                return 2;
        }
        if (!strcmp(word, "LABEL") || !strncmp(word, "JMP", 3)) {
                unsigned long long id;
                int n;
                if (!mc7p_parse_label_id(p, &id)) {
                        return -1;
                }
                if (!strcmp(word, "LABEL")) {
                        out[0] = 0x68;
                } else if (!strcmp(word, "JMP") || !strncmp(word, "JMP{", 4)) {
                        out[0] = 0x6c;
                        if (mc7p_has_flag_text(word, "COND")) {
                                out[0] |= 1;
                        }
                        if (mc7p_has_flag_text(word, "NEGATED")) {
                                out[0] |= 2;
                        }
                } else {
                        return -1;
                }
                n = mc7p_encode_positive_immediate(out + 1, id);
                if (n < 0) {
                        return -1;
                }
                rz_asm_op_set_buf(op, out, n + 1);
                return n + 1;
        }
        if (!strcmp(word, "RET")) {
                unsigned long long v = 1;
                while (*p && isspace((unsigned char)*p)) {
                        p++;
                }
                if (*p) {
                        if (mc7p_startswith_ci(p, "TRUE")) {
                                v = 1;
                        } else if (mc7p_startswith_ci(p, "FALSE")) {
                                v = 0;
                        } else if (!mc7p_parse_label_id(p, &v) || v > 2) {
                                return -1;
                        }
                }
                out[0] = 0x14;
                out[1] = (ut8)v;
                rz_asm_op_set_buf(op, out, 2);
                return 2;
        }
        return -1;
}

static char *mc7p_mnemonics(const RzAsm *a, int id, bool json) {
        RzStrBuf *buf;
        int i;
        if (id >= 0 && id < MC7P_OP_COUNT && mc7p_ops[id].name) {
                return json ? rz_str_newf("[\"%s\"]\n", mc7p_ops[id].name) :
                              rz_str_dup(mc7p_ops[id].name);
        }
        if (id != -1) {
                return NULL;
        }
        buf = rz_strbuf_new("");
        if (!buf) {
                return NULL;
        }
        if (json) {
                rz_strbuf_append(buf, "[");
        }
        for (i = 0; i < MC7P_OP_COUNT; i++) {
                const char *name = mc7p_ops[i].name;
                if (!name) {
                        continue;
                }
                if (json) {
                        if (rz_strbuf_length(buf) > 1) {
                                rz_strbuf_append(buf, ",");
                        }
                        rz_strbuf_appendf(buf, "\"%s\"", name);
                } else {
                        rz_strbuf_appendf(buf, "%s\n", name);
                }
        }
        if (json) {
                rz_strbuf_append(buf, "]\n");
        }
        return rz_strbuf_drain(buf);
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
        .assemble = &assemble_mc7plus,
        .mnemonics = &mc7p_mnemonics,
};

/* ------------------------------------------------------------- analysis */

static void mc7p_flag_label(RzAnalysis *analysis, ut64 addr, long id) {
        RzFlagBind *fb;
        char name[64];
        if (!analysis || id < 0) {
                return;
        }
        fb = rz_analysis_get_flag_bind(analysis);
        if (!fb || !fb->set || !fb->f) {
                return;
        }
        snprintf(name, sizeof(name), "mc7p.label.%ld", id);
        if (fb->get) {
                RzFlagItem *old = fb->get(fb->f, name);
                if (old && old->offset != addr) {
                        snprintf(name, sizeof(name), "mc7p.label.%ld_%" PFMT64x,
                                 id, addr);
                }
        }
        fb->set(fb->f, name, addr, 1);
}

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

static char *mc7p_get_reg_profile(RzAnalysis *analysis) {
        return rz_str_dup(
                "=PC\tpc\n"
                "=SP\tsp\n"
                "=A0\tacc\n"
                "gpr\tpc\t.32\t0\t0\n"
                "gpr\tsp\t.32\t4\t0\n"
                "gpr\tacc\t.64\t8\t0\n"
                "gpr\tstw\t.32\t16\t0\n"
                "gpr\trlo\t.1\t20\t0\n");
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
                mc7p_flag_label(analysis, addr, flow.label_id);
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
        case MC7P_FLOW_CALL:
                op->eob = false;
                if (flow.label_id >= 0) {
                        op->val = (ut64)flow.label_id;
                }
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
        .get_reg_profile = &mc7p_get_reg_profile,
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
