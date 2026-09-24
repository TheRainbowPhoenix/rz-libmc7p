// SPDX-License-Identifier: LGPL-3.0-only
/* MC7+ standalone assembler -- C port of the focused native encoder used by
 * the rizin plugin.  No rizin dependency: Cutter and tests call this same
 * entry point through mc7p_assemble_one().
 */
#include "mc7plus.h"
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MC7P_ASM_MAX_OPERANDS 32
#define MC7P_ASM_MAX_BYTES 256

static int mc7p_stricmp(const char *a, const char *b) {
        while (*a && *b) {
                int ca = toupper((unsigned char)*a++);
                int cb = toupper((unsigned char)*b++);
                if (ca != cb) {
                        return ca - cb;
                }
        }
        return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static int mc7p_strnicmp(const char *a, const char *b, size_t n) {
        while (n-- && *a && *b) {
                int ca = toupper((unsigned char)*a++);
                int cb = toupper((unsigned char)*b++);
                if (ca != cb) {
                        return ca - cb;
                }
        }
        return n == (size_t)-1 ? 0 : (int)(unsigned char)*a - (int)(unsigned char)*b;
}
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

static int mc7p_encode_positive_immediate(uint8_t *out, unsigned long long v) {
        int n = 0;
        int i;
        if (v <= 2) {
                out[0] = (uint8_t)v;
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
        out[0] = 0x20 | (uint8_t)(n - 1);
        for (i = 0; i < n; i++) {
                out[1 + i] = (uint8_t)(v >> ((n - 1 - i) * 8));
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
                if (mc7p_ot_names[i] && !mc7p_stricmp(mc7p_ot_names[i], name)) {
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

static int mc7p_write_offset(uint8_t *out, size_t cap, unsigned long long value) {
        int n = 1;
        int i;
        while (n < 8 && (value >> (n * 8))) {
                n++;
        }
        if ((size_t)n > cap) {
                return -1;
        }
        for (i = 0; i < n; i++) {
                out[i] = (uint8_t)(value >> ((n - 1 - i) * 8));
        }
        return n - 1;
}

static int mc7p_write_slot_no(uint8_t *out, size_t cap, unsigned long long value,
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
                out[i] = (uint8_t)(wire >> ((add - i) * 8));
        }
        out[add] |= (uint8_t)(fraction & 3);
        return add;
}

static int mc7p_write_ptr_no(uint8_t *out, size_t cap, unsigned long long value,
                             int fraction) {
        unsigned long long wire = value << 3;
        int add;
        if (wire <= 248) {
                add = 0;
        } else if (wire <= 65528) {
                add = 1;
        } else {
                return -1;
        }
        if ((size_t)(add + 1) > cap) {
                return -1;
        }
        for (int i = 0; i <= add; i++) {
                out[i] = (uint8_t)(wire >> ((add - i) * 8));
        }
        out[add] |= (uint8_t)(fraction & 7);
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
        if (!mc7p_stricmp(s, "BIT")) {
                return MC7P_RANGE_SLOTBIT;
        }
        for (i = 0; i < 8; i++) {
                if (mc7p_range_names[i] && !mc7p_stricmp(s, mc7p_range_names[i])) {
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
        if (tok[0] == '[') {
                char inner[256];
                char *plus, *base, *off, *end;
                size_t len = strlen(tok);
                if (len < 3 || tok[len - 1] != ']' ||
                    len - 2 >= sizeof(inner)) {
                        return -1;
                }
                memcpy(inner, tok + 1, len - 2);
                inner[len - 2] = 0;
                plus = strchr(inner, '+');
                if (!plus) {
                        return -1;
                }
                *plus++ = 0;
                base = inner;
                off = plus;
                while (*base && isspace((unsigned char)*base)) base++;
                end = base + strlen(base);
                while (end > base && isspace((unsigned char)end[-1])) *--end = 0;
                while (*off && isspace((unsigned char)*off)) off++;
                end = off + strlen(off);
                while (end > off && isspace((unsigned char)end[-1])) *--end = 0;
                a->base = (mc7p_access_t *)calloc(1, sizeof(mc7p_access_t));
                a->offset_acc = (mc7p_access_t *)calloc(1, sizeof(mc7p_access_t));
                if (!a->base || !a->offset_acc) {
                        free(a->base);
                        free(a->offset_acc);
                        return -1;
                }
                if (mc7p_parse_operand(base, a->base) ||
                    mc7p_parse_operand(off, a->offset_acc) ||
                    a->base->kind != MC7P_ACC_POINTER ||
                    (a->offset_acc->kind != MC7P_ACC_IMMEDIATE &&
                     a->offset_acc->kind != MC7P_ACC_SLOT)) {
                        free(a->base);
                        free(a->offset_acc);
                        memset(a, 0, sizeof(*a));
                        return -1;
                }
                a->kind = MC7P_ACC_INDIRECT;
                a->data_type = MC7P_OT_VOID;
                return 0;
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
                if (!mc7p_strnicmp(tok, "@PSYS.", 6)) {
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
        if (!mc7p_strnicmp(tok, "DB", 2)) {
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
        if (!mc7p_stricmp(tok, "TRUE") || !mc7p_stricmp(tok, "FALSE")) {
                a->kind = MC7P_ACC_IMMEDIATE;
                a->data_type = MC7P_OT_BOOL;
                a->value = !mc7p_stricmp(tok, "TRUE") ? 1 : 0;
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
                int depth = 0;
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
                while (*s && (depth > 0 || !isspace((unsigned char)*s))) {
                        if (*s == '[') {
                                depth++;
                        } else if (*s == ']' && depth > 0) {
                                depth--;
                        }
                        s++;
                }
        }
        return n;
}

static void mc7p_free_operand_tree(mc7p_access_t *a) {
        if (!a) {
                return;
        }
        mc7p_free_operand_tree(a->base);
        mc7p_free_operand_tree(a->offset_acc);
        free(a->base);
        free(a->offset_acc);
        a->base = NULL;
        a->offset_acc = NULL;
}

static int mc7p_encode_immediate_typed(uint8_t *out, size_t cap,
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
                out[0] = (uint8_t)v;
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

static int mc7p_encode_type_access(uint8_t *out, size_t cap, int type) {
        int wire = mc7p_type_to_wire(type);
        if (wire < 0 || cap < 1) {
                return -1;
        }
        out[0] = (uint8_t)wire;
        return 1;
}

static int mc7p_encode_memory(uint8_t *out, size_t cap, const mc7p_access_t *a,
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
                out[1] = (uint8_t)area;
                L = mc7p_write_offset(out + 2, cap - 2, off);
                if (L < 0) {
                        return -1;
                }
                out[0] = (direct_bit ? 0xa0 : 0xa4) | (uint8_t)L;
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
                         (uint8_t)((area << 2) & 0x1c) | (uint8_t)L;
                return 1 + L + 1;
        }
}

static int mc7p_encode_native(uint8_t *out, size_t cap, const mc7p_access_t *a) {
        int loc, scope, L;
        if (a->kind == MC7P_ACC_POINTER &&
            a->scope == MC7P_SCOPE_NativeSystem) {
                int area = mc7p_area_direct_code(a->ptr_area);
                if (!area || cap < 1) {
                        return -1;
                }
                out[0] = 0x08 | (uint8_t)area;
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
        out[0] = 0x40 | (uint8_t)((loc << 2) & 0x1c) | (uint8_t)L;
        return 1 + L + 1;
}

static int mc7p_encode_db(uint8_t *out, size_t cap, const mc7p_access_t *a) {
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
                out[0] = 0xa8 | (uint8_t)L;
                return 1 + L + 1;
        }
        L2 = mc7p_write_offset(out + 1 + L + 1, cap - (size_t)(1 + L + 1),
                               off);
        if (L2 < 0) {
                return -1;
        }
        out[0] = (direct_bit ? 0xc0 : 0xd0) | (uint8_t)(L << 2) | (uint8_t)L2;
        return 1 + L + 1 + L2 + 1;
}

static int mc7p_encode_indirect(uint8_t *out, size_t cap,
                                const mc7p_access_t *a, int ref_type) {
        const mc7p_access_t *base = a->base;
        const mc7p_access_t *off = a->offset_acc;
        int access, L;
        if (!base || !off || base->kind != MC7P_ACC_POINTER || cap < 2) {
                return -1;
        }
        access = (base->scope == MC7P_SCOPE_NATIVEBLOCK) ? 1 : 0;
        if (a->type_safe) {
                access |= 4;
        }
        if (a->granted) {
                access |= 2;
        }
        L = mc7p_write_ptr_no(out + 1, cap - 1,
                              (unsigned long long)base->pointer_number,
                              access);
        if (L < 0) {
                return -1;
        }
        if (off->kind == MC7P_ACC_SLOT) {
                int scope = mc7p_scope_code(off->scope);
                int L2;
                if (scope < 0) {
                        return -1;
                }
                L2 = mc7p_write_slot_no(out + 2 + L, cap - (size_t)(2 + L),
                                        (unsigned long long)off->slot_number,
                                        scope);
                if (L2 < 0) {
                        return -1;
                }
                out[0] = 0xe0 | (uint8_t)((L << 2) & 4) | (uint8_t)(L2 & 3);
                return 2 + L + L2 + 1;
        }
        if (off->kind == MC7P_ACC_IMMEDIATE) {
                unsigned long long value = off->value;
                int type = (a->data_type != MC7P_OT_VOID &&
                            a->data_type != MC7P_OT_UNDEF) ?
                                   a->data_type : ref_type;
                if (value == 0) {
                        out[0] = 0xe8 | (uint8_t)((L << 2) & 4);
                        return 2 + L;
                } else {
                        unsigned long long offset = value;
                        bool direct_bit = mc7p_is_direct_bit_type(type, value);
                        int L2;
                        if (!direct_bit) {
                                if (offset % 8) {
                                        return -1;
                                }
                                offset /= 8;
                        }
                        L2 = mc7p_write_offset(out + 2 + L,
                                               cap - (size_t)(2 + L), offset);
                        if (L2 < 0) {
                                return -1;
                        }
                        out[0] = (direct_bit ? 0xf0 : 0xf8) |
                                 (uint8_t)((L << 2) & 4) | (uint8_t)(L2 & 3);
                        return 2 + L + L2 + 1;
                }
        }
        return -1;
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

static int mc7p_encode_operand(uint8_t *out, size_t cap, const mc7p_access_t *a,
                               const mc7p_param_t *p, int ref_type) {
        if (a->kind == MC7P_ACC_IMMEDIATE) {
                int type = (p->predefined_type >= 0 &&
                            p->predefined_type != MC7P_OT_UNDEF) ?
                                   p->predefined_type : ref_type;
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
                out[0] = (uint8_t)c;
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
        if (a->kind == MC7P_ACC_INDIRECT) {
                return mc7p_encode_indirect(out, cap, a, ref_type);
        }
        return -1;
}

static int mc7p_assemble_table(const char *buf, uint8_t *out, size_t cap) {
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
                                        out[p->byte_pos] |= (uint8_t)(1u << p->bit_pos);
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
                        out[p->byte_pos] |= (uint8_t)(by << p->bit_pos);
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
                        out[ti++] = (uint8_t)c;
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

static int mc7p_encode_ident_ref(uint8_t *out, size_t cap, const mc7p_access_t *a,
                                 int ref_type, int mode) {
        mc7p_param_t p;
        memset(&p, 0, sizeof(p));
        p.kind = MC7P_PARAM_IDENT;
        p.predefined_type = MC7P_OT_UNDEF;
        p.mode = (uint8_t)mode;
        return mc7p_encode_operand(out, cap, a, &p, ref_type);
}

static int mc7p_assemble_selected(const char *buf, uint8_t *out, size_t cap) {
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
                static const struct { const char *name; uint8_t code; } ops[] = {
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
                out[pos++] = (uint8_t)c;
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

int mc7p_assemble_one(const char *buf, uint8_t *out, size_t out_cap) {
        uint8_t small[16];
        char word[64];
        const char *p = buf;
        size_t wlen = 0;
        int table_len;

        if (!buf || !out || out_cap == 0) {
                return -1;
        }
        table_len = mc7p_assemble_selected(buf, out, out_cap);
        if (table_len < 0) {
                table_len = mc7p_assemble_table(buf, out, out_cap);
        }
        if (table_len > 0) {
                return table_len;
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
                if (out_cap < 1) return -1;
                out[0] = 0x00;
                return 1;
        }
        if (!strcmp(word, "NOT")) {
                if (out_cap < 1) return -1;
                out[0] = 0x01;
                return 1;
        }
        if (!strcmp(word, "SET_RLO")) {
                if (out_cap < 1) return -1;
                out[0] = 0x02;
                return 1;
        }
        if (!strcmp(word, "STATION")) {
                if (out_cap < 1) return -1;
                out[0] = 0x05;
                return 1;
        }
        if (!strcmp(word, "NOP_FF")) {
                if (out_cap < 2) return -1;
                out[0] = 0xff;
                out[1] = 0xff;
                return 2;
        }
        if (!strcmp(word, "LABEL") || !strncmp(word, "JMP", 3)) {
                unsigned long long id;
                int n;
                if (!mc7p_parse_label_id(p, &id)) {
                        return -1;
                }
                if (!strcmp(word, "LABEL")) {
                        small[0] = 0x68;
                } else if (!strcmp(word, "JMP") || !strncmp(word, "JMP{", 4)) {
                        small[0] = 0x6c;
                        if (mc7p_has_flag_text(word, "COND")) {
                                small[0] |= 1;
                        }
                        if (mc7p_has_flag_text(word, "NEGATED")) {
                                small[0] |= 2;
                        }
                } else {
                        return -1;
                }
                n = mc7p_encode_positive_immediate(small + 1, id);
                if (n < 0 || out_cap < (size_t)(n + 1)) {
                        return -1;
                }
                memcpy(out, small, (size_t)n + 1);
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
                if (out_cap < 2) return -1;
                out[0] = 0x14;
                out[1] = (uint8_t)v;
                return 2;
        }
        return -1;
}
