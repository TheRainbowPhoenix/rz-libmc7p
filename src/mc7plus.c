// SPDX-License-Identifier: LGPL-3.0-only
/*
 * MC7+ statement decoder -- C port of zymatik/mc7plus/asm/disasm.py.
 *
 * Approach (identical to the reference):
 *   1. candidate selection: every op whose InstrCode byte length matches and
 *      whose bytes agree with the stream after masking flag bits and
 *      in-operation coding bits;
 *   2. operand decode: walk parameter_infos in wire order (ident params
 *      decode the var-length operand forms);
 *   3. the first candidate whose operands consume the block exactly wins
 *      (longer end first, then higher flag-bit score, then lowest op number).
 */
#include "mc7plus.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#define Undef MC7P_OT_UNDEF
#define Void MC7P_OT_VOID
#define Bool MC7P_OT_BOOL
#define DInt MC7P_OT_DINT
#define String MC7P_OT_STRING
#define WString MC7P_OT_WSTRING
#define LReal MC7P_OT_LREAL
#define Any MC7P_OT_ANY
#define Real MC7P_OT_REAL
#define Pointer_t MC7P_OT_POINTER

#define U64_MAX 0xFFFFFFFFFFFFFFFFULL

/* ------------------------------------------------------------------ arena */
typedef struct block_s {
        struct block_s *next;
        size_t used, cap;
        char data[];
} block_t;

typedef struct arena_s {
        block_t *head;
} arena_t;

static void *arena_alloc(arena_t *a, size_t n) {
        if (!a->head || a->head->cap - a->head->used < n) {
                size_t cap = 65536;
                block_t *b;
                while (cap < n + sizeof(block_t) + 16) {
                        cap *= 2;
                }
                b = (block_t *)malloc(sizeof(block_t) + cap);
                if (!b) {
                        return NULL;
                }
                b->cap = cap;
                b->used = 0;
                b->next = a->head;
                a->head = b;
        }
        {
                block_t *b = a->head;
                /* keep alignment at 16 */
                size_t off = (b->used + 15u) & ~(size_t)15u;
                void *p;
                if (b->cap - off < n) {
                        b->used = b->cap;
                        return arena_alloc(a, n);
                }
                p = b->data + off;
                b->used = off + n;
                return p;
        }
}

static char *arena_strdup_n(arena_t *a, const uint8_t *s, size_t n) {
        char *p = (char *)arena_alloc(a, n + 1);
        if (!p) {
                return NULL;
        }
        memcpy(p, s, n);
        p[n] = 0;
        return p;
}

static void arena_free_all(arena_t *a) {
        block_t *b = a->head;
        while (b) {
                block_t *nx = b->next;
                free(b);
                b = nx;
        }
        a->head = NULL;
}

/* ------------------------------------------------------------------ reader */
typedef struct {
        const uint8_t *code;
        size_t len;
        size_t pos;
        const uint8_t *constants;
        size_t clen;
} reader_t;

static int rd_take(reader_t *r, size_t n, const uint8_t **out) {
        if (r->pos + n > r->len) {
                return -1;
        }
        *out = r->code + r->pos;
        r->pos += n;
        return 0;
}

static int rd_peek(reader_t *r) {
        return r->pos < r->len ? (int)r->code[r->pos] : -1;
}

static unsigned long long rd_be(const uint8_t *b, size_t n) {
        unsigned long long v = 0;
        size_t i;
        for (i = 0; i < n; i++) {
                v = (v << 8) | b[i];
        }
        return v;
}

/* --------------------------------------------------------- area byte table */
/* disasm.py _AREA_BY_ADDRESS */
static int area_from_address_byte(int b) {
        if (b >= 64 && b <= 127) {
                return MC7P_AREA_TSH0 + (b - 64);
        }
        if (b >= 192 && b <= 255) {
                return MC7P_AREA_H0 + (b - 192);
        }
        switch (b) {
        case 6: return MC7P_AREA_OB_N;
        case 7: return MC7P_AREA_FC_N;
        case 8: return MC7P_AREA_FB_N;
        case 11: return MC7P_AREA_OB_C;
        case 12: return MC7P_AREA_FC_C;
        case 13: return MC7P_AREA_FB_C;
        case 128: return MC7P_AREA_PINPUT;
        case 129: return MC7P_AREA_INPUT;
        case 130: return MC7P_AREA_OUTPUT;
        case 131: return MC7P_AREA_MEMORY;
        case 132: return MC7P_AREA_DATA;
        case 133: return MC7P_AREA_XDATA;
        case 134: return MC7P_AREA_LOCAL;
        case 135: return MC7P_AREA_FATHER;
        case 138: return MC7P_AREA_DBRETAIN;
        case 139: return MC7P_AREA_DBVOLATILE;
        case 142: return MC7P_AREA_TSLOCAL;
        case 143: return MC7P_AREA_TSFATHER;
        default: return -1;
        }
}

/* disasm.py _DIRECT_BY_CODE (PlusAreaDirect) */
static int area_from_direct(int c) {
        switch (c) {
        case 1: return MC7P_AREA_INPUT;
        case 2: return MC7P_AREA_OUTPUT;
        case 3: return MC7P_AREA_MEMORY;
        case 4: return MC7P_AREA_PINPUT;
        case 5: return MC7P_AREA_POUTPUT;
        case 6: return MC7P_AREA_LOCAL;
        case 7: return MC7P_AREA_TSLOCAL;
        default: return -1;
        }
}

static int scope_from_code(int c) {
        switch (c) {
        case 0: return MC7P_SCOPE_NATIVEGLOBAL;
        case 1: return MC7P_SCOPE_NATIVELOCAL;
        case 2: return MC7P_SCOPE_NATIVEBLOCK;
        case 3: return MC7P_SCOPE_NATIVECALL;
        default: return -1;
        }
}

/* disasm.py _DB_DIRECT_RANGE / _DB_EXT_RANGE */
static int db_direct_range(int c) {
        switch (c) {
        case 0: return MC7P_AREA_DATA;
        case 1: return MC7P_AREA_DBRETAIN;
        case 2: return MC7P_AREA_DBVOLATILE;
        default: return -1;
        }
}

static int db_ext_range(int c) {
        switch (c) {
        case 4: return MC7P_AREA_DBA;
        case 6: return MC7P_AREA_OB_N;
        case 7: return MC7P_AREA_FC_N;
        case 8: return MC7P_AREA_FB_N;
        case 9: return MC7P_AREA_PIPI;
        case 10: return MC7P_AREA_PIPQ;
        case 11: return MC7P_AREA_OB_C;
        case 12: return MC7P_AREA_FC_C;
        case 13: return MC7P_AREA_FB_C;
        default: return -1;
        }
}

/* ------------------------------------------------------------ decode state */
typedef struct {
        arena_t arena;
        int err;
} dctx_t;

static mc7p_access_t *acc_new(dctx_t *d, int kind) {
        mc7p_access_t *a = (mc7p_access_t *)arena_alloc(&d->arena,
                         sizeof(mc7p_access_t));
        if (!a) {
                d->err = 1;
                return NULL;
        }
        memset(a, 0, sizeof(*a));
        a->kind = kind;
        a->data_type = Void;
        return a;
}

static int type_from_byte(int b) {
        if (b < 0 || b >= 64) {
                return -1;
        }
        return mc7p_type_byte_to_ot[b];
}

/* -------------------------------------------------------- operand decoders */
static mc7p_access_t *decode_immediate(dctx_t *d, reader_t *r, int predef);
static mc7p_access_t *decode_memory(dctx_t *d, reader_t *r,
                                    const int *dt_out, int dt_out_len);
static mc7p_access_t *decode_native(dctx_t *d, reader_t *r);
static mc7p_access_t *decode_db(dctx_t *d, reader_t *r,
                                const int *dt_out, int dt_out_len);
static mc7p_access_t *decode_indirect(dctx_t *d, reader_t *r,
                                      const int *dt_out, int dt_out_len);
static mc7p_access_t *decode_immediate_long_ref(dctx_t *d, reader_t *r,
                                                int predef);

static mc7p_access_t *decode_immediate(dctx_t *d, reader_t *r, int predef) {
        const uint8_t *p;
        int v0;
        if (rd_take(r, 1, &p)) {
                return NULL;
        }
        v0 = p[0];
        if (v0 <= 2) {
                mc7p_access_t *a = acc_new(d, MC7P_ACC_IMMEDIATE);
                if (!a) {
                        return NULL;
                }
                a->data_type = (predef != Undef) ? predef : DInt;
                a->value = (unsigned long long)v0;
                a->bool_value = (a->data_type == Bool) ? v0 : 0;
                return a;
        }
        if (v0 == 3) {
                mc7p_access_t *a = acc_new(d, MC7P_ACC_IMMEDIATE);
                if (!a) {
                        return NULL;
                }
                a->data_type = predef;
                a->value = U64_MAX;
                return a;
        }
        if (v0 == 4) { /* ANY pointer: 10 payload bytes */
                const uint8_t *payload;
                mc7p_access_t *a;
                if (rd_take(r, 10, &payload)) {
                        return NULL;
                }
                a = acc_new(d, MC7P_ACC_IMMEDIATE);
                if (!a) {
                        return NULL;
                }
                a->value = 0;
                a->data_type = Any;
                a->complex_len = 10;
                memcpy(a->complex_bytes, payload, 10);
                return a;
        }
        {
                int hdr = v0;
                int kind = hdr & 0xF8;
                int L = hdr & 0x07;
                if (kind == 0x30) { /* real */
                        const uint8_t *payload = NULL;
                        size_t plen = 0;
                        uint8_t raw[8];
                        unsigned long long bits;
                        mc7p_access_t *a;
                        /* r26: the reference assembler right-trims ZERO bytes
                         * from the BE payload, so L==0 is AMBIGUOUS: bare `30`
                         * = 0.0 but `30 40` = 2.0.  Take the 1-byte payload
                         * unless the next byte is 0x00 (which can never be a
                         * trimmed real payload). */
                        if (L > 0 || rd_peek(r) > 0) {
                                plen = (size_t)L + 1;
                                if (rd_take(r, plen, &payload)) {
                                        return NULL;
                                }
                        }
                        /* plen == 0 -> payload stays NULL: bare 30 = 0.0 */
                        a = acc_new(d, MC7P_ACC_IMMEDIATE);
                        if (!a) {
                                return NULL;
                        }
                        if (predef == LReal || (int)plen > 4) {
                                memset(raw, 0, 8);
                                if (plen > 8) {
                                        return NULL;
                                }
                                memcpy(raw, payload, plen);
                                bits = rd_be(raw, 8);
                                a->value = bits;
                                a->data_type = LReal;
                                a->is_real = 1;
                        } else {
                                memset(raw, 0, 8);
                                if (plen > 0) {
                                        memcpy(raw, payload, plen);
                                }
                                bits = rd_be(raw, 4);
                                a->value = bits;
                                a->data_type = Real;
                                a->is_real = 1;
                        }
                        return a;
                }
                if (kind == 0x20 || kind == 0x28) {
                        const uint8_t *payload;
                        size_t plen = (size_t)L + 1;
                        unsigned long long v;
                        mc7p_access_t *a;
                        if (rd_take(r, plen, &payload)) {
                                return NULL;
                        }
                        v = rd_be(payload, plen);
                        if (kind == 0x28 && plen < 8) {
                                /* negative: re-extend with 0xFF to 8 bytes */
                                v |= U64_MAX << (plen * 8);
                        }
                        a = acc_new(d, MC7P_ACC_IMMEDIATE);
                        if (!a) {
                                return NULL;
                        }
                        a->value = v;
                        a->data_type = predef;
                        return a;
                }
        }
        return NULL;
}

static mc7p_access_t *decode_memory(dctx_t *d, reader_t *r,
                                    const int *dt_out, int dt_out_len) {
        const uint8_t *p;
        int hdr;
        if (rd_take(r, 1, &p)) {
                return NULL;
        }
        hdr = p[0];
        if ((hdr & 0xF0) == 0xA0) { /* address style: 0xA0|L (bit) 0xA4|L */
                int L = hdr & 0x03;
                int direct_bit = (hdr & 0x04) == 0;
                int area_byte, area, dt;
                const uint8_t *ab, *ob;
                unsigned long long off;
                mc7p_access_t *a;
                if (rd_take(r, 1, &ab)) {
                        return NULL;
                }
                area_byte = ab[0];
                if (rd_take(r, (size_t)L + 1, &ob)) {
                        return NULL;
                }
                off = rd_be(ob, (size_t)L + 1);
                area = area_from_address_byte(area_byte);
                if (area < 0) {
                        return NULL;
                }
                dt = direct_bit ? Bool :
                     (dt_out_len > 0 ? dt_out[0] : Void);
                a = acc_new(d, MC7P_ACC_MEMORY);
                if (!a) {
                        return NULL;
                }
                a->area = area;
                a->offset = direct_bit ? off : off * 8;
                a->data_type = dt;
                return a;
        }
        {
                int kind = hdr & 0xE0;
                if (kind == 0x60 || kind == 0x80) {
                        int area_direct = (hdr >> 2) & 0x07;
                        int L = hdr & 0x03;
                        int area, dt, direct_bit = (kind == 0x60);
                        const uint8_t *ob;
                        unsigned long long off;
                        mc7p_access_t *a;
                        if (rd_take(r, (size_t)L + 1, &ob)) {
                                return NULL;
                        }
                        off = rd_be(ob, (size_t)L + 1);
                        area = area_from_direct(area_direct);
                        if (area < 0) {
                                return NULL;
                        }
                        dt = direct_bit ? Bool :
                             (dt_out_len > 0 ? dt_out[0] : Void);
                        if (!direct_bit && dt == Bool) {
                                dt = Void;
                        }
                        a = acc_new(d, MC7P_ACC_MEMORY);
                        if (!a) {
                                return NULL;
                        }
                        a->area = area;
                        a->offset = direct_bit ? off : off * 8;
                        a->data_type = dt;
                        return a;
                }
        }
        return NULL;
}

static mc7p_access_t *decode_native(dctx_t *d, reader_t *r) {
        const uint8_t *p;
        int hdr;
        if (rd_take(r, 1, &p)) {
                return NULL;
        }
        hdr = p[0];
        if (hdr >= 0x08 && hdr <= 0x0F) { /* system pointer 1 byte */
                int code = hdr & 0x07;
                int area = area_from_direct(code);
                mc7p_access_t *a;
                if (area < 0) {
                        return NULL;
                }
                a = acc_new(d, MC7P_ACC_POINTER);
                if (!a) {
                        return NULL;
                }
                a->scope = MC7P_SCOPE_NativeSystem;
                a->pointer_number = 0;
                a->ptr_area = area;
                a->data_type = Pointer_t;
                return a;
        }
        if (hdr < 0x40 || hdr > 0x5F) {
                return NULL;
        }
        {
                int loc = (hdr >> 2) & 0x07;
                int L = hdr & 0x03;
                const uint8_t *payload;
                unsigned long long number;
                int scope, range = -1, dt;
                mc7p_access_t *a;
                if (rd_take(r, (size_t)L + 1, &payload)) {
                        return NULL;
                }
                number = rd_be(payload, (size_t)L + 1) >> 2;
                scope = scope_from_code(payload[L] & 3);
                if (scope < 0) {
                        return NULL;
                }
                a = acc_new(d, (loc == MC7P_LOC_POINTER) ? MC7P_ACC_POINTER
                                                          : MC7P_ACC_SLOT);
                if (!a) {
                        return NULL;
                }
                if (loc == MC7P_LOC_POINTER) {
                        a->scope = scope;
                        a->pointer_number = (int)number;
                        a->data_type = Pointer_t;
                        return a;
                }
                switch (loc) {
                case MC7P_LOC_BIT: range = MC7P_RANGE_SLOTBIT; dt = Bool; break;
                case MC7P_LOC_SLOT8: range = MC7P_RANGE_SLOT8; dt = MC7P_OT_BYTE; break;
                case MC7P_LOC_SLOT16: range = MC7P_RANGE_SLOT16; dt = MC7P_OT_WORD; break;
                case MC7P_LOC_SLOT32: range = MC7P_RANGE_SLOT32; dt = MC7P_OT_DWORD; break;
                case MC7P_LOC_SLOT64: range = MC7P_RANGE_SLOT64; dt = MC7P_OT_LWORD; break;
                case MC7P_LOC_REAL: range = MC7P_RANGE_SLOTREAL; dt = Real; break;
                default: return NULL;
                }
                a->kind = MC7P_ACC_SLOT;
                a->scope = scope;
                a->slot_number = (int)number;
                a->slot_type = range;
                a->data_type = dt;
                return a;
        }
}

static mc7p_access_t *decode_db(dctx_t *d, reader_t *r,
                                const int *dt_out, int dt_out_len) {
        const uint8_t *p;
        int hdr, kind;
        if (rd_take(r, 1, &p)) {
                return NULL;
        }
        hdr = p[0];
        kind = hdr & 0xF8;
        if (kind == 0xA8) { /* no offset: hdr | L ; range in low 2 bits */
                int L = hdr & 0x07;
                const uint8_t *payload;
                unsigned long long number;
                int range_, dt;
                mc7p_access_t *a;
                if (rd_take(r, (size_t)L + 1, &payload)) {
                        return NULL;
                }
                number = rd_be(payload, (size_t)L + 1) >> 2;
                range_ = db_direct_range(payload[L] & 3);
                if (range_ < 0) {
                        return NULL;
                }
                dt = dt_out_len > 0 ? dt_out[0] : Void;
                a = acc_new(d, MC7P_ACC_DBPI);
                if (!a) {
                        return NULL;
                }
                a->number = (int)number;
                a->offset = 0;
                a->range = range_;
                a->data_type = dt;
                return a;
        }
        if (kind == 0xC0 || kind == 0xD0) {
                int L = (hdr >> 2) & 3;
                int L2 = hdr & 3;
                int direct_bit = (kind == 0xC0);
                const uint8_t *payload, *ob;
                unsigned long long number, off;
                int range_, dt;
                mc7p_access_t *a;
                if (rd_take(r, (size_t)L + 1, &payload)) {
                        return NULL;
                }
                number = rd_be(payload, (size_t)L + 1) >> 2;
                range_ = db_direct_range(payload[L] & 3);
                if (range_ < 0) {
                        return NULL;
                }
                if (rd_take(r, (size_t)L2 + 1, &ob)) {
                        return NULL;
                }
                off = rd_be(ob, (size_t)L2 + 1);
                dt = direct_bit ? Bool :
                     (dt_out_len > 0 ? dt_out[0] : Void);
                a = acc_new(d, MC7P_ACC_DBPI);
                if (!a) {
                        return NULL;
                }
                a->number = (int)number;
                a->offset = direct_bit ? off : off * 8;
                a->range = range_;
                a->data_type = dt;
                return a;
        }
        if (kind == 0xB0 || kind == 0xB8) {
                int L = (hdr >> 2) & 3;
                int L2 = hdr & 3;
                int direct_bit = (kind == 0xB0);
                const uint8_t *rc, *payload, *ob;
                unsigned long long number, off;
                int range_, dt;
                mc7p_access_t *a;
                if (rd_take(r, 1, &rc)) {
                        return NULL;
                }
                range_ = db_ext_range(rc[0]);
                if (range_ < 0) {
                        return NULL;
                }
                if (rd_take(r, (size_t)L + 1, &payload)) {
                        return NULL;
                }
                number = rd_be(payload, (size_t)L + 1);
                if (rd_take(r, (size_t)L2 + 1, &ob)) {
                        return NULL;
                }
                off = rd_be(ob, (size_t)L2 + 1);
                dt = direct_bit ? Bool :
                     (dt_out_len > 0 ? dt_out[0] : Void);
                a = acc_new(d, MC7P_ACC_DBPI);
                if (!a) {
                        return NULL;
                }
                a->number = (int)number;
                a->offset = direct_bit ? off : off * 8;
                a->range = range_;
                a->data_type = dt;
                return a;
        }
        return NULL;
}

static mc7p_access_t *decode_indirect(dctx_t *d, reader_t *r,
                                      const int *dt_out, int dt_out_len) {
        const uint8_t *p;
        int hdr, kind, L, ptr_no, access_code, dt;
        mc7p_access_t *a, *base;
        if (rd_take(r, 1, &p)) {
                return NULL;
        }
        hdr = p[0];
        kind = hdr & 0xF8;
        if (kind != 0xE0 && kind != 0xE8 && kind != 0xF0 && kind != 0xF8) {
                return NULL;
        }
        L = (hdr >> 2) & 1;
        {
                const uint8_t *payload;
                if (rd_take(r, (size_t)L + 1, &payload)) {
                        return NULL;
                }
                ptr_no = (int)(rd_be(payload, (size_t)L + 1) >> 3);
                access_code = payload[L] & 7;
        }
        base = acc_new(d, MC7P_ACC_POINTER);
        if (!base) {
                return NULL;
        }
        base->scope = (access_code & 1) ? MC7P_SCOPE_NATIVEBLOCK
                                        : MC7P_SCOPE_NATIVELOCAL;
        base->pointer_number = ptr_no;
        base->data_type = Pointer_t;
        dt = (kind == 0xF0) ? Bool :
             (dt_out_len > 0 ? dt_out[0] : Void);
        a = acc_new(d, MC7P_ACC_INDIRECT);
        if (!a) {
                return NULL;
        }
        a->base = base;
        a->type_safe = (access_code & 4) ? 1 : 0;
        a->granted = (access_code & 2) ? 1 : 0;
        a->data_type = dt;
        if (kind == 0xE0) {
                int L2 = hdr & 3;
                const uint8_t *payload2;
                unsigned long long slot_no;
                int scope;
                mc7p_access_t *slot;
                if (rd_take(r, (size_t)L2 + 1, &payload2)) {
                        return NULL;
                }
                slot_no = rd_be(payload2, (size_t)L2 + 1) >> 2;
                scope = scope_from_code(payload2[L2] & 3);
                if (scope < 0) {
                        return NULL;
                }
                slot = acc_new(d, MC7P_ACC_SLOT);
                if (!slot) {
                        return NULL;
                }
                slot->scope = scope;
                slot->slot_number = (int)slot_no;
                slot->slot_type = MC7P_RANGE_SLOT32;
                slot->data_type = MC7P_OT_DWORD;
                a->offset_acc = slot;
        } else if (kind == 0xE8) {
                mc7p_access_t *imm = acc_new(d, MC7P_ACC_IMMEDIATE);
                if (!imm) {
                        return NULL;
                }
                imm->value = 0;
                imm->data_type = MC7P_OT_DINT;
                a->offset_acc = imm;
        } else {
                int L2 = hdr & 3;
                const uint8_t *ob;
                unsigned long long off;
                mc7p_access_t *imm;
                if (rd_take(r, (size_t)L2 + 1, &ob)) {
                        return NULL;
                }
                off = rd_be(ob, (size_t)L2 + 1);
                imm = acc_new(d, MC7P_ACC_IMMEDIATE);
                if (!imm) {
                        return NULL;
                }
                imm->value = (kind == 0xF0) ? off : off * 8;
                imm->data_type = MC7P_OT_DINT;
                a->offset_acc = imm;
        }
        return a;
}

static mc7p_access_t *decode_immediate_long_ref(dctx_t *d, reader_t *r,
                                                int predef) {
        const uint8_t *p, *ab;
        int hdr, L;
        unsigned long long off = 0;
        mc7p_access_t *a;
        if (rd_take(r, 1, &p)) {
                return NULL;
        }
        hdr = p[0];
        if (rd_take(r, 1, &ab)) {
                return NULL;
        }
        (void)ab; /* area byte of the constants reference */
        L = hdr & 3;
        if (L) {
                const uint8_t *ob;
                if (rd_take(r, (size_t)L + 1, &ob)) {
                        return NULL;
                }
                off = rd_be(ob, (size_t)L + 1);
        }
        a = acc_new(d, MC7P_ACC_IMMEDIATE);
        if (!a) {
                return NULL;
        }
        a->value = 0;
        if (predef == String) {
                /* python slice: raw = buf[off + 1 : off + ln]
                 * (ln INCLUDES the length byte; slice clamps at end) */
                int ln = (off < r->clen) ? r->constants[off] : 0;
                int n = 0;
                if (ln > 0 && off + 1 < r->clen) {
                        n = ln - 1;
                        if ((size_t)(off + 1) + (size_t)n > r->clen) {
                                n = (int)(r->clen - (size_t)(off + 1));
                        }
                }
                a->data_type = String;
                a->str_value = arena_strdup_n(&d->arena,
                        n > 0 ? r->constants + off + 1 : (const uint8_t *)"",
                        (size_t)(n > 0 ? n : 0));
        } else if (predef == WString) {
                int ln = (off + 1 < r->clen) ? r->constants[off + 1] : 0;
                size_t avail, nchars, i;
                uint8_t *utf8;
                size_t used = 0;
                if (off + 2 > r->clen) {
                        ln = 0;
                }
                avail = (off + 2 <= r->clen) ? r->clen - (size_t)(off + 2) : 0;
                if ((size_t)ln * 2 > avail) {
                        ln = (int)(avail / 2);
                }
                nchars = (size_t)(ln > 0 ? ln : 0);
                utf8 = (uint8_t *)arena_alloc(&d->arena, nchars * 3 + 1);
                if (!utf8) {
                        return NULL;
                }
                for (i = 0; i < nchars; i++) {
                        unsigned c = (r->constants[off + 2 + i * 2] << 8) |
                                     r->constants[off + 3 + i * 2];
                        if (c < 0x80) {
                                utf8[used++] = (uint8_t)c;
                        } else if (c < 0x800) {
                                utf8[used++] = (uint8_t)(0xC0 | (c >> 6));
                                utf8[used++] = (uint8_t)(0x80 | (c & 0x3F));
                        } else if (c >= 0xD800 && c <= 0xDFFF) {
                                /* python decode(replace) -> U+FFFD */
                                utf8[used++] = 0xEF;
                                utf8[used++] = 0xBF;
                                utf8[used++] = 0xBD;
                        } else {
                                utf8[used++] = (uint8_t)(0xE0 | (c >> 12));
                                utf8[used++] = (uint8_t)(0x80 | ((c >> 6) & 0x3F));
                                utf8[used++] = (uint8_t)(0x80 | (c & 0x3F));
                        }
                }
                utf8[used] = 0;
                a->data_type = WString;
                a->str_value = (char *)utf8;
        } else {
                /* DT/DTL/TOD long payloads: raw complex bytes */
                size_t avail = (off < r->clen) ? r->clen - (size_t)off : 0;
                a->data_type = predef;
                a->complex_len = (int)(avail > 16 ? 16 : avail);
                if (a->complex_len > 0) {
                        memcpy(a->complex_bytes, r->constants + off,
                               (size_t)a->complex_len);
                }
        }
        return a;
}

static mc7p_access_t *decode_ident(dctx_t *d, reader_t *r, int mode,
                                   int predef, const int *dt_out,
                                   int dt_out_len) {
        int hdr = rd_peek(r);
        if (hdr < 0) {
                return NULL;
        }
        /* 1) immediates: tiny 0..2, -1 (3), ANY (4), int 0x20/0x28, real 0x30 */
        if (hdr <= 4 || (hdr & 0xF8) == 0x20 || (hdr & 0xF8) == 0x28 ||
            (hdr & 0xF8) == 0x30) {
                return decode_immediate(d, r, predef);
        }
        /* 1b) immediate-long reference for String/WString params */
        if (hdr >= 0xA4 && hdr <= 0xA7 && dt_out_len > 0 &&
            (dt_out[0] == String || dt_out[0] == WString)) {
                return decode_immediate_long_ref(d, r, dt_out[0]);
        }
        /* 2) native slot/pointer */
        if (hdr >= 0x40 && hdr <= 0x5F) {
                return decode_native(d, r);
        }
        /* r20d: pointer-mode params may still carry a MEMORY-form access;
         * decode native for native headers, memory forms fall through. */
        if ((mode == MC7P_MODE_POINTER || mode == MC7P_MODE_SYSPTR) &&
            !(hdr >= 0x60 && hdr <= 0xFF)) {
                return decode_native(d, r);
        }
        /* 3) memory direct 0x60..0x9F and address style 0xA0..0xA7 */
        if ((hdr >= 0x60 && hdr <= 0x9F) || (hdr >= 0xA0 && hdr <= 0xA7)) {
                return decode_memory(d, r, dt_out, dt_out_len);
        }
        /* 4) DB forms 0xA8..0xDF */
        if (hdr >= 0xA8 && hdr <= 0xDF) {
                return decode_db(d, r, dt_out, dt_out_len);
        }
        /* 5) indirect 0xE0..0xFF */
        if (hdr >= 0xE0) {
                return decode_indirect(d, r, dt_out, dt_out_len);
        }
        return NULL;
}

/* ----------------------------------------------------------- first-byte idx */
typedef struct {
        int16_t ops[512];   /* op numbers, ascending */
        int count;
} first_slot_t;

static first_slot_t g_first[256];
static int g_first_built = 0;

static uint32_t flag_mask_of(const mc7p_op_t *op, int byte) {
        uint32_t m = 0;
        int i;
        for (i = 0; i < op->param_count; i++) {
                const mc7p_param_t *p = &mc7p_params[op->param_off + i];
                if (p->kind == MC7P_PARAM_FLAG && p->byte_pos == byte) {
                        m |= 1u << p->bit_pos;
                }
        }
        return m;
}

static uint32_t coding_mask_of(const mc7p_op_t *op, int byte) {
        uint32_t m = 0;
        int i;
        for (i = 0; i < op->param_count; i++) {
                const mc7p_param_t *p = &mc7p_params[op->param_off + i];
                if (p->kind == MC7P_PARAM_CODING && p->byte_pos == byte) {
                        uint8_t maxv = 0;
                        int j;
                        for (j = 0; j < p->coding_len; j++) {
                                uint8_t enc = mc7p_type_codings[
                                        p->coding_off + j].enc;
                                if (enc > maxv) {
                                        maxv = enc;
                                }
                        }
                        /* python: width = max(values).bit_length() */
                        {
                                uint32_t bits = 0, w = maxv;
                                while (w) {
                                        bits++;
                                        w >>= 1;
                                }
                                m |= ((1u << bits) - 1u) << p->bit_pos;
                        }
                }
        }
        return m;
}

static void build_first_index(void) {
        int got, num;
        if (g_first_built) {
                return;
        }
        memset(g_first, 0, sizeof(g_first));
        for (got = 0; got < 256; got++) {
                for (num = 0; num < MC7P_OP_COUNT; num++) {
                        const mc7p_op_t *op = &mc7p_ops[num];
                        uint32_t mask;
                        if (!op->name || op->code_len == 0) {
                                continue;
                        }
                        mask = flag_mask_of(op, 0) | coding_mask_of(op, 0);
                        if ((got & ~mask & 0xFF) == op->code[0]) {
                                if (g_first[got].count < 512) {
                                        g_first[got].ops[g_first[got].count++]
                                                = (int16_t)num;
                                }
                        }
                }
        }
        g_first_built = 1;
}

/* --------------------------------------------------------- statement decode */
typedef struct {
        mc7p_access_t **ops;
        int count, cap;
} opl_t;

static int opl_push(dctx_t *d, opl_t *l, mc7p_access_t *a) {
        if (l->count >= MC7P_MAX_OPERANDS) {
                return -1;
        }
        if (l->count >= l->cap) {
                int ncap = l->cap ? l->cap * 2 : 8;
                mc7p_access_t **n = (mc7p_access_t **)arena_alloc(&d->arena,
                                   (size_t)ncap * sizeof(mc7p_access_t *));
                if (!n) {
                        return -1;
                }
                if (l->ops) {
                        memcpy(n, l->ops, (size_t)l->count *
                               sizeof(mc7p_access_t *));
                }
                l->ops = n;
                l->cap = ncap;
        }
        l->ops[l->count++] = a;
        return 0;
}

static int decode_params(dctx_t *d, const mc7p_op_t *op, reader_t *r,
                         size_t stmt_pos, opl_t *opl, int *end_out) {
        int pending = -1;      /* pending_predef */
        int multiple_count = -1;
        int pidx, param_count = op->param_count;
        for (pidx = 0; pidx < param_count; pidx++) {
                const mc7p_param_t *p = &mc7p_params[op->param_off + pidx];
                if (p->kind == MC7P_PARAM_FLAG) {
                        continue; /* flags restored after best candidate */
                }
                if (p->kind == MC7P_PARAM_CODING) {
                        /* recover the type from the code bits */
                        uint8_t maxv = 0;
                        uint32_t bits, width_bits, w;
                        int j, ot = -1;
                        for (j = 0; j < p->coding_len; j++) {
                                uint8_t enc = mc7p_type_codings[
                                        p->coding_off + j].enc;
                                if (enc > maxv) {
                                        maxv = enc;
                                }
                        }
                        w = maxv;
                        width_bits = 0;
                        while (w) {
                                width_bits++;
                                w >>= 1;
                        }
                        bits = (r->code[stmt_pos + p->byte_pos] >> p->bit_pos) &
                               ((width_bits >= 32) ? 0xFFFFFFFFu :
                                ((1u << width_bits) - 1u));
                        /* python rev = {enc: ot}; last pair wins */
                        for (j = 0; j < p->coding_len; j++) {
                                if (mc7p_type_codings[p->coding_off + j].enc ==
                                    bits) {
                                        ot = mc7p_type_codings[
                                                p->coding_off + j].ot;
                                }
                        }
                        if (ot < 0) {
                                return -1;
                        }
                        {
                                mc7p_access_t *a = acc_new(d, MC7P_ACC_TYPE);
                                if (!a) {
                                        return -1;
                                }
                                a->type_val = ot;
                                a->data_type = ot;
                                if (opl_push(d, opl, a)) {
                                        return -1;
                                }
                        }
                        pending = ot;
                        continue;
                }
                if (p->kind == MC7P_PARAM_TYPE) {
                        const uint8_t *tb;
                        int ot;
                        mc7p_access_t *a;
                        if (rd_take(r, 1, &tb)) {
                                return -1;
                        }
                        ot = type_from_byte(tb[0]);
                        if (ot < 0) {
                                return -1;
                        }
                        a = acc_new(d, MC7P_ACC_TYPE);
                        if (!a) {
                                return -1;
                        }
                        a->type_val = ot;
                        a->data_type = ot;
                        if (opl_push(d, opl, a)) {
                                return -1;
                        }
                        pending = -1;
                        continue;
                }
                if (p->kind == MC7P_PARAM_COND) {
                        const uint8_t *cb;
                        int cond;
                        mc7p_access_t *a;
                        if (rd_take(r, 1, &cb)) {
                                return -1;
                        }
                        cond = (cb[0] < 32) ? mc7p_relcond_to_cond[cb[0]] : -1;
                        if (cond < 0) {
                                return -1;
                        }
                        a = acc_new(d, MC7P_ACC_CONDITION);
                        if (!a) {
                                return -1;
                        }
                        a->cond_val = cond;
                        a->data_type = Void;
                        if (opl_push(d, opl, a)) {
                                return -1;
                        }
                        continue;
                }
                /* IDENT */
                {
                        int dt_out[1];
                        int dt_out_len = 0;
                        int repeat = 1;
                        int rep;
                        if (p->ref_type != -1) {
                                if (pending != -1) {
                                        dt_out[0] = pending;
                                        dt_out_len = 1;
                                }
                        } else {
                                dt_out[0] = p->predefined_type;
                                dt_out_len = 1;
                        }
                        if (op->multi && pidx == param_count - 1 &&
                            multiple_count >= 0) {
                                repeat = multiple_count;
                        }
                        for (rep = 0; rep < repeat; rep++) {
                                mc7p_access_t *a = decode_ident(d, r,
                                        p->mode, p->predefined_type, dt_out,
                                        dt_out_len);
                                if (!a || opl_push(d, opl, a)) {
                                        return -1;
                                }
                        }
                        if (p->mode == MC7P_MODE_LEN && opl->count > 0) {
                                mc7p_access_t *last =
                                        opl->ops[opl->count - 1];
                                if (last->kind == MC7P_ACC_IMMEDIATE) {
                                        multiple_count = (int)last->value;
                                }
                        }
                        pending = -1;
                }
        }
        *end_out = (int)r->pos;
        return 0;
}

static void restore_flags(const mc7p_op_t *op, const uint8_t *code,
                          size_t pos, int *flags, int *count) {
        int i;
        *count = 0;
        for (i = 0; i < op->param_count && *count < 8; i++) {
                const mc7p_param_t *p = &mc7p_params[op->param_off + i];
                if (p->kind == MC7P_PARAM_FLAG) {
                        if (code[pos + p->byte_pos] & (1u << p->bit_pos)) {
                                flags[(*count)++] = p->flag_type;
                        }
                }
        }
}


/* best-candidate selection at code[pos] (shared by decode_code and
 * disassemble_one): longest end wins, then higher flag-bit score, then
 * lowest op number (candidates iterate in ascending op order). */
typedef struct {
        int op;                     /* winning op number, -1 if none */
        mc7p_access_t **ops;        /* arena-backed operand array */
        int op_count;
        int end;                    /* absolute end offset */
        int flags[8];
        int flag_count;
} best_t;

static int decode_best_at(dctx_t *d, const uint8_t *code, size_t len,
                          size_t pos, best_t *best) {
        int slot_i;
        int matched = 0;
        int best_end = -1, best_score = -1;
        memset(best, 0, sizeof(*best));
        best->op = -1;
        for (slot_i = 0; slot_i < g_first[code[pos]].count; slot_i++) {
                int num = g_first[code[pos]].ops[slot_i];
                const mc7p_op_t *op = &mc7p_ops[num];
                reader_t r;
                opl_t opl;
                int end = 0, ok, bi;
                uint32_t score = 0;

                if (op->code_len == 0 || pos + op->code_len > len) {
                        continue;
                }
                ok = 1;
                for (bi = 0; bi < op->code_len; bi++) {
                        uint32_t mask = flag_mask_of(op, bi) |
                                        coding_mask_of(op, bi);
                        if ((code[pos + bi] & ~mask & 0xFF) != op->code[bi]) {
                                ok = 0;
                                break;
                        }
                }
                if (!ok) {
                        continue;
                }
                memset(&r, 0, sizeof(r));
                r.code = code;
                r.len = len;
                r.pos = pos + op->code_len;
                memset(&opl, 0, sizeof(opl));
                if (decode_params(d, op, &r, pos, &opl, &end) != 0) {
                        continue;
                }
                matched = 1;
                {
                        int fi;
                        for (fi = 0; fi < op->param_count; fi++) {
                                const mc7p_param_t *p =
                                        &mc7p_params[op->param_off + fi];
                                if (p->kind == MC7P_PARAM_FLAG) {
                                        uint8_t bits = code[pos +
                                                p->byte_pos] &
                                                (1u << p->bit_pos);
                                        while (bits) {
                                                score += bits & 1u;
                                                bits >>= 1;
                                        }
                                }
                        }
                }
                if (end > best_end ||
                    (end == best_end && (int)score > best_score)) {
                        int fv[8];
                        int fc = 0;
                        best_end = end;
                        best_score = (int)score;
                        best->op = num;
                        best->ops = opl.ops;
                        best->op_count = opl.count;
                        best->end = end;
                        restore_flags(op, code, pos, fv, &fc);
                        memcpy(best->flags, fv, sizeof(fv));
                        best->flag_count = fc;
                }
        }
        return matched;
}

int mc7p_decode_code(const uint8_t *code, size_t len,
                     const uint8_t *constants, size_t clen,
                     mc7p_list_t *out, size_t *err_pos) {
        dctx_t d;
        size_t pos = 0;
        mc7p_list_t list;

        build_first_index();
        memset(&d, 0, sizeof(d));
        memset(&list, 0, sizeof(list));

        if (err_pos) {
                *err_pos = 0;
        }
        if (len == 0) {
                out->stmts = NULL;
                out->count = 0;
                out->_arena = NULL;
                return 0;
        }

        while (pos < len) {
                size_t start = pos;
                best_t best;
                if (!decode_best_at(&d, code, len, pos, &best)) {
                        if (err_pos) {
                                *err_pos = pos;
                        }
                        arena_free_all(&d.arena);
                        if (list.count == 0) {
                                out->stmts = NULL;
                                out->count = 0;
                                out->_arena = NULL;
                        } else {
                                out->stmts = (mc7p_stmt_t **)list.stmts;
                                out->count = list.count;
                                out->_arena = d.arena.head;
                        }
                        return -1;
                }
                {
                        mc7p_stmt_t *st = (mc7p_stmt_t *)arena_alloc(&d.arena,
                                                   sizeof(mc7p_stmt_t));
                        if (!st) {
                                break;
                        }
                        memset(st, 0, sizeof(*st));
                        st->operation = best.op;
                        st->operands = best.ops;
                        st->operand_count = best.op_count;
                        memcpy(st->flags, best.flags, sizeof(best.flags));
                        st->flag_count = best.flag_count;
                        st->sac = (long)start;
                        st->bin_len = (long)(best.end - (int)start);
                        if (list.count == 0 || list.count >= list.cap) {
                                /* statements live in the arena too */
                                mc7p_stmt_t **n;
                                int ncap = list.cap ? list.cap * 2 : 16;
                                n = (mc7p_stmt_t **)arena_alloc(&d.arena,
                                        (size_t)ncap * sizeof(mc7p_stmt_t *));
                                if (!n) {
                                        break;
                                }
                                if (list.stmts) {
                                        memcpy(n, list.stmts,
                                               (size_t)list.count *
                                               sizeof(mc7p_stmt_t *));
                                }
                                list.stmts = n;
                                list.cap = ncap;
                        }
                        list.stmts[list.count++] = st;
                }
                if (best.end <= (int)start) {
                        /* cannot make progress; avoid infinite loop */
                        if (err_pos) {
                                *err_pos = best.end;
                        }
                        arena_free_all(&d.arena);
                        return -1;
                }
                pos = (size_t)best.end;
        }

        out->stmts = list.stmts;
        out->count = list.count;
        out->_arena = d.arena.head;
        return 0;
}

void mc7p_free_list(mc7p_list_t *list) {
        if (list && list->_arena) {
                arena_t a;
                a.head = (block_t *)list->_arena;
                arena_free_all(&a);
                list->_arena = NULL;
                list->stmts = NULL;
                list->count = 0;
        }
}

/* ------------------------------------------------------------- text render */
/* port of zymatik/mc7plus/asm/text.py (render side) */

typedef struct {
        char *buf;
        size_t len, cap;
        int err;
} sb_t;

static void sb_putn(sb_t *s, const char *p, size_t n) {
        if (s->err) {
                return;
        }
        if (s->len + n + 1 > s->cap) {
                size_t ncap = s->cap ? s->cap * 2 : 256;
                char *nb;
                while (s->len + n + 1 > ncap) {
                        ncap *= 2;
                }
                nb = (char *)realloc(s->buf, ncap);
                if (!nb) {
                        s->err = 1;
                        return;
                }
                s->buf = nb;
                s->cap = ncap;
        }
        memcpy(s->buf + s->len, p, n);
        s->len += n;
        s->buf[s->len] = 0;
}

static void sb_put(sb_t *s, const char *p) {
        sb_putn(s, p, strlen(p));
}

static void sb_printf(sb_t *s, const char *fmt, ...) {
        char tmp[256];
        va_list ap;
        int n;
        va_start(ap, fmt);
        n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
        va_end(ap);
        if (n < 0) {
                s->err = 1;
                return;
        }
        if ((size_t)n < sizeof(tmp)) {
                sb_putn(s, tmp, (size_t)n);
        } else {
                char *big = (char *)malloc((size_t)n + 1);
                if (!big) {
                        s->err = 1;
                        return;
                }
                va_start(ap, fmt);
                vsnprintf(big, (size_t)n + 1, fmt, ap);
                va_end(ap);
                sb_putn(s, big, (size_t)n);
                free(big);
        }
}

/* python repr()-compatible shortest float text */
static void fmt_python_double(sb_t *s, double v, int suffix_l) {
        char tmp[64];
        int prec;
        if (v != v || v * 0 != 0) { /* nan / inf */
                sb_printf(s, "%s", v != v ? "nan" : (v > 0 ? "inf" : "-inf"));
                return;
        }
        for (prec = 1; prec <= 17; prec++) {
                snprintf(tmp, sizeof(tmp), "%.*g", prec, v);
                if (strtod(tmp, NULL) == v) {
                        break;
                }
        }
        if (!strpbrk(tmp, ".eE")) {
                size_t l = strlen(tmp);
                tmp[l] = '.';
                tmp[l + 1] = '0';
                tmp[l + 2] = 0;
        }
        sb_put(s, tmp);
        if (suffix_l) {
                sb_put(s, "L");
        }
}

static int bits_width(int t) {
        switch (t) {
        case MC7P_OT_BOOL: return 1;
        case MC7P_OT_BBOOL: case MC7P_OT_BYTE: case MC7P_OT_CHAR:
        case MC7P_OT_USINT: case MC7P_OT_SINT:
                return 8;
        case MC7P_OT_WORD: case MC7P_OT_INT: case MC7P_OT_UINT:
        case MC7P_OT_WCHAR: case MC7P_OT_DATE: case MC7P_OT_S5TIME:
                return 16;
        case MC7P_OT_DWORD: case MC7P_OT_DINT: case MC7P_OT_UDINT:
        case MC7P_OT_REAL: case MC7P_OT_TIME: case MC7P_OT_TIME_OF_DAY:
                return 32;
        case MC7P_OT_LWORD: case MC7P_OT_LINT: case MC7P_OT_ULINT:
        case MC7P_OT_LREAL: case MC7P_OT_LTIME: case MC7P_OT_LTOD:
        case MC7P_OT_LDT: case MC7P_OT_DTL:
                return 64;
        default:
                return 8;
        }
}

static void explicit_suffix(sb_t *s, int t, const char *letter) {
        int hit = 0;
        if (strcmp(letter, "D") == 0) {
                hit = (t == MC7P_OT_REAL || t == MC7P_OT_TIME ||
                       t == MC7P_OT_TIME_OF_DAY);
        } else if (strcmp(letter, "L") == 0) {
                hit = (t == MC7P_OT_LREAL || t == MC7P_OT_LTIME ||
                       t == MC7P_OT_LINT || t == MC7P_OT_ULINT ||
                       t == MC7P_OT_LTOD || t == MC7P_OT_LDT ||
                       t == MC7P_OT_DTL);
        } else if (strcmp(letter, "W") == 0) {
                hit = (t == MC7P_OT_DATE || t == MC7P_OT_S5TIME ||
                       t == MC7P_OT_WCHAR);
        }
        if (hit) {
                sb_printf(s, ":%s", mc7p_ot_names[t] ? mc7p_ot_names[t] : "?");
        }
}

static void render_access(sb_t *s, const mc7p_access_t *a);

static void render_immediate(sb_t *s, const mc7p_access_t *a) {
        if (a->is_real) {
                if (a->data_type == LReal) {
                        double v;
                        unsigned long long bits = a->value;
                        memcpy(&v, &bits, 8);
                        fmt_python_double(s, v, 1);
                } else {
                        double v;
                        float f;
                        uint32_t bits = (uint32_t)(a->value & 0xFFFFFFFFu);
                        memcpy(&f, &bits, 4);
                        v = (double)f;
                        fmt_python_double(s, v, 0);
                }
                return;
        }
        if (a->data_type == Bool) {
                sb_put(s, a->bool_value ? "TRUE" : "FALSE");
                return;
        }
        if (a->str_value && (a->data_type == String ||
                             a->data_type == WString)) {
                sb_put(s, "'");
                sb_put(s, a->str_value);
                sb_put(s, "'");
                return;
        }
        {
                unsigned long long v = a->value;
                long long signed_v = (v < (1ULL << 63)) ?
                                             (long long)v :
                                             -(long long)(~v) - 1;
                int t = a->data_type;
                switch (t) {
                case MC7P_OT_LINT:
                        sb_printf(s, "L#%lld", signed_v);
                        return;
                case MC7P_OT_ULINT:
                        sb_printf(s, "UL#%llu", v);
                        return;
                case MC7P_OT_DWORD:
                        sb_printf(s, "DW#16#%llX", v & 0xFFFFFFFFu);
                        return;
                case MC7P_OT_UDINT:
                        sb_printf(s, "%llu", v & 0xFFFFFFFFu);
                        return;
                case MC7P_OT_DINT:
                        sb_printf(s, "%lld", signed_v);
                        return;
                case MC7P_OT_WORD:
                case MC7P_OT_UINT:
                        sb_printf(s, "W#16#%llX", v & 0xFFFFu);
                        return;
                case MC7P_OT_BYTE:
                case MC7P_OT_USINT:
                case MC7P_OT_BBOOL:
                        sb_printf(s, "B#16#%llX", v & 0xFFu);
                        return;
                case MC7P_OT_SINT:
                case MC7P_OT_INT:
                case MC7P_OT_CHAR:
                        sb_printf(s, "%lld", signed_v);
                        return;
                case MC7P_OT_TIME:
                        sb_printf(s, "T#%lldms", signed_v);
                        return;
                case MC7P_OT_S5TIME:
                        sb_printf(s, "S5T#%lluMS", v & 0x3FFu);
                        return;
                case MC7P_OT_DATE:
                        sb_printf(s, "D#%llu", v & 0xFFFFu);
                        return;
                case MC7P_OT_TIME_OF_DAY:
                        sb_printf(s, "TOD#%llu", v & 0xFFFFFFFFu);
                        return;
                case Undef:
                case Void:
                        sb_printf(s, "%lld", signed_v);
                        return;
                default:
                        sb_printf(s, "%lld", signed_v);
                        return;
                }
        }
}

static const char *area_prefix(int area) {
        switch (area) {
        case MC7P_AREA_INPUT: return "I";
        case MC7P_AREA_OUTPUT: return "Q";
        case MC7P_AREA_MEMORY: return "M";
        case MC7P_AREA_LOCAL: return "L";
        case MC7P_AREA_PINPUT: return "PI";
        case MC7P_AREA_POUTPUT: return "PQ";
        default: return mc7p_area_names[area] ? mc7p_area_names[area] : "?";
        }
}

static const char *scope_short(int scope) {
        switch (scope) {
        case MC7P_SCOPE_NATIVELOCAL: return "L";
        case MC7P_SCOPE_NATIVEGLOBAL: return "G";
        case MC7P_SCOPE_NATIVECALL: return "C";
        case MC7P_SCOPE_NATIVEBLOCK: return "B";
        default: return "L";
        }
}

static void render_access(sb_t *s, const mc7p_access_t *a) {
        switch (a->kind) {
        case MC7P_ACC_MEMORY: {
                const char *pre = area_prefix(a->area);
                unsigned long long byte = a->offset / 8;
                unsigned long long bit = a->offset % 8;
                if (a->data_type == Bool ||
                    ((a->data_type == Undef || a->data_type == Void) &&
                     bit != 0)) {
                        sb_printf(s, "%%%s%llu.%llu", pre, byte, bit);
                        return;
                }
                {
                        int width = bits_width(a->data_type) / 8;
                        const char *letter = (width == 1) ? "B" :
                                             (width == 2) ? "W" :
                                             (width == 4) ? "D" :
                                             (width == 8) ? "L" : "B";
                        sb_printf(s, "%%%s%s%llu", pre, letter, byte);
                        explicit_suffix(s, a->data_type, letter);
                }
                return;
        }
        case MC7P_ACC_DBPI: {
                const char *pre = (a->range == MC7P_AREA_DATA) ? "DB" :
                                  (a->range == MC7P_AREA_DBRETAIN) ? "DBR" :
                                  (a->range == MC7P_AREA_DBVOLATILE) ? "DBV" :
                                  "DB";
                unsigned long long byte = a->offset / 8;
                unsigned long long bit = a->offset % 8;
                if (bit != 0 || a->data_type == Bool) {
                        sb_printf(s, "%s%u.DBX%llu.%llu", pre,
                                  (unsigned)a->number, byte, bit);
                        return;
                }
                {
                        int width = bits_width(a->data_type) / 8;
                        const char *letter = (width == 1) ? "DBB" :
                                             (width == 2) ? "DBW" :
                                             (width == 4) ? "DBD" :
                                             (width == 8) ? "DBL" : "DBB";
                        sb_printf(s, "%s%u.%s%llu", pre,
                                  (unsigned)a->number, letter, byte);
                }
                return;
        }
        case MC7P_ACC_SLOT:
                sb_printf(s, "@S%s.%s.%d", scope_short(a->scope),
                          mc7p_range_names[a->slot_type], a->slot_number);
                return;
        case MC7P_ACC_POINTER:
                if (a->scope == MC7P_SCOPE_NativeSystem) {
                        sb_printf(s, "@PSYS.%d", a->ptr_area);
                } else {
                        sb_printf(s, "@P%s.%d", scope_short(a->scope),
                                  a->pointer_number);
                }
                return;
        case MC7P_ACC_INDIRECT:
                sb_put(s, "[");
                render_access(s, a->base);
                sb_put(s, " + ");
                render_access(s, a->offset_acc);
                sb_put(s, "]");
                return;
        case MC7P_ACC_TYPE:
                sb_printf(s, ":%s",
                          mc7p_ot_names[a->type_val] ?
                          mc7p_ot_names[a->type_val] : "?");
                return;
        case MC7P_ACC_CONDITION:
                sb_printf(s, "=%s", mc7p_cond_names[a->cond_val]);
                return;
        case MC7P_ACC_IMMEDIATE:
                render_immediate(s, a);
                return;
        default:
                sb_put(s, "?");
                return;
        }
}

int mc7p_render_statement(const mc7p_stmt_t *st, char *buf, size_t bufsize) {
        sb_t s;
        const char *name = mc7p_op_name(st->operation);
        char head[64];
        int i;
        memset(&s, 0, sizeof(s));
        if (!name) {
                snprintf(head, sizeof(head), "OP_%d", st->operation);
                name = head;
        }
        sb_put(&s, name);
        if (st->flag_count > 0) {
                int first = 1;
                sb_put(&s, "{");
                for (i = 0; i < st->flag_count; i++) {
                        int f = st->flags[i];
                        if (f == MC7P_FLAG_UNDEF) {
                                continue;
                        }
                        sb_put(&s, first ? "" : ",");
                        sb_put(&s, mc7p_flag_names[f]);
                        first = 0;
                }
                sb_put(&s, "}");
        }
        for (i = 0; i < st->operand_count; i++) {
                sb_put(&s, " ");
                render_access(&s, st->operands[i]);
        }
        if (s.len == 0) {
                /* python: (head + " " + ops).strip() */
        }
        if (s.buf && s.len && s.buf[s.len - 1] == ' ') {
                s.buf[--s.len] = 0;
        }
        if (s.err || !s.buf) {
                free(s.buf);
                if (bufsize) {
                        buf[0] = 0;
                }
                return -1;
        }
        {
                size_t n = s.len;
                if (n > bufsize - 1) {
                        n = bufsize - 1;
                }
                memcpy(buf, s.buf, n);
                buf[n] = 0;
        }
        free(s.buf);
        return (int)s.len;
}

const char *mc7p_op_name(int operation) {
        if (operation < 0 || operation >= MC7P_OP_COUNT) {
                return NULL;
        }
        return mc7p_ops[operation].name;
}

int mc7p_disassemble_one(const uint8_t *code, size_t len, char *buf,
                         size_t bufsize, int *is_return) {
        dctx_t d;
        best_t best;
        int is_ret = 0;

        if (is_return) {
                *is_return = 0;
        }
        if (len == 0) {
                return -1;
        }
        build_first_index();
        memset(&d, 0, sizeof(d));
        if (decode_best_at(&d, code, len, 0, &best) && best.op >= 0) {
                mc7p_stmt_t st;
                memset(&st, 0, sizeof(st));
                st.operation = best.op;
                st.operands = best.ops;
                st.operand_count = best.op_count;
                memcpy(st.flags, best.flags, sizeof(best.flags));
                st.flag_count = best.flag_count;
                st.sac = 0;
                st.bin_len = best.end;
                if (mc7p_render_statement(&st, buf, bufsize) >= 0) {
                        const char *nm = mc7p_ops[best.op].name;
                        is_ret = nm && strncmp(nm, "RET", 3) == 0;
                } else {
                        best.op = -1;
                }
        }
        arena_free_all(&d.arena);
        if (best.op < 0) {
                return -1;
        }
        if (is_return && is_ret) {
                *is_return = 1;
        }
        return best.end;
}

int mc7p_flow_one(const uint8_t *code, size_t len, size_t off,
                  mc7p_flow_t *out) {
        dctx_t d;
        best_t best;
        const char *nm;
        int flow_cond = 0;

        if (out) {
                out->kind = MC7P_FLOW_NONE;
                out->label_id = -1;
        }
        if (len == 0 || off >= len) {
                return -1;
        }
        build_first_index();
        memset(&d, 0, sizeof(d));
        if (!decode_best_at(&d, code, len, off, &best) || best.op < 0) {
                arena_free_all(&d.arena);
                return -1;
        }
        nm = mc7p_ops[best.op].name;
        if (nm && strncmp(nm, "LABEL", 6) == 0) {
                /* label marker: operand 0 carries the label id */
                if (out && best.op_count > 0) {
                        const mc7p_access_t *a = best.ops[0];
                        if (a->kind == MC7P_ACC_IMMEDIATE && !a->is_real) {
                                out->kind = MC7P_FLOW_LABEL;
                                out->label_id = (long)a->value;
                        }
                }
        } else if (nm && strncmp(nm, "JMP", 3) == 0) {
                /* plain JMP: label in operand 0; every other JMP_* variant
                 * carries the target label in the LAST operand (zymatik VM
                 * reads o[-1]).  The wire COND flag marks conditional. */
                int i;
                const mc7p_access_t *a = NULL;
                for (i = 0; i < best.flag_count; i++) {
                        if (best.flags[i] == MC7P_FLAG_COND) {
                                flow_cond = 1;
                                break;
                        }
                }
                if (best.op_count == 1) {
                        a = best.ops[0];
                } else if (best.op_count > 1) {
                        a = best.ops[best.op_count - 1];
                }
                if (out) {
                        out->kind = flow_cond ? MC7P_FLOW_CJMP : MC7P_FLOW_JMP;
                        if (a && a->kind == MC7P_ACC_IMMEDIATE && !a->is_real) {
                                out->label_id = (long)a->value;
                        }
                }
        } else if (nm && strncmp(nm, "CALL", 4) == 0) {
                if (out) {
                        out->kind = MC7P_FLOW_CALL;
                }
        } else if (nm && strncmp(nm, "RET", 3) == 0) {
                if (out) {
                        out->kind = MC7P_FLOW_RET;
                }
        }
        arena_free_all(&d.arena);
        return best.end;
}
