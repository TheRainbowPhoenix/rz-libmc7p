// SPDX-License-Identifier: LGPL-3.0-only
#ifndef LIB_MC7PLUS_H
#define LIB_MC7PLUS_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "mc7plus_isa.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * MC7+ (S7-1200/1500) statement decoder + assembler-text renderer.
 *
 * Faithful C port of the zymatik python reference:
 *   zymatik/mc7plus/asm/disasm.py  (candidate decode)
 *   zymatik/mc7plus/asm/text.py    (render)
 *
 * MC7+ is the S7-1200/1500 bytecode ("classic" MC7 of the S7-300/400 is a
 * different ISA and stays in simatic.c -- the two coexist; select them
 * explicitly, a raw blob is ambiguous between the two dialects).
 */

/* access kinds (model.py AccessBase subclasses) */
enum {
	MC7P_ACC_MEMORY = 0,
	MC7P_ACC_IMMEDIATE,
	MC7P_ACC_CONDITION,
	MC7P_ACC_SLOT,
	MC7P_ACC_POINTER,
	MC7P_ACC_TYPE,
	MC7P_ACC_DBPI,
	MC7P_ACC_INDIRECT,
};

typedef struct mc7p_access_s {
	int kind;
	int data_type;              /* OperandType (MC7P_OT_*) */

	/* MC7P_ACC_MEMORY: offset is a BIT offset (byte*8 + bit) */
	int area;                   /* MC7P_AREA_* */
	unsigned long long offset;

	/* MC7P_ACC_IMMEDIATE */
	unsigned long long value;   /* raw payload / IEEE bits when is_real */
	int is_real;
	int bool_value;
	char *str_value;            /* String/WString complex payload (owned) */
	unsigned char complex_bytes[16];
	int complex_len;

	/* MC7P_ACC_SLOT */
	int scope;                  /* MC7P_SCOPE_* */
	int slot_number;
	int slot_type;              /* MC7P_RANGE_* */

	/* MC7P_ACC_POINTER */
	int pointer_number;
	int ptr_area;               /* NativeSystem 1-byte form */

	/* MC7P_ACC_DBPI */
	int number;                 /* DB/DI number */
	int range;                  /* MC7P_AREA_* subrange */

	/* MC7P_ACC_INDIRECT */
	struct mc7p_access_s *base;    /* PointerAccess (owned) */
	struct mc7p_access_s *offset_acc; /* Slot or Immediate (owned) */
	int type_safe;
	int granted;

	/* MC7P_ACC_TYPE / MC7P_ACC_CONDITION */
	int type_val;
	int cond_val;
} mc7p_access_t;

typedef struct mc7p_stmt_s {
	int operation;              /* PlusOperator number */
	mc7p_access_t **operands;   /* owned by the list */
	int operand_count;
	int flags[8];
	int flag_count;
	long sac;                   /* statement address in the code blob */
	long bin_len;               /* encoded byte length */
} mc7p_stmt_t;

typedef struct mc7p_list_s {
	mc7p_stmt_t **stmts;
	int count;
	int cap;                    /* internal */
	void *_arena;               /* internal */
} mc7p_list_t;

/*
 * Decode a full MC7+ code blob.  constants = the immediateLong blob when
 * available (String/WString long references); may be NULL/0.
 * Returns 0 and fills *out on success (even for partially-empty input);
 * returns -1 when decoding fails at some offset (see *err_pos).
 * Free with mc7p_free_list().
 */
int mc7p_decode_code(const uint8_t *code, size_t len,
		     const uint8_t *constants, size_t clen,
		     mc7p_list_t *out, size_t *err_pos);

void mc7p_free_list(mc7p_list_t *list);

/* Assembler text of one statement ("MOVE :Word @SL.Slot16.0 0").
 * Writes at most bufsize-1 bytes, always NUL terminated; returns the
 * untruncated length (like snprintf). */
int mc7p_render_statement(const mc7p_stmt_t *st, char *buf, size_t bufsize);

const char *mc7p_op_name(int operation);

/* Decode a single statement at code[0] and render its assembler text.
 * Returns the encoded byte length, or -1 when nothing matches.
 * is_return (optional) is set to 1 for RET-family statements. */
int mc7p_disassemble_one(const uint8_t *code, size_t len, char *buf,
			 size_t bufsize, int *is_return);

#ifdef __cplusplus
}
#endif
#endif /* LIB_MC7PLUS_H */
