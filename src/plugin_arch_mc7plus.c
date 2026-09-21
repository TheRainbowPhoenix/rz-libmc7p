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
 */
#include <rz_arch.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_types.h>

#include "mc7plus.h"

#define MC7P_ASM_BUF 256

static int disassemble_mc7plus(const RzAsm *a, RzAsmOp *op, const ut8 *buf,
			       int len) {
	char asm_buf[MC7P_ASM_BUF];
	int read = mc7p_disassemble_one(buf, (size_t)len, asm_buf,
					sizeof(asm_buf), NULL);
	if (read < 0) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 1;
	} else {
		rz_asm_op_set_asm(op, asm_buf);
		op->size = read;
	}
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

static int analysis_op_mc7plus(RzAnalysis *analysis, RzAnalysisOp *op,
			       ut64 addr, const ut8 *data, int len,
			       RzAnalysisOpMask mask) {
	char asm_buf[MC7P_ASM_BUF];
	int is_return = 0;
	int read = mc7p_disassemble_one(data, (size_t)len, asm_buf,
					sizeof(asm_buf), &is_return);
	if (read > 0) {
		op->size = read;
		op->eob = is_return;
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
