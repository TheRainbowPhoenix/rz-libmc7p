// SPDX-License-Identifier: LGPL-3.0-only
/* Standalone MC7+ assembler round-trip test.
 *
 * Uses only the core C library:
 *   original bytes -> C disasm/render -> C assembler -> C disasm/render
 *
 * The decoder is treated as the oracle.  A supported assembler form must
 * disassemble back to the same statement text.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mc7plus.h"
#include "mc7plus_test_vectors.h"

static int roundtrip_stmt(const char *case_name, int stmt_no,
			  const char *asm_text, int *unsupported) {
	uint8_t encoded[256];
	char decoded[1024];
	int n = mc7p_assemble_one(asm_text, encoded, sizeof(encoded));
	int d;

	if (n < 0) {
		(*unsupported)++;
		if (*unsupported <= 25) {
			printf("UNSUPPORTED %s #%d: %s\n", case_name, stmt_no,
			       asm_text);
		}
		return 0;
	}
	d = mc7p_disassemble_one(encoded, (size_t)n, decoded, sizeof(decoded),
				 NULL);
	if (d != n) {
		printf("FAIL %s #%d: re-disasm consumed %d of %d for %s\n",
		       case_name, stmt_no, d, n, asm_text);
		return 1;
	}
	if (strcmp(decoded, asm_text) != 0) {
		printf("FAIL %s #%d: round-trip text mismatch\n", case_name,
		       stmt_no);
		printf("  asm : %s\n", asm_text);
		printf("  dis : %s\n", decoded);
		return 1;
	}
	return 0;
}

int main(void) {
	int cases = (int)(sizeof(mc7p_test_cases) / sizeof(mc7p_test_cases[0]));
	int fails = 0, unsupported = 0, supported = 0, total = 0;

	for (int i = 0; i < cases; i++) {
		const mc7p_test_case_t *tc = &mc7p_test_cases[i];
		mc7p_list_t list;
		size_t err_pos = 0;
		if (mc7p_decode_code(tc->code, tc->code_len, NULL, 0,
				     &list, &err_pos) != 0) {
			printf("FAIL %s: decode error at 0x%zx\n", tc->name,
			       err_pos);
			fails++;
			continue;
		}
		for (int j = 0; j < list.count; j++) {
			char asm_text[1024];
			int before = unsupported;
			if (mc7p_render_statement(list.stmts[j], asm_text,
						  sizeof(asm_text)) < 0) {
				printf("FAIL %s #%d: render error\n", tc->name,
				       j + 1);
				fails++;
				continue;
			}
			total++;
			fails += roundtrip_stmt(tc->name, j + 1, asm_text,
						&unsupported);
			if (unsupported == before) {
				supported++;
			}
		}
		mc7p_free_list(&list);
	}

	printf("MC7+ asm round-trip: %d/%d supported, %d unsupported, %d failed\n",
	       supported, total, unsupported, fails);
	if (unsupported > 25) {
		printf("... %d more unsupported statements omitted\n",
		       unsupported - 25);
	}
	return (fails || unsupported) ? 1 : 0;
}
