// SPDX-License-Identifier: LGPL-3.0-only
/* test_mc7plus -- C decoder vs zymatik reference vectors (no rizin needed).
 *
 * Each case embeds a corpus blob plus the assembler text produced by the
 * zymatik python reference decoder at generation time.  The C port must
 * reproduce it byte for byte.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mc7plus.h"
#include "mc7plus_test_vectors.h"

static int expect_flow(const char *name, const uint8_t *code, size_t code_len,
		       mc7p_flow_kind_t kind, long label_id) {
	mc7p_flow_t flow;
	int n = mc7p_flow_one(code, code_len, 0, &flow);
	if (n <= 0) {
		printf("FAIL %s: flow decode error\n", name);
		return 1;
	}
	if (flow.kind != kind || flow.label_id != label_id) {
		printf("FAIL %s: flow kind=%d label=%ld, expected kind=%d label=%ld\n",
		       name, flow.kind, flow.label_id, kind, label_id);
		return 1;
	}
	printf("PASS %s flow\n", name);
	return 0;
}

static int expect_decode_one_statement(void) {
	uint8_t code[64];
	mc7p_list_t one;
	int n = mc7p_assemble_one("MOVE :Word @SL.Slot16.0 0", code, sizeof(code));
	if (n <= 0) {
		printf("FAIL decode_one: assemble error\n");
		return 1;
	}
	if (mc7p_decode_one_statement(code, (size_t)n, &one) != n) {
		printf("FAIL decode_one: decode length mismatch\n");
		return 1;
	}
	if (one.count != 1 || !one.stmts || !one.stmts[0] ||
	    one.stmts[0]->operand_count != 3) {
		printf("FAIL decode_one: malformed statement\n");
		mc7p_free_list(&one);
		return 1;
	}
	if (one.stmts[0]->operands[0]->kind != MC7P_ACC_TYPE ||
	    one.stmts[0]->operands[1]->kind != MC7P_ACC_SLOT ||
	    one.stmts[0]->operands[1]->scope != MC7P_SCOPE_NATIVELOCAL ||
	    one.stmts[0]->operands[1]->slot_type != MC7P_RANGE_SLOT16 ||
	    one.stmts[0]->operands[1]->slot_number != 0 ||
	    one.stmts[0]->operands[2]->kind != MC7P_ACC_IMMEDIATE) {
		printf("FAIL decode_one: unexpected structured operands\n");
		mc7p_free_list(&one);
		return 1;
	}
	mc7p_free_list(&one);
	printf("PASS decode_one structured operands\n");
	return 0;
}

int main(void) {
	int n = (int)(sizeof(mc7p_test_cases) / sizeof(mc7p_test_cases[0]));
	int i, fails = 0;

	for (i = 0; i < n; i++) {
		const mc7p_test_case_t *tc = &mc7p_test_cases[i];
		mc7p_list_t list;
		size_t err_pos = 0;
		int rc = mc7p_decode_code(tc->code, tc->code_len, NULL, 0,
					  &list, &err_pos);
		if (rc != 0) {
			printf("FAIL %s: decode error at 0x%zx\n", tc->name,
			       err_pos);
			fails++;
			continue;
		}
		{
			int j;
			char *joined = (char *)malloc(1 << 20);
			size_t used = 0;
			int render_fail = 0;
			joined[0] = 0;
			for (j = 0; j < list.count; j++) {
				char buf[4096];
				int l = mc7p_render_statement(list.stmts[j],
							      buf, sizeof(buf));
				size_t bl;
				if (l < 0) {
					printf("FAIL %s: render error\n",
					       tc->name);
					render_fail = 1;
					break;
				}
				bl = strlen(buf);
				if (j) {
					joined[used++] = '\n';
				}
				memcpy(joined + used, buf, bl);
				used += bl;
				joined[used] = 0;
			}
			if (!render_fail) {
				if (strcmp(joined, tc->expected) != 0) {
					printf("FAIL %s: output mismatch\n",
					       tc->name);
					printf("--- expected ---\n%s\n",
					       tc->expected);
					printf("--- got ---\n%s\n", joined);
					fails++;
				} else {
					printf("PASS %s (%d statements)\n",
					       tc->name, list.count);
				}
			} else {
				fails++;
			}
			free(joined);
		}
		mc7p_free_list(&list);
	}
	{
		const uint8_t jmp_plain[] = { 0x6c, 0x20, 0x11 };
		const uint8_t jmp_negated[] = { 0x6e, 0x20, 0x14 };
		const uint8_t jmp_bbool[] = { 0xfb, 0x52, 0x44, 0x01, 0x20, 0x4b };
		fails += expect_flow("JMP", jmp_plain, sizeof(jmp_plain),
				     MC7P_FLOW_JMP, 17);
		fails += expect_flow("JMP{NEGATED}", jmp_negated,
				     sizeof(jmp_negated), MC7P_FLOW_CJMP, 20);
		fails += expect_flow("JMP_BBOOL", jmp_bbool, sizeof(jmp_bbool),
				     MC7P_FLOW_CJMP, 75);
	}
	fails += expect_decode_one_statement();
	if (fails) {
		printf("%d/%d vectors FAILED\n", fails, n);
		return 1;
	}
	printf("%d/%d MC7+ vectors passed\n", n, n);
	return 0;
}
