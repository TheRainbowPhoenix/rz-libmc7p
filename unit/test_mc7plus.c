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
	if (fails) {
		printf("%d/%d vectors FAILED\n", fails, n);
		return 1;
	}
	printf("%d/%d MC7+ vectors passed\n", n, n);
	return 0;
}
