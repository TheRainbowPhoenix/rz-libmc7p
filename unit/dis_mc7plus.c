// SPDX-License-Identifier: LGPL-3.0-only
/*
 * dis_mc7plus -- standalone MC7+ disassembler CLI (no rizin needed).
 *
 * Usage:
 *   dis_mc7plus [--constants FILE] FILE.bin [FILE2.bin ...]
 *
 * Prints one assembler statement per line, matching the zymatik python
 * reference text format (zymatik/mc7plus/asm/text.py).  On a decode error
 * the message goes to stderr and the exit code is 1.
 */
#include "mc7plus.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int disassemble_file(const char *path, const uint8_t *constants,
			    size_t clen) {
	FILE *f = fopen(path, "rb");
	uint8_t *code = NULL;
	long sz;
	mc7p_list_t list;
	size_t err_pos = 0;
	int i, rc;

	if (!f) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		return -1;
	}
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (sz < 0) {
		fclose(f);
		return -1;
	}
	code = (uint8_t *)malloc(sz ? (size_t)sz : 1);
	if (!code || fread(code, 1, (size_t)sz, f) != (size_t)sz) {
		fprintf(stderr, "%s: read error\n", path);
		free(code);
		fclose(f);
		return -1;
	}
	fclose(f);

	rc = mc7p_decode_code(code, (size_t)sz, constants, clen, &list,
			      &err_pos);
	free(code);
	if (rc != 0) {
		fprintf(stderr, "%s: decode error at offset 0x%zx (%zu)\n",
			path, err_pos, err_pos);
		mc7p_free_list(&list);
		return -1;
	}
	for (i = 0; i < list.count; i++) {
		char buf[4096];
		if (mc7p_render_statement(list.stmts[i], buf, sizeof(buf)) >= 0) {
			printf("%s\n", buf);
		}
	}
	mc7p_free_list(&list);
	return 0;
}

int main(int argc, char **argv) {
	const char *constants_path = NULL;
	uint8_t *constants = NULL;
	size_t clen = 0;
	int i, failures = 0, nfiles = 0;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--constants") && i + 1 < argc) {
			constants_path = argv[++i];
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			printf("usage: dis_mc7plus [--constants FILE] "
			       "FILE.bin [...]\n");
			return 0;
		}
	}
	if (constants_path) {
		FILE *f = fopen(constants_path, "rb");
		if (!f) {
			fprintf(stderr, "%s: %s\n", constants_path,
				strerror(errno));
			return 2;
		}
		fseek(f, 0, SEEK_END);
		clen = (size_t)ftell(f);
		fseek(f, 0, SEEK_SET);
		constants = (uint8_t *)malloc(clen ? clen : 1);
		if (clen && fread(constants, 1, clen, f) != clen) {
			fprintf(stderr, "%s: read error\n", constants_path);
			return 2;
		}
		fclose(f);
	}
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--constants")) {
			i++;
			continue;
		}
		nfiles++;
		if (disassemble_file(argv[i], constants, clen) != 0) {
			failures++;
		}
	}
	free(constants);
	return failures ? 1 : 0;
}
