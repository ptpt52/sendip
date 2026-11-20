#include <stdio.h>
#include <inttypes.h>
#include "crc32defs.h"

#define ENTRIES_PER_LINE 4
#define TABLE_SIZE 256

static uint32_t crc32table_le[TABLE_SIZE];
static uint32_t crc32table_be[TABLE_SIZE];

/* Always generate full byte tables. Smaller processing widths select the
 * appropriate entries instead of changing the checked-in table format.
 */
static void crc32init_le(void) {
	unsigned int i, j;
	uint32_t crc=1;
	for (i=128; i; i>>=1) {
		crc=(crc>>1)^((crc&1) ? CRCPOLY_LE : 0);
		for (j=0; j<TABLE_SIZE; j+=2*i)
			crc32table_le[i+j]=crc^crc32table_le[j];
	}
}

static void crc32init_be(void) {
	unsigned int i, j;
	uint32_t crc=UINT32_C(0x80000000);
	for (i=1; i<TABLE_SIZE; i<<=1) {
		crc=(crc<<1)^((crc&UINT32_C(0x80000000)) ? CRCPOLY_BE : 0);
		for (j=0; j<i; ++j)
			crc32table_be[i+j]=crc^crc32table_be[j];
	}
}

static void output_table(const uint32_t table[], const char *name) {
	printf("#if CRC_%s_BITS > 1\n", name[0]=='l' ? "LE" : "BE");
	printf("static const u_int32_t crc32table_%s[] = {", name);
	for (int i=0; i<TABLE_SIZE; ++i) {
		if (i%ENTRIES_PER_LINE==0) printf("\n\t");
		printf("UINT32_C(0x%08" PRIx32 ")", table[i]);
		if (i+1<TABLE_SIZE) printf(",%s", i%ENTRIES_PER_LINE==3 ? "" : " ");
	}
	printf("\n};\n#endif\n");
}

int main(void) {
	printf("/* this file is generated - do not edit */\n\n");
	crc32init_le();
	crc32init_be();
	output_table(crc32table_le, "le");
	printf("\n");
	output_table(crc32table_be, "be");
	return 0;
}
