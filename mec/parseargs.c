#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "parse.h"

static int
mstrchr(const char *s, int c)
{
	if (!s) return isspace((unsigned char)c);
	return strchr(s, c) != NULL;
}

/* Parse a string into space-separated (or other) arguments. Chews up the
 * string, replacing the blanks with nuls. Returns the number of arguments
 * found. Does NOT check the array for size.
 *
 * Arguments:
 *	string	(in/out, changes) - string to be parsed
 *	args	(out, filled) - where to put result pointers
 *	seps	(in) - separator chars instead of space, NULL if none
 */
int
parseargs(char *string, char *args[], const char *seps)
{
	int i;

	for (i=0; *string; ++i) {
		while (*string && mstrchr(seps, *string))
			*string++ = '\0';
		if (!*string)
			break;
		args[i] = string;
		while (*string && !mstrchr(seps, *string))
			++string;
	}
	return i;
}

/* Bounded tokenizer: terminate every token and reject excess arguments.
 * Return -1 on invalid arguments or if the token count exceeds limit.
 */
int
parsenargs(char *string, char *args[], int limit, const char *seps)
{
	int count=0;
	if (!string || limit<0 || (limit && !args)) return -1;
	for (;;) {
		while (*string && mstrchr(seps, *string)) *string++='\0';
		if (!*string) return count;
		if (count==limit) return -1;
		args[count++]=string;
		while (*string && !mstrchr(seps, *string)) ++string;
		if (*string) *string++='\0';
	}
}

#ifdef TEST
static int
printargs(char *string, const char *seps)
{
	char *args[BUFSIZ];
	int n = parsenargs(string, args, sizeof(args)/sizeof(args[0]), seps);
	if (n < 0) {
		fputs("Too many input tokens\n", stderr);
		return 1;
	}
	for (int i=0; i < n; ++i)
		fprintf(stderr, "%d %s ", i, args[i]);
	fprintf(stderr, "\n");
	return 0;
}

int main(int argc, char **argv)
{
	char buffer[BUFSIZ];
	if (argc == 2)
		return printargs(argv[1], NULL);
	if (argc > 2) {
		for (int i=2; i < argc; ++i)
			if (printargs(argv[i], argv[1])) return 1;
	} else {
		while (fgets(buffer, sizeof(buffer), stdin)) {
			buffer[strcspn(buffer, "\n")] = '\0';
			if (printargs(buffer, NULL)) return 1;
		}
	}
	return 0;
}
#endif


