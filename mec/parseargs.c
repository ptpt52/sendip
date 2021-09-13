#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "parse.h"

static int
mstrchr(const char *s, int c)
{
	if (!s) return isspace(c);
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

/* Same as above, but with an array limit. If we hit the limit,
 * the rest gets dumped into the final arg.
 */
int
parsenargs(char *string, char *args[], int limit, const char *seps)
{
	int i;

	for (i=0; *string && i < limit; ++i) {
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

#ifdef TEST
static void
printargs(char *args[], int n)
{
	int i;

	for (i=0; i < n; ++i)
		printf("%d %s ", i, args[i]);
	printf("\n");
}

main(int argc, char **argv)
{
	int i, n;
	char buffer[BUFSIZ];
	char *args[BUFSIZ];

	if (argc > 1) {
		if (argc > 2) {
			for (i=2; i < argc; ++i) {
				n = parseargs(argv[i], args, argv[1]);
				printargs(args, n);
			}
		} else {
			n = parseargs(argv[1], args, NULL);
			printargs(args, n);
		}
	} else while (gets(buffer)) {
		n = parseargs(buffer, args, NULL);
		printargs(args, n);
	}
}
#endif


