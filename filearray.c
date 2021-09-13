#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <memory.h>
#include <string.h>
#include <search.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sendip_module.h"
#include <errno.h>

typedef struct _filearray {
	unsigned int length;
	unsigned int index;
	char *lines[0];
} Filearray;


static struct hsearch_data fa_tab;

int
fa_init(void)
{
	memset((void *)&fa_tab, 0, sizeof(fa_tab));
#define HSIZE	512	/* why not, probably plenty */
	return hcreate_r(HSIZE, &fa_tab);
}

void
fa_close(void)
{
	hdestroy_r(&fa_tab);
	memset((void *)&fa_tab, 0, sizeof(fa_tab));
}

Filearray *
fa_create(char *name)
{
	FILE *fp;
	Filearray *answer;
	int linelimit=0;
	struct stat statbuf;
	char line[BUFSIZ];

	if (!(fp = fopen(name, "r")))
		return NULL;
	/* guess a line count based on size */
	if (stat(name, &statbuf) < 0)
		return NULL;
	linelimit = statbuf.st_size/5;
	answer = (Filearray *)malloc(sizeof(struct _filearray)+linelimit*(sizeof(char *)));
	if (!answer) return NULL;
	/* read the lines into memory */
	answer->index=0;
	for (answer->length=0; fgets(line, BUFSIZ, fp); ++answer->length) {
		if (answer->length >= linelimit-1) {
			linelimit *= 2;
			answer = (Filearray *)realloc(answer,
				sizeof(struct _filearray)+linelimit*(sizeof(char *)));
			if (!answer) return NULL;
		}
		line[strlen(line)-1] = '\0';
		answer->lines[answer->length] = strdup(line);
	}
	fclose(fp);
	return answer;
}

/* Find the entry for a given file. If there isn't one,
 * create it.
 */
Filearray *
fa_find(char *name)
{
	ENTRY item, *found;

	item.key = name;
	item.data = NULL;
	if (hsearch_r(item, FIND, &found, &fa_tab) <= 0) {
		if (errno == ESRCH || !found) {
			item.data = (void *)fa_create(name);
			if (!item.data) {
				perror(name);
				return NULL;
			}
			if (hsearch_r(item, ENTER, &found, &fa_tab) <= 0) {
				perror(name);
				return NULL;
			}
		}
	}
	return (Filearray *)found->data;
}


/* Takes a file argument, looks it up in the hash table, and
 * returns the next line from the associated file.
 */
char *
fileargument(char *arg)
{
	Filearray *fa;
	char *answer;

	fa = fa_find(arg);
	if (!fa) return NULL;
	answer = fa->lines[fa->index];
	++fa->index;
	if (fa->index >= fa->length)
		fa->index = 0;
	return answer;
}

#ifdef FA_TEST
main()
{
	char arg[BUFSIZ];
	char *line;

	fa_init();
	while (1) {
		printf("file? ");
		fgets(arg, BUFSIZ, stdin);
		arg[strlen(arg)-1] = '\0';
		if (!arg[0]) break;
		line = filearg(arg);
		if (line) {
			printf("%s: %s\n", arg, line);
		} else {
			printf("%s: not found\n", arg);
		}
	}
	fa_close();
}
#endif
