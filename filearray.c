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
#include <stdint.h>

typedef struct _filearray {
	struct _filearray *next;
	char *name;
	size_t length;
	size_t index;
	char *lines[];
} Filearray;

#if defined(__APPLE_CC__)
#include <stdint.h>
#include <limits.h>
typedef struct _ENTRY {
	unsigned int used;
	ENTRY entry;
} _ENTRY;

struct hsearch_data {
	struct _ENTRY *table;
	unsigned int size;
	unsigned int filled;
};

/* For the used double hash method the table size has to be a prime. To
   correct the user given table size we need a prime test.  This trivial
   algorithm is adequate because
   a)  the code is (most probably) called a few times per program run and
   b)  the number is small because the table must fit in the core  */
static int
isprime (unsigned int number)
{
	/* no even number will be passed */
	for (unsigned int div = 3; div <= number / div; div += 2)
		if (number % div == 0)
			return 0;
	return 1;
}

/* Before using the hash table we must allocate memory for it.
   Test for an existing table are done. We allocate one element
   more as the found prime number says. This is done for more effective
   indexing as explained in the comment for the hsearch function.
   The contents of the table is zeroed, especially the field used
   becomes zero.  */
int
hcreate_r (size_t nel, struct hsearch_data *htab)
{
	/* Test for correct arguments.  */
	if (htab == NULL)
	{
		errno = EINVAL;
		return 0;
	}

	/* There is still another table active. Return with error. */
	if (htab->table != NULL)
		return 0;

	/* We need a size of at least 3.  Otherwise the hash functions we
	   use will not work.  */
	if (nel < 3)
		nel = 3;

	/* Change nel to the first prime number in the range [nel, UINT_MAX - 2],
	   The '- 2' means 'nel += 2' cannot overflow.  */
	for (nel |= 1; ; nel += 2)
	{
		if (UINT_MAX - 2 < nel)
		{
			errno = ENOMEM;
			return 0;
		}
		if (isprime (nel))
			break;
	}

	htab->size = nel;
	htab->filled = 0;

	/* allocate memory and zero out */
	htab->table = (_ENTRY *) calloc (htab->size + 1, sizeof (_ENTRY));
	if (htab->table == NULL)
		return 0;

	/* everything went alright */
	return 1;
}

/* After using the hash table it has to be destroyed. The used memory can
   be freed and the local static variable can be marked as not used.  */
void
hdestroy_r (struct hsearch_data *htab)
{
	/* Test for correct arguments.  */
	if (htab == NULL)
	{
		errno = EINVAL;
		return;
	}

	/* Free used memory.  */
	free (htab->table);

	/* the sign for an existing table is an value != NULL in htable */
	htab->table = NULL;

	return;
}

/* This is the search function. It uses double hashing with open addressing.
   The argument item.key has to be a pointer to an zero terminated, most
   probably strings of chars. The function for generating a number of the
   strings is simple but fast. It can be replaced by a more complex function
   like ajw (see [Aho,Sethi,Ullman]) if the needs are shown.
   We use an trick to speed up the lookup. The table is created by hcreate
   with one more element available. This enables us to use the index zero
   special. This index will never be used because we store the first hash
   index in the field used where zero means not used. Every other value
   means used. The used field can be used as a first fast comparison for
   equality of the stored and the parameter value. This helps to prevent
   unnecessary expensive calls of strcmp.  */
int
hsearch_r (ENTRY item, ACTION action, ENTRY **retval,
           struct hsearch_data *htab)
{
	unsigned int hval;
	unsigned int count;
	unsigned int len = strlen (item.key);
	unsigned int idx;

	/* Compute an value for the given string. Perhaps use a better method. */
	hval = len;
	count = len;
	while (count-- > 0)
	{
		hval <<= 4;
		hval += item.key[count];
	}
	if (hval == 0)
		++hval;

	/* First hash function: simply take the modul but prevent zero. */
	idx = hval % htab->size + 1;

	if (htab->table[idx].used)
	{
		/* Further action might be required according to the action value. */
		if (htab->table[idx].used == hval
		        && strcmp (item.key, htab->table[idx].entry.key) == 0)
		{
			if (retval == NULL)
			{
				/* Set errno to EINVAL, because 'retval' is a NULL pointer
				   (invalid pointer for returning a hash table ENTRY). */
				errno = EINVAL;
				return 0;
			}
			else
			{
				*retval = &htab->table[idx].entry;
				return 1;
			}
		}

		/* Second hash function, as suggested in [Knuth] */
		unsigned int hval2 = 1 + hval % (htab->size - 2);
		unsigned int first_idx = idx;

		do
		{
			/* Because SIZE is prime this guarantees to step through all
			   available indeces.  */
			if (idx <= hval2)
				idx = htab->size + idx - hval2;
			else
				idx -= hval2;

			/* If we visited all entries leave the loop unsuccessfully.  */
			if (idx == first_idx)
				break;

			/* If entry is found use it. */
			if (htab->table[idx].used == hval
			        && strcmp (item.key, htab->table[idx].entry.key) == 0)
			{
				if (retval == NULL)
				{
					/* Set errno to EINVAL, because 'retval' is a NULL pointer
					   (invalid pointer for returning a hash table ENTRY). */
					errno = EINVAL;
					return 0;
				}
				else
				{
					*retval = &htab->table[idx].entry;
					return 1;
				}
			}
		}
		while (htab->table[idx].used);
	}

	/* An empty bucket has been found. */
	if (action == ENTER)
	{
		/* If table is full and another entry should be entered return
		   with error.  */
		if (htab->filled == htab->size)
		{
			errno = ENOMEM;
			/* Prevent the dereferencing of a NULL pointer. */
			if (retval != NULL)
			{
				*retval = NULL;
			}
			return 0;
		}

		htab->table[idx].used  = hval;
		htab->table[idx].entry = item;

		++htab->filled;

		/* Ignore 'retval' if 'action' is 'ENTER' and 'retval' is a
		   NULL pointer. */
		if (retval != NULL)
		{
			/* Prevent the dereferencing of a NULL pointer. */
			*retval = &htab->table[idx].entry;
		}
		return 1;
	}

	errno = ESRCH;
	/* Prevent the dereferencing of a NULL pointer. */
	if (retval != NULL)
	{
		*retval = NULL;
	}
	return 0;
}
#endif

static struct hsearch_data fa_tab;
static Filearray *fa_files;
static bool fa_ready;
static void fa_free(Filearray *fa);

int
fa_init(void)
{
	if (fa_ready) fa_close();
	memset((void *)&fa_tab, 0, sizeof(fa_tab));
#define HSIZE	512	/* why not, probably plenty */
	fa_ready=hcreate_r(HSIZE, &fa_tab) != 0;
	return fa_ready;
}

void
fa_close(void)
{
	if (fa_ready) hdestroy_r(&fa_tab);
	while (fa_files) {
		Filearray *next=fa_files->next;
		fa_free(fa_files);
		fa_files=next;
	}
	fa_ready=false;
	memset((void *)&fa_tab, 0, sizeof(fa_tab));
}

static void
fa_free(Filearray *fa)
{
	if (!fa) return;
	for (size_t i=0; i<fa->length; ++i)
		free(fa->lines[i]);
	free(fa->name);
	free(fa);
}

/* File arguments are text values: validate their counted bytes before
 * removing the line ending or caching a C string.
 */
static bool prepare_line(char *line, size_t length) {
	if (memchr(line, '\0', length)) {
		errno=EINVAL;
		return FALSE;
	}
	if (length && line[length-1]=='\n') {
		line[--length]='\0';
		if (length && line[length-1]=='\r') line[--length]='\0';
	}
	return TRUE;
}

Filearray *
fa_create(const char *name)
{
	FILE *fp;
	Filearray *answer;
	size_t linelimit=8, linecap=0;
	char *line=NULL;
	ssize_t length;
	int error;

	if (!(fp = fopen(name, "r"))) return NULL;
	answer = malloc(sizeof(*answer)+linelimit*sizeof(answer->lines[0]));
	if (!answer) goto fail;
	answer->index=answer->length=0;
	answer->name=NULL;
	answer->next=NULL;
	for (;;) {
		errno=0;
		length=getline(&line, &linecap, fp);
		if (length<0 || ferror(fp)) break;
		if (!prepare_line(line, (size_t)length)) goto fail;
		if (answer->length == linelimit) {
			Filearray *grown;
			if (linelimit > (SIZE_MAX-sizeof(*answer))/sizeof(answer->lines[0])/2) {
				errno=ENOMEM;
				goto fail;
			}
			linelimit *= 2;
			grown = realloc(answer, sizeof(*answer)+linelimit*sizeof(answer->lines[0]));
			if (!grown) goto fail;
			answer=grown;
		}
		answer->lines[answer->length]=strdup(line);
		if (!answer->lines[answer->length]) goto fail;
		++answer->length;
	}
	if (ferror(fp) || !feof(fp)) {
		if (!errno) errno=EIO;
		goto fail;
	}
	if (!answer->length) {
		errno=EINVAL;
		goto fail;
	}
	answer->name=strdup(name);
	if (!answer->name) goto fail;
	free(line);
	fclose(fp);
	return answer;

fail:
	error=errno;
	free(line);
	fa_free(answer);
	fclose(fp);
	errno=error;
	return NULL;
}

static bool insert_file(struct hsearch_data *table, Filearray *file) {
	ENTRY item = { .key=file->name, .data=file };
	ENTRY *found=NULL;
	errno=0;
	if (hsearch_r(item, ENTER, &found, table)>0 && found && found->data==file)
		return TRUE;
	if (!errno) errno=EIO;
	return FALSE;
}

/* Find the cache entry or load it on a miss. */
Filearray *
fa_find(const char *name)
{
	if (!fa_ready || !name) {
		errno=EINVAL;
		return NULL;
	}
	/* BSD implementations may report a successful FIND with a NULL result
	 * when the key is absent. FIND does not modify the search key.
	 */
	ENTRY item = { .key=(char *)name };
	ENTRY *found=NULL;
	errno=0;
	int result=hsearch_r(item, FIND, &found, &fa_tab);
	if (result>0 && found) return found->data;
	if (result<=0 && errno && errno!=ESRCH) {
		perror(name);
		return NULL;
	}

	Filearray *fa=fa_create(name);
	if (!fa || !insert_file(&fa_tab, fa)) {
		int error=errno;
		fa_free(fa);
		errno=error;
		perror(name);
		errno=error;
		return NULL;
	}
	fa->next=fa_files;
	fa_files=fa;
	return fa;
}


/* Takes a file argument, looks it up in the hash table, and
 * returns the next line from the associated file.
 */
char *
fileargument(const char *arg)
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
int main(void)
{
	char arg[BUFSIZ];
	char *line;

	if (!fa_init()) return 1;
	while (1) {
		fprintf(stderr, "file? ");
		if (!fgets(arg, sizeof(arg), stdin)) break;
		arg[strcspn(arg, "\n")] = '\0';
		if (!arg[0]) break;
		line = fileargument(arg);
		if (line) {
			fprintf(stderr, "%s: %s\n", arg, line);
		} else {
			fprintf(stderr, "%s: not found\n", arg);
		}
	}
	fa_close();
}
#endif
