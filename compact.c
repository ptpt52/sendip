/* compact.c - function to convert hex/octal/decimal/raw string to raw
 * ChangeLog since initial release in sendip 2.1.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <netinet/in.h>
#include "sendip_module.h"

int compact_string(char *data_out) {
	char *data_in = data_out;
	int i=0;
	if(*data_in=='0') {
		data_in++;
		if(*data_in=='x' || *data_in=='X') {
			/* Hex */
			char c='\0';
			data_in++;
			while(*data_in) {
				if(*data_in>='0' && *data_in<='9') {
					c+=*data_in-'0';
				} else if(*data_in>='A' && *data_in<='F') {
					c+=*data_in-'A'+10;
				} else if(*data_in>='a' && *data_in<='f') {
					c+=*data_in-'a'+10;
				} else {
					fprintf(stderr,"Character %c invalid in hex data stream\n",
							  *data_in);
					return 0;
				}
				if( i&1) {
					*(data_out++)=c;  // odd nibble - output it
					c='\0';
				} else {
					c<<=4;   // even nibble - shift to top of byte
				}
				data_in++; i++;
			}
			*data_out=c; // make sure last nibble is added
			i++; i>>=1;  // i was a nibble count...
			return i;
		} else {
         /* Octal */
			char c='\0';
			while(*data_in) {
				if(*data_in>='0' && *data_in<='7') {
					c+=*data_in-'0';
				} else {
					fprintf(stderr,"Character %c invalid in octal data stream\n",
							  *data_in);
					return 0;
				}
				if( (i&3) == 3 ) {
					*(data_out++)=c;  // output every 4th char
					c='\0';
				} else {        // otherwise just shift it up
					c<<=2;
				}
				data_in++; i++;
			}
			*data_out=c;     // add partial last byte
			i+=3; i>>=2;
			return i;
		}
	} else {
		/* String */
		return strlen(data_in);
	}
}

/* @@ Since I'm using the "string, rand or zero" business for filling
 * out several header data areas, I decided to extract all of this
 * into routines here.
 *
 * Note the handling of space is slightly screwy - compact_string
 * above overwrites its argument in place, since it knows that
 * no matter what, the string it produces can be no longer than
 * its argument. randombytes and zerobytes, however, use a static
 * areas, since the calling argument there (something like r32) will
 * generally be much shorter than the string produced.
 *
 * In practice, in both cases the string returned will be immediately
 * copied into an allocated area, so the differences in string handling
 * don't matter. But this should be kept in mind if these routines
 * are used elsewhere.
 */
/* @@ Return a pointer to a string of random bytes. Note this is a
 * static area which is overwritten at each call.
 */
u_int8_t *
randombytes(int length)
{
	static u_int8_t answer[MAXRAND];
	int i;

	/* Sanity check */
	if (length > MAXRAND) {
		usage_error("Random data too long to be sane\n");
		return NULL;
	}
	for (i=0; i < length; ++i)
		answer[i] = (u_int8_t)random();
	/* Zero-pad out to 64-bit boundary */
	for (; i&07; ++i)
		answer[i] = 0;
	return answer;
}

/* @@ Return a pointer to a string of zero bytes. Note this is a
 * static area which should really be left alone ...
 */
u_int8_t *
zerobytes(int length)
{
	static u_int8_t answer[MAXRAND];

	/* Sanity check */
	if (length > MAXRAND) {
		usage_error("Zero data too long to be sane\n");
		return NULL;
	}
	/* Paranoia */
	(void) memset((void *)answer, 0, MAXRAND);
	return answer;
}

/* @@ Yes, well, not the world's most brilliant name, but this
 * does the standard string argument handling. The output
 * may either be the transformed input or a static area.
 * The return value is the length of the output.
 */
int
stringargument(char *input, char **output)
{
	int length=0;

	if (!input || !output) return 0;
	/* Special case for rN, zN strings */
	switch (*input) {
	case 'r':
		if (isdigit(*(input+1))) {
			length = atoi(input+1);
			*output = (char *)randombytes(length);
			if (!*output) return 0;
			return length;
		}
		break;
	case 'z':
		if (isdigit(*(input+1))) {
			length = atoi(input+1);
			*output = (char *)zerobytes(length);
			if (!*output) return 0;
			return length;
		}
		break;
	default:
		break;
	}
	length = compact_string(input);
	*output = input;
	return length;
}

/* @@ This is the integer (1, 2 or 4 byte) version of the above. It takes
 * the input, which may be decimal, octal, hex, or the special strings
 * rX (random bytes) or zX (zero bytes - kind of pointless) and converts
 * it to an integer with the specified number of bytes in *network* byte
 * order. The idea is you can just do:
 *
 * 	field = integerargument(input, sizeof(field));
 */
u_int32_t
integerargument(char *input, int length)
{
	int inputlength;
	u_int8_t *string;

	if (!input || !length) return 0;
	/* Special case for rN, zN strings */
	switch (*input) {
	case 'r':
		if (isdigit(*(input+1))) {
			inputlength = atoi(input+1);
			if (inputlength > length)
				inputlength = length;
			string = randombytes(inputlength);
			if (!string) return 0;
			switch (length) {
			case 1:
				return (u_int8_t)*string;
			case 2:
				return *(u_int16_t *)string;
			default:
				return *(u_int32_t *)string;
			}
		}
		break;
	case 'z':
		/* like I said, pointless ... */
		return 0;
	default:
		break;
	}

	/* Everything else, just use strtoul, then cast and swap */
	switch (length) {
	case 1:
		return (u_int8_t)strtoul(input, (char **)NULL, 0);
	case 2:
		return htons((u_int16_t)strtoul(input, (char **)NULL, 0));
	default:
		return htonl(strtoul(input, (char **)NULL, 0));
	}
}
