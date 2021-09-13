/* compact.c - function to convert hex/octal/decimal/raw string to raw
 * ChangeLog since initial release in sendip 2.1.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
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
/*
 * randomfill() expects a 32-bit pseudorandom value, i.e., one between
 * 0 and 2^32-1, inclusive. However, random(), for historical reasons,
 * only returns 31 random bits - the most significant bit is always 0.
 * So to get a full 32-bit value, you can either call random() twice
 * and add the results (which seems wasteful for just one bit) or use
 * a different function. A couple of possibilites for the latter are
 * jrand48() (or one of its related siblings), or the "dirtyrand()"
 * function below. Neither of these perform quite as well on tests
 * of "randomness" as random(), but they both do give a full 32 bits,
 * and both are considerably faster than random(). On my system
 * (64-bit Linux), jrand48() is about 30% faster, and dirtyrand()
 * is about six times as fast.
 *
 * Note: as employed here, neither jrand48() nor dirtyrand() are
 * thread-safe. The static values would have to be per-thread (e.g., passed
 * in as paramaters) for that. Though I understand that jrand48() still
 * has some other static value in its implementation somewhere that
 * presents an issue. In the context of sendip, which isn't intended
 * to be threaded, this isn't a problem, but it may be elsewhere.
 *
 * Of course, for a pseudorandom number generator, all that threading
 * might do is make the values returned actually random rather than just
 * pseudorandom. For reproducibility, this isn't good, but for other
 * purposes, it may be fine.
 */
#define USE_DIRTY	1	/* Use the simpler/faster one */
#ifdef USE_DIRTY

/* This is adapted from an old hash generator. The magic numbers are all
 * relatively prime to each other, which at least guarantees a long
 * period. In practice, it seems to have a decent spread. This was
 * written with 64-bit arithmetic in mind, and would require some
 * adaptation for good performance on a 32-bit system.
 */
u_int32_t
dirtyrand(void)
{
	static u_int64_t dirtybase=1927868237;
	union {
		u_int64_t whole;
		u_int32_t half[2];
	} answer;

	answer.whole = dirtybase * 69069 + 907133923;
	dirtybase = answer.whole;
	return answer.half[0]^answer.half[1];
}
#define	myrandom()	dirtyrand()

#else 	/* !USE_DIRTY */
/* static version of jrand48(), for convenience */
u_int32_t
sjrand48(void)
{
	static unsigned short xsubi[3];

	return (u_int32_t)jrand48(xsubi);
}
#define	myrandom()	sjrand48()

#endif

u_int32_t randomcalls;
static void
randomfill(u_int32_t *buffer, int length)
{
	int i; 

	for (i=0; i < length; ++i) {
		++randomcalls;
		/*buffer[i] = (u_int32_t)random()+(u_int32_t)random();*/
		buffer[i] = (u_int32_t)myrandom();
	}
}

/* @@ Return a pointer to a string of random bytes. Note this is a
 * static area which is periodically overwritten.
 */
u_int8_t *
randombytes(int length)
{
	static union {
		u_int32_t random32[MAXRAND/4];
		u_int8_t random8[MAXRAND];
	} store;
	static int rnext=MAXRAND;
	u_int8_t *answer;

	/* Sanity check */
	if (length > MAXRAND) {
		usage_error("Random data too long to be sane\n");
		return NULL;
	}
	/* This could be done more efficiently ... */
	if (length+rnext >= MAXRAND) {
		randomfill(store.random32, MAXRAND/4);
		rnext = 0;
	}
	answer = &store.random8[rnext];
	rnext += length;

#ifdef notdef
	/* Zero-pad out to 64-bit boundary */
	/*@@ why did I do this ? */ for (; i&07; ++i)
		answer.answer8[i] = 0;
#endif
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
#ifdef notdef
	/* Paranoia */
	(void) memset((void *)answer, 0, MAXRAND);
#endif
	return answer;
}

/* Write out the current time. We always write 16 bytes into a zero-padded
 * buffer, in host byte order. The caller can use however many bytes
 * desired.
 */
u_int8_t *
timestamp(int length)
{
	static u_int8_t answer[MAXRAND];

	/* Sanity check */
	if (length > MAXRAND) {
		usage_error("Time data too long to be sane\n");
		return NULL;
	}
	gettimeofday((struct timeval *)answer, NULL);
#ifdef notdef
	/* Paranoia */
	(void) memset((void *)answer, 0, MAXRAND);
#endif
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
	/* Special case for rN, zN, fN, tN strings */
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
	case 'f':
		return stringargument(fileargument(input+1), output);
	case 't':	/* timestamp */
		if (isdigit(*(input+1))) {
			length = atoi(input+1);
			*output = (char *)timestamp(length);
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
integerargument(const char *input, int length)
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
			/* There's no point in byte-swapping
			 * random bytes!
			 */
			switch (length) {
			case 1:
				return (u_int8_t)*string;
			case 2:
				return *(u_int16_t *)string;
			case 3:
				return (htonl(0xffffff) & *(u_int32_t *)string);
			default:
				return *(u_int32_t *)string;
			}
		}
		break;
	case 'z':
		/* like I said, pointless ... */
		return 0;
	case 'f':
		return integerargument(fileargument(input+1), length);
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


/* same as above, except the result is in host byte order */
u_int32_t
hostintegerargument(const char *input, int length)
{
	int inputlength;
	u_int8_t *string;

	if (!input || !length) return 0;
	/* Special case for rN, zN, fN strings */
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
			case 3:
				return (0xffffff & *(u_int32_t *)string);
			default:
				return *(u_int32_t *)string;
			}
		}
		break;
	case 'z':
		/* like I said, pointless ... */
		return 0;
	case 'f':
		return hostintegerargument(fileargument(input+1), length);
	default:
		break;
	}

	/* Everything else, just use strtoul, then cast */
	switch (length) {
	case 1:
		return (u_int8_t)strtoul(input, (char **)NULL, 0);
	case 2:
		return (u_int16_t)strtoul(input, (char **)NULL, 0);
	default:
		return strtoul(input, (char **)NULL, 0);
	}
}
/* @@ IPv4 dotted decimal arguments can be specified in several ways.
 * First off, you can use the rN random arguments as above:
 * 	10.1.2.r1 - random address within this /24
 * 	10.1.r2 - random address within this /16
 * 	10.r3 - random 10. address
 * 	r4 - completely random IPv4 address.
 *
 * Secondly, and probably more usefully, you can specify addresses with
 * CIDR notation, implicitly requesting a random address within the given
 * subnet. So, for example:
 * 	10.1.2.0/24 - same result as 10.1.2.r1 (except leaves out 0 and 255)
 * 	10.1.2.0/26 - address in the range 10.1.2.1 to 10.1.2.62
 * Note the CIDR specification won't generate either a 0 or all 1s (broadcast)
 * in the host portion of the address, while the rN method above can.
 *
 * Finally, you can use file arguments - most useful when you are using
 * looping, and working through a list of addresses. The addresses can
 * include the random or CIDR-type specifications above.
 *
 * If you're wondering why the different types, the answer is that I
 * only did the first type at first, because it was easiest to implement,
 * but then needed the others, with the noted restrictions, for a
 * particular project.
 * 
 * This returns the address, in network byte order.
 */
in_addr_t
cidrargument(const char *input, char *slashpoint, int length)
{
	static char ipv4space[BUFSIZ]; /* actual max around 40 */
	in_addr_t host;
	in_addr_t hmask, smask;
	struct in_addr cidrarg;
	int slash;

	strncpy(ipv4space, input, slashpoint-input);
	ipv4space[slashpoint-input] = '\0';
	inet_pton(AF_INET, ipv4space, &cidrarg);
	slash = atoi(++slashpoint);
	/* Interpret weird /xx values as fixed addresses */
	if (slash <= 0 || slash >= 32)
		return cidrarg.s_addr;
	/* The host and subnet parts, in host order for now */
	hmask = ((1<<(32-slash))-1);
	smask = ~hmask;
	/* Determine how much randomness we need, and get it. */
	/* Don't allow 0 or ffff.. host parts if we can help it.
	 * We can help it so long as slash < 31.
	 */
	do {
		if (slash < 8) {
			host = integerargument("r4", 4);
		} else if (slash < 16) {
			host = integerargument("r3", 3);
		} else if (slash < 24) {
			host = integerargument("r2", 2);
		} else {
			host = integerargument("r1", 1);
		}
		host &= hmask;
	} while (slash < 31 && (host == 0 || host == hmask));
	/* Now fold the random host into the output */
	return ((cidrarg.s_addr&htonl(smask))|htonl(host));
}

in_addr_t
ipv4argument(const char *input, int length)
{
	static char ipv4space[BUFSIZ]; /* actual max around 40 */
	u_int32_t a, b, c, d;
	char *dotpoint, *slashpoint;

	/* Special case for fN strings */
	switch (*input) {
	case 'f':
		return ipv4argument(fileargument(input+1), length);
	default:
		break;
	}
	/* Special case for CIDR notation */
	if ((slashpoint=strchr(input, '/'))) {
		return cidrargument(input, slashpoint, length);
	}

	/* This covers the rN and fixed methods of address specification */
	if (!(dotpoint=strchr(input, '.')))	/* aaaaaaaa */
		return integerargument(input, 4);	/* in network order */
	a = hostintegerargument(input, 1);
	input = dotpoint; ++input; length -= dotpoint-input;
	if (!(dotpoint=strchr(input, '.'))) {	/* aa.bbbbbb */
		b = hostintegerargument(input, 3);
		sprintf(ipv4space, "%d.%d", a, b);
		return inet_addr(ipv4space);
	}
	b = hostintegerargument(input, 1);
	input = dotpoint; ++input; length -= dotpoint-input;
	if (!(dotpoint=strchr(input, '.'))) {	/* aa.bb.cccc */
		c = hostintegerargument(input, 2);
		sprintf(ipv4space, "%d.%d.%d", a, b, c);
		return inet_addr(ipv4space);
	}
	c = hostintegerargument(input, 1);
	input = dotpoint; ++input; length -= dotpoint-input;
	d = hostintegerargument(input, 1);
	sprintf(ipv4space, "%d.%d.%d.%d", a, b, c, d);
	return inet_addr(ipv4space);
}

