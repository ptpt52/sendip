/* ah.c - authentication header (for IPv6)
 *
 * This currently is strictly a dummy version; eventually I hope
 * to add provisions to allow plugging in real AH modules.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"
#include "ah.h"

/* Character that identifies our options
 */
const char opt_char='a';

sendip_data *
initialize(void)
{
	sendip_data *ret = malloc(sizeof(sendip_data));
	ah_header *ah = malloc(sizeof(ah_header));

	memset(ah,0,sizeof(ah_header));
	ah->hdrlen = 1;		/* RFC 4302 length with empty auth data */
	ret->alloc_len = sizeof(ah_header);
	ret->data = ah;
	ret->modified=0;
	return ret;
}

bool
do_opt(char *opt, char *arg, sendip_data *pack)
{
	ah_header *ah = (ah_header *)pack->data;
	char *temp;
	int length;

	switch(opt[1]) {
	case 's':	/* SPI (32 bits) */
		ah->spi = htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= AH_MOD_SPI;
		break;
	case 'q':	/* Sequence number (32 bits) */
		ah->seq_no = htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= AH_MOD_SEQUENCE;
		break;
	case 'd':	/* Authentication data (variable length) */
		/* For right now, we will do either random generation
		 * or a user-provided string.
		 */
		length = compact_or_rand(arg, &temp);
#ifdef notdef
		switch (*arg) {
		case 'r':	/* rN - random data, N bytes */
			length = atoi(arg+1);
			temp = randombytes(length);
			break;
		default:	/* read hex/octal/decimal/raw string */
			length = compact_string(arg);
			temp = (u_int8_t *)arg;
			break;
		}
#endif
		pack->data = realloc(ah, sizeof(ah_header)+length);
		pack->alloc_len = sizeof(ah_header)+length;
		ah = (ah_header *)pack->data;
		memcpy(ah->auth_data, temp, length);
		/* as per RFC 4302 */
		ah->hdrlen = 1 + length/4;
		pack->modified |= AH_MOD_AUTHDATA;
		break;
	case 'n':	/* Next header */
		ah->nexthdr = name_to_proto(arg);
		pack->modified |= AH_MOD_NEXTHDR;
		break;
	}
	return TRUE;

}

bool
finalize(char *hdrs, sendip_data *headers[], int index,
			sendip_data *data, sendip_data *pack)
{
	ah_header *ah = (ah_header *)pack->data;

	if (!(pack->modified&AH_MOD_NEXTHDR))
		ah->nexthdr = header_type(hdrs[index+1]);
	return TRUE;
}

int
num_opts(void)
{
	return sizeof(ah_opts)/sizeof(sendip_option); 
}

sendip_option *
get_opts(void)
{
	return ah_opts;
}

char
get_optchar(void)
{
	return opt_char;
}
