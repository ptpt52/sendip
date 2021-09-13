/* hop.c - hop-by-hop and destination options headers
 *
 * Note that we compile two different versions of this
 * extension, one for the hop-by-hop option header (0)
 * and one for the destination option header (60).
 * Right now, these are basically the same (in this
 * implementation) except for their option characters.
 *
 * Of course, some options may only be approved/applicable
 * for one of the headers (e.g., the home address option
 * is only for the destination header), but the code
 * here is not going to force that.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"
#include "hop.h"

/* Character that identifies our options
 */

#if defined(HOP_OPT)
const char opt_char='H';	/* 'h' gives help message */
#elif defined(DEST_OPT)
const char opt_char='d';
#else
#error "option character not defined"
#endif

/* Handling of lengths while assembling the option packet header is
 * perhaps unnecessarily complicated, but this was the only way I
 * could see of tracking the real used space while assembling the
 * options and not introducing any additional variables.
 *
 * Here's how it works: While assembling the options, the hop
 * header length field contains length/8 - that is, the total
 * length consumed divided by 8 (remainder discarded). Note this
 * is *not* (necessarily) the proper final value ((length-8)/8) for
 * the transmitted packet, but this will be adjusted below.
 *
 * The low three bits of pack->modified contain the amount of the
 * final 8-byte segment used - that is, length%8. As always,
 * pack->alloc_len says how much (in bytes) has actually been
 * allocated.
 *
 * Then in finalize, we compare pack->alloc_len with the amount
 * actually filled out, and zero out any unfilled bytes (equivalent
 * to some pad1s) if not. We then adjust the header length field
 * if necessary.
 */

/* The minimum legal option header length is 8 bytes (HDR_ALLOC).
 */
sendip_data *
initialize(void)
{
	sendip_data *ret = malloc(sizeof(sendip_data));
	hop_header *hop = malloc(HDR_ALLOC);

	memset(hop,0,HDR_ALLOC);
	hop->hdrlen = 0;
	ret->modified = sizeof(hop_header);	/* for the opt header itself */
	ret->alloc_len = HDR_ALLOC;
	ret->data = hop;
	return ret;
}

bool
addopt(sendip_data *pack, struct ipv6_hopopt *opt)
{
	hop_header *hop = (hop_header *)pack->data;
	u_int8_t *where;
	int alloclen = pack->alloc_len;
	int hoplen;
	int optlen;

	hoplen = hop->hdrlen*HDR_ALLOC + (pack->modified&(HDR_ALLOC-1));
	/* The PAD0 option doesn't have a real header, so we
	 * have to special-case it.
	 */
	if (opt && opt->hopt_type) {
		optlen = opt->hopt_len+2;
	} else {
		optlen = 1;
	}

	/* See if we're past our allocation. If so, we'll have
	 * to add space.
	 */
	if (hoplen + optlen > alloclen) {
		alloclen = (1 + (hoplen+optlen)/HDR_ALLOC)*HDR_ALLOC;
		hop = realloc((void *)hop, alloclen);
		pack->data = hop;
		pack->alloc_len = alloclen;
	}
	where = ((u_int8_t *)hop) + hoplen;

	/* Special case, part 2 */
	if (opt && opt->hopt_type) {
		memcpy((void *)where, (void *)opt, optlen);
	} else {
		*where = 0;
	}

	hoplen += optlen;
	hop->hdrlen = hoplen/HDR_ALLOC;
	pack->modified &= ~(HDR_ALLOC-1);
	pack->modified |= (hoplen%HDR_ALLOC);
	return TRUE;
}

bool do_opt(char *opt, char *arg, sendip_data *pack)
{
	hop_header *hop = (hop_header *)pack->data;
	struct ipv6_hopopt *hopt;
	u_int32_t value;
	u_int16_t svalue;
	struct in6_addr addr;
	u_int8_t type;
	char *temp;
	int length;

	switch(opt[1]) {
	case 'n':	/* next header */
		hop->nexthdr = name_to_proto(arg);
		pack->modified |= HOP_MOD_NEXTHDR;
		break;
	case '0':	/* pad 0 - pad with 1 byte */
		pack->modified |= HOP_MOD_PAD0;
		/* The pad0 option doesn't really use the TLV option
		 * format; it's just a single zero byte. So since
		 * we have to special-case it anyway, let's go all
		 * the way...
		 */
		if (!addopt(pack, NULL))
			return FALSE;
		break;
	case 'p':	/* pad N - pad with N bytes */
		pack->modified |= HOP_MOD_PADN;
		svalue = strtoul(arg, (char **)NULL, 0);

		if (svalue < 2) {
			usage_error("Too small a pad value\n");
			return FALSE;
		}
		if (svalue > OCTET_MAX+2) {
			usage_error("Too big a pad value\n");
			return FALSE;
		}

		hopt = (struct ipv6_hopopt *)
			malloc(svalue);
		hopt->hopt_type = IPV6_TLV_PADN;
		hopt->hopt_len = svalue-2;
		memset(hopt->hopt_data, 0, svalue-2);
		if (!addopt(pack, hopt))
			return FALSE;
		free((void *)hopt);
		break;
	case 'r':	/* router alert */
		pack->modified |= HOP_MOD_RA;
		svalue = integerargument(arg, 2);
		hopt = (struct ipv6_hopopt *)
			malloc(sizeof(struct ipv6_hopopt) + 2);
		hopt->hopt_type = IPV6_TLV_ROUTERALERT;
		hopt->hopt_len = 2;
		memcpy(hopt->hopt_data, &svalue, 2);
		if (!addopt(pack, hopt))
			return FALSE;
		free((void *)hopt);
		break;
	case 'j':	/* jumbo frame length */
		pack->modified |= HOP_MOD_JUMBO;
		value = integerargument(arg, 4);
		hopt = (struct ipv6_hopopt *)
			malloc(sizeof(struct ipv6_hopopt) + 4);
		hopt->hopt_type = IPV6_TLV_JUMBO;
		hopt->hopt_len = 4;
		memcpy(hopt->hopt_data, &value, 4);
		if (!addopt(pack, hopt))
			return FALSE;
		free((void *)hopt);
		break;
	case 'h':	/* (destination option only) home address */
		if (inet_pton(AF_INET6, arg, &addr)) {
			pack->modified |= HOP_MOD_HAO;
			hopt = (struct ipv6_hopopt *)
				malloc(sizeof(struct ipv6_hopopt)
					+ sizeof(struct in6_addr));
			hopt->hopt_type = IPV6_TLV_HAO;
			hopt->hopt_len = sizeof(struct in6_addr);
			memcpy(hopt->hopt_data, &addr, sizeof(struct in6_addr));
			if (!addopt(pack, hopt))
				return FALSE;
			free((void *)hopt);
		} else {
			fprintf(stderr, "Couldn't parse home address %s\n",
				arg);
			return FALSE;
		}
		break;
	case 'a':	/* arbitrary tlv data */
		pack->modified |= HOP_MOD_TLV;
		/* The argument passed in should be t.l.v, that
		 * is, type.length.value. The value can be specified
		 * in the usual way as octal, hex, literal, or "rN"
		 * for N random bytes.
		 */
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > OCTET_MAX) {
			usage_error("Too big a type value\n");
			return FALSE;
		}
		type = svalue;
		arg = index(arg, '.');
		if (arg) {
			++arg;
			svalue = strtoul(arg, (char **)NULL, 0);
		} else {
			svalue = 0;
		}

		if (svalue > OCTET_MAX) {
			usage_error("Too big a length value\n");
			return FALSE;
		}

		arg = index(arg, '.');
		if (arg) {
			++arg;

			length = stringargument(arg, &temp);
		} else {
			temp = NULL;
		}
		hopt = (struct ipv6_hopopt *)
			malloc(sizeof(struct ipv6_hopopt) + svalue);
		hopt->hopt_type = type;
		hopt->hopt_len = svalue;
		memset(hopt->hopt_data, 0, svalue);
		length = (length > svalue) ? svalue : length;
		memcpy((void *)hopt->hopt_data, (void *)temp, length);
		if (!addopt(pack, hopt))
			return FALSE;
		free((void *)hopt);
		break;
	}
	return TRUE;
}

bool finalize(char *hdrs, sendip_data *headers[], int index,
			sendip_data *data, sendip_data *pack)
{
	hop_header *hop = (hop_header *)pack->data;
	int alloclen = pack->alloc_len;
	int hoplen;

	hoplen = hop->hdrlen*HDR_ALLOC + (pack->modified&(HDR_ALLOC-1));

	if (!(pack->modified&HOP_MOD_NEXTHDR))
		hop->nexthdr = header_type(hdrs[index+1]);
	/* Fix the header length field */
	if (hoplen != alloclen) {
		/* This indicates nobody filled out the final bytes.
		 * I suppose we could zero the rest (equivalent to
		 * some pad1s) - why not?
		 */
		int i;
		u_int8_t *where;

		where = (u_int8_t *)hop;
		for (i = hoplen; i < alloclen; ++i)
			where[i] = 0;
		/* Now replace header length with IETF-approved value */
		hop->hdrlen = alloclen/HDR_ALLOC - 1;
	}
	return TRUE;
}

int num_opts(void)
{
	return sizeof(hop_opts)/sizeof(sendip_option); 
}

sendip_option *get_opts(void)
{
	return hop_opts;
}

char get_optchar(void)
{
	return opt_char;
}
