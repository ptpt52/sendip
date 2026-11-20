#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"

struct sendip_headers sendip_headers[] = {
	{'H', IPPROTO_HOPOPTS},		/* h already taken */
	{'F', IPPROTO_FRAGMENT},	/* f already taken */
	{'g', IPPROTO_GRE},
	{'e', IPPROTO_ESP},		/* TBD */
	{'a', IPPROTO_AH},
	{'c', IPPROTO_ICMPV6},
	{'t', IPPROTO_TCP},
	{'u', IPPROTO_UDP},
	{'i', IPPROTO_IPIP},	/* for 4-in-4 tunnels */
	{'6', IPPROTO_IPV6},	/* for 6-in-4 tunnels */
	{'d', IPPROTO_DSTOPTS},
	{'o', IPPROTO_ROUTING},	/* sorry, r and R already taken ...*/
	{'s', IPPROTO_SCTP},
	{'w', IPPROTO_WESP},
	{0, IPPROTO_NONE},
	/* These are placeholders */
	{'n', 0},		/* ntp */
	{'r', 0},		/* rip */
	{'R', 0},		/* ripng */
	/* These are base flags and can't be used for headers:
	 * d f h p v
	 */
};

u_int8_t
header_type(const char hdr_char)
{
	int i;

	for (i=0; sendip_headers[i].opt_char; ++i)
		if (hdr_char == sendip_headers[i].opt_char)
			return sendip_headers[i].ipproto;
	return IPPROTO_NONE;
}

int
outer_header(const char *hdrs, int index, const char *choices)
{
	int i;

	for (i=index-1; i >=0; --i) {
		if (strchr(choices, hdrs[i]))
			return i;
	}
	return -1;
}

int
inner_header(const char *hdrs, int index, const char *choices)
{
	int i;

	for (i=index+1; hdrs[i]; ++i) {
		if (strchr(choices, hdrs[i]))
			return i;
	}
	return -1;
}

/* Destination options are not finalized yet: use their allocated extent,
 * not the pending Hdr Ext Len field, while parsing the option TLVs.
 */
static bool home_address_source(const sendip_data *header, struct in6_addr *source) {
	if (!header || header->alloc_len<2) return FALSE;
	const u_int8_t *options=header->data;
	for (int offset=2; offset<header->alloc_len;) {
		if (!options[offset]) { ++offset; continue; } /* Pad1 */
		if (header->alloc_len-offset<2) return FALSE;
		int length=options[offset+1];
		if (length>header->alloc_len-offset-2) return FALSE;
		if (options[offset]==201) { /* Mobile IPv6 Home Address option */
			if (length!=(int)sizeof(*source)) return FALSE;
			memcpy(source, options+offset+2, sizeof(*source));
		}
		offset+=length+2;
	}
	return TRUE;
}

/* Resolve the final destination before enclosing routing headers finalize.
 * Read wire bytes rather than assuming their alignment inside the packet.
 */
bool ipv6_pseudo_header(const char *hdrs, sendip_data *headers[],
                       int ip_index, int transport_index, int length,
                       u_int8_t protocol, struct ipv6_pseudo_hdr *pseudo) {
	if (ip_index<0 || transport_index<=ip_index || hdrs[ip_index]!='6' ||
	    !headers[ip_index] || headers[ip_index]->alloc_len<40 || length<0)
		return FALSE;
	const u_int8_t *ip=headers[ip_index]->data;
	memset(pseudo, 0, sizeof(*pseudo));
	memcpy(&pseudo->source, ip+8, sizeof(pseudo->source));
	memcpy(&pseudo->destination, ip+24, sizeof(pseudo->destination));
	pseudo->ulp_length=htonl(length);
	pseudo->nexthdr=protocol;

	for (int i=ip_index+1; i<transport_index; ++i) {
		if (hdrs[i]=='d') {
			if (!home_address_source(headers[i], &pseudo->source)) {
				usage_error("Cannot derive checksum source from invalid IPv6 destination options\n");
				return FALSE;
			}
			continue;
		}
		if (hdrs[i]!='o') continue;
		if (!headers[i] || headers[i]->alloc_len<4) goto invalid;
		const u_int8_t *route=headers[i]->data;
		if (!route[3]) continue; /* No remaining route segments. */
		if (route[2]!=IPV6_SRCRT_TYPE_0 && route[2]!=IPV6_SRCRT_TYPE_2) {
			usage_error("Supply a checksum for an unsupported IPv6 routing type\n");
			return FALSE;
		}
		int addresses=route[1]/2;
		if ((route[1]&1) || !addresses || route[3]>addresses ||
		    (route[2]==IPV6_SRCRT_TYPE_2 && addresses!=1) ||
		    headers[i]->alloc_len<8+16*addresses) goto invalid;
		memcpy(&pseudo->destination, route+8+16*(addresses-1),
		       sizeof(pseudo->destination));
	}
	return TRUE;
invalid:
	usage_error("Cannot derive checksum destination from an invalid IPv6 route\n");
	return FALSE;
}

/* RFC 2675: a Jumbo Payload option belongs to the immediate Hop-by-Hop
 * header and cannot be combined with a Fragment header in this IPv6 packet.
 */
bool ipv6_jumbo_length(const char *hdrs, sendip_data *headers[], int ip_index,
                       u_int32_t *length) {
	if (!hdrs || !headers || !length || ip_index<0 || hdrs[ip_index]!='6' ||
	    hdrs[ip_index+1]!='H' || !headers[ip_index+1]) return FALSE;
	for (int i=ip_index+1;
	     hdrs[i]=='H' || hdrs[i]=='d' || hdrs[i]=='o' ||
	     hdrs[i]=='F' || hdrs[i]=='a' || hdrs[i]=='e'; ++i)
		if (hdrs[i]=='F') return FALSE;
	const sendip_data *hop=headers[ip_index+1];
	if (!hop->data || hop->alloc_len<8 || hop->alloc_len>2048 || hop->alloc_len%8)
		return FALSE;
	const u_int8_t *wire=hop->data;
	u_int32_t jumbo=0;
	bool found=FALSE;
	for (int offset=2; offset<hop->alloc_len;) {
		if (!wire[offset]) { ++offset; continue; } /* Pad1 */
		if (hop->alloc_len-offset<2) return FALSE;
		int size=wire[offset+1];
		if (size>hop->alloc_len-offset-2) return FALSE;
		if (wire[offset]==194) { /* Jumbo Payload */
			if (found || size!=4 || offset%4!=2) return FALSE;
			jumbo=((u_int32_t)wire[offset+2]<<24) |
			      ((u_int32_t)wire[offset+3]<<16) |
			      ((u_int32_t)wire[offset+4]<<8) | wire[offset+5];
			if (jumbo<=UINT16_MAX) return FALSE;
			found=TRUE;
		}
		offset+=size+2;
	}
	if (!found) return FALSE;
	*length=jumbo;
	return TRUE;
}
