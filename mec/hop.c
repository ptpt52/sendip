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
#include <errno.h>
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

sendip_data *initialize(void) {
	sendip_data *pack=calloc(1, sizeof(*pack));
	if (!pack) return NULL;
	pack->data=calloc(1, sizeof(hop_header));
	if (!pack->data) { free(pack); return NULL; }
	pack->alloc_len=sizeof(hop_header);
	return pack;
}

static bool append_bytes(sendip_data *pack, const void *bytes, int length) {
	/* The extension header length field can represent at most 2048 bytes. */
	if (length<0 || length>2048-pack->alloc_len) return FALSE;
	void *replacement=realloc(pack->data, (size_t)pack->alloc_len+length);
	if (!replacement) return FALSE;
	memcpy((u_int8_t *)replacement+pack->alloc_len, bytes, length);
	pack->data=replacement;
	pack->alloc_len+=length;
	return TRUE;
}

bool addopt(sendip_data *pack, struct ipv6_hopopt *opt) {
	const u_int8_t pad=0;
	return opt && opt->hopt_type ? append_bytes(pack, opt, opt->hopt_len+2) :
	                              append_bytes(pack, &pad, 1);
}

/* Pad before the core assembles all headers into the final packet. */
bool do_pad(sendip_data *pack) {
	const u_int8_t zeros[HDR_ALLOC]={0};
	int padding=(HDR_ALLOC-pack->alloc_len%HDR_ALLOC)%HDR_ALLOC;
	return !padding || append_bytes(pack, zeros, padding);
}

static bool parse_value(const char *arg, unsigned long maximum,
                        unsigned long *value, char **end) {
	if (!isdigit((unsigned char)*arg)) return FALSE;
	errno=0;
	*value=strtoul(arg, end, 0);
	return !errno && *end!=arg && *value<=maximum;
}

static bool align_option(sendip_data *pack, int alignment, int offset) {
	int padding=(alignment+offset-pack->alloc_len%alignment)%alignment;
	if (!padding) return TRUE;
	if (padding==1) return addopt(pack, NULL);
	u_int8_t bytes[8]={IPV6_TLV_PADN};
	struct ipv6_hopopt *pad=(void *)bytes;
	pad->hopt_len=padding-2;
	return addopt(pack, pad);
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	hop_header *hop=pack->data;
	u_int8_t storage[2+255]={0};
	struct ipv6_hopopt *hopt=(void *)storage;
	unsigned long value;
	char *end, *temp;
	int length;
	int alignment=1, offset=0;

	switch (opt[1]) {
	case 'n':
		if (!protocolargument(arg, &hop->nexthdr)) return FALSE;
		pack->modified |= HOP_MOD_NEXTHDR;
		return TRUE;
	case '0':
		return addopt(pack, NULL);
	case 'p':
		if (!parse_value(arg, 257, &value, &end) || *end || value<2) return FALSE;
		hopt->hopt_type=IPV6_TLV_PADN;
		hopt->hopt_len=value-2;
		break;
	case 'r': {
		alignment=2;
		u_int16_t alert=integerargument(arg, 2);
		hopt->hopt_type=IPV6_TLV_ROUTERALERT;
		hopt->hopt_len=sizeof(alert);
		memcpy(hopt->hopt_data, &alert, sizeof(alert));
		break;
	}
	case 'j': {
		alignment=4;
		offset=2;
		u_int32_t jumbo=integerargument(arg, 4);
		hopt->hopt_type=IPV6_TLV_JUMBO;
		hopt->hopt_len=sizeof(jumbo);
		memcpy(hopt->hopt_data, &jumbo, sizeof(jumbo));
		break;
	}
	case 'h': {
		alignment=8;
		offset=6;
		struct in6_addr address;
		if (inet_pton(AF_INET6, arg, &address)!=1) return FALSE;
		hopt->hopt_type=IPV6_TLV_HAO;
		hopt->hopt_len=sizeof(address);
		memcpy(hopt->hopt_data, &address, sizeof(address));
		break;
	}
	case 'a':
	case 't':
		if (!parse_value(arg, 255, &value, &end) || *end!='.') return FALSE;
		hopt->hopt_type=value;
		arg=end+1;
		if (!parse_value(arg, 255, &value, &end) || *end!='.') return FALSE;
		hopt->hopt_len=value;
		length=stringargument(end+1, &temp);
		if (!temp) return FALSE;
		/* The declared length controls the TLV; pad or truncate its value. */
		if (length>(int)value) length=value;
		memcpy(hopt->hopt_data, temp, length);
		break;
	default:
		return FALSE;
	}
	return align_option(pack, alignment, offset) && addopt(pack, hopt);
}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	hop_header *hop=pack->data;
	if (!(pack->modified&HOP_MOD_NEXTHDR))
		hop->nexthdr=header_type(hdrs[index+1]);
	hop->hdrlen=pack->alloc_len/HDR_ALLOC-1;
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

/* PadN occupies between two and 257 bytes including its type and length. */
u_int32_t randomize_arg(const char *option, u_int32_t value) {
	return option[1]=='p' ? (value & UINT8_MAX)+2 : value;
}
