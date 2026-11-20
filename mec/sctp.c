/* sctp.c - stream control transmission protocol
 *
 */

#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"
#include "sctp.h"
#include "parse.h"

/* Character that identifies our options
 */
const char opt_char='s';

typedef struct {
	int current_offset;
	int final_parameter_padding;
} sctp_state;

void destroy(sendip_data *pack) {
	free(pack->private);
	pack->private=NULL;
}

sendip_data *
initialize(void)
{
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	sctp_header *sctp = malloc(sizeof(sctp_header));
	sctp_state *state=calloc(1, sizeof(*state));

	if (!ret || !sctp || !state) {
		free(state);
		free(sctp);
		free(ret);
		return NULL;
	}
	memset(sctp,0,sizeof(sctp_header));
	ret->alloc_len = sizeof(sctp_header);
	ret->data = sctp;
	ret->private=state;
	ret->modified=0;
	return ret;
}

/* Each chunk gets built one at a time, growing the allocated
 * space as needed. A pointer to the current chunk header is
 * returned. Note these routines may change pack->data.
 */

static int round4(int length) {
	return (length+3)&~3;
}

sctp_chunk_header *add_chunk(sendip_data *pack, u_int8_t type) {
	if (pack->alloc_len>INT_MAX-7) return NULL;
	int start=round4(pack->alloc_len);
	int size=start+sizeof(sctp_chunk_header);
	void *replacement=realloc(pack->data, size);
	if (!replacement) return NULL;
	memset((u_int8_t *)replacement+pack->alloc_len, 0, size-pack->alloc_len);
	pack->data=replacement;
	pack->alloc_len=size;
	sctp_chunk_header *chunk=(void *)((u_int8_t *)replacement+start);
	chunk->type=type;
	chunk->length=htons(sizeof(*chunk));
	((sctp_state *)pack->private)->final_parameter_padding=0;
	if (!(pack->modified&SCTP_MOD_VTAG))
		((sctp_header *)replacement)->vtag=type==SCTP_CID_INIT ? 0 : htonl(1);
	return chunk;
}

static sctp_chunk_header *append_chunk(sendip_data *pack, sctp_chunk_header *chunk,
                                       int length, const void *data, bool padded) {
	if (length<0 || length>UINT16_MAX) return NULL;
	int padding=padded ? round4(length)-length : 0;
	sctp_state *state=pack->private;
	if (!chunk) {
		/* Allocate the implicit chunk header and its first payload together.
		 * A failed payload allocation must not leave an empty chunk behind.
		 */
		if (length>UINT16_MAX-(int)sizeof(sctp_chunk_header) ||
		        pack->alloc_len>INT_MAX-7) return NULL;
		int start=round4(pack->alloc_len);
		int total=start+sizeof(sctp_chunk_header);
		if (total>INT_MAX-length-padding) return NULL;
		total+=length+padding;
		void *replacement=realloc(pack->data, total);
		if (!replacement) return NULL;
		memset((u_int8_t *)replacement+pack->alloc_len, 0,
		       total-pack->alloc_len);
		pack->data=replacement;
		pack->alloc_len=total;
		chunk=(void *)((u_int8_t *)replacement+start);
		chunk->type=0;
		chunk->length=htons(sizeof(*chunk)+length);
		if (data) memcpy((u_int8_t *)chunk+sizeof(*chunk), data, length);
		state->final_parameter_padding=padding;
		if (!(pack->modified&SCTP_MOD_VTAG))
			((sctp_header *)replacement)->vtag=htonl(1);
		return chunk;
	}
	if (!length && !padding) return chunk;
	if (pack->alloc_len>INT_MAX-length-padding) return NULL;
	int offset=(u_int8_t *)chunk-(u_int8_t *)pack->data;
	int used=pack->alloc_len-offset;
	if (used>(int)UINT16_MAX-length || pack->alloc_len>INT_MAX-length-padding) return NULL;
	void *replacement=realloc(pack->data, (size_t)pack->alloc_len+length+padding);
	if (!replacement) return NULL;
	pack->data=replacement;
	chunk=(void *)((u_int8_t *)replacement+offset);
	/* Physical positions never depend on the user-supplied wire length. */
	if (data) memcpy((u_int8_t *)chunk+used, data, length);
	else memset((u_int8_t *)chunk+used, 0, length);
	memset((u_int8_t *)chunk+used+length, 0, padding);
	pack->alloc_len+=length+padding;
	/* A previous parameter's padding becomes internal only when more data
	 * follows. Padding of the final parameter is excluded (RFC 9260 3.2).
	 */
	chunk->length=htons(ntohs(chunk->length)+state->final_parameter_padding+length);
	state->final_parameter_padding=padding;
	return chunk;
}

sctp_chunk_header *grow_chunk(sendip_data *pack, sctp_chunk_header *chunk,
                              int length, const void *data) {
	return append_chunk(pack, chunk, length, data, FALSE);
}

sctp_chunk_header *grow_chunk_round4(sendip_data *pack, sctp_chunk_header *chunk,
                                     int length, const void *data) {
	return append_chunk(pack, chunk, length, data, TRUE);
}

bool
do_opt(char *opt, char *arg, sendip_data *pack)
{
	u_int32_t parsed;
	sctp_header *sctp = (sctp_header *)pack->data;
	unsigned long svalue;
	char *temp;
	int length;
	sctp_state *state=pack->private;
	sctp_chunk_header *currentchunk=state->current_offset ?
	    (void *)((u_int8_t *)pack->data+state->current_offset) : NULL;

	switch(opt[1]) {
	/* Overall header arguments are lowercase; chunk args are upper */
	case 's':	/* SCTP source port (16 bits) */
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		sctp->source = parsed;
		pack->modified |= SCTP_MOD_SOURCE;
		break;
	case 'd':	/* SCTP destination port (16 bits) */
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		sctp->dest = parsed;
		pack->modified |= SCTP_MOD_DEST;
		break;
	case 'v':	/* SCTP vtag (32 bits) */
		/* While the value should be 32 bits, let them specify
		 * whatever they want. We only try to fit four bytes,
		 * however.
		 */
		length = stringargument(arg, &temp);
		if (!temp) return FALSE;
		if (length < sizeof(u_int32_t)) {
			sctp->vtag = 0;
			memcpy((void *)&sctp->vtag, temp, length);
		} else {
			memcpy((void *)&sctp->vtag, temp, sizeof(u_int32_t));
		}
		pack->modified |= SCTP_MOD_VTAG;
		break;
	case 'c':	/* SCTP checksum (32 bits) */
		if (!integerargument_checked(arg, 4, &parsed)) return FALSE;
		sctp->checksum = parsed;
		pack->modified |= SCTP_MOD_CHECKSUM;
		break;

	case 'T':	/* SCTP chunk type (8 bits) */
		if (!uintargument(arg, OCTET_MAX, &svalue)) {
			usage_error("Too big a type value\n");
			return FALSE;
		}
		currentchunk = add_chunk(pack, svalue);
		if (!currentchunk) return FALSE;

		break;
	case 'F':	/* SCTP chunk flags (8 bits) */
		if (!uintargument(arg, OCTET_MAX, &svalue)) {
			usage_error("Too big a flags value\n");
			return FALSE;
		}
		if (!currentchunk ) {
			currentchunk = add_chunk(pack, 0);
		if (!currentchunk) return FALSE;
		}
		currentchunk->flags = svalue;
		break;
	case 'L':	/* SCTP chunk length (16 bits) */
		if (!uintargument(arg, UINT16_MAX, &svalue)) return FALSE;
		if (!currentchunk ) {
			currentchunk = add_chunk(pack, 0);
		if (!currentchunk) return FALSE;
		}
		/* Be careful! Adding a fake chunk length does not change
		 * the size of the packet or placement of later data.
		 * Specify it after other fields to override their computed length.
		 */
		currentchunk->length = htons(svalue);
		state->final_parameter_padding=0;
		break;
	case 'D':	/* arbitrary SCTP chunk data */
		length = stringargument(arg, &temp);
		if (!temp) return FALSE;
		currentchunk = grow_chunk(pack, currentchunk, length,
		                          (void *)temp);
		if (!currentchunk) return FALSE;
		break;

	case 'I':	/* SCTP Init chunk (complete) */
	{
		sctp_inithdr_t init;
#define INITFIELDS	5
		char *strargs[INITFIELDS+1];
		int nargs;

		/* set up defaults first, then overwrite with any others */
		init.init_tag = htonl(1);
		init.a_rwnd = htonl(0x1000);
		init.num_outbound_streams = htons(1);
		init.num_inbound_streams = htons(1);
		init.initial_tsn = htonl(1);

		nargs = parsenargs(arg, strargs, INITFIELDS, " ,:.");
		if (nargs<0) return FALSE;
		/* Note the cheesy reverse fallthrough */
		switch (nargs) {
		case 5:
			if (!integerargument_checked(strargs[4], sizeof(init.initial_tsn), &parsed)) return FALSE;
			init.initial_tsn = parsed;
		case 4:
			if (!integerargument_checked(strargs[3], sizeof(init.num_inbound_streams), &parsed)) return FALSE;
			init.num_inbound_streams = parsed;
		case 3:
			if (!integerargument_checked(strargs[2], sizeof(init.num_outbound_streams), &parsed)) return FALSE;
			init.num_outbound_streams = parsed;
		case 2:
			if (!integerargument_checked(strargs[1], sizeof(init.a_rwnd), &parsed)) return FALSE;
			init.a_rwnd = parsed;
		case 1:
			if (!integerargument_checked(strargs[0], sizeof(init.init_tag), &parsed)) return FALSE;
			init.init_tag = parsed;
		}

		currentchunk = grow_chunk(pack, NULL,
		                          sizeof(sctp_inithdr_t), (void *)&init);
		if (!currentchunk) return FALSE;
		currentchunk->type=SCTP_CID_INIT;
		if (!(pack->modified&SCTP_MOD_VTAG))
			((sctp_header *)pack->data)->vtag=0;
		break;
	}
	case '4':	/* IPv4 address parameter */
	{
		sctp_ipv4addr_param_t v4param;
		struct in_addr address;

		v4param.param_hdr.type = SCTP_PARAM_IPV4_ADDRESS;
		v4param.param_hdr.length = htons(sizeof(sctp_ipv4addr_param_t));
		if (inet_aton(arg, &address)) {
			v4param.addr=address;
		} else {
			fprintf(stderr,
			        "Couldn't parse v4 address %s\n", arg);
			return FALSE;
		}
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_ipv4addr_param_t), (void *)&v4param);
		if (!currentchunk) return FALSE;
	}
	break;

	case '6':	/* IPv6 address parameter */
	{
		sctp_ipv6addr_param_t v6param;

		v6param.param_hdr.type = SCTP_PARAM_IPV6_ADDRESS;
		v6param.param_hdr.length = htons(sizeof(sctp_ipv6addr_param_t));
		if (inet_pton(AF_INET6, arg, &v6param.addr) > 0) {
			;
		} else {
			fprintf(stderr,
			        "Couldn't parse v6 address %s\n", arg);
			return FALSE;
		}
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_ipv6addr_param_t), (void *)&v6param);
		if (!currentchunk) return FALSE;
	}
	break;
	case 'C':	/* Cookie preservative */
	{
		sctp_cookie_preserve_param_t cookieparam;

		cookieparam.param_hdr.type = SCTP_PARAM_COOKIE_PRESERVATIVE;
		cookieparam.param_hdr.length =
		    htons(sizeof(sctp_cookie_preserve_param_t));
		if (!integerargument_checked(arg, 4, &parsed)) return FALSE;
		cookieparam.lifespan_increment = parsed;
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_cookie_preserve_param_t),
		                          (void *)&cookieparam);
		if (!currentchunk) return FALSE;
	}
	break;
	case 'H':	/* Host name address */
	{
		size_t hostname_length=strlen(arg);
		if (hostname_length>UINT16_MAX-sizeof(sctp_hostname_param_t)-1) return FALSE;
		++hostname_length;
		int parameter_length=sizeof(sctp_hostname_param_t)+hostname_length;
		u_int8_t *parameter=malloc(parameter_length);
		if (!parameter) return FALSE;
		sctp_hostname_param_t *hostnameparam=(void *)parameter;

		/* From RFC 4960: "At least one null terminator is included
		 * in the Host Name string and must be included in the length."
		 * Also, parameters need to be padded to a multiple of
		 * 4 bytes in length.
		 */
		hostnameparam->param_hdr.type = SCTP_PARAM_HOST_NAME_ADDRESS;
		hostnameparam->param_hdr.length = htons(parameter_length);
		memcpy(parameter+sizeof(*hostnameparam), arg, hostname_length);
		currentchunk = grow_chunk_round4(pack, currentchunk,
		                                 parameter_length, parameter);
		free(parameter);
		if (!currentchunk) return FALSE;
	}
	break;

	case 'A':	/* Supported address types */
	{
		/* The supported address type parameter is, somewhat
		 * clumsily, an array of 16-bit ints, rather than,
		 * say, a bitmask. But considering there are only three
		 * defined types right now, that's not a huge waste,
		 * I suppose.
		 */
#define MAXSUPPORTEDADDRS	8	/* why not */
		char *straddrs[MAXSUPPORTEDADDRS+1];
		struct {
			sctp_paramhdr_t param_hdr;
			u_int16_t types[MAXSUPPORTEDADDRS];
		} supportedaddrs;
		int naddrs, i;

		naddrs = parsenargs(arg, straddrs, MAXSUPPORTEDADDRS, " ,:.");
		if (naddrs<0) return FALSE;
		for (i=0; i < naddrs; ++i) {
			if (!uintargument(straddrs[i], UINT16_MAX, &svalue)) {
				usage_error("Invalid SCTP supported address type\n");
				return FALSE;
			}
			supportedaddrs.types[i] = htons(svalue);
		}
		supportedaddrs.param_hdr.type = SCTP_PARAM_SUPPORTED_ADDRESS_TYPES;
		supportedaddrs.param_hdr.length =
		    htons(sizeof(sctp_supported_addrs_param_t)
		          + 2*naddrs);
		currentchunk = grow_chunk_round4(pack, currentchunk,
		                                 sizeof(sctp_supported_addrs_param_t)+2*naddrs,
		                                 &supportedaddrs);
		if (!currentchunk) return FALSE;
		break;
	}

	case 'E':	/* ECN capable */
	{
		sctp_ecn_capable_param_t ecncapable;

		/* So far as I can tell with this one, just it being
		 * present implies capability, so there are no
		 * additional parameters at all.
		 */
		ecncapable.param_hdr.type = SCTP_PARAM_ECN_CAPABLE;
		ecncapable.param_hdr.length =
		    htons(sizeof(sctp_ecn_capable_param_t));
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_ecn_capable_param_t),
		                          (void *)&ecncapable);
		if (!currentchunk) return FALSE;
		break;
	}

	case 'W':	/* Forward TSN supported */
	{
		sctp_forward_tsn_param_t forward_tsn;

		/* This seems to be like ECN capable - presence
		 * implies capability.
		 */
		forward_tsn.param_hdr.type = SCTP_PARAM_FWD_TSN_SUPPORT;
		forward_tsn.param_hdr.length =
		    htons(sizeof(sctp_forward_tsn_param_t));
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_forward_tsn_param_t),
		                          (void *)&forward_tsn);
		if (!currentchunk) return FALSE;
		break;
	}
	case 'Y':	/* Adaptation layer indication */
	{
		sctp_adaptation_ind_param_t adaptationparam;

		/* I assume this is just some value that can be
		 * passed up to higher (adaptation) layers. Since
		 * I don't know what it is, I'll just allow fixed
		 * specification of it.
		 */
		adaptationparam.param_hdr.type =
		    SCTP_PARAM_ADAPTATION_LAYER_IND;
		adaptationparam.param_hdr.length =
		    htons(sizeof(sctp_adaptation_ind_param_t));
		if (!integerargument_checked(arg, 4, &parsed)) return FALSE;
		adaptationparam.adaptation_ind = parsed;
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_adaptation_ind_param_t),
		                          (void *)&adaptationparam);
		if (!currentchunk) return FALSE;
	}
	break;

	}
	state->current_offset=currentchunk ? (u_int8_t *)currentchunk-(u_int8_t *)pack->data : 0;
	return TRUE;
}

/* Reflected Castagnoli polynomial; SCTP uses CRC-32C, not Ethernet CRC-32. */
static u_int32_t sctp_crc32c(u_int32_t crc, const void *data, int length) {
	const u_int8_t *bytes=data;
	while (length-- > 0) {
		crc ^= *bytes++;
		for (int bit=0; bit<8; ++bit)
			crc=(crc>>1)^((crc&1) ? UINT32_C(0x82f63b78) : 0);
	}
	return crc;
}

bool do_pad(sendip_data *pack) {
	if (pack->alloc_len>INT_MAX-3) return FALSE;
	int length=round4(pack->alloc_len);
	if (length==pack->alloc_len) return TRUE;
	void *replacement=realloc(pack->data, length);
	if (!replacement) return FALSE;
	memset((u_int8_t *)replacement+pack->alloc_len, 0, length-pack->alloc_len);
	pack->data=replacement;
	pack->alloc_len=length;
	return TRUE;
}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack)
{
	sctp_header *sctp = (sctp_header *)pack->data;

	if (!(pack->modified&SCTP_MOD_CHECKSUM)) {
		sctp->checksum = 0;

		u_int32_t crc=sctp_crc32c(UINT32_MAX, sctp, pack->alloc_len);
		crc=~sctp_crc32c(crc, data->data, data->alloc_len);
		/* RFC 3309 maps the reflected result low-order octet first. */
		u_int8_t *wire=(u_int8_t *)&sctp->checksum;
		for (int i=0; i<4; ++i) wire[i]=crc>>(8*i);
	}
	return TRUE;
}

int num_opts(void)
{
	return sizeof(sctp_opts)/sizeof(sendip_option);
}

sendip_option *get_opts(void)
{
	return sctp_opts;
}

char get_optchar(void)
{
	return opt_char;
}

/* Keep bare-r generation in range without weakening explicit validation. */
u_int32_t randomize_arg(const char *option, u_int32_t value) {
	switch (option[1]) {
	case 'T': case 'F': return value & OCTET_MAX;
	case 'L': case 'A': return value & UINT16_MAX;
	default: return value;
	}
}
