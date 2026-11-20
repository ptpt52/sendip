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

void destroy(sendip_data *pack) {
	free(pack->private);
	pack->private=NULL;
}

sendip_data *
initialize(void)
{
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	sctp_header *sctp = malloc(sizeof(sctp_header));
	int *current_offset=calloc(1, sizeof(*current_offset));

	if (!ret || !sctp || !current_offset) {
		free(current_offset);
		free(sctp);
		free(ret);
		return NULL;
	}
	memset(sctp,0,sizeof(sctp_header));
	ret->alloc_len = sizeof(sctp_header);
	ret->data = sctp;
	ret->private=current_offset;
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
	return chunk;
}

sctp_chunk_header *grow_chunk(sendip_data *pack, sctp_chunk_header *chunk,
                              int length, const void *data) {
	if (length<0 || length>UINT16_MAX || pack->alloc_len>INT_MAX-length) return NULL;
	if (!chunk) {
		chunk=add_chunk(pack, 0);
		if (!chunk) return NULL;
	}
	int offset=(u_int8_t *)chunk-(u_int8_t *)pack->data;
	int used=pack->alloc_len-offset;
	if (used>(int)UINT16_MAX-length || pack->alloc_len>INT_MAX-length) return NULL;
	void *replacement=realloc(pack->data, (size_t)pack->alloc_len+length);
	if (!replacement) return NULL;
	pack->data=replacement;
	chunk=(void *)((u_int8_t *)replacement+offset);
	/* An explicitly malformed wire length never becomes a memory offset. */
	if (data) memcpy((u_int8_t *)chunk+used, data, length);
	else memset((u_int8_t *)chunk+used, 0, length);
	pack->alloc_len+=length;
	chunk->length=htons(ntohs(chunk->length)+length);
	return chunk;
}

static int round2(int length) {
	return (length+1)&~1;
}

sctp_chunk_header *grow_chunk_round4(sendip_data *pack, sctp_chunk_header *chunk,
                                     int length, const void *data) {
	if (length<0 || length>UINT16_MAX) return NULL;
	int rounded=round4(length);
	chunk=grow_chunk(pack, chunk, rounded, NULL);
	if (!chunk) return NULL;
	if (data) memcpy((u_int8_t *)pack->data+pack->alloc_len-rounded, data, length);
	return chunk;
}

bool
do_opt(char *opt, char *arg, sendip_data *pack)
{
	sctp_header *sctp = (sctp_header *)pack->data;
	u_int16_t svalue;
	u_int32_t lvalue;
	char *temp;
	int length;
	int *current_offset=pack->private;
	sctp_chunk_header *currentchunk=*current_offset ?
	    (void *)((u_int8_t *)pack->data+*current_offset) : NULL;

	switch(opt[1]) {
	/* Overall header arguments are lowercase; chunk args are upper */
	case 's':	/* SCTP source port (16 bits) */
		pack->modified |= SCTP_MOD_SOURCE;
		sctp->source = integerargument(arg, 2);
		break;
	case 'd':	/* SCTP destination port (16 bits) */
		pack->modified |= SCTP_MOD_DEST;
		sctp->dest = integerargument(arg, 2);
		break;
	case 'v':	/* SCTP vtag (32 bits) */
		pack->modified |= SCTP_MOD_VTAG;
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
		break;
	case 'c':	/* SCTP checksum (32 bits) */
		pack->modified |= SCTP_MOD_CHECKSUM;
		sctp->checksum = integerargument(arg, 4);
		break;

	case 'T':	/* SCTP chunk type (8 bits) */
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > OCTET_MAX) {
			usage_error("Too big a type value\n");
			return FALSE;
		}
		currentchunk = add_chunk(pack, svalue);
		if (!currentchunk) return FALSE;
		if (!(pack->modified&SCTP_MOD_VTAG)) {
			/* Be careful - add_chunk may have moved things */
			sctp = (sctp_header *)pack->data;
			if (svalue == SCTP_CID_INIT) {
				/* This is just for documentation purposes,
				 * since it's already 0.
				 */
				sctp->vtag = 0;
			} else {
				sctp->vtag = htonl(1);
			}
		}
		break;
	case 'F':	/* SCTP chunk flags (8 bits) */
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > OCTET_MAX) {
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
		svalue = strtoul(arg, (char **)NULL, 0);
		if (!currentchunk ) {
			currentchunk = add_chunk(pack, 0);
		if (!currentchunk) return FALSE;
		}
		/* Be careful! Adding a fake chunk length does not change
		 * the size of the packet or placement of later data.
		 * Specify it after other fields to override their computed length.
		 */
		currentchunk->length = htons(svalue);
		break;
	case 'D':	/* arbitrary SCTP chunk data */
		length = stringargument(arg, &temp);
		if (!temp) return FALSE;
		if (!currentchunk ) {
			currentchunk = add_chunk(pack, 0);
		if (!currentchunk) return FALSE;
		}
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

		currentchunk = add_chunk(pack, SCTP_CID_INIT);
		if (!currentchunk) return FALSE;
		/* set up defaults first, then overwrite with any others */
		init.init_tag = __constant_htonl(1);
		init.a_rwnd = __constant_htonl(0x1000);
		init.num_outbound_streams = __constant_htons(1);
		init.num_inbound_streams = __constant_htons(1);
		init.initial_tsn = __constant_htonl(1);

		nargs = parsenargs(arg, strargs, INITFIELDS, " ,:.");
		if (nargs<0) return FALSE;
		/* Note the cheesy reverse fallthrough */
		switch (nargs) {
		case 5:
			init.initial_tsn =
			    integerargument(strargs[4],
			                    sizeof(init.initial_tsn));
		case 4:
			init.num_inbound_streams =
			    integerargument(strargs[3],
			                    sizeof(init.num_inbound_streams));
		case 3:
			init.num_outbound_streams =
			    integerargument(strargs[2],
			                    sizeof(init.num_outbound_streams));
		case 2:
			init.a_rwnd =
			    integerargument(strargs[1],
			                    sizeof(init.a_rwnd));
		case 1:
			init.init_tag =
			    integerargument(strargs[0],
			                    sizeof(init.init_tag));
		}

		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_inithdr_t), (void *)&init);
		if (!currentchunk) return FALSE;
		break;
	}
	case '4':	/* IPv4 address parameter */
	{
		sctp_ipv4addr_param_t v4param;

		v4param.param_hdr.type = SCTP_PARAM_IPV4_ADDRESS;
		v4param.param_hdr.length = htons(sizeof(sctp_ipv4addr_param_t));
		if (inet_aton(arg, &v4param.addr)) {
			;
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
		lvalue = strtoul(arg, (char **)NULL, 0);
		cookieparam.lifespan_increment = htonl(lvalue);
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_cookie_preserve_param_t),
		                          (void *)&cookieparam);
		if (!currentchunk) return FALSE;
	}
	break;
	case 'H':	/* Host name address */
	{
		sctp_hostname_param_t hostnameparam;
		if (strlen(arg)>UINT16_MAX-sizeof(hostnameparam)-1) return FALSE;

		/* From RFC 4960: "At least one null terminator is included
		 * in the Host Name string and must be included in the length."
		 * Also, parameters need to be padded to a multiple of
		 * 4 bytes in length.
		 */
		hostnameparam.param_hdr.type = SCTP_PARAM_HOST_NAME_ADDRESS;
		hostnameparam.param_hdr.length =
		    htons(sizeof(sctp_hostname_param_t)
		          + strlen(arg)+1);
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_hostname_param_t),
		                          (void *)&hostnameparam);
		if (!currentchunk) return FALSE;
		currentchunk = grow_chunk_round4(pack, currentchunk,
		                                 strlen(arg)+1, (void *)arg);
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
		sctp_supported_addrs_param_t supportedaddrs;
#define MAXSUPPORTEDADDRS	8	/* why not */
		char *straddrs[MAXSUPPORTEDADDRS+1];
		u_int16_t addrs[MAXSUPPORTEDADDRS+1];
		int naddrs, i;

		supportedaddrs.param_hdr.type =
		    SCTP_PARAM_SUPPORTED_ADDRESS_TYPES;
		naddrs = parsenargs(arg, straddrs, MAXSUPPORTEDADDRS, " ,:.");
		if (naddrs<0) return FALSE;
		for (i=0; i < naddrs; ++i)
			addrs[i] = htons(atoi(straddrs[i]));
		addrs[i] = 0;
		supportedaddrs.param_hdr.length =
		    htons(sizeof(sctp_supported_addrs_param_t)
		          + 2*naddrs);
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_supported_addrs_param_t),
		                          (void *)&supportedaddrs);
		if (!currentchunk) return FALSE;
		currentchunk = grow_chunk(pack, currentchunk,
		                          2*round2(naddrs), addrs);
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
		lvalue = strtoul(arg, (char **)NULL, 0);
		adaptationparam.adaptation_ind = htonl(lvalue);
		currentchunk = grow_chunk(pack, currentchunk,
		                          sizeof(sctp_adaptation_ind_param_t),
		                          (void *)&adaptationparam);
		if (!currentchunk) return FALSE;
	}
	break;

	}
	*current_offset=currentchunk ? (u_int8_t *)currentchunk-(u_int8_t *)pack->data : 0;
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
