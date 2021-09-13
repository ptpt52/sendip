/* sctp.c - stream control transmission protocol
 *
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
#include "sctp.h"
#include "crc32.h"
#include "parse.h"

/* Character that identifies our options
 */
const char opt_char='s';

sendip_data *
initialize(void)
{
	sendip_data *ret = malloc(sizeof(sendip_data));
	sctp_header *sctp = malloc(sizeof(sctp_header));

	memset(sctp,0,sizeof(sctp_header));
	ret->alloc_len = sizeof(sctp_header);
	ret->data = sctp;
	ret->modified=0;
	return ret;
}

/* Each chunk gets built one at a time, growing the allocated
 * space as needed. A pointer to the current chunk header is
 * returned. Note these routines may change pack->data.
 */

sctp_chunk_header *
add_chunk(sendip_data *pack, u_int8_t type)
{
	sctp_header *sctp = (sctp_header *)pack->data;
	sctp_chunk_header *chunk;

	pack->data = sctp = (sctp_header *)realloc((void *)sctp,
		pack->alloc_len + sizeof(sctp_chunk_header));
	chunk = (sctp_chunk_header *)((u_int8_t *)sctp + pack->alloc_len);
	pack->alloc_len += sizeof(sctp_chunk_header);
	memset(chunk, 0, sizeof(sctp_chunk_header));
	chunk->type = type;
	chunk->length = ntohs(sizeof(sctp_chunk_header));
fprintf(stderr, "Adding %ld byte SCTP chunk header, total SCTP length %d\n", sizeof(sctp_chunk_header), pack->alloc_len);
	return chunk;
}

/* Add in data space */
sctp_chunk_header *
grow_chunk(sendip_data *pack, sctp_chunk_header *chunk,
		u_int16_t length, void *data)
{
	sctp_header *sctp = (sctp_header *)pack->data;
	/* urp */
	int offset = (u_int8_t *)chunk - (u_int8_t *)sctp;

	pack->data = sctp = (sctp_header *)realloc((void *)sctp,
			pack->alloc_len + length);
	chunk = (sctp_chunk_header *)((u_int8_t *)sctp + offset);
	pack->alloc_len += length;
	offset = ntohs(chunk->length);
	chunk->length = htons(offset+length);
	if (data)
		memcpy((void *)((u_int8_t *)chunk+offset), data, length);
fprintf(stderr, "Adding %d data bytes, total SCTP length %d\n", length, pack->alloc_len);
	return chunk;
}

/* Chunks and parameters in them need to be rounded up to 4 byte boundaries.
 * The chunks headers are already the right size, but some of the parameters
 * are arbitrary lengths. Somewhat inconveniently, RFC 4960 says that the
 * chunk length must include the padding of all but the last parameter
 * in the chunk. (The padding needs to be there, just not included in
 * the length.) The lengths in the individual TLV parameters should not
 * include the padding.
 */
int
round2(int number)
{
	return (number&1) ? (number + 1) : number;
}

int
round4(int number)
{
	return (number&3) ? (number + 4-(number&3)) : number;
}

/* Add in data space, rounded up to 4-byte boundary */
sctp_chunk_header *
grow_chunk_round4(sendip_data *pack, sctp_chunk_header *chunk,
		u_int16_t length, void *data)
{
	sctp_header *sctp = (sctp_header *)pack->data;
	/* urp */
	int offset = (u_int8_t *)chunk - (u_int8_t *)sctp;
	u_int16_t roundup;

	roundup = round4(length);
	if (roundup == length) return grow_chunk(pack, chunk, length, data);

	pack->data = sctp = (sctp_header *)realloc((void *)sctp,
			pack->alloc_len + roundup);
	chunk = (sctp_chunk_header *)((u_int8_t *)sctp + offset);
	pack->alloc_len += roundup;
	offset = ntohs(chunk->length);
	chunk->length = htons(offset+roundup);
	if (data)
		memcpy((void *)((u_int8_t *)chunk+offset), data, length);
fprintf(stderr, "Rounding %d to %d data bytes, total SCTP length %d\n", length, roundup, pack->alloc_len);
	memset((void *)((u_int8_t *)chunk+offset+length), 0, roundup-length);
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
	static sctp_chunk_header *currentchunk;

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
		if (length < sizeof(u_int32_t)) {
			sctp->vtag = 0;
			memcpy((void *)&sctp->vtag, temp, length);
		} else {
			memcpy((void *)&sctp->vtag, temp, sizeof(u_int32_t));
		}
		break;
	case 'c':	/* SCTP checksum (32 bits) */
		pack->modified |= SCTP_MOD_CHECKSUM;
		sctp->dest = integerargument(arg, 4);
		break;

	case 'T':	/* SCTP chunk type (8 bits) */
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > OCTET_MAX) {
			usage_error("Too big a type value\n");
			return FALSE;
		}
		currentchunk = add_chunk(pack, svalue);
		if (!(pack->modified&SCTP_MOD_VTAG)) {
			/* Be careful - add_chunk may have moved things */
			sctp = (sctp_header *)pack->data;
			if (svalue == SCTP_CID_INIT) {
				/* This is just for documentation purposes,
				 * since it's already 0.
				 */
				sctp->vtag = 0;
			} else {
				sctp->vtag = 1;
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
		}
		currentchunk->flags = svalue;
		break;
	case 'L':	/* SCTP chunk length (16 bits) */
		svalue = strtoul(arg, (char **)NULL, 0);
		if (!currentchunk ) {
			currentchunk = add_chunk(pack, 0);
		}
		/* Be careful! Adding a fake chunk length does not change
		 * the size of the packet, but may affect the placement
		 * of later data. If you're going to muck with the length,
		 * do it after all the other fields.
		 */
		currentchunk->length = htons(svalue);
		break;
	case 'D':	/* arbitrary SCTP chunk data */
		length = stringargument(arg, &temp);
		if (!currentchunk ) {
			currentchunk = add_chunk(pack, 0);
		}
		currentchunk = grow_chunk(pack, currentchunk, length,
			(void *)temp);
		break;

	case 'I':	/* SCTP Init chunk (complete) */
		{
		sctp_inithdr_t init;
#define INITFIELDS	5
		char *strargs[INITFIELDS+1];
		int nargs;

		currentchunk = add_chunk(pack, SCTP_CID_INIT);
		/* set up defaults first, then overwrite with any others */
		init.init_tag = __constant_htonl(1);
		init.a_rwnd = __constant_htonl(0x1000);
		init.num_outbound_streams = __constant_htons(1);
		init.num_inbound_streams = __constant_htons(1);
		init.initial_tsn = __constant_htonl(1);

		nargs = parsenargs(arg, strargs, INITFIELDS, " ,:.");
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
		}
		break;
	case 'C':	/* Cookie preservative */
		{
		sctp_cookie_preserve_param_t cookieparam;

		cookieparam.param_hdr.type = SCTP_PARAM_STATE_COOKIE;
		cookieparam.param_hdr.length =
			htons(sizeof(sctp_cookie_preserve_param_t));
		lvalue = strtoul(arg, (char **)NULL, 0);
		cookieparam.lifespan_increment = htonl(lvalue);
		currentchunk = grow_chunk(pack, currentchunk,
			sizeof(sctp_cookie_preserve_param_t),
				(void *)&cookieparam);
		}
		break;
	case 'H':	/* Host name address */
		{
		sctp_hostname_param_t hostnameparam;

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
		currentchunk = grow_chunk_round4(pack, currentchunk,
			strlen(arg)+1, (void *)arg);
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
		for (i=0; i < naddrs; ++i)
			addrs[i] = htons(atoi(straddrs[i]));
		addrs[i] = 0;
		supportedaddrs.param_hdr.length =
			htons(sizeof(sctp_supported_addrs_param_t)
				+ 2*naddrs);
		currentchunk = grow_chunk(pack, currentchunk,
			sizeof(sctp_supported_addrs_param_t),
				(void *)&supportedaddrs);
		currentchunk = grow_chunk(pack, currentchunk,
				2*round2(naddrs), addrs);
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
		}
		break;

	}
	return TRUE;
}

bool finalize(char *hdrs, sendip_data *headers[], int index,
			sendip_data *data, sendip_data *pack)
{
	sctp_header *sctp = (sctp_header *)pack->data;

	if (!(pack->modified&SCTP_MOD_CHECKSUM)) {
		sctp->checksum = 0;

		sctp->checksum = crc32(~((u_int32_t) 0), (void *)sctp,
			pack->alloc_len);
	}
	return TRUE;
}

int num_opts()
{
	return sizeof(sctp_opts)/sizeof(sendip_option); 
}

sendip_option *get_opts()
{
	return sctp_opts;
}

char get_optchar()
{
	return opt_char;
}
