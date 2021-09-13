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
		svalue = strtoul(arg, (char **)NULL, 0);
		sctp->source = htons(svalue);
		break;
	case 'd':	/* SCTP destination port (16 bits) */
		pack->modified |= SCTP_MOD_DEST;
		svalue = strtoul(arg, (char **)NULL, 0);
		sctp->dest = htons(svalue);
		break;
	case 'v':	/* SCTP vtag (32 bits) */
		pack->modified |= SCTP_MOD_VTAG;
		lvalue = strtoul(arg, (char **)NULL, 0);
		sctp->dest = htonl(lvalue);
		break;
	case 'c':	/* SCTP checksum (32 bits) */
		pack->modified |= SCTP_MOD_CHECKSUM;
		lvalue = strtoul(arg, (char **)NULL, 0);
		sctp->dest = htonl(lvalue);
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
		int i;

		currentchunk = add_chunk(pack, SCTP_CID_INIT);
		/* set up defaults first, then overwrite with any others */
		init.init_tag = __constant_htonl(1);
		init.a_rwnd = __constant_htonl(0x1000);
		init.num_outbound_streams = __constant_htons(1);
		init.num_inbound_streams = __constant_htons(1);
		init.initial_tsn = __constant_htonl(1);
		for (i=0; arg; ++i) {
			lvalue = strtoul(arg, (char **)NULL, 0);
			switch (i) {
			case 0:
				init.init_tag = htonl(lvalue);
				break;
			case 1:
				init.a_rwnd = htonl(lvalue);
				break;
			case 2:
				init.num_outbound_streams =
					htons((u_int16_t)lvalue);
				break;
			case 3:
				init.num_inbound_streams =
					htons((u_int16_t)lvalue);
				break;
			case 4:
				init.initial_tsn = htonl(lvalue);
				break;
			default:
				break;
			}
			arg = index(arg, '.');
			if (arg) {
				++arg;
			}

		}
		currentchunk = grow_chunk(pack, currentchunk,
			sizeof(sctp_inithdr_t), (void *)&init);
		break;
		}
	case '4':	/* IPv4 address parameter */
		{
		sctp_ipv4addr_param_t v4param;

		v4param.param_hdr.type = SCTP_PARAM_IPV4_ADDRESS;
		v4param.param_hdr.length = sizeof(sctp_ipv4addr_param_t);
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
		v6param.param_hdr.length = sizeof(sctp_ipv6addr_param_t);
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
			sizeof(sctp_cookie_preserve_param_t);
		lvalue = strtoul(arg, (char **)NULL, 0);
		cookieparam.lifespan_increment = htonl(lvalue);
		currentchunk = grow_chunk(pack, currentchunk,
			sizeof(sctp_cookie_preserve_param_t),
				(void *)&cookieparam);
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
