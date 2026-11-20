/* ipv6.c - sendip IPv6 code
 * Taken from code by Antti Tuominen <ajtuomin@tml.hut.fi>
 * ChangeLog since 2.0 release:
 * 09/08/2002 Setting src/dst now works (Pekka Savola <pekkas@netcore.fi>)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "sendip_module.h"
#include "ipv6.h"

/* Character that identifies our options
 */
const char opt_char='6';

sendip_data *initialize(void) {
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	ipv6_header *ipv6 = malloc(sizeof(ipv6_header));
	if (!ret || !ipv6) {
		free(ipv6);
		free(ret);
		return NULL;
	}
	memset(ipv6,0,sizeof(ipv6_header));
	ipv6->ip6_src=in6addr_loopback;
	ret->alloc_len = sizeof(ipv6_header);
	ret->data = (void *)ipv6;
	ret->modified=0;
	return ret;
}

bool set_addr(char *hostname, sendip_data *pack) {
	ipv6_header *ip=pack->data;
	if (!(pack->modified&IPV6_MOD_SRC)) ip->ip6_src=in6addr_loopback;
	if (!(pack->modified&IPV6_MOD_DST)) {
		struct sockaddr_storage address;
		socklen_t length;
		if (!resolve_address(hostname, AF_INET6, &address, &length)) return FALSE;
		ip->ip6_dst=((struct sockaddr_in6 *)&address)->sin6_addr;
	}
	return TRUE;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	u_int32_t parsed;
	ipv6_header *hdr = (ipv6_header *)pack->data;
	struct in6_addr addr;

	switch(opt[1]) {
	case 'f':
		if (!hostintegerargument_checked(arg, 4, &parsed)) return FALSE;
		hdr->ip6_flow &= htonl(~0x000FFFFFU);
		hdr->ip6_flow |= htonl(parsed & 0x000FFFFF);
		pack->modified |= IPV6_MOD_FLOW;
		break;
	case 't':
		if (!hostintegerargument_checked(arg, 4, &parsed)) return FALSE;
		hdr->ip6_flow &= htonl(~0x0FF00000U);
		hdr->ip6_flow |= htonl((parsed << 20) & 0x0FF00000);
		pack->modified |= IPV6_MOD_FLOW;
		break;
	case 'v':
		if (!hostintegerargument_checked(arg, 1, &parsed)) return FALSE;
		hdr->ip6_vfc.version = (u_int8_t)(parsed & 0x0F);
		pack->modified |= IPV6_MOD_VERSION;
		break;
	case 'p':
		if (!hostintegerargument_checked(arg, 1, &parsed)) return FALSE;
		hdr->ip6_vfc.priority = (u_int8_t)(parsed & 0x0F);
		pack->modified |= IPV6_MOD_PRIORITY;
		break;
	case 'l':
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		hdr->ip6_plen = parsed;
		pack->modified |= IPV6_MOD_PLEN;
		break;
	case 'h':
		if (!hostintegerargument_checked(arg, 1, &parsed)) return FALSE;
		hdr->ip6_hlim = parsed;
		pack->modified |= IPV6_MOD_HLIM;
		break;
	case 'n':
		/*@@ allow use of protocol names */
		if (!protocolargument(arg, &hdr->ip6_nxt)) return FALSE;
		/*@@hdr->ip6_nxt = (u_int8_t)strtoul(arg, (char **)NULL, 0);*/
		pack->modified |= IPV6_MOD_NXT;
		break;
	case 's':
		/*@@ TODO: flexible address specification @@*/
		if (inet_pton(AF_INET6, arg, &addr)!=1) {
			fprintf(stderr, "Invalid IPv6 address: %s\n", arg);
			return FALSE;
		}
		memcpy(&hdr->ip6_src, &addr, sizeof(addr));
		pack->modified |= IPV6_MOD_SRC;
		break;
	case 'd':
		/*@@ TODO: flexible address specification @@*/
		if (inet_pton(AF_INET6, arg, &addr)!=1) {
			fprintf(stderr, "Invalid IPv6 address: %s\n", arg);
			return FALSE;
		}
		memcpy(&hdr->ip6_dst, &addr, sizeof(addr));
		pack->modified |= IPV6_MOD_DST;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	ipv6_header *ipv6 = (ipv6_header *)pack->data;

	if(!(pack->modified&IPV6_MOD_VERSION)) {
		ipv6->ip6_vfc.version = 6;
	}
	if(!(pack->modified&IPV6_MOD_PRIORITY)) {
		if (!((pack->modified&IPV6_MOD_FLOW) && (ipv6->ip6_vfc.priority&0xF)))
			ipv6->ip6_vfc.priority = 0;
	}
	if(!(pack->modified&IPV6_MOD_FLOW)) {
		ipv6->ip6_flow &= htonl(~0x000FFFFFU);
	}
	if(!(pack->modified&IPV6_MOD_PLEN)) {
		if (data->alloc_len>UINT16_MAX) {
			u_int32_t jumbo;
			if (!ipv6_jumbo_length(hdrs, headers, index, &jumbo) ||
			    jumbo!=(u_int32_t)data->alloc_len) {
				usage_error("Oversized IPv6 payload needs a matching Jumbo Payload option\n");
				return FALSE;
			}
			ipv6->ip6_plen=0;
		} else {
			ipv6->ip6_plen = htons(data->alloc_len);
		}
	}
	if(!(pack->modified&IPV6_MOD_NXT)) {
		/*@@ipv6->ip6_nxt = (u_int8_t)IPPROTO_NONE;*/
		/* New default: actual type of following header */
		ipv6->ip6_nxt = header_type_at(hdrs, index+1);
	}
	if(!(pack->modified&IPV6_MOD_HLIM)) {
		ipv6->ip6_hlim = 32;
	}

	return TRUE;
}

int num_opts(void) {
	return sizeof(ipv6_opts)/sizeof(sendip_option);
}
sendip_option *get_opts(void) {
	return ipv6_opts;
}
char get_optchar(void) {
	return opt_char;
}
