/* route.c - (IPv6) routing extension header
 *
 * TBD - create a version that works for IPv4 as well.
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
#include "route.h"
#include "parse.h"

/* Character that identifies our options
 */
const char opt_char='o';	/* r'o'uting - r and R already used */

sendip_data *
initialize(void)
{
	sendip_data *ret = malloc(sizeof(sendip_data));
	/* Note the Linux generic routing header structure doesn't
	 * include the 4-byte reserved field. To get that, let's
	 * just use the type 0 routing header as the allocation unit.
	 */
	route_header *route = malloc(sizeof(struct rt0_hdr));

	memset(route,0,sizeof(struct rt0_hdr));
	ret->alloc_len = sizeof(struct rt0_hdr);
	ret->data = route;
	ret->modified=0;
	return ret;
}

bool
readaddrs(char *arg, sendip_data *pack)
{
	/* We'll use the type 0 routing header to get at the
	 * other fields.
	 */
	struct rt0_hdr *rt;
	int count, i;
	char *addrs[ADDRMAX];

	count = parsenargs(arg, addrs, ADDRMAX, ", ");
	pack->data = realloc(pack->data,
		sizeof(struct rt0_hdr)+count*sizeof(struct in6_addr));
	rt = (struct rt0_hdr *)pack->data;
	pack->alloc_len = sizeof(struct rt0_hdr)+count*sizeof(struct in6_addr);
	for (i=0; i < count; ++i) {
		if (!inet_pton(AF_INET6, addrs[i], &rt->addr[i])) {
			usage_error("Can't parse address\n");
			return FALSE;
		}
	}
	rt->rt_hdr.hdrlen = count*2;
	return TRUE;
}

bool
do_opt(char *opt, char *arg, sendip_data *pack)
{
	route_header *route = (route_header *)pack->data;
	/* We'll use the type 0 routing header to get at the
	 * other fields.
	 */
	struct rt0_hdr *rt = (struct rt0_hdr *)route;
	u_int16_t svalue;

	switch(opt[1]) {
	case 'n':	/* Route next header */
		route->nexthdr = name_to_proto(arg);
		pack->modified |= ROUTE_MOD_NEXTHDR;
		break;
	case 't':	/* Type */
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > OCTET_MAX) {
			usage_error("Too big a type value\n");
			return FALSE;
		}
		route->type = svalue;
		pack->modified |= ROUTE_MOD_TYPE;
		break;
	case 's':	/* Segments left */
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > OCTET_MAX) {
			usage_error("Too big a segments left value\n");
			return FALSE;
		}
		route->segments_left = svalue;
		pack->modified |= ROUTE_MOD_SEGMENTS;
		break;
	case 'r':	/* Reserved field (4 bytes) */
		rt->reserved = integerargument(arg, 4);
		pack->modified |= ROUTE_MOD_RESV;
		break;
	case 'a':	/* address list */
		if (!readaddrs(arg, pack))
			return FALSE;
		pack->modified |= ROUTE_MOD_ADDRLIST;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], int index,
			sendip_data *data, sendip_data *pack)
{
	route_header *route = (route_header *)pack->data;

	if (!(pack->modified&ROUTE_MOD_NEXTHDR))
		route->nexthdr = header_type(hdrs[index+1]);
	return TRUE;
}

int num_opts()
{
	return sizeof(route_opts)/sizeof(sendip_option); 
}

sendip_option *get_opts()
{
	return route_opts;
}

char get_optchar()
{
	return opt_char;
}
