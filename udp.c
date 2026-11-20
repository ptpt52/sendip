/* udp.c - UDP code for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog since 2.0 release:
 * ChangeLog since 2.1 release:
 * 16/04/2002: Only check one layer of enclosing headers for ip
 * 16/04/2002: Add support for UDP over IPV6
 * ChangeLog since 2.4 release:
 * 21/04/2003: Fix errors found by valgrind
 */

#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "sendip_module.h"
#include "udp.h"
#include "ipv4.h"
#include "ipv6.h"

/* Character that identifies our options
 */
const char opt_char='u';

static void udpcsum(sendip_data *ip_hdr, sendip_data *udp_hdr,
                    sendip_data *data) {
	udp_header *udp=udp_hdr->data;
	ip_header *ip=ip_hdr->data;
	u_int8_t pseudo[12]={0};
	u_int16_t length=htons(udp_hdr->alloc_len+data->alloc_len);
	memcpy(pseudo, &ip->saddr, 4);
	memcpy(pseudo+4, &ip->daddr, 4);
	pseudo[9]=IPPROTO_UDP;
	memcpy(pseudo+10, &length, 2);
	const void *blocks[]={pseudo, udp_hdr->data, data->data};
	int lengths[]={sizeof(pseudo), udp_hdr->alloc_len, data->alloc_len, 0};
	udp->check=0;
	udp->check=csumv(blocks, lengths);
	if (!udp->check) udp->check=htons(0xffff);
}

static void udp6csum(const struct ipv6_pseudo_hdr *phdr, sendip_data *udp_hdr,
                     sendip_data *data) {
	udp_header *udp=udp_hdr->data;
	const void *blocks[]={phdr, udp_hdr->data, data->data};
	int lengths[]={sizeof(*phdr), udp_hdr->alloc_len, data->alloc_len, 0};
	udp->check=0;
	udp->check=csumv(blocks, lengths);
	if (!udp->check) udp->check=htons(0xffff);
}

sendip_data *initialize(void) {
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	udp_header *udp = malloc(sizeof(udp_header));
	if (!ret || !udp) {
		free(udp);
		free(ret);
		return NULL;
	}
	memset(udp,0,sizeof(udp_header));
	ret->alloc_len = sizeof(udp_header);
	ret->data = (void *)udp;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	udp_header *udp = (udp_header *)pack->data;
	switch(opt[1]) {
	case 's':
		/*@@udp->source = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		udp->source = integerargument(arg, 2);
		pack->modified |= UDP_MOD_SOURCE;
		break;
	case 'd':
		/*@@udp->dest = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		udp->dest = integerargument(arg, 2);
		pack->modified |= UDP_MOD_DEST;
		break;
	case 'l':
		/*@@udp->len = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		udp->len = integerargument(arg, 2);
		pack->modified |= UDP_MOD_LEN;
		break;
	case 'c':
		/*@@udp->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		udp->check = integerargument(arg, 2);
		pack->modified |= UDP_MOD_CHECK;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	udp_header *udp = (udp_header *)pack->data;
	int i;

	/* Set relevant fields */
	if(!(pack->modified&UDP_MOD_LEN)) {
		udp->len=htons(pack->alloc_len+data->alloc_len);
	}

	/* Find enclosing IP header and do the checksum */
	i = outer_header(hdrs, index, "i6");/*@@*/
	if (i < 0) {
		if (pack->modified&UDP_MOD_CHECK) return TRUE;
		usage_error("UDP checksum not defined when UDP is not embedded in IP\n");
		return FALSE;
	}
	if(hdrs[i]=='i') {
		unsigned int old_daddr = 0;
		if(!(headers[i]->modified&IP_MOD_PROTOCOL)) {
			((ip_header *)(headers[i]->data))->protocol=header_type(hdrs[i+1]);
			headers[i]->modified |= IP_MOD_PROTOCOL;
		}
		//replace ip daddr
		if((headers[i]->modified & IP_MOD_ROUTE_DADDR)) {
			old_daddr=((ip_header *)(headers[i]->data))->daddr;
			((ip_header *)(headers[i]->data))->daddr=headers[i]->route_daddr;
		}
		if(!(pack->modified&UDP_MOD_CHECK)) {
			udpcsum(headers[i],pack,data);
		}
		//restore ip daddr
		if((headers[i]->modified & IP_MOD_ROUTE_DADDR)) {
			((ip_header *)(headers[i]->data))->daddr=old_daddr;
		}
	} else if(hdrs[i]=='6') {
		// @@ This is subsumed by my new code which determines the
		// next header type in the ipv6 module.
		//if(!(headers[i]->modified&IPV6_MOD_NXT)) {
		//	((ipv6_header *)(headers[i]->data))->ip6_nxt=IPPROTO_UDP;
		//	headers[i]->modified |= IPV6_MOD_NXT;
		//}
		if(!(pack->modified&UDP_MOD_CHECK)) {
			struct ipv6_pseudo_hdr phdr;
			if (!ipv6_pseudo_header(hdrs, headers, i, index,
			                       pack->alloc_len+data->alloc_len, IPPROTO_UDP, &phdr))
				return FALSE;
			udp6csum(&phdr, pack, data);
		}

	} else {
		if(!(pack->modified&UDP_MOD_CHECK)) {
			usage_error("UDP checksum not defined when UDP is not embedded in IP\n");
			return FALSE;
		}
	}

	return TRUE;
}

int num_opts(void) {
	return sizeof(udp_opts)/sizeof(sendip_option);
}
sendip_option *get_opts(void) {
	return udp_opts;
}
char get_optchar(void) {
	return opt_char;
}
