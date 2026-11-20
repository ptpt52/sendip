/* icmp.c - ICMP support for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog since 2.0 release:
 * 02/12/2001: Moved ipv6_csum into here as this is where it is used.
 * 02/12/2001: Merged icmp6csum with ipv6_csum
 * 02/12/2001: Only check one layer of headers for enclosing ipv[46] header
 * 22/01/2002: Include string.h
 * 22/02/2002: Fix alignment problem in icmp*csum
 * ChangeLog since 2.1 release:
 * 16/04/2002: Move ipv6_pseudo_header into ipv6.h so tcp.c and udp.c can get it
 * ChangeLog since 2.4 release:
 * 21/04/2003: Fix errors detected by valgrind
 */

#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "sendip_module.h"
#include "icmp.h"
#include "ipv4.h"
#include "ipv6.h"

/* Character that identifies our options
 */
const char opt_char='c';

static void icmpcsum(sendip_data *hdr, sendip_data *data) {
	icmp_header *icmp=hdr->data;
	const void *blocks[]={hdr->data, data->data};
	int lengths[]={hdr->alloc_len, data->alloc_len, 0};
	icmp->check=0;
	icmp->check=csumv(blocks, lengths);
}

static void icmp6csum(const struct ipv6_pseudo_hdr *phdr,
                     sendip_data *hdr, sendip_data *data) {
	icmp_header *icmp=hdr->data;
	const void *blocks[]={phdr, hdr->data, data->data};
	int lengths[]={sizeof(*phdr), hdr->alloc_len, data->alloc_len, 0};
	icmp->check=0;
	icmp->check=csumv(blocks, lengths);
}

sendip_data *initialize(void) {
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	icmp_header *icmp = malloc(sizeof(icmp_header));
	if (!ret || !icmp) {
		free(icmp);
		free(ret);
		return NULL;
	}
	memset(icmp,0,sizeof(icmp_header));
	ret->alloc_len = sizeof(icmp_header);
	ret->data = (void *)icmp;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	icmp_header *icp = (icmp_header *)pack->data;
	switch(opt[1]) {
	case 't':
		/*@@icp->type = (u_int8_t)strtoul(arg, (char **)NULL, 0);*/
		icp->type = integerargument(arg, 1);
		pack->modified |= ICMP_MOD_TYPE;
		break;
	case 'd':
		/*@@icp->code = (u_int8_t)strtoul(arg, (char **)NULL, 0);*/
		icp->code = integerargument(arg, 1);
		pack->modified |= ICMP_MOD_CODE;
		break;
	case 'c':
		/*@@icp->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		icp->check = integerargument(arg, 2);
		pack->modified |= ICMP_MOD_CHECK;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	icmp_header *icp = (icmp_header *)pack->data;
	int i;

	/*@@
	 * This code was incorrectly assuming the previous header
	 * had to be the ip/ipv6 header. I'm changing it to search
	 * backward for the first v4 or v6 header and use that.
	 */
	i = outer_header(hdrs, index, "i6");
	if (i < 0) {
		usage_error("Can't find ip header\n");
		return FALSE;
	}
	/*@@ end of addition */

	/* Find enclosing IP header and do the checksum */
	if(hdrs[i]=='i') {
		// ipv4
		if(!(headers[i]->modified&IP_MOD_PROTOCOL)) {
			((ip_header *)(headers[i]->data))->protocol=hdrs[i+1]=='c' ? IPPROTO_ICMP : header_type(hdrs[i+1]);
			headers[i]->modified |= IP_MOD_PROTOCOL;
		}
	} else if(hdrs[i]=='6') {
		// ipv6
		// @@ This is subsumed by my new code which determines the
		// next header type in the ipv6 module.
		//if(!(headers[i]->modified&IPV6_MOD_NXT)) {
		//	((ipv6_header *)(headers[i]->data))->ip6_nxt=IPPROTO_ICMPV6;
		//	headers[i]->modified |= IPV6_MOD_NXT;
		//}
	}

	if(!(pack->modified&ICMP_MOD_TYPE)) {
		if(hdrs[i]=='6') {
			icp->type=ICMP6_ECHO_REQUEST;
		} else {
			icp->type=ICMP_ECHO;
		}
	}

	if(!(pack->modified&ICMP_MOD_CHECK)) {
		if (hdrs[i] == '6') {
			// ipv6
			struct ipv6_pseudo_hdr phdr;
			if (!ipv6_pseudo_header(hdrs, headers, i, index,
			                       pack->alloc_len+data->alloc_len, IPPROTO_ICMPV6, &phdr))
				return FALSE;
			icmp6csum(&phdr, pack, data);
		} else {
			// ipv4 or anything else
			icmpcsum(pack,data);
		}
	}
	return TRUE;
}

int num_opts(void) {
	return sizeof(icmp_opts)/sizeof(sendip_option);
}
sendip_option *get_opts(void) {
	return icmp_opts;
}
char get_optchar(void) {
	return opt_char;
}
