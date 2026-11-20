/* rip.c - RIP-1 and -2 code for sendip
 * Taken from code by Richard Polton <Richard.Polton@msdw.com>
 * ChangeLog since 2.0 release:
 * 02/12/2001 Only check 1 layer for enclosing UDP header
 * 21/08/2002 Off-by-one fix in -re handling that caused bad things to happen
 * 21/08/2002 htons() and htonl() added where needed
 * ChangeLog since 2.2 release:
 * 24/11/2002 make it compile on archs that care about alignment
 */

#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "sendip_module.h"
#include "rip.h"

/* Character that identifies our options
 */
const char opt_char='r';

sendip_data *initialize(void) {
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	rip_header *rip = malloc(sizeof(rip_header));
	if (!ret || !rip) {
		free(rip);
		free(ret);
		return NULL;
	}
	memset(rip,0,sizeof(rip_header));
	ret->alloc_len = sizeof(rip_header);
	ret->data = (void *)rip;
	ret->modified=0;
	return ret;
}

static bool add_entry(sendip_data *pack) {
	if (pack->alloc_len > INT_MAX-(int)sizeof(rip_options)) return FALSE;
	void *data=realloc(pack->data, (size_t)pack->alloc_len+sizeof(rip_options));
	if (!data) return FALSE;
	pack->data=data;
	memset((char *)data+pack->alloc_len, 0, sizeof(rip_options));
	pack->alloc_len+=sizeof(rip_options);
	return TRUE;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	rip_header *rippack = (rip_header *)pack->data;
	rip_options *ripopt;
	char *fields[6], *remaining;
	switch(opt[1]) {
	case 'v': /* version */
		/*@@rippack->version = (u_int8_t)strtoul(arg, (char **)0, 0);*/
		rippack->version = integerargument(arg, 1);
		pack->modified |= RIP_MOD_VERSION;
		break;
	case 'c': /* command */
		/*@@rippack->command = (u_int8_t)strtoul(arg, (char **)0, 0);*/
		rippack->command = integerargument(arg, 1);
		pack->modified |= RIP_MOD_COMMAND;
		break;
	case 'a': /* authenticate */
		if(RIP_NUM_ENTRIES(pack) != 0) {
			usage_error("Warning: a real RIP-2 packet only has authentication on the first entry.\n");
		}
		pack->modified |= RIP_IS_AUTH;
		pack->data = realloc(pack->data,pack->alloc_len+strlen(arg));
		memcpy((char *)pack->data+pack->alloc_len,arg,strlen(arg));
		pack->alloc_len += strlen(arg);
		break;
	case 'e': /* Split and validate every field before growing the packet. */
		remaining=arg;
		for (size_t i=0; i<sizeof(fields)/sizeof(fields[0]); ++i) {
			fields[i]=strsep(&remaining, ":");
			if (!fields[i]) {
				usage_error("Malformed RIP entry\n");
				return FALSE;
			}
		}
		if (remaining) {
			usage_error("Too many fields in RIP entry\n");
			return FALSE;
		}
		if (!add_entry(pack)) return FALSE;
		rippack=pack->data;
		ripopt=RIP_OPTION(pack);
		rippack->addressFamily=htons(*fields[0] ? strtoul(fields[0], NULL, 0) : 2);
		rippack->routeTagOrAuthenticationType=htons(*fields[1] ? strtoul(fields[1], NULL, 0) : 0);
		pack->modified |= RIP_MOD_ADDRFAM|RIP_MOD_ROUTETAG;
		ripopt->address=inet_addr(*fields[2] ? fields[2] : "0.0.0.0");
		ripopt->subnetMask=inet_addr(*fields[3] ? fields[3] : "255.255.255.0");
		ripopt->nextHop=inet_addr(*fields[4] ? fields[4] : "0.0.0.0");
		ripopt->metric=htonl(*fields[5] ? strtoul(fields[5], NULL, 0) : 16);
		break;
	case 'd': /* default request */
		if(RIP_NUM_ENTRIES(pack) != 0) {
			usage_error("Warning: a real RIP-1 or -2 packet does not have any entries in a default request.\n");
		}
		rippack->command = (u_int8_t)1;
		rippack->addressFamily = (u_int16_t)0;
		rippack->routeTagOrAuthenticationType = (u_int16_t)0;
		if (!add_entry(pack)) return FALSE;
		ripopt=RIP_OPTION(pack);
		ripopt->address=inet_addr("0.0.0.0");
		ripopt->subnetMask=inet_addr("0.0.0.0");
		ripopt->nextHop=inet_addr("0.0.0.0");
		ripopt->metric=htons((u_int16_t)16);
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	if(index<1 || hdrs[index-1] != 'u') {
		usage_error("Warning: RIP should be contained in a UDP packet\n");
	}

	return TRUE;
}

int num_opts() {
	return sizeof(rip_opts)/sizeof(sendip_option);
}
sendip_option *get_opts() {
	return rip_opts;
}
char get_optchar() {
	return opt_char;
}
