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
	rip->command=1;
	rip->version=2;
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
	u_int32_t parsed;
	rip_header *rippack = (rip_header *)pack->data;
	rip_options *ripopt;
	char *fields[6], *remaining;
	switch(opt[1]) {
	case 'v': /* version */
		/*@@rippack->version = (u_int8_t)strtoul(arg, (char **)0, 0);*/
		if (!integerargument_checked(arg, 1, &parsed)) return FALSE;
		rippack->version = parsed;
		pack->modified |= RIP_MOD_VERSION;
		break;
	case 'c': /* command */
		/*@@rippack->command = (u_int8_t)strtoul(arg, (char **)0, 0);*/
		if (!integerargument_checked(arg, 1, &parsed)) return FALSE;
		rippack->command = parsed;
		pack->modified |= RIP_MOD_COMMAND;
		break;
	case 'a': /* RFC 2453 simple-password authentication occupies one RTE. */
		if (strlen(arg)>16) {
			usage_error("RIP authentication passwords must be at most 16 bytes\n");
			return FALSE;
		}
		if (RIP_NUM_ENTRIES(pack)!=0)
			usage_error("Warning: RIP authentication should be the first entry\n");
		if (!add_entry(pack)) return FALSE;
		ripopt=RIP_OPTION(pack);
		ripopt->addressFamily=htons(0xffff);
		ripopt->routeTagOrAuthenticationType=htons(2);
		memcpy(&ripopt->address, arg, strlen(arg));
		pack->modified |= RIP_IS_AUTH;
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
		u_int32_t family=htons(2), tag=0, metric=htonl(16);
		if ((*fields[0] && !integerargument_checked(fields[0], 2, &family)) ||
		    (*fields[1] && !integerargument_checked(fields[1], 2, &tag)) ||
		    (*fields[5] && !integerargument_checked(fields[5], 4, &metric)))
			return FALSE;
		struct in_addr addresses[3];
		const char *defaults[]={"0.0.0.0", "255.255.255.0", "0.0.0.0"};
		for (size_t i=0; i<3; ++i) {
			if (!inet_aton(*fields[i+2] ? fields[i+2] : defaults[i], &addresses[i])) {
				usage_error("Invalid IPv4 address in RIP entry\n");
				return FALSE;
			}
		}
		if (!add_entry(pack)) return FALSE;
		ripopt=RIP_OPTION(pack);
		ripopt->addressFamily=family;
		ripopt->routeTagOrAuthenticationType=tag;
		pack->modified |= RIP_MOD_ADDRFAM|RIP_MOD_ROUTETAG;
		ripopt->address=addresses[0].s_addr;
		ripopt->subnetMask=addresses[1].s_addr;
		ripopt->nextHop=addresses[2].s_addr;
		ripopt->metric=metric;
		break;
	case 'd': /* default request */
		if(RIP_NUM_ENTRIES(pack) != 0) {
			usage_error("Warning: a real RIP-1 or -2 packet does not have any entries in a default request.\n");
		}
		if (!add_entry(pack)) return FALSE;
		rippack=pack->data;
		rippack->command = (u_int8_t)1;
		ripopt=RIP_OPTION(pack);
		ripopt->address=inet_addr("0.0.0.0");
		ripopt->subnetMask=inet_addr("0.0.0.0");
		ripopt->nextHop=inet_addr("0.0.0.0");
		ripopt->metric=htonl(16);
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

int num_opts(void) {
	return sizeof(rip_opts)/sizeof(sendip_option);
}
sendip_option *get_opts(void) {
	return rip_opts;
}
char get_optchar(void) {
	return opt_char;
}
