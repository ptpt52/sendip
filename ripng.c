/* ripng.c - RIPng (version 1) code for sendip
 * Created by hacking rip code
 * ChangeLog since 2.2 release:
 * 15/10/2002 Read the spec
 * 24/11/2002 Made it compile on archs needing alignment
 */

#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "sendip_module.h"
#include "ripng.h"

/* Character that identifies our options
 */
const char opt_char='R';


sendip_data *initialize(void) {
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	ripng_header *rip = malloc(sizeof(ripng_header));
	if (!ret || !rip) {
		free(rip);
		free(ret);
		return NULL;
	}
	memset(rip,0,sizeof(ripng_header));
	rip->command=1;
	rip->version=1;
	ret->alloc_len = sizeof(ripng_header);
	ret->data = (void *)rip;
	ret->modified=0;
	return ret;
}

static bool add_entry(sendip_data *pack) {
	if (pack->alloc_len > INT_MAX-(int)sizeof(ripng_entry)) return FALSE;
	void *data=realloc(pack->data, (size_t)pack->alloc_len+sizeof(ripng_entry));
	if (!data) return FALSE;
	pack->data=data;
	memset((char *)data+pack->alloc_len, 0, sizeof(ripng_entry));
	pack->alloc_len+=sizeof(ripng_entry);
	return TRUE;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	u_int32_t parsed;
	ripng_header *rippack = (ripng_header *)pack->data;
	ripng_entry *ripopt;
	char *fields[4], *remaining;
	switch(opt[1]) {
	case 'v': /* version */
		if (!integerargument_checked(arg, 1, &parsed)) return FALSE;
		rippack->version = parsed;
		pack->modified |= RIPNG_MOD_VERSION;
		break;
	case 'c': /* command */
		if (!integerargument_checked(arg, 1, &parsed)) return FALSE;
		rippack->command = parsed;
		pack->modified |= RIPNG_MOD_COMMAND;
		break;
	case 'r': /* reserved */
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		rippack->res = parsed;
		pack->modified |= RIPNG_MOD_RESERVED;
		break;
	/*
	case 'a': / * authenticate * /
	if(RIPNG_NUM_ENTRIES(pack) != 0) {
		usage_error("Warning: a real RIP-2 packet only has authentication on the first entry.\n");
	}
	pack->modified |= RIP_IS_AUTH;
	pack->data = realloc(pack->data,pack->alloc_len+strlen(arg));
	memcpy((char *)pack->data+pack->alloc_len,arg,strlen(arg));
	pack->alloc_len += strlen(arg);
	break;
	*/
	case 'e': /* Split and validate every field before growing the packet. */
		remaining=arg;
		for (size_t i=0; i<sizeof(fields)/sizeof(fields[0]); ++i) {
			fields[i]=strsep(&remaining, "/");
			if (!fields[i]) {
				usage_error("Malformed RIPNG entry\n");
				return FALSE;
			}
		}
		if (remaining) {
			usage_error("Too many fields in RIPNG entry\n");
			return FALSE;
		}
		u_int32_t tag=0, prefix_length=128, metric=16;
		if ((*fields[1] && !integerargument_checked(fields[1], 2, &tag)) ||
		    (*fields[2] && !integerargument_checked(fields[2], 1, &prefix_length)) ||
		    (*fields[3] && !integerargument_checked(fields[3], 1, &metric)))
			return FALSE;
		struct in6_addr prefix=in6addr_any;
		if (*fields[0]) {
			struct sockaddr_storage address;
			socklen_t length;
			if (!resolve_address(fields[0], AF_INET6, &address, &length)) return FALSE;
			prefix=((struct sockaddr_in6 *)&address)->sin6_addr;
		}
		if (!add_entry(pack)) return FALSE;
		ripopt=RIPNG_ENTRY(pack);
		ripopt->prefix=prefix;
		ripopt->tag=tag;
		ripopt->len=prefix_length;
		ripopt->metric=metric;
		break;
	case 'd': /* default request */
		if(RIPNG_NUM_ENTRIES(pack) != 0) {
			usage_error("Warning: a real RIPng packet does not have any other entries in a default request.\n");
		}
		rippack->command = (u_int8_t)1;
		rippack->version = (u_int8_t)1;
		rippack->res = (u_int16_t)0;
		pack->modified|=RIPNG_MOD_COMMAND|RIPNG_MOD_VERSION|RIPNG_MOD_RESERVED;
		if (!add_entry(pack)) return FALSE;
		ripopt=RIPNG_ENTRY(pack);
		ripopt->prefix=in6addr_any;
		ripopt->tag=(u_int16_t)0;
		ripopt->len=(u_int8_t)0;
		ripopt->metric=16;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	if(index<1 || hdrs[index-1] != 'u') {
		usage_error("Warning: RIPng should be contained in a UDP packet\n");
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
