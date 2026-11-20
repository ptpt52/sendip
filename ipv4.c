/* ipv4.c - IPV4 code for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog from 2.0 release:
 * 26/11/2001 IP options
 * 23/01/2002 Spelling fix (Dax Kelson <dax@gurulabs.com>)
 * 26/08/2002 Put tot_len field in host byte order on FreeBSD
 * ChangeLog since 2.2 release:
 * 24/11/2002 make it compile on archs that care about alignment
 * ChangeLog since 2.3 release:
 * 23/12/2002 fix bug with -iossr and -iolsr
 * 20/01/2003 fix FreeBSD sendto(): invalid argument error.  Again.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include "sendip_module.h"
#include "ipv4.h"

/* Character that identifies our options
 */
const char opt_char='i';

static void ipcsum(sendip_data *ip_hdr) {
	ip_header *ip = (ip_header *)ip_hdr->data;
	ip->check=0;
	ip->check=csum(ip_hdr->data, ip_hdr->alloc_len);
}

/* Output storage is separate: short numeric addresses can expand to four
 * binary bytes and must not overwrite the remaining source text.
 */
static int buildroute(char *input, u_int8_t *output, sendip_data *pack) {
	if (strlen(input)<3 || !isxdigit((unsigned char)input[0]) ||
	    !isxdigit((unsigned char)input[1]) || input[2]!=':') return 0;
	char pointer[3]={input[0], input[1], 0};
	output[0]=strtoul(pointer, NULL, 16);
	int used=1;
	char *remaining=input+3, *address;
	while ((address=strsep(&remaining, ":"))) {
		if (!*address || used>253-4) return 0;
		u_int32_t ip=ipv4argument(address, strlen(address));
		memcpy(output+used, &ip, 4);
		used+=4;
	}
	/* The pointer identifies the next hop to consume, not the final
	 * destination required by the transport checksum pseudo-header.
	 */
	if (pack && !(pack->modified&IP_MOD_ROUTE_DADDR) && output[0]>=4 &&
	    (output[0]-4)%4==0 && output[0]<=used+2) {
		pack->modified |= IP_MOD_ROUTE_DADDR;
		memcpy(&pack->route_daddr, output+used-4, 4);
	}
	return used;
}

/* Timestamp overflow and flag are decimal nibbles, not unchecked ints. */
static bool timestamp_nibble(const char *input, unsigned long *value) {
	char *end;
	if (!isdigit((unsigned char)*input)) return FALSE;
	errno=0;
	*value=strtoul(input, &end, 10);
	return !errno && !*end && *value<=15;
}

static int buildtimestamp(char *input, u_int8_t *output) {
	char *remaining=input;
	char *pointer=strsep(&remaining, ":");
	char *overflow=strsep(&remaining, ":");
	char *flag=strsep(&remaining, ":");
	if (!pointer || strlen(pointer)!=2 || !overflow || !flag || !remaining ||
	    !isxdigit((unsigned char)pointer[0]) || !isxdigit((unsigned char)pointer[1]))
		return 0;
	unsigned long over, flags;
	if (!timestamp_nibble(overflow, &over) || !timestamp_nibble(flag, &flags))
		return 0;
	output[0]=strtoul(pointer, NULL, 16);
	output[1]=(over<<4)|flags;
	int used=2;
	while (remaining) {
		char *field=strsep(&remaining, ":");
		if (flags) {
			if (!remaining || used>253-8) return 0;
			u_int32_t ip=ipv4argument(field, strlen(field));
			memcpy(output+used, &ip, 4);
			used+=4;
			field=strsep(&remaining, ":");
		}
		if (used>253-4) return 0;
		u_int32_t timestamp=integerargument(field, 4);
		memcpy(output+used, &timestamp, 4);
		used+=4;
	}
	return used;
}

/* This bears an incredible resemblance to the TCP addoption function... */
static bool addoption(u_int8_t copy, u_int8_t class, u_int8_t num,
                      int len, u_int8_t *data,
                      sendip_data *pack) {
	/* opt is copy flag (1bit) + class (2 bit) + number (5 bit) */
	u_int8_t opt = ((copy&1)<<7) | ((class&3)<<5) | (num&31);
	if (len<1 || len>255 || pack->alloc_len>INT_MAX-len || (len>2 && !data))
		return FALSE;
	void *replacement=realloc(pack->data, (size_t)pack->alloc_len+len);
	if (!replacement) return FALSE;
	pack->data=replacement;
	*((u_int8_t *)pack->data+pack->alloc_len) = opt;
	if(len > 1)
		*((u_int8_t *)pack->data+pack->alloc_len+1) = len;
	if(len > 2)
		memcpy((u_int8_t *)pack->data+pack->alloc_len+2,data,len-2);
	pack->alloc_len += len;
	return TRUE;
}

sendip_data *initialize(void) {
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	ip_header *ip = malloc(sizeof(ip_header));
	if (!ret || !ip) {
		free(ip);
		free(ret);
		return NULL;
	}
	memset(ip,0,sizeof(ip_header));
	ret->alloc_len = sizeof(ip_header);
	ret->data = (void *)ip;
	ret->modified=0;
	return ret;
}

bool set_addr(char *hostname, sendip_data *pack) {
	ip_header *ip=pack->data;
	if (!(pack->modified&IP_MOD_SADDR)) ip->saddr=htonl(INADDR_LOOPBACK);
	if (!(pack->modified&IP_MOD_DADDR)) {
		struct sockaddr_storage address;
		socklen_t length;
		if (!resolve_address(hostname, AF_INET, &address, &length)) return FALSE;
		ip->daddr=((struct sockaddr_in *)&address)->sin_addr.s_addr;
	}
	return TRUE;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	ip_header *iph = (ip_header *)pack->data;
	bool added=TRUE;
	switch(opt[1]) {
	case 's':
		/*@@iph->saddr = inet_addr(arg);*/
		iph->saddr = ipv4argument(arg, strlen(arg));
		pack->modified |= IP_MOD_SADDR;
		break;
	case 'd':
		/*@@iph->daddr = inet_addr(arg);*/
		iph->daddr = ipv4argument(arg, strlen(arg));
		pack->modified |= IP_MOD_DADDR;
		break;
	case 'h':
		iph->header_len = (unsigned int)strtoul(arg, (char **)NULL, 0) & 0xF;
		pack->modified |= IP_MOD_HEADERLEN;
		break;
	case 'v':
		iph->version = (unsigned int)strtoul(arg, (char **)NULL, 0) & 0xF;
		pack->modified |= IP_MOD_VERSION;
		break;
	case 'y':
		iph->tos = (u_int8_t)strtoul(arg, (char **)NULL, 0);
		pack->modified |= IP_MOD_TOS;
		break;
	case 'l':
		iph->tot_len = integerargument(arg, 2);

		pack->modified |= IP_MOD_TOTLEN;
		break;
	case 'i':
		/*@@iph->id = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		iph->id = integerargument(arg, 2);
		pack->modified |= IP_MOD_ID;
		break;

	case 'f':
		if(opt[2]) {
			/* Note: *arg&1 is what we want because:
				if arg=="0", *arg&1==0
				if arg=="1", *arg&1==1
				otherwise, it doesn't really matter...
			*/
			switch(opt[2]) {
			case 'r':
				iph->res=*arg&1;
				pack->modified |= IP_MOD_RES;
				break;
			case 'd':
				iph->df=*arg&1;
				pack->modified |= IP_MOD_DF;
				break;
			case 'm':
				iph->mf=*arg&1;
				pack->modified |= IP_MOD_MF;
				break;
			}
		} else {
			/* Preserve the flags when setting the wire-format offset. */
			IP_SET_FRAGOFF(iph,(u_int16_t)strtoul(arg, (char **)NULL, 0) &
			               (u_int16_t)0x1FFF);
			pack->modified |= IP_MOD_FRAGOFF;
			break;
		}
		break;

	case 't':
		/*@@iph->ttl = (u_int8_t)strtoul(arg, (char **)NULL, 0);*/
		iph->ttl = integerargument(arg, 1);
		pack->modified |= IP_MOD_TTL;
		break;
	case 'p':
		/*@@iph->protocol = (u_int8_t)strtoul(arg, (char **)NULL, 0);*/
		iph->protocol = integerargument(arg, 1);
		pack->modified |= IP_MOD_PROTOCOL;
		break;
	case 'c':
		/*@@iph->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		iph->check = integerargument(arg, 2);
		pack->modified |= IP_MOD_CHECK;
		break;


	case 'o':
		/* IP options */
		if(!strcmp(opt+2, "num")) {
			/* Other options (auto length) */
			u_int8_t cp, cls, num;
			int len;
			u_int8_t *data = malloc(strlen(arg)+3);
			if(!data) {
				fprintf(stderr,"Out of memory!\n");
				return FALSE;
			}
			snprintf((char *)data, strlen(arg)+3, "0x%s",arg);
			len = compact_string((char *)data);
			if (len<1 || len>254) { free(data); return FALSE; }
			cp=(*data&0x80)>>7;
			cls=(*data&0x60)>>5;
			num=(*data&0x1F);
			added=addoption(cp,cls,num,len+1,data+1,pack);
			free(data);
		} else if(!strcmp(opt+2, "eol")) {
			/* End of list */
			added=addoption(0,0,0,1,NULL,pack);
		} else if(!strcmp(opt+2, "nop")) {
			/* NOP */
			added=addoption(0,0,1,1,NULL,pack);
		} else if(!strcmp(opt+2, "rr")) {
			u_int8_t data[253];
			int len=buildroute(arg, data, NULL);
			if (!len) return FALSE;
			added=addoption(0,0,7,len+2,data,pack);
		} else if(!strcmp(opt+2, "ts")) {
			u_int8_t data[253];
			int len=buildtimestamp(arg, data);
			if (!len) return FALSE;
			added=addoption(0,2,4,len+2,data,pack);
		} else if(!strcmp(opt+2, "lsr")) {
			u_int8_t data[253];
			int len=buildroute(arg, data, pack);
			if (!len) return FALSE;
			added=addoption(1,0,3,len+2,data,pack);
		} else if(!strcmp(opt+2, "sid")) {
			/* Stream ID (RFC791) */
			/*@@u_int16_t sid = htons(atoi(arg));*/
			u_int16_t sid = integerargument(arg, 2);
			added=addoption(1,0,8,4,(u_int8_t *)&sid,pack);
		} else if(!strcmp(opt+2, "ssr")) {
			u_int8_t data[253];
			int len=buildroute(arg, data, pack);
			if (!len) return FALSE;
			added=addoption(1,0,9,len+2,data,pack);
		} else {
			fprintf(stderr, "unsupported IP option %s val %s\n", opt, arg);
			return FALSE;
		}
		break;

	default:
		usage_error("unknown IP option\n");
		return FALSE;
		break;
	}
	return added;

}

bool do_pad(sendip_data *pack) {
	while (pack->alloc_len%4)
		if (!addoption(0,0,0,1,NULL,pack)) return FALSE;
	return TRUE;
}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	ip_header *iph = (ip_header *)pack->data;

	(void)headers;

	if(!(pack->modified & IP_MOD_VERSION)) {
		iph->version=4;
	}
	if(!(pack->modified & IP_MOD_HEADERLEN)) {
		if (pack->alloc_len>60) {
			usage_error("IPv4 header exceeds the automatic IHL field\n");
			return FALSE;
		}
		iph->header_len=pack->alloc_len/4;
	}
	if(!(pack->modified & IP_MOD_TOTLEN)) {
		if ((size_t)pack->alloc_len+(size_t)data->alloc_len>UINT16_MAX) {
			usage_error("IPv4 packet exceeds the automatic Total Length field\n");
			return FALSE;
		}
		iph->tot_len=pack->alloc_len + data->alloc_len;
		iph->tot_len = htons(iph->tot_len);
	}
	if(!(pack->modified & IP_MOD_ID)) {
		iph->id = rand();
	}
	if(!(pack->modified & IP_MOD_TTL)) {
		iph->ttl = 255;
	}
	if(!(pack->modified&IP_MOD_PROTOCOL)) {
		/* New default: actual type of following header */
		iph->protocol = header_type_at(hdrs, index+1);
	}
	if(!(pack->modified & IP_MOD_CHECK)) {
		ipcsum(pack);
	}
	return TRUE;
}

int num_opts(void) {
	return sizeof(ip_opts)/sizeof(sendip_option);
}
sendip_option *get_opts(void) {
	return ip_opts;
}
char get_optchar(void) {
	return opt_char;
}
