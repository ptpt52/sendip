/* tcp.c - tcp support for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * TCP options taken from code by Alexander Talos <at@atat.at>
 * ChangeLog since 2.0 release:
 * 27/11/2001: Added -tonum option
 * 02/12/2001: Only check 1 layer for enclosing IPV4 header
 * ChangeLog since 2.1 release:
 * 16/04/2002: Tidy up checksum code (like in icmp.c)
 * 16/04/2002: Add support for TCP over IPV6 (code from armite <armite@163.com>)
 * 26/08/2002: Fix bug where tcp length was wrong with tcp options
 * ChangeLog since 2.2 release:
 * 24/11/2002: made it compile on archs that care about alignment
 * ChangeLog since 2.4 release:
 * 21/04/2003: fix errors found by valgrind
 * 10/06/2003: fix -tonum (pointed out by Yaniv Kaul <ykaul@checkpoint.com>)
 */

#include <sys/types.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <netinet/in.h>
#include <string.h>
#include "sendip_module.h"
#include "tcp.h"
#include "ipv4.h"
#include "ipv6.h"

/* Character that identifies our options
 */
const char opt_char='t';

static bool decimal32(const char *input, char **end, u_int32_t *value) {
	if (!isdigit((unsigned char)*input)) return FALSE;
	errno=0;
	unsigned long parsed=strtoul(input, end, 10);
	if (errno || *end==input || parsed>UINT32_MAX) return FALSE;
	*value=parsed;
	return TRUE;
}

static void tcpcsum(sendip_data *ip_hdr, sendip_data *tcp_hdr,
                    sendip_data *data) {
	tcp_header *tcp=tcp_hdr->data;
	ip_header *ip=ip_hdr->data;
	u_int8_t pseudo[12]={0};
	u_int16_t length=htons(tcp_hdr->alloc_len+data->alloc_len);
	memcpy(pseudo, &ip->saddr, 4);
	memcpy(pseudo+4, &ip->daddr, 4);
	pseudo[9]=IPPROTO_TCP;
	memcpy(pseudo+10, &length, 2);
	const void *blocks[]={pseudo, tcp_hdr->data, data->data};
	int lengths[]={sizeof(pseudo), tcp_hdr->alloc_len, data->alloc_len, 0};
	tcp->check=0;
	tcp->check=csumv(blocks, lengths);
}

static void tcp6csum(const struct ipv6_pseudo_hdr *phdr, sendip_data *tcp_hdr,
                     sendip_data *data) {
	tcp_header *tcp=tcp_hdr->data;
	const void *blocks[]={phdr, tcp_hdr->data, data->data};
	int lengths[]={sizeof(*phdr), tcp_hdr->alloc_len, data->alloc_len, 0};
	tcp->check=0;
	tcp->check=csumv(blocks, lengths);
}

static bool addoption(u_int8_t opt, int len, u_int8_t *data,
                      sendip_data *pack) {
	if (len<1 || len>255 || pack->alloc_len>INT_MAX-len || (len>2 && !data))
		return FALSE;
	void *replacement=realloc(pack->data, (size_t)pack->alloc_len+len);
	if (!replacement) return FALSE;
	pack->data=replacement;
	*((u_int8_t *)pack->data+pack->alloc_len) = opt;
	if(len > 1)
		*((u_int8_t *)pack->data+pack->alloc_len+1)=len;
	if(len > 2)
		memcpy((u_int8_t *)pack->data+pack->alloc_len+2,data,len-2);
	pack->alloc_len += len;
	return TRUE;
}

sendip_data *initialize(void) {
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	tcp_header *tcp = malloc(sizeof(tcp_header));
	if (!ret || !tcp) {
		free(tcp);
		free(ret);
		return NULL;
	}
	memset(tcp,0,sizeof(tcp_header));
	ret->alloc_len = sizeof(tcp_header);
	ret->data = (void *)tcp;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	u_int32_t parsed;
	tcp_header *tcp = (tcp_header *)pack->data;
	// opt[0]==t
	bool added=TRUE;
	switch(opt[1]) {
	case 's':
		/*@@tcp->source = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		tcp->source = parsed;
		pack->modified |= TCP_MOD_SOURCE;
		break;
	case 'd':
		/*@@tcp->dest = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		tcp->dest = parsed;
		pack->modified |= TCP_MOD_DEST;
		break;
	case 'n':
		/*@@tcp->seq = htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));*/
		if (!integerargument_checked(arg, 4, &parsed)) return FALSE;
		tcp->seq = parsed;
		pack->modified |= TCP_MOD_SEQ;
		break;
	case 'a':
		/*@@tcp->ack_seq = htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));*/
		if (!integerargument_checked(arg, 4, &parsed)) return FALSE;
		tcp->ack_seq = parsed;
		pack->modified |= TCP_MOD_ACKSEQ;
		if(!(pack->modified&TCP_MOD_ACK)) {
			tcp->ack = 1;
			pack->modified |= TCP_MOD_ACK;
		}
		break;
	case 't':
		/*@@tcp->off = (u_int16_t)strtoul(arg, (char **)NULL, 0) &0xF;*/
		if (!integerargument_checked(arg, 1, &parsed)) return FALSE;
		tcp->off = parsed&0xF;
		pack->modified |= TCP_MOD_OFF;
		break;
	case 'r':
		/*@@tcp->res = (u_int16_t)(strtoul(arg, (char **)NULL, 0) & 0x000F);*/
		if (!integerargument_checked(arg, 1, &parsed)) return FALSE;
		tcp->res = parsed&0xF;
		pack->modified |= TCP_MOD_RES;
		break;
	case 'f':
		switch(opt[2]) {
		case 'e':
			tcp->ecn=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_ECN;
			break;
		case 'c':
			tcp->cwr=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_CWR;
			break;
		case 'u':
			tcp->urg=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_URG;
			break;
		case 'a':
			tcp->ack=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_ACK;
			break;
		case 'p':
			tcp->psh=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_PSH;
			break;
		case 'r':
			tcp->rst=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_RST;
			break;
		case 's':
			tcp->syn=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_SYN;
			break;
		case 'f':
			tcp->fin=(u_int16_t)*arg&1;
			pack->modified |= TCP_MOD_FIN;
			break;
		default:
			usage_error("TCP flag not known\n");
			return FALSE;
		}
		break;
	case 'w':
		/*@@tcp->window = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		tcp->window = parsed;
		pack->modified |= TCP_MOD_WINDOW;
		break;
	case 'c':
		/*@@tcp->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		tcp->check = parsed;
		pack->modified |= TCP_MOD_CHECK;
		break;
	case 'u':
		/*@@tcp->urg_ptr = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));*/
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		tcp->urg_ptr = parsed;
		pack->modified |= TCP_MOD_URGPTR;
		if(!(pack->modified&TCP_MOD_URG)) {
			tcp->urg = 1;
			pack->modified |= TCP_MOD_URG;
		}
		break;

	case 'o':
		/* TCP OPTIONS */
		if(!strcmp(opt+2, "num")) {
			/* Other options (auto length) */
			u_int8_t *data = malloc(strlen(arg)+3);
			int len;
			if(!data) {
				fprintf(stderr,"Out of memory!\n");
				return FALSE;
			}
			snprintf((char *)data, strlen(arg)+3, "0x%s",arg);
			len = compact_string((char *)data);
			if (len<1 || len>254) { free(data); return FALSE; }
			if(len==1)
				added=addoption(*data,1,NULL,pack);
			else
				added=addoption(*data,len+1,data+1,pack);
			free(data);
		} else if (!strcmp(opt+2, "eol")) {
			/* End of options list RFC 793 kind 0, no length */
			added=addoption(0,1,NULL,pack);
		} else if (!strcmp(opt+2, "nop")) {
			/* No op RFC 793 kind 1, no length */
			added=addoption(1,1,NULL,pack);
		} else if (!strcmp(opt+2, "mss")) {
			/* Maximum segment size RFC 793 kind 2 */
			if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
			u_int16_t mss = parsed;
			added=addoption(2,4,(u_int8_t *)&mss,pack);
		} else if (!strcmp(opt+2, "wscale")) {
			/* Window scale rfc1323 */
			if (!hostintegerargument_checked(arg, 1, &parsed)) return FALSE;
			u_int8_t wscale = parsed;
			added=addoption(3,3,&wscale,pack);
		} else if (!strcmp(opt+2, "sackok")) {
			/* Selective Acknowledge permitted rfc1323 */
			added=addoption(4,2,NULL,pack);
		} else if (!strcmp(opt+2, "sack")) {
			/* Each SACK block contains two 32-bit sequence numbers. */
			u_int8_t blocks[31*8];
			int count=0;
			char *remaining=arg, *block;
			while ((block=strsep(&remaining, ","))) {
				char *right=strchr(block, ':');
				if (!right || right==block || count==31 || !right[1]) return FALSE;
				*right++='\0';
				char *end;
				u_int32_t left, last;
				if (!decimal32(block, &end, &left) || *end ||
				    !decimal32(right, &end, &last) || *end) return FALSE;
				left=htonl(left);
				last=htonl(last);
				memcpy(blocks+count*8, &left, 4);
				memcpy(blocks+count*8+4, &last, 4);
				++count;
			}
			added=addoption(5, count*8+2, blocks, pack);
		} else if (!strcmp(opt+2, "ts")) {
			/* Timestamp rfc1323 */
			u_int32_t tsval=0, tsecr=0;
			u_int8_t comb[8];
			char *end;
			if (!decimal32(arg, &end, &tsval) || *end!=':' ||
			    !decimal32(end+1, &end, &tsecr) || *end) {
				fprintf(stderr,
				        "Invalid value for tcp timestamp option.\n");
				fprintf(stderr,
				        "Usage: -tots tsval:tsecr\n");
				return FALSE;
			}
			tsval=htonl(tsval);
			memcpy(comb, &tsval, 4);
			tsecr=htonl(tsecr);
			memcpy(comb+4, &tsecr, 4);
			added=addoption(8,10,comb,pack);
		} else {
			/* Unrecognized -to* */
			fprintf(stderr, "unsupported TCP Option %s val %s\n",
			        opt, arg);
			return FALSE;
		}
		break;

	default:
		usage_error("unknown TCP option\n");
		return FALSE;
		break;

	}

	return added;

}

/* TCP Data Offset counts complete 32-bit words, including zero padding. */
bool do_pad(sendip_data *pack) {
	while (pack->alloc_len%4)
		if (!addoption(0, 1, NULL, pack)) return FALSE;
	return TRUE;
}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	tcp_header *tcp = (tcp_header *)pack->data;
	int i;

	/* Set relevant fields */
	if(!(pack->modified&TCP_MOD_SEQ)) {
		tcp->seq = (u_int32_t)rand();
	}
	if(!(pack->modified&TCP_MOD_OFF)) {
		if (pack->alloc_len>60) {
			usage_error("TCP header exceeds the automatic Data Offset field\n");
			return FALSE;
		}
		tcp->off = pack->alloc_len/4;
	}
	if(!(pack->modified&TCP_MOD_SYN)) {
		tcp->syn=1;
	}
	if(!(pack->modified&TCP_MOD_WINDOW)) {
		tcp->window=htons((u_int16_t)65535);
	}

	/* Find enclosing IP header and do the checksum */
	i = outer_header(hdrs, index, "i6");/*@@*/
	if (i < 0) {
		if (pack->modified&TCP_MOD_CHECK) return TRUE;
		usage_error("TCP checksum not defined when TCP is not embedded in IP\n");
		return FALSE;
	}
	if(hdrs[i]=='i') {
		if (!(pack->modified&TCP_MOD_CHECK) &&
		    (size_t)pack->alloc_len+(size_t)data->alloc_len>UINT16_MAX) {
			usage_error("TCP over IPv4 exceeds the automatic checksum length field\n");
			return FALSE;
		}
		unsigned int old_daddr = 0;
		if(!(headers[i]->modified&IP_MOD_PROTOCOL)) {
			((ip_header *)(headers[i]->data))->protocol=header_type_at(hdrs, i+1);
			headers[i]->modified |= IP_MOD_PROTOCOL;
		}
		//replace ip daddr
		if((headers[i]->modified & IP_MOD_ROUTE_DADDR)) {
			old_daddr=((ip_header *)(headers[i]->data))->daddr;
			((ip_header *)(headers[i]->data))->daddr=headers[i]->route_daddr;
		}
		if(!(pack->modified&TCP_MOD_CHECK)) {
			tcpcsum(headers[i],pack,data);
		}
		//restore ip daddr
		if((headers[i]->modified & IP_MOD_ROUTE_DADDR)) {
			((ip_header *)(headers[i]->data))->daddr=old_daddr;
		}
	} else if(hdrs[i]=='6') {
		// @@ This is subsumed by my new code which determines the
		// next header type in the ipv6 module.
		//if(!(headers[i]->modified&IPV6_MOD_NXT)) {
		//	((ipv6_header *)(headers[i]->data))->ip6_nxt=IPPROTO_TCP;
		//	headers[i]->modified |= IPV6_MOD_NXT;
		//}
		if(!(pack->modified&TCP_MOD_CHECK)) {
			struct ipv6_pseudo_hdr phdr;
			if (!ipv6_pseudo_header(hdrs, headers, i, index,
			                       pack->alloc_len+data->alloc_len, IPPROTO_TCP, &phdr))
				return FALSE;
			tcp6csum(&phdr, pack, data);
		}
	} else {
		if(!(pack->modified&TCP_MOD_CHECK)) {
			usage_error("TCP checksum not defined when TCP is not embedded in IP\n");
			return FALSE;
		}
	}

	return TRUE;
}

int num_opts(void) {
	return sizeof(tcp_opts)/sizeof(sendip_option);
}
sendip_option *get_opts(void) {
	return tcp_opts;
}
char get_optchar(void) {
	return opt_char;
}
