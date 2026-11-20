/* ntp.c - Network Timxe Protocol module for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog since 2.1 release:
 */

#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <math.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "sendip_module.h"
#include "ntp.h"

/* Character that identifies our options
 */
const char opt_char='n';

static bool make_fixed_point(double n, bool issigned, int fracbits,
                             u_int32_t *result) {
	double scaled=ldexp(n, fracbits);
	double minimum=issigned ? -2147483648.0 : 0.0;
	double maximum=issigned ? 2147483648.0 : 4294967296.0;
	if (!isfinite(scaled) || scaled<minimum || scaled>=maximum) return FALSE;
	/* Convert in a signed type wide enough for either 32-bit wire format. */
	*result=htonl((u_int32_t)(int64_t)scaled);
	return TRUE;
}

static bool parse_fixed_point(const char *src, bool issigned, int fracbits,
                              u_int32_t *result) {
	char *end;
	errno=0;
	double value=strtod(src, &end);
	return end!=src && !*end && !errno &&
	       make_fixed_point(value, issigned, fracbits, result);
}

bool make_ts(ntp_ts *dest, char *src) {
	char *end=src;
	unsigned long seconds=0;
	u_int32_t fraction=0;
	if (!isdigit((unsigned char)*src) && *src!='.') return FALSE;
	if (*src!='.') {
		errno=0;
		seconds=strtoul(src, &end, 0);
		if (errno || seconds>UINT32_MAX) return FALSE;
	}
	if (*end=='.') {
		char *fraction_end;
		errno=0;
		double value=strtod(end, &fraction_end);
		if (fraction_end==end || *fraction_end || errno || value<0 || value>=1 ||
		    !make_fixed_point(value, FALSE, 32, &fraction)) return FALSE;
	} else if (*end) return FALSE;
	dest->intpart=htonl((u_int32_t)seconds);
	dest->fracpart=fraction;
	return TRUE;
}

sendip_data *initialize(void) {
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	ntp_header *ntp = malloc(sizeof(ntp_header));
	if (!ret || !ntp) {
		free(ntp);
		free(ret);
		return NULL;
	}
	memset(ntp,0,sizeof(ntp_header));
	ret->alloc_len = sizeof(ntp_header);
	ret->data = (void *)ntp;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	ntp_header *ntp = (ntp_header *)pack->data;
	switch(opt[1]) {
	case 'l':  /* Leap Indicator (2 bits) */
		ntp->leap=(u_int8_t)strtoul(arg,(char **)NULL,0)&3;
		pack->modified|=NTP_MOD_LEAP;
		break;
	case 's':  /* Status (6 bits, values 0-4 defined */
		ntp->status=(u_int8_t)strtoul(arg,(char **)NULL,0)&0x3F;
		pack->modified|=NTP_MOD_STATUS;
		break;
	case 't':  /* Type (8 bits, values 0-4 defined */
		ntp->type=(u_int8_t)strtoul(arg,(char **)NULL,0)&0xFF;
		pack->modified|=NTP_MOD_TYPE;
		break;
	case 'p':  /* precision (16 bits, range +32 to -32) */
		ntp->precision=htons((int8_t)strtol(arg,(char **)NULL,0));
		pack->modified|=NTP_MOD_PRECISION;
		break;
	case 'e':  /* esitmated error (32 bits, fixed point between bits 15/16) */
		if (!parse_fixed_point(arg, FALSE, 16, &ntp->error)) return FALSE;
		pack->modified|=NTP_MOD_ERROR;
		break;
	case 'd':  /* estimated drift rate (32 bits, signed fixed point left of
					  high order bit) */
		if (!parse_fixed_point(arg, TRUE, 31, &ntp->drift)) return FALSE;
		pack->modified|=NTP_MOD_DRIFT;
		break;
	case 'r':  /* reference clock id (32 bits or a 4 byte string).  Can be:
					  If type==1: "WWVB", "GOES", "WWV\0"
					  If type==2: IP address
					  Else: must be zero
				  */
		if('0'<=*arg&&*arg<='9') {
			/* either a number or an IP */
			if((ntp->reference.ipaddr=inet_addr(arg))==INADDR_NONE) {
				/* Not a valid IP, or really want 255.255.255.255 */
				if(strcmp(arg,"255.255.255.255")) {
					ntp->reference.ipaddr=htonl(strtol(arg,(char **)NULL,0));
				}
			}
		} else {
			/* Hopefully a 4 byte or less string */
			ntp->reference.ipaddr = 0;
			if(strlen(arg)<=4) {
				memcpy(ntp->reference.id,arg,strlen(arg));
			} else {
				usage_error("NTP reference clock ID must be IP addr, 32 bit integer, or 4 byte string\n");
				return FALSE;
			}
		}
		pack->modified|=NTP_MOD_REF;
		break;
	case 'f':  /* reference timestamp (64 bits) */
		if(make_ts(&(ntp->reference_ts),arg)) {
			pack->modified|=NTP_MOD_REFERENCE;
		} else {
			usage_error("Couldn't parse NTP reference timestamp\n");
			return FALSE;
		}
		break;
	case 'o':  /* originate timestamp (64 bits) */
		if(make_ts(&(ntp->originate_ts),arg)) {
			pack->modified|=NTP_MOD_ORIGINATE;
		} else {
			usage_error("Couldn't parse NTP originate timestamp\n");
			return FALSE;
		}
		break;
	case 'a':  /* receive timestamp (64 bits) */
		if(make_ts(&(ntp->receive_ts),arg)) {
			pack->modified|=NTP_MOD_RECEIVE;
		} else {
			usage_error("Couldn't parse NTP receive timestamp\n");
			return FALSE;
		}
		break;
	case 'x':  /* transmit timestamp (64 bits) */
		if(make_ts(&(ntp->transmit_ts),arg)) {
			pack->modified|=NTP_MOD_TRANSMIT;
		} else {
			usage_error("Couldn't parse NTP transmit timestamp\n");
			return FALSE;
		}
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	if(index<1 || hdrs[index-1] != 'u') {
		usage_error("Warning: NTP should be contained in a UDP packet\n");
	}
	return TRUE;
}

int num_opts() {
	return sizeof(ntp_opts)/sizeof(sendip_option);
}
sendip_option *get_opts() {
	return ntp_opts;
}
char get_optchar() {
	return opt_char;
}
