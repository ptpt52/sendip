/* wesp.c - wrapped ESP header, provisional version
 *
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
#include "wesp.h"
#include "esp.h"

/* Character that identifies our options
 */
const char opt_char='w';

sendip_data *
initialize(void)
{
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	/* Reserve the optional padding until the final packet offset is known. */
	wesp_header *wesp = malloc(sizeof(wesp_header)+4);

	if (!ret || !wesp) {
		free(wesp);
		free(ret);
		return NULL;
	}
	memset(wesp,0,sizeof(wesp_header)+4);
	ret->alloc_len = sizeof(wesp_header)+4;
	ret->data = wesp;
	ret->modified=0;
	return ret;
}

/* Pretty straightforward. If they flip the padded flag, we
 * add exactly 4 bytes.
 */
bool
addpadding(sendip_data *pack)
{
	wesp_header *wesp = (wesp_header *)pack->data;
	int alloclen = pack->alloc_len+4;

	wesp = realloc((void *)wesp, alloclen);
	if (!wesp) return FALSE;
	pack->data = wesp;
	pack->alloc_len = alloclen;
	/* Be a good citizen */
	wesp->padding[0] = 0;
	return TRUE;
}

bool
do_opt(char *opt, char *arg, sendip_data *pack)
{
	wesp_header *wesp = (wesp_header *)pack->data;
	unsigned long svalue;

	switch(opt[1]) {
	case 'v':	/* WESP version number (2 bits) */
		if (!uintargument(arg, DUO_MAX, &svalue)) {
			usage_error("Too big a version value\n");
			return FALSE;
		}
		wesp->version = svalue;
		pack->modified |= WESP_MOD_VERSION;
		break;
	case 'e':	/* Encrypted payload flag */
		if (!uintargument(arg, 1, &svalue)) {
			usage_error("There's only one bit!\n");
			return FALSE;
		}
		wesp->encrypted = svalue;
		pack->modified |= WESP_MOD_ENCRYPTED;
		break;
	case 'p':	/* Padded flag */
		if (!uintargument(arg, 1, &svalue)) {
			usage_error("There's only one bit!\n");
			return FALSE;
		}
		if (svalue && pack->alloc_len==(int)sizeof(*wesp)) {
			if (!addpadding(pack)) return FALSE;
			wesp = pack->data;
		} else if (!svalue) {
			/* Clearing the flag also removes the corresponding wire bytes. */
			pack->alloc_len=sizeof(*wesp);
		}
		pack->modified |= WESP_MOD_PADDED;
		wesp->padded = svalue;
		break;
	case 'r':	/* WESP reserved (4 bits) */
		if (!uintargument(arg, QUARTET_MAX, &svalue)) {
			usage_error("Too big a resv value\n");
			return FALSE;
		}
		wesp->reserved = svalue;
		pack->modified |= WESP_MOD_RESERVED;
		break;
	case 'h':	/* Header length */
		if (!uintargument(arg, OCTET_MAX, &svalue)) {
			usage_error("Too big a header length\n");
			return FALSE;
		}
		wesp->hdrlen = svalue;
		pack->modified |= WESP_MOD_HDRLEN;
		break;
	case 't':	/* Trailer length */
		if (!uintargument(arg, OCTET_MAX, &svalue)) {
			usage_error("Too big a trailer length\n");
			return FALSE;
		}
		wesp->trlrlen = svalue;
		pack->modified |= WESP_MOD_TRLRLEN;
		break;

	case 'n':	/* WESP next header */
		if (!protocolargument(arg, &wesp->nexthdr)) return FALSE;
		pack->modified |= WESP_MOD_NEXTHDR;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack)
{
	wesp_header *wesp = (wesp_header *)pack->data;
	if (!(pack->modified&WESP_MOD_PADDED)) {
		int ip=outer_header(hdrs, index, "i6");
		if (ip<0 || !headers[ip] || !headers[ip]->data) return FALSE;
		int padding=0;
		if (hdrs[ip]=='6') {
			/* Outer ESP/WESP finalizers have not run yet. Use their final
			 * prefix sizes rather than offsets that they will later move.
			 */
			unsigned int offset=headers[ip]->alloc_len%8;
			for (int i=ip+1; i<index; ++i) {
				sendip_data *prefix=headers[i];
				if (!prefix || prefix->alloc_len<0) return FALSE;
				if (hdrs[i]=='e') {
					esp_private *outer=prefix->private;
					if (!outer || prefix->alloc_len<(int)sizeof(struct ip_esp_hdr) ||
					    outer->ivlen>(unsigned int)prefix->alloc_len-sizeof(struct ip_esp_hdr))
						return FALSE;
					/* ESP's fixed prefix is eight bytes; its trailer moves past us. */
					offset=(offset+outer->ivlen%8)%8;
				} else if (hdrs[i]=='w' && !(prefix->modified&WESP_MOD_PADDED)) {
					/* An automatic outer WESP will align the following ESP. */
					if (offset%4) return FALSE;
					offset=0;
				} else {
					offset=(offset+prefix->alloc_len%8)%8;
				}
			}
			/* A preceding UDP protocol identifier already contributes four bytes. */
			padding=(8-(offset+sizeof(*wesp))%8)%8;
			if (padding!=0 && padding!=4) return FALSE;
		}
		int length=sizeof(*wesp)+padding;
		if (pack->alloc_len<length || data->alloc_len<0) return FALSE;
		int removed=pack->alloc_len-length;
		if (removed) {
			/* Finalizers may shrink a header if they move the following data. */
			memmove((u_int8_t *)data->data-removed, data->data, data->alloc_len);
			data->data=(u_int8_t *)data->data-removed;
			pack->alloc_len=length;
		}
		wesp->padded=padding!=0;
	}
	/* Sanity check - if the user is doing something funky and
	 * the next header is not esp, don't try to interpret it
	 * as such.
	 */
	bool nextesp = (hdrs[index+1] == 'e');
	esp_private *priv = nextesp && headers[index+1] ? headers[index+1]->private : NULL;

	if (!wesp->encrypted && !priv &&
	    (!(pack->modified&WESP_MOD_HDRLEN) || !(pack->modified&WESP_MOD_TRLRLEN))) {
		usage_error("WESP needs an ESP header to derive header and trailer lengths\n");
		return FALSE;
	}

	if (!(pack->modified&WESP_MOD_NEXTHDR)) {
		if (wesp->encrypted || !nextesp)
			wesp->nexthdr = 0;
		else {
			/* ESP has finalized already. Mirror its actual trailer, including
			 * an explicit Next Header override (RFC 5840 section 2).
			 */
			if (!priv || data->alloc_len<(int)sizeof(struct ip_esp_hdr)+2 ||
			    priv->icvlen>(unsigned int)data->alloc_len-sizeof(struct ip_esp_hdr)-2) {
				usage_error("Cannot locate the finalized ESP Next Header\n");
				return FALSE;
			}
			wesp->nexthdr=((const u_int8_t *)data->data)[data->alloc_len-priv->icvlen-1];
		}
	}
	if (!(pack->modified&WESP_MOD_HDRLEN)) {
		if (wesp->encrypted)
			wesp->hdrlen = 0;
		else {
			/* hdrlen is the length from the start of WESP header to
			 * the start of the post-IV payload.
			 */
			size_t length=(size_t)pack->alloc_len+sizeof(struct ip_esp_hdr)+priv->ivlen;
			if (length>OCTET_MAX) {
				usage_error("Derived WESP header length exceeds one byte\n");
				return FALSE;
			}
			wesp->hdrlen=length;
		}
	}
	if (!(pack->modified&WESP_MOD_TRLRLEN)) {
		if (wesp->encrypted)
			wesp->trlrlen = 0;
		else {
			/* trlrlen is just the ICV length */
			if (priv->icvlen>OCTET_MAX) {
				usage_error("Derived WESP trailer length exceeds one byte\n");
				return FALSE;
			}
			wesp->trlrlen = priv->icvlen;
		}
	}
	return TRUE;
}

int num_opts(void)
{
	return sizeof(wesp_opts)/sizeof(sendip_option);
}

sendip_option *get_opts(void)
{
	return wesp_opts;
}

char get_optchar(void)
{
	return opt_char;
}

/* Keep bare-r generation in range without weakening explicit validation. */
u_int32_t randomize_arg(const char *option, u_int32_t value) {
	switch (option[1]) {
	case 'v': return value & DUO_MAX;
	case 'e': case 'p': return value & 1;
	case 'r': return value & QUARTET_MAX;
	case 'h': case 't': return value & OCTET_MAX;
	default: return value;
	}
}
