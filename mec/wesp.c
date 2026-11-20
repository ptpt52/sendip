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
	wesp_header *wesp = malloc(sizeof(wesp_header));

	if (!ret || !wesp) {
		free(wesp);
		free(ret);
		return NULL;
	}
	memset(wesp,0,sizeof(wesp_header));
	ret->alloc_len = sizeof(wesp_header);
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
		pack->modified |= WESP_MOD_VERSION;
		if (!uintargument(arg, DUO_MAX, &svalue)) {
			usage_error("Too big a version value\n");
			return FALSE;
		}
		wesp->version = svalue;
		break;
	case 'e':	/* Encrypted payload flag */
		pack->modified |= WESP_MOD_ENCRYPTED;
		if (!uintargument(arg, 1, &svalue)) {
			usage_error("There's only one bit!\n");
			return FALSE;
		}
		wesp->encrypted = svalue;
		break;
	case 'p':	/* Padded flag */
		if (!uintargument(arg, 1, &svalue)) {
			usage_error("There's only one bit!\n");
			return FALSE;
		}
		if (svalue && pack->alloc_len==(int)sizeof(*wesp)) {
			if (!addpadding(pack)) return FALSE;
			wesp = pack->data;
		}
		pack->modified |= WESP_MOD_PADDED;
		wesp->padded = svalue;
		break;
	case 'r':	/* WESP reserved (4 bits) */
		pack->modified |= WESP_MOD_RESERVED;
		if (!uintargument(arg, QUARTET_MAX, &svalue)) {
			usage_error("Too big a resv value\n");
			return FALSE;
		}
		wesp->reserved = svalue;
		break;
	case 'h':	/* Header length */
		pack->modified |= WESP_MOD_HDRLEN;
		if (!uintargument(arg, OCTET_MAX, &svalue)) {
			usage_error("Too big a header length\n");
			return FALSE;
		}
		wesp->hdrlen = svalue;
		break;
	case 't':	/* Trailer length */
		pack->modified |= WESP_MOD_TRLRLEN;
		if (!uintargument(arg, OCTET_MAX, &svalue)) {
			usage_error("Too big a trailer length\n");
			return FALSE;
		}
		wesp->trlrlen = svalue;
		break;

	case 'n':	/* WESP next header */
		wesp->nexthdr = name_to_proto(arg);
		pack->modified |= WESP_MOD_NEXTHDR;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack)
{
	wesp_header *wesp = (wesp_header *)pack->data;
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
		else 	/* supposed to be the header after esp */
			wesp->nexthdr = header_type(hdrs[index+2]);
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
