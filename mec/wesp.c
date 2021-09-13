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
	sendip_data *ret = malloc(sizeof(sendip_data));
	wesp_header *wesp = malloc(sizeof(wesp_header));

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
	u_int16_t svalue;

	switch(opt[1]) {
	case 'v':	/* WESP version number (2 bits) */
		pack->modified |= WESP_MOD_VERSION;
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > DUO_MAX) {
			usage_error("Too big a version value\n");
			return FALSE;
		}
		wesp->version = svalue;
		break;
	case 'e':	/* Encrypted payload flag */
		pack->modified |= WESP_MOD_ENCRYPTED;
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > 1) {
			usage_error("There's only one bit!\n");
			return FALSE;
		}
		wesp->encrypted = svalue;
		break;
	case 'p':	/* Padded flag */
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > 1) {
			usage_error("There's only one bit!\n");
			return FALSE;
		}
		if (svalue && (!(pack->modified&WESP_MOD_PADDED)))
			(void)addpadding(pack);
		pack->modified |= WESP_MOD_PADDED;
		wesp->padded = svalue;
		break;
	case 'r':	/* WESP reserved (4 bits) */
		pack->modified |= WESP_MOD_RESERVED;
		svalue = strtoul(arg, (char **)NULL, 0);
		if (svalue > QUARTET_MAX) {
			usage_error("Too big a resv value\n");
			return FALSE;
		}
		wesp->reserved = svalue;
		break;
	case 'h':	/* Header length */
		pack->modified |= WESP_MOD_HDRLEN;
		svalue = strtoul(arg, (char **)NULL, 0);

		if (svalue > OCTET_MAX) {
			usage_error("Too big a header length\n");
			return FALSE;
		}
		wesp->hdrlen = svalue;
		break;
	case 't':	/* Trailer length */
		pack->modified |= WESP_MOD_TRLRLEN;
		svalue = strtoul(arg, (char **)NULL, 0);

		if (svalue > OCTET_MAX) {
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
	esp_private *priv;

	if (!headers[index+1]) {	/* oh well */
		nextesp = FALSE;
		priv = NULL;
	} else {
		priv = (esp_private *)headers[index+1]->private;
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
			wesp->hdrlen = pack->alloc_len +
					sizeof(struct ip_esp_hdr) +
						priv->ivlen;
		}
	}
	if (!(pack->modified&WESP_MOD_TRLRLEN)) {
		if (wesp->encrypted)
			wesp->trlrlen = 0;
		else {
		/* trlrlen is just the ICV length */
			wesp->trlrlen = priv->icvlen;
		}
	}
	return TRUE;
}

int num_opts()
{
	return sizeof(wesp_opts)/sizeof(sendip_option); 
}

sendip_option *get_opts()
{
	return wesp_opts;
}

char get_optchar()
{
	return opt_char;
}
