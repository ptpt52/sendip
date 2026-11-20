/* ah.c - authentication header (for IPv6)
 *
 * This currently is strictly a dummy version; eventually I hope
 * to add provisions to allow plugging in real AH modules.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"
#define _CRYPTO_MAIN
#define _AH_MAIN
#include "ah.h"
#include "crypto_module.h"

/* Character that identifies our options
 */
const char opt_char='a';



void destroy(sendip_data *pack) {
	ah_private *priv=pack->private;
	if (!priv) return;
	unload_crypto_module(priv->crypto);
	free(priv);
	pack->private=NULL;
}

sendip_data *
initialize(void)
{
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	ah_header *ah = malloc(sizeof(ah_header));
	ah_private *priv = malloc(sizeof(ah_private));

	if (!ret || !ah || !priv) {
		free(priv);
		free(ah);
		free(ret);
		return NULL;
	}
	memset(ah,0,sizeof(ah_header));
	memset(priv,0,sizeof(ah_private));
	ah->hdrlen = 1;		/* RFC 4302 length with empty auth data */
	ret->alloc_len = sizeof(ah_header);
	ret->data = ah;
	priv->type = IPPROTO_AH;
	ret->private = priv;
	ret->modified=0;
	return ret;
}

bool
do_opt(char *opt, char *arg, sendip_data *pack)
{
	ah_header *ah = (ah_header *)pack->data;
	ah_private *priv = (ah_private *)pack->private;
	char *temp;
	int length;

	switch(opt[1]) {
	case 's':	/* SPI (32 bits) */
		ah->spi = integerargument(arg, 4);
		pack->modified |= AH_MOD_SPI;
		break;
	case 'q':	/* Sequence number (32 bits) */
		ah->seq_no = integerargument(arg, 4);
		pack->modified |= AH_MOD_SEQUENCE;
		break;
	case 'd':	/* Authentication data (variable length) */
		/* For right now, we will do either random generation
		 * or a user-provided string.
		 */
		length = stringargument(arg, &temp);
		if (!temp) return FALSE;
		ah = realloc(ah, sizeof(ah_header)+length);
		if (!ah) return FALSE;
		pack->data = ah;
		pack->alloc_len = sizeof(ah_header)+length;
		ah = (ah_header *)pack->data;
		memcpy(ah->auth_data, temp, length);
		/* as per RFC 4302 */
		ah->hdrlen = 1 + length/4;
		pack->modified |= AH_MOD_AUTHDATA;
		break;
	case 'k':       /* Key */
		length = stringargument(arg, &temp);
		if (!temp) return FALSE;
		priv = (ah_private *)realloc(priv,
		                             sizeof(ah_private) + length);
		if (!priv) return FALSE;
		priv->keylen = length;
		memcpy(priv->key, temp, priv->keylen);
		pack->private = priv;
		pack->modified |= AH_MOD_KEY;
		break;
	case 'm':       /* Cryptographic module */
		{
			crypto_module *module=load_crypto_module(arg);
			if (!module) return FALSE;
			unload_crypto_module(priv->crypto);
			priv->crypto=module;
		}
		/* Call any init routine */
		if (priv->crypto->cryptoinit)
			return (*priv->crypto->cryptoinit)(pack);
		break;

	case 'n':	/* Next header */
		ah->nexthdr = name_to_proto(arg);
		pack->modified |= AH_MOD_NEXTHDR;
		break;
	}
	return TRUE;

}

bool
finalize(char *hdrs, sendip_data *headers[], int index,
         sendip_data *data, sendip_data *pack)
{
	ah_header *ah = (ah_header *)pack->data;
	ah_private *priv = (ah_private *) pack->private;
	int ret = TRUE;

	if (!(pack->modified&AH_MOD_NEXTHDR))
		ah->nexthdr = header_type(hdrs[index+1]);
	/* If there's a crypto module, give it the packet to fill
	 * in the auth data.
	 */
	if (priv->crypto && priv->crypto->cryptomod) {
		ret = (*priv->crypto->cryptomod)(priv, hdrs, headers, index,
		                             data, pack);
	}
	return ret;
}

int
num_opts(void)
{
	return sizeof(ah_opts)/sizeof(sendip_option);
}

sendip_option *
get_opts(void)
{
	return ah_opts;
}

char
get_optchar(void)
{
	return opt_char;
}
