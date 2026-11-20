/* esp.c - esp header (for IPv6)
 *
 * This currently is strictly a dummy version; eventually I hope
 * to add provisions to allow plugging in real ESP modules.
 */

#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"
#define _CRYPTO_MAIN
#define _ESP_MAIN
#include "esp.h"
#include "crypto_module.h"

/* Character that identifies our options
 */
const char opt_char='e';



void destroy(sendip_data *pack) {
	esp_private *priv=pack->private;
	if (!priv) return;
	unload_crypto_module(priv->auth);
	unload_crypto_module(priv->crypto);
	free(priv);
	pack->private=NULL;
}

sendip_data *
initialize(void)
{
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	/* We allocate an additional 4 bytes to ensure we have
	 * enough space for any padding in finalize(). In reality,
	 * we will only need at most 3 bytes, but this should
	 * help keep things aligned better.
	 */
	esp_header *esp = malloc(ESP_WORK_HEADER_LEN + ESP_MIN_PADDING);
	esp_private *priv = malloc(sizeof(esp_private));

	if (!ret || !esp || !priv) {
		free(priv);
		free(esp);
		free(ret);
		return NULL;
	}
	memset(esp,0,ESP_WORK_HEADER_LEN+ESP_MIN_PADDING);
	memset(priv,0,sizeof(esp_private));
	ret->alloc_len = ESP_WORK_HEADER_LEN+ESP_MIN_PADDING;
	ret->data = esp;
	priv->type = IPPROTO_ESP;
	ret->private = priv;
	ret->modified=0;
	return ret;
}

/* Rebuild the variable region before releasing the old buffer. This also
 * makes repeated IV/ICV options replace the previous value without gaps.
 */
static bool replace_components(sendip_data *pack, const void *iv, int ivlen,
                               const void *icv, int icvlen, int padding) {
	size_t size=ESP_WORK_HEADER_LEN+(size_t)ivlen+icvlen+padding;
	if (ivlen<0 || icvlen<0 || padding<0 || size>INT_MAX) return FALSE;
	esp_header *replacement=calloc(1, size);
	if (!replacement) return FALSE;
	memcpy(replacement, pack->data, ESP_WORK_HEADER_LEN);
	if (ivlen) memcpy(replacement->tail.ivicv, iv, ivlen);
	if (icvlen) memcpy(replacement->tail.ivicv+ivlen, icv, icvlen);
	free(pack->data);
	pack->data=replacement;
	pack->alloc_len=(int)size;
	return TRUE;
}

bool
do_opt(char *opt, char *arg, sendip_data *pack)
{
	esp_header *esp = (esp_header *)pack->data;
	esp_private *priv = (esp_private *)pack->private;
	char *temp;
	int length;

	switch(opt[1]) {
	case 's':	/* SPI (32 bits) */
		esp->hdr.spi = integerargument(arg, 4);
		pack->modified |= ESP_MOD_SPI;
		break;
	case 'q':	/* Sequence number (32 bits) */
		esp->hdr.seq_no = integerargument(arg, 4);
		pack->modified |= ESP_MOD_SEQUENCE;
		break;
	case 'p': /* Explicit padding replaces the previous reservation. */
	{
		char *end;
		errno=0;
		unsigned long padding=strtoul(arg, &end, 0);
		if (!isdigit((unsigned char)*arg) || errno || *end || padding>OCTET_MAX) {
			usage_error("Padding length must be between 0 and 255\n");
			return FALSE;
		}
		if (!replace_components(pack, esp->tail.ivicv, priv->ivlen,
		                        esp->tail.ivicv+priv->ivlen, priv->icvlen, padding))
			return FALSE;
		esp=pack->data;
		esp->tail.padlen=padding;
		pack->modified |= ESP_MOD_PADDING;
		break;
	}
	case 'i': /* Initialization vector */
		length=stringargument(arg, &temp);
		if (!temp || !replace_components(pack, temp, length,
		                                 esp->tail.ivicv+priv->ivlen, priv->icvlen,
		                                 pack->modified&ESP_MOD_PADDING ? esp->tail.padlen : ESP_MIN_PADDING))
			return FALSE;
		priv->ivlen=length;
		pack->modified |= ESP_MOD_IV;
		break;
	case 'I': /* Integrity check value */
		length=stringargument(arg, &temp);
		if (!temp || !replace_components(pack, esp->tail.ivicv, priv->ivlen,
		                                 temp, length,
		                                 pack->modified&ESP_MOD_PADDING ? esp->tail.padlen : ESP_MIN_PADDING))
			return FALSE;
		priv->icvlen=length;
		pack->modified |= ESP_MOD_ICV;
		break;
	case 'k': /* Key */
		length=stringargument(arg, &temp);
		if (!temp) return FALSE;
		priv=realloc(priv, sizeof(*priv)+(size_t)length);
		if (!priv) return FALSE;
		priv->keylen=length;
		memcpy(priv->key, temp, length);
		pack->private=priv;
		pack->modified |= ESP_MOD_KEY;
		break;
	case 'a':	/* Authentication module */
		{
			crypto_module *module=load_crypto_module(arg);
			if (!module) return FALSE;
			unload_crypto_module(priv->auth);
			priv->auth=module;
		}
		/* Call any init routine */
		pack->modified |= ESP_MOD_AUTH;
		if (priv->auth->cryptoinit)
			return (*priv->auth->cryptoinit)(pack);
		break;
	case 'c':	/* Cryptographic (encryption/privacy) module */
		{
			crypto_module *module=load_crypto_module(arg);
			if (!module) return FALSE;
			unload_crypto_module(priv->crypto);
			priv->crypto=module;
		}
		/* Call any init routine */
		pack->modified |= ESP_MOD_CRYPT;
		if (priv->crypto->cryptoinit)
			return (*priv->crypto->cryptoinit)(pack);
		break;
	case 'n':	/* Next header */
		esp->tail.nexthdr = name_to_proto(arg);
		pack->modified |= ESP_MOD_NEXTHDR;
		break;
	}
	return TRUE;

}

bool
finalize(char *hdrs, sendip_data *headers[], int index,
         sendip_data *data, sendip_data *pack)
{
	esp_header *esp = (esp_header *)pack->data;
	esp_private *priv = (esp_private *)pack->private;
	/* Let's just be stupid! */
	u_int8_t padlen, nexthdr;
	u_int8_t *iv, *icv, *where;
	int ret = TRUE;

	if (!(pack->modified&ESP_MOD_NEXTHDR))
		esp->tail.nexthdr = header_type(hdrs[index+1]);
	/* @@ figure out padding if not already set */
	if (!(pack->modified&ESP_MOD_PADDING)) {
		/* We need to pad out IV+packet data length
		 * to be equal to 2 mod 4. I'll subtract it
		 * from 6 rather than 2 to keep signs positive.
		 *
		 * 0->2  (6-0) -> 2
		 * 1->1	 (6-1) -> 1
		 * 2->0	 (6-2) -> 0
		 * 3->3  (6-3) -> 3
		 */
		esp->tail.padlen =
		    (6 - ((data->alloc_len + priv->ivlen)&03))&03;
		/* We preallocated 4 bytes for padding above,
		 * so we will actually be trimming a little bit.
		 */
		pack->alloc_len -= ESP_MIN_PADDING-esp->tail.padlen;

	}

	/* Now move the tail past the data portion of the packet
	 * Premove layout:
	 * esp header:	SPI
	 * 		sequence number
	 * 		pad length
	 * 		next header
	 * 		IV
	 * 		ICV
	 * 		padding
	 * payload:	packet data
	 *
	 * Postmove layout:
	 * esp header:	SPI
	 * 		sequence number
	 * payload:	IV
	 *		packet data
	 * esp trailer:	padding
	 * 		pad length
	 * 		next header
	 * 		ICV
	 */
	/* For the sake of clarity, we do all of this in the
	 * most straightforward, stupid manner possible.
	 */
	padlen = esp->tail.padlen;
	nexthdr = esp->tail.nexthdr;
	if (priv->ivlen) {
		iv = (u_int8_t *)malloc(priv->ivlen);
		if (!iv) return FALSE;
		memcpy(iv, &esp->tail.ivicv[0], priv->ivlen);
	} else {
		iv = NULL;
	}
	if (priv->icvlen) {
		icv = (u_int8_t *)malloc(priv->icvlen);
		if (!icv) { free(iv); return FALSE; }
		memcpy(icv, &esp->tail.ivicv[priv->ivlen], priv->icvlen);
	} else {
		icv = NULL;
	}

	/* Now fill out the packet */
	where = esp->hdr.enc_data;
	/* This can't overwrite the packet data, as the iv space was already
	 * in the original oversized "header."
	 */
	if (iv) {
		memcpy(where, iv, priv->ivlen);
		where += priv->ivlen;
		free((void *)iv);
	}
	/* I think memcpy would work, too (at least, the implementations
	 * of it that I have seen), but since technically this could
	 * be an "overlapping" move, we'll use memmove.
	 */
	memmove(where, data->data, data->alloc_len);
	/* Move the data pointer to the new payload head for the
	 * benefit of any crypto module that wants to know where
	 * things are.
	 */
	data->data = (void *)(where - priv->ivlen);
	/* Now move our work pointer past the packet data and
	 * fill out the trailer.
	 */
	where += data->alloc_len;
	memset(where, 0, padlen);
	where += padlen;
	*where++ = padlen;
	*where++ = nexthdr;
	if (icv) {
		memcpy(where, icv, priv->icvlen);
		free((void *)icv);
	}

	/* Now let's testify to the real lengths */
	pack->alloc_len = sizeof(struct ip_esp_hdr);
	data->alloc_len += priv->ivlen + padlen + priv->icvlen + 2;

	/* Call any authentication and/or encryption modules, in
	 * that order, and let them work their magic.
	 */
	if (priv->auth && priv->auth->cryptomod) {
		ret = (*priv->auth->cryptomod)(priv, hdrs, headers, index,
		                            data, pack);
	}
	if (ret == TRUE) {
		if (priv->crypto && priv->crypto->cryptomod) {
			ret = (*priv->crypto->cryptomod)(priv, hdrs, headers,
			                              index, data, pack);
		}
	}

	return ret;
}

int
num_opts(void)
{
	return sizeof(esp_opts)/sizeof(sendip_option);
}

sendip_option *
get_opts(void)
{
	return esp_opts;
}

char
get_optchar(void)
{
	return opt_char;
}
