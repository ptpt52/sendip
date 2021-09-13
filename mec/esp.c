/* esp.c - esp header (for IPv6)
 *
 * This currently is strictly a dummy version; eventually I hope
 * to add provisions to allow plugging in real ESP modules.
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
#define _ESP_MAIN
#include "esp.h"
#include "crypto_module.h"

/* Character that identifies our options
 */
const char opt_char='e';

crypto_module *authesp, *cryptoesp;

sendip_data *
initialize(void)
{
	sendip_data *ret = malloc(sizeof(sendip_data));
	/* We allocate an additional 4 bytes to ensure we have
	 * enough space for any padding in finalize(). In reality,
	 * we will only need at most 3 bytes, but this should
	 * help keep things aligned better.
	 */
	esp_header *esp = malloc(sizeof(esp_header) + ESP_MIN_PADDING);
	esp_private *priv = malloc(sizeof(esp_private));

	memset(esp,0,sizeof(esp_header)+ESP_MIN_PADDING);
	memset(priv,0,sizeof(esp_private));
	ret->alloc_len = sizeof(esp_header)+ESP_MIN_PADDING;
	ret->data = esp;
	priv->type = IPPROTO_ESP;
	ret->private = priv;
	ret->modified=0;
	return ret;
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
		esp->hdr.spi = htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= ESP_MOD_SPI;
		break;
	case 'q':	/* Sequence number (32 bits) */
		esp->hdr.seq_no =
			htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= ESP_MOD_SEQUENCE;
		break;
	case 'p':	/* padding (variable length) */
		/* We initially put the padding at the end of the
		 * header, then move it past the payload in finalize.
		 */
		length = strtoul(arg, (char **)NULL, 0);
		if (length > OCTET_MAX) {
			usage_error("Padding length can't be over 255\n");
			return FALSE;
		}
		esp->tail.padlen = length;
		if (length >  ESP_MIN_PADDING) {
			pack->alloc_len += length-ESP_MIN_PADDING;
			pack->data = realloc(esp, pack->alloc_len);
		}
		/* We don't bother doing anything with the padding
		 * contents right now
		 */
		pack->modified |= ESP_MOD_PADDING;
		break;
	case 'i':	/* IV data (variable length) */
		/* For right now, we will do either random generation
		 * or a user-provided string. We put it in the header,
		 * where in finalize it will constitute the beginning
		 * of the payload area.
		 */
		length = stringargument(arg, &temp);
		priv->ivlen = length;
		pack->alloc_len += length;
		pack->data = realloc(esp, pack->alloc_len);
		esp = (esp_header *)pack->data;
		/* Check if we have an ICV we have to shove down */
		if (priv->icvlen)
			memmove(&esp->tail.ivicv[priv->ivlen],
				&esp->tail.ivicv[0], priv->icvlen);
		memcpy(&esp->tail.ivicv[0], temp, priv->ivlen);
		pack->modified |= ESP_MOD_IV;
		break;
	case 'I':	/* ICV data (variable length) */
		/* For right now, we will do either random generation
		 * or a user-provided string. We put it in the header,
		 * then move it into the trailer in finalize.
		 */
		length = stringargument(arg, &temp);
		priv->icvlen = length;
		pack->alloc_len += length;
		pack->data = realloc(esp, pack->alloc_len);
		esp = (esp_header *)pack->data;
		memcpy(&esp->tail.ivicv[priv->ivlen], temp, priv->icvlen);
		pack->modified |= ESP_MOD_ICV;
		break;
	case 'k':	/* Key */
		length = stringargument(arg, &temp);
		priv->keylen = length;
		priv = (esp_private *)realloc(priv,
				sizeof(esp_private) + length);
		memcpy(priv->key, temp, priv->keylen);
		pack->private = priv;
		pack->modified |= ESP_MOD_KEY;
		break;
	case 'a':	/* Authentication module */
		authesp = load_crypto_module(arg);
		if (!authesp)
			return FALSE;
		/* Call any init routine */
		pack->modified |= ESP_MOD_AUTH;
		if (authesp->cryptoinit)
			return (*authesp->cryptoinit)(pack);
		break;
	case 'c':	/* Cryptographic (encryption/privacy) module */
		cryptoesp = load_crypto_module(arg);
		if (!cryptoesp)
			return FALSE;
		/* Call any init routine */
		pack->modified |= ESP_MOD_CRYPT;
		if (cryptoesp->cryptoinit)
			return (*cryptoesp->cryptoinit)(pack);
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
		memcpy(iv, &esp->tail.ivicv[0], priv->ivlen);
	} else {
		iv = NULL;
	}
	if (priv->icvlen) {
		icv = (u_int8_t *)malloc(priv->icvlen);
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
		where += priv->icvlen;
		free((void *)icv);
	}

	/* Now let's testify to the real lengths */
	pack->alloc_len = sizeof(struct ip_esp_hdr);
	data->alloc_len += priv->ivlen + padlen + priv->icvlen + 2;

	/* Call any authentication and/or encryption modules, in
	 * that order, and let them work their magic.
	 */
	if (authesp && authesp->cryptomod) {
		ret = (*authesp->cryptomod)(priv, hdrs, headers, index,
			data, pack);
	}
	if (ret == TRUE) {
		if (cryptoesp && cryptoesp->cryptomod) {
			ret = (*cryptoesp->cryptomod)(priv, hdrs, headers,
				index, data, pack);
		}
	}

	/* @@ We can't free the private data, as WESP needs it */
	/* free((void *)priv);
	pack->private = NULL; */
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
