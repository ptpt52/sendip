/* xorcrypto.c - this is a dummy "encryption" module that
 * demonstrates the interfaces for an external encryption
 * module.
 *
 * The "encryption" simply consists of xor-ing the "key"
 * with the packet data. Of course, with a really big
 * key (one-time pad), this would be pretty good!
 */

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"
#include "../ipv6.h"
#include "../ipv4.h"
#include "ah.h"
#include "esp.h"
#include "crypto_module.h"

/* There's no particular "initialization" to be done here, so
 * this is just a demo interface. In real life, initialization
 * might involve key negotiation, IV determination, or whatever.
 */
bool
cryptoinit(sendip_data *pack)
{
	if (!pack || !pack->private) return FALSE; /* don't mess with me! */
	if (*(u_int32_t *)pack->private!=IPPROTO_ESP) {
		usage_error("xorcrypto requires an ESP header\n");
		return FALSE;
	}
	/* Here we might determine and fill in the key:
	 * esp_private *epriv = (esp_private *)pack->private;
	 *
	 *	epriv = (esp_private *)realloc(epriv,
	 *		sizeof(esp_private) + keylength);
	 *	epriv->keylen = keylength;
	 *	memcpy(epriv->key, key, keylength);
	 *	pack->private = epriv;
	 *	pack->modified |= ESP_MOD_KEY;
	 */
	return TRUE;
}

/* The actual "encryption" routine.
 *
 * I could have made the data arguments a full vector, but two
 * elements are enough, so I left it at that.
 */
void
xorcrypto(u_int8_t *key, u_int32_t keylen,
          u_int8_t *data, u_int32_t datalen)
{
	u_int32_t d, k;
	if (!keylen) return;

	for (d=0, k=0; d < datalen; ++d, k = (k+1)%keylen) {
		data[d] ^= key[k];
	}
}

bool
espcrypto(esp_private *epriv, sendip_data *data, sendip_data *pack)
{
	u_int32_t keylen;
	u_int8_t *key;
	static u_int8_t fakekey;
	struct ip_esp_hdr *esp = (struct ip_esp_hdr *)pack->data;

	/* Finalize exposes the eight-byte ESP header separately from the IV,
	 * payload, encrypted trailer and trailing ICV. Check before subtracting.
	 */
	if (pack->alloc_len!=(int)sizeof(*esp) || data->alloc_len<2 ||
	    epriv->ivlen>(u_int32_t)data->alloc_len-2 ||
	    epriv->icvlen>(u_int32_t)data->alloc_len-2-epriv->ivlen) {
		usage_error("Invalid ESP encryption extent\n");
		return FALSE;
	}

	if (!epriv->keylen) {	/* This isn't going to be very productive... */
		key = &fakekey;
		keylen = 1;
	} else {
		key = (u_int8_t *)epriv->key;
		keylen = epriv->keylen;
	}
	/* The explicit IV and ICV stay clear; transform payload and trailer. */
	xorcrypto(key, keylen,
	          (u_int8_t *)esp->enc_data+epriv->ivlen,
	          data->alloc_len-epriv->ivlen-epriv->icvlen);
	return TRUE;
}

bool
cryptomod(void *priv, char *hdrs, sendip_data *headers[],
          int index, sendip_data *data, sendip_data *pack)
{
	if (!pack || !priv || !data) return FALSE; /* don't mess with me! */
	if (*(u_int32_t *)priv!=IPPROTO_ESP) return FALSE;

	return espcrypto((esp_private *)priv, data, pack);
}
