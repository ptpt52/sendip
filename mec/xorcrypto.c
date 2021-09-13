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
	int d, k;

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

	if (!epriv->keylen) {	/* This isn't going to be very productive... */
		key = &fakekey;
		keylen = 1;
	} else {
		key = (u_int8_t *)epriv->key;
		keylen = epriv->keylen;
	}
	/* Encrypt everything past the ESP header */
	xorcrypto(key, keylen, 
		(u_int8_t *)esp->enc_data,
			pack->alloc_len + data->alloc_len -
				sizeof(struct ip_esp_hdr));
	return TRUE;
}

bool 
cryptomod(void *priv, char *hdrs, sendip_data *headers[],
	int index, sendip_data *data, sendip_data *pack)
{
	if (!pack || !priv || !data) return FALSE; /* don't mess with me! */

	return espcrypto((esp_private *)priv, data, pack);
}
