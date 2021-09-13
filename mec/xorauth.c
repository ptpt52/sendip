/* xorauth.c - this is a dummy "authentication" module that
 * demonstrates the interfaces for an external authentication
 * module.
 *
 * This module works with both AH and ESP, detecting which
 * is being used when it is called.
 *
 * The "authentication" simply consists of xor-ing the "key"
 * with the packet data, and storing the result in the
 * appropriate place (auth_data for AH, the ICV for ESP).
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
 * might involve key negotiation, ICV length specification,
 * IV determination, or whatever.
 */
bool
cryptoinit(sendip_data *pack)
{
	u_int32_t type;

	if (!pack || !pack->private) return FALSE; /* don't mess with me! */
	type = *(u_int32_t *) pack->private;
	switch (type) {
	case IPPROTO_AH:
		{
		/* Here we might determine and fill in the key:
		 * ah_private *apriv = (ah_private *)pack->private;
		 *
		 *	apriv = (ah_private *)realloc(apriv,
		 *		sizeof(ah_private) + keylength);
		 *	apriv->keylen = keylength;
		 *	memcpy(apriv->key, key, keylength);
		 *	pack->private = apriv;
		 *	pack->modified |= AH_MOD_KEY;
		 */
		}
		break;
	case IPPROTO_ESP:
		{
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
		}
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

/* The actual ICV determination routine.
 *
 * I could have made the data arguments a full vector, but two
 * elements are enough, so I left it at that.
 */
void
xoricv(u_int8_t *key, u_int32_t keylen,
	u_int8_t *icv, u_int32_t icvlen,
	u_int8_t *data1, u_int32_t data1len,
	u_int8_t *data2, u_int32_t data2len)
{
	int d, k, i;

	/* @@ The icv should be zeroed prior to calculation. Should
	 * we do that here, or just assume that this has been done?
	 * I guess we will have to do it, just to make sure. Of course,
	 * this defeats any attempt to "spike" the icv with some
	 * initial value, but anyone who wants to do that is free to
	 * write his or her own authentication module ...
	 */
	(void) memset((void *)icv, 0, icvlen);

	for (d=0, k=0, i=0; d < data1len; ++d,
			k = (k+1)%keylen, i = (i+1)%icvlen) {
		icv[i] ^= (key[k]^data1[d]);
	}
	for (d=0, k=0, i=0; d < data2len; ++d,
			k = (k+1)%keylen, i = (i+1)%icvlen) {
		icv[i] ^= (key[k]^data2[d]);
	}
}

/* For AH, the RFC has various rules about what gets included
 * and not included when computing the ICV. If we were doing a real
 * implementation, we'd have to care about the rules. Here, we are just
 * demonstrating interfaces, so we ignore the rules for the most part.
 *
 * We do handle some of the awkwardness, though. AH is supposed
 * to apply to (portions of) the IP header as well, which is not very
 * convenient, as it has not been finalized yet. So we have to create
 * a fake header and "finalize" that.
 */

bool
ahipv4(ah_private *apriv, char *hdrs, int index, sendip_data *ipack,
	sendip_data *data, sendip_data *pack)
{
	ip_header *realip = (ip_header *)ipack->data;
	ip_header pseudoip;
	ah_header *ah = (ah_header *)pack->data;
	u_int32_t keylen;
	u_int32_t authlen;
	u_int8_t *key;
	static u_int8_t fakekey;

	(void) memset(&pseudoip, 0, sizeof(pseudoip));
	if (!(ipack->modified & IP_MOD_VERSION))
		pseudoip.version = 4;
	else
		pseudoip.version = realip->version;
	if (!(ipack->modified & IP_MOD_HEADERLEN))
		pseudoip.header_len = (ipack->alloc_len+3)/4;
	else
		pseudoip.header_len = realip->header_len;
	if (!(ipack->modified & IP_MOD_TOTLEN)) {
		pseudoip.tot_len = ipack->alloc_len +
			pack->alloc_len + data->alloc_len;
#ifndef __FreeBSD__
#ifndef __FreeBSD
		pseudoip.tot_len = htons(pseudoip.tot_len);
#endif
#endif
	} else
		pseudoip.tot_len = realip->tot_len;
	/* Here there's an issue, since the ipv4 module inserts a
	 * random id if none is present. This seems like the only
	 * solution, though it is a nasty violation of module
	 * boundaries...
	 */
	if(!(ipack->modified & IP_MOD_ID)) {
		pseudoip.id = realip->id = rand();
		ipack->modified |= IP_MOD_ID;
	} else
		pseudoip.id = realip->id;
	if (!(ipack->modified&IP_MOD_PROTOCOL)) {
                /* New default: actual type of following header */
		pseudoip.protocol = header_type(hdrs[index+1]);
	} else
		pseudoip.protocol = realip->protocol;
	/* set_addr is called before finalize, so we know the
	 * addresses are already set.
	 */
	pseudoip.saddr = realip->saddr;
	pseudoip.daddr = realip->daddr;

	/* Here is the sloppy part. We don't evaluate which
	 * interior headers have parts which should be ignored
	 * and which don't. A full implementation would have
	 * to do that.
	 *
	 * We also don't look at any headers which come between
	 * the IP and AH headers, but seeing as how it's a
	 * violation of the RFCs to have any, that at least is
	 * not a big deal.
	 */
	if (!apriv->keylen) {
		key = &fakekey;
		keylen = 1;
	} else {
		key = (u_int8_t *)apriv->key;
		keylen = apriv->keylen;
	}
	/* We allow odd ICV lengths, so we use this rather than
	 * calculate from the length value in the AH header.
	 */
	authlen = pack->alloc_len - sizeof(ah_header);
	xoricv(key, keylen, (u_int8_t *)ah->auth_data, authlen,
		(u_int8_t *)&pseudoip, sizeof(pseudoip),
		(u_int8_t *)data->data, data->alloc_len);
	return TRUE;
}

bool
ahipv6(ah_private *apriv, char *hdrs, int index, sendip_data *ipack,
	sendip_data *data, sendip_data *pack)
{
	ipv6_header *realip = (ipv6_header *)ipack->data;
	ipv6_header pseudoip;
	ah_header *ah = (ah_header *)pack->data;
	u_int32_t keylen;
	u_int32_t authlen;
	u_int8_t *key;
	static u_int8_t fakekey;

	(void) memset(&pseudoip, 0, sizeof(pseudoip));
	if (!(ipack->modified & IPV6_MOD_VERSION)) {
		pseudoip.ip6_vfc &= 0x0F;
		pseudoip.ip6_vfc |= (6 << 4);
	} else
		pseudoip.ip6_vfc = realip->ip6_vfc;
	if (!(ipack->modified & IPV6_MOD_PLEN)) {
		pseudoip.ip6_plen = htons(ipack->alloc_len + pack->alloc_len
			+ data->alloc_len);
	} else
		pseudoip.ip6_plen = realip->ip6_plen;
	if (!(ipack->modified&IPV6_MOD_NXT)) {
                /* New default: actual type of following header */
		pseudoip.ip6_nxt = header_type(hdrs[index+1]);
	} else
		pseudoip.ip6_nxt = realip->ip6_nxt;
	/* set_addr is called before finalize, so we know the
	 * addresses are already set.
	 */
	pseudoip.ip6_src = realip->ip6_src;
	pseudoip.ip6_dst = realip->ip6_dst;

	/* Same comments as for the IPv4 case: we don't try to
	 * determine which interior header fields should be
	 * ignored in ICV determination, and we ignore any
	 * (nonstandard) headers inserted between the IPv6 and
	 * AH header.
	 */
	if (!apriv->keylen) {
		key = &fakekey;
		keylen = 1;
	} else {
		key = (u_int8_t *)apriv->key;
		keylen = apriv->keylen;
	}
	/* We allow odd ICV lengths, so we use this rather than
	 * calculate from the length value in the AH header.
	 */
	authlen = pack->alloc_len - sizeof(ah_header);
	xoricv(key, keylen, (u_int8_t *)ah->auth_data, authlen,
		(u_int8_t *)&pseudoip, sizeof(pseudoip),
		(u_int8_t *)data->data, data->alloc_len);
	return TRUE;
}


/* ESP ICV calculation is much simpler, as it just goes
 * from the ESP header to right before the ICV area. It
 * is therefore the same for IPv4 and IPv6.
 */
bool
espip(esp_private *epriv, char *hdrs, int index, sendip_data *ipack,
	sendip_data *data, sendip_data *pack)
{
	u_int32_t keylen;
	u_int8_t *key;
	static u_int8_t fakekey;
	u_int8_t *icv;

	if (!epriv->keylen) {
		key = &fakekey;
		keylen = 1;
	} else {
		key = (u_int8_t *)epriv->key;
		keylen = epriv->keylen;
	}
	icv = (u_int8_t *)data->data + (data->alloc_len - epriv->icvlen);
	/* In this case, the two regions being "authenticated" are
	 * contiguous, so we don't actually need to vector them. But
	 * the routine is just sitting there ...
	 */
	xoricv(key, keylen, icv, epriv->icvlen,
		(u_int8_t *)pack->data, pack->alloc_len,
		(u_int8_t *)data->data, data->alloc_len - epriv->icvlen);
	return TRUE;
}

bool 
cryptomod(void *priv, char *hdrs, sendip_data *headers[],
	int index, sendip_data *data, sendip_data *pack)
{
	u_int32_t type;
	int i;
	sendip_data *ipack;

	if (!pack || !priv || !data) return FALSE; /* don't mess with me! */
	type = *(u_int32_t *) priv;
	i = outer_header(hdrs, index, "i6");	/* IPv4/IPv6 */
	ipack = headers[i];
	if (!ipack) return FALSE; /* don't mess with me! */

	switch (type) {
	case IPPROTO_AH:
		switch (hdrs[i]) {
		case 'i':	/* IPv4 */
			return ahipv4((ah_private *)priv, hdrs, index, ipack,
				data, pack);
			break;
		case '6':	/* IPv6 */
			return ahipv6((ah_private *)priv, hdrs, index, ipack,
				data, pack);
			break;
		default:
			return FALSE;
		}
		break;
	case IPPROTO_ESP:
		/* No need to differentiate between IPv4 and IPv6 */
		return espip((esp_private *)priv, hdrs, index, ipack,
			data, pack);
		break;
	default:
		return FALSE;
	}
	/* Wow, how did we get here? */
	return FALSE;

}
