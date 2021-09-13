/* esp.h
 */
#ifndef _SENDIP_ESP_H
#define _SENDIP_ESP_H

/* Real ESP header (ip_esp_hdr) is defined in ipv6ext.h.
 * For allocation purposes, we make up a fake header which includes
 * the ESP trailer. We then move the trailer after the packet data
 * in finalize.
 */
struct ip_esp_tail {
	u_int8_t padlen;	/* padding is pushed before tail */
	u_int8_t nexthdr;
	u_int32_t ivicv[0];	/* both IV and ICV, if any */
};
#define ESP_MIN_PADDING	4	/* We preallocate 4 bytes to handle any
				 * padding requirements.
				 */

struct ip_esp_headtail {
	struct ip_esp_hdr hdr;
	struct ip_esp_tail tail;
};

typedef struct ip_esp_headtail esp_header;

/* We include provisions for a stored key for future use, when we allow
 * "real" ESP implementations.
 */
typedef struct ip_esp_private {		/* keep track of things privately */
	u_int32_t type;		/* type = IPPROTO_ESP */
	u_int32_t ivlen;	/* length of IV portion */
	u_int32_t icvlen;	/* length of ICV portion */
	u_int32_t keylen;	/* length of "key" (not transmitted data) */
	u_int32_t key[0];	/* key itself */
} esp_private;

/* Defines for which parts have been modified
 */
#define ESP_MOD_SPI		(1)
#define ESP_MOD_SEQUENCE	(1<<1)
#define ESP_MOD_PADDING		(1<<2)
#define ESP_MOD_NEXTHDR		(1<<3)
#define ESP_MOD_IV		(1<<4)
#define ESP_MOD_ICV		(1<<5)
#define ESP_MOD_KEY		(1<<6)
#define ESP_MOD_AUTH		(1<<7)
#define ESP_MOD_CRYPT		(1<<8)

#ifdef _ESP_MAIN
/* Options
 */
sendip_option esp_opts[] = {
	{"s",1,"ESP Security Parameters Index","0"},
	{"q",1,"ESP Sequence Number","0"},
	{"p",1,"ESP Padding Length","Minimum needed for alignment"},
	{"n",1,"ESP Next Header","Correct"},
	{"i",1,"ESP IV (string, zN for N nul bytes, or rN for N random bytes)","None"},
	{"I",1,"ESP ICV (string, zN for N nul bytes, or rN for N random bytes)","None"},
	{"k",1,"ESP Key (string, zN for N nul bytes, or rN for N random bytes)"
"  Not transmitted in the packet, but passed to the cryptographic "
"module(s), if any.",
"none"},
	{"a",1,"ESP authentication module", "none"},
	{"c",1,"ESP cryptographic (encryption/privacy) module", "none"},
};
#endif

#define MAXAUTH	8192	/* maximum length of IV or ICV data */

#endif  /* _SENDIP_ESP_H */
