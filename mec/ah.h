/* ah.h
 */
#ifndef _SENDIP_AH_H
#define _SENDIP_AH_H

/* AH header is defined in ipv6ext.h
 */
typedef struct ip_auth_hdr ah_header;

/* Defines for which parts have been modified
 */
#define AH_MOD_SPI	(1)
#define AH_MOD_SEQUENCE	(1<<1)
#define AH_MOD_AUTHDATA	(1<<2)
#define AH_MOD_NEXTHDR	(1<<3)

/* Options
 */
sendip_option ah_opts[] = {
	{"s",1,"AH Security Parameters Index","1"},
	{"q",1,"AH Sequence Number","1"},
	{"d",1,"AH Authentication Data"
"  Variable length authentication data, can be either a user-provided "
"string (in hex, octal, decimal, or raw), or rN for N random bytes.",
"0"},
	{"n",1,"AH Next Header","Correct"},
};


#endif  /* _SENDIP_AH_H */
