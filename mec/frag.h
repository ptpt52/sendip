/* frag.h
 * (ipv6) fragment header
 */
#ifndef _SENDIP_FRAG_H
#define _SENDIP_FRAG_H

/* fragment header
 */
typedef struct ipv6_frag_hdr	frag_header;

#define IPV6_FRAG_MF  	0x0001		/* more fragments flag */
#define IPV6_FRAG_FLAGS	0x0007		/* flag space in frag_off */
#define IPV6_FRAG_OFFSHIFT	3
#define IPV6_FRAG_MAXOFFSET	((1<<13)-1)

/* Defines for which parts have been modified
 */
#define FRAG_MOD_NEXTHDR   (1)
#define FRAG_MOD_RESV 	(1<<1)
#define FRAG_MOD_OFFSET	(1<<2)
#define FRAG_MOD_FLAGS	(1<<3)
#define FRAG_MOD_ID	(1<<4)

/* Options
 */
sendip_option frag_opts[] = {
	{"n",1,"Fragment next header","Correct"},
	{"r",1,"Fragment reserved (1 byte)", "0"},
	{"o",1,"Fragment offset","0"},
	{"f",1,"Fragment flags (3 bits, lsb=more fragments)","0"},
	{"i",1,"Fragment identification","0"},
};

#endif  /* _SENDIP_FRAG_H */
