#ifndef _IPV6EXT_H
#define _IPV6EXT_h

/* The following are taken from a variety of Linux kernel header
 * files, rearranged and reworked for our purposes here.
 */

/*
 *	IPV6 extension headers
 *	In the Linux source, some of these (those also in v4)
 *	are part of an enum, but let's just pull them all together.
 */
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS		0	/* IPv6 hop-by-hop options	*/
#define IPPROTO_ROUTING		43	/* IPv6 routing header		*/
#define IPPROTO_FRAGMENT	44	/* IPv6 fragmentation header	*/
#define IPPROTO_GRE		47	/* Cisco GRE tunnels		*/
#define IPPROTO_ESP		50	/* Encapsulation Security Payload */
#define IPPROTO_AH		51	/* Authentication Header	*/
#define IPPROTO_ICMPV6		58	/* ICMPv6			*/
#define IPPROTO_NONE		59	/* IPv6 no next header		*/
#define IPPROTO_DSTOPTS		60	/* IPv6 destination options	*/
#define IPPROTO_BEETPH		94	/* IP option pseudo header for BEET */
#define IPPROTO_COMP		108	/* Compression Header		*/
#define IPPROTO_MH		135	/* IPv6 mobility header		*/
#endif

/* others ... */
#ifndef IPPROTO_IP
#define IPPROTO_IP		0	/* Dummy protocol for TCP	*/
#define IPPROTO_ICMP		1	/* Internet Control Message 	*/
#define IPPROTO_IGMP		2	/* Internet Group Management 	*/
#define IPPROTO_IPIP		4	/* IPIP tunnels 		*/
#define IPPROTO_TCP		6	/* Transmission Control Protocol*/
#define IPPROTO_EGP		8	/* Exterior Gateway Protocol	*/
#define IPPROTO_PUP		12	/* PUP 				*/
#define IPPROTO_UDP		17	/* User Datagram Protocol	*/
#define IPPROTO_IDP		22	/* XNS IDP protocol		*/
#define IPPROTO_DCCP		33	/* Datagram Congestion Control 	*/
#define IPPROTO_IPV6		41	/* IPv6-in-IPv4 tunnelling	*/
#define IPPROTO_RSVP		46	/* RSVP 			*/
#define IPPROTO_PIM		103	/* Protocol Independent Multicast*/
#define IPPROTO_SCTP		132	/* Stream Control Transport 	*/
#define IPPROTO_UDPLITE		136	/* UDP-Lite (RFC 3828)		*/
#define IPPROTO_RAW		255	/* Raw IP packets		*/
#endif

/* Just allocated by IANA */
#define IPPROTO_WESP		141	/* Wrapped ESP */

/* Header types and associated sendip opt_chars. Things should be set
 * up so this can be determined dynamically, but for now, we'll just
 * make a fixed table.
 */
struct sendip_headers {
	const char opt_char;
	const u_int8_t ipproto;
};
extern struct sendip_headers sendip_headers[];

/* hop-by-hop and destination options header */
struct ipv6_opt_hdr {
	u_int8_t		nexthdr;
	u_int8_t		hdrlen;
	/*
	 * TLV encoded option data follows.
	 */
};

#define ipv6_destopt_hdr ipv6_opt_hdr
#define ipv6_hopopt_hdr  ipv6_opt_hdr

/*
 *	home address option in destination options header
 */

struct ipv6_destopt_hao {
	u_int8_t	type;
	u_int8_t	length;
	struct in6_addr	addr;
};

/*
 *	fragmentation header
 */

struct ipv6_frag_hdr {
	u_int8_t	nexthdr;
	u_int8_t	reserved;
	u_int16_t	frag_off;   /* fragment offset - 13 bits + 3 flags */
	u_int32_t	identification;
};


/*
 *	routing header
 */
#define IPV6_SRCRT_STRICT	0x01	/* Deprecated; will be removed */
#define IPV6_SRCRT_TYPE_0	0	/* Deprecated; will be removed */
#define IPV6_SRCRT_TYPE_2	2	/* IPv6 type 2 Routing Header	*/
struct ipv6_rt_hdr {
	u_int8_t		nexthdr;
	u_int8_t		hdrlen;
	u_int8_t		type;
	u_int8_t		segments_left;

	/*
	 *	type specific data
	 *	variable length field
	 */
};

/*
 *	routing header type 0 (used in cmsghdr struct)
 */

struct rt0_hdr {
	struct ipv6_rt_hdr	rt_hdr;
	u_int32_t		reserved;
	struct in6_addr		addr[0];

#define rt0_type		rt_hdr.type
};

/*
 *	routing header type 2
 */

struct rt2_hdr {
	struct ipv6_rt_hdr	rt_hdr;
	u_int32_t		reserved;
	struct in6_addr		addr;

#define rt2_type		rt_hdr.type
};

/*
 * authentication header
 */
struct ip_auth_hdr {
	u_int8_t  nexthdr;
	u_int8_t  hdrlen;	/* This one is measured in 32 bit units! */
	u_int16_t reserved;
	u_int32_t spi;
	u_int32_t seq_no;	/* Sequence number */
	u_int8_t  auth_data[0];	/* Variable len but >=4. Mind the 64 bit alignment! */
#define	icv	auth_data	/* rfc 4302 name */
	/* TBD - high-order sequence number */
	
};

/*
 * encapsulated security payload header
 */
struct ip_esp_hdr {
	u_int32_t spi;
	u_int32_t seq_no;	/* Sequence number */
	u_int8_t  enc_data[0];	/* Variable len but >=8. Mind the 64 bit alignment! */
};


/*
 * compression header
 */
struct ip_comp_hdr {
	u_int8_t nexthdr;
	u_int8_t flags;
	u_int16_t cpi;
};

/*
 * beet header
 */
struct ip_beet_phdr {
	u_int8_t nexthdr;
	u_int8_t hdrlen;
	u_int8_t padlen;
	u_int8_t reserved;
};

/* miscellanea */
/* for code documentation purposes, largest u_int8_t (8-bit unsigned) value */
#define OCTET_MAX	255
/* Largest 4-bit unsigned value */
#define QUARTET_MAX	15
/* Largest 2-bit unsigned value */
#define DUO_MAX		3
/* Largest 1-bit value is left as an exercise for the reader */

#endif
