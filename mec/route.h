/* route.h
 * (ipv6) routing extension header
 */
#ifndef _SENDIP_ROUTE_H
#define _SENDIP_ROUTE_H

/* routement header
 */
typedef struct ipv6_rt_hdr	route_header;

/* Defines for which parts have been modified
 */
#define ROUTE_MOD_NEXTHDR	   (1)
#define ROUTE_MOD_TYPE 		(1<<1)
#define ROUTE_MOD_SEGMENTS	(1<<2)
#define ROUTE_MOD_RESV		(1<<3)
#define ROUTE_MOD_ADDRLIST	(1<<4)

/* Absolute limit on the number of addresses we can specify */
#define ADDRMAX		(OCTET_MAX/2)

/* Options
 */
sendip_option route_opts[] = {
	{"n",1,"Routing next header","Correct"},
	{"t",1,"Routing header type", "0"},
	{"s",1,"Routing segments left","0"},
	{"r",1,"Routing reserved field","0"},
	{"a",1,"Routing list of addresses (comma separated)","none"},
};

#endif  /* _SENDIP_ROUTE_H */
