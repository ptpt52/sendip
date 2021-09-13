/* protoname.c - protocol number/name conversion */

/* Based on some code in ipv6header from ip6tables:
 * Original idea: Brad Chapman 
 * Rewritten by: Andras Kis-Szabo <kisza@sch.bme.hu>
 *
 * This by Mark Carson.
 */

#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>

#include "mec/ipv6ext.h"

/* A few hardcoded protocols for 'all' and in case the user has no
 *    /etc/protocols */
struct pprot {
	const char *name;
	u_int8_t num;
};

struct numflag {
	u_int8_t proto;
	u_int8_t flag;
};

static struct pprot chain_protos[] = {
	{ "hop-by-hop", IPPROTO_HOPOPTS },
	{ "protocol", IPPROTO_RAW },
	{ "hop", IPPROTO_HOPOPTS },
	{ "dst", IPPROTO_DSTOPTS },
	{ "route", IPPROTO_ROUTING },
	{ "frag", IPPROTO_FRAGMENT },
	{ "auth", IPPROTO_AH },
	{ "esp", IPPROTO_ESP },
	{ "none", IPPROTO_NONE },
	{ "prot", IPPROTO_RAW },
	{ "0", IPPROTO_HOPOPTS },
	{ "60", IPPROTO_DSTOPTS },
	{ "43", IPPROTO_ROUTING },
	{ "44", IPPROTO_FRAGMENT },
	{ "51", IPPROTO_AH },
	{ "50", IPPROTO_ESP },
	{ "59", IPPROTO_NONE },
	{ "255", IPPROTO_RAW },
	/* { "all", 0 }, */
};

const char *
proto_to_name(u_int8_t proto, int nolookup)
{
        unsigned int i;

        if (proto && !nolookup) {
                struct protoent *pent = getprotobynumber(proto);
                if (pent)
                        return pent->p_name;
        }

        for (i = 0; i < sizeof(chain_protos)/sizeof(struct pprot); i++)
                if (chain_protos[i].num == proto)
                        return chain_protos[i].name;

        return NULL;
}

u_int8_t
name_to_proto(char *s)
{
        unsigned int proto=0;
        struct protoent *pent;

	/* Check for a number */
	if (isdigit(*s))
		return (u_int8_t)strtoul(s, (char **)NULL, 0);
	/* If we have /etc/protocols, use that */
        if ((pent = getprotobyname(s)))
        	proto = pent->p_proto;
        else {	/* our backup method */
        	unsigned int i;
        	for (i = 0;
        		i < sizeof(chain_protos)/sizeof(struct pprot);
        		i++) {
        		if (strcmp(s, chain_protos[i].name) == 0) {
        			proto = chain_protos[i].num;
        			break;
        		}
        	}

        	if (i == sizeof(chain_protos)/sizeof(struct pprot)) {
        		fprintf(stderr, "unknown header `%s' specified", s);
			exit(1);
		}
        }

        return (u_int8_t)proto;
}
