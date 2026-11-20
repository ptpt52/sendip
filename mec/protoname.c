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
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#include "sendip_module.h"
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
	{ "wesp", IPPROTO_WESP },
	{ "0", IPPROTO_HOPOPTS },
	{ "60", IPPROTO_DSTOPTS },
	{ "43", IPPROTO_ROUTING },
	{ "44", IPPROTO_FRAGMENT },
	{ "51", IPPROTO_AH },
	{ "50", IPPROTO_ESP },
	{ "59", IPPROTO_NONE },
	{ "141", IPPROTO_WESP },
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

bool protocolargument(const char *input, u_int8_t *value) {
	struct protoent *entry;
	if (!input || !*input || !value) goto invalid;
	/* Require a complete integer, then retain the legacy width conversion. */
	if (isdigit((unsigned char)*input)) {
		char *end;
		errno=0;
		unsigned long number=strtoul(input, &end, 0);
		if (errno || *end) goto invalid;
		*value=(u_int8_t)number;
		return TRUE;
	}
	if ((entry=getprotobyname(input))) {
		*value=entry->p_proto;
		return TRUE;
	}
	for (size_t i=0; i<sizeof(chain_protos)/sizeof(chain_protos[0]); ++i) {
		if (!strcmp(input, chain_protos[i].name)) {
			*value=chain_protos[i].num;
			return TRUE;
		}
	}
invalid:
	fprintf(stderr, "Unknown header `%s' specified\n", input ? input : "(null)");
	return FALSE;
}

/* Retain the original entry point for external modules. Built-in modules
 * use protocolargument() so their caller owns all failure cleanup.
 */
u_int8_t name_to_proto(char *input) {
	u_int8_t value;
	if (!protocolargument(input, &value)) exit(EXIT_FAILURE);
	return value;
}
