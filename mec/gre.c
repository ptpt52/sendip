/* gre.c - Generic Routing Encapsulation
 * By Mark Carson
 */

#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"
#include "gre.h"

/* Character that identifies our options
 */
const char opt_char='g';

/* Our initial allocation only includes the non-optional fields. Others
 * are added in response to the appropriate options.
 */
sendip_data *
initialize(void)
{
	sendip_data *ret = calloc(1, sizeof(sendip_data));
	gre_header *gre = malloc(sizeof(gre_header));
	if (!ret || !gre) {
		free(gre);
		free(ret);
		return NULL;
	}
	memset(gre,0,sizeof(gre_header));
	ret->alloc_len = sizeof(gre_header);
	ret->data = gre;
	ret->modified=0;
	return ret;
}

/* There's an unfortunate collision between the way GRE lays out
 * fields and the way sendip handles space allocation. Since sendip
 * gives no space allocation other than the actual space in the
 * packet (and a single word of "flags"), everything must be
 * more or less in place at the end of processing each option,
 * as there is no way of telling whether this is the last option
 * or not. But the layout of a GRE header depends on which
 * options are included. Hence, we have to juggle fields each
 * time.
 *
 * I could simplify all this by adding a provision for auxiliary
 * allocated space in sendip. During option processing, all the
 * optional fields would be stuck into the auxiliary space; only
 * in finalize would they be laid out into the packet. This is
 * how the Linux kernel handles GRE, as an example.
 *
 * I may still do that, but for now I will try doing everything
 * in place. Wish me luck!
 */
int
gre_where(u_int16_t flags, u_int16_t addflag)
{
	int where;

	/* Let's be as stupidly explicit as possible */
	/* Order of options:
	 *
	 * 0: checksum : offset
	 * 1: key
	 * 2: sequence
	 * 3: routing
	 */
	where = 0;
	switch (addflag) {
	case GRE_CSUM:
		break;
	case GRE_KEY:
		if (flags&GRE_CSUM)
			++where;
		break;
	case GRE_SEQ:
		if (flags&GRE_CSUM)
			++where;
		if (flags&GRE_KEY)
			++where;
		break;
	case GRE_ROUTING:
		/* Routing always requires checksum/offset field
		 * to be allocated
		 */
		/*if (flags&GRE_CSUM)*/
		++where;
		if (flags&GRE_KEY)
			++where;
		if (flags&GRE_SEQ)
			++where;
		break;
	}
	return where;
}

/* Physical allocation is independent of intentionally malformed wire flags.
 * Keep its flag mask in the unused high half of pack->modified.
 */
static u_int16_t allocated_flags(const sendip_data *pack) {
	return pack->modified>>16;
}

gre_header *gre_resize(sendip_data *pack, u_int16_t flags, u_int16_t addflag) {
	(void)flags;
	u_int16_t oldflags=allocated_flags(pack), newflags=oldflags|addflag;
	const u_int16_t fields[]={GRE_CSUM, GRE_KEY, GRE_SEQ, GRE_ROUTING};
	if (newflags&GRE_ROUTING) newflags |= GRE_CSUM;
	if (newflags==oldflags) return pack->data;
	size_t size=sizeof(gre_header);
	for (size_t i=0; i<sizeof(fields)/sizeof(fields[0]); ++i)
		if (newflags&fields[i]) size+=sizeof(u_int32_t);
	gre_header *replacement=calloc(1, size);
	if (!replacement) return NULL;
	gre_header *old=pack->data;
	memcpy(replacement, old, sizeof(*old));
	for (size_t i=0; i<sizeof(fields)/sizeof(fields[0]); ++i)
		if (oldflags&fields[i])
			replacement->gre_info.thirtytwo[gre_where(newflags, fields[i])]=
			    old->gre_info.thirtytwo[gre_where(oldflags, fields[i])];
	free(old);
	pack->data=replacement;
	pack->alloc_len=size;
	pack->modified=(pack->modified&0xffff)|((unsigned int)newflags<<16);
	return replacement;
}

bool
do_opt(char *opt, char *arg, sendip_data *pack)
{
	u_int32_t parsed;
	gre_header *gre = (gre_header *)pack->data;
	unsigned long svalue;

	switch(opt[1]) {
	case 'c':
		if (gre->gre_flag&GRE_CSUM) {
			usage_error("Already have a checksum specified\n");
			return FALSE;
		}
		gre = gre_resize(pack, gre->gre_flag, GRE_CSUM);
		if (!gre) return FALSE;
		gre->gre_flag |= GRE_CSUM;
		/* There's only one place for the checksum field to go! */
		gre->gre_info.sixteen[GRE_CHECKSUM_FIELD] =
		    htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= GRE_MOD_CHECKSUM;
		break;
	case 'C':
		if (gre->gre_flag&GRE_CSUM) {
			usage_error("Already have a checksum specified\n");
			return FALSE;
		}
		gre = gre_resize(pack, gre->gre_flag, GRE_CSUM);
		if (!gre) return FALSE;
		gre->gre_flag |= GRE_CSUM;
		/* Actual checksum will be computed in finalize */
		/* Note we do *not* set the pack flag here, so we will
		 * know below that we need to compute a value.
		 */
		break;
	case 'r':
		gre = gre_resize(pack, gre->gre_flag, GRE_ROUTING);
		if (!gre) return FALSE;
		gre->gre_info.thirtytwo[gre_where(allocated_flags(pack), GRE_ROUTING)] =
		    htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));
		gre->gre_flag |= GRE_ROUTING;
		pack->modified |= GRE_MOD_ROUTING;
		break;
	case 'k':
		gre = gre_resize(pack, gre->gre_flag, GRE_KEY);
		if (!gre) return FALSE;
		gre->gre_info.thirtytwo[gre_where(allocated_flags(pack), GRE_KEY)] =
		    htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));
		gre->gre_flag |= GRE_KEY;
		pack->modified |= GRE_MOD_KEY;
		break;
	case 's':
		gre = gre_resize(pack, gre->gre_flag, GRE_SEQ);
		if (!gre) return FALSE;
		gre->gre_info.thirtytwo[gre_where(allocated_flags(pack), GRE_SEQ)] =
		    htonl((u_int32_t)strtoul(arg, (char **)NULL, 0));
		gre->gre_flag |= GRE_SEQ;
		pack->modified |= GRE_MOD_SEQUENCE;
		break;
	case 'S':
		/* Logically, this only makes sense if routing info
		 * is supplied, but of course we won't enforce this.
		 */
		gre->gre_flag |= GRE_STRICT;
		pack->modified |= GRE_MOD_STRICT;
		break;
	case 'e':
		if (!uintargument(arg, GRE_MAX_REC, &svalue)) {
			usage_error("Too big a recursion limit\n");
			return FALSE;
		}
		gre->gre_flag &= ~GRE_REC;
		gre->gre_flag |= (GRE_REC&htons(svalue<<GRE_REC_SHIFT));
		pack->modified |= GRE_MOD_RECURSION;
		break;
	case 'v':
		if (!uintargument(arg, GRE_MAX_VERSION, &svalue)) {
			usage_error("Too big a version number\n");
			return FALSE;
		}
		gre->gre_flag &= ~GRE_VERSION;
		gre->gre_flag |= (GRE_VERSION&htons(svalue));
		pack->modified |= GRE_MOD_VERSION;
		break;
	case 'p':
		if (!integerargument_checked(arg, 2, &parsed)) return FALSE;
		gre->gre_protocol = parsed;
		pack->modified |= GRE_MOD_PROTOCOL;
		break;
	case 'o':
		/* This is tricky - in order to have an offset field,
		 * we have to have a checksum field. But we don't mark
		 * the latter as set, so we can properly check setting
		 * of it later. This does mean we could end up
		 * constructing a bad header (checksum/offset fields
		 * allocated, but no flag set). Of course, the purpose
		 * of this code is to be able to construct bad headers.
		 */
		gre = gre_resize(pack, gre->gre_flag, GRE_CSUM);
		if (!gre) return FALSE;
		/* There's only one place for the offset field to go! */
		gre->gre_info.sixteen[GRE_OFFSET_FIELD] =
		    htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= GRE_MOD_OFFSET;
		break;
	}
	return TRUE;

}

bool
finalize(char *hdrs, sendip_data *headers[], int index, sendip_data *data,
         sendip_data *pack)
{
	gre_header *gre = (gre_header *)pack->data;

	/* Note that GRE uses the Ethernet protocol value and not the
	 * IP one! Because it's "generic," you see.
	 */
	if (!(pack->modified&GRE_MOD_PROTOCOL)) {
		/* Protocol Type describes the immediate payload, not a deeper IP. */
		switch (hdrs[index+1]) {
		case 'i':
			gre->gre_protocol = htons(ETH_P_IP);
			break;
		case '6':
			gre->gre_protocol = htons(ETH_P_IPV6);
			break;
		default:
			usage_error("Specify the GRE payload protocol when the next header is not IP\n");
			return FALSE;
		}
	}
	if ((gre->gre_flag&GRE_CSUM) && !(pack->modified&GRE_MOD_CHECKSUM)) {
		/* We need to compute the checksum */
		const void *vec[3];
		int lens[3];

		vec[0] = pack->data;
		lens[0] = pack->alloc_len;
		vec[1] = data->data;
		lens[1] = data->alloc_len;
		vec[2] = NULL;
		lens[2] = 0;
		gre->gre_info.sixteen[GRE_CHECKSUM_FIELD] = 0;
		gre->gre_info.sixteen[GRE_CHECKSUM_FIELD] = csumv(vec, lens);
	}
	return TRUE;

}

int num_opts(void) {
	return sizeof(gre_opts)/sizeof(sendip_option);
}
sendip_option *get_opts(void) {
	return gre_opts;
}
char get_optchar(void) {
	return opt_char;
}

/* Keep bare-r generation in range without weakening explicit validation. */
u_int32_t randomize_arg(const char *option, u_int32_t value) {
	switch (option[1]) {
	case 'e': return value & GRE_MAX_REC;
	case 'v': return value & GRE_MAX_VERSION;
	default: return value;
	}
}
