#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"

struct sendip_headers sendip_headers[] = {
	{'H', IPPROTO_HOPOPTS},		/* h already taken */
	{'F', IPPROTO_FRAGMENT},	/* f already taken */
	{'g', IPPROTO_GRE},
	{'e', IPPROTO_ESP},		/* TBD */
	{'a', IPPROTO_AH},
	{'c', IPPROTO_ICMPV6},
	{'t', IPPROTO_TCP},
	{'u', IPPROTO_UDP},
	{'i', IPPROTO_IPIP},	/* for 4-in-4 tunnels */
	{'6', IPPROTO_IPV6},	/* for 6-in-4 tunnels */
	{'d', IPPROTO_DSTOPTS},
	{'o', IPPROTO_ROUTING},	/* sorry, r and R already taken ...*/
	{'s', IPPROTO_SCTP},
	{'w', IPPROTO_WESP},
	{0, IPPROTO_NONE},
	/* These are placeholders */
	{'n'},		/* ntp */
	{'r'},		/* rip */
	{'R'},		/* ripng */
	/* These are base flags and can't be used for headers:
	 * d f h p v
	 */
};

u_int8_t
header_type(const char hdr_char)
{
	int i;

	for (i=0; sendip_headers[i].opt_char; ++i)
		if (hdr_char == sendip_headers[i].opt_char)
			return sendip_headers[i].ipproto;
	return IPPROTO_NONE;
}

int
outer_header(const char *hdrs, int index, const char *choices)
{
	int i;

	for (i=index-1; i >=0; --i) {
		if (strchr(choices, hdrs[i]))
			return i;
	}
	return -1;
}

int
inner_header(const char *hdrs, int index, const char *choices)
{
	int i;

	for (i=index+1; hdrs[i]; ++i) {
		if (strchr(choices, hdrs[i]))
			return i;
	}
	return -1;
}
