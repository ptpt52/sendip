/* csum.c
 * Computes the standard internet checksum of a set of data (from RFC1071)
 *	ChangeLog since sendip 2.0:
 * 02/12/2001: Moved ipv6_csum into icmp.c as that is where it is used
 * 22/01/2002: Include types.h to make sure u_int*_t defined on Solaris
 */

#define __USE_BSD    /* GLIBC */
#define _DEFAULT_SOURCE  /* LIBC5 */
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include "types.h"

/* Add bytes in network order without requiring aligned 16-bit access.
 * Carry byte parity between vector elements, so an odd block is not padded
 * until the end of the entire message. Fold as we go to bound the sum.
 */
static u_int32_t add_bytes(u_int32_t sum, const unsigned char *bytes,
                          int length, int *odd) {
	while (length-- > 0) {
		sum += (u_int32_t)*bytes++ << (*odd ? 0 : 8);
		sum = (sum & 0xffff) + (sum >> 16);
		*odd = !*odd;
	}
	return sum;
}

/* Return the checksum in the byte order used by packet header fields. */
u_int16_t csum(const void *packet, int packlen) {
	int odd=0;
	u_int32_t sum=add_bytes(0, (const unsigned char *)packet, packlen, &odd);
	return htons((u_int16_t)~sum);
}

/* The caller's vector and lengths are read-only. A zero length terminates it. */
u_int16_t csumv(const void *const packet[], const int packlen[]) {
	u_int32_t sum=0;
	int odd=0;
	for (int i=0; packlen[i]; ++i)
		sum=add_bytes(sum, (const unsigned char *)packet[i], packlen[i], &odd);
	return htons((u_int16_t)~sum);
}
