#ifndef _SENDIP_MODULE_H
#define _SENDIP_MODULE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>   // for fprintf

#include "types.h"

/* Options
 */
typedef struct {
	const char *optname;
	const bool arg;
	const char *description;
	const char *def;
} sendip_option;

/* Data
 */
typedef struct {
	void *data;
	int alloc_len;
	unsigned int modified;
	unsigned int route_daddr;
	void *private;		/* Owned by the module; released by optional destroy(). */
} sendip_data;

/* Wire layout shared by IPv6 transport checksum calculations. */
struct ipv6_pseudo_hdr {
	struct in6_addr source;
	struct in6_addr destination;
	u_int32_t ulp_length;
	u_int32_t zero:24,
	          nexthdr:8;
};

/* Prototypes */
#ifndef _SENDIP_MAIN
sendip_data *initialize(void);
/* Optional: release module-owned state; do not free pack or pack->data. */
void destroy(sendip_data *pack);
bool do_opt(char *optstring, char *optarg, sendip_data *pack);
bool set_addr(char *hostname, sendip_data *pack);
/* Optional: pad before assembly using the nearest enclosing IP type ('i'/'6'). */
bool do_pad_ip(char outer_ip, sendip_data *pack);
bool finalize(char *hdrs, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack);
int num_opts(void);
sendip_option *get_opts(void);
char get_optchar(void);
/* Optional: constrain the legacy bare-r value to a field's valid range. */
u_int32_t randomize_arg(const char *option, u_int32_t value);

#endif  /* _SENDIP_MAIN */

#define usage_error(x) fprintf(stderr,x)

extern u_int16_t csum(const void *packet, int packlen);
/* Decode in place; return the byte count or -1 for invalid input. */
extern int compact_string(char *data_out);
/*@@ added */
#define MAXRAND	8192	/* maximum length of random data */
u_int8_t * randombytes(int length);
int stringargument(const char *input, char **output);
bool uintargument(const char *input, unsigned long maximum, unsigned long *value);
u_int32_t integerargument(const char *input, int length);
u_int32_t hostintegerargument(const char *input, int length);
in_addr_t cidrargument(const char *input, char *slashpoint, int length);
in_addr_t ipv4argument(const char *input, int length);
bool resolve_address(const char *hostname, int family,
                     struct sockaddr_storage *address, socklen_t *length);
char *fileargument(const char *input);
int fa_init(void);
void fa_close(void);

const char * proto_to_name(u_int8_t proto, int nolookup);
u_int8_t name_to_proto(char *s);
bool protocolargument(const char *input, u_int8_t *value);
u_int8_t header_type(const char hdr_char);
/* Resolve a header at index; ICMP follows its nearest enclosing IP version. */
u_int8_t header_type_at(const char *hdrs, int index);
int outer_header(const char *hdrs, int index, const char *choices);
int inner_header(const char *hdrs, int index, const char *choices);
bool ipv6_pseudo_header(const char *hdrs, sendip_data *headers[],
                       int ip_index, int transport_index, int length,
                       u_int8_t protocol, struct ipv6_pseudo_hdr *pseudo);

/* Read a well-formed Jumbo Payload option from the immediate Hop-by-Hop header.
 * That header may not have been finalized yet; use its allocated wire extent.
 */
bool ipv6_jumbo_length(const char *hdrs, sendip_data *headers[], int ip_index,
                       u_int32_t *length);

extern u_int16_t csumv(const void *const packet[], const int packlen[]);
/*@@ end added */

#endif  /* _SENDIP_MODULE_H */
