/* sctp.h - stream control transmission protocol
 *
 * stream control transmission protocol (RFC 4960)
 *
 * Many of the structures and definitions here are taken/adapted from
 * the Linux kernel sctp implementation. Of course, this implementation
 * uses entirely different code (other than the crc32 calculation).
 */
#ifndef _SENDIP_SCTP_H
#define _SENDIP_SCTP_H

#include <asm/byteorder.h>

/*
 * Overall header
 */
typedef struct sctp {
	u_int16_t	source;
	u_int16_t	dest;
	u_int32_t	vtag;
	u_int32_t	checksum;
} sctp_header;

/*
 * Chunk header
 */
typedef struct sctp_chunk {
	u_int8_t type;
	u_int8_t flags;
	u_int16_t length;
} sctp_chunk_header;

/* Chunk types - taken from the Linux kernel sctp header: */

typedef enum {
	SCTP_CID_DATA                   = 0,
	SCTP_CID_INIT                   = 1,
	SCTP_CID_INIT_ACK               = 2,
	SCTP_CID_SACK                   = 3,
	SCTP_CID_HEARTBEAT              = 4,
	SCTP_CID_HEARTBEAT_ACK          = 5,
	SCTP_CID_ABORT                  = 6,
	SCTP_CID_SHUTDOWN               = 7,
	SCTP_CID_SHUTDOWN_ACK           = 8,
	SCTP_CID_ERROR                  = 9,
	SCTP_CID_COOKIE_ECHO            = 10,
	SCTP_CID_COOKIE_ACK             = 11,
	SCTP_CID_ECN_ECNE               = 12,
	SCTP_CID_ECN_CWR                = 13,
	SCTP_CID_SHUTDOWN_COMPLETE      = 14,

	/* AUTH Extension Section 4.1 */
	SCTP_CID_AUTH                   = 0x0F,

	/* PR-SCTP Sec 3.2 */
	SCTP_CID_FWD_TSN                = 0xC0,

	/* Use hex, as defined in ADDIP sec. 3.1 */
	SCTP_CID_ASCONF                 = 0xC1,
	SCTP_CID_ASCONF_ACK             = 0x80,
} sctp_cid_t; /* enum */

/* Section 3.2
 * Chunk Types are encoded such that the highest-order two bits specify
 * the action that must be taken if the processing endpoint does not
 * recognize the Chunk Type.
 */
typedef enum {
        SCTP_CID_ACTION_DISCARD     = 0x00,
	SCTP_CID_ACTION_DISCARD_ERR = 0x40,
	SCTP_CID_ACTION_SKIP        = 0x80,
	SCTP_CID_ACTION_SKIP_ERR    = 0xc0,
} sctp_cid_action_t;

enum { SCTP_CID_ACTION_MASK = 0xc0, };

/* Init header */
typedef struct sctp_inithdr {
	u_int32_t init_tag;
	u_int32_t a_rwnd; /* advertised receiver window credit */
	u_int16_t num_outbound_streams;
	u_int16_t num_inbound_streams;
	u_int32_t initial_tsn;
	u_int8_t  params[0];
} sctp_inithdr_t;

/* Data header */
typedef struct sctp_datahdr {
	u_int32_t tsn;
	u_int16_t stream;
	u_int16_t ssn;
	u_int32_t ppid;
	u_int8_t  payload[0];
} sctp_datahdr_t;

/* TLV parameter types */
typedef enum {

	/* RFC 2960 Section 3.3.5 */
	SCTP_PARAM_HEARTBEAT_INFO               = __constant_htons(1),
	/* RFC 2960 Section 3.3.2.1 */
	SCTP_PARAM_IPV4_ADDRESS                 = __constant_htons(5),
	SCTP_PARAM_IPV6_ADDRESS                 = __constant_htons(6),
	SCTP_PARAM_STATE_COOKIE                 = __constant_htons(7),
	SCTP_PARAM_UNRECOGNIZED_PARAMETERS      = __constant_htons(8),
	SCTP_PARAM_COOKIE_PRESERVATIVE          = __constant_htons(9),
	SCTP_PARAM_HOST_NAME_ADDRESS            = __constant_htons(11),
	SCTP_PARAM_SUPPORTED_ADDRESS_TYPES      = __constant_htons(12),
	SCTP_PARAM_ECN_CAPABLE                  = __constant_htons(0x8000),

	/* AUTH Extension Section 3 */
	SCTP_PARAM_RANDOM                       = __constant_htons(0x8002),
	SCTP_PARAM_CHUNKS                       = __constant_htons(0x8003),
	SCTP_PARAM_HMAC_ALGO                    = __constant_htons(0x8004),

	/* Add-IP: Supported Extensions, Section 4.2 */
	SCTP_PARAM_SUPPORTED_EXT        = __constant_htons(0x8008),

	/* PR-SCTP Sec 3.1 */
	SCTP_PARAM_FWD_TSN_SUPPORT      = __constant_htons(0xc000),

	/* Add-IP Extension. Section 3.2 */
	SCTP_PARAM_ADD_IP               = __constant_htons(0xc001),
	SCTP_PARAM_DEL_IP               = __constant_htons(0xc002),
	SCTP_PARAM_ERR_CAUSE            = __constant_htons(0xc003),
	SCTP_PARAM_SET_PRIMARY          = __constant_htons(0xc004),
	SCTP_PARAM_SUCCESS_REPORT       = __constant_htons(0xc005),
	SCTP_PARAM_ADAPTATION_LAYER_IND = __constant_htons(0xc006),

} sctp_param_t; /* enum */

/* The generic Linux structure just includes the type and length.
 * Data fields are in the type-specific structures.
 */
typedef struct sctp_paramhdr {
	u_int16_t	type;
	u_int16_t	length;
} sctp_paramhdr_t;

/* Individual TLV parameter types. Note that only a handful of these
 * are currently implemented in sendip!
 */

/* Section 3.3.2.1. IPv4 Address Parameter (5) */
typedef struct sctp_ipv4addr_param {
	sctp_paramhdr_t param_hdr;
	struct in_addr addr;
} sctp_ipv4addr_param_t;

/* Section 3.3.2.1. IPv6 Address Parameter (6) */
typedef struct sctp_ipv6addr_param {
	sctp_paramhdr_t param_hdr;
	struct in6_addr addr;
} sctp_ipv6addr_param_t;

/* Section 3.3.2.1 Cookie Preservative (9) */
typedef struct sctp_cookie_preserve_param {
	sctp_paramhdr_t param_hdr;
	u_int32_t lifespan_increment;
} sctp_cookie_preserve_param_t;

/* Section 3.3.2.1 Host Name Address (11) */
typedef struct sctp_hostname_param {
	sctp_paramhdr_t param_hdr;
	uint8_t hostname[0];
} sctp_hostname_param_t;

/* Section 3.3.2.1 Supported Address Types (12) */
typedef struct sctp_supported_addrs_param {
	sctp_paramhdr_t param_hdr;
	u_int16_t types[0];
} sctp_supported_addrs_param_t;

/* Appendix A. ECN Capable (32768) */
typedef struct sctp_ecn_capable_param {
	sctp_paramhdr_t param_hdr;
} sctp_ecn_capable_param_t;

/* ADDIP Section 3.2.6 Adaptation Layer Indication */
typedef struct sctp_adaptation_ind_param {
	struct sctp_paramhdr param_hdr;
	u_int32_t adaptation_ind;
} sctp_adaptation_ind_param_t;

/* ADDIP Section 4.2.7 Supported Extensions Parameter */
typedef struct sctp_supported_ext_param {
	struct sctp_paramhdr param_hdr;
	u_int8_t chunks[0];
} sctp_supported_ext_param_t;

/* AUTH Section 3.1 Random */
typedef struct sctp_random_param {
	sctp_paramhdr_t param_hdr;
	u_int8_t random_val[0];
} sctp_random_param_t;

/* AUTH Section 3.2 Chunk List */
typedef struct sctp_chunks_param {
	sctp_paramhdr_t param_hdr;
	u_int8_t chunks[0];
} sctp_chunks_param_t;


/* AUTH Section 3.3 HMAC Algorithm */
typedef struct sctp_hmac_algo_param {
	sctp_paramhdr_t param_hdr;
	u_int16_t hmac_ids[0];
} sctp_hmac_algo_param_t;

/* RFC 2960.  Section 3.3.3 Initiation Acknowledgement (INIT ACK) (2):
 *   The INIT ACK chunk is used to acknowledge the initiation of an SCTP
 *   association.
 */

/* Section 3.3.3.1 State Cookie (7) */
typedef struct sctp_cookie_param {
	sctp_paramhdr_t p;
	u_int8_t body[0];
} sctp_cookie_param_t;


/* Section 3.3.3.1 Unrecognized Parameters (8) */
typedef struct sctp_unrecognized_param {
	sctp_paramhdr_t param_hdr;
	sctp_paramhdr_t unrecognized;
} sctp_unrecognized_param_t;


/* Added for support of sctp demo program */
/* Forward TSN supported (0xC000, 49152) - mere presence seems to imply
 * capability, just like with ECN, so there are no other fields.
 */
typedef struct sctp_forward_tsn_param {
	sctp_paramhdr_t param_hdr;
} sctp_forward_tsn_param_t;


#define SCTP_MOD_SOURCE		(1)
#define SCTP_MOD_DEST		(1<<1)
#define SCTP_MOD_VTAG		(1<<2)
#define SCTP_MOD_CHECKSUM	(1<<3)
/* Don't bother noting setting of chunk fields with flags */

/* Options
 */
sendip_option sctp_opts[] = {
	{"s",1,"SCTP source port","0"},
	{"d",1,"SCTP dest port","0"},
	{"v",1,"SCTP vtag","0 (if init chunk) 1 (if other); may be specified as number, string, or rN for N (should be 4) random bytes"},
	{"c",1,"SCTP CRC checksum","Correct"},
	{"T",1,"SCTP chunk type","0 (i.e., a data chunk)\n"\
"Note: multiple chunks may be included. Each chunk type begins a new\n"\
"chunk; subsequent chunk-related fields are applied to that chunk."},
	{"F",1,"SCTP chunk flags","0"},
	{"L",1,"SCTP chunk length","Correct"},
	{"D",1,"SCTP chunk data (hex, octal, decimal, literal, "
"zN for N zero bytes or rN for N random bytes).", "0"},
	{"I",1,"SCTP INIT chunk", "1.0x1000.1.1.1\n"\
"Creates a complete INIT chunk with the specified initiate tag, receiver\n"\
"window credit, number of outbound and inbound streams, and initial TSN,\n"\
"in that order. Each field may be specified as number, string, or rN for N\n"\
"(should be 2 or 4) random bytes. Other variable parameters may be appended\n"\
"to this chunk."},
	{"4",1,"SCTP IPv4 address TLV", "none"},
	{"6",1,"SCTP IPv6 address TLV", "none"},
	{"C",1,"SCTP cookie preservative TLV", "none"},
	{"H",1,"SCTP host name address TLV", "none"},
	{"A",1,"SCTP supported address types TLV", "none"},
	{"E",0,"SCTP ECN capable (boolean)", "(false)"},
	{"W",0,"SCTP forward TSN supported (boolean)", "(false)"},
	{"Y",1,"SCTP adaptation layer indication parameter", "none"},
};

#endif  /* _SENDIP_SCTP_H */
