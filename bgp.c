/*----------------------------------------------------------------------------
 * bgp.c   - bgp module for SendIP
 *
 * Copyright (C) David Ball for Project Purple, August 2001
 *----------------------------------------------------------------------------
 */

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "sendip_module.h"


/*
 * Roughly stolen from arpa/nameser.h
 */
#define GETSHORT(ptr) ((                              \
    ((u_int16_t)((u_int8_t *)(ptr))[0] << 8) |             \
    ((u_int16_t)((u_int8_t *)(ptr))[1])                    \
))

#define GETLONG(ptr) ((                               \
    ((u_int32_t)((u_int8_t *)(ptr))[0] << 24) |            \
    ((u_int32_t)((u_int8_t *)(ptr))[1] << 16) |            \
    ((u_int32_t)((u_int8_t *)(ptr))[2] << 8)  |            \
    ((u_int32_t)((u_int8_t *)(ptr))[3])                    \
))

#define PUTSHORT(ptr, s) {                                 \
    u_int16_t v = (u_int16_t)(s);                   \
    *((u_int8_t *)(ptr)) = v >> 8;                         \
    *(((u_int8_t *)(ptr)) + 1) = v;                        \
}

#define PUTLONG(ptr, l) {                                  \
    u_int32_t v = (u_int32_t)(l);                    \
    *((u_int8_t *)(ptr)) = v >> 24;                        \
    *(((u_int8_t *)(ptr)) + 1) = v >> 16;                  \
    *(((u_int8_t *)(ptr)) + 2) = v >> 8;                   \
    *(((u_int8_t *)(ptr)) + 3) = v;                        \
}


/*
 * Defines for which parts have been modified
 */
const u_int32_t BGP_MOD_LENGTH =   0x00000001;
const u_int32_t BGP_MOD_OPT_LEN =  0x00000002;
const u_int32_t BGP_MOD_WDR_LEN =  0x00000004;
const u_int32_t BGP_MOD_ATTR_LEN = 0x00000008;


/*
 * Parts of BGP messages
 */
typedef enum {
	BGP_HEADER,
	BGP_OPEN,
	BGP_OPEN_OPT,
	BGP_UPDATE_WDR_LEN,
	BGP_UPDATE_WDR,
	BGP_UPDATE_ATTR_LEN,
	BGP_UPDATE_ATTR,
	BGP_UPDATE_NLRI,
	BGP_NOTFN
} bgp_msg_part;


/*
 * Options
 */
sendip_option bgp_opts[] = {
	{	"m", TRUE, "BGP Marker field (format is <hex byte>:<hex byte>:...)",
		"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF"
	},
	{ "l", TRUE, "Packet length", "Correct" },
	{	"t", TRUE, "Message Type (1 OPEN, 2 UPDATE, 3 NOTIFICATION, 4 "
		"KEEPALIVE)",
		"4 (KEEPALIVE)"
	},
	{	"o", TRUE, "Open message.  Format is <version>:<AS number>:"
		"<Hold time>:<BGP Identifier>:<Options length>",
		"4:1:90:127.0.0.1:Correct (Any parameter can be omitted to get "
		"the default)"
	},
	{	"oo", TRUE, "Optional OPEN parameter.  Format is <Type>:<Length>:"
		"<Value> - value is in hex bytes separated by :s",
		"None, though length may be omitted to get correct value"
	},
	{ "ul", TRUE, "Withdrawn routes length", "Correct" },
	{	"uw", TRUE, "Withdrawn route.  Format is x.x.x.x/n:<bytes "
		"for prefix>",
		"Bytes field may be omitted to use the correct number"
	},
	{ "us", TRUE, "Attributes length", "Correct" },
	{	"ua", TRUE, "Attribute.  Format is <flags>:<type>:"
		"<length length (1 or 2):<length>:<data>",
		"The length fields may be omitted to use the correct value"
	},
	{ "un", TRUE, "NLRI Prefix.  Format is as for -buw", "As for -buw" },
	{	"n", TRUE, "Notification.  Format is <code>:<subcode>:<data>",
		"Data may be omitted for no data"
	},
};

/*
 * Option char
 */
const char bgp_opt_char = 'b';


/* A BGP message length is a 16-bit wire field. */
#define BGP_BUFLEN 65535U

typedef struct {
	bgp_msg_part prev_part;
	u_int8_t *len_ptr;
	u_int8_t *opt_len_ptr;
	u_int8_t *wdr_len_ptr;
	u_int8_t *attr_len_ptr;
} bgp_state;

void destroy(sendip_data *pack) {
	free(pack->private);
	pack->private=NULL;
}


sendip_data *initialize (void)
{
	sendip_data *data = NULL;
	u_int8_t    *ptr;
	bgp_state *state;

	data = malloc(sizeof(sendip_data));

	if (data != NULL) {
		memset(data, 0, sizeof(sendip_data));
		data->data = malloc(BGP_BUFLEN);
		if (data->data == NULL) {
			free(data);
			data = NULL;
		}
	}

	if (data != NULL) {
		data->private=calloc(1, sizeof(bgp_state));
		if (!data->private) {
			free(data->data);
			free(data);
			return NULL;
		}
		state=data->private;
		memset(data->data, 0, BGP_BUFLEN);
		ptr = data->data;

		memset(data->data, 0xFF, 16);
		ptr += 16;
		state->len_ptr = ptr;
		PUTSHORT(ptr, 19);
		ptr += 2;
		*ptr++ = 4;

		data->alloc_len = ptr - (u_int8_t *)data->data;
		state->prev_part = BGP_HEADER;
	}
	return (data);
}


/* Return a byte count, or -1 when a token or delimiter is invalid. */
static int bgp_parse_bytes(u_int8_t *buf, char *arg, char **new_arg,
                           u_int32_t limit, int base, char separator, char stopc) {
	u_int32_t count=0;
	char *cursor=arg;
	while (*cursor && *cursor!=stopc && count<limit) {
		char *end;
		if (!(base==16 ? isxdigit((unsigned char)*cursor) :
		                isdigit((unsigned char)*cursor))) goto invalid;
		errno=0;
		unsigned long value=strtoul(cursor, &end, base);
		if (errno || end==cursor || value>UINT8_MAX ||
		    (*end && *end!=separator && *end!=stopc)) goto invalid;
		buf[count++]=value;
		cursor=end;
		if (*end==separator) {
			if (count==limit) break; /* Preserve excess input for the caller. */
			cursor=end+1;
			if (!*cursor || *cursor==stopc) goto invalid;
		}
	}
	if (new_arg) *new_arg=cursor;
	return count;
invalid:
	if (new_arg) *new_arg=cursor;
	usage_error("Malformed BGP byte string\n");
	return -1;
}

/* An omitted Identifier retains the OPEN default; a supplied one is IPv4. */
static bool bgp_parse_identifier(u_int8_t *buf, char *arg, char **end) {
	int count=bgp_parse_bytes(buf, arg, end, 4, 10, '.', ':');
	if (count<0) return FALSE;
	if (!count) {
		PUTLONG(buf, 0x7F000001);
	} else if (count!=4 || (**end && **end!=':')) {
		usage_error("BGP Identifier must contain four IPv4 octets\n");
		return FALSE;
	}
	return TRUE;
}

/* Parse decimal wire bytes without silently skipping malformed tokens. */
static bool bgp_decimal_byte(char *input, char **end, u_int8_t *value) {
	if (!isdigit((unsigned char)*input)) return FALSE;
	errno=0;
	unsigned long parsed=strtoul(input, end, 10);
	if (errno || *end==input || parsed>UINT8_MAX) return FALSE;
	*value=parsed;
	return TRUE;
}

/* Keep the historical narrowing to each wire field, but require the entire
 * argument to be a valid number rather than silently treating bad text as 0.
 */
static bool bgp_scalar_argument(const char *input, int base,
                                unsigned long *value) {
	char *end;

	if (!input || !value) return FALSE;
	errno=0;
	unsigned long parsed=strtoul(input, &end, base);
	if (errno || end==input || *end) {
		usage_error("Malformed BGP numeric field\n");
		return FALSE;
	}
	*value=parsed;
	return TRUE;
}

/* Parse one colon-delimited numeric field. Optional empty fields retain
 * their documented default; nonempty fields must end at ':' or '\0'.
 */
static bool bgp_scalar_field(char **cursor, int base, bool optional,
                             unsigned long fallback, unsigned long *value,
                             bool *specified, bool *separator) {
	char *input=*cursor;
	char *end;

	if (!*input || *input==':') {
		if (!optional) {
			usage_error("Missing BGP numeric field\n");
			return FALSE;
		}
		*value=fallback;
		*specified=FALSE;
		*separator=*input==':';
		*cursor=*separator ? input+1 : input;
		return TRUE;
	}
	errno=0;
	unsigned long parsed=strtoul(input, &end, base);
	if (errno || end==input || (*end && *end!=':')) {
		usage_error("Malformed BGP numeric field\n");
		return FALSE;
	}
	*value=parsed;
	*specified=TRUE;
	*separator=*end==':';
	*cursor=*separator ? end+1 : end;
	return TRUE;
}

static int bgp_parse_nlri(u_int8_t *buf, char *arg) {
	u_int8_t address[4], prefix, explicit_bytes;
	char *end;
	for (int i=0; i<4; ++i) {
		if (!bgp_decimal_byte(arg, &end, &address[i]) || *end!=(i<3 ? '.' : '/'))
			return -1;
		arg=end+1;
	}
	if (!bgp_decimal_byte(arg, &end, &prefix)) return -1;
	unsigned int bytes=(prefix+7U)/8;
	if (*end==':') {
		arg=end+1;
		if (*arg) {
			if (!bgp_decimal_byte(arg, &end, &explicit_bytes) || *end) return -1;
			bytes=explicit_bytes;
		}
	} else if (*end) return -1;

	/* Retain explicit prefix-length/byte-count overrides for malformed
	 * packet tests, but serialize only the requested extent deterministically.
	 */
	buf[0]=prefix;
	memset(buf+1, 0, bytes);
	memcpy(buf+1, address, bytes<sizeof(address) ? bytes : sizeof(address));
	return bytes+1;
}

bool do_opt (char        *optstring,
             char        *optarg,
             sendip_data *pack)
{
	u_int8_t *ptr;
	u_int8_t *rem_ptr = NULL;
	char     *arg_ptr = NULL;
	char     *new_arg_ptr = NULL;
	bool	  rc = TRUE;
	bool	  len_mod = FALSE;
	u_int8_t  bytes;
	int count;
	bgp_state *state=pack->private;
	u_int8_t nlri[256]; /* One prefix-length byte and up to 255 data bytes. */
	u_int8_t marker[16];
	u_int8_t open[10];
	u_int8_t parameter[2+UINT8_MAX];
	int nlri_length=0;
	size_t needed=0;
	unsigned long scalar;
	bool specified, separator;

	if (pack->alloc_len<0 || (unsigned int)pack->alloc_len>BGP_BUFLEN) {
		usage_error("BGP message is too large\n");
		return FALSE;
	}
	/* A short NLRI argument can expand to 256 bytes. Parse it separately
	 * and include any length fields inserted by this state transition.
	 */
	if (optstring[1]=='u' && (optstring[2]=='w' || optstring[2]=='n')) {
		nlri_length=bgp_parse_nlri(nlri, optarg);
		if (nlri_length<0) {
			usage_error("Malformed BGP IPv4 prefix\n");
			return FALSE;
		}
		needed=nlri_length;
		if (state->prev_part==BGP_HEADER)
			needed+=optstring[2]=='w' ? 2 : 4;
		else if (optstring[2]=='n' && (state->prev_part==BGP_UPDATE_WDR_LEN ||
		                             state->prev_part==BGP_UPDATE_WDR))
			needed+=2;
	} else if (optstring[1]=='o' || optstring[1]=='u' || optstring[1]=='n') {
		/* Each parsed value byte consumes input; allow for fixed fields. */
		needed=strnlen(optarg, BGP_BUFLEN)+16;
	}
	if (needed>BGP_BUFLEN-(unsigned int)pack->alloc_len) {
		usage_error("BGP message is too large\n");
		return FALSE;
	}
	ptr=(u_int8_t *)pack->data+pack->alloc_len;

	switch (optstring[1]) {
	case 'm':
		rem_ptr = (u_int8_t *)pack->data;
		count=bgp_parse_bytes(marker, optarg, &new_arg_ptr, 16, 16, ':', '\0');
		if (count<0) return FALSE;
		if (*new_arg_ptr) { usage_error("Too many BGP marker bytes\n"); return FALSE; }
		memcpy(rem_ptr, marker, count);
		break;
	case 'l':
		if (!bgp_scalar_argument(optarg, 10, &scalar)) return FALSE;
		rem_ptr = (u_int8_t *)pack->data + 16;
		PUTSHORT(rem_ptr, (u_int16_t)scalar);
		pack->modified |= BGP_MOD_LENGTH;
		break;
	case 't':
		if (!bgp_scalar_argument(optarg, 0, &scalar)) return FALSE;
		rem_ptr = (u_int8_t *)pack->data + 18;
		*rem_ptr = (u_int8_t)scalar;
		break;
	case 'o':
		switch (optstring[2]) {
		case '\0':
			if (state->prev_part != BGP_HEADER) {
				usage_error("Open message must come immediately "
				            "after header\n");
				rc = FALSE;
			} else {
				u_int8_t *open_ptr=open;
				arg_ptr = optarg;
				if (!bgp_scalar_field(&arg_ptr, 10, TRUE, 4, &scalar,
				                      &specified, &separator)) return FALSE;
				*open_ptr++=(u_int8_t)scalar;
				if (!bgp_scalar_field(&arg_ptr, 10, TRUE, 1, &scalar,
				                      &specified, &separator)) return FALSE;
				PUTSHORT(open_ptr, (u_int16_t)scalar);
				open_ptr+=2;
				if (!bgp_scalar_field(&arg_ptr, 10, TRUE, 90, &scalar,
				                      &specified, &separator)) return FALSE;
				PUTSHORT(open_ptr, (u_int16_t)scalar);
				open_ptr+=2;
				if (!bgp_parse_identifier(open_ptr, arg_ptr, &new_arg_ptr)) return FALSE;
				open_ptr+=4;
				arg_ptr=new_arg_ptr;
				if (*arg_ptr==':') ++arg_ptr;
				if (!bgp_scalar_field(&arg_ptr, 10, TRUE, 0, &scalar,
				                      &specified, &separator)) return FALSE;
				if (separator || *arg_ptr) {
					usage_error("Too many BGP OPEN fields\n");
					return FALSE;
				}
				*open_ptr=(u_int8_t)scalar;
				memcpy(ptr, open, sizeof(open));
				state->opt_len_ptr = ptr+sizeof(open)-1;
				ptr+=sizeof(open);
				if (specified) pack->modified |= BGP_MOD_OPT_LEN;
				state->prev_part = BGP_OPEN;
			}
			break;

		case 'o':
			if (state->prev_part != BGP_OPEN &&
			        state->prev_part != BGP_OPEN_OPT) {
				usage_error("Open options must occur after open "
				            "message\n");
				rc = FALSE;
			} else {
				arg_ptr = optarg;
				if (!bgp_scalar_field(&arg_ptr, 10, FALSE, 0, &scalar,
				                      &specified, &separator)) return FALSE;
				parameter[0]=(u_int8_t)scalar;
				if (!bgp_scalar_field(&arg_ptr, 10, TRUE, 0, &scalar,
				                      &specified, &separator)) return FALSE;
				parameter[1]=(u_int8_t)scalar;
				len_mod=specified;
				count=bgp_parse_bytes(parameter+2, arg_ptr, &new_arg_ptr,
				                      UINT8_MAX, 16, ':', '\0');
				if (count<0) return FALSE;
				if (*new_arg_ptr) { usage_error("Too many BGP value bytes\n"); return FALSE; }

				if (!len_mod) parameter[1]=count;
				if (!(pack->modified & BGP_MOD_OPT_LEN)) {
					size_t added=(size_t)count+2;
					if (added>UINT8_MAX || *state->opt_len_ptr>UINT8_MAX-added) {
						usage_error("Automatic BGP OPEN option length exceeds one byte\n");
						return FALSE;
					}
				}
				memcpy(ptr, parameter, (size_t)count+2);
				ptr+=count+2;
				if (!(pack->modified & BGP_MOD_OPT_LEN))
					*state->opt_len_ptr+=count+2;
				state->prev_part = BGP_OPEN_OPT;
			}
			break;

		default:
			fprintf(stderr, "Unrecognised BGP OPEN option: %s\n",
			        optstring);
			rc = FALSE;
		}
		break;

	case 'u':
		switch(optstring[2]) {
		case 'l':
			if (state->prev_part != BGP_HEADER) {
				usage_error("Update message must come immediately "
				            "after header\n");
				rc = FALSE;
			} else if (!bgp_scalar_argument(optarg, 10, &scalar)) {
				rc = FALSE;
			} else {
				state->wdr_len_ptr = ptr;
				PUTSHORT(ptr, (u_int16_t)scalar);
				ptr += 2;
				pack->modified |= BGP_MOD_WDR_LEN;
				state->prev_part = BGP_UPDATE_WDR_LEN;
			}
			break;

		case 'w':
			if (state->prev_part == BGP_HEADER) {
				state->wdr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				state->prev_part = BGP_UPDATE_WDR_LEN;
			}

			if (state->prev_part != BGP_UPDATE_WDR &&
			        state->prev_part != BGP_UPDATE_WDR_LEN) {
				usage_error("Unfeasible routes must occur immediately "
				            "after header or -bul\n");
				rc = FALSE;
			} else {
				rem_ptr = ptr;
				memcpy(ptr, nlri, nlri_length);
				ptr+=nlri_length;

				if (!(pack->modified & BGP_MOD_WDR_LEN)) {
					PUTSHORT(state->wdr_len_ptr,
					         GETSHORT(state->wdr_len_ptr) + ptr - rem_ptr);
				}
				state->prev_part = BGP_UPDATE_WDR;
			}
			break;

		case 's':
			if (state->prev_part != BGP_HEADER &&
			        state->prev_part != BGP_UPDATE_WDR_LEN &&
			        state->prev_part != BGP_UPDATE_WDR) {
				usage_error("Path Attributes must come after "
				            "unfeasible routes (if any), "
				            "or after header\n");
				rc = FALSE;
			} else if (!bgp_scalar_argument(optarg, 10, &scalar)) {
				rc = FALSE;
			} else {
				if (state->prev_part == BGP_HEADER) {
					state->wdr_len_ptr = ptr;
					PUTSHORT(ptr, 0);
					ptr += 2;
					state->prev_part = BGP_UPDATE_WDR_LEN;
				}
				state->attr_len_ptr = ptr;
				PUTSHORT(ptr, (u_int16_t)scalar);
				ptr += 2;
				pack->modified |= BGP_MOD_ATTR_LEN;
				state->prev_part = BGP_UPDATE_ATTR_LEN;
			}
			break;

		case 'a':
			if (state->prev_part == BGP_HEADER) {
				state->wdr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				state->prev_part = BGP_UPDATE_WDR_LEN;
			}

			if (state->prev_part == BGP_UPDATE_WDR_LEN ||
			        state->prev_part == BGP_UPDATE_WDR) {
				state->attr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				state->prev_part = BGP_UPDATE_ATTR_LEN;
			}

			if (state->prev_part != BGP_UPDATE_ATTR_LEN &&
			        state->prev_part != BGP_UPDATE_ATTR) {
				usage_error("Path Attributes must come after "
				            "unfeasible routes (if any), "
				            "or after header\n");
				rc = FALSE;
			} else {
				rem_ptr = ptr;
				arg_ptr = optarg;

				*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 16);
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}

				*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 10);
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}

				bytes = (u_int8_t)strtoul(arg_ptr, &new_arg_ptr, 10);
				if (arg_ptr != new_arg_ptr) {
					if (bytes <= 1) {
						bytes = 1;
					} else {
						bytes = 2;
					}
				} else {
					if (*rem_ptr & 0x10) {
						bytes = 2;
					} else {
						bytes = 1;
					}
				}
				arg_ptr = new_arg_ptr;
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}

				if (bytes == 1) {
					*ptr++ = (u_int8_t)strtoul(arg_ptr, &new_arg_ptr, 10);
				} else {
					PUTSHORT(ptr, (u_int16_t)strtoul(arg_ptr, &new_arg_ptr, 10));
					ptr += 2;
				}
				if (arg_ptr != new_arg_ptr) {
					len_mod = TRUE;
				}
				arg_ptr = new_arg_ptr;
				if (*arg_ptr != '\0') {
					arg_ptr++;
				}

				if (bytes == 1) {
					count=bgp_parse_bytes(ptr, arg_ptr, &new_arg_ptr, 0xFF, 16, ':', '\0');
					if (count<0) return FALSE;
					ptr+=count;
					if (*new_arg_ptr) { usage_error("Too many BGP value bytes\n"); return FALSE; }
				} else {
					count=bgp_parse_bytes(ptr, arg_ptr, &new_arg_ptr, 0xFFFF, 16, ':', '\0');
					if (count<0) return FALSE;
					ptr+=count;
					if (*new_arg_ptr) { usage_error("Too many BGP attribute bytes\n"); return FALSE; }
				}

				if (!len_mod) {
					if (bytes == 1) {
						*(rem_ptr + 2) = ptr - rem_ptr - 3;
					} else {
						PUTSHORT(rem_ptr + 2, ptr - rem_ptr - 4);
					}
				}

				if (!(pack->modified & BGP_MOD_ATTR_LEN)) {
					PUTSHORT(state->attr_len_ptr,
					         GETSHORT(state->attr_len_ptr) + ptr - rem_ptr);
				}
				state->prev_part = BGP_UPDATE_ATTR;
			}
			break;

		case 'n':
			if (state->prev_part == BGP_HEADER) {
				state->wdr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				state->prev_part = BGP_UPDATE_WDR_LEN;
			}

			if (state->prev_part == BGP_UPDATE_WDR_LEN ||
			        state->prev_part == BGP_UPDATE_WDR) {
				state->attr_len_ptr = ptr;
				PUTSHORT(ptr, 0);
				ptr += 2;
				state->prev_part = BGP_UPDATE_ATTR_LEN;
			}

			if (state->prev_part != BGP_UPDATE_ATTR_LEN &&
			        state->prev_part != BGP_UPDATE_ATTR &&
			        state->prev_part != BGP_UPDATE_NLRI) {
				usage_error("NLRI must come after Unfeasible routes and "
				            "attributes, if any, or after header\n");
				rc = FALSE;
			} else {
				memcpy(ptr, nlri, nlri_length);
				ptr+=nlri_length;

				state->prev_part = BGP_UPDATE_NLRI;
			}
			break;

		default:
			fprintf(stderr, "Unrecognised BGP UPDATE option: %s\n", optstring);
			rc = FALSE;
		}
		break;

	case 'n':
		if (state->prev_part != BGP_HEADER) {
			usage_error("Notification must come immediately after header\n");
			rc = FALSE;
		} else {
			arg_ptr = optarg;
			*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 10);
			if (*arg_ptr != '\0') {
				arg_ptr++;
			}

			*ptr++ = (u_int8_t)strtoul(arg_ptr, &arg_ptr, 10);
			if (*arg_ptr != '\0') {
				arg_ptr++;
			}

			count=bgp_parse_bytes(ptr, arg_ptr, &new_arg_ptr, 0xFFFF, 16, ':', '\0');
			if (count<0) return FALSE;
			ptr+=count;
			if (*new_arg_ptr) { usage_error("Too many BGP notification bytes\n"); return FALSE; }

			state->prev_part = BGP_NOTFN;
		}
		break;

	default:
		fprintf(stderr, "Unrecognised BGP option: %s", optstring);
		rc = FALSE;
	}

	if (rc) {
		pack->alloc_len = ptr - (u_int8_t *)pack->data;
		if (!(pack->modified & BGP_MOD_LENGTH)) {
			PUTSHORT(state->len_ptr, pack->alloc_len);
		}
	}

	return (rc);
}



/* UPDATE always contains a Total Path Attribute Length, even when empty. */
bool do_pad(sendip_data *pack) {
	bgp_state *state=pack->private;
	if (state->prev_part!=BGP_UPDATE_WDR_LEN && state->prev_part!=BGP_UPDATE_WDR)
		return TRUE;
	if (pack->alloc_len<0 || (unsigned int)pack->alloc_len>BGP_BUFLEN-2)
		return FALSE;
	state->attr_len_ptr=(u_int8_t *)pack->data+pack->alloc_len;
	PUTSHORT(state->attr_len_ptr, 0);
	pack->alloc_len+=2;
	state->prev_part=BGP_UPDATE_ATTR_LEN;
	if (!(pack->modified&BGP_MOD_LENGTH)) PUTSHORT(state->len_ptr, pack->alloc_len);
	return TRUE;
}


bool finalize (char        *hdrs,
               sendip_data *headers[],
               int index,
               sendip_data *data,
               sendip_data *pack)
{
	if (index<1 || hdrs[index - 1] != 't') {
		usage_error("WARNING: BGP should be carried over TCP\n");
	}
	return TRUE;
}


int num_opts (void)
{
	return (sizeof(bgp_opts)/sizeof(sendip_option));
}


sendip_option *get_opts (void)
{
	return (bgp_opts);
}


char get_optchar (void)
{
	return (bgp_opt_char);
}
