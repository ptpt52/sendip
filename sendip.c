/* sendip.c - main program code for sendip
 * Copyright 2001 Mike Ricketts <mike@earth.li>
 * Distributed under the GPL.  See LICENSE.
 * Bug reports, patches, comments etc to mike@earth.li
 * ChangeLog since 2.0 release:
 * 27/11/2001 compact_string() moved to compact.c
 * 27/11/2001 change search path for libs to include <foo>.so
 * 23/01/2002 make random fields more random (Bryan Croft <bryan@gurulabs.com>)
 * 10/08/2002 detect attempt to use multiple -d and -f options
 * ChangeLog since 2.2 release:
 * 24/11/2002 compile on archs requiring alignment
 * ChangeLog since 2.3 release:
 * 21/04/2003 random data (Anand (Andy) Rao <andyrao@nortelnetworks.com>)
 * ChangeLog since 2.4 release:
 * 21/04/2003 fix errors detected by valgrind
 * 28/07/2003 fix compile error on solaris
 */

#define _SENDIP_MAIN

/* socket stuff */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>


/* everything else */
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <time.h>
#include <ctype.h> /* isprint */
#include <limits.h>
#include <errno.h>
#include "sendip_module.h"
#include "module_loader.h"

#ifdef __sun__  /* for EVILNESS workaround */
#include "ipv4.h"
#endif /* __sun__ */

/* FreeBSD 11+ accepts network-order fields; older FreeBSD and Darwin
 * expect host-order ip_len/ip_off at the raw-socket boundary only.
 */
#if defined(__FreeBSD__) || defined(__FreeBSD)
#include <sys/param.h>
#endif
#if defined(__APPLE__) || ((defined(__FreeBSD__) || defined(__FreeBSD)) && \
    defined(__FreeBSD_version) && __FreeBSD_version < 1100000)
#define SENDIP_RAW_IPV4_HOST_ORDER 1
#else
#define SENDIP_RAW_IPV4_HOST_ORDER 0
#endif

#if SENDIP_RAW_IPV4_HOST_ORDER
static void raw_ipv4_host_order(void *packet) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char *wire=packet;
	/* Swap just the two socket-specific 16-bit words, without alignment
	 * assumptions. This operation is its own inverse.
	 */
	unsigned char byte=wire[2]; wire[2]=wire[3]; wire[3]=byte;
	byte=wire[6]; wire[6]=wire[7]; wire[7]=byte;
#else
	(void)packet;
#endif
}
#endif

/* Use our own getopt to ensure consistent behaviour on all platforms */
#include "gnugetopt.h"

typedef struct _s_m {
	struct _s_m *next;
	struct _s_m *prev;
	char *name;
	char optchar;
	sendip_data * (*initialize)(void);
	bool (*do_opt)(char *optstring, char *optarg,
	               sendip_data *pack);
	bool (*do_pad)(sendip_data *pack);
	bool (*do_pad_ip)(char outer_ip, sendip_data *pack);
	u_int32_t (*randomize_arg)(const char *option, u_int32_t value);
	void (*destroy)(sendip_data *pack);
	bool (*set_addr)(char *hostname, sendip_data *pack);
	bool (*finalize)(char *hdrs, sendip_data *headers[], int index,
	                 sendip_data *data, sendip_data *pack);
	sendip_data *pack;
	void *handle;
	sendip_option *opts;
	int num_opts;
} sendip_module;

typedef struct {
	struct option *items;
	int count;
	size_t capacity;
} module_option_table;

typedef struct {
	sendip_module *module; /* NULL for a payload argument (-d). */
	const char *name;
	const char *argument;
	char *writable_name;
	char *writable_argument;
	bool random_argument;
} packet_option;

static sendip_module *first;
static sendip_module *last;

static char *progname;

static bool parse_count(const char *input, unsigned long maximum, unsigned long *value) {
	char *end;
	if (!input || !isdigit((unsigned char)*input)) return false;
	errno=0;
	*value=strtoul(input, &end, 10);
	return !errno && !*end && *value<=maximum;
}

static bool set_payload(const char *argument, char **data, int *length) {
	char *source=NULL, *replacement;
	int size=stringargument(argument, &source);
	if (!source) {
		fprintf(stderr, "Couldn't decode packet data\n");
		return false;
	}
	replacement=malloc(size ? (size_t)size : 1);
	if (!replacement) {
		perror("Allocating packet data");
		return false;
	}
	if (size) memcpy(replacement, source, size);
	free(*data);
	*data=replacement;
	*length=size;
	return true;
}

static bool read_payload_file(const char *path, char **data, int *length) {
	FILE *file=fopen(path, "rb");
	if (!file) {
		perror("Couldn't open data file");
		return false;
	}
	char *buffer=NULL;
	size_t size=0, capacity=0, reserve=0;
	struct stat info;
	if (fstat(fileno(file), &info)==0 && S_ISREG(info.st_mode)) {
		if (info.st_size>INT_MAX) {
			usage_error("Data file is too large\n");
			goto fail;
		}
		if (info.st_size>0) reserve=(size_t)info.st_size;
	}
	/* Cache the bytes through EOF. Only regular files provide a useful
	 * size hint, and some virtual files report zero despite having data.
	 */
	char block[BUFSIZ];
	for (;;) {
		size_t received=fread(block, 1, sizeof(block), file);
		if (ferror(file)) {
			perror("Couldn't read data file");
			goto fail;
		}
		if (!received) break;
		if (received>(size_t)INT_MAX-size) {
			usage_error("Data file is too large\n");
			goto fail;
		}
		size_t needed=size+received;
		if (needed>capacity) {
			size_t grown=capacity<=(size_t)INT_MAX/2 ? capacity*2 : INT_MAX;
			if (grown<reserve) grown=reserve;
			if (grown<needed) grown=needed;
			char *replacement=realloc(buffer, grown);
			if (!replacement) {
				perror("Allocating packet data");
				goto fail;
			}
			buffer=replacement;
			capacity=grown;
		}
		memcpy(buffer+size, block, received);
		size=needed;
	}
	if (fclose(file)!=0) {
		perror("Couldn't close data file");
		free(buffer);
		return false;
	}
	if (!size) usage_error("Data file is empty\nNo data will be included\n");
	*data=buffer;
	*length=(int)size;
	return true;

fail:
	free(buffer);
	fclose(file);
	return false;
}

static int sendpacket(sendip_data *data, char *hostname, int af_type,
                      bool verbose) {
	struct sockaddr_storage to;
	socklen_t tolen;
	int s, sent;
	if (!resolve_address(hostname, af_type, &to, &tolen)) return -1;

	if(verbose) {
		int i, j;
		fprintf(stderr, "Final packet data:\n");
		for(i=0; i<data->alloc_len; ) {
			for(j=0; j<4 && i+j<data->alloc_len; j++)
				fprintf(stderr, "%02X ", ((unsigned char *)(data->data))[i+j]);
			fprintf(stderr, "  ");
			for(j=0; j<4 && i+j<data->alloc_len; j++) {
				int c=(int) ((unsigned char *)(data->data))[i+j];
				fprintf(stderr, "%c", isprint(c)?((char *)(data->data))[i+j]:'.');
			}
			fprintf(stderr, "\n");
			i+=j;
		}
	}

	if ((s = socket(af_type, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("Couldn't open RAW socket");
		return -1;
	}
	/* Need this for OpenBSD, shouldn't cause problems elsewhere */
	/* TODO: should make it a command line option */
	if(af_type == AF_INET) {
		const int on=1;
		if (setsockopt(s, IPPROTO_IP,IP_HDRINCL,(const void *)&on,sizeof(on)) <0) {
			perror ("Couldn't setsockopt IP_HDRINCL");
			close(s);
			return -2;
		}
	}

	/* On Solaris, it seems that the only way to send IP options or packets
		with a faked IP header length is to:
		setsockopt(IP_OPTIONS) with the IP option data and size
		decrease the total length of the packet accordingly
		I'm sure this *shouldn't* work.  But it does.
	*/
#ifdef __sun__
	if (af_type==AF_INET && data->alloc_len>=(int)sizeof(ip_header)) {
		ip_header *iphdr = (ip_header *)data->data;
		int optlen=iphdr->header_len*4-(int)sizeof(*iphdr);
		/* Only interpret option bytes actually present in an IPv4 packet. */
		if (iphdr->version==4 && optlen>0 &&
		    optlen<=data->alloc_len-(int)sizeof(*iphdr)) {

			if(verbose)
				fprintf(stderr, "Solaris workaround enabled for %d IP option bytes\n", optlen);

			iphdr->tot_len = htons(ntohs(iphdr->tot_len)-optlen);

			if(setsockopt(s,IPPROTO_IP,IP_OPTIONS,
			              (void *)(((char *)(data->data))+20),optlen)) {
				perror("Couldn't setsockopt IP_OPTIONS");
				close(s);
				return -2;
			}
		}
	}
#endif /* __sun__ */

	/* The assembled packet, dumps and encapsulated headers stay in wire
	 * order. Adapt only the outer header temporarily for legacy raw APIs.
	 */
#if SENDIP_RAW_IPV4_HOST_ORDER
	unsigned char wire_prefix[8];
	bool host_order=af_type==AF_INET && data->alloc_len>=20;
	if (host_order) {
		memcpy(wire_prefix, data->data, sizeof(wire_prefix));
		raw_ipv4_host_order(data->data);
	}
#endif
	/* Send the packet */
	sent = sendto(s, (char *)data->data, data->alloc_len, 0, (const struct sockaddr *)&to, tolen);
#if SENDIP_RAW_IPV4_HOST_ORDER
	if (host_order) {
		int saved_errno=errno;
		memcpy(data->data, wire_prefix, sizeof(wire_prefix));
		errno=saved_errno;
	}
#endif
	if (sent == data->alloc_len) {
		if(verbose) fprintf(stderr, "Sent %d bytes to %s\n",sent,hostname);
	} else {
		if (sent < 0)
			perror("sendto");
		else {
			if(verbose) fprintf(stderr, "Only sent %d of %d bytes to %s\n",
				                    sent, data->alloc_len, hostname);
		}
	}
	close(s);
	return sent;
}

static void release_module_packet(sendip_module *mod, bool owns_data) {
	if (!mod->pack) return;
	if (mod->destroy) mod->destroy(mod->pack);
	if (owns_data) free(mod->pack->data);
	free(mod->pack);
	mod->pack=NULL;
}

static void unload_modules(bool owns_data, int verbosity) {
	for (sendip_module *mod=first; mod;) {
		sendip_module *next=mod->next;
		if(verbosity) fprintf(stderr, "Freeing module %s\n",mod->name);
		release_module_packet(mod, owns_data);
		(void)dlclose(mod->handle);
		free(mod->name);
		free(mod);
		mod=next;
	}
	first=last=NULL;
}

static void free_module_options(module_option_table *table) {
	for (int i=0; i<table->count; ++i) free((void *)table->items[i].name);
	free(table->items);
}

static bool append_module_option(module_option_table *table, char prefix,
                                 const sendip_option *option) {
	size_t needed=(size_t)table->count+2; /* Include the getopt sentinel. */
	size_t maximum=SIZE_MAX/sizeof(*table->items);
	if (maximum>INT_MAX) maximum=INT_MAX;
	if (needed>maximum) {
		errno=ENOMEM;
		return false;
	}
	if (needed>table->capacity) {
		size_t capacity=table->capacity<=maximum/2 ? table->capacity*2 : maximum;
		if (capacity<needed) capacity=needed;
		struct option *items=realloc(table->items, capacity*sizeof(*items));
		if (!items) return false;
		table->items=items;
		table->capacity=capacity;
	}
	size_t length=strlen(option->optname)+1;
	char *name=malloc(length+1);
	if (!name) return false;
	name[0]=prefix;
	memcpy(name+1, option->optname, length);
	table->items[table->count++]=(struct option){
		.name=name, .has_arg=option->arg, .val=(unsigned char)prefix,
	};
	table->items[table->count]=(struct option){0};
	return true;
}

static bool register_module_options(module_option_table *table, const sendip_module *module) {
	for (int i=0; i<module->num_opts; ++i) {
		const sendip_option *option=&module->opts[i];
		if (!option->optname || !*option->optname ||
		    strchr(option->optname, '=') || !option->description) {
			fprintf(stderr, "Module %s returned invalid option metadata\n", module->name);
			return false;
		}
		int match=0;
		for (; match<table->count; ++match) {
			const char *name=table->items[match].name;
			if (name[0]==module->optchar && !strcmp(name+1, option->optname)) break;
		}
		if (match<table->count) {
			if (table->items[match].has_arg!=option->arg) {
				fprintf(stderr, "Module %s has conflicting argument rules for -%c%s\n",
				        module->name, module->optchar, option->optname);
				return false;
			}
		} else if (!append_module_option(table, module->optchar, option)) {
			perror("Allocating module options");
			return false;
		}
	}
	return true;
}

static bool load_module(const char *modname, module_option_table *options) {
	sendip_module *newmod=calloc(1, sizeof(*newmod));
	char *loaded_name=NULL;
	int (*n_opts)(void);
	sendip_option *(*get_opts)(void);
	char (*get_optchar)(void);

	if (!newmod) {
		perror("Allocating module");
		return false;
	}
	newmod->handle=open_sendip_module(modname, &loaded_name);
	if (!newmod->handle) goto fail;
	newmod->name=strdup(modname);
	if (!newmod->name) {
		perror("Copying module name");
		goto fail;
	}

	void *handle=newmod->handle;
	if (!(newmod->initialize=require_module_symbol(handle, loaded_name, "initialize")) ||
	    !(newmod->do_opt=require_module_symbol(handle, loaded_name, "do_opt")) ||
	    !(newmod->finalize=require_module_symbol(handle, loaded_name, "finalize")) ||
	    !(n_opts=require_module_symbol(handle, loaded_name, "num_opts")) ||
	    !(get_opts=require_module_symbol(handle, loaded_name, "get_opts")) ||
	    !(get_optchar=require_module_symbol(handle, loaded_name, "get_optchar")))
		goto fail;
	newmod->do_pad=dlsym(handle, "do_pad");
	newmod->do_pad_ip=dlsym(handle, "do_pad_ip");
	newmod->randomize_arg=dlsym(handle, "randomize_arg");
	newmod->set_addr=dlsym(handle, "set_addr");
	newmod->destroy=dlsym(handle, "destroy");
	newmod->num_opts=n_opts();
	newmod->optchar=get_optchar();
	newmod->opts=get_opts();
	if (newmod->num_opts<0 || !newmod->optchar || newmod->optchar=='=' ||
	    (newmod->num_opts && !newmod->opts)) {
		fprintf(stderr, "Module %s returned invalid option metadata\n", modname);
		goto fail;
	}
	if (!register_module_options(options, newmod)) goto fail;
	newmod->prev=last;
	if (last) last->next=newmod;
	else first=newmod;
	last=newmod;
	free(loaded_name);
	return true;

fail:
	if (newmod->handle) dlclose(newmod->handle);
	free(loaded_name);
	free(newmod->name);
	free(newmod);
	return false;
}

static bool module_has_option(const sendip_module *module, const char *name) {
	if (module->optchar!=name[0]) return false;
	for (int i=0; i<module->num_opts; ++i)
		if (!strcmp(module->opts[i].optname, name+1)) return true;
	return false;
}

static sendip_module *find_option_module(sendip_module *current, const char *name) {
	/* Prefer the most recent matching selector, including the current one. */
	for (sendip_module *mod=current; mod; mod=mod->prev)
		if (module_has_option(mod, name)) return mod;
	/* Options can also precede the first selector for their module. */
	for (sendip_module *mod=current ? current->next : first; mod; mod=mod->next)
		if (module_has_option(mod, name)) return mod;
	return NULL;
}

static void print_usage(void) {
	sendip_module *mod;
	int i;
	fprintf(stderr, "Usage: %s [-v] [-D] [-l loopcount] [-T time] [-d data] [-h] [-f datafile] [-p module] [module options] [hostname]\n",progname);
	fprintf(stderr, " -d data\tadd this data as a string to the end of the packet\n");
	fprintf(stderr, " -f datafile\tread packet data from file\n");
	fprintf(stderr, " -h\t\thelp (this message)\n");
	fprintf(stderr, " -l loopcount\trun loopcount times (0 means indefinitely)\n");
	fprintf(stderr, " -p module\tload the specified module (see below)\n");
	fprintf(stderr, " -T time\twait time seconds between each loop run (0 means as fast as possible)\n");
	fprintf(stderr, " -v\t\tbe verbose\n");
	fprintf(stderr, " -D\t\tdump packet(s) to stdout but don't send\n");

	fprintf(stderr, "\n\nPacket data, and argument values for many header fields, may\n");
	fprintf(stderr, "specified as\n");
	fprintf(stderr, " rN\tto generate N random(ish) data bytes;\n");
	fprintf(stderr, " zN\tto generate N nul (zero) data bytes;\n");
	fprintf(stderr, " tN\tto take N bytes of a native timeval timestamp, padded with zeros as needed;\n");
	fprintf(stderr, " fF\tto read values from file F;\n");
	fprintf(stderr, " 0x or 0X\tfollowed by hex digits;\n");
	fprintf(stderr, " 0\tfollowed by octal digits;\n");
	fprintf(stderr, " 1-9\tfollowed by decimal number for decimal digits;\n");
	fprintf(stderr, "Any other stream of bytes is taken literally.\n");
	fprintf(stderr, "\nIPv4 addresses may be specified by the methods above,\n");
	fprintf(stderr, "or by CIDR-style notation to indicate a random host address\n");
	fprintf(stderr, "within a subnet.\n");

	fprintf(stderr, "\nFor example, the arguments\n\t-p ipv4 -is 10.1.1.0/24 -p udp -us r2\n");
	fprintf(stderr, "generate a random 10.1.1.xx source address and random udp source port.\n\n");

	fprintf(stderr, "sendip may be run repeatedly by using the -l (loop) argument.\n");
	fprintf(stderr, "Each packet sent will be identical unless random (rN) or\n");
	fprintf(stderr, "file (fF) arguments are used.\n");
	fprintf(stderr, "When looping, sendip will send packets as quickly as possible\n");
	fprintf(stderr, "unless a time delay (-T) argument is specified.\n");
	fprintf(stderr, "\nFile arguments are read line by line, with the contents of\n");
	fprintf(stderr, "the line then substituted for the corresponding argument.\n");
	fprintf(stderr, "For example, assume the file F contains the four lines:\n");
	fprintf(stderr, "\n\t10.1.1.1\n");
	fprintf(stderr, "\n\t1000\n");
	fprintf(stderr, "\n\t10.1.1.2\n");
	fprintf(stderr, "\n\t2000\n");
	fprintf(stderr, "\nThen the arguments\n\n\t-l 2 -p ipv4 -id fF -p udp -ud fF\n");
	fprintf(stderr, "\nwould produce two UDP packets, one to 10.1.1.1:1000 and\n");
	fprintf(stderr, "one to 10.1.1.2:2000\n");
	fprintf(stderr, "When the lines in the file are exhausted, it is rewound\n");
	fprintf(stderr, "and read from the beginning again.\n");

	fprintf(stderr, "\n\nModules are loaded in the order the -p option appears.  The headers from\n");
	fprintf(stderr, "each module are put immediately inside the headers from the previous module in\n");
	fprintf(stderr, "the final packet.  For example, to embed bgp inside tcp inside ipv4, do\n");
	fprintf(stderr, "sendip -p ipv4 -p tcp -p bgp ....\n");

	fprintf(stderr, "\n\nModules may be repeated to create multiple instances of a given header\n");
	fprintf(stderr, "type. For example, to create an ipip tunneled packet (ipv4 inside ipv4), do\n");
	fprintf(stderr, "sendip -p ipv4 <outer header arguments> -p ipv4 <inner header arguments> ....\n");
	fprintf(stderr, "In the case of repeated modules, arguments are applied to the closest matching\n");
	fprintf(stderr, "module in the command line.\n");


	fprintf(stderr, "\n\nModules available at compile time:\n");
	fprintf(stderr, "\tipv4 ipv6 icmp tcp udp bgp rip ripng ntp\n");
	fprintf(stderr, "\tah dest esp frag gre hop route sctp wesp.\n\n");
	for(mod=first; mod!=NULL; mod=mod->next) {
		char *shortname = strrchr(mod->name, '/');

		if (!shortname) shortname = mod->name;
		else ++shortname;
		fprintf(stderr, "\n\nArguments for module %s:\n",shortname);
		for(i=0; i<mod->num_opts; i++) {
			fprintf(stderr, "   -%c%s %c\t%s\n",mod->optchar,
			       mod->opts[i].optname,mod->opts[i].arg?'x':' ',
			       mod->opts[i].description);
			if(mod->opts[i].def) fprintf(stderr, "   \t\t  Default: %s\n",
				                             mod->opts[i].def);
		}
	}

}

static bool prepare_packet_options(packet_option *options, size_t count) {
	for (size_t i=0; i<count; ++i) {
		packet_option *option=&options[i];
		if (!option->module) continue;
		option->writable_name=strdup(option->name);
		if (!option->writable_name) return false;
		if (option->argument) {
			option->random_argument=!strcmp(option->argument, "r");
			size_t length=option->random_argument ? sizeof("4294967295") :
			              strlen(option->argument)+1;
			option->writable_argument=malloc(length);
			if (!option->writable_argument) return false;
		}
	}
	return true;
}

static bool apply_packet_options(packet_option *options, size_t count,
                                 char **data, int *datalen) {
	for (size_t i=0; i<count; ++i) {
		packet_option *option=&options[i];
		sendip_module *mod=option->module;
		if (!mod) {
			if (!set_payload(option->argument, data, datalen)) return false;
			continue;
		}

		/* Callbacks receive writable arguments that stay valid until the
		 * packet is destroyed. Restore them before each use.
		 */
		strcpy(option->writable_name, option->name);
		if (option->random_argument) {
			/* random() supplies 31 bits. Repeat one bit to fill the field. */
			u_int32_t value=(u_int32_t)random()<<1;
			value+=(value&0x00000040)>>6;
			if (mod->randomize_arg)
				value=mod->randomize_arg(option->name, value);
			snprintf(option->writable_argument, sizeof("4294967295"),
			         "%lu", (unsigned long)value);
		} else if (option->argument) {
			strcpy(option->writable_argument, option->argument);
		}
		if (!mod->do_opt(option->writable_name, option->writable_argument, mod->pack)) {
			print_usage();
			return false;
		}
	}
	return true;
}

static bool pad_modules(void) {
	char outer_ip=0;
	for (sendip_module *mod=first; mod; mod=mod->next) {
		if (mod->optchar=='i' || mod->optchar=='6') outer_ip=mod->optchar;
		if ((mod->do_pad && !mod->do_pad(mod->pack)) ||
		    (mod->do_pad_ip && !mod->do_pad_ip(outer_ip, mod->pack))) {
			fprintf(stderr, "Padding module %s failed\n", mod->name);
			return FALSE;
		}
	}
	return TRUE;
}

int main(int argc, char *const argv[]) {
	int i;
	int status=0;

	const struct option empty_options[]={{0}};
	const struct option *opts=NULL;
	module_option_table module_options={0};
	int longindex=0;
	packet_option *packet_options=NULL;
	size_t packet_option_count=0;
	char *packet_hostname=NULL;
	char *hdrs=NULL;
	sendip_data **headers=NULL;

	bool usage=FALSE, verbosity=FALSE, dump=FALSE;

	char *data=NULL;
	const char *datafile=NULL;
	int datalen=0;
	bool has_payload=false;

	sendip_module *mod;
	int optc;

	int num_modules=0;

	sendip_data packet = {0};

	/*@@*/
	int loopcount=1;
	unsigned int delaytime=0;

	first=last=NULL;

	progname=argv[0];

	/* magic random seed that gives 4 really random octets */
	srandom(time(NULL) ^ (getpid()+(42<<15)));

	/*@@ init global tools */
	if (!fa_init()) {
		perror("Initializing file arguments");
		status=1;
		goto cleanup;
	}

	/* Learn options as modules load, so their argument values are consumed
	 * as values even when they resemble global flags such as -p or -d.
	 */
	gnuopterr=0;
	gnuoptind=0;
	for (;;) {
		longindex=-1;
		optc=gnugetopt_long_only(argc, argv, "-p:l:T:vd:hf:D", opts, &longindex);
		if (optc==EOF) break;
		if (longindex>=0) continue;
		if (optc=='p') {
			if (!load_module(gnuoptarg, &module_options)) {
				status=1;
				goto cleanup;
			}
			++num_modules;
			opts=module_options.items ? module_options.items : empty_options;
		} else if (optc=='?' || optc==':') {
			gnugetopt_discard_short_group();
		}
	}
	if (!opts) opts=empty_options;


	/* Resolve argument order and module ownership once. Values such as
	 * file-backed fields and random data are still evaluated per packet.
	 */
	/* A packet option consumes at least one argument slot. */
	packet_options=calloc((size_t)argc, sizeof(*packet_options));
	if (!packet_options) {
		perror("Allocating packet options");
		status=1;
		goto cleanup;
	}
	sendip_module *next_selector=first;
	sendip_module *currentmod=NULL;
	gnuopterr=1;
	gnuoptind=0;
	for (;;) {
		longindex=-1;
		optc=gnugetopt_long_only(argc, argv, "p:l:T:vd:hf:D", opts, &longindex);
		if (optc==EOF) break;
		if (longindex>=0) {
			const char *name=opts[longindex].name;
			mod=find_option_module(currentmod, name);
			if (!mod) {
				usage=TRUE;
				status=1;
			} else {
				packet_options[packet_option_count++]=(packet_option){
					.module=mod, .name=name, .argument=gnuoptarg,
				};
			}
			continue;
		}
		switch(optc) {
		case 'D':
			dump=TRUE;
			break;
		case 'p':
			/* A newly recognized module option may have consumed an earlier
			 * -p as its argument. Check the loaded order before dispatch.
			 */
			if (!next_selector || strcmp(next_selector->name, gnuoptarg)!=0) {
				fprintf(stderr, "Unexpected module selector for %s after resolving module options\n",
				        gnuoptarg);
				status=1;
				goto cleanup;
			}
			currentmod=next_selector;
			next_selector=next_selector->next;
			break;
		case 'l':
		{
			unsigned long count;
			if (!parse_count(gnuoptarg, INT_MAX, &count)) {
				fprintf(stderr, "Invalid loop count\n");
				status=1;
				goto cleanup;
			}
			loopcount=(int)count;
			break;
		}
		case 'T':
		{
			unsigned long delay;
			if (!parse_count(gnuoptarg, UINT_MAX, &delay)) {
				fprintf(stderr, "Invalid packet delay\n");
				status=1;
				goto cleanup;
			}
			delaytime=(unsigned int)delay;
			break;
		}
		case 'v':
			verbosity=TRUE;
			break;
		case 'h':
			usage=TRUE;
			break;
		case 'd':
		case 'f':
			if (has_payload) {
				fprintf(stderr,"Only one -d or -f option can be given\n");
				usage = TRUE;
				status=1;
			} else if (optc=='f') {
				datafile=gnuoptarg;
			} else {
				packet_options[packet_option_count++]=(packet_option){.argument=gnuoptarg};
			}
			has_payload=true;
			break;
		case '?':
		case ':':
			usage=TRUE;
			status=1;
			break;
		}
	}


	if (usage) {
		print_usage();
		goto cleanup;
	}
	if (next_selector) {
		fprintf(stderr, "Module selector for %s is missing after resolving module options\n",
		        next_selector->name);
		status=1;
		goto cleanup;
	}
	if (argc-gnuoptind>1) {
		fprintf(stderr,"More than one hostname specified\n");
		print_usage();
		status=1;
		goto cleanup;
	}
	const char *hostname=gnuoptind<argc ? argv[gnuoptind] : NULL;
	const char *address=hostname;
	if (!hostname && first && first->set_addr)
		address=first->optchar=='6' ? "::1" : "127.0.0.1";
	if (address) {
		packet_hostname=strdup(address);
		if (!packet_hostname) {
			perror("Copying packet hostname");
			status=1;
			goto cleanup;
		}
	}
	if (!prepare_packet_options(packet_options, packet_option_count)) {
		perror("Copying packet options");
		status=1;
		goto cleanup;
	}
	if (datafile && !read_payload_file(datafile, &data, &datalen)) {
		status=1;
		goto cleanup;
	}

	size_t slots=(size_t)num_modules+1;
	hdrs=malloc(slots);
	headers=calloc(slots, sizeof(*headers));
	if (!hdrs || !headers) {
		perror("Allocating module header lists");
		status=1;
		goto cleanup;
	}

	if(verbosity) fprintf(stderr, "Added %d options\n",module_options.count);

	/*@@ looping - needs to be after module loading, but before
	 * module option processing ... */
	bool forever=loopcount==0;
	while (forever || loopcount>0) {
		if (!forever) --loopcount;

		/* Initialize all */
		for(mod=first; mod!=NULL; mod=mod->next) {
			if(verbosity) fprintf(stderr, "Initializing module %s\n",mod->name);
			mod->pack=mod->initialize();
			if (!mod->pack) {
				perror("Initializing protocol module");
				status=1;
				goto cleanup;
			}
		}

		if (!apply_packet_options(packet_options, packet_option_count, &data, &datalen)) {
			status=1;
			goto cleanup;
		}

		if (!hostname) {
			fprintf(stderr,"No hostname specified, assuming -D (dump to stdout)\n");
			dump = TRUE;
		}
		if (address) strcpy(packet_hostname, address);
		if (first && first->set_addr && !first->set_addr(packet_hostname, first->pack)) {
			print_usage();
			status=1;
			goto cleanup;
		}

		/* Validate the enclosing layer before finalizers inspect their parents. */
		if ((!first && !data) || (first && first->optchar!='i' && first->optchar!='6')) {
			fprintf(stderr, "%s\n", first ?
			        "Either IPv4 or IPv6 must be the outermost packet" :
			        "Nothing specified to send!");
			status=1;
			goto cleanup;
		}

		if (!pad_modules()) {
			status=1;
			goto cleanup;
		}

		/* EVIL EVIL EVIL! */
		/* Stick all the bits together.  This means that finalize better not
			change the size or location of any packet's data... */
		/* @@ New addition - we allow finalize to shrink, but not expand,
		 * the packet size. Of course, any finalize which does so is
		 * responsible for pulling back all the later packet data into
		 * the area that will be sent.
		 *
		 * All of this is to accommodate esp, which needs to put its
		 * trailer after the packet data, with some padding for alignment.
		 * Since esp can't know how much padding will be needed until
		 * the rest of the packet is filled out, it preallocates an
		 * excess of padding first, and then trims in finalize to the
		 * amount actually needed.
		 */
		packet.alloc_len = 0;
		for(mod=first; mod!=NULL; mod=mod->next) {
			if (mod->pack->alloc_len<0 || (mod->pack->alloc_len && !mod->pack->data)) {
				fprintf(stderr, "Module %s returned invalid header storage\n", mod->name);
				status=1;
				goto cleanup;
			}
			if (mod->pack->alloc_len>INT_MAX-packet.alloc_len) {
				fprintf(stderr, "Packet headers are too large\n");
				status=1;
				goto cleanup;
			}
			packet.alloc_len+=mod->pack->alloc_len;
		}
		if (datalen>INT_MAX-packet.alloc_len) {
			fprintf(stderr, "Packet data is too large\n");
			status=1;
			goto cleanup;
		}
		packet.alloc_len+=datalen;
		packet.data = malloc(packet.alloc_len ? (size_t)packet.alloc_len : 1);
		if (!packet.data) {
			perror("Allocating packet");
			status=1;
			goto cleanup;
		}
		for(i=0, mod=first; mod!=NULL; mod=mod->next) {
			if (mod->pack->alloc_len)
				memcpy((char *)packet.data+i,mod->pack->data,mod->pack->alloc_len);
			free(mod->pack->data);
			mod->pack->data = (char *)packet.data+i;
			i+=mod->pack->alloc_len;
		}

		/* Add any data */
		if(data != NULL) memcpy((char *)packet.data+i,data,datalen);

		/* Finalize from inside out */
		{
			sendip_data d = {
				.data = (char *)packet.data+packet.alloc_len-datalen,
				.alloc_len = datalen,
			};

			for(i=0,mod=first; mod!=NULL; mod=mod->next,i++) {
				hdrs[i]=mod->optchar;
				headers[i]=mod->pack;
			}
			hdrs[num_modules] = '\0';
			headers[num_modules] = NULL;

			for(i=num_modules-1,mod=last; mod!=NULL; mod=mod->prev,i--) {
				char *start=mod->pack->data;
				int capacity=mod->pack->alloc_len+d.alloc_len;
				if(verbosity) fprintf(stderr, "Finalizing module %s\n",mod->name);
				if (!mod->finalize(hdrs, headers, i, &d, mod->pack)) {
					fprintf(stderr, "Finalizing module %s failed\n", mod->name);
					status=1;
					goto cleanup;
				}

				/* The header and its following data must remain contiguous
				 * within the space available to this finalizer.
				 */
				if (mod->pack->data!=start ||
				    d.alloc_len<0 || d.alloc_len>capacity ||
				    mod->pack->alloc_len<0 || mod->pack->alloc_len>capacity-d.alloc_len ||
				    d.data!=start+mod->pack->alloc_len) {
					fprintf(stderr, "Module %s returned an invalid finalized packet layout\n",
					        mod->name);
					status=1;
					goto cleanup;
				}
				d.data=start;
				d.alloc_len+=mod->pack->alloc_len;
			}
			/* @@ Trim back the packet length if need be */
			if (d.alloc_len < packet.alloc_len)
				packet.alloc_len = d.alloc_len;
		}
		/* And send the packet */
		{
			int af_type=first && first->optchar=='6' ? AF_INET6 : AF_INET;
			if (dump) {
				if (fwrite(packet.data, 1, packet.alloc_len, stdout)!=(size_t)packet.alloc_len ||
				    fflush(stdout)==EOF) {
					perror("Writing packet data");
					status=1;
				}
			} else if (sendpacket(&packet,packet_hostname,af_type,verbosity)!=packet.alloc_len) {
				status=1;
			}
			if (status) goto cleanup;
		}

		for (mod=first; mod; mod=mod->next)
			release_module_packet(mod, false);
		free(packet.data);
		packet.data=NULL;

		/*@@ looping */
		if ((forever || loopcount) && delaytime)
			sleep(delaytime);
	} /*@@ back to top of loop */

cleanup:
	/* Before assembly each module owns a separate header allocation. After
	 * assembly the views borrow storage from the single packet buffer.
	 */
	unload_modules(!packet.data, verbosity);
	free(packet.data);
	free(headers);
	free(hdrs);
	for (size_t j=0; j<packet_option_count; ++j) {
		free(packet_options[j].writable_name);
		free(packet_options[j].writable_argument);
	}
	free(packet_options);
	free(packet_hostname);
	free_module_options(&module_options);
	free(data);
	/*@@ global de-init */
	fa_close();


	return status;
}
