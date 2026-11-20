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
#include <netinet/in.h>
#include <netdb.h>


/* everything else */
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ctype.h> /* isprint */
#include <limits.h>
#include <errno.h>
#include "sendip_module.h"

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

static int num_opts=0;
static sendip_module *first;
static sendip_module *last;

static char *progname;

static void free_arguments(char **arguments) {
	if (!arguments) return;
	for (size_t i=0; arguments[i]; ++i) free(arguments[i]);
	free(arguments);
}

static char **copy_arguments(int count, char *const arguments[]) {
	char **copy=calloc((size_t)count+1, sizeof(*copy));
	if (!copy) return NULL;
	for (int i=0; i<count; ++i) {
		copy[i]=strdup(arguments[i]);
		if (!copy[i]) {
			free_arguments(copy);
			return NULL;
		}
	}
	return copy;
}

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

static void unload_modules(bool freeit, int verbosity) {
	sendip_module *mod, *p;
	p = NULL;
	for(mod=first; mod!=NULL; mod=mod->next) {
		if(verbosity) fprintf(stderr, "Freeing module %s\n",mod->name);
		if(p) free(p);
		p = mod;
		free(mod->name);
		if (mod->pack) {
			if (mod->destroy) mod->destroy(mod->pack);
			if(freeit) free(mod->pack->data);
			free(mod->pack);
		}
		(void)dlclose(mod->handle);
		/* Do not free options - TODO should we? */
	}
	if(p) free(p);
	first=last=NULL;
	num_opts=0;
}

static bool load_module(char *modname) {
	static const char *patterns[]={"%s", "./%s.so", "%s/%s.so", "%s/%s"};
	char *errors[4]={NULL};
	sendip_module *newmod=calloc(1, sizeof(*newmod));
	size_t namesize=strlen(modname)+strlen(SENDIP_LIBS)+6;
	int (*n_opts)(void);
	sendip_option *(*get_opts)(void);
	char (*get_optchar)(void);

	if (!newmod) {
		perror("Allocating module");
		return false;
	}
	newmod->name=malloc(namesize);
	if (!newmod->name) goto fail;
	for (int i=0; i<4; ++i) {
		if (i<2) snprintf(newmod->name, namesize, patterns[i], modname);
		else snprintf(newmod->name, namesize, patterns[i], SENDIP_LIBS, modname);
		newmod->handle=dlopen(newmod->name, RTLD_NOW);
		if (newmod->handle) break;
		const char *error=dlerror();
		errors[i]=strdup(error ? error : "unknown loader error");
	}
	if (!newmod->handle) {
		fprintf(stderr, "Couldn't open module %s, tried:\n", modname);
		for (int i=0; i<4; ++i)
			fprintf(stderr, "  %s\n", errors[i] ? errors[i] : "loader error unavailable");
	}
	for (int i=0; i<4; ++i) free(errors[i]);
	if (!newmod->handle) goto fail;
	memcpy(newmod->name, modname, strlen(modname)+1);

	if (!(newmod->initialize=dlsym(newmod->handle, "initialize")) ||
	    !(newmod->do_opt=dlsym(newmod->handle, "do_opt")) ||
	    !(newmod->finalize=dlsym(newmod->handle, "finalize")) ||
	    !(n_opts=dlsym(newmod->handle, "num_opts")) ||
	    !(get_opts=dlsym(newmod->handle, "get_opts")) ||
	    !(get_optchar=dlsym(newmod->handle, "get_optchar"))) {
		const char *error=dlerror();
		fprintf(stderr, "Module %s is missing an entry point: %s\n", modname,
		        error ? error : "null function pointer");
		goto fail;
	}
	newmod->do_pad=dlsym(newmod->handle, "do_pad");
	newmod->do_pad_ip=dlsym(newmod->handle, "do_pad_ip");
	newmod->randomize_arg=dlsym(newmod->handle, "randomize_arg");
	newmod->set_addr=dlsym(newmod->handle, "set_addr");
	newmod->destroy=dlsym(newmod->handle, "destroy");
	newmod->num_opts=n_opts();
	newmod->optchar=get_optchar();
	newmod->opts=get_opts();
	if (newmod->num_opts<0 || newmod->num_opts>INT_MAX-num_opts-1 ||
	    !newmod->optchar || (newmod->num_opts && !newmod->opts)) {
		fprintf(stderr, "Module %s returned invalid option metadata\n", modname);
		goto fail;
	}
	for (int i=0; i<newmod->num_opts; ++i) {
		if (!newmod->opts[i].optname || !*newmod->opts[i].optname ||
		    !newmod->opts[i].description) {
			fprintf(stderr, "Module %s returned invalid option metadata\n", modname);
			goto fail;
		}
	}
	num_opts+=newmod->num_opts;
	newmod->prev=last;
	if (last) last->next=newmod;
	else first=newmod;
	last=newmod;
	return true;

fail:
	if (newmod->handle) dlclose(newmod->handle);
	free(newmod->name);
	free(newmod);
	return false;
}

static void free_options(struct option *options) {
	if (!options) return;
	for (size_t i=0; options[i].name; ++i) free((void *)options[i].name);
	free(options);
}

static struct option *module_options(void) {
	struct option *options=calloc((size_t)num_opts+1, sizeof(*options));
	if (!options) return NULL;
	int i=0;
	for (sendip_module *module=first; module; module=module->next) {
		for (int j=0; j<module->num_opts; ++j, ++i) {
			size_t size=strlen(module->opts[j].optname)+2;
			char *name=malloc(size);
			if (!name) { free_options(options); return NULL; }
			snprintf(name, size, "%c%s", module->optchar, module->opts[j].optname);
			options[i].name=name;
			options[i].has_arg=module->opts[j].arg;
			options[i].val=module->optchar;
		}
	}
	return options;
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
	fprintf(stderr, " tN\tto generate a timestamp (16 bytes) padded with N-16 nul (zero) bytes;\n");
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

extern u_int32_t randomcalls;

int main(int argc, char *const argv[]) {
	int i;
	int status=0;

	struct option *opts=NULL;
	int longindex=0;
	char rbuff[31];
	char **packet_argv=NULL;

	bool usage=FALSE, verbosity=FALSE, dump=FALSE;

	char *data=NULL;
	int datafile=-1;
	int datalen=0;
	char *datarg=NULL;

	sendip_module *mod, *currentmod;
	int optc;

	int num_modules=0;

	sendip_data packet;

	/*@@*/
	int loopcount=1;
	unsigned int delaytime=0;

	num_opts = 0;
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
		optc=getopt_long_only(argc, argv, "-p:l:T:vd:hf:D", opts, &longindex);
		if (optc==EOF) break;
		if (longindex>=0) continue;
		if (optc=='p') {
			if (!load_module(gnuoptarg)) {
				status=1;
				goto cleanup;
			}
			++num_modules;
			struct option *updated=module_options();
			if (!updated) {
				perror("Allocating module options");
				status=1;
				goto cleanup;
			}
			free_options(opts);
			opts=updated;
		} else if (optc=='?' || optc==':') {
			if (nextchar && *nextchar) ++gnuoptind;
			nextchar=NULL;
		}
	}
	if (!opts) {
		opts=module_options();
		if (!opts) {
			perror("Allocating module options");
			status=1;
			goto cleanup;
		}
	}


	/* Resolve global options only after the complete module option table exists. */
	gnuopterr=1;
	gnuoptind=0;
	for (;;) {
		longindex=-1;
		optc=getopt_long_only(argc, argv, "p:l:T:vd:hf:D", opts, &longindex);
		if (optc==EOF) break;
		if (longindex>=0) continue;
		switch(optc) {
		case 'D':
			dump=TRUE;
			break;
		case 'p':
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
		case 'd':
			if (!datarg && datafile == -1) {
				datarg = gnuoptarg; /* Select the source; decode in packet option order. */

			} else {
				fprintf(stderr,"Only one -d or -f option can be given\n");
				usage = TRUE;
				status=1;
			}
			break;
		case 'h':
			usage=TRUE;
			break;
		case 'f':
			if(!datarg && datafile == -1) {
				off_t file_length;
				datafile=open(gnuoptarg,O_RDONLY);
				if(datafile == -1) {
					perror("Couldn't open data file");
					status=1;
					goto cleanup;
				} else {
					file_length = lseek(datafile,0,SEEK_END);
					if(file_length == (off_t)-1) {
						perror("Error reading data file: lseek()");
						status=1;
						goto cleanup;
					}
					if (file_length > INT_MAX) {
						fprintf(stderr,"Data file is too large\n");
						status=1;
						goto cleanup;
					}
					datalen=(int)file_length;
					if(datalen == 0) {
						fprintf(stderr,"Data file is empty\nNo data will be included\n");
					} else {
						data = mmap(NULL,datalen,PROT_READ,MAP_SHARED,datafile,0);
						if(data == MAP_FAILED) {
							perror("Couldn't read data file: mmap()");
							data = NULL;
							status=1;
							goto cleanup;
						}
					}
				}
			} else {
				fprintf(stderr,"Only one -d or -f option can be given\n");
				usage = TRUE;
				status=1;
			}
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

	if(verbosity) fprintf(stderr, "Added %d options\n",num_opts);

	/*@@ looping - needs to be after module loading, but before
	 * module option processing ... */
	bool forever=loopcount==0;
	while (forever || loopcount>0) {
		if (!forever) --loopcount;

		/* Discard all previous packet views before any initializer can fail. */
		for (mod=first; mod; mod=mod->next) {
			if (mod->pack && mod->destroy) mod->destroy(mod->pack);
			free(mod->pack);
			mod->pack=NULL;
		}
		free_arguments(packet_argv);
		packet_argv=copy_arguments(argc, argv);
		if (!packet_argv) {
			perror("Copying packet arguments");
			status=1;
			goto cleanup;
		}

		/* Initialize all */
		for(mod=first; mod!=NULL; mod=mod->next) {
			if(verbosity) fprintf(stderr, "Initializing module %s\n",mod->name);
			mod->pack=mod->initialize();
			if (!mod->pack) {
				perror("Initializing protocol module");
				unload_modules(TRUE, verbosity);
				status=1;
				goto cleanup;
			}
		}

		/* Do the get opt */
		gnuopterr=1;
		gnuoptind=0;
		/* @@ Change so that options apply first to the most recently
		 * invoked module. This is to allow separate arguments for
		 * multiply-invoked modules, e.g. for creating ipip tunneled
		 * packets.
		 */
		currentmod = NULL;
		for (;;) {
			longindex=-1;
			optc=getopt_long_only(argc, packet_argv, "p:l:T:vd:hf:D", opts, &longindex);
			if (optc==EOF) break;
			if (longindex<0) {
				if (optc=='p') currentmod=currentmod ? currentmod->next : first;
				else if (optc=='d') {
					if (!set_payload(gnuoptarg, &data, &datalen)) {
						unload_modules(TRUE, verbosity);
						status=1;
						goto cleanup;
					}
				}
				else if (optc=='?' || optc==':') {
					usage=TRUE;
					status=1;
					break;
				}
				continue;
			}
			/*@@ check current mod first */
			if (currentmod && currentmod->optchar == optc)
				mod = currentmod;
			else {
				for(mod=first; mod!=NULL; mod=mod->next) {
					if(mod->optchar==optc)
						break;
				}
			}
			if (mod) {
				/* Random option arguments */
				if(gnuoptarg != NULL && !strcmp(gnuoptarg,"r")) {
					/* need a 32 bit number, but random() is signed and
						nonnegative so only 31bits - we simply repeat one */
					unsigned long r = (unsigned long)random()<<1;
					r+=(r&0x00000040)>>6;
					if (mod->randomize_arg)
						r=mod->randomize_arg(opts[longindex].name, (u_int32_t)r);
					sprintf(rbuff,"%lu",r);
					gnuoptarg = rbuff;
				}

				if(!mod->do_opt((char *)opts[longindex].name,gnuoptarg,mod->pack)) {
					usage=TRUE;
					status=1;
					break;
				}
			} else {
				usage=TRUE;
				status=1;
				break;
			}
		}

		/* A failed callback may leave partially updated state. Do not call
		 * another option handler or resolve addresses after that failure.
		 */
		if (usage) {
			print_usage();
			unload_modules(TRUE, verbosity);
			goto cleanup;
		}

		/* gnuoptind is the first thing that is not an option - should have exactly
			one hostname...
		*/
		if(argc-gnuoptind < 1) {
			fprintf(stderr,"No hostname specified, assuming -D (dump to stdout)\n");
			dump = TRUE;
			if(first && first->set_addr) {
				if (!first->set_addr((char*)"localhost",first->pack)) {
					usage=TRUE;
					status=1;
				}
			}
		} else if(argc > gnuoptind+1) {
			usage=TRUE;
			status=1;
			fprintf(stderr,"More than one hostname specified\n");
		} else {
			if(first && first->set_addr) {
				if (!first->set_addr(packet_argv[gnuoptind],first->pack)) {
					usage=TRUE;
					status=1;
				}
			}
		}

		if(usage) {
			print_usage();
			unload_modules(TRUE,verbosity);
			goto cleanup;
		}

		/* Validate the enclosing layer before finalizers inspect their parents. */
		if ((!first && !data) || (first && first->optchar!='i' && first->optchar!='6')) {
			fprintf(stderr, "%s\n", first ?
			        "Either IPv4 or IPv6 must be the outermost packet" :
			        "Nothing specified to send!");
			unload_modules(TRUE, verbosity);
			status=1;
			goto cleanup;
		}

		if (!pad_modules()) {
			unload_modules(TRUE, verbosity);
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
		packet.data = NULL;
		packet.alloc_len = 0;
		packet.modified = 0;
		for(mod=first; mod!=NULL; mod=mod->next) {
			if (mod->pack->alloc_len<0 || mod->pack->alloc_len>INT_MAX-packet.alloc_len) {
				fprintf(stderr, "Packet headers are too large\n");
				unload_modules(TRUE, verbosity);
				status=1;
				goto cleanup;
			}
			packet.alloc_len+=mod->pack->alloc_len;
		}
		if (datalen>INT_MAX-packet.alloc_len) {
			fprintf(stderr, "Packet data is too large\n");
			unload_modules(TRUE, verbosity);
			status=1;
			goto cleanup;
		}
		packet.alloc_len+=datalen;
		packet.data = malloc(packet.alloc_len ? (size_t)packet.alloc_len : 1);
		if (!packet.data) {
			perror("Allocating packet");
			unload_modules(TRUE, verbosity);
			status=1;
			goto cleanup;
		}
		for(i=0, mod=first; mod!=NULL; mod=mod->next) {
			memcpy((char *)packet.data+i,mod->pack->data,mod->pack->alloc_len);
			free(mod->pack->data);
			mod->pack->data = (char *)packet.data+i;
			i+=mod->pack->alloc_len;
		}

		/* Add any data */
		if(data != NULL) memcpy((char *)packet.data+i,data,datalen);

		/* Finalize from inside out */
		{
			char hdrs[num_modules+1];
			sendip_data *headers[num_modules+1];
			sendip_data d;

			d.alloc_len = datalen;
			d.data = (char *)packet.data+packet.alloc_len-datalen;

			for(i=0,mod=first; mod!=NULL; mod=mod->next,i++) {
				hdrs[i]=mod->optchar;
				headers[i]=mod->pack;
			}
			hdrs[num_modules] = '\0';
			headers[num_modules] = NULL;

			for(i=num_modules-1,mod=last; mod!=NULL; mod=mod->prev,i--) {

				if(verbosity) fprintf(stderr, "Finalizing module %s\n",mod->name);
				/* Remove this header from enclosing list */
				/* @@ Don't erase the header type, so that
				 * it's available to upper-level headers where
				 * needed. Instead, we tell the upper-level
				 * headers where they are in the list.
				 */
				/*@@hdrs[i]='\0';@@*/
				/* @@ wesp needs to see the esp header info,
				 * so now we can't erase that, either.
				 */
				/*@@headers[i] = NULL;*/

				/* @@ */
				if (!mod->finalize(hdrs, headers, i, &d, mod->pack)) {
					fprintf(stderr, "Finalizing module %s failed\n", mod->name);
					free(packet.data);
					status=1;
					goto cleanup;
				}

				/* Get everything ready for the next call */
				if (d.alloc_len<0 || mod->pack->alloc_len<0 ||
				    mod->pack->alloc_len>packet.alloc_len-d.alloc_len) {
					fprintf(stderr, "Module %s expanded the finalized packet\n", mod->name);
					free(packet.data);
					status=1;
					goto cleanup;
				}
				d.data=(char *)d.data-mod->pack->alloc_len;
				d.alloc_len+=mod->pack->alloc_len;
			}
			/* @@ Trim back the packet length if need be */
			if (d.alloc_len < packet.alloc_len)
				packet.alloc_len = d.alloc_len;
		}
		/* @@ We could (and should?) free any leftover priv data here. */

		/* And send the packet */
		{
			int af_type=first && first->optchar=='6' ? AF_INET6 : AF_INET;
			if (dump) {
				if (fwrite(packet.data, 1, packet.alloc_len, stdout)!=(size_t)packet.alloc_len ||
				    fflush(stdout)==EOF) {
					perror("Writing packet data");
					status=1;
				}
			} else if (sendpacket(&packet,packet_argv[gnuoptind],af_type,verbosity)!=packet.alloc_len) {
				status=1;
			}
			free(packet.data);
			if (status) goto cleanup;
		}

		/*@@ looping */
		if ((forever || loopcount) && delaytime)
			sleep(delaytime);
	} /*@@ back to top of loop */

cleanup:
	free_options(opts);
	if(datafile != -1) {
		if (data && datalen) munmap(data,datalen);
		close(datafile);
	}
	else free(data);

	unload_modules(FALSE,verbosity);
	free_arguments(packet_argv);
	/*@@ global de-init */
	fa_close();


	/*@@fprintf(stderr, "%d random calls\n", randomcalls);*/

	return status;
}
