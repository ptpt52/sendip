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
#include "sendip_module.h"

#ifdef __sun__  /* for EVILNESS workaround */
#include "ipv4.h"
#endif /* __sun__ */

/* Use our own getopt to ensure consistent behaviour on all platforms */
#include "gnugetopt.h"

typedef struct _s_m {
	struct _s_m *next;
	struct _s_m *prev;
	char *name;
	char optchar;
	sendip_data * (*initialize)(void);
	bool (*do_opt)(const char *optstring, const char *optarg,
	               sendip_data *pack);
	bool (*do_pad)(sendip_data *pack);
	bool (*set_addr)(char *hostname, sendip_data *pack);
	bool (*finalize)(char *hdrs, sendip_data *headers[], int index,
	                 sendip_data *data, sendip_data *pack);
	sendip_data *pack;
	void *handle;
	sendip_option *opts;
	int num_opts;
} sendip_module;

/* sockaddr_storage struct is not defined everywhere, so here is our own
	nasty version
*/
typedef struct {
	u_int16_t ss_family;
	u_int32_t ss_align;
	char ss_padding[122];
} _sockaddr_storage;

static int num_opts=0;
static sendip_module *first;
static sendip_module *last;

static char *progname;

static int sendpacket(sendip_data *data, char *hostname, int af_type,
                      bool verbose) {
	_sockaddr_storage *to = malloc(sizeof(_sockaddr_storage));
	int tolen;

	/* socket stuff */
	int s;                            /* socket for sending       */

	/* hostname stuff */
	struct hostent *host = NULL;      /* result of gethostbyname2 */

	/* casts for specific protocols */
	struct sockaddr_in *to4 = (struct sockaddr_in *)to; /* IPv4 */
	struct sockaddr_in6 *to6 = (struct sockaddr_in6 *)to; /* IPv6 */

	int sent;                         /* number of bytes sent */

	if(to==NULL) {
		perror("OUT OF MEMORY!\n");
		return -3;
	}
	memset(to, 0, sizeof(_sockaddr_storage));

	if ((host = gethostbyname2(hostname, af_type)) == NULL) {
		fprintf(stderr,"Couldn't get destination host %s (af %d): ",
		        hostname, af_type);
		perror("gethostbyname2");
		free(to);
		return -1;
	}

	switch (af_type) {
	case AF_INET:
		to4->sin_family = host->h_addrtype;
		memcpy(&to4->sin_addr, host->h_addr, host->h_length);
		tolen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		to6->sin6_family = host->h_addrtype;
		memcpy(&to6->sin6_addr, host->h_addr, host->h_length);
		tolen = sizeof(struct sockaddr_in6);
		break;
	default:
		return -2;
		break;
	}

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
		free(to);
		return -1;
	}
	/* Need this for OpenBSD, shouldn't cause problems elsewhere */
	/* TODO: should make it a command line option */
	if(af_type == AF_INET) {
		const int on=1;
		if (setsockopt(s, IPPROTO_IP,IP_HDRINCL,(const void *)&on,sizeof(on)) <0) {
			perror ("Couldn't setsockopt IP_HDRINCL");
			free(to);
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
	if((*((char *)(data->data))&0x0F) != 5) {
		ip_header *iphdr = (ip_header *)data->data;

		int optlen = iphdr->header_len*4-20;

		if(verbose)
			fprintf(stderr, "Solaris workaround enabled for %d IP option bytes\n", optlen);

		iphdr->tot_len = htons(ntohs(iphdr->tot_len)-optlen);

		if(setsockopt(s,IPPROTO_IP,IP_OPTIONS,
		              (void *)(((char *)(data->data))+20),optlen)) {
			perror("Couldn't setsockopt IP_OPTIONS");
			free(to);
			close(s);
			return -2;
		}
	}
#endif /* __sun__ */

	/* Send the packet */
	sent = sendto(s, (char *)data->data, data->alloc_len, 0, (void *)to, tolen);
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
	free(to);
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
		if(freeit) free(mod->pack->data);
		free(mod->pack);
		(void)dlclose(mod->handle);
		/* Do not free options - TODO should we? */
	}
	if(p) free(p);
}

static bool load_module(char *modname) {
	sendip_module *newmod = malloc(sizeof(sendip_module));
	/*@@
		sendip_module *cur;
	@@*/
	int (*n_opts)(void);
	sendip_option * (*get_opts)(void);
	char (*get_optchar)(void);

	/*@@
	 * 	We allow multiple loads for the same module in case they
	 * 	use static storage for stuff. Is this really necessary?
	 *
		for(cur=first;cur!=NULL;cur=cur->next) {
			if(!strcmp(modname,cur->name)) {
				memcpy(newmod,cur,sizeof(sendip_module));
				newmod->num_opts=0;
				goto out;
			}
		}
	@@*/
	newmod->name=malloc(strlen(modname)+strlen(SENDIP_LIBS)+strlen(".so")+2);
	strcpy(newmod->name,modname);
	if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))) {
		char *error0=strdup(dlerror());
		sprintf(newmod->name,"./%s.so",modname);
		if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))) {
			char *error1=strdup(dlerror());
			sprintf(newmod->name,"%s/%s.so",SENDIP_LIBS,modname);
			if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))) {
				char *error2=strdup(dlerror());
				sprintf(newmod->name,"%s/%s",SENDIP_LIBS,modname);
				if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))) {
					char *error3=strdup(dlerror());
					fprintf(stderr,"Couldn't open module %s, tried:\n",modname);
					fprintf(stderr,"  %s\n  %s\n  %s\n  %s\n", error0, error1,
					        error2, error3);
					free(newmod);
					free(error3);
					return FALSE;
				}
				free(error2);
			}
			free(error1);
		}
		free(error0);
	}
	strcpy(newmod->name,modname);
	if(NULL==(newmod->initialize=dlsym(newmod->handle,"initialize"))) {
		fprintf(stderr,"%s doesn't have an initialize function: %s\n",modname,
		        dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}
	if(NULL==(newmod->do_opt=dlsym(newmod->handle,"do_opt"))) {
		fprintf(stderr,"%s doesn't contain a do_opt function: %s\n",modname,
		        dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}
	newmod->do_pad=dlsym(newmod->handle,"do_pad");
	newmod->set_addr=dlsym(newmod->handle,"set_addr"); // don't care if fails
	if(NULL==(newmod->finalize=dlsym(newmod->handle,"finalize"))) {
		fprintf(stderr,"%s\n",dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}
	if(NULL==(n_opts=dlsym(newmod->handle,"num_opts"))) {
		fprintf(stderr,"%s\n",dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}
	if(NULL==(get_opts=dlsym(newmod->handle,"get_opts"))) {
		fprintf(stderr,"%s\n",dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}
	if(NULL==(get_optchar=dlsym(newmod->handle,"get_optchar"))) {
		fprintf(stderr,"%s\n",dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}
	newmod->num_opts = n_opts();
	newmod->optchar=get_optchar();
	/* TODO: check uniqueness */
	newmod->opts = get_opts();

	num_opts+=newmod->num_opts;

	/*@@
	out:
	@@*/
	newmod->pack=NULL;
	newmod->prev=last;
	newmod->next=NULL;
	last = newmod;
	if(last->prev) last->prev->next = last;
	if(!first) first=last;

	return TRUE;
}

static void print_usage(void) {
	sendip_module *mod;
	int i;
	fprintf(stderr, "Usage: %s [-v] [-D] [-l loopcount] [-t time] [-d data] [-h] [-f datafile] [-p module] [module options] [hostname]\n",progname);
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
	fprintf(stderr, "unless a time delay (-t) argument is specified.\n");
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

extern u_int32_t randomcalls;

int main(int argc, char *const argv[]) {
	int i;

	struct option *opts=NULL;
	int longindex=0;
	char rbuff[31];

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
	fa_init();

	/* First, get all the builtin options, and load the modules */
	gnuopterr=0;
	gnuoptind=0;
	while(gnuoptind<argc && (EOF != (optc=gnugetopt(argc,argv,"-p:l:T:vd:hf:D")))) {
		switch(optc) {
		case 'D':
			dump=TRUE;
			break;
		case 'p':
			if(load_module(gnuoptarg))
				num_modules++;
			break;
		case 'l':
			loopcount = atoi(gnuoptarg);
			break;
		case 'T':
			delaytime = atoi(gnuoptarg);
			break;
		case 'v':
			verbosity=TRUE;
			break;
		case 'd':
			if (datafile == -1) {
				char *sdata;

				datarg = gnuoptarg;	/* save for regen */
				datalen = stringargument(datarg, &sdata);
				data=(char *)malloc(datalen);
				memcpy(data, sdata, datalen);

			} else {
				fprintf(stderr,"Only one -d or -f option can be given\n");
				usage = TRUE;
			}
			break;
		case 'h':
			usage=TRUE;
			break;
		case 'f':
			if(data == NULL) {
				datafile=open(gnuoptarg,O_RDONLY);
				if(datafile == -1) {
					perror("Couldn't open data file");
					fprintf(stderr,"No data will be included\n");
				} else {
					datalen = lseek(datafile,0,SEEK_END);
					if(datalen == -1) {
						perror("Error reading data file: lseek()");
						fprintf(stderr,"No data will be included\n");
						datalen=0;
					} else if(datalen == 0) {
						fprintf(stderr,"Data file is empty\nNo data will be included\n");
					} else {
						data = mmap(NULL,datalen,PROT_READ,MAP_SHARED,datafile,0);
						if(data == MAP_FAILED) {
							perror("Couldn't read data file: mmap()");
							fprintf(stderr,"No data will be included\n");
							data = NULL;
							datalen=0;
						}
					}
				}
			} else {
				fprintf(stderr,"Only one -d or -f option can be given\n");
				usage = TRUE;
			}
			break;
		case '?':
		case ':':
			/* skip any further characters in this option
				this is so that -tonop doesn't cause a -p option
			*/
			nextchar = NULL;
			gnuoptind++;
			break;
		}
	}

	/*@@ looping - needs to be after module loading, but before
	 * module option processing ... */
	while (--loopcount >= 0) {

		/* Build the getopt listings */
		opts = malloc((1+num_opts)*sizeof(struct option));
		if(opts==NULL) {
			perror("OUT OF MEMORY!\n");
			return 1;
		}
		memset(opts,'\0',(1+num_opts)*sizeof(struct option));
		i=0;
		for(mod=first; mod!=NULL; mod=mod->next) {
			int j;
			char *s;   // nasty kludge because option.name is const
			for(j=0; j<mod->num_opts; j++) {
				/* +2 on next line is one for the char, one for the trailing null */
				opts[i].name = s = malloc(strlen(mod->opts[j].optname)+2);
				sprintf(s,"%c%s",mod->optchar,mod->opts[j].optname);
				opts[i].has_arg = mod->opts[j].arg;
				opts[i].flag = NULL;
				opts[i].val = mod->optchar;
				i++;
			}
		}
		if(verbosity) fprintf(stderr, "Added %d options\n",num_opts);

		/* Initialize all */
		for(mod=first; mod!=NULL; mod=mod->next) {
			if(verbosity) fprintf(stderr, "Initializing module %s\n",mod->name);
			/*@@ if looping, check if reloading */
			/*@@*/if (mod->pack) free(mod->pack);
			mod->pack=mod->initialize();
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
		while(EOF != (optc=getopt_long_only(argc,argv,"p:l:T:vd:hf:D",opts,&longindex))) {

			switch(optc) {
			case 'p':
				/* @@ should double-check match */
				if (!currentmod)
					currentmod = first;
				else
					currentmod = currentmod->next;
				break;
			case 'D':
			case 'v':
			case 'd':
			case 'f':
			case 'h':
			case 'l':/*@@*/
			case 'T':/*@@*/
				/* Processed above */
				break;
			case ':':
				usage=TRUE;
				fprintf(stderr,"Option %s requires an argument\n",
				        opts[longindex].name);
				break;
			case '?':
				usage=TRUE;
				fprintf(stderr,"Option starting %c not recognized\n",gnuoptopt);
				break;
			default:
				/*@@ check current mod first */
				if (currentmod->optchar == optc)
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
						sprintf(rbuff,"%lu",r);
						gnuoptarg = rbuff;
					}

					if(!mod->do_opt(opts[longindex].name,gnuoptarg,mod->pack)) {
						usage=TRUE;
					}
				}
				break;
			}
		}

		/* gnuoptind is the first thing that is not an option - should have exactly
			one hostname...
		*/
		if(argc-gnuoptind < 1) {
			fprintf(stderr,"No hostname specified, assuming -D (dump to stdout)\n");
			dump = TRUE;
			if(first && first->set_addr) {
				first->set_addr((char*)"localhost",first->pack);
			}
		} else if(argc > gnuoptind+1) {
			usage=TRUE;
			fprintf(stderr,"More than one hostname specified\n");
		} else {
			if(first && first->set_addr) {
				first->set_addr(argv[gnuoptind],first->pack);
			}
		}

		/* free opts now we have finished with it */
		for(i=0; i<(1+num_opts); i++) {
			if(opts[i].name != NULL) free((void *)opts[i].name);
		}
		free(opts); /* don't need them any more */

		if(usage) {
			print_usage();
			unload_modules(TRUE,verbosity);
			if(datafile != -1) {
				munmap(data,datalen);
				close(datafile);
				datafile=-1;
			}
			if (datarg) free(data);
			return 0;
		}

		for(mod=first; mod!=NULL; mod=mod->next) {
			if (mod->do_pad)
				mod->do_pad(mod->pack);
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
			packet.alloc_len+=mod->pack->alloc_len;
		}
		if(data != NULL) packet.alloc_len+=datalen;
		packet.data = malloc(packet.alloc_len);
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
			char hdrs[num_modules];
			sendip_data *headers[num_modules];
			sendip_data d;

			d.alloc_len = datalen;
			d.data = (char *)packet.data+packet.alloc_len-datalen;

			for(i=0,mod=first; mod!=NULL; mod=mod->next,i++) {
				hdrs[i]=mod->optchar;
				headers[i]=mod->pack;
			}

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
				mod->finalize(hdrs, headers, i, &d, mod->pack);

				/* Get everything ready for the next call */
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
			int af_type;
			if(first==NULL) {
				if(data == NULL) {
					fprintf(stderr,"Nothing specified to send!\n");
					print_usage();
					free(packet.data);
					unload_modules(FALSE,verbosity);
					return 1;
				} else {
					af_type = AF_INET;
				}
			}
			else if(first->optchar=='i') af_type = AF_INET;
			else if(first->optchar=='6') af_type = AF_INET6;
			else {
				fprintf(stderr,"Either IPv4 or IPv6 must be the outermost packet\n");
				unload_modules(FALSE,verbosity);
				free(packet.data);
				return 1;
			}
			if (dump)
				i = fwrite(packet.data, packet.alloc_len, 1, stdout);
			else
				i = sendpacket(&packet,argv[gnuoptind],af_type,verbosity);
			free(packet.data);
		}
		/* @@ Regenerate data on subsequent loop calls */
		if (loopcount && datarg) {
			char *sdata;

			datalen = stringargument(datarg, &sdata);
			memcpy(data, sdata, datalen);
		}

		/*@@ looping */
		if (loopcount && delaytime)
			sleep(delaytime);
	} /*@@ back to top of loop */

	/* cleanup */
	if(datafile != -1) {
		munmap(data,datalen);
		close(datafile);
		datafile=-1;
	}
	if (datarg) free(data);

	unload_modules(FALSE,verbosity);
	/*@@ global de-init */
	fa_close();


	/*@@fprintf(stderr, "%d random calls\n", randomcalls);*/

	return 0;
}
