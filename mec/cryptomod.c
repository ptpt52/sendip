/* cryptomod.c - cryptographic module support
 *
 * This loads in modules which provide authentication and encryption
 * support for AH and/or ESP.
 *
 * The assumption is that such modules will be put into the same
 * directory as the other sendip modules. Obviously the module
 * interfaces are a bit different, but this shouldn't really
 * cause confusion.
 *
 * Speaking of which, the module interfaces here are about as
 * simple-minded as you can get. Crypto modules get passed a
 * "key" and a pointer to the packet. They can then encrypt
 * (rewrite) the packet and/or return authentication info to
 * be added to it.
 *
 * Crypto modules have the following entry points:
 *
 * 	cryptoinit(key) - called with "key" as argument; perform initialization
 * 	cryptomod() - called with both the private "key" information and
 * 		the usual arguments to finalize. It should fill in the
 * 		appropriate portions of the packet based on the other
 * 		arguments.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include "sendip_module.h"
#include "ipv6ext.h"
#include "ah.h"
#include "esp.h"
#define _CRYPTO_MAIN
#include "crypto_module.h"

/* This is patterned after the sendip load_module, but I made
 * it a bit more compact.
 */
struct modname_pattern {
	const char *pattern;
	const char *dirarg;
	const char *error;
} namepats[] = {
	{"%s",	NULL, NULL},
	{"./%s.so",	NULL, NULL},
	{"%s/%s.so", SENDIP_LIBS, NULL},
	{"%s/%s", SENDIP_LIBS, NULL},
	{NULL, NULL, NULL}
};

crypto_module *
load_crypto_module(char *modname)
{
	crypto_module *newmod = malloc(sizeof(crypto_module));
	int i;

	/* Longest possible name is:
	 * SENDIP_LIBS/modname.so
	 */

	newmod->name = (char *)
		malloc(strlen(modname)+strlen(SENDIP_LIBS)+strlen(".so")+2);
	for (i=0; namepats[i].pattern; ++i) {
		if (namepats[i].dirarg) {
			sprintf(newmod->name, namepats[i].pattern,
				namepats[i].dirarg, modname);
		} else { 
			sprintf(newmod->name, namepats[i].pattern, modname);
		}
		if ((newmod->handle=dlopen(newmod->name,RTLD_NOW))) {
			break;
		}
		namepats[i].error = strdup(dlerror());
	}
	if (!newmod->handle) {
		fprintf(stderr,"Couldn't open module %s, tried:\n",modname);
		for (i=0; namepats[i].pattern; ++i) {
			fprintf(stderr, "\t%s\n", namepats[i].error);
			free((void *)namepats[i].error);
		}
		free(newmod);
		return NULL;
	} else {
		for (i=0; namepats[i].pattern; ++i) {
			if (namepats[i].error)
				free((void *)namepats[i].error);
		}
	}

	/* Initialize is optional */
	newmod->cryptoinit=dlsym(newmod->handle,"cryptoinit");
	if (!newmod->cryptoinit) {
		fprintf(stderr,"Warning: %s has no initialize function: %s\n",
			modname, dlerror());
	}

	/* cryptomod is not */
	newmod->cryptomod=dlsym(newmod->handle,"cryptomod");
	if (!newmod->cryptomod) {
		fprintf(stderr,"Error: %s has no cryptomod function: %s\n",
			modname, dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return NULL;
	}
	return newmod;
}
