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
crypto_module *
load_crypto_module(char *modname)
{
	static const char *patterns[]={"%s", "./%s.so", "%s/%s.so", "%s/%s"};
	char *errors[4]={NULL};
	crypto_module *newmod=calloc(1, sizeof(*newmod));
	size_t namesize=strlen(modname)+strlen(SENDIP_LIBS)+6;

	if (!newmod) return NULL;
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
	newmod->cryptomod=dlsym(newmod->handle, "cryptomod");
	if (!newmod->cryptomod) {
		const char *error=dlerror();
		fprintf(stderr, "Module %s has no cryptomod function: %s\n", modname,
		        error ? error : "null function pointer");
		goto fail;
	}
	/* Initialization is optional. */
	newmod->cryptoinit=dlsym(newmod->handle, "cryptoinit");
	return newmod;

fail:
	if (newmod->handle) dlclose(newmod->handle);
	free(newmod->name);
	free(newmod);
	return NULL;
}
