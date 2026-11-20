#ifndef SENDIP_MODULE_LOADER_H
#define SENDIP_MODULE_LOADER_H

#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Path rules are shared by protocol and crypto modules. On success the
 * caller owns both the handle and the allocated candidate name.
 */
static void *open_sendip_module(const char *name, char **loaded_name) {
	*loaded_name=NULL;
	if (!name || !*name) {
		fputs("Module name is empty\n", stderr);
		return NULL;
	}

	size_t length=strlen(name);
	bool explicit_path=strchr(name, '/')!=NULL;
	bool has_suffix=length>=3 && !strcmp(name+length-3, ".so");
	const char *suffix=has_suffix ? "" : ".so";
	/* Explicit paths stay relative or absolute as supplied. For short
	 * names, retain the usual loader, working-directory and LIBDIR order.
	 */
	const char *dirs[]={"", explicit_path ? "" : ".", SENDIP_LIBS, SENDIP_LIBS};
	const char *suffixes[]={"", suffix, suffix, ""};
	char *errors[sizeof(dirs)/sizeof(dirs[0])]={NULL};
	size_t count=has_suffix ? 3 : 4;
	if (explicit_path) count=has_suffix ? 1 : 2;
	else if (!*SENDIP_LIBS) count=2;

	/* Room for the directory, separator, .so suffix and terminator. */
	size_t overhead=sizeof(SENDIP_LIBS)+sizeof("/.so");
	if (length>SIZE_MAX-overhead) {
		fputs("Module path is too long\n", stderr);
		return NULL;
	}
	size_t capacity=length+overhead;
	char *candidate=malloc(capacity);
	if (!candidate) {
		perror("Allocating module path");
		return NULL;
	}

	void *handle=NULL;
	size_t i;
	for (i=0; i<count; ++i) {
		const char *separator=*dirs[i] ? "/" : "";
		int written=snprintf(candidate, capacity, "%s%s%s%s",
		                     dirs[i], separator, name, suffixes[i]);
		if (written<0 || (size_t)written>=capacity) {
			fprintf(stderr, "Could not format module path for %s\n", name);
			break;
		}
		handle=dlopen(candidate, RTLD_NOW);
		if (handle) break;
		const char *error=dlerror();
		if (error) errors[i]=strdup(error);
	}
	if (handle) {
		*loaded_name=candidate;
	} else {
		fprintf(stderr, "Couldn't open module %s, tried:\n", name);
		for (size_t j=0; j<i; ++j)
			fprintf(stderr, "  %s%s%s%s: %s\n", dirs[j], *dirs[j] ? "/" : "",
			        name, suffixes[j],
			        errors[j] ? errors[j] : "loader error unavailable");
		free(candidate);
	}
	for (size_t j=0; j<i; ++j) free(errors[j]);
	return handle;
}

static void *require_module_symbol(void *handle, const char *module, const char *name) {
	(void)dlerror();
	void *symbol=dlsym(handle, name);
	const char *error=dlerror();
	if (!symbol || error) {
		fprintf(stderr, "Module %s cannot use required entry point %s: %s\n",
		        module, name, error ? error : "null function pointer");
		return NULL;
	}
	return symbol;
}

#endif
