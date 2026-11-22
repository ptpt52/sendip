#include <stdlib.h>
#include <string.h>
#include "sendip_module.h"

struct saved_option {
	char *name;
	char *argument;
};

static sendip_option options[] = {
	{"label", true, "Exercise writable option storage across packet iterations", NULL},
};

sendip_data *initialize(void) {
	sendip_data *pack=calloc(1, sizeof(*pack));
	if (!pack) return NULL;
	pack->data=malloc(1);
	pack->private=calloc(1, sizeof(struct saved_option));
	if (!pack->data || !pack->private) {
		free(pack->data);
		free(pack->private);
		free(pack);
		return NULL;
	}
	pack->alloc_len=1;
	return pack;
}

void destroy(sendip_data *pack) {
	free(pack->private);
}

int num_opts(void) {
	return sizeof(options)/sizeof(options[0]);
}

sendip_option *get_opts(void) {
	return options;
}

char get_optchar(void) {
	return 'q';
}

u_int32_t randomize_arg(const char *name, u_int32_t value) {
	return strcmp(name, "qlabel")==0 ? UINT32_MAX : value;
}

bool do_opt(char *name, char *argument, sendip_data *pack) {
	struct saved_option *saved=pack->private;
	if (strcmp(name, "qlabel") || !argument || strcmp(argument, "4294967295"))
		return false;
	saved->name=name;
	saved->argument=argument;
	name[0]='x';
	argument[0]='y';
	return true;
}

bool finalize(char *names, sendip_data *headers[], int index,
              sendip_data *data, sendip_data *pack) {
	struct saved_option *saved=pack->private;
	if (!saved->name || strcmp(saved->name, "xlabel") || strcmp(saved->argument, "y294967295"))
		return false;
	*(char *)pack->data='!';
	return true;
}
