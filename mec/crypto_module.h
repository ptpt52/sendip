#ifndef _CRYPTO_MODULE_H
#define _CRYPTO_MODULE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../sendip_module.h"

typedef struct crypto_module {
	char *name;
	void *handle;
	bool (*cryptoinit)(sendip_data *pack);
	bool (*cryptomod)(void *priv, char *hdrs, sendip_data *headers[],
	                  int index, sendip_data *data, sendip_data *pack);
} crypto_module;

crypto_module *load_crypto_module(char *modname);
bool initialize_crypto_module(crypto_module *module, sendip_data *pack);
void unload_crypto_module(crypto_module *module);

/* Prototypes */
#ifndef _CRYPTO_MAIN
/* May resize or replace pack->private with a valid protocol state. Module
 * handles in that state are owned by the calling protocol module.
 */
bool cryptoinit(sendip_data *pack);
bool cryptomod(void *priv, char *hdrs, sendip_data *headers[],
               int index, sendip_data *data, sendip_data *pack);
#endif  /* _CRYPTO_MAIN */

#endif  /* _CRYPTO_MODULE_H */
