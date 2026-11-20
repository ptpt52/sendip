#ifndef _CRYPTO_MODULE_H
#define _CRYPTO_MODULE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

typedef struct {
	char *name;
	void *handle;
	sendip_bool (*cryptoinit)(void *priv);
	sendip_bool (*cryptomod)(void *priv, char *hdrs, sendip_data *headers[],
	                  int index, sendip_data *data, sendip_data *pack);
} crypto_module;

crypto_module *load_crypto_module(char *modname);

/* Prototypes */
#ifndef _CRYPTO_MAIN
sendip_bool cryptoinit(sendip_data *pack);
sendip_bool cryptomod(void *priv, char *hdrs, sendip_data *headers[],
               int index, sendip_data *data, sendip_data *pack);
#endif  /* _CRYPTO_MAIN */

#endif  /* _CRYPTO_MODULE_H */
