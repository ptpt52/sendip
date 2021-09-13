#ifndef _CRYPTO_MODULE_H
#define _CRYPTO_MODULE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

typedef struct {
	char *name;
	void *handle;
	bool (*cryptoinit)(void *priv);
	bool (*cryptomod)(void *priv, char *hdrs, sendip_data *headers[],
		int index, sendip_data *data, sendip_data *pack);
} crypto_module;

crypto_module *load_crypto_module(char *modname);

/* Prototypes */
#ifndef _CRYPTO_MAIN
bool cryptoinit(sendip_data *pack);
bool cryptomod(void *priv, char *hdrs, sendip_data *headers[],
	int index, sendip_data *data, sendip_data *pack);
#endif  /* _CRYPTO_MAIN */

#endif  /* _CRYPTO_MODULE_H */
