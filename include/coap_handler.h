#ifndef COAP_HANDLER_H
#define COAP_HANDLER_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>


struct COAP_CTX
{
	char *psk_identity;
	int identity_len;
	char *psk_key;
	int psk_len;
	char *server_addr;
	int addr_len;
	SSL *ssl;
	SSL_CTX *ssl_ctx;
};


struct COAP_CTX* COAP_init();
int COAP_set_psk_key(struct COAP_CTX* ctx, char *key, int len);
int COAP_set_psk_identity(struct COAP_CTX* ctx, char *identity, int len);
int COAP_send_get(struct COAP_CTX* ctx, char *endpoint, int endpoint_len, void (*callback)(char*, int));
int COAP_set_server_addr(struct COAP_CTX* ctx, char *addr, int len);
void COAP_free(struct COAP_CTX* ctx);

#endif
