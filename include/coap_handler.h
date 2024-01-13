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


int COAP_init(void);
int COAP_set_psk_key(char *key, int len);
int COAP_set_psk_identity(char *identity, int len);
int COAP_send_get(char *endpoint, int endpoint_len, char *response);
int COAP_send_put(char *endpoint, int endpoint_len, char*payload, int payload_len, char *response);
int COAP_send_post(char *endpoint, int endpoint_len, char*payload, int payload_len, void (*callback)(char*, int));
int COAP_set_server_addr(char *addr, int len);
void COAP_free(void);

#endif
