#ifndef COAP_HANDLER_H
#define COAP_HANDLER_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>


struct COAP_CTX_t
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


int CoapInit(void);
int CoapConnect(void);
int CoapSetPskKey(char *key, int len);
int CoapSetPskIdentity(char *identity, int len);
int CoapGetRequest(char *endpoint, int endpoint_len, char *response);
int CoapPutRequest(char *endpoint, int endpoint_len, char*payload, int payload_len, char *response);
int CoapPostRequest(char *endpoint, int endpoint_len, char*payload, int payload_len, char *response);
int CoapSetServerAddr(char *addr, int len);

void CoapFree(void);

#endif
