#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <Winsock2.h>
#include <Ws2tcpip.h>


#include "coap_handler.h"

#include "../credentials.txt"

struct COAP_CTX *ctx = NULL;

#define COAP_PORT "5684" // COAP port is always 5684?

#define TOKEN_LEN 8

#define GET 	1
#define POST 	2
#define PUT 	3


/**
 * Generate a random hex, used for token
 **/
static void generateRandomArray(int size, uint8_t *hexArray) 
{
    if (size <= 0) 
    {
        printf("Size should be a positive integer.\n");
        return;
    }

    // Seed the random number generator
    srand(time(NULL));

    // Generate random hex values
    for (int i = 0; i < size; ++i) 
    {

    	uint8_t r = rand() % 256; // Generate random value between 0 and 15 (for one hex digit)
        hexArray[i] = r;

    }
}


/**
 * Callback function used for DTLS psk handshake
 * Uses the pre-shared key and identity
 **/
unsigned int psk_client_callback(SSL *ssl, const char *hint, char *identity,
                                 unsigned int max_identity_len,
                                 unsigned char *psk,
                                 unsigned int max_psk_len) {
    const char *psk_identity = ctx->psk_identity; // Your PSK identity
    const char *psk_key = ctx->psk_key; // Your PSK value in hexadecimal format
    long key_len = strlen(psk_key);
    unsigned char *key;

    snprintf(identity, max_identity_len, "%s", psk_identity);

    key = OPENSSL_hexstr2buf(psk_key, &key_len);
        if (key == NULL) {
            fprintf(stderr, "Could not convert PSK key '%s' to buffer\n",
                       psk_key);
            return 0;
        }
        if (max_psk_len > INT_MAX || key_len > (long)max_psk_len) {
            fprintf(stderr,
                       "PSK buffer of callback is too small (%d) for key (%ld)\n",
                       max_psk_len, key_len);
            OPENSSL_free(key);
            return 0;
        }

        memcpy(psk, key, key_len);
        OPENSSL_free(key);


    return key_len; // Length of the PSK in bytes
}

static int COAP_connect(WSADATA *wsaData, int *sockfd)
{
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Connect to the server
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
 	if (getaddrinfo(ctx->server_addr, COAP_PORT, &hints, &res) != 0) {
        printf("getaddrinfo failed\n");
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        closesocket(*sockfd);
        WSACleanup();
        return 2;
    }

    // Create a TCP socket
    *sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sockfd == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 3;
    }

    if (connect(*sockfd, res->ai_addr, (int)res->ai_addrlen) != 0) {
        printf("Socket connection failed\n");
        freeaddrinfo(res);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        closesocket(*sockfd);
        WSACleanup();
        return 4;
    }

    // Attach the socket to the SSL structure
    SSL_set_fd(ctx->ssl, *sockfd);

    // Perform the TLS handshake
    if (SSL_connect(ctx->ssl) <= 0) {
        printf("SSL handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        return 4;
    }
}

struct COAP_CTX* COAP_init()
{
	assert(ctx == NULL);	// Should not be called twice
	ctx = malloc(sizeof(struct COAP_CTX));
	ctx->psk_key = NULL;
	ctx->psk_identity = NULL;
	ctx->server_addr = NULL;

	SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx->ssl_ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        printf("Error creating SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ssl_ctx, DTLS1_2_VERSION);

    // Tradfri only supports several ciphers
   const char *cipher_list = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:" \
						    "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:" \
						    "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:" \
						    "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:" \
						    "TLS_PSK_WITH_AES_128_GCM_SHA256:" \
						    "TLS_PSK_WITH_AES_256_GCM_SHA384:" \
						    "TLS_PSK_WITH_AES_128_CCM_8:" \
						    "TLS_PSK_WITH_AES_256_CCM_8:" \
						    "TLS_PSK_WITH_AES_128_CCM:" \
						    "TLS_PSK_WITH_AES_256_CCM:";
    if (SSL_CTX_set_cipher_list(ctx->ssl_ctx, cipher_list) != 1) {
        printf("Error setting cipher list\n");
        SSL_CTX_free(ctx->ssl_ctx);
        return NULL;
    }

    // Set the options compatible with Tradfri
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | SSL_OP_NO_EXTENDED_MASTER_SECRET | SSL_OP_NO_TICKET | SSL_OP_NO_ENCRYPT_THEN_MAC);
    // Set PSK callback
    SSL_CTX_set_psk_client_callback(ctx->ssl_ctx, psk_client_callback);

    SSL_CTX_set_security_level(ctx->ssl_ctx, 0);	// Tradfri uses DTLSv_1.2 requiring the use of less secure communication

    ctx->ssl = SSL_new(ctx->ssl_ctx);
    if (!ctx->ssl) {
        printf("Error creating SSL\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx->ssl_ctx);
        return NULL;
    }
	return ctx;
}

int COAP_set_psk_key(struct COAP_CTX* ctx, char *key, int len)
{
	if (ctx == NULL) return 1;
	if (len <= 0) return 2;
	ctx->psk_len = len;
	ctx->psk_key = malloc(len);
	memcpy(ctx->psk_key, key, len);
	return 0;
}

int COAP_set_psk_identity(struct COAP_CTX* ctx, char *identity, int len)
{
	if (ctx == NULL) return 1;
	if (len <= 0) return 2;
	ctx->identity_len = len;
	ctx->psk_identity = malloc(len);
	memcpy(ctx->psk_identity, identity, len);
	return 0;
}

int COAP_set_server_addr(struct COAP_CTX* ctx, char *addr, int len)
{
	if (ctx == NULL) return 1;
	if (len <= 0) return 2;
	ctx->addr_len = len;
	ctx->server_addr = malloc(len);
	memcpy(ctx->server_addr, addr, len);
	return 0;
}


int COAP_send_get(struct COAP_CTX* ctx, char *endpoint, int endpoint_len, void (*callback)(char*, int))
{
	if (ctx->psk_key == NULL || ctx->server_addr == NULL || ctx->psk_identity == NULL) { return 1;}
	WSADATA wsaData;
    char *res_data;
	int sockfd, rc, offset;
	uint8_t token[TOKEN_LEN];
	uint8_t msg_id[2];
	
	uint8_t buf[1024]; //Should be enough
	int len = 0;

    generateRandomArray(TOKEN_LEN, token);
    generateRandomArray(2, msg_id);
    char *coap_header = "\x48\x01\x12\x02";
    memcpy(buf, coap_header, 4);
    len += 4;
    memcpy(buf+4, token, 8);
    len += 8;



    if (endpoint_len > 269)
    {

    }
    else if (endpoint_len > 13)
    {

    }
    else
    {
        char s[endpoint_len];
        memcpy(s, endpoint, endpoint_len);
        char *token = strtok(s, "/");
        uint8_t options = '\xB0';
        options |= strlen(token);
        memcpy(buf + len, &options, 1);
        len += 1;
        memcpy(buf + len, token, strlen(token));
        len += strlen(token);
        token = strtok(NULL, "/");
        if (token != NULL)
        {
            options = strlen(token);
            memcpy(buf + len, &options, 1);
            len += 1;
            memcpy(buf + len, token, strlen(token));
            len += strlen(token);
        }
    }

	COAP_connect(&wsaData, &sockfd);

	rc = SSL_write(ctx->ssl, buf, len);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return 1;
    }

    rc = SSL_read(ctx->ssl, buf, sizeof(buf) - 1);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return 2;
    }
    //Strip header, Maybe do some extra checks ?
    // For a start skip all until data
    uint8_t *ptr = buf;
    uint8_t res_header = *ptr++;
    uint8_t res_token_len = res_header & 0x0F;
    uint8_t res_code = *ptr++;
    uint16_t res_msg_id = (*ptr++ << 8) | *ptr;
    uint8_t res_token[res_token_len];
    for (int i = 0; i < res_token_len; i++)
    {
        res_token[i] = *ptr++;
    }
    // Discard options
    while (*ptr != 0xFF) 
    {
        // Extract the length of the option
        uint8_t optionDelta = (*ptr & 0xF0);

        // Extract the length of the option value
        uint8_t optionLength = (*ptr & 0x0F);
        ptr++;

        //Read option data
        uint8_t option_data[optionLength];
        for (int i = 0; i < optionLength; i++)
        {
            if (*ptr == 0xFF) break; // Sometimes option length is shorter than what it says, arggh
            option_data[i] = *ptr++;
        }

        if (optionDelta == 0xC0) { 
            printf("Content-type: Application/");
            if (option_data[0] == 0x32)
            {
                printf("json\n");
            }
        }
    }
    *ptr++;
    // Calculate the offset to the data
    ptrdiff_t size = ((char *)ptr) - ((char *)buf);
    size = rc - size;
    res_data = malloc(size);
    memcpy(res_data, ptr, size);

    if (callback != NULL) (*callback)(res_data, size);


    SSL_shutdown(ctx->ssl);
    closesocket(sockfd);
    WSACleanup();
}

int COAP_send_put(struct COAP_CTX* ctx, char *endpoint, int endpoint_len, char*payload, int payload_len, void (*callback)(char*, int))
{
    if (ctx->psk_key == NULL || ctx->server_addr == NULL || ctx->psk_identity == NULL) { return 1;}
    WSADATA wsaData;
    char *res_data;
    int sockfd, rc, offset;
    uint8_t token[TOKEN_LEN];
    uint8_t msg_id[2];
    
    uint8_t buf[1024]; //Should be enough
    int len = 0;

    generateRandomArray(TOKEN_LEN, token);
    generateRandomArray(2, msg_id);
    char *coap_header = "\x48\x03\x12\x02";
    memcpy(buf, coap_header, 4);
    len += 4;
    memcpy(buf+4, token, 8);
    len += 8;


    if (endpoint_len > 269)
    {
        // Won't really happen?
    }
    else if (endpoint_len > 13)
    {
        // Won't really happen?
    }
    else
    {
        //Split end point to several options
        char s[endpoint_len];
        memcpy(s, endpoint, endpoint_len);
        char *token = strtok(s, "/");
        uint8_t options = '\xB0';
        options |= strlen(token);
        memcpy(buf + len, &options, 1);
        len += 1;
        memcpy(buf + len, token, strlen(token));
        len += strlen(token);
        token = strtok(NULL, "/");
        if (token != NULL)
        {
            options = strlen(token);
            memcpy(buf + len, &options, 1);
            len += 1;
            memcpy(buf + len, token, strlen(token));
            len += strlen(token);
        }
    }
    buf[len++] = 0X10; // Plain text option
    buf[len++] = 0xFF; // Payload marker
    memcpy(buf + len, payload, payload_len);
    len += payload_len;

    COAP_connect(&wsaData, &sockfd);

    rc = SSL_write(ctx->ssl, buf, len);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return 1;
    }

    rc = SSL_read(ctx->ssl, buf, sizeof(buf) - 1);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return 2;
    }
    //Strip header, Maybe do some extra checks ?
    // For a start skip all until data
    uint8_t *ptr = buf;
    uint8_t res_header = *ptr++;
    uint8_t res_token_len = res_header & 0x0F;
    uint8_t res_code = *ptr++;
    uint16_t res_msg_id = (*ptr++ << 8) | *ptr;
    uint8_t res_token[res_token_len];
    for (int i = 0; i < res_token_len; i++)
    {
        res_token[i] = *ptr++;
    }
    while (*ptr != 0xFF) 
    {
        // Extract the length of the option
        uint8_t optionDelta = (*ptr & 0xF0);

        // Extract the length of the option value
        uint8_t optionLength = (*ptr & 0x0F);
        ptr++;

        //Read option data
        uint8_t option_data[optionLength];
        for (int i = 0; i < optionLength; i++)
        {
            if (*ptr == 0xFF) break; // Sometimes option length is shorter than what it says, arggh
            option_data[i] = *ptr++;
        }

        if (optionDelta == 0xC0) { 
            printf("Content-type: Application/");
            if (option_data[0] == 0x32)
            {
                printf("json\n");
            }
        }
    }
    *ptr++;
    ptrdiff_t size = ((char *)ptr) - ((char *)buf);
    size = rc - size;
    res_data = malloc(size);
    memcpy(res_data, ptr, size);

    if (callback != NULL) (*callback)(res_data, size);


    //SSL_shutdown(ctx->ssl);
    closesocket(sockfd);
    WSACleanup();
}

void COAP_free(struct COAP_CTX* ctx)
{
	if (ctx->psk_identity != NULL) free(ctx->psk_identity);
	if (ctx->psk_key != NULL) free(ctx->psk_key);
    SSL_free(ctx->ssl);
    SSL_CTX_free(ctx->ssl_ctx);
}


void cb_test(char* data, int len)
{
    printf("%s\n", data);
}

//Test main
int main(int argc, char** argv)
{
	struct COAP_CTX *ctx;

	ctx = COAP_init();

	COAP_set_psk_key(ctx, PSK_KEY, strlen(PSK_KEY));
	COAP_set_psk_identity(ctx, PSK_IDENTITY, strlen(PSK_IDENTITY));
	COAP_set_server_addr(ctx, SERVER_IP, strlen(SERVER_IP));

	COAP_send_get(ctx, "15001/65557", strlen("15001/65557"), cb_test);
    COAP_send_put(ctx, "15001/65557", strlen("15001/65557"), "{\"3311\": [{ \"5850\": 1 }]}", sizeof("{\"3311\": [{ \"5850\": 0 }]}"), cb_test);
    COAP_free(ctx);
}
