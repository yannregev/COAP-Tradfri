#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <Winsock2.h>
#include <Ws2tcpip.h>


#include "coap_handler.h"

#define UNUSED(x) (void)(x)


#define COAP_PORT "5684" // COAP port is always 5684?

#define TOKEN_LEN 8
#define ID_LEN    2

#define GET 	1
#define POST 	2
#define PUT 	3

typedef struct {
    uint8_t version_type_token;
    uint8_t code;
    uint16_t message_id;
} CoapHeader;

struct COAP_CTX_t *ctx;
WSADATA wsaData;
int sockfd;

/**
 * Generate a random hex, used for token
 **/
static void GenerateRandomArray(int size, uint8_t *hexArray) 
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

static void PrintResCode(int res_code) 
{
    printf("Code: ");
    switch(res_code)
    {
    case 0x85:
        printf("4.05 Method not allowed\n");
        break;
    case 0x84:
        printf("4.04 Not found\n");
        break;
    case 0x45:
        printf("2.05 Content\n");
        break;
    case 0x44:
        printf("2.04 Changed\n");
        break;
    case 0xa0:
        printf("5.00 Internal server error\n");
        break;
    default:
        printf("Unknown\n");
    }
}

/**
 *  Parse the header of coap response
 *  @param response - the coap response
 *  @param len - length of the response, will be decreamented
 **/
static void parse_response_header(uint8_t **response, int *len)
{
    // Strip header, Maybe do some extra checks ?
    // For a start skip all until data
    uint8_t res_header = *(*response)++;
    (*len)--;
    uint8_t res_token_len = res_header & 0x0F;
    uint8_t res_code = *(*response)++;
    PrintResCode(res_code);
    (*len)--;
    uint16_t res_msg_id = (*(*response) << 8) | *(*response);
    UNUSED(res_msg_id);
    (*response)+=2;
    (*len) -=2;
    uint8_t res_token[res_token_len];
    UNUSED(res_token);
    for (int i = 0; i < res_token_len; i++)
    {
        res_token[i] = *(*response)++;
        (*len)--;
    }
    // Discard options
    while ((uint8_t)*(*response) != 0xFF && *len != 0) 
    {
        // Extract the length of the option
        uint8_t optionDelta = (*(*response) & 0xF0);

        // Extract the length of the option value
        uint8_t optionLength = (*(*response) & 0x0F);
        (*response)++;
        (*len)--;

        //Read option data
        uint8_t option_data[optionLength];
        for (int i = 0; i < optionLength; i++)
        {
            if ((uint8_t)*(*response) == 0xFF) return; // Sometimes option length is shorter than what it says, arggh
            option_data[i] = *(*response)++;
            (*len)--;
        }
        if (optionDelta == 0xC0) 
        { 
            printf("Content-type: Application/");
            if (option_data[0] == 0x32)
            {
                printf("json\n");
            }
        }
    }
}

static int CreateCoapHeader(uint8_t *buf, int request_type, char *endpoint, int endpoint_len)
{
    uint8_t token[TOKEN_LEN];
    uint8_t msg_id[ID_LEN];
    int len = 0;

    GenerateRandomArray(TOKEN_LEN, token);
    GenerateRandomArray(ID_LEN, msg_id);

    CoapHeader header;
    header.version_type_token = 0x48;
    header.code = request_type;
    header.message_id = (msg_id[0] << 8) | msg_id[1];
    
    memcpy(buf, (uint8_t*)&header, 4);
    len += 4;
    memcpy(buf + len, token, 8);
    len += 8;

    if (endpoint_len > 269)
    {
        //Should not happend with tradfi communication
    }
    else if (endpoint_len > 13)
    {
        //Should not happend with tradfi communication
    }
    else
    {
        char s[endpoint_len];
        memcpy(s, endpoint, endpoint_len+1);
        s[endpoint_len] = '\0';
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
    return len;
}

/**
 * Callback function used for DTLS psk handshake
 * Uses the pre-shared key and identity
 **/
unsigned int PskClientCallback(SSL *ssl, const char *hint, char *identity,
                                 unsigned int max_identity_len,
                                 unsigned char *psk,
                                 unsigned int max_psk_len) {
    const char *psk_identity = ctx->psk_identity; // Your PSK identity
    const char *psk_key = ctx->psk_key; // Your PSK value in hexadecimal format
    long key_len = ctx->psk_len;
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

int CoapConnect(void)
{
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // Connect to the server
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
 	if (getaddrinfo(ctx->server_addr, COAP_PORT, &hints, &res) != 0) {
        fprintf(stderr, "getaddrinfo failed\n");
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        WSACleanup();
        return 2;
    }

    // Create a TCP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed\n");
        freeaddrinfo(res);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        WSACleanup();
        return 3;
    }

    if (connect(sockfd, res->ai_addr, (int)res->ai_addrlen) != 0) {
        fprintf(stderr, "Socket connection failed\n");
        freeaddrinfo(res);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        WSACleanup();
        return 4;
    }

    // Attach the socket to the SSL structure
    SSL_set_fd(ctx->ssl, sockfd);

    // Perform the TLS handshake
    if (SSL_connect(ctx->ssl) <= 0) {
        fprintf(stderr, "SSL handshake failed\n");
        ERR_print_errors_fp(stderr);
        closesocket(sockfd);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        WSACleanup();
        return 5;
    }
    freeaddrinfo(res);
    return 0;
}

int CoapInit(void)
{
    if (ctx != NULL)
    {
        fprintf(stderr, "COAP_init called twice!\n");
        return 1;
    }
	ctx = (struct COAP_CTX_t*)malloc(sizeof(struct COAP_CTX_t));
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
        return 2;
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
        return 3;
    }

    // Set the options compatible with Tradfri
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | SSL_OP_NO_EXTENDED_MASTER_SECRET | SSL_OP_NO_TICKET | SSL_OP_NO_ENCRYPT_THEN_MAC);
    // Set PSK callback
    SSL_CTX_set_psk_client_callback(ctx->ssl_ctx, PskClientCallback);

    SSL_CTX_set_security_level(ctx->ssl_ctx, 0);	// Tradfri uses DTLSv_1.2 requiring the use of less secure communication

    ctx->ssl = SSL_new(ctx->ssl_ctx);
    if (!ctx->ssl) {
        printf("Error creating SSL\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx->ssl_ctx);
        return 4;
    }

    

	return 0;
}

int CoapSetPskKey(char *key, int len)
{
	if (ctx == NULL) return 1;
	if (len <= 0) return 2;
	ctx->psk_len = len;
	ctx->psk_key = malloc(len+1);

	memcpy(ctx->psk_key, key, len);
    ctx->psk_key[len] = '\0';
	return 0;
}

int CoapSetPskIdentity(char *identity, int len)
{
	if (ctx == NULL) return 1;
	if (len <= 0) return 2;
	ctx->identity_len = len;
	ctx->psk_identity = malloc(len+1);
	memcpy(ctx->psk_identity, identity, len);
    ctx->psk_identity[len] = '\0';
	return 0;
}

int CoapSetServerAddr(char *addr, int len)
{
	if (ctx == NULL) return 1;
	if (len <= 0) return 2;
	ctx->addr_len = len;
	ctx->server_addr = malloc(len+1);
	memcpy(ctx->server_addr, addr, len);
    ctx->server_addr[len] = '\0';
	return 0;
}


int CoapGetRequest(char *endpoint, int endpoint_len, char *response)
{
	if (ctx->psk_key == NULL || ctx->server_addr == NULL || ctx->psk_identity == NULL) { return 1;}
	
	int rc;
	
	uint8_t buf[1024]; //Should be enough
	int len = CreateCoapHeader(buf, GET, endpoint, endpoint_len);

	

	rc = SSL_write(ctx->ssl, buf, len);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return -1;
    }

    rc = SSL_read(ctx->ssl, buf, sizeof(buf) - 1);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return -2;
    }

    uint8_t *ptr = buf;
    parse_response_header(&ptr, &rc);
    ptr++;
    rc--;
    if (rc > 0)
    {
        memcpy(response, ptr, rc); 
        response[rc] = '\0';
    }
    

    return rc;
}

int CoapPutRequest(char *endpoint, 
        int endpoint_len, 
            char*payload,    
                int payload_len,
                    char *response)
{
    if (ctx->psk_key == NULL || ctx->server_addr == NULL || ctx->psk_identity == NULL) { return 1;}
    int rc;
    
    uint8_t buf[1024]; //Should be enough
    int len = CreateCoapHeader(buf, PUT, endpoint, endpoint_len);
    
    buf[len++] = 0X10; // Plain text option
    buf[len++] = 0xFF; // Payload marker
    memcpy(buf + len, payload, payload_len);
    len += payload_len;

    rc = SSL_write(ctx->ssl, buf, len);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return -1;
    }

    rc = SSL_read(ctx->ssl, buf, sizeof(buf) - 1);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return -2;
    }

    uint8_t *ptr = buf;
    parse_response_header(&ptr, &rc); 
    ptr++;
    rc--;
    if (rc > 0)
    {
        memcpy(response, ptr, rc); 
        response[rc] = '\0'; 
    }
    return rc;
}


int CoapPostRequest(char *endpoint, 
        int endpoint_len, 
            char*payload,    
                int payload_len,
                    char *response)
{
    if (ctx->psk_key == NULL || ctx->server_addr == NULL || ctx->psk_identity == NULL) { return 1;}
    int rc;
    
    uint8_t buf[1024]; //Should be enough
    int len = CreateCoapHeader(buf, POST, endpoint, endpoint_len);

    buf[len++] = 0X10; // Plain text option
    buf[len++] = 0xFF; // Payload marker
    memcpy(buf + len, payload, payload_len);
    len += payload_len;

    rc = SSL_write(ctx->ssl, buf, len);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return -1;
    }

    rc = SSL_read(ctx->ssl, buf, sizeof(buf) - 1);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ctx->ssl);
        SSL_CTX_free(ctx->ssl_ctx);
        close(sockfd);
        return -2;
    }

    uint8_t *ptr = buf;
    parse_response_header(&ptr, &rc); 
    ptr++;
    rc--; 
    if (rc > 0)
    {
        memcpy(response, ptr, rc); 
        response[rc] = '\0'; 
    }
    return rc;
}

void CoapFree(void)
{
    SSL_shutdown(ctx->ssl);
    closesocket(sockfd);
    WSACleanup();
	if (ctx->psk_identity) free(ctx->psk_identity);
	if (ctx->psk_key) free(ctx->psk_key);
    if (ctx->server_addr) free(ctx->server_addr);
    if (ctx->ssl) SSL_free(ctx->ssl);
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    if (ctx) 
    {
        free(ctx);
        ctx = NULL;
    }
}

