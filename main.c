#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/e_os2.h>

#define SERVER_IP "192.168.0.10"
#define ENDPOINT "/15001/65557"
static const char* BULBS = "15001";
#define SERVER_PORT "5684"


#if RAND_MAX == 0x7FFF
#define RAND_MAX_BITS 15
#elif RAND_MAX == 0x7FFFFFFF
#define RAND_MAX_BITS 31
#else
#error TBD code
#endif

unsigned int psk_client_callback(SSL *ssl, const char *hint, char *identity,
                                 unsigned int max_identity_len,
                                 unsigned char *psk,
                                 unsigned int max_psk_len) {
    const char *psk_identity = PSK_IDENTITY; // Your PSK identity
    const char *psk_key = PSK_KEY; // Your PSK value in hexadecimal format
    long key_len = strlen(PSK_KEY);
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
                       "psk buffer of callback is too small (%d) for key (%ld)\n",
                       max_psk_len, key_len);
            OPENSSL_free(key);
            return 0;
        }

        memcpy(psk, key, key_len);
        OPENSSL_free(key);


    return key_len; // Length of the PSK in bytes
}

void rand_buf(byte *dest, size_t size) {

    int r;
    int r_queue = 0;
    int r_bit_count = 0;

    for (size_t i = 0; i < size; i++) {
        r = 0;
        //printf("%3zu %2d %8x\n", i, r_bit_count, r_queue);
        if (r_bit_count < 8) {
            int need = 8 - r_bit_count;
            r = r_queue << need;
            r_queue = rand();
            r ^= r_queue;  // OK to flip bits already saved in `r`
            r_queue >>= need;
            r_bit_count = RAND_MAX_BITS - need;
        } else {
            r = r_queue;
            r_queue >>= 8;
            r_bit_count -= 8;
        }
        dest[i] = r;
    }

}

int sendCoAPPacket(const char *endpoint, const char *payload) 
{
    WSADATA wsaData;
    SSL_CTX* ctx = NULL;
    int sockfd, len, rc;
     char buf[1024];
    SSL *ssl = NULL;


    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Create a TCP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        printf("Error creating SSL context\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);


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
    if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1) {
        printf("Error setting cipher list\n");
        SSL_CTX_free(ctx);
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    //SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

    SSL_CTX_set_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | SSL_OP_NO_EXTENDED_MASTER_SECRET | SSL_OP_NO_TICKET | SSL_OP_NO_ENCRYPT_THEN_MAC);
    // Set PSK callback
    SSL_CTX_set_psk_client_callback(ctx, psk_client_callback);

    SSL_CTX_set_security_level(ctx,0);


    SSL_set_tlsext_host_name(ssl, SERVER_IP);
    // Create new SSL connection state
    ssl = SSL_new(ctx);

    // Connect to the server
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &res) != 0) {
        printf("getaddrinfo failed\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    if (connect(sockfd, res->ai_addr, (int)res->ai_addrlen) != 0) {
        printf("Socket connection failed\n");
        freeaddrinfo(res);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    // Attach the socket to the SSL structure
    SSL_set_fd(ssl, sockfd);

    // Perform the TLS handshake
    if (SSL_connect(ssl) <= 0) {
        printf("SSL handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    char token[8];
    rand_buf(token, 8);
    char *coap_header = "\x48\x01\x12\x02";
/*    
    //char *coap_get_request = "\x48\x01\x12\x02\x88\x08\xf3\xdb\x16\xda\x89\xf4\xb5\x31\x35\x30\x30\x31";
    strncat(coap_header, token, 100); // Add token
    strncat(coap_header, "\xb5", 100); // Add option
    strncat(coap_header, "15001", 100);
    int size_coap = 4+8+1+5;
    // Assemble CoAP packet
    memcpy(buf, coap_header, size_coap);
    len = size_coap;
*/
    memcpy(buf, coap_header, 4);
    memcpy(buf+4, token, 8);
    memcpy(buf+4+8, "\xb5", 1);
    memcpy(buf+4+8+1, "15001", 5);
    len = 4+8+1+5;
    rc = SSL_write(ssl, buf, len);
    if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return 1;
    }

    rc = SSL_read(ssl, buf, sizeof(buf) - 1);
       if (rc <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return 1;
    }

    printf("response: %s\n",buf);
    // Perform other operations with the SSL connection
    // (e.g., send/receive data)

    // Clean up

    int ret = SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(sockfd);
    WSACleanup();

    return 0;
}

int main()
{
    const char *endpoint = "/15001/65557"; // Example endpoint for a specific device (change the device ID)
    //const char *payload = "{\"3311\":[{\"5850\":0}]}"; // Payload to turn off a light
    const char *payload = "{ \"3311\": [{ \"5850\": 0 }] }"; // Payload to turn off a light
    

    sendCoAPPacket(endpoint, payload);
	

    return 0;
}


void requestId(void)
{


}