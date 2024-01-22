
#include "tradfri.h"
#include "coap_handler.h"
#include "file_handler.h"

//Not too elegant but works for now
//#include "../Credentials.txt"

#define SERVER_IP "192.168.0.10"

#define TURN_ON_LAMP_PAYLOAD "{\"3311\": [{ \"5850\": 1 }]}"
#define TURN_OFF_LAMP_PAYLOAD "{\"3311\": [{ \"5850\": 0 }]}"

#define DIM_LAMP_PAYLOAD "{\"3311\": [{ \"5851\": %d }]}"
#define COLOR_LAMP_PAYLOAD "{\"3311\": [{ \"5706\": \"%06x\" }]}"

#define REGISTER_ENDPOINT "15001/9063"
#define DEFAULT_PATH "15001/"

static char* retrieve_key(char* data, int len)
{
	fprintf(stderr, "Not implemented!\n");
	exit(1);

	char *ptr;
	char *tok;
	char *res;
	if ((ptr = strstr(data, "\"9091\":")) == NULL)
	{
		fprintf(stderr, "Critical error registering identity!\n");
		exit(1);
	}

	tok = strtok(ptr, "\""); // 9091
	tok = strtok(NULL, "\""); // :
	tok = strtok(NULL, "\""); // key

	res = malloc(strlen(tok)+1);
	strcpy(res, tok);
	return res;
}

static void generate_identity(char *hexArray, int size)
{
    for (int i = 0; i < size; ++i) {
        int randomType = rand() % 3;

        switch (randomType) {
            case 0:
                hexArray[i] = 'a' + rand() % 26; 
                break;
            case 1:
                hexArray[i] = 'A' + rand() % 26;
                break;
            case 2:
                hexArray[i] = '0' + rand() % 10;
                break;
        }
    }
}

/**
 *	TODO: Read security key from usere 
 **/
static void tradfri_register_identity(void)
{
	char payload[100];
	char response[100];
	char identity[15];
	char *key = malloc(100);

	fprintf(stdout, "Enter tradfri security key:\n");
	fgets(key, 100, stdin);
	key[strcspn(key, "\n")] = 0;
	generate_identity(identity, 14);
	identity[14] = '\0';


	int len = sprintf(payload, "{\"9090\" : \"%s\"}", identity);
	printf("payload = %s\n\n",payload);
	exit(1);
	COAP_set_psk_key(key, strlen(key));
	COAP_set_psk_identity(identity, strlen(identity));
	len = COAP_send_post(REGISTER_ENDPOINT, strlen(REGISTER_ENDPOINT), payload, len, response);
	key = retrieve_key(response, len);
	struct Credentials credentials;
	credentials.identity = identity;
	credentials.key = key;
	store_credentials(credentials);
}

int tradfri_init()
{
    // Seed the random number generator
    srand(time(NULL));
	struct Credentials credentials;
	assert(COAP_init() == 0);
	if (load_credentials(&credentials) != 0)
	{
		tradfri_register_identity();
	}
	else
	{
		COAP_set_psk_key(credentials.key, strlen(credentials.key));
		COAP_set_psk_identity(credentials.identity, strlen(credentials.identity));
	}

	COAP_set_server_addr(SERVER_IP, strlen(SERVER_IP));
	assert(COAP_connect() == 0);

	free(credentials.key);
	free(credentials.identity);

	return 0;
}

void tradfri_free()
{
	COAP_free();
}

int tradfri_get_all_lamps(char *response)
{
	return COAP_send_get("15001", strlen("15001"), response);
}

int tradfri_get_lamp(char* lamp_id, char *response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);

	len = COAP_send_get(endpoint, strlen(endpoint), response);
	return len;
}

int tradfri_dim_lamp(char* lamp_id, int dim, char* response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	char payload[strlen(DIM_LAMP_PAYLOAD) + 4];

	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);


	len = snprintf(payload, strlen(DIM_LAMP_PAYLOAD) + 4, DIM_LAMP_PAYLOAD, dim);
    len = COAP_send_put(endpoint, strlen(endpoint), payload, len, response);
    return len;
}

int tradfri_turn_on_lamp(char* lamp_id, char *response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	
	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);

    len = COAP_send_put(endpoint, strlen(endpoint), TURN_ON_LAMP_PAYLOAD, strlen(TURN_ON_LAMP_PAYLOAD), response);
    return len;
}

int tradfri_turn_off_lamp(char* lamp_id, char *response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	
	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);
	len = COAP_send_put(endpoint, strlen(endpoint), TURN_OFF_LAMP_PAYLOAD, strlen(TURN_OFF_LAMP_PAYLOAD), response);
	return len;
}

int tradfri_set_lamp_color(char* lamp_id, uint64_t color_hex, char *response, int res_len)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	char payload[strlen(COLOR_LAMP_PAYLOAD) + 7];

	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);

	len = snprintf(payload, strlen(COLOR_LAMP_PAYLOAD) + 7, COLOR_LAMP_PAYLOAD, (uint32_t)color_hex);
	len = COAP_send_put(endpoint, strlen(endpoint), payload, strlen(payload), response);
    return len;
}