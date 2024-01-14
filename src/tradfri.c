
#include "tradfri.h"
#include "coap_handler.h"

//Not too elegant but works for now
#include "../Credentials.txt"


#define TURN_ON_LAMP_PAYLOAD "{\"3311\": [{ \"5850\": 1 }]}"
#define TURN_OFF_LAMP_PAYLOAD "{\"3311\": [{ \"5850\": 0 }]}"
#define REGISTER_ENDPOINT "15001/9063"
#define DEFAULT_PATH "15001/"

static void retrieve_key(char* data, int len)
{
	char *ptr;
	if ((ptr = strstr(data, "\"9091\":")) == NULL)
	{
		fprintf(stderr, "Critical error registering identity!\n");
		exit(1);
	}
	// TODO: Save key
}

static void generate_identity(char *hexArray, int size)
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

    	uint8_t r = (rand() % 26) + 65; 
        hexArray[i] = r;

    }
}

static void tradfri_register_identity(char* identity, char* key)
{
	char payload[100];
	int len = sprintf(payload, "{\"9090\" : \"%s\"}", identity);
	COAP_send_post(REGISTER_ENDPOINT, strlen(REGISTER_ENDPOINT), payload, len, retrieve_key);
}
/*
int tradfri_init()
{

	assert(COAP_init() == 0);
#if defined(PSK_KEY) && defined(PSK_IDENTITY)
	COAP_set_psk_key(PSK_KEY, strlen(PSK_KEY));
	COAP_set_psk_identity(PSK_IDENTITY, strlen(PSK_IDENTITY));
	COAP_set_server_addr(SERVER_IP, strlen(SERVER_IP));
#else

	fprintf(stderr,"No credentials found\n \
					Enter tradfri security key\n");
	char key_buf[100];
	sscanf("%s", key_buf, 100);
	char identity_buf[15];
	generate_identity(identity_buf, 14);
	identity[15] = '\0';
#endif

	return 0;
}
*/
int tradfri_get_all_lamps(char *response)
{
	int len;
	assert(COAP_init() == 0);
	COAP_set_psk_key(PSK_KEY, strlen(PSK_KEY));
	COAP_set_psk_identity(PSK_IDENTITY, strlen(PSK_IDENTITY));
	COAP_set_server_addr(SERVER_IP, strlen(SERVER_IP));
	len = COAP_send_get("15001", strlen("15001"), response);
	COAP_free();
	return len;
}

int tradfri_get_lamp(char* lamp_id, char *response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	
	assert(COAP_init() == 0);
	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);

	COAP_set_psk_key(PSK_KEY, strlen(PSK_KEY));
	COAP_set_psk_identity(PSK_IDENTITY, strlen(PSK_IDENTITY));
	COAP_set_server_addr(SERVER_IP, strlen(SERVER_IP));
	len = COAP_send_get(endpoint, strlen(endpoint), response);
	COAP_free();
	return len;
}

int tradfri_turn_on_lamp(char* lamp_id, char *response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	
	assert(COAP_init() == 0);
	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);

	COAP_set_psk_key(PSK_KEY, strlen(PSK_KEY));
	COAP_set_psk_identity(PSK_IDENTITY, strlen(PSK_IDENTITY));
	COAP_set_server_addr(SERVER_IP, strlen(SERVER_IP));
    len = COAP_send_put(endpoint, strlen(endpoint), TURN_ON_LAMP_PAYLOAD, strlen(TURN_ON_LAMP_PAYLOAD), response);
    COAP_free();
    return len;
}
int tradfri_turn_off_lamp(char* lamp_id, char *response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	
	assert(COAP_init() == 0);
	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);
	
	COAP_set_psk_key(PSK_KEY, strlen(PSK_KEY));
	COAP_set_psk_identity(PSK_IDENTITY, strlen(PSK_IDENTITY));
	COAP_set_server_addr(SERVER_IP, strlen(SERVER_IP));
	len = COAP_send_put(endpoint, strlen(endpoint), TURN_OFF_LAMP_PAYLOAD, strlen(TURN_OFF_LAMP_PAYLOAD), response);
	COAP_free();
	return len;
}