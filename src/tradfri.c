
#include "tradfri.h"
#include "coap_handler.h"
#include "file_handler.h"

//Not too elegant but works for now
//#include "../Credentials.txt"

#define SERVER_IP "192.168.1.16"

#define TURN_ON_LAMP_PAYLOAD "{\"3311\": [{ \"5850\": 1 }]}"
#define TURN_OFF_LAMP_PAYLOAD "{\"3311\": [{ \"5850\": 0 }]}"

#define DIM_LAMP_PAYLOAD "{\"3311\": [{ \"5851\": %d }]}"
#define COLOR_LAMP_PAYLOAD "{\"3311\": [{ \"5706\": \"%06x\" }]}"

#define REGISTER_ENDPOINT "15001/9063"
#define DEFAULT_PATH "15001/"

static char* RetrieveKey(char* data, int len)
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

static void GenerateIdentity(char *hexArray, int size)
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
static void TradfriRegisterIdentity(void)
{
	char payload[100];
	char response[100];
	char identity[15];
	char *key = malloc(100);

	fprintf(stdout, "Enter tradfri security key:\n");
	fgets(key, 100, stdin);
	key[strcspn(key, "\n")] = 0;
	GenerateIdentity(identity, 14);
	identity[14] = '\0';


	int len = sprintf(payload, "{\"9090\" : \"%s\"}", identity);
	printf("payload = %s\n\n",payload);
	CoapSetPskKey(key, strlen(key));
	CoapSetPskIdentity(identity, strlen(identity));
	len = CoapPostRequest(REGISTER_ENDPOINT, strlen(REGISTER_ENDPOINT), payload, len, response);
	
	key = RetrieveKey(response, len);
	struct Credentials credentials;
	credentials.identity = identity;
	credentials.key = key;
	StoreCredentials(credentials);
}

int TradfriInit()
{
    // Seed the random number generator
    srand(time(NULL));
	struct Credentials credentials;
	assert(CoapInit() == 0);
	if (LoadCredentials(&credentials) != 0)
	{
		TradfriRegisterIdentity();
	}
	else
	{
		CoapSetPskKey(credentials.key, strlen(credentials.key));
		CoapSetPskIdentity(credentials.identity, strlen(credentials.identity));
	}

	CoapSetServerAddr(SERVER_IP, strlen(SERVER_IP));
	assert(CoapConnect() == 0);

	free(credentials.key);
	free(credentials.identity);

	return 0;
}

void TradfriFree()
{
	CoapFree();
}

int TradfriGetAllLamps(char *response)
{
	return CoapGetRequest("15001", strlen("15001"), response);
}

int TradfriGetLamp(char* lamp_id, char *response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);

	len = CoapGetRequest(endpoint, strlen(endpoint), response);
	return len;
}

int TradfriDimLamp(char* lamp_id, int dim, char* response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	char payload[strlen(DIM_LAMP_PAYLOAD) + 4];

	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);


	len = snprintf(payload, strlen(DIM_LAMP_PAYLOAD) + 4, DIM_LAMP_PAYLOAD, dim);
    len = CoapPutRequest(endpoint, strlen(endpoint), payload, len, response);
    return len;
}

int TradfriTurnOnLamp(char* lamp_id, char *response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	
	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);

    len = CoapPutRequest(endpoint, strlen(endpoint), TURN_ON_LAMP_PAYLOAD, strlen(TURN_ON_LAMP_PAYLOAD), response);
    return len;
}

int TradfriTurnOffLamp(char* lamp_id, char *response)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	
	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);
	len = CoapPutRequest(endpoint, strlen(endpoint), TURN_OFF_LAMP_PAYLOAD, strlen(TURN_OFF_LAMP_PAYLOAD), response);
	return len;
}

int TradfriSetLampColor(char* lamp_id, uint64_t color_hex, char *response, int res_len)
{
	int len;
	int endpoint_len = strlen(lamp_id)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpoint_len];
	char payload[strlen(COLOR_LAMP_PAYLOAD) + 7];

	strncpy(endpoint, DEFAULT_PATH, strlen(DEFAULT_PATH) + 1);
	strncat(endpoint, lamp_id, strlen(lamp_id) + 1);

	len = snprintf(payload, strlen(COLOR_LAMP_PAYLOAD) + 7, COLOR_LAMP_PAYLOAD, (uint32_t)color_hex);
	len = CoapPutRequest(endpoint, strlen(endpoint), payload, strlen(payload), response);
    return len;
}