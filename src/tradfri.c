
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
	Credentials_t credentials;
	credentials.identity = identity;
	credentials.key = key;
	StoreCredentials(credentials);
}

int TradfriInit()
{
    // Seed the random number generator
    srand(time(NULL));
	Credentials_t credentials;
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

int TradfriGetLamp(char* lampId, char *response)
{
	int len;
	int endpointLen = strlen(lampId) + strlen(DEFAULT_PATH);
	char endpoint[endpointLen + 1];
	snprintf(endpoint, sizeof(endpoint), "%s%s", DEFAULT_PATH, lampId);
	len = CoapGetRequest(endpoint, strlen(endpoint), response);
	return len;
}

int TradfriDimLamp(char* lampId, uint8_t dim, char* response)
{
	const uint8_t MAX_DIM_LEN = 3; // Dim can only be upto 3 digits long

	int endpointLen = strlen(lampId) + strlen(DEFAULT_PATH) + 1;
	int payloadLen = strlen(DIM_LAMP_PAYLOAD) + MAX_DIM_LEN + 1;

	char endpoint[endpointLen];
	char payload[payloadLen];

	snprintf(endpoint, sizeof(endpoint), "%s%s", DEFAULT_PATH, lampId);
	snprintf(payload, sizeof(payload), DIM_LAMP_PAYLOAD, dim);
    return CoapPutRequest(endpoint, strlen(endpoint), payload, strlen(payload), response);
}

int TradfriTurnOnLamp(char* lampId, char *response)
{
	int endpointLen = strlen(lampId) + strlen(DEFAULT_PATH) + 1;
	char endpoint[endpointLen];
	
	snprintf(endpoint, sizeof(endpoint), "%s%s", DEFAULT_PATH, lampId);
    return CoapPutRequest(endpoint, strlen(endpoint), TURN_ON_LAMP_PAYLOAD, strlen(TURN_ON_LAMP_PAYLOAD), response);
}

int TradfriTurnOffLamp(char* lampId, char *response)
{
	int endpointLen = strlen(lampId)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpointLen];

	snprintf(endpoint, sizeof(endpoint), "%s%s", DEFAULT_PATH, lampId);
	return CoapPutRequest(endpoint, strlen(endpoint), TURN_OFF_LAMP_PAYLOAD, strlen(TURN_OFF_LAMP_PAYLOAD), response);
}

int TradfriSetLampColor(char* lampId, uint64_t color_hex, char *response)
{
	const int MAX_COLOR_HEX_LEN = 6;
	int endpointLen = strlen(lampId)+strlen(DEFAULT_PATH) + 1;
	char endpoint[endpointLen];
	char payload[strlen(COLOR_LAMP_PAYLOAD) + MAX_COLOR_HEX_LEN + 1];

	snprintf(endpoint, sizeof(endpoint), "%s%s", DEFAULT_PATH, lampId);
	snprintf(payload, strlen(COLOR_LAMP_PAYLOAD) + 7, COLOR_LAMP_PAYLOAD, (uint32_t)color_hex);
	return CoapPutRequest(endpoint, strlen(endpoint), payload, strlen(payload), response);
}