
#include "tradfri.h"
#include "coap_handler.h"
#include "file_handler.h"

#define TURN_ON_LAMP_PAYLOAD "{\"3311\": [{ \"5850\": 1 }]}"
#define TURN_OFF_LAMP_PAYLOAD "{\"3311\": [{ \"5850\": 0 }]}"

#define DIM_LAMP_PAYLOAD "{\"3311\": [{ \"5851\": %d }]}"
#define COLOR_LAMP_PAYLOAD "{\"3311\": [{ \"5706\": \"%06x\" }]}"

#define REGISTER_ENDPOINT "15011/9063"
#define DEFAULT_PATH "15001/"

static char* RetrieveKey(char* data, int len)
{
	if (strncmp(data, "{\"9091\":\"", strlen("{\"9091\":\"")) != 0)
	{
		fprintf(stderr, "Error, String does not contain 9091!\n");
		exit(1);
	}
	char *first;
	char *end;
	if ((first = strchr(data, ':')) == NULL)
	{
		fprintf(stderr, "Critical error registering identity!\n");
		exit(1);
	}
	first += 2; // skip (:")
	if ((end = strchr(first, '"')) == NULL)
	{
		fprintf(stderr, "Critical error registering identity!\n");
		exit(1);
	}

	size_t keyLen = end - first + 1;
	char *key = (char*)malloc(keyLen);
	strncpy(key,first, keyLen);
	key[keyLen-1] = '\0';
	return key;
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
 *	TODO: Read security key from user
 **/
static void TradfriRegisterIdentity(void)
{
	char payload[100];
	char response[100];
	char identity[15];
	char ipAddress[20];
	char key[100];

	// TODO check IP address

	fprintf(stdout, "Enter tradfri security key:\n");
	fgets(key, 100, stdin);
	key[strcspn(key, "\n")] = 0;
	GenerateIdentity(identity, 14);
	identity[14] = '\0';

	int len = sprintf(payload, "{\"9090\" : \"%s\"}", identity);
	printf("payload = %s\n\n",payload);
	CoapSetPskKey(key, strlen(key));
	CoapSetPskIdentity(identity, strlen(identity));

	//TODO: connect to server


	GetIpAddress(ipAddress, 100);
	CoapSetServerAddr(ipAddress, strlen(ipAddress));
	assert(CoapConnect() == 0);

	len = CoapPostRequest(REGISTER_ENDPOINT, strlen(REGISTER_ENDPOINT), payload, len, response);
	
	//TODO: Disconnect from server

	free(credentials.key);
	free(credentials.identity);
	CoapDisconnect();

	key = RetrieveKey(response, len);
	Credentials_t credentials;
	credentials.identity = identity;
	credentials.key = key;

	printf("identity = %s, key %s\n", identity, key);

	StoreCredentials(credentials);
	CoapSetPskKey(key, strlen(key));
}

int TradfriInit()
{
    // Seed the random number generator
    srand(time(NULL));
	FileHandlerInit();
	Credentials_t credentials;
	assert(CoapInit() == 0);
	if (GetCredentials(&credentials) != 0)
	{
		TradfriRegisterIdentity();
	}
	else
	{
		CoapSetPskKey(credentials.key, strlen(credentials.key));
		CoapSetPskIdentity(credentials.identity, strlen(credentials.identity));
	}
	char ipAddress[100];
	GetIpAddress(ipAddress, 100);
	CoapSetServerAddr(ipAddress, strlen(ipAddress));
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