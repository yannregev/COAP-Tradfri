#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "file_handler.h"

//#define DEBUG

#define SETTINGS_PATH "./Settings.txt"

typedef void (*SettingHandler)(char* value);

typedef struct {
	char* key;
	char** value;
} Settings_t;

static char *ipAddress;
static char *identity;
static char *key;

Settings_t settings[] = {
	{"IP_ADDRESS=", &ipAddress},
	{"IDENTITY=", &identity},
	{"KEY=", &key},
};

int GetIpAddress(char *buffer, int size)
{
	if (strlen(ipAddress) > size) return -1;
	strncpy(buffer, ipAddress, size);
	return 0;
}

int GetCredentials(Credentials_t *cred)
{
	cred->identity = (char*)malloc(strlen(identity) + 1);
	cred->key = (char*)malloc(strlen(key) + 1);
	strncpy(cred->identity, identity, strlen(identity) + 1);
	strncpy(cred->key, key, strlen(key) + 1);
	return 0;
}

int StoreCredentials(const Credentials_t cred)
{
	if (key) free(key);
	if (identity) free(identity);

	identity = (char*)malloc(strlen(cred.identity) + 1);
	key = (char*)malloc(strlen(cred.key) + 1);
	strncpy(identity, cred.identity, strlen(cred.identity) + 1);
	strncpy(key, cred.key, strlen(cred.key) + 1);

	FILE *file = fopen(SETTINGS_PATH, "wb");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }
    
	for (int i = 0; i < sizeof(settings) / sizeof(Settings_t); ++i)
	{
		fprintf(file, "%s\"%s\"\n", settings[i].key, *settings[i].value);
	}

    fclose(file);
	return 0;
}

static void ParseSettings(const char* filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }
    char line[1024];

    // Read file line by line
    while (fgets(line, sizeof(line), file) != NULL) 
	{
        for (int i = 0; i < sizeof(settings) / sizeof(Settings_t); ++i)
		{
			if (strncmp(line, settings[i].key, strlen(settings[i].key)) == 0) 
			{
				char *start = strchr(line, '"');
				if (start) {
					char *end = strchr(start + 1, '"');
					if (end) {
						size_t length = end - start - 1;
						*settings[i].value = malloc(length + 1); 
						if (*settings[i].value) {
							
							strncpy(*settings[i].value, start + 1, length);
							(*settings[i].value)[length] = '\0';
						}
					}
				}
			}
		}
    }
    fclose(file);
}

void FileHandlerInit(void)
{
	ParseSettings(SETTINGS_PATH);

#ifdef DEBUG
	printf("%s\n%s\n%s\n", ipAddress, identity, key);
	exit(1);
#endif

	if (!ipAddress || !identity || !key)
	{
		printf("Missing settings!\n");
		exit(1);
	}

}