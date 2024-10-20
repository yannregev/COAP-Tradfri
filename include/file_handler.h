#ifndef FILE_HANDER_H_
#define FILE_HANDER_H_

typedef struct {
	char *identity;
	char *key;
}Credentials_t;

void FileHandlerInit(void);

int GetCredentials(Credentials_t *cred);

int GetIpAddress(char *buffer, int size);

int StoreCredentials(Credentials_t cred);

#endif //FILE_HANDER_H_