#ifndef FILE_HANDER_H_
#define FILE_HANDER_H_

typedef struct {
	char *identity;
	char *key;
}Credentials_t;

int LoadCredentials(Credentials_t *cred);

int StoreCredentials(Credentials_t cred);

#endif //FILE_HANDER_H_