#ifndef FILE_HANDER_H_
#define FILE_HANDER_H_

struct Credentials
{
	char *identity;
	char *key;
};

int LoadCredentials(struct Credentials *cred);

int StoreCredentials(struct Credentials cred);

#endif //FILE_HANDER_H_