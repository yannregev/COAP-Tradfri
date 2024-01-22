#ifndef FILE_HANDER_H_
#define FILE_HANDER_H_

struct Credentials
{
	char *identity;
	char *key;
};

int load_credentials(struct Credentials *cred);

int store_credentials(struct Credentials cred);

#endif //FILE_HANDER_H_