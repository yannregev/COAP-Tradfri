#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "file_handler.h"

#define CREDENTIALS_PATH "./Credentials.txt"

int LoadCredentials(struct Credentials *cred)
{
	FILE *f;
	char ch;
	int i = 0;
	cred->identity = malloc(100);
	cred->key = malloc(100);

	memset(cred->identity, '\0', 100);
	memset(cred->key, '\0', 100);

	if ((f = fopen(CREDENTIALS_PATH, "rb")) == NULL)
	{
		fprintf(stderr, "Failed to  open %s!\n", CREDENTIALS_PATH);
		return -1;
	} 

	while ((ch = fgetc(f)) != ' ' && i < 100-1)
	{
		cred->identity[i++] = ch;
	}
	i = 0;
	while ((ch = fgetc(f)) != ' ' && i < 100-1)
	{
		cred->key[i++] = ch;
	}



	cred->identity = realloc(cred->identity, strlen(cred->identity)+1);
	cred->key = realloc(cred->key, strlen(cred->key)+1);
	printf("identity: %s\nkey: %s\n", cred->identity, cred->key);

	fclose(f);
	return 0;
}

int StoreCredentials(const struct Credentials cred)
{

	FILE *f;

	if ((f = fopen(CREDENTIALS_PATH, "wb")) == NULL)
	{
		fprintf(stderr, "Failed to  open %s!\n", CREDENTIALS_PATH);
		return -1;
	} 

 	if (fwrite(cred.identity, sizeof(char), strlen(cred.identity),  f) != strlen(cred.identity))
 	{
 		fprintf(stderr, "Failed to write identity!\n");
 		fclose(f);
 		return -2;
 	}
 	fwrite(" ", sizeof(char), 1, f);

 	if (fwrite(cred.key, sizeof(char), strlen(cred.key),  f) != strlen(cred.key))
 	{
 		fprintf(stderr, "Failed to write identity!\n");
 		fclose(f);
 		return -3;
 	}
	fwrite(" ", sizeof(char), 1, f);

	fclose(f);
	return 0;
}