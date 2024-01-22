#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "file_handler.h"

#define CREDENTIALS_PATH "Credentials.txt"

int load_credentials(struct Credentials *cred)
{
	FILE *f;
	char ch;
	int i = 0;
	cred->identity = malloc(100);
	cred->key = malloc(100);

	if ((f = fopen(CREDENTIALS_PATH, "rb")) == NULL)
	{
		fprintf(stderr, "Failed to  open %s!\n", CREDENTIALS_PATH);
		return -1;
	} 

	while ((ch = fgetc(f)) != '\0' && i < 100-1)
	{
		cred->identity[i++] = ch;
	}
	cred->identity[i] = '\0';
	i = 0;
	while ((ch = fgetc(f)) != '\0' && i < 100-1)
	{
		cred->key[i++] = ch;
	}
	cred->key[i] = '\0';

	cred->identity = realloc(cred->identity, strlen(cred->identity+1));
	cred->key = realloc(cred->key, strlen(cred->key+1));

	fclose(f);
	return 0;
}

int store_credentials(const struct Credentials cred)
{

	FILE *f;

	if ((f = fopen(CREDENTIALS_PATH, "wb")) == NULL)
	{
		fprintf(stderr, "Failed to  open %s!\n", CREDENTIALS_PATH);
		return -1;
	} 

 	if (fwrite(cred.identity, sizeof(char), strlen(cred.identity)+1,  f) != strlen(cred.identity)+1)
 	{
 		fprintf(stderr, "Failed to write identity!\n");
 		fclose(f);
 		return -2;
 	}
 	if (fwrite(cred.key, sizeof(char), strlen(cred.key)+1,  f) != strlen(cred.key)+1)
 	{
 		fprintf(stderr, "Failed to write identity!\n");
 		fclose(f);
 		return -3;
 	}

	fclose(f);
	return 0;
}