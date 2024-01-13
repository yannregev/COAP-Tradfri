#include <stdio.h>
#include <string.h>

#include "tradfri.h"

static void printOptions(void)
{

	printf(	"Enter one of the following options:\n"
			"	*\"get-all\" : get all lamps registered with tradfri\n"
			"	*\"Turn-on-<lamp-id>\": Turn on a lamp\n"
			"	*\"Turn-off-<lamp-id>\": Turn on a lamp\n"
			"	*\"exit\": quit program\n"
			"input: ");

}

int main(int argc, char** argv)
{
	//tradfri_init();
/*	
	
	tradfri_get_all_lamps(res);
	printf("response = %s\n", res);
	tradfri_turn_on_lamp("15001/65557", res);
	printf("response = %s\n", res);
*/
	char res[1000];
	char input[1000];
	printOptions();

	fgets(input, 1000, stdin);
	while (strncmp(input, "exit", 4) != 0)
	{
		if (strncmp(input, "get-all", 7) == 0)
		{
			tradfri_get_all_lamps(res);
			printf("response = %s\n", res);
		}
		else if (strncmp(input, "turn-off", 8) == 0)
		{
			tradfri_turn_off_lamp("15001/65557", res);
			//printf("response = %s\n", res);
		}
		else if (strncmp(input, "turn-on", 7) == 0)
		{
			tradfri_turn_on_lamp("15001/65557", res);
			//printf("response = %s\n", res);
		}
		printf("input: ");
		fgets(input, 1000, stdin);
	}

	return 0;
}
