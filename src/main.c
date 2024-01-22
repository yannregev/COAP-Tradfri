#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "tradfri.h"

static void printOptions(void)
{

	printf(	"Enter one of the following options:\n"
			"	*\"get-all\" : get all lamps registered with tradfri\n"
			"	*\"get <lamp-id>\" : get data about a specific\n"
			"	*\"Turn-on <lamp-id>\": Turn on a lamp\n"
			"	*\"Turn-off <lamp-id>\": Turn on a lamp\n"
			"	*\"dim <lamp-id> <value>\": Turn on a lamp\n"
			"	*\"exit\": quit program\n"
			"input: ");

}

int main(int argc, char** argv)
{
	
	char *lamp_id;
	char res[1024];
	char input[100] = {0};
	uint64_t value;
	tradfri_init();
	printOptions();

	fgets(input, 100, stdin);
	input[strcspn(input, "\n")] = '\0';	// Strip newline
	while (strncmp(input, "exit", 4) != 0 && strncmp(input, "\0", 1) != 0)
	{
		if (strncmp(input, "get-all", 7) == 0)
		{
			tradfri_get_all_lamps(res);
			printf("response = %s\n", res);
		}
		else if (strncmp(input, "get ", 4) == 0)
		{
			tradfri_get_lamp(input+4, res);
			printf("response = %s\n", res);
		}
		else if (strncmp(input, "turn-off ", 9) == 0)
		{
			tradfri_turn_off_lamp(input+9, res);
			//printf("response = %s\n", res);
		}
		else if (strncmp(input, "turn-on ", 8) == 0)
		{
			tradfri_turn_on_lamp(input+8, res);
			//printf("response = %s\n", res);
		}
		else if (strncmp(input, "dim ", 4) == 0)
		{
			
			lamp_id = strtok(input+3, " ");
			value = atoi(strtok(NULL, " "));
			if (value < 0 || value > 254) 
			{ 
				printf("Illegal dim value!\n");
			}
			else
			{
				tradfri_dim_lamp(lamp_id, value, res);
				printf("response = %s\n", res);
			}

		}
		else if (strncmp(input, "color ", 6) == 0)
		{
			
			lamp_id = strtok(input+6, " ");
			value = strtol(strtok(NULL, " "), NULL, 16);
			{
				tradfri_set_lamp_color(lamp_id, value, res, 1024);
				printf("response = %s\n", res);
			}

		}
		printf("input: ");
		memset(input, '\0', 100);
		fgets(input, 100, stdin);
		input[strcspn(input, "\n")] = '\0';	// Strip newline
	}

	tradfri_free();
	return 0;
}
