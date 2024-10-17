#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "tradfri.h"

//Commands
#define GET_ALL "get-all"
#define GET "get "
#define TURN_OFF "turn-off "
#define TURN_ON "turn-on "
#define DIM "dim "
#define COLOR "color "
#define INPUT "input:"
#define EXIT "exit\n"

static void printOptions(void)
{

	printf(	"Enter one of the following options:\n"
			"	*\"get-all\" : get all lamps registered with tradfri\n"
			"	*\"get <lamp-id>\" : get data about a specific\n"
			"	*\"Turn-on <lamp-id>\": Turn on a lamp\n"
			"	*\"Turn-off <lamp-id>\": Turn off a lamp\n"
			"	*\"dim <lamp-id> <value>\": change the lamp dimmnes\n"
			"	*\"color <lamp-id> <hex>\": Change lamp color\n"
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
	while (strncmp(input, "exit", 4) != 0)
	{
		if (strncmp(input, GET_ALL, strlen(GET_ALL)) == 0)
		{
			tradfri_get_all_lamps(res);
			printf("response = %s\n", res);
		}
		else if (strncmp(input, GET, strlen(GET)) == 0)
		{
			tradfri_get_lamp(input + strlen(GET), res);
			printf("response = %s\n", res);
		}
		else if (strncmp(input, TURN_OFF, strlen(TURN_OFF)) == 0)
		{
			tradfri_turn_off_lamp(input + strlen(TURN_OFF), res);
			//printf("response = %s\n", res);
		}
		else if (strncmp(input, TURN_ON, strlen(TURN_ON)) == 0)
		{
			tradfri_turn_on_lamp(input + strlen(TURN_ON), res);
			//printf("response = %s\n", res);
		}
		else if (strncmp(input, DIM, strlen(DIM)) == 0)
		{
			
			lamp_id = strtok(input + strlen(DIM), " ");
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
		else if (strncmp(input, COLOR, strlen(COLOR)) == 0)
		{
			
			lamp_id = strtok(input + strlen(COLOR), " ");
			value = strtol(strtok(NULL, " "), NULL, 16);
			{
				tradfri_set_lamp_color(lamp_id, value, res, 1024);
				printf("response = %s\n", res);
			}

		}
		printf(INPUT);
		memset(input, '\0', 100);
		fgets(input, 100, stdin);
		input[strcspn(input, "\n")] = '\0';	// Strip newline
	}

	printf(EXIT);
	tradfri_free();
	return 0;
}
