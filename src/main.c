#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "tradfri.h"

//Commands
#define GET_ALL "get-all"
#define GET "get"
#define TURN_OFF "turn-off"
#define TURN_ON "turn-on"
#define DIM "dim"
#define COLOR "color"
#define INPUT "input:"
#define EXIT "exit\n"

static int HandleGetAllCommand(char *arg, char *res)
{
	return TradfriGetAllLamps(res);
}

static int HandleDimCommand(char *arg, char *res) 
{
	char *lamp_id = strtok(arg, " ");
	int value = atoi(strtok(NULL, " "));
	if (value < 0 || value > 254) 
	{ 
		printf("Illegal dim value!\n");
		return -1;
	}
	return TradfriDimLamp(lamp_id, value, res);
}

static int HandleColorCommand(char *arg, char *res) 
{
	char *lamp_id = strtok(arg, " ");
	uint16_t value = strtol(strtok(NULL, " "), NULL, 16);
	return TradfriSetLampColor(lamp_id, value, res);
}

typedef int (*CommandFunc)(char *arg, char *res);

typedef struct {
	const char *command;
	CommandFunc func;
	int argOffset;
}Command_t;

Command_t commandTable[] = {
	{GET_ALL, HandleGetAllCommand, 0},
	{GET, TradfriGetLamp, strlen(GET) + 1},
	{TURN_OFF, TradfriTurnOffLamp, strlen(TURN_OFF) + 1},
	{TURN_ON, TradfriTurnOnLamp, strlen(TURN_ON) + 1},
	{DIM, HandleDimCommand, strlen(DIM) + 1},
	{COLOR, HandleColorCommand, strlen(COLOR) + 1},
};

static void parseAndExecuteCommand(char *input, char *res)
{
	for (int i = 0; i < sizeof(commandTable) / sizeof(Command_t); ++i)
	{
		const char* command = commandTable[i].command;
		if (strncmp(input, command, strlen(command)) == 0) 
		{
			commandTable[i].func(input + commandTable[i].argOffset, res);
			return;
		}
	}
}

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
	char res[1024] = {0};
	char input[100] = {0};
	TradfriInit();
	printOptions();

	fgets(input, 100, stdin);
	input[strcspn(input, "\n")] = '\0';	// Strip newline
	while (strncmp(input, "exit", 4) != 0)
	{
		parseAndExecuteCommand(input, res);
		printf("Response = %s\n", res);
		printf(INPUT);
		memset(input, '\0', 100);
		fgets(input, 100, stdin);
		input[strcspn(input, "\n")] = '\0';	// Strip newline
	}

	printf(EXIT);
	TradfriFree();
	return 0;
}
