#ifndef TRADFRI_H
#define TRADFRI_H

#include <stdint.h>

int TradfriInit();
void TradfriFree();
int TradfriGetAllLamps(char* response);
int TradfriGetLamp(char* lampId, char *response);
int TradfriTurnOnLamp(char* lampId, char* response);
int TradfriTurnOffLamp(char* lampId, char* response);
int TradfriDimLamp(char* lampId, int dim, char* response);
int TradfriSetLampColor(char* lampId, uint64_t color_hex, char *response);
#endif