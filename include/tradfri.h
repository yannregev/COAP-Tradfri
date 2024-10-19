#ifndef TRADFRI_H
#define TRADFRI_H

#include <stdint.h>

int TradfriInit();
void TradfriFree();
int TradfriGetAllLamps(char* response);
int TradfriGetLamp(char* lamp_id, char *response);
int TradfriTurnOnLamp(char* lamp_id, char* response);
int TradfriTurnOffLamp(char* lamp_id, char* response);
int TradfriDimLamp(char* lamp_id, int dim, char* response);
int TradfriSetLampColor(char* lamp_id, uint64_t color_hex, char *response);
#endif