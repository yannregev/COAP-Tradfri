#ifndef TRADFRI_H
#define TRADFRI_H

#include <stdint.h>

int tradfri_init();
void tradfri_free();
int tradfri_get_all_lamps(char* response);
int tradfri_get_lamp(char* lamp_id, char *response);
int tradfri_turn_on_lamp(char* lamp_id, char* response);
int tradfri_turn_off_lamp(char* lamp_id, char* response);
int tradfri_dim_lamp(char* lamp_id, int dim, char* response);
int tradfri_set_lamp_color(char* lamp_id, uint64_t color_hex, char *response);
#endif