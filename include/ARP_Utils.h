#ifndef ARP_UTILS_H
#define ARP_UTILS_H

#include "ARP_Headers.h"
#include "ARP_Packet.h"

void            get_my_mac(const char* const if_name, MAC my_mac);

#endif // ARP_UTILS_H