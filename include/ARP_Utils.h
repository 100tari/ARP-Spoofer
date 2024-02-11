#ifndef ARP_UTILS_H
#define ARP_UTILS_H

#include "ARP_Headers.h"
#include "ARP_Packet.h"

void                    get_my_mac(const char* const if_name, MAC my_mac);
void                    str_to_ip(const char* const str_ip, IP ip);
void                    get_interface_index(const char* const if_name, struct sockaddr_ll* intrfce);

#endif // ARP_UTILS_H