#ifndef ARP_SPOOFER_H
#define ARP_SPOOFER_H

#include "ARP_Headers.h"
#include "ARP_Packet.h"
#include "ARP_Log.h"

int init_spoofing(const char* const if_name);

void broadcast_spoofed_ip(MAC my_mac, IP spoofed_ip, IP target_ip, struct sockaddr_ll* sending_if, int sock_fd);

void get_target_mac(int sock_fd, IP target_ip, MAC target_mac);

void send_spoofed_ip(MAC my_mac, IP spoofed_ip, MAC target_mac, IP target_ip, struct sockaddr_ll* sending_if, int sock_fd);

#endif // ARP_SPOOFER_H