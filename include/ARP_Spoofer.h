#ifndef ARP_SPOOFER_H
#define ARP_SPOOFER_H

#include "ARP_Headers.h"
#include "ARP_Packet.h"
#include "ARP_Log.h"

#define RECV_TIME_OUT                       10            // seconds    
#define SEND_TIME_OUT                       60 
#define SEND_DELAY                          5      

struct spoofer
{
    int                     sock_fd;
    struct sockaddr_ll*     interfc;
    IP                      frst_ip;
    MAC                     frst_mc;
    IP                      scnd_ip;
    MAC                     scnd_mc;
    MAC                     my_mac;
};

struct spoofer*     init_spoofing(const char* const if_name, const IP frst_ip, const IP scnd_ip, const MAC my_mac);

void                get_targets_mac(const struct spoofer* spoofer);

void                send_spoofed_ip(const struct spoofer* const spoofer);

void                free_spoofer(struct spoofer* spoofer);

#endif // ARP_SPOOFER_H