#ifndef ARP_PACKET_H
#define ARP_PACKET_H

#include "ARP_Headers.h"

#define MAC_FORMAT(X)           "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",X[0],X[1],X[2],X[3],X[4],X[5]
#define  IP_FORMAT(X)           "%u.%u.%u.%u", X[0], X[1], X[2], X[3]

#define MAC_LEN                 6
#define IP_LEN                  4

typedef uint8_t                 IP[IP_LEN];
typedef uint8_t                 MAC[MAC_LEN];


struct arppld
{
    MAC     SHA;                /* Sender Hardware Address */
    IP      SPA;                /* Sender Protocol Address */
    MAC     THA;                /* Target Hardware Address */
    IP      TPA;                /* Target Protocol Address */
} __attribute__((__packed__));


#endif // ARP_PACKET_H