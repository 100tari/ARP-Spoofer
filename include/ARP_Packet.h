#ifndef ARP_PACKET_H
#define ARP_PACKET_H

#include "ARP_Headers.h"

#define MAC_FORMAT(X)           "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",X[0],X[1],X[2],X[3],X[4],X[5]
#define  IP_FORMAT(X)           "%u.%u.%u.%u", X[0], X[1], X[2], X[3]

#define MAC_LEN                 6
#define IP_LEN                  4

typedef uint8_t                 IP[IP_LEN];
typedef uint8_t                 MAC[MAC_LEN];

#define BROADCAST               (MAC) {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}

struct arppld
{
    MAC     SHA;                /* Sender Hardware Address */
    IP      SPA;                /* Sender Protocol Address */
    MAC     THA;                /* Target Hardware Address */
    IP      TPA;                /* Target Protocol Address */
} __attribute__((__packed__));

struct arppkt
{
    struct arphdr   arp_hdr;    /* Packet Header */
    struct arppld   arp_pld;    /* Packet Payload */
} __attribute__((__packed__));

struct ethfrm
{
    struct ethhdr   eth_hdr;    /* Frame Header */
    struct arppkt   eth_pld;    /* Frame Payload (Arp Packet) */
} __attribute__((__packed__));

struct arppkt* make_arp_pkt(MAC const sndr_mac, IP const sndr_ip,
                            MAC const trgt_mac, IP const trgt_ip, uint16_t op_cod);

struct ethfrm* make_eth_arp_frm(MAC const src_mac, MAC const dst_mac, struct arppkt* arppkt);

#endif // ARP_PACKET_H