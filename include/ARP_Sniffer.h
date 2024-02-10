#ifndef ARP_SNIFFER_H
#define ARP_SNIFFER_H

#include "ARP_Headers.h"

int                 init_capturing(const char* const if_name);
size_t              capture(int sock_fd, unsigned char* const buf, size_t buf_size);
struct ethhdr*      extract_ether_header(const unsigned char* const pkt_buf);
struct arphdr*      extract_arp_header(const unsigned char* const pkt_buf);
struct arppld*      extract_arp_payload(const unsigned char* const pkt_buf);
int                 sniff_arp_pkt(const unsigned char* const pkt_buf, const size_t pkt_size);

#endif // ARP_SNIFFER_H