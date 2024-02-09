#ifndef ARP_SNIFFER_H
#define ARP_SNIFFER_H

#include "ARP_Headers.h"

int                 init_capturing(const char* const if_name);
size_t              capture(int sock_fd, unsigned char* const buf, size_t buf_size);
void                extract_arp_header(const unsigned char* const pkt_buf);
void                extract_arp_payload(const unsigned char* const pkt_buf);

#endif // ARP_SNIFFER_H