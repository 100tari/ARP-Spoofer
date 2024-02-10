#include "ARP_Headers.h"
#include "ARP_Sniffer.h"

int main()
{
    unsigned char buff[ETH_FRAME_LEN * sizeof(char)] = {0};
    size_t buf_size;
    int sock_raw;

    sock_raw = init_capturing("wlan0");

    while(1)
    {
        buf_size = capture(sock_raw, buff, ETH_FRAME_LEN);
        sniff_arp_pkt(buff, buf_size);
    }
    
}