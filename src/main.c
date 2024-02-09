#include "ARP_Headers.h"
#include "ARP_Sniffer.h"

int main()
{
    unsigned char buff[ETH_FRAME_LEN * sizeof(char)] = {0};
    int sock_raw;

    sock_raw = init_capturing("wlan0");

    while(1)
    {
        capture(sock_raw, buff, ETH_FRAME_LEN);
        extract_arp_header(buff);
        extract_arp_payload(buff);
        printf("-----------------------------------------\n");
    }
    
}