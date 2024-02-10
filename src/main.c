#include "ARP_Headers.h"
#include "ARP_Sniffer.h"
#include "ARP_Packet.h"
#include "ARP_Log.h"

int main()
{
    // unsigned char buff[ETH_FRAME_LEN * sizeof(char)] = {0};
    // int sock_raw;

    // sock_raw = init_capturing("wlan0");

    // while(1)
    // {
    //     capture(sock_raw, buff, ETH_FRAME_LEN);
    //     extract_arp_header(buff);
    //     extract_arp_payload(buff);
    //     printf("-----------------------------------------\n");
    // }
    
    MAC sndr_mac = {1,2,3,4,5,6};
    MAC trgt_mac = {11,12,13,14,15,16};
    
    IP sndr_ip = {192,168,1,1};
    IP trgt_ip = {192,168,1,5};

    struct arppkt* pkt = make_arp_pkt(sndr_mac, sndr_ip, trgt_mac, trgt_ip, ARPOP_REQUEST);

    struct ethfrm* frm = make_eth_arp_frm(sndr_mac, trgt_mac, pkt);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    struct sockaddr_ll dst;
    dst.sll_ifindex = if_nametoindex("wlan0");

    __CheckErr(sendto(fd, frm, sizeof(*frm), 0, (const struct sockaddr*) &dst, sizeof(dst)) < 0,
    "Sending Failed\n");
}