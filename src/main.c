#include "ARP_Headers.h"
#include "ARP_Sniffer.h"
#include "ARP_Packet.h"
#include "ARP_Spoofer.h"
#include "ARP_Log.h"
#include "ARP_Utils.h"

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
    
    // MAC sndr_mac = {0xDC, 0x21, 0x5C, 0x9C, 0xEA, 0x00};
    // // MAC trgt_mac = {11,12,13,14,15,16};
    
    // IP sndr_ip = {192,168,1,1};
    // IP trgt_ip = {192,168,43,1};

    // // struct arppkt* pkt = make_arp_pkt(sndr_mac, sndr_ip, trgt_mac, trgt_ip, ARPOP_REQUEST);

    // // struct ethfrm* frm = make_eth_arp_frm(sndr_mac, trgt_mac, pkt);

    // int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // struct sockaddr_ll dst;
    // dst.sll_ifindex = if_nametoindex("wlan0");

    // // __CheckErr(sendto(fd, frm, sizeof(*frm), 0, (const struct sockaddr*) &dst, sizeof(dst)) < 0,
    // // "Sending Failed\n");

    // broadcast_spoofed_ip(sndr_mac, sndr_ip, trgt_ip, &dst, fd);

    // MAC mac;
    // get_target_mac(fd, trgt_ip, mac);

    // printf(MAC_FORMAT(mac));

    // send_spoofed_ip(sndr_mac, sndr_ip, mac, trgt_ip, &dst, fd);

    MAC my_mac ;
    get_my_mac("wlan0", my_mac);

    LOG(MAC_FORMAT(my_mac));
}