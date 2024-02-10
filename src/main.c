#include "ARP_Headers.h"
#include "ARP_Sniffer.h"
#include "ARP_Packet.h"
#include "ARP_Spoofer.h"
#include "ARP_Log.h"
#include "ARP_Utils.h"

int main(int args, char* argv[])
{
    IP ip;

    str_to_ip(argv[1], ip);

    LOG(IP_FORMAT(ip));
}