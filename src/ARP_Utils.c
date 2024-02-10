#include "ARP_Utils.h"
#include "ARP_Log.h"

void
get_my_mac(const char* const if_name, MAC my_mac)
{   
    __CheckNull(my_mac);

    char  dir[] = "/sys/class/net/";
    char  str_mac[MAC_LEN * 3];

    strcat(dir, if_name);
    strcat(dir, "/address");

    int fd = open(dir, O_RDONLY);
    __CheckErr(fd < 0, "Openning Mac Address's File Failed\n");

    __CheckErr(read(fd, str_mac, MAC_LEN * 3) < 0,
        "Reading Mac Address Failed\n");

    sscanf(str_mac, "%x:%x:%x:%x:%x:%x", 
    (uint32_t*)&my_mac[0], (uint32_t*)&my_mac[1], (uint32_t*)&my_mac[2],
    (uint32_t*)&my_mac[3], (uint32_t*)&my_mac[4], (uint32_t*)&my_mac[5]);
}

void
str_to_ip(const char* const str_ip, IP ip)
{
    __CheckNull(str_ip);

    struct sockaddr_in tmp;
    inet_pton(AF_INET, str_ip, &(tmp.sin_addr));

    for(int i = IP_LEN-1 ; i >= 0 ; --i)
        ip[i] = tmp.sin_addr.s_addr >> i*8;

    __CheckErr(memcmp(ip, (IP) {0,0,0,0}, IP_LEN) == 0,
        "IP BAD FORMAT: IP incorrect format, it must be in format x.x.x.x which 0<=x<=255\n");
}