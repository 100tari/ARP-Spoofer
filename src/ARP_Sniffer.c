#include "ARP_Sniffer.h"
#include "ARP_Log.h"
#include "ARP_Packet.h"


int 
init_capturing(const char* const if_name)
{
    int sock_raw;
    __CheckErr((sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0,
        "Socket Initilizing Failed\n");

   if(if_name != NULL)
   {
     __CheckErr(setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)) < 0,
        "Socket Option Setting Failed\n");
   }

    return sock_raw;
}

size_t
capture(int sock_fd, unsigned char* const buf, size_t buf_size)
{
    size_t recv_size;
    __CheckErr((recv_size = recv(sock_fd, buf, buf_size, 0)) < 0,
        "Socket Capturing Failed\n");

    return recv_size;
}


struct ethhdr*
extract_ether_header(const unsigned char* const pkt_buf)
{
    struct ethhdr* eth = (struct ethhdr*) (pkt_buf);
    __CheckNull(eth);

    char eth_src_mac[MAC_LEN * 3 * sizeof(char)];
    char eth_dst_mac[MAC_LEN * 3 * sizeof(char)];
    char eth_pro_typ[16 * sizeof(char)];

    sprintf(eth_src_mac, MAC_FORMAT(eth->h_source));
    sprintf(eth_dst_mac, MAC_FORMAT(eth->h_dest));
    sprintf(eth_pro_typ, ntohs(eth->h_proto)==ETH_P_ARP ? "ARP (0x0806)" : 
                         ntohs(eth->h_proto)==ETH_P_IP ? "IPv4 (0x0800)" :  
                         "unknown");

    LOG(BOLD DYEL"[Ethernet Header]\n"NORM);
    LOG(DYEL"\t[+] Source MAC:\t\t\t%s\n",              eth_src_mac)      
    LOG("\t[+] Destination MAC:\t\t%s\n",               eth_dst_mac); 
    LOG("\t[+] Type:\t\t\t%s\n"NORM,                  eth_pro_typ);

    return eth;
}

struct arphdr*
extract_arp_header(const unsigned char* const pkt_buf)
{
    struct ethhdr* eth = (struct ethhdr*) (pkt_buf);
    __CheckNull(eth);

    if(ntohs(eth->h_proto) == ETH_P_ARP)
    {
        struct arphdr* arp = (struct arphdr*) (pkt_buf + sizeof(struct ethhdr));

        if(ntohs(arp->ar_hrd) == ARPHRD_ETHER && ntohs(arp->ar_pro) == ETH_P_IP)
        {
            LOG(BOLD DGRN"[ARP Header]\n"NORM);
            LOG(DGRN"\t[+] Hardware Type:\t\t%s (%u)\n",            ntohs(arp->ar_hrd)==ARPHRD_ETHER    ? "Ethernet" : " ", ntohs(arp->ar_hrd));
            LOG("\t[+] Protocol Type:\t\t%s (0x%.4X)\n",            ntohs(arp->ar_pro)==ETH_P_IP        ? "IPv4"  : " ",     ntohs(arp->ar_pro));
            LOG("\t[+] Hardware Length:\t\t%u\n",                   arp->ar_hln);
            LOG("\t[+] Protocol Length:\t\t%u\n",                   arp->ar_pln);
            LOG("\t[+] Operation Code:\t\t%s (%u)\n"NORM,           ntohs(arp->ar_op)==ARPOP_REQUEST    ?"Request" : "Reply",ntohs(arp->ar_op));
        }

        return arp;
    }

    return NULL;
}

struct arppld*
extract_arp_payload(const unsigned char* const pkt_buf)
{
    struct ethhdr* eth = (struct ethhdr*) (pkt_buf);
    __CheckNull(eth);

    if(ntohs(eth->h_proto) == ETH_P_ARP)
    {
        struct arphdr* arp = (struct arphdr*) (pkt_buf + sizeof(struct ethhdr));

        if(ntohs(arp->ar_pro) == ETH_P_IP && ntohs(arp->ar_hrd) == ARPHRD_ETHER)
        {
            struct arppld* arp_p = (struct arppld*) (pkt_buf + sizeof(struct ethhdr) + sizeof(struct arphdr));

            char arp_p_sha[MAC_LEN * 3 * sizeof(char) ];
            char arp_p_tha[MAC_LEN * 3 * sizeof(char) ];
            char arp_p_spa[IP_LEN  * 4 * sizeof(char) ];
            char arp_p_tpa[IP_LEN  * 4 * sizeof(char) ];

            sprintf(arp_p_sha, MAC_FORMAT(arp_p->SHA));
            sprintf(arp_p_spa, IP_FORMAT(arp_p->SPA));
            sprintf(arp_p_tha, MAC_FORMAT(arp_p->THA));
            sprintf(arp_p_tpa, IP_FORMAT(arp_p->TPA));
            

            LOG(BOLD DCYN"[ARP Payload]\n"NORM);
            LOG(DCYN"\t[+] Sender Hardware Address:\t%s\n"NORM,           arp_p_sha);
            LOG(DCYN"\t[+] Sender Protocol Address:\t%s\n"NORM,           arp_p_spa);
            LOG(DCYN"\t[+] Target Hardware Address:\t%s\n"NORM,           arp_p_tha);
            LOG(DCYN"\t[+] Target Protocol Address:\t%s\n"NORM,           arp_p_tpa);

            return arp_p;
        }
    }

    return NULL;
}

int
sniff_arp_pkt(const unsigned char* const pkt_buf, const size_t pkt_size)
{
    struct ethhdr* eth = (struct ethhdr*) (pkt_buf);
    __CheckNull(eth);

    if(ntohs(eth->h_proto) == ETH_P_ARP)
    {
        LOG(BOLD DRED"\t\t\tARP Packet Captured: %lu\n"NORM, (uint64_t) pkt_size);

        extract_ether_header(pkt_buf);
        extract_arp_header(pkt_buf);
        extract_arp_payload(pkt_buf);

        LOG("---------------------------------------\n");
        
        return 1;
    }

    return 0;
}