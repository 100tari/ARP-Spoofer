#include "ARP_Packet.h"
#include "ARP_Log.h"

static struct arphdr*
make_arp_hdr(uint16_t hrd_typ, uint16_t pro_typ, 
             uint8_t  hrd_len, uint8_t  pro_len, uint8_t op_cod)
{
    struct arphdr* hdr = (struct arphdr*) malloc(sizeof(*hdr));
    __CheckNull(hdr);

    hdr->ar_hrd = htons(hrd_typ);
    hdr->ar_pro = htons(pro_typ);
    hdr->ar_hln = hrd_len;
    hdr->ar_pln = pro_len;
    hdr->ar_op  = htons(op_cod);

    return hdr;
}

struct arppkt*
make_arp_pkt(MAC const sndr_mac, IP const sndr_ip,
             MAC const trgt_mac, IP const trgt_ip, uint16_t op_cod)
{
    struct arppkt* pkt = (struct arppkt*) malloc(sizeof(*pkt));
    __CheckNull(pkt);

    struct arphdr* hdr = make_arp_hdr(ARPHRD_ETHER, ETH_P_IP, MAC_LEN, IP_LEN, op_cod);
    memcpy(&pkt->arp_hdr, hdr, sizeof(*hdr));
    free(hdr);

    memcpy(&pkt->arp_pld.SHA, sndr_mac, sizeof(MAC));
    memcpy(&pkt->arp_pld.THA, trgt_mac, sizeof(MAC));
    memcpy(&pkt->arp_pld.SPA, sndr_ip,  sizeof(IP)) ;
    memcpy(&pkt->arp_pld.TPA, trgt_ip,  sizeof(IP)) ;

    return pkt;
}

struct ethfrm*
make_eth_arp_frm(MAC const src_mac, MAC const dst_mac, struct arppkt* arppkt)
{
    struct ethfrm* frm = (struct ethfrm*) malloc(sizeof(*frm));
    __CheckNull(frm);

    memcpy(&frm->eth_hdr.h_source, src_mac,   sizeof(MAC));
    memcpy(&frm->eth_hdr.h_dest  , dst_mac,   sizeof(MAC));
    frm->eth_hdr.h_proto = htons(ETH_P_ARP);

    memcpy(&frm->eth_pld, arppkt, sizeof(*arppkt));

    return frm;
}