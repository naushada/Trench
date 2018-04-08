#ifndef __TRANSPORT_H__
#define __TRANSPORT_H__

/* ARP protocol opcodes. */
#define ARPOP_REQUEST   1               /* ARP request                  */
#define ARPOP_REPLY     2               /* ARP reply                    */
#define ARPOP_RREQUEST  3               /* RARP request                 */
#define ARPOP_RREPLY    4               /* RARP reply                   */
#define ARPOP_InREQUEST 8               /* InARP request                */
#define ARPOP_InREPLY   9               /* InARP reply                  */
#define ARPOP_NAK       10              /* (ATM)ARP NAK                 */

#define ARPHRD_ETHER    1               /* Ethernet 10Mbps              */

#define ETH_ALEN        6               /* Octets in one ethernet addr  */
#define ETH_P_ARP       0x0806          /* Address Resolution packet    */
#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define ETH_P_ALL       0x0003          /* Every packet (be careful!!!) */
#define ETH_P_WOL       0x0842
#define ETH_P_ETHBR     0x6558
#define ETH_P_8021Q     0x8100
#define ETH_P_IPX       0x8137
#define ETH_P_IPv6      0x86dd
#define ETH_P_PPP       0x880b
#define ETH_P_PPPOED    0x8863
#define ETH_P_PPPOES    0x8864
#define ETH_P_EAPOL     0x888e


struct arp {
uint16_t  ar_hrd;          /*Hardware Type*/
uint16_t  ar_pro;          /*Protocol Type*/
uint8_t   ar_hlen;         /*ARP HLEN*/
uint8_t   ar_plen;          /*length of protocol address*/
uint16_t  ar_opcode;       /*ARP opcode*/
uint8_t   ar_sender_ha[6]; /*Sender MAC Address*/
uint32_t  ar_sender_ip;    /*Sender IP Address*/
uint8_t   ar_target_ha[6]; /*Destination MAC*/
uint32_t  ar_target_ip;    /*Destination IP*/
}__attribute__((packed));

struct eth {
  uint8_t    h_dest[6];       /* destination eth addr */
  uint8_t    h_source[6];     /* source ether addr    */
  uint16_t   h_proto;         /* packet type ID field */
}__attribute__((packed));

struct iphdr {
  uint32_t ip_len:4;
  uint32_t ip_ver:4;
  uint32_t ip_tos:8;
  uint32_t ip_tot_len:16;

  uint16_t ip_id;
  uint16_t ip_flag_offset;

  uint32_t ip_ttl:8;
  uint32_t ip_proto:8;
  uint32_t ip_chksum:16;

  uint32_t ip_src_ip;
  uint32_t ip_dest_ip;
}__attribute__((packed));

struct udphdr {
 uint16_t udp_src_port;
 uint16_t udp_dest_port;
 uint16_t udp_len;
 uint16_t udp_chksum;
}__attribute__((packed));

struct icmphdr {
  uint8_t  type;
  uint8_t  code;
  uint16_t cksum;
  uint16_t seq_number;
  uint16_t id;
}__attribute__((packed));

typedef enum {
  IP_ICMP   = 1,
  IP_IGMP   = 2,
  IP_TCP    = 6,
  IP_UDP    = 17

}ip_protocol_t;

#endif
