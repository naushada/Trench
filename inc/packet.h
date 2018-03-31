#ifndef __PACKET_H__
#define __PACKET_H__

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

struct ethhdr {
  unsigned char   eht_dest[ETH_ALEN];       /* destination eth addr */
  unsigned char   eth_source[ETH_ALEN];     /* source ether addr    */
  unsigned short  eth_proto;                /* packet type ID field */
}__attribute__((packed));

struct sockaddr_ll {
  unsigned short  sll_family;
  unsigned short  sll_protocol;
  int             sll_ifindex;
  unsigned short  sll_hatype;
  unsigned char   sll_pkttype;
  unsigned char   sll_halen;
  unsigned char   sll_addr[8];
};


/* ARP ioctl request. */
struct arphdr {
  unsigned short        arp_htype;      /*Hardware Type*/
  unsigned short        arp_ptype;      /*Protocol Type*/
  unsigned char         arp_hlen;       /*Hardware Length*/
  unsigned char         arp_plen;       /*Protocol Length*/
  unsigned short        arp_opcode;     /*Protocol Length*/
  unsigned char         arp_sha[6];     /*Sender MAC address*/
  unsigned char         arp_spa[4];     /*Sender IP address */
  unsigned char         arp_tha[6];     /*Target MAC address*/
  unsigned char         arp_tpa[4];     /*Target IP address */
}__attribute__((packed));

struct iphdr {
  /*IP Header Version which is always 4*/
  unsigned int   ip_ver:4;
  /*IP Header Length which is multiplied by 4*/
  unsigned int   ip_len:4;
  /*Type Of Service*/
  unsigned int   ip_tos:16;
  /*Total Length of IP Packet which may have TCP/UDP payload*/
  unsigned int   ip_tot_len:8;
  /*Sequence Number which is unique and will be used for packet re-assembly*/
  unsigned int   ip_seq_no:16;
  /*Flags- DF = Dont Fragment, MF = More Fragment. Note: First Bit is kept Reserved*/
  unsigned int   ip_flag:3;
  /*Fragment Offset*/
  unsigned int   ip_offset:13;
  /*Time To Live*/
  unsigned int   ip_ttl:8;
  /*Protocol- TCP, UDP, ICMP*/ 
  unsigned int   ip_proto:8;
  /*Check Sum Of IP Packet*/
  unsigned int   ip_chksum:16;
  /*Source IP Address*/
  unsigned int   ip_src_ip;
  /*Destination IP Address*/
  unsigned int   ip_dest_ip;
}__attribute__((packed));


struct udphdr {
  /*UDP Source Port*/
  unsigned short  udp_src_port;
  /*UDP Destination Port*/
  unsigned short  udp_dest_port;
  /*UDP Length (UPDP Header + Payload)*/
  unsigned short  udp_len;
  /*Check Sum of Packet*/
  unsigned short  udp_chksum;
}__attribute__((packed));


#endif
