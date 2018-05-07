#ifndef __ARP_C__
#define __ARP_C__

#include <common.h>
#include <transport.h>
#include <arp.h>
#include <utility.h>
#include <net.h>

arp_ctx_t arp_ctx_g;

/********************************************************************
 * Function Definition
 ********************************************************************/
uint32_t arp_init(uint8_t *eth_name, uint32_t ip_addr) {

  arp_ctx_t *pArpCtx = &arp_ctx_g;
  struct ifreq ifr;
  int32_t fd;

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if(fd > 0) {
    
    memset((void *)&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, eth_name, IFNAMSIZ);
    
    /*Retrieving MAC Address*/
    if(ioctl(fd, SIOCGIFHWADDR, &ifr)) {
      fprintf(stderr, "Getting MAC failed\n");
      perror("MAC:");
      close(fd);
      return(-1);
    }
    
    memset((void *)pArpCtx->mac, 0, ETH_ALEN);
    memcpy(pArpCtx->mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
  }
 
  close(fd);
  pArpCtx->ip_addr = ip_addr;

  return(0);
}/*arp_init*/

uint32_t arp_build_ARP_request(uint32_t dest_ip) {

  int32_t  fd;
  uint8_t  packet[500];
  uint16_t packet_length;
  int32_t  ret = -1;

  arp_ctx_t *pArpCtx = &arp_ctx_g;

  //uint8_t  bmac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  //uint8_t  bmac[6] = {0x60, 0x67, 0x20, 0x40, 0xFC, 0xE2};
  uint8_t  bmac[6] = {0x76, 0x4e, 0x90, 0x1A, 0x88, 0x64};
  struct eth *eth_rsp_ptr = (struct eth *)packet;
  struct arp *arp_rsp_ptr = (struct arp *)&packet[sizeof(struct eth)];

  packet_length = sizeof(struct eth) + sizeof(struct arp);

  /*RAW ethernet Socket*/ 
  fd = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_ALL));

  /*Destination MAC*/
  memcpy((void *)eth_rsp_ptr->h_dest, bmac, 6);
  /*Source MAC*/
  memcpy((void *)eth_rsp_ptr->h_source, pArpCtx->mac, 6);
 
  /*Ether Net Protocol*/
  eth_rsp_ptr->h_proto = htons(ETH_P_ARP); 
  
  /*ARP Header*/
  arp_rsp_ptr->ar_pro    = htons(0x0800);
  arp_rsp_ptr->ar_hrd    = htons(0x0001);
  arp_rsp_ptr->ar_opcode = htons(ARP_REQUEST);
  arp_rsp_ptr->ar_plen   = 4;
  arp_rsp_ptr->ar_hlen   = 6;

  memcpy((void *)arp_rsp_ptr->ar_sender_ha, pArpCtx->mac, 6);
  arp_rsp_ptr->ar_sender_ip = htonl(pArpCtx->ip_addr);

  memset((void *)arp_rsp_ptr->ar_target_ha, 0, 6) ;
  arp_rsp_ptr->ar_target_ip = htonl(dest_ip);

  fprintf(stderr, "This is ARP REQUEST\n");
  utility_hex_dump(packet, packet_length);

  ret = write_eth_frame(fd, 
                        (unsigned char *)eth_rsp_ptr->h_dest, 
                        packet, 
                        packet_length);
  if(ret < 0) {
    fprintf(stderr, "tun_write error ret is %d\n", ret);
    perror("The Error is ");
  }

  close(fd);
  return(0);
}/*arp_build_ARP_request*/

int32_t arp_process_ARP_request(int32_t fd, uint8_t *packet_ptr, uint16_t packet_length) {

  arp_ctx_t *pArpCtx = &arp_ctx_g;
  uint8_t  packet[1500];
  uint8_t mac[ETH_ALEN];
  
  memset((void *)packet, 0, sizeof(packet));
  memset((void *)mac, 0, sizeof(mac));

  struct eth *eth_rsp_ptr = (struct eth *)packet;
  struct arp *arp_rsp_ptr = (struct arp *)&packet[sizeof(struct eth)];

  struct arp *arp_ptr = (struct arp *)&packet_ptr[sizeof(struct eth)];
  struct eth *eth_ptr = (struct eth *)packet_ptr;
   
  /*destination MAC*/  
  memcpy((void *)eth_rsp_ptr->h_dest,   eth_ptr->h_source, arp_ptr->ar_hlen);
  /*source MAC*/
  memcpy((void *)eth_rsp_ptr->h_source, pArpCtx->mac, arp_ptr->ar_hlen);

  /*proto of ethernet, i.e. ARP*/
  eth_rsp_ptr->h_proto = eth_ptr->h_proto;

  /*ARP Header Preparation*/

  /*HDR - Hardware Type*/
  arp_rsp_ptr->ar_pro    = arp_ptr->ar_pro;
  arp_rsp_ptr->ar_hrd    = arp_ptr->ar_hrd;
  arp_rsp_ptr->ar_opcode = htons(ARP_REPLY);
  arp_rsp_ptr->ar_plen   = arp_ptr->ar_plen;
  arp_rsp_ptr->ar_hlen   = arp_ptr->ar_hlen;
  
  /*SHA - Source Hardware Address*/
  memcpy((void *)arp_rsp_ptr->ar_sender_ha, pArpCtx->mac, arp_ptr->ar_hlen);
  /*SPA - Source Protocol Address (IP Address)*/
  arp_rsp_ptr->ar_sender_ip = htonl(pArpCtx->ip_addr);

  /*THA - Target Hardware Address*/
  memcpy((void *)arp_rsp_ptr->ar_target_ha, eth_ptr->h_source, arp_ptr->ar_hlen);

  /*TPA - Target Protocol Address (IP Address)*/
  arp_rsp_ptr->ar_target_ip = arp_ptr->ar_sender_ip;

  /*Sending Packet to the peer*/ 
  write_eth_frame(fd, (uint8_t *)eth_rsp_ptr->h_dest, packet, packet_length);
  
  return(0);
}/*arp_process_ARP_request*/

uint32_t arp_main(int32_t fd, 
                  uint8_t *packet_ptr, 
                  uint16_t packet_length) {

  arp_ctx_t *pArpCtx = &arp_ctx_g;

  /*Is ARP is for our Machine, check the destination IP*/
  struct arp *arphdr_ptr = (struct arp *)&packet_ptr[sizeof(struct eth)];

  if (ARP_REQUEST == ntohs(arphdr_ptr->ar_opcode)) {
    /*Is ARP for our IP*/
    if (ntohl(arphdr_ptr->ar_target_ip) == pArpCtx->ip_addr) {
      /*Prepare ARP Reply*/
      arp_process_ARP_request(fd, packet_ptr, packet_length);
       
    } else if(!memcmp((void *)arphdr_ptr->ar_sender_ha, (void *)pArpCtx->mac, ETH_ALEN)) {
      /*Pass it on*/ 
      fprintf(stderr, "\nSelf Broadcast ARP Packet is Received (Ignore) for other"
                      " IP Addr is 0x%X\n", 
                      ntohl(arphdr_ptr->ar_target_ip));
    } 
  } else if(ARP_REPLY == ntohs(arphdr_ptr->ar_opcode)) {
    fprintf(stderr, "\n Got the ARP Reply"); 
  } 
  return(0);

}/*arp_main*/

#endif /* __ARP_C__ */
