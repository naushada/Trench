#ifndef __EAPOL_C__
#define __EAPOL_C__

#include <common.h>
#include <transport.h>
#include <type.h>
#include "eapol.h"

eapol_ctx_t eapol_ctx_g;

int32_t eapol_init(uint8_t *eth_name) {
  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  int32_t fd;
  struct ifreq ifr;

  memset((void *)pEapolCtx->eth_name, 0, sizeof(pEapolCtx->eth_name));
  strncpy((void *)pEapolCtx->eth_name, eth_name, sizeof(pEapolCtx->eth_name) - 1);

  memset((void *)&ifr, 0, sizeof(struct ifreq));

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, eth_name, IFNAMSIZ);

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation failed\n", __FILE__, __LINE__);
    perror("fd:");
    return(1);
  }

  /*Retrieving Ethernet interface index*/
  if(ioctl(fd, SIOCGIFINDEX, &ifr)) {
    fprintf(stderr, "\n%s:%dGetting index failed\n", __FILE__, __LINE__);
    perror("INDEX:");
    close(fd);
    return(2);
  }
  
  pEapolCtx->intf_idx = ifr.ifr_ifindex;

  return(0); 
}/*eapol_init*/

int32_t eapol_sendto(int32_t fd, 
                     uint8_t *dst_mac, 
                     uint8_t *packet, 
                     uint32_t packet_len) {
  int ret = -1;
  struct sockaddr_ll sa;
  uint16_t offset = 0;
  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  socklen_t addr_len = sizeof(sa);


  if(!packet) {
    return (-1);
  }

  memset((void *)&sa, 0, sizeof(sa));
  sa.sll_family   = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex  = pEapolCtx->intf_idx;
  sa.sll_halen    = ETH_ALEN;

  memcpy((void *)sa.sll_addr, (void *)dst_mac, ETH_ALEN);

  do {
    ret = sendto(fd, 
                (const void *)&packet[offset], 
                (packet_len - offset), 
                0, 
                (struct sockaddr *)&sa, 
                addr_len);

    if(ret > 0) {
      offset += ret;

      if(!(packet_len - offset)) {
        ret = 0;
      }
    }

  }while((ret == -1) && (errno == EINTR));
 
  return (ret);
}/*eapol_sendto*/

uint8_t *eapol_build_identity_req(int32_t fd, 
                                  uint8_t *in_ptr, 
                                  uint32_t *rsp_len) {

  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_size = sizeof(uint8_t) * 256;
  struct eth *eth_ptr = NULL;
  struct ieee802dot1x *dot1x_ptr = NULL;
  struct eapol *eapol_ptr = NULL;

  rsp_ptr = (uint8_t *)malloc(rsp_size);
  assert(rsp_ptr != NULL);
  memset((void *)rsp_ptr, 0, rsp_size);

  eth_ptr = (struct eth *)rsp_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&rsp_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&rsp_ptr[sizeof(struct eth) + sizeof(struct ieee802dot1x)];

  /*Populating Ethernet Header*/
  memcpy((void *)eth_ptr->h_source, ((struct eth *)in_ptr)->h_dest, ETH_ALEN);
  memcpy((void *)eth_ptr->h_dest, ((struct eth *)in_ptr)->h_source, ETH_ALEN);
  eth_ptr->h_proto = ((struct eth *)in_ptr)->h_proto;

  /*Populating 802.1x header*/
  dot1x_ptr->ver = 1;
  /*802.1x containing EAP Payload*/
  dot1x_ptr->type = EAPOL_TYPE_EAP;
  /*802.1x payload length*/ 
  dot1x_ptr->len = htons(5);

  /*Populating EAP Request*/
  eapol_ptr->code = EAP_CODE_REQUEST;
  eapol_ptr->id = 1;
  eapol_ptr->length = htons(5);
  eapol_ptr->type = EAP_TYPE_IDENTITY;
 
  *rsp_len = sizeof(struct eth) + sizeof(struct ieee802dot1x) + 5;

  return(rsp_ptr); 
}/*eapol_build_identity_req*/

int32_t eapol_main(int32_t fd, uint8_t *in_ptr, uint32_t inlen) {
  uint8_t multicast_mac[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
  struct eth *eth_ptr;
  struct ieee802dot1x *dot1x_ptr;
  struct eapol *eapol_ptr;
  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_len = 0;

  eth_ptr = (struct eth *)in_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&in_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&in_ptr[sizeof(struct eth) + sizeof(struct ieee802dot1x)];

  if(!memcmp(multicast_mac, eth_ptr->h_dest, ETH_ALEN)) {
    fprintf(stderr, "\n%s:%d EAPOL Multicast Packet Received\n",
                      __FILE__, __LINE__);    
  }

  switch(dot1x_ptr->type) {
    case EAPOL_TYPE_EAP:
      /*EAP Packet*/
      
      break;

    case EAPOL_TYPE_START:
      rsp_ptr = eapol_build_identity_req(fd, in_ptr, &rsp_len);
      break;

    case EAPOL_TYPE_LOGOFF:
      break;

    case EAPOL_TYPE_KEY:
      break;

    case EAPOL_TYPE_ENCAPSULATED:
      break;

    default:
      fprintf(stderr, "\n%s:%d Invalid 802.1x packet type %d", __FILE__, __LINE__, dot1x_ptr->type);
      break;
  }

  if(rsp_len) {
    uint8_t dst_mac[ETH_ALEN];
    memcpy(dst_mac, rsp_ptr, ETH_ALEN);
    eapol_sendto(fd, dst_mac, rsp_ptr, rsp_len);
    free(rsp_ptr);
  }

}/*eapol_main*/
#endif /* __EAPOL_C__ */
