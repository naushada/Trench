#ifndef __ICMP_C__
#define __ICMP_C__

#include <type.h>
#include <transport.h>
#include <common.h>
#include <icmp.h>
#include <tun.h>
#include <utility.h>
#include <nat.h>
#include <net.h>

/********************************************************************
 *Global Instance Variable
 ********************************************************************/
icmp_ctx_t icmp_ctx_g;

/*********************************************************************
 * Function Definition
 ********************************************************************/

int32_t icmp_build_common_header(uint8_t *rsp_ptr, 
                                 uint16_t *len, 
                                 uint8_t *packet_ptr, 
                                 uint16_t packet_length) {
  uint8_t tmp_mac[6];
  uint32_t tmp_ip;
  struct eth *eth_ptr;
  struct iphdr *iphdr_ptr;

  eth_ptr = (struct eth *)rsp_ptr;
  iphdr_ptr = (struct iphdr *)&rsp_ptr[sizeof(struct eth)];

  /*Populating MAC Header*/
  memcpy((void *)tmp_mac, ((struct eth *)packet_ptr)->h_dest, sizeof(tmp_mac));
  memcpy((void *)eth_ptr->h_dest, ((struct eth *)packet_ptr)->h_source, ETH_ALEN);
  memcpy((void *)eth_ptr->h_source, tmp_mac, ETH_ALEN);
  eth_ptr->h_proto = ((struct eth *)packet_ptr)->h_proto;

  /*Populating IP Header*/
  tmp_ip = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_dest_ip;
  iphdr_ptr->ip_dest_ip = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_src_ip;
  iphdr_ptr->ip_src_ip = tmp_ip;
  iphdr_ptr->ip_chksum = 0;
  iphdr_ptr->ip_len = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_len;
  iphdr_ptr->ip_ver = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_ver;
  iphdr_ptr->ip_flag_offset = htons(0x1 << 14);
  iphdr_ptr->ip_ttl = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_ttl;
  iphdr_ptr->ip_tos = 0;
  iphdr_ptr->ip_proto = IP_ICMP;
  
  *len = sizeof(struct eth) + (4 * iphdr_ptr->ip_len);
  return(0);
}/*icmp_build_header*/


int32_t icmp_build_echo_reply(int16_t fd, 
                              uint8_t *packet_ptr, 
                              uint16_t packet_length) {

  uint8_t rsp_buffer[1500];
  uint16_t len = 0;
  int32_t ret = -1;
  struct icmphdr *icmphdr_ptr = NULL;
  uint16_t ip_header_len = 0;
  uint8_t dest_mac[ETH_ALEN];

  memset((void *)&rsp_buffer, 0, sizeof(rsp_buffer));

  ip_header_len = 4 * ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_len;

  /*This will build the MAC Header + IP HEADER*/
  icmp_build_common_header((uint8_t *)rsp_buffer, 
                           &len, 
                           packet_ptr, 
                           packet_length);

  icmphdr_ptr = (struct icmphdr *)&rsp_buffer[len];
 
  icmphdr_ptr->type = (uint8_t )ICMP_ECHO_REPLY;
  icmphdr_ptr->code = 0;
  /*Will be calculated later*/
  icmphdr_ptr->cksum = 0;

  icmphdr_ptr->id = ((struct icmphdr *)&packet_ptr[sizeof(struct eth) + 
                    ip_header_len])->id;

  icmphdr_ptr->seq_number = ((struct icmphdr *)&packet_ptr[sizeof(struct eth) + 
                            ip_header_len])->seq_number;

  len += sizeof(struct icmphdr);

  /*Is there any payload in request? if so then it must be copied back to ECHO REPLY*/ 
  if(packet_length > len) {

    memcpy((void *)&rsp_buffer[len], 
           (void *)&packet_ptr[sizeof(struct eth) + 
           ip_header_len + 
           sizeof(struct icmphdr)],
           (packet_length - len));

    len += (packet_length - len);
  }

  /*Updating total length in IP Header*/
  ((struct iphdr *)&rsp_buffer[sizeof(struct eth)])->ip_tot_len = htons(len - sizeof(struct eth));

  /*Populating IP Header check sum*/
  ((struct iphdr *)&rsp_buffer[sizeof(struct eth)])->ip_chksum = 
                  utility_cksum((void *)&rsp_buffer[sizeof(struct eth)], 
                             ip_header_len);

  /*Populating ICMP Header check sum (Header's payload to be included 
   *while calculating check sum. 
   */
  icmphdr_ptr->cksum = utility_cksum((void *)&rsp_buffer[sizeof(struct eth) + 
                                  ((struct iphdr *)&rsp_buffer[sizeof(struct eth)])->ip_len * 4],
                                  len - (sizeof(struct eth) + ip_header_len));

  memcpy((void *)dest_mac, (const void *)rsp_buffer, 6);

  ret = write_eth_frame(fd, 
                       dest_mac, 
                       rsp_buffer, 
                       len);
  if(ret < 0) {
    perror("ICMP ECHO REPLY:");
    return(-1);
  }

  return(0);
}/*icmp_build_echo_reply*/

int32_t icmp_build_response(uint8_t type, 
                            int16_t fd, 
                            uint8_t *packet_ptr, 
                            uint16_t packet_length) {

  switch(type) {
    case ICMP_ECHO_REPLY:
      icmp_build_echo_reply(fd, packet_ptr, packet_length);
    break;

    default:
    break; 
  }/*end of switch*/

}/*icmp_build_response*/

int32_t icmp_init(uint32_t ip_addr, uint32_t subnet_mask) {
  icmp_ctx_t *pIcmpCtx = &icmp_ctx_g;
  pIcmpCtx->ip_addr = ip_addr;
  pIcmpCtx->subnet_mask = subnet_mask;

  return(0);
}/*icmp_init*/

int32_t icmp_main(int16_t fd, uint8_t *packet_ptr, uint16_t packet_length) {

  icmp_ctx_t *pIcmpCtx = &icmp_ctx_g;
  int32_t ret = -1;
  uint8_t buffer[1500];
  uint16_t buffer_length;
  uint16_t ip_header_len = 0;
  struct iphdr *iphdr_ptr;
  struct icmphdr *icmphdr_ptr;
  uint32_t ipaddr;

  iphdr_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)];
  ip_header_len = 4 * iphdr_ptr->ip_len;
  ipaddr = ntohl(iphdr_ptr->ip_dest_ip);

  icmphdr_ptr = (struct icmphdr *)&packet_ptr[sizeof(struct eth) + ip_header_len];
  switch (icmphdr_ptr->type) {

    case ICMP_ECHO_REQUEST:
    {
      if((pIcmpCtx->ip_addr & pIcmpCtx->subnet_mask) != 
         (ipaddr & pIcmpCtx->subnet_mask)) {

        /*Ping Request is for other Network*/
        ret = tun_write((uint8_t *)&packet_ptr[sizeof(struct eth)], 
                        (packet_length - sizeof(struct eth)));

        if(ret < 0) {
          perror("Writing to tunnel failed");
          return(-1);
        }

      } else {
        icmp_build_response((uint8_t)ICMP_ECHO_REPLY, 
                            fd, 
                            packet_ptr, 
                            packet_length);
      }
    }
    break;

    default:
    break;
  }
  return(0);

}/*icmp_main*/


#endif /*__ICMP_C__*/
