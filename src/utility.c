/** @file utility.c
 *  @brief This file contains the utility function for common use. 
 *
 *  This contains the core logic of various utility function exposed to other entity.
 *  
 *
 *  @author Mohd. Naushad Ahmed
 *  @bug No known bugs.
 */

#ifndef __UTILITY_C__
#define __UTILITY_C__

#include <common.h>
#include <transport.h>
#include <type.h>
#include <utility.h>

/** @brief This convert from decimal dotted IP Address
 *         into equivalent integer IP Address.
 *
 *  @param record the character to poiner
 *  @return The converted IP Address
 */
uint32_t utility_ip_str_to_int(uint8_t *record) {

  uint32_t ip_addr;
  uint8_t ip[4];

  sscanf((const char *)record, 
          "%d.%d.%d.%d", 
          (int32_t *)&ip[0],
          (int32_t *)&ip[1],
          (int32_t *)&ip[2],
          (int32_t *)&ip[3]);

  ip_addr = ip[0] << 24 | 
            ip[1] << 16 | 
            ip[2] << 8 | 
            ip[3] << 0;

  return(ip_addr);
}/*utility_ip_str_to_int*/


uint32_t utility_network_id_int_to_str(uint32_t network_id, uint8_t *record) {

  uint8_t ip_str[8][8];
  uint32_t ip_addr;
  uint8_t octet;
  
  sprintf((char *)record, 
          "%d.%d.%d", 
          ((network_id >>  16) & 0xFF),
          ((network_id >>   8) & 0xFF),
          ((network_id >>   0) & 0xFF));
  fprintf(stderr, "\n%s:%d Network Id is %s\n", __FILE__, __LINE__, record);
  return(0);
}/*utility_network_id_int_to_str*/


uint32_t utility_network_id_str_to_int(uint8_t *record) {

  uint32_t ip_addr;
  uint32_t ip[4];

  sscanf((const char *)record, 
          "%d.%d.%d", 
          (int32_t *)&ip[0],
          (int32_t *)&ip[1],
          (int32_t *)&ip[2]);

  ip_addr = ip[0] << 16 |
            ip[1] << 8  |
            ip[2] << 0;

  return(ip_addr);
}/*utility_network_id_str_to_int*/


uint32_t utility_protocol_int_to_str(uint8_t ip_proto, uint8_t *protocol_str) {
 
  switch(ip_proto) { 
    case 6:
      sprintf((char *)protocol_str, 
             "%s",
             "TCP");
    break;

    case 17:
      sprintf((char *)protocol_str, 
             "%s",
             "UDP");
    break;

    default:
      sprintf((char *)protocol_str, 
             "%s",
             "UNKNOWN");
    break;
  }
  
  return(0);
}/*utility_protocol_int_to_str*/


uint32_t utility_mac_int_to_str(uint8_t *mac_addr, uint8_t *mac_str) {
  
  return(sprintf((char *)mac_str, 
          "%X:%X:%X:%X:%X:%X",
          mac_addr[0],
          mac_addr[1],
          mac_addr[2],
          mac_addr[3],
          mac_addr[4],
          mac_addr[5]));

}/*utility_mac_int_to_str*/


uint32_t utility_ip_int_to_str(uint32_t ip_addr, uint8_t *ip_str) {
  
  return(sprintf((char *)ip_str, 
          "%d.%d.%d.%d",
          (ip_addr  & 0xFF),
          ((ip_addr & 0xFF00) >> 8),
          ((ip_addr & 0xFF0000) >> 16),
          ((ip_addr & 0xFF000000) >> 24)));

}/*utility_ip_int_to_str*/


uint32_t utility_mac_str_to_int(uint8_t *record, uint8_t *dst_mac) {

  uint8_t mac_str[8][8];
  uint32_t idx = 0;

  memset((void *)mac_str, 0, (sizeof(uint8_t) * 8 * 8));

  sscanf((const char *)record,
         "%X:%X:%X:%X:%X:%X",
         (int32_t *)&dst_mac[0],
         (int32_t *)&dst_mac[1],
         (int32_t *)&dst_mac[2],
         (int32_t *)&dst_mac[3],
         (int32_t *)&dst_mac[4],
         (int32_t *)&dst_mac[5]);

  return(0);
}/*utility_mac_str_to_int*/


/*Function Definition Starts*/
int32_t utility_hex_dump(uint8_t *packet, uint16_t packet_len) {
  int idx;
  fprintf(stderr, "\npacket length is %d\n", packet_len);
  for(idx = 0; idx < packet_len ; idx++) {
    if(!(idx%16)) {
      fprintf(stderr, "\n");
    }
    fprintf(stderr, "%.2x ", packet[idx]);
  }
  
  return(0);

}/*utility_hex_dump*/

uint16_t utility_cksum(void *pkt_ptr, size_t pkt_len) {
  uint32_t sum = 0;
  const uint16_t *ipl = (uint16_t *)pkt_ptr;

  while(pkt_len > 1) {
    sum += *ipl++;

    if(sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }

    pkt_len -= 2;
  }

  /*pkt_len is an odd*/ 
  if(pkt_len) {
    sum += (uint32_t ) *(uint8_t *)ipl;
  }

  /*wrapping up into 2 bytes*/
  while(sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  /*1's complement*/ 
  return (~sum);
}/*utility_cksum*/


/** @brief This function receives the IP Packet and prepend 
 *         UDP Pseudo header t UDP and calculate the checksum.
 *
 *  @param Pointer to IP Packet
 *  @return 1's complement of 1's complement of 16 bits sum
 */
uint16_t utility_udp_checksum(uint8_t *packet_ptr) {
  uint8_t *pseudo_ptr = NULL;
  uint16_t ip_header_len = 0;
  struct iphdr *iphdr_ptr = NULL;
  struct udphdr *udphdr_ptr = NULL;
  uint16_t tmp_len = 0;
  uint16_t offset = 0;
  uint16_t checksum = 0;

  iphdr_ptr = (struct iphdr *)packet_ptr;
  ip_header_len = (iphdr_ptr->ip_len * 4);
  tmp_len = (ntohs(iphdr_ptr->ip_tot_len) - ip_header_len) + 12/*UDP Pseudo Header Length*/;

  udphdr_ptr = (struct udphdr *)&packet_ptr[ip_header_len];

  /*Populating pseudo header for UDP checksum calculation*/
  pseudo_ptr = (uint8_t *)malloc(tmp_len);
  memset((void *)pseudo_ptr, 0, tmp_len);
 
  /*Source IP Address*/ 
  *((uint32_t *)&pseudo_ptr[offset]) = iphdr_ptr->ip_src_ip;
  offset += 4;
  /*Destination IP Address*/
  *((uint32_t *)&pseudo_ptr[offset]) = iphdr_ptr->ip_dest_ip;
  offset += 4;

  /*Reserved one Byte*/
  pseudo_ptr[offset]  = 0;
  offset += 1;
  /*Protocol is UDP*/
  pseudo_ptr[offset]  = 17;
  offset += 1;
  /*Length of UDP Header + it's payload*/
  *((uint16_t *)&pseudo_ptr[offset]) = htons(ntohs(iphdr_ptr->ip_tot_len) - ip_header_len);
  offset += 2;

  memcpy((void *)&pseudo_ptr[offset], 
         (void *)&packet_ptr[ip_header_len], 
         (ntohs(iphdr_ptr->ip_tot_len) - ip_header_len));

  offset += (ntohs(iphdr_ptr->ip_tot_len) - ip_header_len); 

  checksum = utility_cksum((void *)pseudo_ptr, offset);

  free(pseudo_ptr);
  pseudo_ptr = NULL;

  return(checksum);
}/*utility_udp_checksum*/

int32_t utility_coe(int32_t fd) {
  register int flags = fcntl(fd, F_GETFD, 0); 
  if (flags == -1) return -1; 
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}/*utility_coe*/

#endif /* __UTILITY_C__ */
