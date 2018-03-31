#ifndef __DHCP_C__
#define __DHCP_C__

#include <type.h>
#include <common.h>
#include <pthread.h>
#include <db.h>
#include <transport.h>
#include <utility.h>
#include <dhcp.h>
#include <tcp.h>
#include <dns.h>
#include <arp.h>
#include <icmp.h>
#include <nat.h>


/*global instance creation*/
dhcp_ctx_t dhcp_ctx_g;

/** @brief this function is used to receive ethernet fram
 *
 *  @param fd the file descriptor at which ethernet frame to be sent
 *  @param packet is the ether net packet to be sent
 *  @param packet_len is the ethernet frame length to be sent
 *
 *  @return upon success it returns length of received ethernet frame else < 0
 */
int32_t dhcp_recvfrom(int32_t fd, uint8_t *packet, uint16_t *packet_len) {
  int32_t ret = -1;
  int32_t max_len = 1500;
  struct sockaddr_ll sa;
  socklen_t addr_len = sizeof(sa);

  if (!packet) { 
    return (ret);
  }

  do {
    ret = recvfrom(fd, 
                   packet, 
                   max_len, 
                   0, 
                   (struct sockaddr *)&sa,
                    &addr_len);

  }while((ret == -1) && (errno == EINTR));

  *packet_len = ret;
  return(ret);

}/*dhcp_recvfrom*/

/** @brief this function is used to send the ethernet frame
 *
 *  @param fd the file descriptor at which ethernet frame to be sent
 *  @param dst_mac is the destination mac address
 *  @param packet is the ether net packet to be sent
 *  @param packet_len is the ethernet frame length to be sent
 *
 *  @return upon success it returns 0 else < 0
 */
int32_t dhcp_sendto(int32_t fd, 
                    uint8_t *dst_mac, 
                    uint8_t *packet, 
                    uint16_t packet_len) {
  int ret = -1;
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  struct sockaddr_ll sa;
  uint16_t offset = 0;
  socklen_t addr_len = sizeof(sa);

  if(!packet) {
    return (-1);
  }

  memset((void *)&sa, 0, sizeof(sa));
  sa.sll_family   = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex  = pDhcpCtx->intf_idx;
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
}/*dhcp_sendto*/

/** @brief This function sets the provided ip address and subnet mask to the interface
 *
 *  @param interface_name is the eth name
 *  @param ip_addr is the ip address to be set
 *  @param netmask_addr is the subnet mask to be set
 *
 *  @return upon success it returns 0 else < 0
 */
int32_t dhcp_setaddr(uint8_t *interface_name,
                     uint32_t ip_addr, 
                     uint32_t netmask_addr) {
  int32_t fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  memset((void *)&ifr, 0, sizeof(struct ifreq));
  strncpy((char *)ifr.ifr_name, (const char *)interface_name, IFNAMSIZ);

  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;
  ifr.ifr_netmask.sa_family = AF_INET;

  /*Make sure to null terminate*/
  ifr.ifr_name[IFNAMSIZ-1] = 0;

  ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = ip_addr;

  if (ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0) {
    fprintf(stderr, "Setting of interface address failed\n");
    close(fd);
    return(-1);
  }
  
  if(netmask_addr) {
    ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr = netmask_addr;

    if(ioctl(fd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
      fprintf(stderr, "\n%s:%d Setting of interface NETMASK failed\n", __FILE__, __LINE__);
      perror("netmask failed");
      close(fd);
      return(-2);
    }
  }

  close(fd);
  return(0);
}/*dhcp_setaddr*/

/** @brief This function opens the ethernet interface for receiving ether net frame
 *
 *  @param none
 *  @return upon success it returns 0 else < 0
 */
int32_t dhcp_open(void) {
  int fd = -1;
  int option = 0;
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  struct ifreq ifr;
  struct sockaddr_ll sa;
  
  /*RAW ethernet Socket*/ 
  fd = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_ALL));

  if (fd < 0) {
    fprintf(stderr, "\nopen of socket failed");
    return(-1);  
  }

  pDhcpCtx->fd = fd;
  option = 1;

  setsockopt(fd, SOL_SOCKET, TCP_NODELAY,
		       &option, sizeof(option));

  /*Enable to receive/Transmit Broadcast Frame*/
  option = 1;
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
		       &option, sizeof(option));

  /* Set interface in promisc mode */
  struct packet_mreq mr;

  memset((void *)&ifr, 0, sizeof(ifr));
  strncpy((char *)ifr.ifr_name, (const char *)pDhcpCtx->eth_name, IFNAMSIZ);

  if(ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
    syslog(LOG_ERR, "%s: ioctl(SIOCGIFFLAGS)", strerror(errno));
    close(fd);
    return(-2);

  } else {
    ifr.ifr_flags |= (IFF_PROMISC | IFF_NOARP);

    if(ioctl (fd, SIOCSIFFLAGS, &ifr) == -1) {
      syslog(LOG_ERR, "%s: Could not set flag IFF_PROMISC", strerror(errno));
      close(fd);
      return(-3);
    }
  }

  memset((void *)&mr, 0, sizeof(mr));
  mr.mr_ifindex = pDhcpCtx->intf_idx;
  mr.mr_type    = PACKET_MR_PROMISC;

  if(setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       (char *)&mr, sizeof(mr)) < 0) {
    close(fd);
    return(-4);
  }

  /* Bind to particular interface */
  memset((void *)&sa, 0, sizeof(sa));
  sa.sll_family   = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex  = pDhcpCtx->intf_idx;

  if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    syslog(LOG_ERR, "%s: bind(sockfd=%d) failed", strerror(errno), fd);
    close(fd);
    return(-5);
  }

  return(0);
}/*dhcp_open*/

/** @brief this function is used to get the mac address based on provided ip address
 *
 *  @param ip_address is the input to this function
 *  @param mac_addr is the output mac address
 *  @param upon success, it returns 0 else < 0
 */
int32_t dhcp_get_mac(uint32_t ip_address, uint8_t *mac_addr) {

  uint8_t sql_query[128];
  uint32_t row;
  uint32_t col;
  uint8_t record[2][16][32];
  uint16_t host_id;
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
 
  host_id = ntohl(ip_address) & (~pDhcpCtx->dhcpS_param.subnet_mask);
  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query,
           sizeof(sql_query),
           "%s%s%s%d%s",
           "SELECT * FROM ",
           pDhcpCtx->ip_allocation_table,
           " WHERE host_id='",
           host_id,
           "'");
  if(!db_exec_query(sql_query)) {

    memset((void *)record, 0, sizeof(record));
    row = 0, col = 0;
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {

      if(row) {
        utility_mac_str_to_int(record[0][1], mac_addr);
        return(0);
      }
    } 
  }

  return(-1);
}/*dhcp_get_mac*/

/** @brief This function processes the received ethernet frame
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_process_eth_frame(int32_t fd, 
                               uint8_t *packet_ptr, 
                               uint16_t packet_length) {

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  /*broadcast MAC*/
  uint8_t bmac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  /*Pointer to IP Packet*/
  struct iphdr *iphdr_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)];

  /*protocol could have any of value - 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP*/
  struct udphdr *udphdr_ptr = (struct udphdr *)&packet_ptr[sizeof(struct eth) + 
                                                           sizeof(struct iphdr)];

  /*Pointer to Ethernet Packet*/
  struct eth *eth_hdr_ptr = (struct eth *)packet_ptr;

  if(ETH_P_IP == ntohs(eth_hdr_ptr->h_proto)) {

    /*Ethernet packet is followed by IP Packet*/
    if(!memcmp(eth_hdr_ptr->h_dest, bmac, ETH_ALEN)) {
      /*It's a broadcast Packet*/
      if(IP_UDP == iphdr_ptr->ip_proto) {

        /*Check whether it's DHCP packet or not based on destination port*/
        if((DHCP_SERVER_PORT == ntohs(udphdr_ptr->udp_dest_port)) &&
           (DHCP_CLIENT_PORT == ntohs(udphdr_ptr->udp_src_port))) {

          dhcp_option_t dhcp_option;
          /*subtracting the fixed part of DHCP header*/
          dhcp_option.len = ntohs(udphdr_ptr->udp_len) - sizeof(dhcp_packet_t);
          dhcp_option.option = (char *)malloc(dhcp_option.len);
           
          if(!dhcp_option.option) {
            fprintf(stderr, "\nMalloc failed to allocate the memory");
            exit(0);
          }
     
          memset((void *)dhcp_option.option, 0, dhcp_option.len);
           
          dhcp_option.option =  (char *)&packet_ptr[sizeof(struct eth) + 
                                sizeof(struct iphdr)  + 
                                sizeof(struct udphdr) + 
                                sizeof(dhcp_packet_t) + 4 /*DHCP Cookie*/];

          dhcp_process_option((char *)packet_ptr, 
                              packet_length, 
                              (uint8_t *)dhcp_option.option, 
                              dhcp_option.len);

          dhcp_process_request(fd, packet_ptr, packet_length);
        }
      } 
    } else if(!memcmp(eth_hdr_ptr->h_dest, pDhcpCtx->mac_addr, ETH_ALEN)) {

      if(53 /*DNS PORT*/ == ntohs(udphdr_ptr->udp_dest_port)) {
        /*DNS Request*/
        dns_main(fd, packet_ptr, packet_length);

      } else if(IP_UDP == iphdr_ptr->ip_proto) {
        //fprintf(stderr, "\n");

      } else if(IP_TCP == iphdr_ptr->ip_proto) {
        tcp_main(fd, packet_ptr, packet_length);

      } else if(IP_ICMP == iphdr_ptr->ip_proto) {
        /*PING Request*/
        icmp_main(fd, packet_ptr, packet_length);
     }
   } else {
     //fprintf(stderr, "\n%s:%d IP Multicast Packets\n", __FILE__, __LINE__);
     //utility_hex_dump(packet_ptr, packet_length);
   }
 
  } else if (ETH_P_ARP == ntohs(eth_hdr_ptr->h_proto)) {
    arp_main(fd, packet_ptr, packet_length); 
  }

  return(0);
}/*dhcp_process_eth_frame*/

/** @brief this function initialises the the dhcp global parameters
 *
 *  @param eth_name is the ether net device name
 *  @param ip_addr is the ip address on which dhcp server will be listening on
 *  @param conf_param is the dhcp server configuration parameters which will be 
 *         provided to dhclient
 *  @param ip_allocation_table_name is the name of the data base table maintained by dhcp server
 */
int dhcp_init(uint8_t *eth_name, 
              uint32_t ip_addr, 
              dhcp_conf_t *conf_param, 
              uint8_t *ip_allocation_table_name) {
 
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  int fd = -1;
  struct ifreq ifr;

  strncpy(pDhcpCtx->eth_name, eth_name, IFNAMSIZ);
  pDhcpCtx->ip_addr = ip_addr;
  gethostname(pDhcpCtx->host_name, sizeof(pDhcpCtx->host_name));

  memcpy((void *)&pDhcpCtx->dhcpS_param, 
         (const void *)conf_param, 
         sizeof(pDhcpCtx->dhcpS_param));  

  memset((void *)pDhcpCtx->ip_allocation_table, 0, sizeof(pDhcpCtx->ip_allocation_table));
  strncpy(pDhcpCtx->ip_allocation_table, 
          ip_allocation_table_name, 
          strlen(ip_allocation_table_name));

  memset((void *)&ifr, 0, sizeof(struct ifreq));

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, eth_name, IFNAMSIZ);

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if(fd < 0) {
    fprintf(stderr, "Creation of fd failed\n");
    perror("fd:");
    return(-1);
  }

  /*Retrieving MAC Address*/
  if(ioctl(fd, SIOCGIFHWADDR, &ifr)) {
    fprintf(stderr, "Getting MAC failed\n");
    perror("MAC:");
    close(fd);
    return(-2);
  }

  memcpy(pDhcpCtx->mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  /*Retrieving Ethernet interface index*/
  if(ioctl(fd, SIOCGIFINDEX, &ifr)) {
    fprintf(stderr, "Getting index failed\n");
    perror("INDEX:");
    close(fd);
    return(-3);
  }
  
  pDhcpCtx->intf_idx = ifr.ifr_ifindex;

  close(fd);
  /*Remove ip configured to this interface*/
  dhcp_setaddr(eth_name, 0, 0);
  dhcp_open();

  return(0);
}/*dhcp_init*/

/** @brief This function parses the optional parameters 
 *         received in DHCP_DISCOVER or DHCP_REQUEST messages
 *
 *  @param packet_ptr is the buffer holding the ethernet frame of dhcp discover/request
 *  @param packet_length is the length of ethernet frame received
 *  @param option_ptr is the output argument in which parsed optional argument will be stored
 *  @param option_len is the offset at which optional parameters starts at
 *
 *  @return upon success it return length os the optional parameters else < 0
 */
int32_t dhcp_process_option(uint8_t *packet_ptr, 
                            uint16_t packet_length, 
                            uint8_t *option_ptr, 
                            int32_t option_len) {
  uint16_t offset = 0;
  uint16_t idx = 0;

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  while (option_len > 0) {

    switch (option_ptr[offset]) {
      case DHCP_OPTION_END:
        /*Optional tag ends here and exit the while loop*/
        option_len = 0;
        break;

      default:
        pDhcpCtx->opt_tag.tag[idx].tag = option_ptr[offset++];
        pDhcpCtx->opt_tag.tag[idx].len = option_ptr[offset++];
        /*Value Part*/
        memcpy((void *)pDhcpCtx->opt_tag.tag[idx].value, 
               (const void *)&option_ptr[offset], 
               pDhcpCtx->opt_tag.tag[idx].len);

        offset += pDhcpCtx->opt_tag.tag[idx].len;

        option_len -= (1/*1 octet for tag*/ + 
                       1/*1 octet for len*/ + 
                       pDhcpCtx->opt_tag.tag[idx].len /* number of octets in value*/);
        idx += 1;
        break;
    }
  }

  /*Total number of optional tags present*/
  pDhcpCtx->opt_tag.tag_count = idx;

  /*success*/
  return(idx); 
}/*dhcp_process_option*/

/** @brief this function checks if dhcp client supports 2-way hand shake or 4-way hand shake
 *
 *  @param none
 *  @return it returns 1 meaning it does support 2-way handshake else 0
 */
uint8_t dhcp_is_two_way_handshake(void) {
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  uint16_t idx = 0;

  for(idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {
    if(DHCP_OPTION_RAPID_COMMIT == pDhcpCtx->opt_tag.tag[idx].tag) {
      return(1);
    }
  }

  return(0);
}/*dhcp_is_two_way_handshake*/

/** @brief This function processes the DHCP Request 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_process_request(int32_t fd, 
                             uint8_t *packet_ptr, 
                             uint16_t packet_length) {
  uint16_t idx = 0;
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  for (idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {

    switch (pDhcpCtx->opt_tag.tag[idx].tag) {
      case DHCP_OPTION_MESSAGE_TYPE:

        if(DHCPDISCOVER == pDhcpCtx->opt_tag.tag[idx].value[0]) {

          if(dhcp_is_two_way_handshake()) {
            /*Prepare DHCPACK message*/
            dhcp_ACK(fd, packet_ptr, packet_length);
          } else {
            /*Prepare DHCPOFFER message*/
            dhcp_OFFER(fd, packet_ptr, packet_length);
          }
 
        } else if (DHCPREQUEST == pDhcpCtx->opt_tag.tag[idx].value[0]) {
          /*Prepare DHCPACK message*/
          dhcp_ACK(fd, packet_ptr, packet_length);

        } else if (DHCPDECLINE == pDhcpCtx->opt_tag.tag[idx].value[0]) {
          /*Prepare DHCPACK message*/
          dhcp_ACK(fd, packet_ptr, packet_length);

        } else if (DHCPRELEASE == pDhcpCtx->opt_tag.tag[idx].value[0]) {
          /*Prepare DHCPACK message*/
          dhcp_RELEASE(fd, packet_ptr, packet_length);
        } 
      break;

      case DHCP_OPTION_END:
      default:
        /*Controlling the for loop*/
        idx = pDhcpCtx->opt_tag.tag_count;
        break;
    } 
  }

  return(idx); 
}/*dhcp_process_request*/

/** @brief This function processes the DHCP RELEASE and updated the data base accordingly 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_RELEASE(int32_t fd, uint8_t *packet_ptr, uint16_t packet_length) {

  uint8_t sql_query[255];
  uint8_t mac_str[32];
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  memset((void *)mac_str, 0, sizeof(mac_str));
  utility_mac_int_to_str((uint8_t *)&packet_ptr[ETH_ALEN], mac_str);

  memset((void *)sql_query, 0, sizeof(sql_query));
  snprintf(sql_query,
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%s",
           "UPDATE ",
           pDhcpCtx->ip_allocation_table,
           "SET ip_allocation_status ='RELEASED'",
           " WHERE mac_address='",
           mac_str,
           "'");

  if(db_exec_query(sql_query)) {
    fprintf(stderr, "\n%s:%d Execution of (%s) Failed\n", 
                     __FILE__, __LINE__,
                     sql_query);
    return(-1);
  }

}/*dhcp_RELEASE*/

/** @brief This function processes the DHCP OFFER Request 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_OFFER (int32_t fd, uint8_t *packet_ptr, uint16_t packet_length) {
  int32_t rsp_len = -1;
  uint8_t rsp_buffer[1500];
  uint8_t dest_mac[ETH_ALEN];
  uint8_t message_type = (uint8_t)DHCPOFFER;
  
  memset((void *)rsp_buffer, 0, sizeof(rsp_buffer));

  rsp_len = dhcp_build_rsp(message_type, 
                           rsp_buffer, 
                           packet_ptr, 
                           packet_length);

  memcpy((void *)dest_mac, (const void *)rsp_buffer, ETH_ALEN);

  if (rsp_len > 0) {
    rsp_len = dhcp_sendto(fd, 
                          dest_mac, 
                          rsp_buffer, 
                          rsp_len); 
  }
  
  return(rsp_len);
}/*dhcp_OFFER*/

/** @brief This function processes the DHCP ACK 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_ACK (int32_t fd, uint8_t *packet_ptr, uint16_t packet_length) {
  int32_t rsp_len = -1;
  uint8_t rsp_buffer[1500];
  uint8_t dest_mac[ETH_ALEN];
  uint8_t message_type = (uint8_t)DHCPACK;
  
  memset((void *)rsp_buffer, 0, sizeof(rsp_buffer));

  rsp_len = dhcp_build_rsp(message_type, 
                           rsp_buffer, 
                           packet_ptr, 
                           packet_length);

  memcpy((void *)dest_mac, (const void *)rsp_buffer, ETH_ALEN);

  if (rsp_len > 0) {
    rsp_len = dhcp_sendto(fd, 
                          dest_mac, 
                          rsp_buffer,
                          rsp_len); 
  }
  
  return(rsp_len);
}/*dhcp_ACK*/

/** @brief This function processes the DHCP NACK 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_NACK (int32_t fd, uint8_t *packet_ptr, uint16_t packet_length) {
  int32_t rsp_len = -1;
  uint8_t rsp_buffer[1500];
  uint8_t dest_mac[ETH_ALEN];
  uint8_t message_type = (unsigned char)DHCPNACK;
  
  memset((void *)rsp_buffer, 0, sizeof(rsp_buffer));

  rsp_len = dhcp_build_rsp(message_type, 
                           rsp_buffer, 
                           packet_ptr, 
                           packet_length);
  memcpy((void *)dest_mac, 
         (const void *)rsp_buffer, 
         ETH_ALEN);
 
  if (rsp_len > 0) {
    rsp_len = dhcp_sendto(fd,
                          dest_mac, 
                          rsp_buffer, 
                          rsp_len); 
  }
  
  return(rsp_len);
}/*dhcp_NACK*/

/** @brief This function populates the optional parameters in response 
 *
 *  @param message_type is the reply to the request
 *  @param rsp_ptr is the pointer to response buffer
 *  @param offset is the length at which optional parameters to be filled in
 */
int32_t dhcp_populate_dhcp_options(uint8_t message_type, 
                                   uint8_t *rsp_ptr, 
                                   uint16_t offset) {

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  uint16_t idx = 0;
  uint16_t inner_idx = 0;
  uint8_t cookie[] = {0x63, 0x82, 0x53, 0x63};

  /*Fill DHCP Cookie*/
  memcpy((void *)&rsp_ptr[offset], cookie, 4);
  offset += 4; 

  /*Fill Message Type*/
  rsp_ptr[offset++] = DHCP_OPTION_MESSAGE_TYPE;
  rsp_ptr[offset++] = 1;
  rsp_ptr[offset++] = message_type;
  
  for(idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {

    switch(pDhcpCtx->opt_tag.tag[idx].tag) {

      case DHCP_OPTION_PARAMETER_REQUEST_LIST: 

        for(inner_idx = 0; inner_idx < pDhcpCtx->opt_tag.tag[idx].len; inner_idx++) {

          switch(pDhcpCtx->opt_tag.tag[idx].value[inner_idx]) {

            case DHCP_OPTION_SUBNET_MASK:
              rsp_ptr[offset++] = DHCP_OPTION_SUBNET_MASK;
              rsp_ptr[offset++] = 4;
              *((uint32_t *)&rsp_ptr[offset]) = htonl(pDhcpCtx->dhcpS_param.subnet_mask);
              offset += 4;
            break;

            case DHCP_OPTION_ROUTER:
              rsp_ptr[offset++] = DHCP_OPTION_ROUTER;
              rsp_ptr[offset++] = 4;
              *((uint32_t *)&rsp_ptr[offset]) = htonl(pDhcpCtx->ip_addr);
              offset += 4;
            break;

            case DHCP_OPTION_TIME_SERVER:
            break;

            case DHCP_OPTION_DOMAIN_NAME_SERVER:
              rsp_ptr[offset++] = DHCP_OPTION_DOMAIN_NAME_SERVER;
              rsp_ptr[offset++] = 4;
              *((uint32_t *)&rsp_ptr[offset]) = htonl(pDhcpCtx->ip_addr);
              offset += 4;
            break;

            case DHCP_OPTION_HOST_NAME:
              rsp_ptr[offset++] = DHCP_OPTION_HOST_NAME;
              rsp_ptr[offset++] = strlen(pDhcpCtx->host_name);
              memcpy((void *)&rsp_ptr[offset], 
                     (void *)&pDhcpCtx->host_name, 
                     strlen(pDhcpCtx->host_name));
              offset += strlen(pDhcpCtx->host_name);
            break;

            case DHCP_OPTION_DOMAIN_NAME:
              rsp_ptr[offset++] = DHCP_OPTION_DOMAIN_NAME;
              rsp_ptr[offset++] = strlen(pDhcpCtx->dhcpS_param.domain_name);
              memcpy((void *)&rsp_ptr[offset], 
                     (void *)&pDhcpCtx->dhcpS_param.domain_name, 
                     strlen(pDhcpCtx->dhcpS_param.domain_name));
              offset += strlen(pDhcpCtx->dhcpS_param.domain_name);
            break;

            case DHCP_OPTION_INTERFACE_MTU:
              rsp_ptr[offset++] = DHCP_OPTION_INTERFACE_MTU;
              rsp_ptr[offset++] = 2;
              rsp_ptr[offset++] = (pDhcpCtx->dhcpS_param.mtu >> 8) & 0xFF;
              rsp_ptr[offset++] = pDhcpCtx->dhcpS_param.mtu  & 0xFF;
            break;

            case DHCP_OPTION_BROADCAST_ADDRESS:
            break;
            case DHCP_OPTION_NIS_DOMAIN:
            break;

            case DHCP_OPTION_NTP_SERVER:
              rsp_ptr[offset++] = DHCP_OPTION_NTP_SERVER;
              rsp_ptr[offset++] = 4;
              *((uint32_t *)&rsp_ptr[offset]) = pDhcpCtx->ip_addr;
              offset += 4;
            break;

            case DHCP_OPTION_REQUESTED_IP_ADDRESS:
            break;
            case DHCP_OPTION_IP_LEASE_TIME:
            break;
            case DHCP_OPTION_OPTION_OVERLOAD:
            break;
            case DHCP_OPTION_SERVER_IDENTIFIER:
            break;

            default:
            break;
          }
        }
      case DHCP_OPTION_AUTO_CONFIGURE:
        rsp_ptr[offset++] = DHCP_OPTION_AUTO_CONFIGURE;
        rsp_ptr[offset++] = 1;
        rsp_ptr[offset++] = 0x00;
      break;
        
      default:
      break;
    }       
  }

  rsp_ptr[offset++] = DHCP_OPTION_IP_LEASE_TIME;
  rsp_ptr[offset++] = 4;
  rsp_ptr[offset++] = ((pDhcpCtx->dhcpS_param.lease >> 24) & 0xFF);
  rsp_ptr[offset++] = ((pDhcpCtx->dhcpS_param.lease >> 16) & 0xFF);
  rsp_ptr[offset++] = ((pDhcpCtx->dhcpS_param.lease >>  8) & 0xFF);
  rsp_ptr[offset++] = ((pDhcpCtx->dhcpS_param.lease >>  0) & 0xFF);

  rsp_ptr[offset++] = DHCP_OPTION_INTERFACE_MTU;
  rsp_ptr[offset++] = 2;
  rsp_ptr[offset++] = (pDhcpCtx->dhcpS_param.mtu >> 8) & 0xFF;
  rsp_ptr[offset++] = (pDhcpCtx->dhcpS_param.mtu  & 0xFF);

  rsp_ptr[offset++] = DHCP_OPTION_SERVER_IDENTIFIER;
  rsp_ptr[offset++] = 4;
  *((uint32_t *)&rsp_ptr[offset]) = htonl(pDhcpCtx->ip_addr);
  offset += 4;
  
  rsp_ptr[offset++] = DHCP_OPTION_END;

  return (offset); 
}/*dhcp_populate_dhcp_options*/

/** @brief This function retrieves the dhclient hostname from stored optional parameters 
 *
 *  @param host_name is the dhclient host name which is the output 
 *  @return upon success return 0 else < 0 
 */
uint32_t dhcp_get_dhclient_host_name(uint8_t *host_name) {
  uint32_t idx = 0;
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  for(idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {

    if(DHCP_OPTION_HOST_NAME == pDhcpCtx->opt_tag.tag[idx].tag) {
      memcpy((void *)host_name, 
             (void *)pDhcpCtx->opt_tag.tag[idx].value, 
             pDhcpCtx->opt_tag.tag[idx].len);
      break;
    }
  }
 
  return(idx == pDhcpCtx->opt_tag.tag_count ? 0:1); 
}/*dhcp_get_dhclient_host_name*/

/** @brief This function validates whether requested ip addres can be assigned to dhclient or not 
 *
 *  @param  is the dhclient host name which is the output 
 *  @return upon success return 1 else  0 
 */
uint32_t dhcp_is_dhcpc_requested_ip(uint8_t *mac_str, uint32_t *ip_addr_ptr) {
  
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  uint8_t  sql_query[512];
  int8_t   record[2][16][32]; 
  int32_t  row = 0;
  int32_t  col = 0;
  uint32_t idx = 0;
  uint8_t ip_addr[4];
  uint32_t ip;
  uint32_t nw;
  uint8_t  host_name[255];
  uint16_t host_id;
  uint8_t network_id[24];

  for(idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {

    if(DHCP_OPTION_REQUESTED_IP_ADDRESS == pDhcpCtx->opt_tag.tag[idx].tag) {
      
      memcpy((void *)ip_addr, 
             (void *)pDhcpCtx->opt_tag.tag[idx].value, 
             pDhcpCtx->opt_tag.tag[idx].len);
     
      break;
    }
  }
 
  /*did it hit the end*/ 
  if(idx == pDhcpCtx->opt_tag.tag_count) {
    return(0);
  }

  ip = ip_addr[0] << 24 | ip_addr[1] << 16 | ip_addr[2] << 8 | ip_addr[3];

  host_id = ip & ~(pDhcpCtx->dhcpS_param.subnet_mask);
  nw = ip & pDhcpCtx->dhcpS_param.subnet_mask;

  memset((void *)network_id, 0, sizeof(network_id));
  snprintf(network_id, 
           sizeof(network_id), 
           "%d.%d.%d", 
           ((uint8_t *)&nw)[3], 
           ((uint8_t *)&nw)[2], 
           ((uint8_t *)&nw)[1]);

  memset((void *)&sql_query, 0, sizeof(sql_query));
  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%s%d%s",
           "SELECT * FROM ",
           pDhcpCtx->ip_allocation_table,
           " WHERE (mac_address =",
           "'",
           mac_str,
           "' AND host_id ='",
           host_id,
           "')");

  if(!db_exec_query((char *)sql_query)) {
    
    memset((void *)record, 0, sizeof(record));
    row = 0, col = 0;
    /*Query is executed successfully*/
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
    
      if(row > 0) {
        /*Requested IP address can be allocated, proceed to it*/
         *ip_addr_ptr = ip;

         memset((void *)host_name, 0, sizeof(host_name));
         dhcp_get_dhclient_host_name(host_name);

        /*Update the xid received from dhcp client*/
        memset((void *)sql_query, 0, sizeof(sql_query));
        snprintf((char *)sql_query,  
                 sizeof(sql_query),  
                 "%s%s%s%s%s"
                 "%s%s%s%d%s",
                 "UPDATE ",
                 pDhcpCtx->ip_allocation_table,
                 " SET ",
                 "host_name='",
                 host_name,
                 "',ip_allocation_status='ASSIGNED' WHERE (network_id ='",
                 network_id,
                 "' AND host_id ='",
                 host_id,
                 "')");

        if(db_exec_query((char *)sql_query)) {
          fprintf(stderr, "\nExecution of SQL query failed");
          exit(0);
        }
        return(1);
      }
    }
  }

  /*Requested IP address can not be allocated*/
  return(0);
}/*dhcp_is_dhcpc_requested_ip*/

/** @brief This function allocates the ip address to chcp client 
 *
 *  @param  mac_addr is the mac address of dhcp client
 *  @return upon success returns ip_addr else  0 
 */
uint32_t dhcp_get_client_ip(uint8_t *mac_addr) {

  char sql_query[512];
  char record[2][16][32]; 
  int  row = 0;
  int  col = 0;
  uint32_t ip_addr;
  uint8_t mac_str[32];
  uint8_t ip_str[32];
  uint8_t host_name[255];
  uint16_t host_id;
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  
  memset((void *)record, 0, sizeof(record));
  memset((void *)mac_str, 0, sizeof(mac_str));

  utility_mac_int_to_str(mac_addr, mac_str);
  memset((void *)ip_str, 0, sizeof(ip_str));

  /*check dhcpc - dhcp client has requested for specific IP address*/
  if(dhcp_is_dhcpc_requested_ip(mac_str, &ip_addr)) {
    return(ip_addr);
  }
 
  memset((void *)sql_query, 0, sizeof(sql_query));
  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s",
           "SELECT * FROM ",
           pDhcpCtx->ip_allocation_table,
           " WHERE mac_address ='",
           mac_str,
           "'");
             
  if(!db_exec_query((char *)sql_query)) {

    /*Query is executed successfully*/
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
    
      if(row > 0) {
        /*A record is found*/
        memset((void *)ip_str, 0, sizeof(ip_str));
        snprintf((char *)ip_str, 
                 sizeof(ip_str),
                 "%s.%s",
                 record[0][2],
                 record[0][3]);
 
        ip_addr = utility_ip_str_to_int(ip_str);
        return(ip_addr);
      }
      /*No result found for given query. Allocate the IP address now*/
      memset((void *)sql_query, 0, sizeof(sql_query));
      snprintf((char *)sql_query, 
               sizeof(sql_query),
               "%s%s",
               "SELECT max(CAST (host_id AS INTEGER)) FROM ",
               pDhcpCtx->ip_allocation_table);

      if(!db_exec_query((char *)sql_query)) {
        memset((void *)record, 0, sizeof(record));

        if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {

          if(row > 0) {
            host_id = atoi(record[0][0]) + 1;
          } else {
            host_id = 2;
          }
          uint8_t network_id_str[32];
          uint8_t ip_addr_str[32];
          /*DHCP Client Host Name*/
          memset((void *)host_name, 0, sizeof(host_name));
          dhcp_get_dhclient_host_name(host_name);

          memset((void *)network_id_str, 0, sizeof(network_id_str));
          utility_network_id_int_to_str(pDhcpCtx->dhcpS_param.network_id, network_id_str);

          memset((void *)ip_addr_str, 0, sizeof(ip_addr_str));
          snprintf((char *)ip_addr_str, 
                   sizeof(ip_addr_str),
                   "%s.%d",
                   network_id_str,
                   host_id);

          /*Freed IP Address is found*/
          ip_addr = utility_ip_str_to_int(ip_addr_str);
     
          /*Table to mark that this ip address is allocated to dhcp client*/ 
          memset((void *)sql_query, 0, sizeof(sql_query));
          snprintf((char *)sql_query, 
                   sizeof(sql_query), 
                   "%s%s%s%s%s"
                   "%s%s%s%s%s"
                   "%s%s%s%s%d"
                   "%s%s",
                   "INSERT INTO ",
                   pDhcpCtx->ip_allocation_table,
                   " (host_name, mac_address, network_id, ",
                   "host_id, ip_allocation_status) VALUES (",
                   "'",
                   host_name,
                   "',",
                   " '",
                   mac_str,
                   "',",
                   " '",
                   network_id_str,
                   "' ,",
                   " '",
                   host_id,
                   "' ,",
                   "'ASSIGNED')");

          if(db_exec_query((char *)sql_query)) {
            fprintf(stderr, "\nExecution of SQL query failed");
            exit(0);
          }  
          /*Return the allocated dhcp client ip address*/ 
          return(ip_addr);
        }
      }
    }
  }

  return(0);
}/*dhcp_get_client_ip*/

/** @brief This function prepares the DHCP Response to received Request
 *
 *  @param message_type is the message in response to DHCP Request
 *  @param rsp_ptr it is the output buffer for response
 *  @param packet_ptr is the request ethernet frame received
 *  @param packet_length is the length of the ethernet frame received
 *
 *  @return
 */
int32_t dhcp_build_rsp(uint8_t message_type, 
                       uint8_t *rsp_ptr, 
                       uint8_t *packet_ptr, 
                       uint16_t packet_length) {

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  uint16_t offset = 0;
  int32_t rsp_len = -1;
  uint8_t bmac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  struct eth     *eth_ptr   = (struct eth  *)rsp_ptr;
  struct iphdr   *ip_ptr    = (struct iphdr   *)&rsp_ptr[sizeof(struct eth)];
  struct udphdr  *udp_ptr   = (struct udphdr  *)&rsp_ptr[sizeof(struct eth) + 
                                                         sizeof(struct iphdr)];
  struct dhcphdr *dhcp_ptr  = (struct dhcphdr *)&rsp_ptr[sizeof(struct udphdr) + 
                                                         sizeof(struct iphdr) + 
                                                         sizeof(struct eth)];

  /*dhcp request ptr*/
  struct dhcphdr *dhcp_req_ptr  = (struct dhcphdr *)&packet_ptr[sizeof(struct udphdr) + 
                                                                sizeof(struct iphdr) + 
                                                                sizeof(struct eth)];
  /*Fill MAC Header Data*/
  /*Response shall be Unicast*/
  memcpy((void *)eth_ptr->h_dest, ((struct eth *)packet_ptr)->h_source, ETH_ALEN);
  memcpy((void *)eth_ptr->h_source, pDhcpCtx->mac_addr, ETH_ALEN);
  eth_ptr->h_proto = htons(ETH_P_IP);

  /*Fill IP Header*/
  ip_ptr->ip_ver     = 0x4;
  /*Length shall be multiple of 4. i.e. 5 X 4 = 20 bytes Header*/
  ip_ptr->ip_len     = 0x5;
  /*Type of service*/  
  ip_ptr->ip_tos     = 0x00;
  /*Value shall be Header Len + payload Len*/
  ip_ptr->ip_tot_len = 0x00;
  ip_ptr->ip_id      = htons(random()%65535);
  /*bit0 - R (Reserved), bit1 - DF (Don't Fragment), bit2 - MF (More Fragment)*/
  ip_ptr->ip_flag_offset     = htons(0x1 << 14);
  /*Maximum Number of Hops, At each hop, It's decremented by 1*/
  ip_ptr->ip_ttl     = 0x10;
  /*1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP*/
  ip_ptr->ip_proto   = 0x11;
  /*Checksum will be computed latter*/
  ip_ptr->ip_chksum  = 0x00;
  /*Source IP Address*/
  ip_ptr->ip_src_ip  = htonl(pDhcpCtx->ip_addr);
  /*Destination IP Address*/
  
  if(0 == ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_src_ip) {
    memcpy((void *)&ip_ptr->ip_dest_ip, bmac, 4);

  } else {
    ip_ptr->ip_dest_ip = htonl(((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_src_ip);
  }
 
  /*Fill UDP Header*/
  udp_ptr->udp_src_port  = htons(67);
  udp_ptr->udp_dest_port = htons(68);
  udp_ptr->udp_len       = 0x00;
  udp_ptr->udp_chksum    = 0x00;  
  
  /*Preparing response based on requested options*/
   
  /*Fill DHCP Header*/
  /*1 = BOOTREQUEST, 2 = BOOTREPLY*/
  dhcp_ptr->dhcp_op     = 0x02;
  dhcp_ptr->dhcp_htype  = ETHERNET_10Mb;
  /*length of MAC address of ethernet*/
  dhcp_ptr->dhcp_hlen   = 0x6;

  /*after reaching at 5th router, this message is discarded*/
  dhcp_ptr->dhcp_hops   = 0x5;
  dhcp_ptr->dhcp_xid    = dhcp_req_ptr->dhcp_xid;
  dhcp_ptr->dhcp_secs   = 0x00;
  dhcp_ptr->dhcp_flags  = 0x00;

  /*This field will be filled by dhcp client*/
  dhcp_ptr->dhcp_ciaddr = htonl(0x00);

  /*Retrieve dhcp client IP assignment*/
  dhcp_ptr->dhcp_yiaddr = htonl(dhcp_get_client_ip(((struct eth *)packet_ptr)->h_source));
  dhcp_ptr->dhcp_siaddr = 0x00;
  dhcp_ptr->dhcp_giaddr = 0x00;
  dhcp_ptr->dhcp_siaddr = htonl(pDhcpCtx->ip_addr);

  /*Copy Client MAC address*/
  memset((void *)dhcp_ptr->dhcp_chaddr, 0, 16);
  memcpy((void *)dhcp_ptr->dhcp_chaddr, ((struct eth *)packet_ptr)->h_source, ETH_ALEN);

  memset((void *)dhcp_ptr->dhcp_sname, 0, 64);
  memcpy((void *)dhcp_ptr->dhcp_sname, 
         (const void *)pDhcpCtx->host_name, 
         strlen(pDhcpCtx->host_name));

  memset((void *)&dhcp_ptr->dhcp_file, 0, 128);

  /*Populating Options field of DHCP*/
  offset = sizeof(struct dhcphdr) + 
           sizeof(struct udphdr)  + 
           sizeof(struct iphdr)   + 
           sizeof(struct eth);

  /*dhcp message type*/ 
  rsp_len = dhcp_populate_dhcp_options(message_type, 
                                       rsp_ptr, 
                                       offset);

  /*Populating IP Header + payload Length and it's payload length*/
  ip_ptr->ip_tot_len = htons(rsp_len - sizeof(struct ethhdr));

  /*UDP Header + Payload length*/
  udp_ptr->udp_len = htons(rsp_len - 
                           (sizeof(struct eth) + 
                           sizeof(struct iphdr)));
 
  ip_ptr->ip_chksum = utility_cksum((void *)ip_ptr,  
                                    (sizeof(uint32_t) * ip_ptr->ip_len));

  udp_ptr->udp_chksum = utility_udp_checksum((void *)ip_ptr); 

  return(rsp_len);
}/*dhcp_build_rsp*/

/** @brief This function is the main function for dhcp server
 *
 *  @param  pointer to void thread id
 *  @return none
 */
void *dhcp_main(void *tid) {
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  fd_set rd;
  int32_t max_fd;
  struct timeval to;
  int32_t ret =-1;
  uint8_t eth_buffer[1500];
  uint16_t req_len = 0;
  uint16_t max_len = sizeof(eth_buffer);

  
  for(;;) {

    FD_ZERO(&rd);
    FD_SET(pDhcpCtx->fd, &rd);
    max_fd = pDhcpCtx->fd + 1;
    /*Wait for 1 sec*/
    to.tv_sec = 1;
    to.tv_usec = 0;

    ret = select(max_fd, &rd, NULL, NULL, &to);

    if(ret > 0) {
      memset((void *)eth_buffer, 0, max_len);
      dhcp_recvfrom(pDhcpCtx->fd, eth_buffer, &req_len);
     
      if(req_len > 0) {
        if(memcmp((const void *)&eth_buffer[ETH_ALEN], 
                  (const void *)pDhcpCtx->mac_addr, 
                  ETH_ALEN)) {
          dhcp_process_eth_frame(pDhcpCtx->fd, 
                                 eth_buffer, 
                                 req_len);    
        }
      }
    }
  }
  
}/*dhcp_main*/


#endif /* __DHCP_C__ */
