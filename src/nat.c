/** @file nat.c
 *  @brief This file contains the source natting and destination natting. 
 *
 *  This contains the core logic of source natting and destination natting
 *  along with other subfunction which facillitates source and destination natting
 *  
 *
 *  @author Mohd. Naushad Ahmed
 *  @bug No known bugs.
 */

#ifndef __NAT_C__
#define __NAT_C__

#include <type.h>
#include <transport.h>
#include <common.h>
#include <db.h>
#include <subscriber.h>
#include <nat.h>
#include <utility.h>
#include <subscriber.h>
#include <tun.h>
#include <tcp.h>
#include <dhcp.h>

/********************************************************************
 * Global Instance
 ********************************************************************/
nat_ctx_t nat_ctx_g;

/********************************************************************
 *Function Definition
 ********************************************************************/

/** @brief This function initializes global for NAT functionality
 *
 *  @param ip_addr is the ip_addr of accesscontroller
 *  @param dns1 is Public Domain Name Server1
 *  @param dns2 is the Public Domain Name Server2
 *  @param redir_ip is the ip address at which uer will be redirected for login page
 *  @param redir_port is the port for redirection of HTTP request
 *  @param uamS_ip is the ip address of UAM Server at which user will be supplying the credentials
 *  @param uamS_port is the port at which user will be redirected for login page
 *  @param cache_table_name is the cache table name maintained by NAT
 *
 *  @return upon success returns 0 else < 0
 */
int32_t nat_init(uint32_t ip_addr,
                 uint32_t dns1,
                 uint32_t dns2,
                 uint32_t redir_ip,
                 uint16_t redir_port,
                 uint32_t uamS_ip,
                 uint32_t uamS_port,
                 uint8_t *cache_table_name) {

  nat_ctx_t *pNatCtx = &nat_ctx_g;
 
  pNatCtx->ip_addr = ip_addr;
  pNatCtx->redir_ip = redir_ip;
  pNatCtx->redir_port = redir_port;
  pNatCtx->dns1 = dns1;
  pNatCtx->dns2 = dns2;
  pNatCtx->uamS_ip = uamS_ip;
  pNatCtx->uamS_port = uamS_port;

  strncpy((char *)pNatCtx->cache_table_name, 
          (const char *)cache_table_name, 
          strlen((const char *)cache_table_name));

  return(0);
}/*nat_init*/

/** @brief this function is used to delete entry from cache table based on dest ip and port
 *
 *  @param dest_port is the destination port in the direction WAN -> TUN - > LAN
 *  @param dest_ip is the destination ip at which request were sent in direction LAN -> TUN -> WAN
 * 
 *  @return Upon success it returns 0 else < 0
 */
int32_t nat_delete_cache(uint16_t dest_port,
                         uint32_t dest_ip) {
  uint8_t sql_query[255];
  int32_t ret = -1;
  uint8_t ipaddr_str[40];
  nat_ctx_t *pNatCtx = &nat_ctx_g;

  memset((void *)ipaddr_str, 0, sizeof(ipaddr_str));

  utility_ip_int_to_str(ntohl(dest_ip), ipaddr_str);

  ret = snprintf((char *)sql_query, 
                 sizeof(sql_query),
                 "%s%s%s%d%s"
                 "%s%s",
                 "DELETE FROM ",
                 pNatCtx->cache_table_name,
                 " WHERE (src_port='",
                 dest_port,
                 "' AND dest_ip='",
                 ipaddr_str,
                 "')");

  if(db_exec_query(sql_query)) {
    fprintf(stderr, "\n%s:%d::Deletion of entry failed\n", __FILE__, __LINE__);
    return(-1);
  }
  (void)ret;
  return(0);

}/*nat_delete_cache*/

int32_t nat_update_cache(uint32_t ipaddr, 
                         uint8_t *mac_addr, 
                         uint16_t src_port, 
                         uint16_t nat_port,
                         uint32_t dest_ip) {
  int32_t ret = -1;
  uint8_t sql_query[256];
  int32_t row;
  int32_t col;
  int8_t  record[2][16][32];
  uint8_t mac_str[32];
  uint8_t ipaddr_str[32];
  uint8_t dest_ipaddr_str[32];
  nat_ctx_t *pNatCtx = &nat_ctx_g;

  memset((void *)mac_str, 0, sizeof(mac_str));
  memset((void *)ipaddr_str, 0, sizeof(ipaddr_str));

  utility_ip_int_to_str(ipaddr, ipaddr_str);
  utility_ip_int_to_str(dest_ip, dest_ipaddr_str);
  utility_mac_int_to_str(mac_addr, mac_str);

  ret = snprintf((char *)sql_query, 
                sizeof(sql_query),
                "%s%s%s%s%s"
                "%s%s%d%s%s"
                "%s%d%s",
                "SELECT * FROM ",
                pNatCtx->cache_table_name,
                " WHERE (src_ip='",
                ipaddr_str,
                "' AND src_mac='",
                mac_str,
                "' AND src_port='",
                src_port,
                "' AND dest_ip='",
                dest_ipaddr_str,
                "' AND dest_port='",
                nat_port,
                "')");

  if(!db_exec_query((uint8_t *)sql_query)) {

    memset((void *)record, 0, sizeof(record));
    row = 0, col = 0;
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {

      /*Process The Reqult*/
      if(!row) {
        /*No Record found , Insert it*/
        memset((void *)&sql_query, 0, sizeof(sql_query));
        ret = snprintf((char *)sql_query,
                       sizeof(sql_query),
                       "%s%s%s%s%s"
                       "%s%s%d%s%s"
                       "%s%d%s",
                       "INSERT INTO ",
                       pNatCtx->cache_table_name,
                       " (src_ip, src_mac, src_port, dest_ip, dest_port) VALUES ('",
                       ipaddr_str,
                       "' , '",
                       mac_str,
                       "' , '",
                       src_port,
                       "' , '",
                       dest_ipaddr_str,
                       "' , '",
                       nat_port,
                       "')");

        if(db_exec_query((uint8_t *)sql_query)) {
          fprintf(stderr, "\n%s:%d Insertion to Database failed\n", __FILE__, __LINE__);
          return(-3);
        }
      }
    }
  }
  (void)ret;

  return(0);
}/*nat_update_cache*/

int32_t nat_query_cache(uint16_t dest_port, 
                        uint32_t dest_ip, 
                        uint32_t *src_ip, 
                        uint8_t *mac_addr, 
                        uint16_t *src_port) {
  int32_t row;
  int32_t col;
  uint8_t record[2][16][32];
  uint8_t sql_query[256];
  uint8_t  dest_ip_str[40];
  nat_ctx_t *pNatCtx = &nat_ctx_g;

  memset((void *)dest_ip_str, 0, sizeof(dest_ip_str));
  utility_ip_int_to_str(dest_ip, dest_ip_str);

  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%d%s"
           "%s%s",
           "SELECT * FROM ",
           pNatCtx->cache_table_name,
           " WHERE (src_port='",
           dest_port,
           "' AND src_ip='",
           dest_ip_str,
           "')");

  if(!db_exec_query((uint8_t *)sql_query)) {
    
    memset((void *)&record, 0, sizeof(record));
    row = 0;
    col = 0;
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      if(row) {
        /*MAC Address*/
        utility_mac_str_to_int(record[0][1], mac_addr);
        /*dest Port would now become src port*/
        sscanf((const char *)record[0][4], "%d", (uint32_t *)src_port);
        /*src_ip will hold the value of dest ip*/
        *src_ip = utility_ip_str_to_int(record[0][3]);
      } else {

        fprintf(stderr, "\n%s:%d no Row found for ip_address %s and nat_port %d\n%s\n", 
                        __FILE__,
                        __LINE__,
                        dest_ip_str,
                        dest_port,
                        sql_query);

      }
    }
  }

  return(row);
}/*nat_query_cache*/

int32_t nat_perform_snat(uint8_t  *packet_ptr, 
                         uint16_t packet_length, 
                         uint8_t  *snat_ptr, 
                         uint16_t *snat_length) {

  struct iphdr  *ip_ptr  = NULL;
  uint16_t nat_port = 0x0000;
  uint16_t ip_header_len = 0x0000;
  uint32_t dest_ip;

  nat_ctx_t *pNatCtx = &nat_ctx_g;

  struct eth *eth_ptr = (struct eth *)packet_ptr;

  /*Learn the mac of this system*/
  if(memcmp(pNatCtx->mac_addr, eth_ptr->h_dest, ETH_ALEN)) {
    memcpy((void *)pNatCtx->mac_addr, (const void *)eth_ptr->h_dest, ETH_ALEN);
  }

  /*what protocol is this? - what type of frame is followed the Ethernet Header*/
  if(0x0800 == htons(eth_ptr->h_proto)) {
    
    ip_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)];
    ip_header_len = (ip_ptr->ip_len * 4);

    /*copy ip header + its payload*/
    memcpy((void *)snat_ptr, 
           (const void *)&packet_ptr[sizeof(struct eth)], 
           ntohs(ip_ptr->ip_tot_len));

    *snat_length = ntohs(ip_ptr->ip_tot_len);

    switch(ip_ptr->ip_proto) {

      case IP_IGMP:
      break;
      case IP_TCP:
      {
        uint16_t src_port;
        uint16_t dest_port;
        uint32_t src_ip;
        struct tcp *tcphdr_ptr;
        struct iphdr *iphdr_ptr;
        int32_t ret;

        iphdr_ptr = (struct iphdr *)snat_ptr;
        tcphdr_ptr = (struct tcp *)&snat_ptr[ip_header_len];

        src_port = ntohs(tcphdr_ptr->src_port);
        dest_port = ntohs(tcphdr_ptr->dest_port);
        
        src_ip = iphdr_ptr->ip_src_ip;
        dest_ip = iphdr_ptr->ip_dest_ip;

        if((80 == dest_port) || (pNatCtx->redir_port == dest_port)) {
          ret = subscriber_is_authenticated(src_ip, src_port);

          if(!ret) {
            /*New connection Request, update the cache with it*/
            nat_update_cache(src_ip, 
                             eth_ptr->h_source, 
                             src_port,
                             /*destination port*/
                             dest_port,
                             /*destination ip*/
                             dest_ip);

            /*Update the subscriber info as well*/
            //subscriber_add_subscriber(src_ip, eth_ptr->h_source, src_port);
          }

          if((!ret) || (1 == ret)) {
            /*Redirect Request to Redir Server to get Authentication done*/
#if 0
            fprintf(stderr, "\n%s:%d dest_ip 0x%X redir_ip 0x%X\n", 
                            __FILE__,
                            __LINE__,
                            iphdr_ptr->ip_dest_ip, 
                            pNatCtx->redir_ip);
#endif
            iphdr_ptr->ip_dest_ip = htonl(pNatCtx->redir_ip);
            iphdr_ptr->ip_src_ip = src_ip;

            /*IP Header checksum calculation - only header part*/
            iphdr_ptr->ip_chksum = 0;
            iphdr_ptr->ip_chksum = utility_cksum((void *)iphdr_ptr, ip_header_len);
          
            /*Modify the TCP headera as per need*/
            tcphdr_ptr->dest_port = htons(pNatCtx->redir_port);
            tcphdr_ptr->check_sum = 0;
            tcphdr_ptr->check_sum = tcp_checksum(snat_ptr);
          }
        }
      }
      break;

      case IP_UDP:
      {
        struct iphdr *iphdr_ptr = (struct iphdr *)snat_ptr;
        struct udphdr *udphdr_ptr = (struct udphdr *)&snat_ptr[ip_header_len];

        /*Message structure is based on destination UDP Port*/
        if(53 == ntohs(udphdr_ptr->udp_dest_port)) {
          /*DNS Query*/

          /*Change the destination ip-address*/
          iphdr_ptr->ip_dest_ip = htonl(pNatCtx->dns1);
          iphdr_ptr->ip_chksum = 0;
          iphdr_ptr->ip_chksum = utility_cksum((void *)iphdr_ptr, ip_header_len);

          /*Computing UDP Checksum*/
          udphdr_ptr->udp_chksum = 0;
          udphdr_ptr->udp_chksum  = utility_udp_checksum(snat_ptr);
        }
      }
      break;

      default:
      break; 
    }
  }

  return(0);
}/*dns_perform_snat*/

/** @brief 
 *  
 *
 *  @param 
 *  @return 
 */
int32_t nat_perform_dnat(uint8_t *packet_ptr, 
                         uint16_t packet_length,
                         uint8_t *dnat_ptr,
                         uint16_t *dnat_length) {

  uint16_t ip_header_len = 0x00;
  uint16_t nat_port = 0x00;
  uint16_t src_port = 0x00;
  int32_t ret = -1;

  nat_ctx_t *pNatCtx = &nat_ctx_g;

  /*copy the received ip packet into dnat_ptr*/
  memcpy((void *)&dnat_ptr[sizeof(struct eth)], 
         (const void *)packet_ptr, 
         packet_length);
  *dnat_length = packet_length + sizeof(struct eth);
 
  struct iphdr *dnat_iphdr_ptr = (struct iphdr *)&dnat_ptr[sizeof(struct eth)];
  ip_header_len = (4 * dnat_iphdr_ptr->ip_len);

  /*Populating Ethernet Header for IP Protocol*/
  struct eth *dnat_eth_ptr = (struct eth *)dnat_ptr;

  dhcp_get_mac(dnat_iphdr_ptr->ip_dest_ip, 
               dnat_eth_ptr->h_dest);

  memcpy((void *)dnat_eth_ptr->h_source, 
         (const void *)pNatCtx->mac_addr, 
         ETH_ALEN);

  dnat_eth_ptr->h_proto = htons(0x0800);
      
  switch(dnat_iphdr_ptr->ip_proto) {
    case IP_IGMP:
    break;
    case IP_TCP:
    {
      uint8_t dest_mac[6];
      uint16_t dest_port;
      uint16_t src_port;
      uint32_t src_ip = 0;
      uint32_t dest_ip = 0;
      uint8_t query_status = 0;

      struct iphdr *iphdr_ptr = NULL;
      struct tcp *tcphdr_ptr = NULL;

      iphdr_ptr = (struct iphdr *)&dnat_ptr[sizeof(struct eth)];

      dest_ip = iphdr_ptr->ip_dest_ip;
      src_ip = ntohl(iphdr_ptr->ip_src_ip);

      tcphdr_ptr = (struct tcp *)&dnat_ptr[sizeof(struct eth) + ip_header_len];

      dest_port = ntohs(tcphdr_ptr->dest_port);
      src_port = ntohs(tcphdr_ptr->src_port);

      ret = subscriber_is_authenticated(dest_ip, dest_port);

      if((0 == ret) && (ntohl(dest_ip) != pNatCtx->uamS_ip)) {
        /*connection is not yet authenticated*/
        /*Retrieve the IP, MAC from cache based on nat_port*/
        ret = nat_query_cache(dest_port,
                              (uint32_t)dest_ip, 
                              /*destination ip before snat*/
                              (uint32_t *)&src_ip,
                              (uint8_t *)dest_mac,
                              (uint16_t *)&src_port);
 
        /*Modifying the destination IP Address*/
        iphdr_ptr->ip_src_ip = htonl(src_ip);
        iphdr_ptr->ip_chksum = 0;
        iphdr_ptr->ip_chksum = utility_cksum(iphdr_ptr, ip_header_len); 

        /*TCP Dest Port Modification*/
        tcphdr_ptr->src_port = htons(src_port);
        /*checksum field has to be reset before computing it.*/
        tcphdr_ptr->check_sum = 0;
        tcphdr_ptr->check_sum = tcp_checksum(&dnat_ptr[sizeof(struct eth)]);

      } else if(2 == ret) {
        /*connection is authenticated*/
        /*Accounting Management*/
        /*Retrieve the IP, MAC from cache based on nat_port*/
        query_status = nat_query_cache(dest_port,
                                       (uint32_t)dest_ip, 
                                       /*destination ip before snat*/
                                       (uint32_t *)&src_ip,
                                       (uint8_t *)dest_mac,
                                       (uint16_t *)&src_port);
        if(query_status) {
          /*Entry in cache table found, delete it.*/
          nat_delete_cache(dest_port, src_ip);
        }

      } else if(3 == ret) {
        /*Authentication is rejected , reset the connection*/
      }
    }
    break;

    case IP_UDP:
    {
      struct udphdr *dnat_udphdr_ptr = (struct udphdr *)&dnat_ptr[sizeof(struct eth) + ip_header_len];
 
      dnat_iphdr_ptr->ip_src_ip = htonl(pNatCtx->ip_addr);
      
      /*IP Header checksum*/
      dnat_iphdr_ptr->ip_chksum = 0;
      dnat_iphdr_ptr->ip_chksum = utility_cksum((void *)dnat_iphdr_ptr, ip_header_len);

      /*Computing UDP Checksum*/
      dnat_udphdr_ptr->udp_chksum = 0;
      dnat_udphdr_ptr->udp_chksum  = utility_udp_checksum(&dnat_ptr[sizeof(struct eth)]);
    }
    break;

    default:
    break;
  }
  return(0);

}/*dns_perform_dnat*/


#endif /* __NAT_C__ */
