#ifndef __NAT_H__
#define __NAT_H__

#define DD_S_NAT_CACHE_TABLE "nat_cache_table"
#define DD_S_SERVICE_CONF_TABLE "service_conf_table"

/********************************************************************
 *  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
   |15_14_13_12_11_10_9_8_7_6_5_4_3_2_1_0| 
   |_|_ _ _ _ _ _ _|_ _ _ _ _ _ _ _ _ _ _|
   bit15 is set to 1
   bits14 - bit10 are used to designate the NAT Protocol
   bits9  - bit0 are to designate the source port
 */
typedef enum {
  NAT_PROTO_UDP  = 1,
  NAT_PROTO_TCP  = 2,
  NAU_PROTO_DNS  = 3,
  NAT_PROTO_ICMP = 4,
  NAT_PROTO_IGMP = 5,
  NAT_PROTO_RTP  = 6,
  NAT_PROTO_RTCP = 7,
  NAT_PROTO_MAX  = (1 << 5)
  
}nat_protocol_type_t;

typedef enum {
  DIR_LAN_TO_WAN = 0,
  DIR_WAN_TO_LAN = 1
}nat_dir_t;

typedef struct {
  uint32_t ip_addr;
  uint32_t dns1;
  uint32_t dns2;
  uint8_t  mac_addr[ETH_ALEN];
  uint32_t uamS_ip;
  uint16_t uamS_port;
  uint32_t redir_ip;
  uint16_t redir_port;
  uint8_t cache_table_name[255];
}nat_ctx_t;

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
                 uint8_t *cache_table_name);

/** @brief this function is used to delete entry from cache table based on dest ip and port
 *
 *  @param dest_ip is the destination ip at which request were sent in direction LAN -> TUN -> WAN
 * 
 *  @return Upon success it returns 0 else < 0
 */
int32_t nat_delete_cache(uint32_t dest_ip);

int32_t nat_update_cache(uint32_t ipaddr, 
                         uint8_t *mac_addr, 
                         uint16_t src_port, 
                         uint16_t nat_port,
                         uint32_t dest_ip);

int32_t nat_query_cache(uint16_t dest_port, 
                        uint32_t dest_ip, 
                        uint32_t *src_ip, 
                        uint8_t *mac_addr, 
                        uint16_t *src_port);

int32_t nat_perform_snat(uint8_t  *packet_ptr, 
                         uint16_t packet_length, 
                         uint8_t  *snat_ptr, 
                         uint16_t *snat_length);

/** @brief 
 *  
 *
 *  @param 
 *  @return 
 */
int32_t nat_perform_dnat(uint8_t *packet_ptr, 
                         uint16_t packet_length,
                         uint8_t *dnat_ptr,
                         uint16_t *dnat_length);




#endif /*__NAT_H__*/
