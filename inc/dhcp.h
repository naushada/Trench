#ifndef __DHCP_H__
#define __DHCP_H__

typedef enum {
  DHCP_SERVER_PORT = 67,
  DHCP_CLIENT_PORT = 68
}udp_port_t;

typedef union {
  unsigned int ip_addr;
  unsigned char addr[4];
}dhcp_ipaddr_t;


typedef struct dhcphdr {
  unsigned char      dhcp_op;                   /* packet type */
  unsigned char      dhcp_htype;                /* type of hardware address for this machine (Ethernet, etc) */
  unsigned char      dhcp_hlen;                 /* length of hardware address (of this machine) */
  unsigned char      dhcp_hops;                 /* hops */
  unsigned int       dhcp_xid;                  /* random transaction id number - chosen by this machine */
  unsigned short int dhcp_secs;                 /* seconds used in timing */
  unsigned short int dhcp_flags;                /* flags */
  unsigned int       dhcp_ciaddr;               /* IP address of this machine (if we already have one) */
  unsigned int       dhcp_yiaddr;               /* IP address of this machine (offered by the DHCP server) */
  unsigned int       dhcp_siaddr;               /* IP address of DHCP server */
  unsigned int       dhcp_giaddr;               /* IP address of DHCP relay */
  unsigned char      dhcp_chaddr[16];           /* hardware address of this machine */
  unsigned char      dhcp_sname[64];            /* name of DHCP server */
  unsigned char      dhcp_file[128];            /* boot file name (used for diskless booting?) */
}__attribute__((packed)) dhcp_packet_t;

typedef struct {
  int  len;
  char *option;
}dhcp_option_t;

typedef struct {
  /*tag of one octet*/
  unsigned char tag;
  /*length can be of 1 octet*/
  unsigned char len;
  /*value part of the option*/
  unsigned char value[255];
}dhcp_tag_t;

typedef struct {
  unsigned char tag_count;
  dhcp_tag_t    tag[23];
}dhcp_tag_present_t;


typedef enum {
  DHCPUNKNOWN  = 0,
  DHCPDISCOVER = 1,
  DHCPOFFER    = 2,
  DHCPREQUEST  = 3,
  DHCPDECLINE  = 4,
  DHCPACK      = 5,
  DHCPNACK     = 6,
  DHCPRELEASE  = 7

}dhcp_message_type_t;


typedef enum {
  DHCP_OPTION_PAD                        = 0,
  DHCP_OPTION_SUBNET_MASK                = 1,
  DHCP_OPTION_ROUTER                     = 3,
  DHCP_OPTION_TIME_SERVER                = 4,
  DHCP_OPTION_NAME_SERVER                = 5,
  DHCP_OPTION_DOMAIN_NAME_SERVER         = 6,
  DHCP_OPTION_LOG_SERVER                 = 7,
  DHCP_OPTION_QUOTE_SERVER               = 8,
  DHCP_OPTION_IMPRESS_SERVER             = 10,
  DHCP_OPTION_ROUTER_LOCATION_SERVER     = 11,
  DHCP_OPTION_HOST_NAME                  = 12,
  DHCP_OPTION_DOMAIN_NAME                = 15,
  
  DHCP_OPTION_INTERFACE_MTU              = 26,
  DHCP_OPTION_BROADCAST_ADDRESS          = 28,
  /* Network Information Server Domain */
  DHCP_OPTION_NIS_DOMAIN                 = 40,
  /* Network Information Server */
  DHCP_OPTION_NIS                         = 41,
  DHCP_OPTION_NTP_SERVER                  = 42,
  DHCP_OPTION_VENDOR_SPECIFIC_INFO        = 43,
  DHCP_OPTION_REQUESTED_IP_ADDRESS        = 50,
  DHCP_OPTION_IP_LEASE_TIME               = 51,
  DHCP_OPTION_OPTION_OVERLOAD             = 52,
  DHCP_OPTION_MESSAGE_TYPE                = 53,
  DHCP_OPTION_SERVER_IDENTIFIER           = 54,
  DHCP_OPTION_PARAMETER_REQUEST_LIST      = 55,
  DHCP_OPTION_MESSAGE                     = 56,
  DHCP_OPTION_MAXIMUM_DHCP_MESSAGE_SIZE   = 57,
  DHCP_OPTION_RENEWAL_TIME_T1             = 58,
  DHCP_OPTION_REBINDING_TIME_T2           = 59,
  DHCP_OPTION_CLASS_IDENTIFIER            = 60,
  DHCP_OPTION_CLIENT_IDENTIFIER           = 61,
  DHCP_OPTION_RAPID_COMMIT                = 80,
  DHCP_OPTION_AUTO_CONFIGURE              = 116,

  DHCP_OPTION_END                         = 255
}dhcp_option_type_t;

typedef enum {
  ETHERNET_10Mb     = 1,
  IEEE_802_NW       = 6
  
}dhcp_arp_hdr_type_t;

typedef struct {
  uint32_t subnet_mask;
  uint32_t ns1;
  uint32_t ntp_ip;
  uint32_t time_ip;
  uint8_t domain_name[32];
  uint32_t network_id;
  uint16_t host_id_start;
  uint16_t host_id_end;
  uint16_t mtu;
  uint16_t lease;

}dhcp_conf_t;

typedef struct {
  int32_t fd;
  uint8_t mac_addr[ETH_ALEN];
  uint32_t ip_addr;
  uint8_t eth_name[IFNAMSIZ];
  uint8_t host_name[32];
  uint32_t intf_idx;
  dhcp_conf_t dhcpS_param;
  uint8_t ip_allocation_table[128];

  /*List of Optional Tag present in OFFER/REQUEST*/
  dhcp_tag_present_t opt_tag;
}dhcp_ctx_t;

/** @brief this function is used to receive ethernet fram
 *
 *  @param fd the file descriptor at which ethernet frame to be sent
 *  @param packet is the ether net packet to be sent
 *  @param packet_len is the ethernet frame length to be sent
 *
 *  @return upon success it returns length of received ethernet frame else < 0
 */
int32_t dhcp_recvfrom(int32_t fd, uint8_t *packet, uint16_t *packet_len);

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
                    uint16_t packet_len);

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
                     uint32_t netmask_addr);

/** @brief This function opens the ethernet interface for receiving ether net frame
 *
 *  @param none
 *  @return upon success it returns 0 else < 0
 */
int32_t dhcp_open(void);

/** @brief this function is used to get the mac address based on provided ip address
 *
 *  @param ip_address is the input to this function
 *  @param mac_addr is the output mac address
 *  @param upon success, it returns 0 else < 0
 */
int32_t dhcp_get_mac(uint32_t ip_address, uint8_t *mac_addr);

/** @brief This function processes the received ethernet frame
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_process_eth_frame(int32_t fd, 
                               uint8_t *packet_ptr, 
                               uint16_t packet_length);

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
              uint8_t *ip_allocation_table_name);

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
                            int32_t option_len);

/** @brief this function checks if dhcp client supports 2-way hand shake or 4-way hand shake
 *
 *  @param none
 *  @return it returns 1 meaning it does support 2-way handshake else 0
 */
uint8_t dhcp_is_two_way_handshake(void);

/** @brief This function processes the DHCP Request 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_process_request(int32_t fd, 
                             uint8_t *packet_ptr, 
                             uint16_t packet_length);

/** @brief This function processes the DHCP RELEASE and updated the data base accordingly 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_RELEASE(int32_t fd, uint8_t *packet_ptr, uint16_t packet_length);

/** @brief This function processes the DHCP OFFER Request 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_OFFER (int32_t fd, uint8_t *packet_ptr, uint16_t packet_length);

/** @brief This function processes the DHCP ACK 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_ACK (int32_t fd, uint8_t *packet_ptr, uint16_t packet_length);

/** @brief This function processes the DHCP NACK 
 *
 *  @param fd is the file descriptor
 *  @param packet_ptr is the pointer to char of received ethernet frame
 *  @param packet_length is the length of received packet
 */
int32_t dhcp_NACK (int32_t fd, uint8_t *packet_ptr, uint16_t packet_length);

/** @brief This function populates the optional parameters in response 
 *
 *  @param message_type is the reply to the request
 *  @param rsp_ptr is the pointer to response buffer
 *  @param offset is the length at which optional parameters to be filled in
 */
int32_t dhcp_populate_dhcp_options(uint8_t message_type, 
                                   uint8_t *rsp_ptr, 
                                   uint16_t offset);

/** @brief This function retrieves the dhclient hostname from stored optional parameters 
 *
 *  @param host_name is the dhclient host name which is the output 
 *  @return upon success return 0 else < 0 
 */
uint32_t dhcp_get_dhclient_host_name(uint8_t *host_name);

/** @brief This function validates whether requested ip addres can be assigned to dhclient or not 
 *
 *  @param  is the dhclient host name which is the output 
 *  @return upon success return 1 else  0 
 */
uint32_t dhcp_is_dhcpc_requested_ip(uint8_t *mac_str, uint32_t *ip_addr_ptr);

/** @brief This function allocates the ip address to chcp client 
 *
 *  @param  mac_addr is the mac address of dhcp client
 *  @return upon success returns ip_addr else  0 
 */
uint32_t dhcp_get_client_ip(uint8_t *mac_addr);

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
                       uint16_t packet_length);

/** @brief This function is the main function for dhcp server
 *
 *  @param  pointer to void thread id
 *  @return none
 */
void *dhcp_main(void *tid);


#endif

