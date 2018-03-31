#ifndef __NET_H__
#define __NET_H__

/*Data structure definition*/
typedef struct {
  /*Ethernet Interface Index*/
  uint8_t intf_idx;
  /*Ethernet Interface name - eth0 or eth1 etc*/
  uint8_t eth_name[IFNAMSIZ];
}net_ctx_t;

/** @brief This function initialises global for its further use
 *
 *  @param eth_param the name of ethernet interface
 *
 *  @return uopn success it returns 0 else < 0
 */
int32_t net_init(uint8_t *eth_name);

int32_t open_eth(uint8_t *eth_name);

int32_t ndelay_on(int32_t fd);

int32_t coe(int32_t fd);

int32_t read_eth_frame(int32_t fd, uint8_t *packet, uint16_t *packet_len);

int32_t write_eth_frame(int32_t fd, uint8_t *dst_mac, uint8_t *packet, uint16_t packet_len);

int32_t net_setaddr(uint8_t *interface_name,
                    uint32_t ip_addr, 
                    uint32_t netmask_addr);
#endif
