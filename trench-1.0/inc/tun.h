#ifndef __TUN_H__
#define __TUN_H__

#include <type.h>

#define TUN_DEV_PATH "/dev/net/tun"

typedef struct {
  int32_t tun_fd;
  uint8_t tun_devname[16];
  uint8_t tun_ipaddr_str[16];
  uint8_t tun_netmask_str[16];
  uint8_t tun_gw_str[16];
  uint8_t eth_name[16];
  uint32_t ifindex; 

}tun_ctx_t;

int32_t tun_init(uint32_t src_ipr, 
                 uint32_t dest_ip, 
                 uint32_t net_mask,
                 uint8_t *eth_name);

int32_t tun_open_tun(void);

int32_t tun_setaddr(uint32_t ip_addr, 
                    uint32_t dst_addr, 
                    uint32_t netmask_addr);

int32_t tun_set_flags(uint32_t flags);

int32_t tun_get_tun_devname(uint8_t *tun_devname);

int32_t tun_write(uint8_t *packet_ptr, uint16_t packet_length);

int32_t tun_read(uint8_t **packet_ptr, uint16_t *packet_length);

void *tun_main(void *argv);

#endif /*__TUN_H__*/
