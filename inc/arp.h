#ifndef __ARP_H__
#define __ARP_H__

typedef struct arp_cache_t arp_cache_tt;

typedef enum {
  ARP_RESERVED,
  ARP_REQUEST,
  ARP_REPLY,
  RARP_REQUEST,
  RARP_REPLY
}arp_op_code_t;

typedef struct {
  uint8_t  mac[ETH_ALEN];
  uint32_t ip_addr;
 
}arp_ctx_t;


uint32_t arp_build_ARP_request(uint32_t dest_ip);

int arp_process_ARP_request(int32_t fd, 
                            uint8_t *packet_ptr, 
                            uint16_t packet_length);

uint32_t arp_main(int32_t fd, 
                  uint8_t *packet_ptr, 
                  uint16_t packet_length);

uint32_t arp_init(uint8_t *mac_addr, uint32_t ip_addr);

#endif /* __ARP_H__ */
