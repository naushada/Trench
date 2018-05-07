#ifndef __TCP_H__
#define __TCP_H__


typedef enum {
  TCP_URG_BIT = (1 << 5),
  TCP_ACK_BIT = (1 << 4),
  TCP_PSH_BIT = (1 << 3),
  TCP_RST_BIT = (1 << 2),
  TCP_SYN_BIT = (1 << 1),
  TCP_FIN_BIT = (1 << 0)
}tcp_control_bits_t;

/********************************************************************
 *TCP Header
 *
 ********************************************************************/
struct tcp {
  uint16_t  src_port;
  uint16_t  dest_port;
  uint32_t  seq_num;
  uint32_t  ack_number;
  uint16_t  flags;
  uint16_t  window;
  uint16_t  check_sum;
  uint16_t  urgent_ptr;
  
}__attribute__((packed));

/********************************************************************
 *TCP Internal Context Table
 *
 ********************************************************************/
typedef struct {
  uint32_t ip_addr;
  uint32_t ip_mask;
  uint16_t uamS_port;
  uint16_t redir_port;

}tcp_ctx_t;

int32_t tcp_init(uint32_t ip_addr, 
                 uint32_t ip_mask,
                 uint16_t uamS_port,
                 uint16_t redir_port);

uint16_t tcp_checksum(uint8_t *packet_ptr);

int32_t tcp_main(uint16_t fd, 
                 uint8_t *packet_ptr, 
                 uint16_t packet_length);

int32_t tcp_reset_tcp(uint8_t *packet_ptr, 
                      uint16_t packet_length, 
                      uint8_t *rsp_ptr, 
                      uint16_t *rsp_len_ptr);
#endif /*__TCP_H__*/
