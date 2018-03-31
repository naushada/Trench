#ifndef __ICMP_H__
#define __ICMP_H__

typedef struct {
  uint32_t ip_addr;
  uint32_t subnet_mask;
}icmp_ctx_t;

typedef enum {
  /*RFC 792*/
  ICMP_ECHO_REPLY = 0,
  ICMP_DESTINATION_UNREACHABLE = 3,
  ICMP_SOURCE_QUENCH,
  ICMP_REDIRECT,
  ICMP_ALTERNATE_HOST_ADDRESS,
  ICMP_ECHO_REQUEST = 8,
  /*RFC 1256*/
  ICMP_ROUTER_ADVERTISEMENT,
  ICMP_ROUTER_SOLICITATION,
  /*RFC 792*/
  ICMP_TIME_EXCEEDED,
  ICMP_PARAMETER_PROBLEM,
  ICMP_TIMESTAMP_REQUEST,
  ICMP_TIMESTAMP_REPLY,
  ICMP_INFORMATION_REQUEST,
  ICMP_INFORMATION_REPLY,
  /*RFC 950*/
  ICMP_ADDRESS_MASK_REQUEST,
  ICMP_ADDRESS_MASK_REPLY,
  /*RFC 1393*/
  ICMP_TRACE_ROUTE = 30,
  /*RFC 1475*/
  ICMP_CONVERSION_ERROR,
  ICMP_MOBILE_HOST_REDIRECT,
  ICMP_MOBILE_REGISTRATION_REQ = 35,
  ICMP_MOBILE_REGISTRATION_REPLY,
  /*RFC 1788*/
  ICMP_DOMAIN_NAME_REQUEST,
  ICMP_DOMAIN_NAME_REPLY,
  ICMP_RESERVED = 255
   
}icmp_type_t;


int32_t icmp_build_common_header(uint8_t *rsp_ptr, 
                                 uint16_t *len, 
                                 uint8_t *packet_ptr, 
                                 uint16_t packet_length);

int32_t icmp_build_echo_reply(int16_t fd, 
                              uint8_t *packet_ptr, 
                              uint16_t packet_length);

int32_t icmp_build_response(uint8_t type, 
                            int16_t fd, 
                            uint8_t *packet_ptr, 
                            uint16_t packet_length);

int32_t icmp_init(uint32_t ip_addr, uint32_t subnet_mask);

int32_t icmp_main(int16_t fd, uint8_t *packet_ptr, uint16_t packet_length);

#endif /*__ICMP_H__*/
