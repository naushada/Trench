#ifndef __UTILITY_H__
#define __UTILITY_H__

uint32_t utility_ip_str_to_int(uint8_t *record);

uint32_t utility_network_id_str_to_int(uint8_t *record);

uint32_t utility_network_id_int_to_str(uint32_t network_id, uint8_t *record);

uint32_t utility_protocol_int_to_str(uint8_t ip_proto, uint8_t *protocol_str);

uint32_t utility_mac_int_to_str(uint8_t *mac_addr, uint8_t *mac_str);

uint32_t utility_ip_int_to_str(uint32_t ip_addr, uint8_t *ip_str);

uint32_t utility_mac_str_to_int(uint8_t *record, uint8_t *dst_mac);

int utility_hex_dump(uint8_t *packet, uint16_t packet_len);

uint16_t utility_cksum(void *pkt_ptr, size_t pkt_len);

uint16_t utility_udp_checksum(uint8_t *packet_ptr);

int32_t utility_coe(int32_t fd);

#endif /* __UTILITY_H__ */
