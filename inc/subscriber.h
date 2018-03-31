#ifndef __SUBSCRIBER_H__
#define __SUBSCRIBER_H__

typedef struct {
  uint8_t conn_auth_status_table[128];

}subscriber_ctx_t;




int32_t subscriber_init(uint8_t *conn_auth_status_table);

int32_t subscriber_is_authenticated(uint32_t subscriber_ip, uint16_t src_port);

int32_t subscriber_add_subscriber(uint32_t ip_address, 
                                  uint8_t *src_mac_ptr, 
                                  uint16_t src_port);

int32_t subscriber_add_info(uint32_t ip_address,
                            uint16_t dest_port,
                            uint8_t *uri,
                            uint8_t *auth_state);

int32_t subscriber_get_auth_state(uint32_t ip_address, 
                                  uint8_t *auth_state);

int32_t subscriber_update_auth_state(uint32_t ip_address, 
                                     uint8_t *auth_state);


#endif /* __SUBSCRIBER_H__ */
