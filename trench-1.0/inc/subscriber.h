#ifndef __SUBSCRIBER_H__
#define __SUBSCRIBER_H__

typedef struct {
  uint8_t conn_auth_status_table[128];
  uint8_t dns_table[128];

}subscriber_ctx_t;


int32_t subscriber_init(uint8_t *conn_auth_status_table,
                        uint8_t *dns_table);

int32_t subscriber_is_authenticated(uint32_t subscriber_ip);

int32_t subscriber_update_conn_status(uint8_t *ip_str,
                                      uint8_t *status);

#endif /* __SUBSCRIBER_H__ */
