#ifndef __ACC_H__
#define __ACC_H__

#define ACC_CONF_TABLE "acc_conf"
#define ACC_CACHE_TABLE "acc_cache"
#define ACC_CON_AUTH_STATUS_TABLE "acc_conn_auth_status"
#define ACC_IP_ALLOCATION_TABLE "acc_ip_allocation"
#define ACC_DNS_TABLE "acc_dns"

typedef struct {
  pthread_t tid[10];
  uint8_t eth_name[IFNAMSIZ];
  uint32_t ip_addr; 
  uint32_t uamS_ip;
  uint16_t uamS_port;
  uint32_t redir_ip;
  uint16_t redir_port;
  uint32_t radiusC_ip;
  uint16_t radiusC_port;
  uint16_t uidaiC_port;
  uint16_t oauth2_port;
  uint32_t radiusS_ip;
  uint16_t cidr;
  uint32_t dns1;
  uint32_t dns2;
  dhcp_conf_t dhcpS_param;
  uint8_t uamS_secret[255];
  uint8_t radius_secret[255];

}acc_ctx_t;

int32_t acc_update_dns(uint8_t *host_name, uint8_t *ip_str);

int32_t acc_resolve_dns(uint8_t *host_name);

int32_t acc_get_hostname(uint8_t *table_name);
#endif /* __ACC_H__ */
