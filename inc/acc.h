#ifndef __ACC_H__
#define __ACC_H__

#define ACC_CONF_TABLE "acc_conf"
#define ACC_CACHE_TABLE "acc_cache"
#define ACC_CON_AUTH_STATUS_TABLE "acc_conn_auth_status"
#define ACC_IP_ALLOCATION_TABLE "acc_ip_allocation"



typedef struct {
  pthread_t tid[8];
  uint8_t eth_name[IFNAMSIZ];
  uint32_t ip_addr; 
  uint32_t uamS_ip;
  uint16_t uamS_port;
  uint32_t redir_ip;
  uint16_t redir_port;
  uint32_t radiusC_ip;
  uint16_t radiusC_port;
  uint32_t radiusS_ip;
  uint16_t cidr;
  uint32_t dns1;
  uint32_t dns2;
  dhcp_conf_t dhcpS_param;
  uint8_t uamS_secret[255];
  uint8_t radius_secret[255];

}acc_ctx_t;

#endif /* __ACC_H__ */
