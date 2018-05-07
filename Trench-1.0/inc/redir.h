#ifndef __REDIR_H__
#define __REDIR_H__

#define REDIR_DNS_TABLE "acc_dns"

typedef struct {
  uint8_t *uri;
  uint16_t uri_len;
  int32_t (*redir_req_cb)(uint32_t con_fd,
                         uint8_t **response_ptr, 
                         uint16_t *response_len_ptr);
}redir_req_handler_t;

struct redir_session_t {
  
  uint32_t conn;
  /*connection at which user is connected with uam*/
  uint32_t ext_conn;
  /*ip address at from which browser is connected*/
  uint8_t ip_str[32];
  struct sockaddr_in peer_addr;
  uint8_t method[8];
  uint8_t protocol[16];
  uint8_t uri[2048];
  uint8_t url[2048];
  uint16_t mime_header_count;
  uint8_t mime_header[32][2][255];
  struct redir_session_t *next;

};

typedef struct redir_session_t redir_session_t;

typedef struct {
  uint32_t redir_listen_ip;
  uint16_t redir_listen_port;
  uint32_t uam_ip;
  uint16_t uam_port;
  int32_t redir_fd;
  /*radiusC port & fd*/
  uint16_t radiusC_port;
  int32_t radiusC_fd;
  /*uidaiC port & fd*/
  uint16_t uidaiC_port;
  int32_t uidaiC_fd;
  /*oauth2 port & fd*/
  uint16_t oauth2_port;
  int32_t oauth2_fd;

  /*Holds the Name of connection Status Table*/
  uint8_t conn_auth_status_table[128];
  /*Holds the ip allocation status*/
  uint8_t ip_allocation_table[128];
  
  redir_session_t *session;
  redir_req_handler_t *pHandler;

}redir_ctx_t;


int32_t redir_recv(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint16_t *packet_length);

int32_t redir_send(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint16_t packet_length);

void redir_swap(uint32_t *a, 
                uint32_t *b);

uint32_t redir_partition(redir_session_t *session, 
                         int16_t low, 
                         int16_t high);

void redir_quick_sort(redir_session_t *arr, 
                      int16_t low_idx, 
                      int16_t high_idx);

void redir_modify_conn_count(redir_session_t *conn);

int32_t redir_process_req(uint32_t con_fd, 
                          uint8_t *packet_ptr, 
                          uint16_t packet_length);

redir_session_t *redir_get_session(uint32_t conn_id);

int32_t redir_init(uint32_t redir_listen_ip, 
                   uint16_t redir_listen_port, 
                   uint32_t uam_ip, 
                   uint16_t uam_port,
                   uint16_t radiusC_port,
                   uint16_t uidaiC_port,
                   uint16_t oauth2_port,
                   uint8_t *conn_status_table,
                   uint8_t *ip_allocation_table);

void *redir_main(void *argv);

int32_t redir_process_rejected_req(uint32_t conn_id,
                                   uint8_t **response_ptr,
                                   uint16_t *response_len_ptr);

int32_t redir_process_image_req(uint32_t conn_id,
                                uint8_t **response_ptr, 
                                uint16_t *response_len_ptr);

int32_t redir_update_conn_status_success(uint32_t conn_id);

int32_t redir_process_response_callback_req(uint32_t conn_id,
                                            uint8_t **response_ptr,
                                            uint16_t *response_len_ptr);

int32_t redir_process_time_out_req(uint32_t conn_id,
                                   uint8_t **response_ptr,
                                   uint16_t *response_len_ptr);

int32_t redir_process_wait_req(uint32_t conn_id,
                              uint8_t **response_ptr, 
                              uint16_t *response_len_ptr,
                              uint8_t *refresh_uri);

int32_t redir_radiusC_connect(void);

int32_t redir_build_access_request(uint32_t conn_id, 
                                   uint8_t *email_id, 
                                   uint8_t *password);

int32_t redir_process_response_callback_uri(uint32_t conn_id, 
                                            uint8_t *uri);

int32_t redir_process_redirect_req(uint32_t conn_id,
                                   uint8_t **response_ptr,
                                   uint16_t *response_len_ptr);

int32_t redir_process_auth_response(uint32_t conn_id,
                                    uint8_t **response_ptr,
                                    uint16_t *response_len_ptr,
                                    uint8_t *location_ptr);

int32_t redir_process_uidai_response(uint32_t conn_id, 
                                     uint8_t *packet_buffer, 
                                     uint32_t packet_length);

int32_t redir_process_aadhaar_req(uint32_t conn_id, uint8_t *uri);

int32_t redir_parse_aadhaar_req(uint8_t *req_ptr, uint8_t *uri);

uint8_t *redir_get_param(uint8_t *req_ptr, uint8_t *arg);

int32_t redir_send_to_uidai(uint32_t conn_id, 
                            uint8_t *uidai_req, 
                            uint32_t uidai_req_len);

int32_t redir_uidaiC_connect(void);

int32_t redir_oauth2_connect(void);

int32_t redir_compute_ts(uint8_t *ts, uint32_t ts_size);

int32_t redir_process_login_req(uint32_t conn_id, uint8_t *uri);

int32_t redir_update_stats(uint32_t conn_id, uint8_t *packet_ptr, uint32_t packet_length);

int32_t redir_populate_dns(uint8_t *table_name);

int32_t redir_resolve_dns(uint8_t *host_name);

int32_t redir_update_dns(uint8_t *host_name, uint8_t *ip_str);
#endif /* __REDIR_H__ */
