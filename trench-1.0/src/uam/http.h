#ifndef __HTTP_H__
#define __HTTP_H__


typedef struct {
  uint8_t *uri;
  uint16_t uri_len;
  int32_t (*http_req_cb)(uint32_t con_fd,
                         uint8_t **response_ptr, 
                         uint32_t *response_len_ptr);
}http_req_handler_t;

typedef struct {
  uint8_t *gmail_url;
  uint8_t oauth2_rsp;
}http_oauth2_rsp_param_t;

typedef struct {
  /*could hold either mobile/Aadhaar Number*/
  uint8_t uid[14];
  uint8_t status[16];
  /*Reason of failure*/
  uint8_t reason[32];
  uint8_t uidai_rsp;
  /*uid holder's name*/
  uint8_t uid_name[128];
}http_uidai_rsp_param_t;

struct http_session_t {
  uint32_t conn;
  struct sockaddr_in peer_addr;
  uint8_t method[8];
  uint8_t protocol[8];
  uint8_t uri[2024];
  uint8_t url[2024];
  uint16_t mime_header_count;
  uint8_t mime_header[32][2][255];
  /*Holds the response parameters from uidai response*/
  http_uidai_rsp_param_t uidai_param;
  /*oauth2 param for google login*/
  http_oauth2_rsp_param_t oauth2_param;
  struct http_session_t *next;

};

typedef struct http_session_t http_session_t;

typedef struct {
  uint32_t uam_ip;
  uint16_t uam_port;
  int32_t uam_fd;

  uint32_t nas_ip;
  uint16_t nas_port;
  int32_t nas_fd;

  /*pointer to session structure*/
  http_session_t *session;

  http_req_handler_t *pHandler;
}http_ctx_t;


int32_t http_recv(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint32_t *packet_length);

int32_t http_send(int32_t fd, 
                  uint8_t *packet_ptr, 
                  uint32_t packet_length);

void http_swap(uint32_t *a, 
               uint32_t *b);

uint32_t http_partition(http_session_t *session, 
                        int16_t low, 
                        int16_t high);

void http_quick_sort(http_session_t *session, 
                     int16_t low_idx, 
                     int16_t high_idx);

void http_modify_conn_count(http_session_t *session);

int32_t http_process_req(uint32_t con_fd, 
                         uint8_t *packet_ptr, 
                         uint32_t packet_length);

int32_t http_init(uint32_t uam_ip, 
                  uint16_t uam_port,
                  uint32_t nas_ip,
                  uint16_t nas_port);

void *http_main(void *argv);

int32_t http_process_req(uint32_t con_fd, 
                         uint8_t *packet_ptr, 
                         uint32_t packet_length);

int32_t http_process_sign_in_req(uint32_t con_fd,
                                 uint8_t **response_ptr, 
                                 uint32_t *response_len_ptr);

int32_t http_process_register_req(uint32_t con_fd,
                                  uint8_t **response_ptr, 
                                  uint32_t *response_len_ptr);

int32_t http_process_login_with_mobile_no_req(uint32_t con_fd,
                                              uint8_t **response_ptr, 
                                              uint32_t *response_len_ptr);

int32_t http_process_ui_req(uint32_t con_fd,
                            uint8_t **response_ptr, 
                            uint32_t *response_len_ptr);

int32_t http_process_login_req(uint32_t con_fd,
                               uint8_t **response_ptr, 
                               uint32_t *response_len_ptr);

int32_t http_process_image_req(uint32_t con_fd,
                               uint8_t **response_ptr, 
                               uint32_t *response_len_ptr);
 
int32_t http_process_auth_response_req(uint32_t con_fd,
                                       uint8_t **response_ptr,
                                       uint32_t *response_len_ptr);

int32_t http_process_redirect_req(uint32_t conn_id,
                                  uint8_t **response_ptr,
                                  uint32_t *response_len_ptr,
                                  uint8_t *location_uri);

int32_t http_process_aadhaar_ui_req(uint32_t conn_id,
                                    uint8_t **response_ptr,
                                    uint32_t *response_len_ptr);

int32_t http_process_aadhaar_otp_req(uint32_t conn_id,
                                     uint8_t **response_ptr,
                                     uint32_t *response_len_ptr);

int32_t http_process_aadhaar_uid_req(uint32_t conn_id,
                                     uint8_t **response_ptr,
                                     uint32_t *response_len_ptr);


http_session_t *http_get_session(uint32_t conn_id);

int32_t http_build_otp_in_form(uint32_t conn_id,
                               uint8_t **response_ptr,
                               uint32_t *response_len_ptr);

int32_t http_process_aadhaar_auth_otp_req(uint32_t conn_id, 
                                          uint8_t **response_ptr, 
                                          uint32_t *response_len_ptr);

int32_t http_process_wait_req(uint32_t conn_id,
                              uint8_t **response_ptr, 
                              uint32_t *response_len_ptr,
                              uint8_t *refresh_uri);

int32_t http_process_aadhaar_auth_req(uint32_t conn_id, 
                                      uint8_t **response_ptr, 
                                      uint32_t *response_len_ptr);

int32_t http_build_aadhaar_auth_otp_req(uint32_t conn_id, 
                                        uint8_t *req, 
                                        uint32_t *req_len);

int32_t http_send_to_nas(uint32_t conn_id, 
                         uint8_t *req, 
                         uint32_t req_len);

int32_t http_parse_aadhaar_uid_req(uint32_t conn_id, 
                                  uint8_t *req_ptr, 
                                  uint32_t *req_len_ptr);

int32_t http_build_aadhaar_auth_pi_req(uint32_t conn_id, uint8_t *req, uint32_t *req_len);


int32_t http_process_aadhaar_auth_pi_req(uint32_t conn_id, 
                                         uint8_t **response_ptr,
                                         uint32_t *response_len_ptr);

int32_t http_parse_param(uint8_t (*param)[2][64], uint8_t *rsp_ptr);

uint8_t *http_get_param(uint8_t (*param)[2][64], uint8_t *arg);

int32_t http_process_favicon_req(uint32_t conn_id,
                                 uint8_t **response_ptr, 
                                 uint32_t *response_len_ptr);

int32_t http_process_google_ui_req(uint32_t conn_id, 
                                   uint8_t **response_ptr,
                                   uint32_t *response_len_ptr);

int32_t http_process_twitter_ui_req(uint32_t conn_id, 
                                    uint8_t **response_ptr,
                                    uint32_t *response_len_ptr);

int32_t http_process_fb_ui_req(uint32_t conn_id, 
                               uint8_t **response_ptr,
                               uint32_t *response_len_ptr);

int32_t http_process_aadhaar_rsp(uint8_t *packet_ptr,
                                 uint32_t packet_length);

int32_t http_process_google_rsp(uint8_t *packet_ptr, 
                                uint32_t packet_length);

uint8_t *http_get_param_ex(uint8_t (*param)[2][255], uint8_t *arg);

int32_t http_parse_param_ex(uint8_t (*param)[2][255], uint8_t *rsp_ptr);

int32_t http_process_google_access_code_req(uint32_t conn_id,
                                            uint8_t **response_ptr,
                                            uint32_t *response_len_ptr);

int32_t http_process_google_access_token_req(uint32_t conn_id,
                                             uint8_t **response_ptr,
                                             uint32_t *response_len_ptr);
uint8_t *http_get_gparam(uint8_t *req_ptr, 
                         uint32_t req_len, 
                         uint8_t *p_name);

#endif /* __HTTP_H__ */
