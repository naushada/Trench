#ifndef __HTTP_H__
#define __HTTP_H__


typedef struct {
  uint8_t *uri;
  uint16_t uri_len;
  int32_t (*http_req_cb)(uint32_t con_fd,
                         uint8_t **response_ptr, 
                         uint16_t *response_len_ptr);
}http_req_handler_t;

struct http_session_t {
  uint32_t conn;
  struct sockaddr_in peer_addr;
  uint8_t method[8];
  uint8_t protocol[8];
  uint8_t uri[255];
  uint8_t url[1024];
  uint16_t mime_header_count;
  uint8_t mime_header[16][2][255];
  struct http_session_t *next;

};

typedef struct http_session_t http_session_t;

typedef struct {
  uint32_t uam_ip;
  uint16_t uam_port;
  int32_t  uam_fd;

  uint32_t nas_ip;
  uint16_t nas_port;

  /*pointer to session structure*/
  http_session_t *session;

  http_req_handler_t *pHandler;
}http_ctx_t;


int32_t http_recv(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint16_t *packet_length);

int32_t http_send(int32_t fd, 
                  uint8_t *packet_ptr, 
                  uint16_t packet_length);

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
                         uint16_t packet_length);

int32_t http_init(uint32_t uam_ip, 
                  uint16_t uam_port,
                  uint32_t nas_ip,
                  uint16_t nas_port);

void *http_main(void *argv);

int32_t http_process_req(uint32_t con_fd, 
                         uint8_t *packet_ptr, 
                         uint16_t packet_length);

int32_t http_process_sign_in_req(uint32_t con_fd,
                                 uint8_t **response_ptr, 
                                 uint16_t *response_len_ptr);

int32_t http_process_register_req(uint32_t con_fd,
                                  uint8_t **response_ptr, 
                                  uint16_t *response_len_ptr);

int32_t http_process_login_with_mobile_no_req(uint32_t con_fd,
                                              uint8_t **response_ptr, 
                                              uint16_t *response_len_ptr);

int32_t http_process_ui_req(uint32_t con_fd,
                            uint8_t **response_ptr, 
                            uint16_t *response_len_ptr);

int32_t http_process_login_req(uint32_t con_fd,
                               uint8_t **response_ptr, 
                               uint16_t *response_len_ptr);

int32_t http_process_image_req(uint32_t con_fd,
                               uint8_t **response_ptr, 
                               uint16_t *response_len_ptr);
 
int32_t http_process_auth_response_req(uint32_t con_fd,
                                       uint8_t **response_ptr,
                                       uint16_t *response_len_ptr);

int32_t http_process_redirect_req(uint32_t conn_id,
                                  uint8_t **response_ptr,
                                  uint16_t *response_len_ptr,
                                  uint8_t *location_uri);
#endif /* __HTTP_H__ */
