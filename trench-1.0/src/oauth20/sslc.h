#ifndef __SSLC_H__
#define __SSLC_H__

typedef enum {
  ACCESS_TOKEN_ST = 1,
  CALLING_GOOGLE_API_ST,

}sslc_oauth_rsp_type_t;

struct sslc_session {
  uint32_t uam_conn_id;
  uint32_t redir_conn_id;
  uint32_t tcp_fd;
  uint32_t rsp_st;
  uint8_t ip[32];
  SSL *ssl_fd;
  struct sslc_session *next;
};

typedef struct sslc_session sslc_session_t;

typedef struct {
  uint8_t google_host[64];
  uint16_t http_port;
  SSL_CTX *sslCtx;
  sslc_session_t *session;

}sslc_ctx_t;


int32_t sslc_init(void);

uint32_t sslc_get_session_count(void);

int32_t sslc_get_session_list(uint32_t *conn_arr, uint32_t *conn_count);
 
int32_t sslc_get_ipaddr(uint8_t *host_name, uint8_t *ip_str);

int32_t sslc_connect(uint8_t *host_name, uint32_t port, uint32_t *tcp_fd, uint8_t *req_ptr);

sslc_session_t *sslc_get_session(uint32_t tcp_fd);

int32_t sslc_del_session(uint32_t tcp_fd);

int32_t sslc_read(uint32_t tcp_fd, uint8_t *out_ptr, uint32_t *out_len);

int32_t sslc_write(uint32_t tcp_fd, uint8_t *in_ptr, uint32_t in_len);

int32_t sslc_peek(uint32_t tcp_fd, uint8_t *in_ptr, uint32_t in_len);

int32_t sslc_pre_process_rsp(uint8_t *req_ptr, 
                             uint32_t req_len);

uint32_t sslc_get_rsp_st(uint32_t oauth2_fd);

int32_t sslc_set_rsp_st(uint32_t oauth2_fd, uint32_t st);

int32_t sslc_close(uint32_t oauth2_fd);

#endif /* __SSLC_H__ */

