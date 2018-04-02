#ifndef __SSLC_C__
#define __SSLC_C__

#include <type.h>
#include <uidai/common.h>
#include "sslc.h"
#include "oauth20.h"

sslc_ctx_t sslc_ctx_g;

int32_t sslc_close(uint32_t oauth2_fd) {

  sslc_session_t *session = NULL;
  session = sslc_get_session(oauth2_fd);
  
  if(session) {
    close(session->tcp_fd);
    SSL_free(session->ssl_fd);
    return(0);
  }

  return(1);
}/*sslc_close*/

int32_t sslc_init(void) {
  const SSL_METHOD *method;
  SSL_CTX    *ctx;
  sslc_ctx_t *pSslcCtx = &sslc_ctx_g;

  method = TLS_client_method();
  ctx = SSL_CTX_new(method);          /* Create new context */

  if(!ctx) {
    fprintf(stderr, "\n%s:%d Context for SSL creation Failed\n", __FILE__, __LINE__);
    ERR_print_errors_fp(stderr);
  }

  /*Initialize the global structure*/
  memset((void *)&sslc_ctx_g, 0, sizeof(sslc_ctx_t));
  pSslcCtx->sslCtx = ctx;

  return(0);
}/*sslc_init*/

uint32_t sslc_get_session_count(void) {
  sslc_ctx_t *pSslcCtx = &sslc_ctx_g;
  uint32_t session_count = 0;
  sslc_session_t *tmp_session = pSslcCtx->session;

  while(tmp_session) {
    session_count++;
    tmp_session = tmp_session->next;
  }
  
  return(session_count);
}/*sslc_get_session_count*/

int32_t sslc_get_session_list(uint32_t *conn_arr, uint32_t *conn_count) {

  sslc_ctx_t *pSslcCtx = &sslc_ctx_g;
  uint32_t session_count = 0;
  sslc_session_t *tmp_session = pSslcCtx->session;
  uint32_t idx = 0;

  while(tmp_session) {
    conn_arr[idx++] = tmp_session->tcp_fd;      
    tmp_session = tmp_session->next;
  }

  *conn_count = idx;
  return(0);
}/*sslc_get_session_list*/

int32_t sslc_get_ipaddr(uint8_t *host_name, uint8_t *ip_str) {

  struct hostent *he;
  struct in_addr **addr_list;
  uint32_t i;

  if((he = gethostbyname(host_name))) {
    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++) {
      strcpy(ip_str ,inet_ntoa(*addr_list[i]));
      fprintf(stderr, "\n%s:%d ip address %s\n", __FILE__, __LINE__, ip_str);
      return(0);
    }
  }

  return(1);
}/*sslc_get_ipaddr*/

int32_t sslc_connect(uint8_t *host_name, 
                     uint32_t port, 
                     uint32_t *tcp_fd, 
                     uint8_t *req_ptr) {
  sslc_ctx_t *pSslcCtx = &sslc_ctx_g;
  int32_t fd;
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  uint8_t ip_str[32];
  uint32_t ip_addr[4];
  uint32_t ip;
  int32_t ret = -1;
  uint8_t *ext_conn_ptr = NULL;
  uint8_t *conn_ptr = NULL;
  uint8_t *ip_ptr = NULL;
  sslc_session_t *tmp_session = pSslcCtx->session;
  sslc_session_t *new_session = NULL;

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(fd < 0) {
    fprintf(stderr, "\n%s:%d Creation of socket failed\n", __FILE__, __LINE__);
    return(1);
  }

  memset((void *)ip_str, 0, sizeof(ip_str));
  sslc_get_ipaddr(host_name, ip_str);
  sscanf(ip_str, "%d.%d.%d.%d", &ip_addr[0], &ip_addr[1], &ip_addr[2], &ip_addr[3]);
  ip = ip_addr[0] << 24 | ip_addr[1] << 16 | ip_addr[2] << 8|ip_addr[3];

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(ip);
  addr.sin_port = htons(port);
 
  if(connect(fd, (struct sockaddr *)&addr, addr_len) < 0) {
    fprintf(stderr, "\n%s:%d Connect to failed\n", __FILE__, __LINE__);
    perror("connect Failed");
    return(2);
  }

  new_session = (sslc_session_t *)malloc(sizeof(sslc_session_t));
  if(!new_session) {
    fprintf(stderr, "\n%s:%d memory allocation failed\n", __FILE__, __LINE__);
    return(3);
  }

  memset((void *)new_session, 0, sizeof(sslc_session_t));
  new_session->tcp_fd = fd;
  new_session->ssl_fd = SSL_new(pSslcCtx->sslCtx);
  new_session->rsp_st = ACCESS_TOKEN_ST;
  new_session->next = NULL;
  
  conn_ptr = oauth20_get_param(req_ptr, "conn_id");
  ext_conn_ptr = oauth20_get_param(req_ptr, "ext_conn_id");

  if(conn_ptr && ext_conn_ptr) {
    new_session->redir_conn_id = atoi(conn_ptr); 
    new_session->uam_conn_id = atoi(ext_conn_ptr);
    free(conn_ptr);
    free(ext_conn_ptr);
  }

  ip_ptr = oauth20_get_param(req_ptr, "ip");

  if(ip_ptr) {
    memset((void *)new_session->ip, 0, sizeof(new_session->ip));
    strncpy(new_session->ip, ip_ptr, sizeof(new_session->ip));
    free(ip_ptr);
  }

  if(!new_session->ssl_fd) {
    fprintf(stderr, "\n%s:%d ssl instance creation failed\n", __FILE__, __LINE__);
    close(fd);
    free(new_session);
    return(4);
  }

  /*attach tcp_fd with ssl fd*/
  SSL_set_fd(new_session->ssl_fd, new_session->tcp_fd);

  if((ret = SSL_connect(new_session->ssl_fd)) < 0) {
    fprintf(stderr, "\n%s:%d SSL Connect failed %d\n", 
                    __FILE__, 
                    __LINE__, 
                    SSL_get_error(new_session->ssl_fd, ret));
    SSL_free(new_session->ssl_fd);
    close(fd);
    free(new_session);
    return(5);
  }
  
  *tcp_fd = fd;
  if(!tmp_session) {
    /*empty session*/
    pSslcCtx->session = new_session;
    return(0);
  }

  /*get to the end of session list*/
  while(tmp_session->next) {
    tmp_session = tmp_session->next;
  }
  /*establish the link in the list*/
  tmp_session->next = new_session;
  
  return(0);
}/*sslc_connect*/

sslc_session_t *sslc_get_session(uint32_t tcp_fd) {
  sslc_ctx_t *pSslcCtx = &sslc_ctx_g;
  sslc_session_t *tmp_session = pSslcCtx->session;

  while(tmp_session) {

    if(tcp_fd == tmp_session->tcp_fd) {
      return(tmp_session);
    } 
    tmp_session = tmp_session->next;
  }

  return(NULL);  
}/*sslc_get_session*/

int32_t sslc_del_session(uint32_t tcp_fd) {
  sslc_ctx_t *pSslcCtx = &sslc_ctx_g;
  sslc_session_t *curr_session = pSslcCtx->session;
  sslc_session_t *prev_session;

  /*Only one session*/
  if(curr_session && !curr_session->next) {
    if(tcp_fd == curr_session->tcp_fd) {
      free(curr_session);
      pSslcCtx->session = NULL;
      return(0);
    }
    /*incorrect tcp_fd*/
    return(1);
  }

  /*More than one session*/
  while(curr_session && curr_session->next) {
    if(curr_session->tcp_fd == tcp_fd) {
      prev_session->next = curr_session->next;
      free(curr_session);
      return(0);
    }
    prev_session = curr_session;
    curr_session = curr_session->next;
  }

  /*tcp_fd is not found in the session*/
  return(2);
}/*sslc_del_session*/

int32_t sslc_read(uint32_t tcp_fd, uint8_t *out_ptr, uint32_t *out_len) {

  sslc_session_t *session = NULL;
  int32_t ret = -1;

  session = sslc_get_session(tcp_fd);
  if(!session) {
    fprintf(stderr, "\n%s:%d session does not exists\n", __FILE__, __LINE__);
    return(1);
  }

  ret = SSL_read(session->ssl_fd, out_ptr, *out_len);

  if(ret >= 0) {
    *out_len = ret;
  }

  return(0);
}/*sslc_read*/ 

int32_t sslc_write(uint32_t tcp_fd, uint8_t *in_ptr, uint32_t in_len) {
  sslc_session_t *session = NULL;
  uint32_t offset = 0;
  int32_t ret = -1;

  session = sslc_get_session(tcp_fd);
  if(!session) {
    fprintf(stderr, "\n%s:%d session does not exists\n", __FILE__, __LINE__);
    return(1);
  }

  do {
    ret = SSL_write(session->ssl_fd, (in_ptr + offset), (in_len - offset));

    if(ret > 0) {
      offset += ret;
    } else {
      fprintf(stderr, "\n%s:%d SSL_write failed\n", __FILE__, __LINE__);
    }

  }while(offset < in_len);

  return(0);
}/*sslc_write*/

int32_t sslc_peek(uint32_t tcp_fd, uint8_t *in_ptr, uint32_t in_len) {

  sslc_session_t *session = NULL;
  int32_t ret = -1;

  session = sslc_get_session(tcp_fd);
  if(!session) {
    fprintf(stderr, "\n%s:%d session does not exists\n", __FILE__, __LINE__);
    return(1);
  }

  return(SSL_peek(session->ssl_fd, in_ptr, in_len));

}/*sslc_peek*/

/**
 * @brief This function processes the response buffer
 *  without consuming the buffer and ensures that
 *  the complete response is received. It makes sure
 *  that incase of chunked response, end chunked is
 *  received.
 *
 * @param conn_fd is the connection at which response is received.
 * @param packet_buffer holds the response buffer
 * @param packet_len is the received response length
 *
 * @return it returns 0 if entire response is received else returns 1
 */
int32_t sslc_pre_process_rsp(uint8_t *req_ptr, 
                             uint32_t req_len) {
  uint8_t *tmp_ptr = NULL;
  uint8_t *line_ptr = NULL;
  char *save_ptr = NULL;
  uint8_t is_response_chunked = 0;
  uint16_t payload_len = 0;
  uint8_t is_end_chunked = 0;

  if(!req_len) {
    return(req_len);
  }

  tmp_ptr = (uint8_t *)malloc(req_len);
  assert(tmp_ptr != NULL);
  memset((void *)tmp_ptr, 0, req_len);
  memcpy((void *)tmp_ptr, req_ptr, req_len);

  /*Parse the Response*/
  line_ptr = strtok_r(tmp_ptr, "\r\n", &save_ptr);
  while(line_ptr != NULL) {

    if(is_response_chunked) {
      if(!strncmp(line_ptr, "0", 1)) {
        is_end_chunked = 1;
      } 
    } else if(!strncmp(line_ptr, "Transfer-Encoding: chunked", 26)) {
      /*Response received in chunked*/
      is_response_chunked = 1;

    } else if(!strncmp(line_ptr, "Content-Length:", 15)) {
      /*Response is not chunked*/
      free(tmp_ptr);
      return(0);
    }
    line_ptr = strtok_r(NULL, "\r\n", &save_ptr);
  }

  if(is_response_chunked && is_end_chunked) {
    /*Complete chuncked received*/
    free(tmp_ptr);
    return(0);
  }

  free(tmp_ptr);
  /*wait for end of chunked*/
  return(1);
}/*sslc_pre_process_rsp*/

uint32_t sslc_get_rsp_st(uint32_t oauth2_fd) {
 
  sslc_session_t *session = NULL;
  session = sslc_get_session(oauth2_fd);

  if(!session) {
    fprintf(stderr, "\n%s:%d getting session failed\n", __FILE__, __LINE__);
    return(0);
  }

  return(session->rsp_st);
}/*sslc_get_rsp_st*/

int32_t sslc_set_rsp_st(uint32_t tcp_fd, uint32_t st) {
  
  sslc_session_t *session = NULL;
  session = sslc_get_session(tcp_fd);

  if(!session) {
    fprintf(stderr, "\n%s:%d getting session failed\n", __FILE__, __LINE__);
    return(0);
  }

  session->rsp_st = st;
  return(0); 
}/*sslc_set_rsp_st*/

#endif /* __SSLC_C__ */
