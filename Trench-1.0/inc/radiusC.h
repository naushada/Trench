#ifndef __RADIUSC_H__
#define __RADIUSC_H__

typedef struct {
  
  struct sockaddr_in peer_addr;
  uint32_t conn; 
}radiusC_session_t;

typedef struct {
  uint8_t id;
  uint16_t ext_conn_id;
  uint16_t conn_id;
}radiusC_conn_t;

typedef struct {

  /* radiusX where X shall be 
   * C (Radius Client) or S (Radius Server)
   */
  uint32_t radiusC_ip;
  uint32_t radiusC_port;
  struct sockaddr_in self_addr;
  /*Radius Server IP*/
  uint32_t radiusS_ip;
  /*From UAM to RadiusC*/
  uint32_t radiusC_TcpFd;
  /*From RadiusC to RadiusS*/
  uint32_t radiusC_UdpFd;
  uint8_t secret_code[255];
  uint16_t session_count;
  radiusC_session_t session[255];

  uint8_t subscriber_count;
  radiusC_conn_t subscriber_id[255];

}radiusC_ctx_t;

typedef struct {
  uint8_t type;
  uint8_t len;
  uint8_t value[1];
}radiusS_attr_t;

typedef struct {
  uint8_t code;
  uint8_t id;
  uint16_t len;
  uint8_t authenticator[16];
}radiusS_message_header_t;

typedef enum {
  USER_NAME = 1,
  USER_PASSWORD,
  CHAP_PASSWORD,
  NAS_IP_ADDRESS,
  /*Physical Port at which NAS is operating*/
  NAS_PORT,
  SERVICE_TYPE,
  STATE = 24,
  VENDOR_SPECIFIC = 26,
  CALLING_STATION_ID = 31,
  EAP_MESSAGE = 79,
  MESSAGE_AUTHENTICATOR = 80

}radiusS_attr_type_t;

typedef enum {
  ACCESS_REQUEST = 1,
  ACCESS_ACCEPT,
  ACCESS_REJECT,
  ACCOUNTING_REQUEST,
  ACCOUNTING_RESPONSE,
  ACCESS_CHALLENGE = 11,
  STATUS_SERVER,
  STATUS_CLIENT,
  
}message_type_t;

typedef struct {
  uint8_t message_type;
  uint32_t txn_id;

  uint8_t user_name_len;
  uint8_t user_name[255];

  uint8_t calling_station_id_len;
  uint8_t calling_station_id[32];
  
}access_accept_t;

typedef struct {
  uint8_t message_type;
  uint32_t txn_id;
  
}accounting_response_t;

typedef struct {
  uint8_t message_type;
  uint32_t txn_id;
  uint32_t state_len;
  uint8_t state[64];
  uint32_t eap_len;
  uint8_t eap[512];
  
}access_challenge_t;

typedef struct {
  uint8_t message_type;
  /*Socket Fd at which web-browser is connected with UAMS*/
  uint32_t txn_id;
  uint16_t user_id_len;
  uint8_t  user_id[255];
  uint16_t password_len;
  uint8_t password[255];
  uint32_t eap_len;
  uint8_t eap[255]; 
  uint32_t supplicant_id_len;
  uint8_t supplicant_id[32];
  uint32_t state_len;
  uint8_t state[64];
 
}access_request_t;

typedef struct {
  uint8_t message_type;
  /*Socket Fd at which web-browser is connected with UAMS*/
  uint32_t txn_id;
 
}access_reject_t;


typedef struct {
  uint8_t message_type;
  
}accounting_request_t;

typedef union {

  access_request_t access_req;
  accounting_request_t accounting_req;
  access_accept_t access_accept;
  access_reject_t access_reject;
  accounting_response_t accounting_response;
  access_challenge_t access_challenge;
}radiusC_message_t;


int32_t radiusC_send(uint32_t conn_fd, 
                     uint8_t *packet_ptr, 
                     uint16_t packet_length);

int32_t radiusC_recv(uint32_t conn_fd, 
                     uint8_t *packet_ptr, 
                     uint16_t *packet_length);

int32_t radiusC_get_dest_port(uint8_t *packet_ptr);

int32_t radiusC_sendto(uint8_t *packet_ptr, uint16_t packet_length);

int32_t radiusC_process_access_accept(access_accept_t *rsp_ptr,
                                      uint8_t *packet_ptr,
                                      uint16_t packet_length);

int32_t http_get_req_authenticator(uint8_t *authenticator_ptr);


int32_t radiusC_parse_radiusS_response(uint32_t conn_id, 
                                       uint8_t *packet_ptr, 
                                       uint16_t packet_length);

uint32_t radiusC_get_con_id(uint8_t offset);

int32_t radiusC_process_radiusS_response(uint32_t UdpFd);

int32_t radiusC_init(uint32_t radiusC_ip, 
                     uint32_t radiusC_port,
                     uint32_t radiusS_ip,
                     uint8_t *secret);

void *radiusC_main(void *arg);

int32_t radiusC_encode_password(uint8_t *password_ptr, 
                                uint16_t password_len,
                                uint8_t *authenticator_ptr,
                                uint8_t *encoded_password_ptr,
                                uint16_t *len_ptr);

int32_t radiusC_process_request(uint32_t uam_conn,
                                uint8_t *packet_ptr, 
                                uint16_t packet_length);

int32_t radiusC_process_access_challenge(access_challenge_t *rsp_ptr,
                                         uint8_t *packet_ptr,
                                         uint32_t packet_length);
int32_t radiusC_hmac_md5(uint8_t *key, 
                         uint32_t key_len, 
                         uint8_t *in, 
                         uint32_t inlen, 
                         uint8_t *out, 
                         uint32_t *olen);

#endif /* __RADIUSC_H__ */
