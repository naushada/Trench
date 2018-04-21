#ifndef __PEAP_H__
#define __PEAP_H__

#define TLS_START_BIT (1 << 5)
#define TLS_MORE_BIT  (1 << 6)
#define TLS_LEN_BIT   (1 << 7)

#define TLS_VER_10    0x0301
#define TLS_VER_11    0x0302
#define TLS_VER_12    0x0303

typedef enum {
  PEAP_HELLO_REQ = 0,
  PEAP_CLIENT_HELLO,
  PEAP_SERVER_HELLO,
  PEAP_CERTIFICATE = 11,
  PEAP_SERVER_KEY_EXCHANGE = 12,
  PEAP_CERTIFICATE_REQ = 13,
  PEAP_SERVER_HELLO_DONE = 14,
  PEAP_CERTIFICATE_VERIFY = 15,
  PEAP_CLIENT_KEY_EXCHANGE = 16,
  PEAP_FINISHED = 20,
  PEAP_MAX = 255

}peap_tls_msg_type_t;

typedef enum {
  PEAP_TLS_TYPE_CHANGE_CIPHER_SPEC = 20,
  PEAP_TLS_TYPE_ALERT = 21,
  PEAP_TLS_TYPE_HANDSHAKE = 22,
  PEAP_TLS_TYPE_APPLICATION_DATA = 23,
  PEAP_TLS_TYPE_INVALID = 255
}peap_tls_type_t;

struct peap_tls_hdr {
  uint8_t type;
  uint16_t ver;
  uint16_t len;
}__attribute__((packed));

typedef struct {
  uint32_t ts;
  uint8_t random[28];
}peap_random_t;

typedef struct {
  uint8_t msg_type;
  uint8_t len[3];
  uint16_t ver;
  peap_random_t random;
  uint8_t session_id_len;
  uint8_t session_id[64];
  uint16_t suites_len;
  /*Variable length*/
  uint8_t suites[255];
  uint8_t compression_method_len;
  uint8_t commpression_method[255];
  uint16_t extension_len;
  uint8_t extension[255];
  
}peap_client_hello_t;

typedef struct {
  uint8_t msg_type;
  uint8_t len[3];
  uint16_t ver;
  peap_random_t random;
  /*Shall be set to 0*/
  uint8_t session_id_len;
  uint16_t suites;
  /*Default shall be set to 0*/
  uint8_t compression_method; 
}peap_server_hello_t;

typedef struct {
  uint8_t hash;
  uint8_t signature;
}peap_sig_hash_algo_t;

struct peap_session_t {
  /*peap-tls client major version*/
  uint8_t major_ver;
  /*peap-tls client minor version*/
  uint8_t minor_ver;
  peap_random_t peer;
  peap_random_t self;
  uint8_t calling_mac[ETH_ALEN];
  uint8_t self_mac[ETH_ALEN];
  uint16_t sig_hash_len;
  /*Signature Hash Algorithm*/
  peap_sig_hash_algo_t sign_algo[64];
  uint16_t cipher_suites_len;
  uint16_t cipher_suites[64];
  /*Unique ID to map request to response*/
  uint8_t id;
  struct peap_session_t *next; 
};

typedef struct {
  struct peap_session_t *session_ptr;
  /*peap-tls server major version*/
  uint8_t major_ver;
  /*peap-tls server minor version*/
  uint8_t minor_ver; 
}peap_ctx_t; 



uint8_t *peap_build_peap_req(uint8_t *in_ptr, 
                             uint32_t inlen, 
                             uint32_t *olen);

int32_t peap_process_tls_record_handshake(int32_t fd, 
                                          uint8_t *in_ptr,
                                          uint8_t *tls_record_ptr, 
                                          uint32_t tls_record_len);

int32_t peap_process_peap_rsp(int32_t fd,
                              uint8_t *in_ptr,
                              uint32_t in_len);

int32_t peap_add_session(int32_t fd,
                         struct peap_session_t **session_ptr, 
                         uint8_t *in_ptr);

struct peap_session_t *peap_get_session(uint8_t *mac_ptr);

int32_t peap_parse_client_hello(struct peap_session_t *session, 
                                uint8_t *tls_data_ptr,
                                uint32_t tls_len);

int32_t peap_build_peap_header(struct peap_session_t *session,
                               uint8_t *req_ptr, 
                               uint32_t *req_len);

uint32_t peap_get_prf(uint8_t *prf);

uint32_t peap_get_cert_size(uint8_t *certificate_name);

int32_t peap_build_certificate(struct peap_session_t *session, 
                               uint8_t *req_ptr, 
                               uint32_t *tmp_len);

int32_t peap_build_hello_done_req(struct peap_session_t *session, 
                                  uint8_t *req_ptr, 
                                  uint32_t *req_len);

int32_t peap_display_cipher_suites(uint16_t *cipher_suites, uint32_t len);

#endif /*__PEAP_H__*/
