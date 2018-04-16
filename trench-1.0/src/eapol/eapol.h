#ifndef __EAPOL_H__
#define __EAPOL_H___

/*ieee802.1x Payload length*/
#define EAPOL_LEN       10240

typedef enum {
  /*https://www.ietf.org/rfc/rfc3748.txt*/
  EAP_TYPE_IDENTITY = 1,
  EAP_TYPE_NOTIFICATION,
  EAP_TYPE_NAK,
  EAP_TYPE_MD5_CHALLENGE,
  /*One Time Pin*/
  EAP_TYPE_OTP,
  /*Generic Token Card*/
  EAP_TYPE_GTC,
  EAP_TYPE_EXPANDED = 254,
  EAP_TYPE_EXPERIMENTAL = 255
}eapol_type_t;

typedef enum {
  EAP_CODE_REQUEST = 1,
  EAP_CODE_RESPONSE,
  EAP_CODE_SUCCESS,
  EAP_CODE_FAILURE
}eapol_code_t;

typedef enum {
  /*EAPOL carrying EAP Packet*/
  EAPOL_TYPE_EAP = 0,
  EAPOL_TYPE_START,
  EAPOL_TYPE_LOGOFF,
  EAPOL_TYPE_KEY, 
  /*SNMP Alert*/
  EAPOL_TYPE_ENCAPSULATED
}eapol_eapol_t;


struct ieee802dot1x {
  uint8_t  ver;
  uint8_t  type;
  uint16_t len;
} __attribute__((packed));

struct eapol {
  uint8_t  code;
  uint8_t  id;
  uint16_t length;
  uint8_t  type;
  uint8_t  payload[EAPOL_LEN];
} __attribute__((packed));

struct session_t {
  /*supplicant MAC*/
  uint8_t calling_mac[ETH_ALEN];
  /*Authenticator MAC*/
  uint8_t self_mac[ETH_ALEN];
  /*Supplicant user id*/
  uint8_t user_id[255];
  /*RadiusS connection id*/
  int32_t conn_id;
  /*supplicant connection id*/
  int32_t fd;
  /*will state be encoded in access-request*/
  uint32_t state_len;
  /*cookie received in Access-Challenge*/
  uint8_t state[64];
  struct session_t *next;
};

typedef struct {
  uint8_t eth_name[16];
  uint32_t intf_idx;
  uint32_t radiusC_ip;
  uint32_t radiusC_port;
  struct session_t *session_ptr;
}eapol_ctx_t;

int32_t eapol_main(int32_t fd, uint8_t *in, uint32_t inlen);

int32_t eapol_init(uint8_t *eth_name,
                   uint32_t radiusC_ip,
                   uint32_t radiusC_port);

int32_t eapol_sendto(int32_t fd, 
                     uint8_t *dst_mac, 
                     uint8_t *packet, 
                     uint32_t packet_len);

uint8_t *eapol_build_identity_req(int32_t fd, 
                                  uint8_t *in_ptr, 
                                  uint32_t *rsp_len);

uint8_t *eapol_build_failure_req(int32_t fd, 
                                 uint8_t *in_ptr, 
                                 uint32_t *rsp_len);

uint8_t *eapol_build_success_req(int32_t fd, 
                                 uint8_t *in_ptr, 
                                 uint32_t *rsp_len);

int32_t eapol_build_access_req(int32_t fd, 
                               uint8_t *in_ptr, 
                               uint8_t *req_ptr, 
                               uint32_t *req_len);

int32_t eapol_insert_session(int32_t fd, struct session_t **session_ptr, 
                             uint8_t *in_ptr);

struct session_t *eapol_get_session(uint8_t *in_ptr);

int32_t eapol_process_rsp(int32_t fd, 
                          uint8_t *in_ptr, 
                          uint32_t in_len);

int32_t eapol_del_session(struct session_t **session_ptr, 
                          int32_t conn_id);

uint32_t eapol_get_session_count(void);

uint8_t *eapol_build_md5_challenge_req(int32_t fd, 
                                       uint8_t *eap_ptr, 
                                       uint32_t *rsp_len);

int32_t eapol_get_mac(int32_t conn_id, uint8_t *mac);

int32_t eapol_get_session_list(int32_t *conn_list);

void *eapol_recv_main(void *tid);

int32_t eapol_radius_recv(int32_t fd, 
                          uint8_t *out, 
                          uint32_t max_size, 
                          uint32_t *olen); 
#endif /* __EAPOL_H__ */
