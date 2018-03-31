#ifndef __UAMS_RADIUSC_INTERFACE_H__
#define __UAMS_RADIUSC_INTERFACE_H__

/*Abstract Unix Socket File Name*/
#define UN_SOCK_NAME ".uamS_radiusC"
#define UN_SOCK_NAME_LEN strlen(UN_SOCK_NAME)

typedef enum {
  ACCESS_REQUEST = 1,
  ACCESS_ACCEPT,
  ACCESS_REJECT,
  ACCOUNTING_REQUEST,
  ACCOUNTING_RESPONSE,
  ACCESS_CHALLENGE = 11,
  STATUS_SERVER,
  STATUS_CLIENT,
  
}uamS_radiusC_message_type_t;

typedef struct {
  uint8_t message_type;
  uint32_t subscriber_conn_id;

  uint8_t user_name_len;
  uint8_t user_name[255];

  uint8_t calling_station_id_len;
  uint8_t calling_station_id[32];
  
}radiusC_uamS_access_accept_t;

typedef struct {
  uint8_t message_type;
  uint32_t subscriber_conn_id;
  
}radiusC_uamS_accounting_response_t;

typedef struct {
  uint8_t message_type;
  uint32_t subscriber_conn_id;
  
}radiusC_uamS_access_challenge_t;

typedef struct {
  uint8_t message_type;
  /*Socket Fd at which web-browser is connected with UAMS*/
  uint32_t subscriber_conn_id;
  uint16_t user_id_len;
  uint8_t  user_id[255];
  uint16_t password_len;
  uint8_t password[255];
 
}uamS_radiusC_access_request_t;

typedef struct {
  uint8_t message_type;
  /*Socket Fd at which web-browser is connected with UAMS*/
  uint32_t subscriber_conn_id;
 
}uamS_radiusC_access_reject_t;


typedef struct {
  uint8_t message_type;
  
}uamS_radiusC_accounting_request_t;

typedef union {

  uamS_radiusC_access_request_t access_req;;
  uamS_radiusC_accounting_request_t accounting_req;;
  radiusC_uamS_access_accept_t access_accept;
  uamS_radiusC_access_reject_t access_reject;
  radiusC_uamS_accounting_response_t accounting_response;
  radiusC_uamS_access_challenge_t access_challenge;
}uamS_radiusC_message_t;

#endif /* __UAMS_RADIUSC_INTERFACE_H__ */
