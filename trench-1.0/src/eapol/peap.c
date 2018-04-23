#ifndef __PEAP_C__
#define __PEAP_C__

#include <time.h>
#include <sys/stat.h>
#include <type.h>
#include <common.h>
#include <transport.h>
#include <uidai/util.h>
#include "eapol.h"
#include "peap.h"

peap_ctx_t peap_ctx_g;

int32_t peap_display_cipher_suites(uint16_t *cipher_suites, uint32_t len) {
  
  uint32_t idx;
  for(idx = 0; idx < len; idx++) {
    fprintf(stderr, "%x ", ntohs(cipher_suites[idx]));
  }

  fprintf(stderr, "\n");
  return(0);

}/*peap_display_cipher_suites*/

int32_t peap_build_hello_done_req(struct peap_session_t *session, 
                                  uint8_t *req_ptr, 
                                  uint32_t *req_len) {

  uint32_t offset = 0;

  /*Populating the CERTIFICATE REQ*/ 
  req_ptr[offset++] = TLS_LEN_BIT | TLS_VER_BIT;
  /*Length to be encoded later*/
  offset += 4;
  req_ptr[offset++] = PEAP_TLS_TYPE_HANDSHAKE;
  /*TLS Version*/
  req_ptr[offset++] = session->major_ver;
  req_ptr[offset++] = session->minor_ver;
  /*Length of 2 bytes*/
  offset += 2;
  /*TLS Message type*/ 
  req_ptr[offset++] = PEAP_SERVER_HELLO_DONE;
  /*Length of 3 Bytes to be encoded later*/
  req_ptr[offset++] = 0x00;
  req_ptr[offset++] = 0x00;
  req_ptr[offset++] = 0x00;

  /*TLS Record Length*/
  *((uint32_t *)&req_ptr[1]) = htonl(offset - (1/*Flags of 1 byte*/ + 
                                               4/*length of 4 bytes*/));
  /*TLS Handhsake Record Length*/
  *((uint16_t *)&req_ptr[8]) = htons(offset - 10);

  *req_len = offset;
  return(0);
}/*peap_build_hello_done_req*/

int32_t peap_build_certificate(struct peap_session_t *session, 
                               uint8_t *req_ptr, 
                               uint32_t *req_len) {
  uint32_t f_size = 0;
  uint8_t *tmp_ptr = NULL;
  uint8_t *b64_ptr = NULL;
  uint32_t tmp_size;
  uint32_t tmp_len = 0;
  FILE *fp;
  int32_t ret = -1;
  uint8_t *f_name = "../keys/trench.crt";
  uint32_t offset = 0;
  uint8_t *line_ptr = NULL;
  char *save_ptr;

  f_size = peap_get_cert_size(f_name);
  tmp_size = f_size;

  fp = fopen(f_name, "r");
  assert(fp != NULL);

  b64_ptr = (uint8_t *)malloc(tmp_size);
  assert(b64_ptr != NULL);
  memset((void *)b64_ptr, 0, tmp_size);

  ret = fread(b64_ptr, 1, f_size, fp);
  fclose(fp);

  tmp_ptr = (uint8_t *)malloc(tmp_size);
  assert(tmp_ptr != NULL);
  memset((void *)tmp_ptr, 0, tmp_size);

  /*Remove the \n from base64 encoded buffer*/
  for(line_ptr = strtok_r(b64_ptr, "\n", &save_ptr); 
      line_ptr; 
      line_ptr = strtok_r(NULL, "\n", &save_ptr)) {
    offset += sprintf(&tmp_ptr[offset], "%s", line_ptr);
  }

  free(b64_ptr); 
  b64_ptr = (uint8_t *)malloc(tmp_size);
  assert(b64_ptr != NULL);
  memset((void *)b64_ptr, 0, tmp_size);

  sscanf(tmp_ptr, "-----BEGIN CERTIFICATE-----%[^-]-", b64_ptr);
 
  /*Decode from base64 into binary*/
  memset((void *)tmp_ptr, 0, tmp_size);
  util_base64_decode(b64_ptr, strlen(b64_ptr), tmp_ptr, &tmp_len);
  offset = 0;

  /*Populating the CERTIFICATE REQ*/ 
  req_ptr[offset++] = TLS_LEN_BIT | TLS_VER_BIT;
  /*Length to be encoded later*/
  offset += 4;
  req_ptr[offset++] = PEAP_TLS_TYPE_HANDSHAKE;
  /*TLS Version*/
  req_ptr[offset++] = session->major_ver;
  req_ptr[offset++] = session->minor_ver;
  /*Length of 2 bytes*/
  offset += 2;
  /*TLS Message type*/ 
  req_ptr[offset++] = PEAP_CERTIFICATE;
  /*Length of 3 Bytes to be encoded later*/
  req_ptr[offset++] = (tmp_len >> 16) & 0xFF;
  req_ptr[offset++] = (tmp_len >>  8) & 0xFF;
  req_ptr[offset++] = (tmp_len >>  0) & 0xFF;

  /*Chain Length of 3 bytes -3*/
  req_ptr[offset++] = ((tmp_len - 3) >> 16) & 0xFF;
  req_ptr[offset++] = ((tmp_len - 3) >>  8) & 0xFF;
  req_ptr[offset++] = ((tmp_len - 3) >>  0) & 0xFF;

  /*Certificate Length of 3 bytes -3*/
  req_ptr[offset++] = ((tmp_len - 6) >> 16) & 0xFF;
  req_ptr[offset++] = ((tmp_len - 6) >>  8) & 0xFF;
  req_ptr[offset++] = ((tmp_len - 6) >>  0) & 0xFF;
  
  memcpy((void *)&req_ptr[offset], tmp_ptr, tmp_len);
  offset += tmp_len; 
  
  /*TLS Record Length*/
  *((uint32_t *)&req_ptr[1]) = htonl(offset - 5);
  /*TLS Handhsake Record Length*/
  *((uint16_t *)&req_ptr[8]) = htons(offset - 10);
  
  *req_len = offset;
  free(tmp_ptr);
  free(b64_ptr); 
  return(0);
}/*peap_build_certificate*/

uint32_t peap_get_cert_size(uint8_t *certificate_name) {

  struct stat st;
  memset((void *)&st, 0, sizeof(st));
  if(stat(certificate_name, &st)) {
    fprintf(stderr, "\n%s:%d stat system call failed\n", __FILE__, __LINE__);
    return(1);
  }

  return(st.st_size);
}/*peap_get_cert_size*/

int32_t peap_build_peap_header(struct peap_session_t *session,
                               uint8_t *req_ptr, 
                               uint32_t *req_len) {

  struct eth *eth_ptr = NULL;
  struct ieee802dot1x *dot1x_ptr = NULL;
  struct eapol *eapol_ptr = NULL;

  eth_ptr = (struct eth *)req_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&req_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&req_ptr[sizeof(struct eth) + 
                                       sizeof(struct ieee802dot1x)];

  /*Populating Ethernet Header*/
  memcpy((void *)eth_ptr->h_source, session->self_mac, ETH_ALEN);
  memcpy((void *)eth_ptr->h_dest, session->calling_mac, ETH_ALEN);
  eth_ptr->h_proto = htons(0x888E);

  /*Populating 802.1x header*/
  dot1x_ptr->ver = 1;
  /*802.1x containing EAP Payload*/
  dot1x_ptr->type = EAPOL_TYPE_EAP;
  /*802.1x payload length*/ 
  dot1x_ptr->len = htons(0);

  /*Populating EAP Request*/
  eapol_ptr->code = EAP_CODE_REQUEST;
  session->id = (++session->id) % 255;
  eapol_ptr->id = session->id;
  /*Length to be update later*/
  eapol_ptr->length = htons(0);
  eapol_ptr->type = EAP_TYPE_PEAP;
 
  *req_len = sizeof(struct eth) + sizeof(struct ieee802dot1x) + 5;

  return(0); 
}/*peap_build_peap_header*/

struct peap_session_t *peap_get_session(uint8_t *mac_ptr) {
  peap_ctx_t *pPeapCtx = &peap_ctx_g;
  struct peap_session_t *tmp_session = pPeapCtx->session_ptr;

  while(tmp_session && tmp_session->next) {

    if(!memcmp((void *)tmp_session->calling_mac, 
               mac_ptr, 
               ETH_ALEN)) {
      return(tmp_session);
    }
    tmp_session = tmp_session->next;
  }

  if(!tmp_session->next) {
    if(!memcmp((void *)tmp_session->calling_mac, 
               mac_ptr, 
               ETH_ALEN)) {
      return(tmp_session);
    }
  }

  return(NULL);
}/*peap_get_session*/

int32_t peap_add_session(int32_t fd,
                         struct peap_session_t **session_ptr, 
                         uint8_t *in_ptr) {

  struct peap_session_t *tmp_session = *session_ptr;
  struct peap_session_t *new_session = NULL;

  new_session = (struct peap_session_t *)malloc(sizeof(struct peap_session_t));
  assert(new_session != NULL);

  memset((void *)new_session, 0, sizeof(struct peap_session_t));
  memcpy((void *)new_session->calling_mac, &in_ptr[ETH_ALEN], ETH_ALEN);
  memcpy((void *)new_session->self_mac, in_ptr, ETH_ALEN);
  /*Initialize Unique Id to 1*/
  new_session->id = 1;
  new_session->next = NULL;

  if(!tmp_session) {
    /*No session exists as of now*/
    (*session_ptr) = new_session;
    return(0);
  }

  /*Is calling mac exists?*/
  while(tmp_session && tmp_session->next) {

    if(!memcmp((void *)tmp_session->calling_mac, 
               &in_ptr[ETH_ALEN], 
               ETH_ALEN)) {
      /*calling mac found in the existing session*/
      free(new_session);
      return(0); 
    } 

    tmp_session = tmp_session->next;
  }

  /*Hit at end*/
  tmp_session->next = new_session;

  return(0);
}/*peap_add_session*/

int32_t peap_parse_client_hello(struct peap_session_t *session, 
                                uint8_t *tls_data_ptr,
                                uint32_t tls_data_len) {
  uint32_t offset = 4;
  uint16_t ci_len = 0;
  uint32_t idx;
  uint16_t type;

  session->major_ver = tls_data_ptr[offset++];
  session->minor_ver = tls_data_ptr[offset++];
  memcpy((void *)&session->peer, (const void *)&tls_data_ptr[offset], 32); 
  offset += 32;
  /*session id length followed by value*/
  offset += tls_data_ptr[offset++];
  /*cipher Suites length*/
  ci_len = *((uint16_t *)&tls_data_ptr[offset]);
  ci_len = ntohs(ci_len);
  /*2 bytes of length*/
  offset += 2;
  /*Cipher Suites len*/
  session->cipher_suites_len = ci_len/2;
  /*Cipher Suites value*/
  memcpy((void *)session->cipher_suites, (const void *)&tls_data_ptr[offset], ci_len);
  offset += ci_len;

  /*compression Method*/   
  offset += tls_data_ptr[offset++];

  /*Extension Length*/
  ci_len = *((uint16_t *)&tls_data_ptr[offset]);
  ci_len = ntohs(ci_len);
  offset += 2;

  /*Extension Values*/
  for(idx = offset; idx < tls_data_len; idx++) {

    type = *((uint16_t *)&tls_data_ptr[idx]);
    idx += 2;
    type = ntohs(type);

    switch(type) {
      case 0x000d:
        /*Signature Algorithm*/ 
        ci_len = *((uint16_t *)&tls_data_ptr[idx]);
        ci_len = ntohs(ci_len);
        idx += 2;
        session->sig_hash_len = ci_len/2;
        memcpy((void *)session->sign_algo, (const void *)&tls_data_ptr[idx], ci_len);
        idx += ci_len;
        break;

      default:
        ci_len = *((uint16_t *)&tls_data_ptr[idx]);
        ci_len = ntohs(ci_len);
        idx += ci_len;
        break; 
    }  
  }

  return(0);
}/*peap_parse_client_hello*/

uint32_t peap_get_prf(uint8_t *prf) {
  FILE *fp = NULL;
  uint32_t tv = 0;
  int32_t ret = -1;

  fp = fopen("/dev/urandom", "rb");
  assert(fp != NULL);
  ret = fread(&prf[4], 1, 28, fp);
  fclose(fp);
  tv = (uint32_t)time(NULL);
  *((uint32_t *)prf) = htonl(tv);

  return(0);
}/*peap_get_prf*/

/*The PEAP Packet Format*/
/*https://tools.ietf.org/id/draft-josefsson-pppext-eap-tls-eap-06.txt 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
|     Code      |   Identifier  |            Length             | 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
|     Type      |   Flags | Ver |  Data... 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
int32_t peap_build_server_hello(struct peap_session_t *session,
                                uint8_t *req_ptr,
                                uint32_t *req_len) {
  uint32_t offset = 0;
  uint8_t prf[32];
  uint32_t tmp_len = 0;

  /*Encoding Length Bit flags*/
  req_ptr[offset++] = TLS_LEN_BIT | TLS_VER_BIT; 

  /*4 Bytes length of PEAP-TL, Updated at Bottom*/
  offset += 4;

  /*TLS RECORD*/  
  req_ptr[offset++] = PEAP_TLS_TYPE_HANDSHAKE;
  /*TLS Version field*/
  req_ptr[offset++] = session->major_ver;
  req_ptr[offset++] = session->minor_ver;

  /*Length of 2 bytes of Handshake Protocol*/
  offset += 2;
  /*SERVER HELLO*/
  req_ptr[offset++] = PEAP_SERVER_HELLO;
  /*3 Bytes of Length*/
  offset += 3;
  /*Version*/
  req_ptr[offset++] = session->major_ver;
  req_ptr[offset++] = session->minor_ver;

  /*Random Number of 32 Bytes 4(ts) + 28 (Random)*/ 
  memset((void *)prf, 0, sizeof(prf));
  peap_get_prf(prf);
  memcpy((void *)&req_ptr[offset], prf, sizeof(prf));
  /*copying into session*/
  memcpy((void *)&session->self, prf, sizeof(prf));
  offset += sizeof(prf);

  /*Session Id len*/
  req_ptr[offset++] = 0x00;

  /*TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,0x3D };*/ 
  //*((uint16_t *)&req_ptr[offset]) = htons(0x003D);
  *((uint16_t *)&req_ptr[offset]) = htons(0x0035);
  offset += 2;
  /*Compression Method Value (null compression Method)*/
  req_ptr[offset++] = 0x00;
  /*Extension Length*/
  *((uint16_t *)&req_ptr[offset]) = htons(0x0008);
  offset += 2;
  /*Signature Algorithm*/
  *((uint16_t *)&req_ptr[offset]) = htons(0x000d);
  offset += 2;
  /*Length*/ 
  *((uint16_t *)&req_ptr[offset]) = htons(0x0004);
  offset += 2;
  /*Signature Hash Algorithm Length*/
  *((uint16_t *)&req_ptr[offset]) = htons(0x0002);
  offset += 2;
  /*SHA256 (4)*/
  //req_ptr[offset++] = 0x04;
  /*SHA1*/
  req_ptr[offset++] = 0x02;
  /*RSA(1)*/
  req_ptr[offset++] = 0x01;
  
  /*peap-tls message len*/
  *((uint32_t *)&req_ptr[1]) = htonl(offset - 5);
  /*TLS-Record Length - subtract preceiding bytes to length field*/
  *((uint16_t *)&req_ptr[8]) = htons((offset - (10)));
  /*Handshake Record Length - subtract the preceding bytes to length*/ 
  //tmp_len = offset - (3 + 7 + 1);
  tmp_len = offset - (14);
  req_ptr[11] = (tmp_len >> 16 & 0xFF);
  req_ptr[12] = (tmp_len >>  8 & 0xFF);
  req_ptr[13] = (tmp_len >>  0 & 0xFF);

  *req_len = offset; 
  return(0); 
}/*peap_build_server_hello*/


int32_t peap_process_tls_record_handshake(int32_t fd,
                                          uint8_t *in_ptr, 
                                          uint8_t *tls_data_ptr, 
                                          uint32_t tls_len) {
  uint32_t offset = 0;
  peap_ctx_t *pPeapCtx = &peap_ctx_g;
  struct peap_session_t *session = NULL;

  switch(*tls_data_ptr) {
    case PEAP_HELLO_REQ:
      break;

    case PEAP_CLIENT_HELLO: {
      uint8_t *rsp_ptr = NULL;
      uint32_t rsp_len = 0;
      uint32_t tmp_len = 0;
      uint32_t rsp_size = 512;

      fprintf(stderr, "\n%s:%d Client Hello Received\n", __FILE__, __LINE__);
      /*Add session for a client*/
      peap_add_session(fd, &pPeapCtx->session_ptr, in_ptr);
      /*Get the session context based on calling mac address*/
      session = peap_get_session(&in_ptr[ETH_ALEN]);
      assert(session != NULL);
      peap_parse_client_hello(session, tls_data_ptr, tls_len);

      rsp_ptr = (uint8_t *)malloc(sizeof(uint8_t) * rsp_size);
      assert(rsp_ptr != NULL);
      memset((void *)rsp_ptr, 0, rsp_size);
      peap_display_cipher_suites(session->cipher_suites, session->cipher_suites_len);
      peap_build_peap_header(session, rsp_ptr, &rsp_len);
      peap_build_server_hello(session, &rsp_ptr[rsp_len], &tmp_len);
      /*Length to be updated in the PEAP Header*/
      rsp_len += tmp_len;
      *((uint16_t *)&rsp_ptr[16]) = htons(tmp_len + 5);
      *((uint16_t *)&rsp_ptr[20]) = htons(tmp_len + 5);

      eapol_sendto(fd, &in_ptr[ETH_ALEN], rsp_ptr, rsp_len);
      free(rsp_ptr);
      *tls_data_ptr = PEAP_CERTIFICATE;
      peap_process_tls_record_handshake(fd, in_ptr, tls_data_ptr, tls_len); 
      break;
    }

    case PEAP_CERTIFICATE: {
      /*Prepare Server's Certificate Request*/
      uint8_t *req_ptr = NULL;
      uint32_t req_len = 0;
      uint32_t tmp_len = 0;
      uint32_t req_size = 256;
      tmp_len = peap_get_cert_size("../keys/trench.crt");
      req_ptr = (uint8_t *)malloc(tmp_len + req_size);
      assert(req_ptr != NULL);
      memset((void *)req_ptr, 0, (tmp_len + req_size));

      /*Get the session context based on calling mac address*/
      session = peap_get_session(&in_ptr[ETH_ALEN]);
      assert(session != NULL);

      peap_build_peap_header(session, req_ptr, &req_len);
      tmp_len = 0;
      peap_build_certificate(session, &req_ptr[req_len], &tmp_len);
      /*Length to be updated in the PEAP Header*/
      req_len += tmp_len;
      *((uint16_t *)&req_ptr[16]) = htons(tmp_len + 5);
      *((uint16_t *)&req_ptr[20]) = htons(tmp_len + 5);

      eapol_sendto(fd, &in_ptr[ETH_ALEN], req_ptr, req_len);
      free(req_ptr);

      *tls_data_ptr = PEAP_SERVER_HELLO_DONE;
      peap_process_tls_record_handshake(fd, in_ptr, tls_data_ptr, tls_len); 
      break;
    }

    case PEAP_SERVER_KEY_EXCHANGE:

      break;
    case PEAP_CERTIFICATE_REQ:
      break;

    case PEAP_SERVER_HELLO_DONE: {

      uint8_t *req_ptr = NULL;
      uint32_t req_len = 0;
      uint32_t req_size = 256;
      uint32_t tmp_len = 0;

      req_ptr = (uint8_t *)malloc(req_size);
      assert(req_ptr != NULL);
      memset((void *)req_ptr, 0, (req_size));

      /*Get the session context based on calling mac address*/
      session = peap_get_session(&in_ptr[ETH_ALEN]);
      assert(session != NULL);

      peap_build_peap_header(session, req_ptr, &req_len);
      peap_build_hello_done_req(session, &req_ptr[req_len], &tmp_len);
      /*Length to be updated in the PEAP Header*/
      req_len += tmp_len;
      fprintf(stderr, "\n%s:%d offset %d\n", __FILE__, __LINE__, tmp_len);
      *((uint16_t *)&req_ptr[16]) = htons(tmp_len + 5);
      *((uint16_t *)&req_ptr[20]) = htons(tmp_len + 5);

      eapol_sendto(fd, &in_ptr[ETH_ALEN], req_ptr, req_len);
      free(req_ptr);
      break;
    }
    case PEAP_CERTIFICATE_VERIFY:
      break;
    case PEAP_CLIENT_KEY_EXCHANGE:
      break;
    case PEAP_FINISHED:
      break;
    default:
      break;
  }

  return(0);
}/*peap_process_tls_record_handshake*/

int32_t peap_process_peap(int32_t fd, 
                          uint8_t *in_ptr, 
                          uint32_t in_len) {

  struct eth *eth_ptr = NULL;
  struct ieee802dot1x *dot1x_ptr = NULL;
  struct eapol *eapol_ptr = NULL;
  uint32_t offset = 0;
  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_len = 0;

  offset = sizeof(struct eth) +
           sizeof(struct ieee802dot1x);

  eth_ptr = (struct eth *)in_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&in_ptr[sizeof(struct eth)];

  eapol_ptr = (struct eapol *)&in_ptr[offset];

  switch(eapol_ptr->type) {
    case EAP_TYPE_PEAP:
      rsp_ptr = eapol_build_identity_req(fd, in_ptr, &rsp_len);

      if(rsp_len) {
        eapol_sendto(fd, &in_ptr[ETH_ALEN], rsp_ptr, rsp_len);
        free(rsp_ptr);
      }
      break;

    default:
      fprintf(stderr, "\n%s:%d Unsupported type\n", __FILE__, __LINE__);
      break; 
  }  
  return(0);

}/*peap_process_peap*/

int32_t peap_process_peap_rsp(int32_t fd,
                              uint8_t *in_ptr,
                              uint32_t in_len) {
  struct eth *eth_ptr = NULL;
  struct ieee802dot1x *dot1x_ptr = NULL;
  struct eapol *eapol_ptr = NULL;
  struct peap_tls_hdr *tls_hdr_ptr = NULL;
  uint32_t offset = 0;
  uint8_t flags = 0;
  uint32_t tls_len = 0;

  offset = sizeof(struct eth) +
           sizeof(struct ieee802dot1x);

  eth_ptr = (struct eth *)in_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&in_ptr[sizeof(struct eth)];

  eapol_ptr = (struct eapol *)&in_ptr[offset];

  /*0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |   Identifier  |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Flags     |      TLS Message Length
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     TLS Message Length        |       TLS Data...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/

  flags =  eapol_ptr->payload[0];
  /*0 1 2 3 4 5 6 7 8
    +-+-+-+-+-+-+-+-+
    |L M S R R R R R|
    +-+-+-+-+-+-+-+-+*/ 
  if((flags >> 7) & 1) {
    /*TLS Length field is present*/
    tls_len = *((uint32_t *)&eapol_ptr->payload[1]);
    tls_len = ntohl(tls_len);
    fprintf(stderr, "\n%s:%d tls_len %x\n", __FILE__, __LINE__, tls_len);
    tls_hdr_ptr = (struct peap_tls_hdr *)&eapol_ptr->payload[5];

    if(PEAP_TLS_TYPE_HANDSHAKE == tls_hdr_ptr->type) {
      fprintf(stderr, "\n%s:%d version %x len %x\n", 
                      __FILE__, 
                      __LINE__, 
                      ntohs(tls_hdr_ptr->ver), 
                      ntohs(tls_hdr_ptr->len));

      uint32_t tls_record_len = ntohs(tls_hdr_ptr->len);
      uint8_t *tls_record_ptr = (uint8_t *)malloc(tls_record_len);
      assert(tls_record_ptr != NULL);
      memset((void *)tls_record_ptr, 0, tls_record_len);
      /*flags(1)|length(4)|Type(1)|ver(2)|length(2) = 10 offset*/
      memcpy((void *)tls_record_ptr, 
             &eapol_ptr->payload[10], 
             tls_record_len);

      peap_process_tls_record_handshake(fd, 
                                        in_ptr, 
                                        tls_record_ptr, 
                                        tls_record_len);
      free(tls_record_ptr);

    } else if(PEAP_TLS_TYPE_CHANGE_CIPHER_SPEC == tls_hdr_ptr->type) {
      
      fprintf(stderr, "\n%s:%d CIPHER SPECS\n", 
                      __FILE__, 
                      __LINE__);

    } else if(PEAP_TLS_TYPE_ALERT == tls_hdr_ptr->type) {
      fprintf(stderr, "\n%s:%d ALERT\n", 
                      __FILE__, 
                      __LINE__);
      
    } else if (PEAP_TLS_TYPE_APPLICATION_DATA == tls_hdr_ptr->type) {
      fprintf(stderr, "\n%s:%d APPLICATION\n", 
                      __FILE__, 
                      __LINE__);
    } else {

      fprintf(stderr, "\n%s:%d INVALID TYPE\n", 
                      __FILE__, 
                      __LINE__);
    }
  } else if((flags >> 6) & 1) {
    /*Process More Bits*/    
  } else {

    peap_process_peap(fd, in_ptr, in_len);
  }

  return(0);
}/*peap_process_peap_rsp*/    

uint8_t *peap_build_peap_req(uint8_t *in_ptr, 
                             uint32_t inlen, 
                             uint32_t *olen) {
  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_size = sizeof(uint8_t) * 256;
  struct eth *eth_ptr = NULL;
  struct ieee802dot1x *dot1x_ptr = NULL;
  struct eapol *eapol_ptr = NULL;
  struct eapol *eap_req_ptr = NULL;
  uint32_t offset = 0;
  uint8_t flag = 0;

  rsp_ptr = (uint8_t *)malloc(rsp_size);
  assert(rsp_ptr != NULL);
  memset((void *)rsp_ptr, 0, rsp_size);

  eth_ptr = (struct eth *)rsp_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&rsp_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&rsp_ptr[sizeof(struct eth) + 
                                       sizeof(struct ieee802dot1x)];

  /*eap received from radiusS*/
  eap_req_ptr = (struct eapol *)&in_ptr[sizeof(struct eth) +
                                        sizeof(struct ieee802dot1x)];

  /*Populating Ethernet Header*/
  memcpy((void *)eth_ptr->h_dest, &in_ptr[ETH_ALEN], ETH_ALEN);
  memcpy((void *)eth_ptr->h_source, in_ptr, ETH_ALEN);
  eth_ptr->h_proto = htons(0x888e);

  /*Populating 802.1x header*/
  dot1x_ptr->ver = 1;
  /*802.1x containing EAP Payload*/
  dot1x_ptr->type = EAPOL_TYPE_EAP;
  /*802.1x payload length*/ 
  dot1x_ptr->len = htons(6);

  /*Populating EAP Request*/
  eapol_ptr->code = EAP_CODE_REQUEST;
  /*id must be different in every request*/
  eapol_ptr->id = EAP_TYPE_PEAP;
  eapol_ptr->length = htons(6);
  eapol_ptr->type = EAP_TYPE_PEAP;
  /*EAP-TLS Request*/
  eapol_ptr->payload[offset] = flag | TLS_START_BIT;
 
  *olen = sizeof(struct eth) + 
          sizeof(struct ieee802dot1x) + 
          6;

  return(rsp_ptr); 

}/*peap_build_peap_req*/

#endif /*__EAPS_C__*/

