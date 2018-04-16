#ifndef __RADIUSC_C__
#define __RADIUSC_C__

#include <common.h>
#include <type.h>
#include <utility.h>
#include <radiusC.h>
#include <openssl/md5.h>

radiusC_ctx_t g_radiusC_ctx;

/*https://www.ietf.org/rfc/rfc2104.txt*/
int32_t radiusC_hmac_md5(uint8_t *key, 
                         uint32_t key_len, 
                         uint8_t *in, 
                         uint32_t inlen, 
                         uint8_t *out, 
                         uint32_t *olen) {

  MD5_CTX ctx;
  uint8_t k_ipad[65];    /* inner padding -
                          * key XORd with ipad
                          */
  uint8_t k_opad[65];    /* outer padding -
                          * key XORd with opad
                          */
  uint8_t tk[16];
  int32_t i;
  /* if key is longer than 64 bytes reset it to key=MD5(key) */
  if (key_len > 64) {

    MD5_CTX tctx;
    
    MD5_Init(&tctx);
    MD5_Update(&tctx, key, key_len);
    MD5_Final(tk, &tctx);

    key = tk;
    key_len = 16;

  } 
  /*
   * the HMAC_MD5 transform looks like:
   *
   * MD5(K XOR opad, MD5(K XOR ipad, text))
   *
   * where K is an n byte key
   * opad is the byte 0x5c repeated 64 times
   * and text is the data being protected
   */

  /* start out by storing key in pads */
  memset((void *)k_ipad, 0, sizeof(k_ipad));
  memset((void *)k_opad, 0, sizeof(k_opad));
  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);
  /* XOR key with ipad and opad values */
  for(i = 0; i < 64; i++) {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  /*
   * perform inner MD5
   */
  MD5_Init(&ctx);               /* init context for 1st
                                 * pass */
  MD5_Update(&ctx, k_ipad, 64); /* start with inner pad */
  MD5_Update(&ctx, in, inlen);  /* then text of datagram */
  MD5_Final(out, &ctx);         /* finish up 1st pass */
  /*
   * perform outer MD5
   */
  MD5_Init(&ctx);                /* init context for 2nd
                                  * pass */
  MD5_Update(&ctx, k_opad, 64);  /* start with outer pad */
  MD5_Update(&ctx, out, 16);     /* then results of 1st
                                  * hash */
  MD5_Final(out, &ctx);          /* finish up 2nd pass */

  /*128-bits*/
  *olen = 16;

  return(0);
}/*radiusC_hmac_md5*/

int32_t radiusC_send(uint32_t conn_fd, 
                     uint8_t *packet_ptr, 
                     uint16_t packet_length) {
  int32_t ret;
  uint32_t offset = 0;

  do {
    ret = send(conn_fd, 
              (const void *)&packet_ptr[offset], 
              (packet_length - offset), 
              0);

    offset += ret;

    if(!(packet_length - offset)) {
      ret = 0;
    }
  }while(ret);

  return(0);
}/*radiusC_send*/

int32_t radiusC_recv(uint32_t conn_fd, 
                     uint8_t *packet_ptr, 
                     uint16_t *packet_length) {
  int32_t ret = -1;

  ret = recv(conn_fd, packet_ptr, *packet_length, 0);

  if(ret > 0) {
    *packet_length = (uint16_t)ret;
  }

  return(0);
}/*radiusC_recv*/

int32_t radiusC_get_dest_port(uint8_t *packet_ptr) {
  int32_t port;

  switch(*packet_ptr) {
    case ACCESS_REQUEST:
    case ACCESS_ACCEPT:
    case ACCESS_CHALLENGE:
      port = 1812;
      break;
    case ACCOUNTING_REQUEST:
    case ACCOUNTING_RESPONSE:
      port = 1813;
      break;
  }

  return(port);
}/*radiusC_get_dest_port*/

int32_t radiusC_sendto(uint8_t *packet_ptr, uint16_t packet_length) {
  int32_t ret;
  struct sockaddr_in radiusS;
  socklen_t radiusS_len = sizeof(radiusS);
  uint32_t offset = 0;
  radiusC_ctx_t *pRadiusCCtx = &g_radiusC_ctx;

  radiusS.sin_family = AF_INET;
  radiusS.sin_port = htons(radiusC_get_dest_port(packet_ptr));
  radiusS.sin_addr.s_addr = htonl(pRadiusCCtx->radiusS_ip);

  fprintf(stderr, "\n%s:%d RadiusS IP %s packet_size %d port %d\n", 
                  __FILE__, 
                  __LINE__, 
                  inet_ntoa(radiusS.sin_addr), 
                  packet_length,
                  ntohs(radiusS.sin_port));

  memset((void *)radiusS.sin_zero, 0, sizeof(radiusS.sin_zero));

  do {
  
    ret = sendto(pRadiusCCtx->radiusC_UdpFd, 
                 (const void *)&packet_ptr[offset], 
                 (packet_length - offset), 
                 0, 
                 (struct sockaddr *)&radiusS, 
                 radiusS_len); 

    if(ret < 0) {
      fprintf(stderr, "\n%s:%d Send to Radius Server Failed\n", __FILE__, __LINE__);
    }

    offset += ret;

    if(!(packet_length - offset)) {
      ret = 0;
    }

  }while(ret);

  return(0);
}/*radiusC_sendto*/

int32_t radiusC_process_access_challenge(access_challenge_t *rsp_ptr,
                                         uint8_t *packet_ptr,
                                         uint32_t packet_length) {
  radiusS_attr_t *attr_ptr;
  uint32_t offset = sizeof(radiusS_message_header_t);
  uint8_t msg_authenticator[16];
  uint32_t tmp_len = 0;

  do {
    attr_ptr = (radiusS_attr_t *)&packet_ptr[offset];

    switch(attr_ptr->type) {

      case EAP_MESSAGE:
        rsp_ptr->eap_len = attr_ptr->len - 2;
        memset((void *)rsp_ptr->eap, 
               0, 
               sizeof(rsp_ptr->eap));
        memcpy((char *)rsp_ptr->eap, 
               (const char *)attr_ptr->value, 
               rsp_ptr->eap_len);
        offset += attr_ptr->len;
        break;

      case STATE:
        rsp_ptr->state_len = attr_ptr->len - 2; 
        memcpy((void *)rsp_ptr->state, attr_ptr->value, rsp_ptr->state_len);
        offset += attr_ptr->len;
        break;

      case MESSAGE_AUTHENTICATOR:
        tmp_len = attr_ptr->len - 2; 
        memcpy((void *)msg_authenticator, attr_ptr->value, tmp_len);
        offset += attr_ptr->len;
        break;

      default:
        offset += attr_ptr->len;
        break;
    }

  }while(offset < packet_length);

 return(0); 
}/*radiusC_process_access_challenge*/

int32_t radiusC_process_access_reject(access_reject_t *rsp_ptr,
                                      uint8_t *packet_ptr,
                                      uint16_t packet_length) {

  radiusC_ctx_t *pRadiusCCtx = &g_radiusC_ctx;

  rsp_ptr->message_type = *packet_ptr;
  rsp_ptr->txn_id = pRadiusCCtx->subscriber_id[packet_ptr[1]].ext_conn_id;

  return(0);
}/*radiusC_process_access_reject*/

int32_t radiusC_process_access_accept(access_accept_t *rsp_ptr,
                                      uint8_t *packet_ptr,
                                      uint16_t packet_length) {

  radiusS_message_header_t *header_ptr;
  radiusS_attr_t *attr_ptr;
  uint16_t offset = 0;
  radiusC_ctx_t *pRadiusCCtx = &g_radiusC_ctx;

  header_ptr = (radiusS_message_header_t *)packet_ptr;
  
  if(ntohs(header_ptr->len) > packet_length) {
    fprintf(stderr, "\n%s:%d Invalid length is response received\n", 
                     __FILE__, 
                     __LINE__);
    return(-1);
  }
 
  if(ntohs(header_ptr->len) < sizeof(radiusS_message_header_t)) {
    fprintf(stderr, "\n%s:%d Response length is less than 20 Bytes\n", 
                    __FILE__, 
                    __LINE__);
    return(-2);
  } 

  utility_hex_dump(packet_ptr, packet_length);

  /*Get to Attribute Offset*/
  offset = sizeof(radiusS_message_header_t);

  if(offset == packet_length) {
    /*Optional Attributes are not present*/
    rsp_ptr->txn_id =  pRadiusCCtx->subscriber_id[packet_ptr[1]].ext_conn_id;
    
    /*Not Present*/
    rsp_ptr->user_name_len = 0;
    rsp_ptr->calling_station_id_len = 0;
    return(0); 
  }

  do {
    attr_ptr = (radiusS_attr_t *)&packet_ptr[offset];

    switch(attr_ptr->type) {
      case USER_NAME:
        rsp_ptr->user_name_len = ntohs(attr_ptr->len) - 2;
        memset((void *)rsp_ptr->user_name, 
               0, 
               sizeof(rsp_ptr->user_name));
        strncpy((char *)rsp_ptr->user_name, 
                (const char *)attr_ptr->value, 
                /*-2 is because length includes type and len*/
                (ntohs(attr_ptr->len) - 2));
        offset += ntohs(attr_ptr->len);
      break;

      case CALLING_STATION_ID:
        rsp_ptr->calling_station_id_len = ntohs(attr_ptr->len) - 2;
        memset((void *)rsp_ptr->calling_station_id, 
               0, 
               sizeof(rsp_ptr->calling_station_id));
        strncpy((char *)rsp_ptr->calling_station_id, 
                (const char *)attr_ptr->value, 
                /*-2 is because length includes type and len*/
                (ntohs(attr_ptr->len) - 2));
        offset += ntohs(attr_ptr->len);
      break;

      case VENDOR_SPECIFIC:
        rsp_ptr->txn_id = 0;
        rsp_ptr->txn_id = (*(uint32_t *)attr_ptr->value);
        offset += ntohs(attr_ptr->len);
      break;

      default:
        offset += ntohs(attr_ptr->len);
      break;
    }
  }while(offset < packet_length);
  
  return(0); 
}/*radiusC_process_access_accept*/

int32_t http_get_req_authenticator(uint8_t *authenticator_ptr) {
  
  int32_t fd;
  int32_t ret = -1;
 
  fd = open("/dev/urandom", O_RDONLY);
   
  if(fd < 0) {
    fprintf(stderr, "\n%s:%d Opening of /dev/urandom failed\n", 
                    __FILE__, 
                    __LINE__);
    return(-1);
  } 

  ret = read(fd, authenticator_ptr, 16);
  close(fd);

  return(0);
}/*http_get_req_authenticator*/

int32_t radiusC_encode_password(uint8_t *password_ptr, 
                                uint16_t password_len,
                                uint8_t *authenticator_ptr,
                                uint8_t *encoded_password_ptr,
                                uint16_t *len_ptr) {
  uint8_t output[16];
  MD5_CTX context;
  uint16_t idx;
  radiusC_ctx_t *pRadiusCCtx = &g_radiusC_ctx;

  if(password_len & 0x0F) {
    /*Padd with zero to make it 16 octets*/
    *len_ptr = (password_len & 0xF0) + 0x10;
  } else {
    *len_ptr = password_len;
  }

  memcpy((void *)encoded_password_ptr, 
         (const void *)password_ptr, 
         password_len);

  /* Get MD5 hash on secret + authenticator */
  MD5_Init(&context);
  MD5_Update(&context, 
            (uint8_t*)pRadiusCCtx->secret_code, 
            strlen((const char *)pRadiusCCtx->secret_code));
  MD5_Update(&context, authenticator_ptr, 16);
  MD5_Final(output, &context);

  /* XOR first 16 octets of dst with MD5 hash */
  for (idx = 0; idx < 16; idx++) {
    encoded_password_ptr[idx] ^= output[idx];
  }

  return(0);  
}/*radiusC_encode_password*/


int32_t radiusC_process_request(uint32_t uam_conn,
                                uint8_t *packet_ptr, 
                                uint16_t packet_length) {
  uint8_t *radiusS_buffer;
  uint16_t offset = 0;
  uint8_t *secret = "Trench_captive_portal";
  //uint8_t *secret = "testing123";
  uint32_t secret_len = strlen(secret);
  uint8_t ma[16];
  uint32_t ma_len = sizeof(ma);
  uint8_t encoded_password[128];
  uint16_t encoded_password_len;
  radiusC_ctx_t *pRadiusCCtx = &g_radiusC_ctx;

  radiusS_buffer = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
  assert(radiusS_buffer != NULL);
  memset((void *)radiusS_buffer, 0, sizeof(uint8_t) * 1024);

  radiusC_message_t *req = (radiusC_message_t *)packet_ptr;

  radiusS_buffer[offset++] = *packet_ptr;

  switch(*packet_ptr) {
    case ACCESS_REQUEST:
      /*Identifier - running number from 1 to 254*/
      radiusS_buffer[offset++] = (++pRadiusCCtx->subscriber_count) % 255;
      /*Lentgth to be updated latter*/
      *((uint16_t *)&radiusS_buffer[offset]) = 0;
      offset += 2;
      /*16 Byte Random Number for Request Authenticator*/
      http_get_req_authenticator((uint8_t *)&radiusS_buffer[offset]);
      offset += 16;

      if(req->access_req.user_id_len) {
        radiusS_buffer[offset++] =  USER_NAME;
        radiusS_buffer[offset++] =  req->access_req.user_id_len + 2;
        memcpy((void *)&radiusS_buffer[offset], 
               (const char *)req->access_req.user_id, 
               req->access_req.user_id_len);
        offset += req->access_req.user_id_len;
      }
      
      if(req->access_req.password_len) {
        memset((void *)encoded_password, 0, sizeof(encoded_password));
        encoded_password_len = 0;
        radiusC_encode_password(req->access_req.password, 
                                req->access_req.password_len,
                                /*Request Authenticator*/
                                (uint8_t *)&radiusS_buffer[4],
                                encoded_password,
                                &encoded_password_len);

        radiusS_buffer[offset++] = USER_PASSWORD;
        /*+2 is for 1 for type, 1 for length*/
        radiusS_buffer[offset++] = encoded_password_len + 2;
        memcpy((void *)&radiusS_buffer[offset], 
               (const char *)encoded_password, 
               encoded_password_len);
        offset += encoded_password_len;
      }
     
      /*NAS-IP-Address*/
      radiusS_buffer[offset++] = NAS_IP_ADDRESS;
      radiusS_buffer[offset++] = 4 + 2;
      *((uint32_t *)&radiusS_buffer[offset]) = htonl(pRadiusCCtx->radiusC_ip); 
      offset += 4;

      /*NAS-PORT*/
      radiusS_buffer[offset++] = NAS_PORT;
      radiusS_buffer[offset++] = 4 + 2;
      *((uint32_t *)&radiusS_buffer[offset]) = htonl(0x00000001); 
      offset += 4;

      /*Service Type*/
      radiusS_buffer[offset++] = SERVICE_TYPE;
      radiusS_buffer[offset++] = 4 + 2;
      /*Login - 1*/
      *((uint32_t *)&radiusS_buffer[offset]) = htonl(0x00000001); 
      offset += 4;

      if(req->access_req.supplicant_id_len) {
        /*Calling-Station-Id*/
        radiusS_buffer[offset++] = CALLING_STATION_ID;
        radiusS_buffer[offset++] = req->access_req.supplicant_id_len + 2;
        memcpy((void *)&radiusS_buffer[offset], 
               req->access_req.supplicant_id, 
               req->access_req.supplicant_id_len);
        offset += req->access_req.supplicant_id_len;
      }
      
      /*Vendor Specific Attr*/
      radiusS_buffer[offset++] = VENDOR_SPECIFIC;
      radiusS_buffer[offset++] = 4 + 2;
      *((uint32_t *)&radiusS_buffer[offset]) = ntohl(req->access_req.txn_id); 
      offset += 4;

      if(req->access_req.eap_len) {
        /*encode EAP attribute*/
        radiusS_buffer[offset++] =  EAP_MESSAGE;
        radiusS_buffer[offset++] =  req->access_req.eap_len + 2;
        memcpy((void *)&radiusS_buffer[offset], 
               (const char *)req->access_req.eap, 
               req->access_req.eap_len);
        offset += req->access_req.eap_len;
      }

      if(req->access_req.state_len) {
        /*encode STATE Cookie attribute*/
        radiusS_buffer[offset++] =  STATE;
        radiusS_buffer[offset++] =  req->access_req.state_len + 2;
        memcpy((void *)&radiusS_buffer[offset], 
               (const char *)req->access_req.state, 
               req->access_req.state_len);
        offset += req->access_req.state_len;
        
      }
      /*encode Message-Authenticator*/
      radiusS_buffer[offset++] = MESSAGE_AUTHENTICATOR;
      radiusS_buffer[offset++] = ma_len + 2;

      memset((void *)ma, 0, sizeof(ma));
      memcpy((void *)&radiusS_buffer[offset], 
             (const char *)ma, 
             ma_len);
      offset += ma_len;

      /*Updating the final length of RadiusS Packet*/
      *((uint16_t *)&radiusS_buffer[2]) = htons(offset);

      /*Encoding of Message-Authenticator*/
      radiusC_hmac_md5(secret, secret_len, radiusS_buffer, offset, ma, &ma_len);
      memcpy((void *)&radiusS_buffer[offset - 16], ma, ma_len);
 
      /*Vendor Id will not be present in Access-Reject*/ 
      pRadiusCCtx->subscriber_id[pRadiusCCtx->subscriber_count].ext_conn_id = req->access_req.txn_id;

      /*radiusC's TCP connection*/
      pRadiusCCtx->subscriber_id[pRadiusCCtx->subscriber_count].conn_id = uam_conn;
     
      /*Updating the length of RadiusS Packet*/
      *((uint16_t *)&radiusS_buffer[2]) = htons(offset);

      /*calculate the Message Authenticator*/
      utility_hex_dump(radiusS_buffer, offset);
      printf("\n");
      radiusC_sendto(radiusS_buffer, offset);
      free(radiusS_buffer);

    break;

    case ACCOUNTING_REQUEST:
    break;

    case STATUS_SERVER:
    break;

    default:
    break;
  } 

}/*radiusC_process_request*/


int32_t radiusC_parse_radiusS_response(uint32_t uam_conn, 
                                       uint8_t *packet_ptr, 
                                       uint16_t packet_length) {

  uint8_t *response_ptr;
  uint16_t response_length;

  radiusS_message_header_t *header_ptr = 
                      (radiusS_message_header_t *)packet_ptr;

  radiusC_message_t message_response;
  radiusC_ctx_t *pRadiusCCtx = &g_radiusC_ctx;

  switch(*packet_ptr) {

    case ACCESS_ACCEPT:
      message_response.access_accept.message_type = *packet_ptr;

      radiusC_process_access_accept(&message_response.access_accept, 
                                    packet_ptr, 
                                    packet_length);

      response_ptr = (uint8_t *)&message_response.access_accept;
      response_length = sizeof(access_accept_t);

      radiusC_send(uam_conn,
                   response_ptr, 
                   response_length);
      break;

    case ACCESS_REJECT:
      utility_hex_dump(packet_ptr, packet_length);
      radiusC_process_access_reject(&message_response.access_reject,
                                    packet_ptr,
                                    packet_length);
      
      response_ptr = (uint8_t *)&message_response.access_reject;
      response_length = sizeof(access_reject_t);

      radiusC_send(uam_conn, 
                   response_ptr, 
                   response_length);
    break;

    case ACCESS_CHALLENGE:

      utility_hex_dump(packet_ptr, packet_length);
      memset((void *)&message_response.access_challenge,
             0,
             sizeof(message_response.access_challenge));
      message_response.access_challenge.message_type = *packet_ptr;
      radiusC_process_access_challenge(&message_response.access_challenge,
                                       packet_ptr,
                                       packet_length);

      response_ptr = (uint8_t *)&message_response.access_challenge;
      response_length = sizeof(access_challenge_t);

      radiusC_send(uam_conn, 
                   response_ptr, 
                   response_length);
      break;

    case ACCOUNTING_RESPONSE:
      message_response.accounting_response.message_type = *packet_ptr;

      //radiusC_process_accounting_response(message_response);
      break;

    default:
      break;
  }

  return(0);
}/*radiusC_parse_radiusS_response*/

uint32_t radiusC_get_con_id(uint8_t offset) {
  
  radiusC_ctx_t *pRadiusCCtx = &g_radiusC_ctx;

  return(pRadiusCCtx->subscriber_id[offset].conn_id);

}/*radiusC_get_con_id*/

int32_t radiusC_process_radiusS_response(uint32_t UdpFd) {

  uint8_t *packet_ptr;
  uint16_t packet_length;
  struct sockaddr_in peer_addr;;
  size_t addr_len = sizeof(peer_addr);
  int32_t ret = -1;
  uint32_t uam_conn;
  uint16_t max_len = 4096;

  /*Maximum size of Radius Packet could be 4096*/
  packet_ptr = (uint8_t *)malloc(4096);

  if(!packet_ptr) {
    fprintf(stderr, "\n%s:%d Malloc failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)packet_ptr, 0, 4096);
  packet_length = 0;

  ret = recvfrom(UdpFd, 
                 packet_ptr, 
                 max_len, 
                 0, 
                 (struct sockaddr *)&peer_addr,
                 (socklen_t *)&addr_len);
  if(ret > 0) {
    uam_conn = radiusC_get_con_id((uint8_t)packet_ptr[1]);
    packet_length = (uint16_t)ret;

    utility_hex_dump(packet_ptr, packet_length);
    radiusC_parse_radiusS_response(uam_conn, 
                                   packet_ptr, 
                                   packet_length);
    free(packet_ptr);
    packet_ptr = NULL;

  } else {
    fprintf(stderr, "\n%s:%d error in recvfrom\n", __FILE__, __LINE__);
    perror("recvfrom:");
  }
  return(0);

}/*radiusC_process_radiusS_response*/

int32_t radiusC_init(uint32_t radiusC_ip, 
                     uint32_t radiusC_port,
                     uint32_t radiusS_ip,
                     uint8_t *secret) {

  struct sockaddr_in self_addr;
  uint8_t ipc_type;
  radiusC_ctx_t *pRadiusCCtx = &g_radiusC_ctx;

  pRadiusCCtx->radiusC_ip = radiusC_ip;
  pRadiusCCtx->radiusC_port = radiusC_port;
  pRadiusCCtx->radiusS_ip = radiusS_ip;

  memset((void *)pRadiusCCtx->secret_code, 0, sizeof(pRadiusCCtx->secret_code));
  strncpy((char *)pRadiusCCtx->secret_code, secret, (sizeof(pRadiusCCtx->secret_code) - 1));

  pRadiusCCtx->radiusC_TcpFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(pRadiusCCtx->radiusC_TcpFd < 0) {
    fprintf(stderr, "\n%s:%d TCP Socket creation Failed\n", __FILE__, __LINE__);
    return(-1);
  }
  
  self_addr.sin_family = AF_INET;
  self_addr.sin_port = htons(radiusC_port);
  self_addr.sin_addr.s_addr = htonl(radiusC_ip);
  memset((void *)self_addr.sin_zero, 0, sizeof(self_addr.sin_zero));

  pRadiusCCtx->self_addr = self_addr;

  /*RadiusC - UamS*/
  if(bind(pRadiusCCtx->radiusC_TcpFd, (struct sockaddr *)&self_addr, sizeof(self_addr))) {
    fprintf(stderr, "\n%s:%d Bind failed\n", __FILE__, __LINE__);
    return(-2);
  }
 
  listen(pRadiusCCtx->radiusC_TcpFd, 255);
  /*Closing on exit*/
  utility_coe(pRadiusCCtx->radiusC_TcpFd);
 
  pRadiusCCtx->radiusC_UdpFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if(pRadiusCCtx->radiusC_UdpFd < 0) {
    fprintf(stderr, "\n%s:%d UDP Socket creation Failed\n", __FILE__, __LINE__);
    return(-3);
  }
 
  /*RadiusC - RadiusS*/ 
  if(bind(pRadiusCCtx->radiusC_UdpFd, (struct sockaddr *)&self_addr, sizeof(self_addr))) {
    fprintf(stderr, "\n%s:%d Bindng UDP failed\n", __FILE__, __LINE__);
    return(-4);
  }

  pRadiusCCtx->subscriber_count = 0;
  memset((void *)pRadiusCCtx->subscriber_id, 0, sizeof(pRadiusCCtx->subscriber_id));
  return(0);
}/*radiusC_init*/


void *radiusC_main(void *arg) {

  fd_set rd;
  struct timeval to;
  int32_t ret;
  struct sockaddr_in to_addr;
  struct sockaddr_in from_addr;
  int32_t max_fd;
  size_t peer_addr_len;
  int32_t uam_conn = -1;
  uint16_t idx;
  radiusC_ctx_t *pRadiusCCtx = &g_radiusC_ctx;
  peer_addr_len = sizeof(from_addr);

  for(;;) {

    FD_ZERO(&rd);
    to.tv_sec = 2;
    to.tv_usec = 0;
    FD_SET(pRadiusCCtx->radiusC_TcpFd, &rd);
    FD_SET(pRadiusCCtx->radiusC_UdpFd, &rd);

    max_fd = (pRadiusCCtx->radiusC_TcpFd > pRadiusCCtx->radiusC_UdpFd) ? 
                         pRadiusCCtx->radiusC_TcpFd : 
                         pRadiusCCtx->radiusC_UdpFd;

    if(uam_conn > 0) {
      FD_SET(uam_conn, &rd);
      max_fd = (max_fd > uam_conn) ? max_fd : uam_conn;
    }

    max_fd += 1;

    ret = select(max_fd, &rd, NULL, NULL, &to);

    if(ret > 0) {

      if(FD_ISSET(pRadiusCCtx->radiusC_TcpFd, &rd)) {

        /*New Connection Request has come in*/
        uam_conn = accept(pRadiusCCtx->radiusC_TcpFd, 
                          (struct sockaddr *)&from_addr,
                          (socklen_t *)&peer_addr_len); 

      }

      if(FD_ISSET(pRadiusCCtx->radiusC_UdpFd, &rd)) {
        /*Process RadiusS Response*/  
        radiusC_process_radiusS_response(pRadiusCCtx->radiusC_UdpFd);
      } 

      if(FD_ISSET(uam_conn, &rd)) {
        /*Either connection is closed or data has been received.*/
        uint8_t *packet_ptr = NULL;
        uint16_t packet_length = 4096;
        packet_ptr = (uint8_t *)malloc(packet_length);

        if(!packet_ptr) {
          fprintf(stderr, "\n%s:%d Malloc Failed\n", __FILE__, __LINE__);
          exit(0);
        }

        memset((void *)packet_ptr, 0, sizeof(packet_ptr));
        radiusC_recv(uam_conn, 
                     packet_ptr, 
                     &packet_length);

        if(!packet_length) {
          /*Freeing the Allocated Memory*/
          free(packet_ptr);
          packet_ptr = NULL;
          /*Closing the connected conn_id*/
          close(uam_conn);
          uam_conn = -1;

        } else {
          /*Process Request from UAM/NAS */
          radiusC_process_request(uam_conn,
                                  packet_ptr, 
                                  packet_length);
          free(packet_ptr);
          packet_ptr = NULL;
        }
      }
    }
  }
}/*radiusC_main*/


#endif /* __RADIUSC_C__ */
