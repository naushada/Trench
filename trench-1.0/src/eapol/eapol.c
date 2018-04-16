#ifndef __EAPOL_C__
#define __EAPOL_C__

#include <common.h>
#include <transport.h>
#include <type.h>
#include <radiusC.h>
#include "eapol.h"

/*
 * https://www.ietf.org/rfc/rfc2104.txt
 */
eapol_ctx_t eapol_ctx_g;

int32_t eapol_process_radius_response(int32_t conn_id, 
                                      uint8_t *in_ptr, 
                                      uint32_t in_len) {
  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  struct session_t *session = NULL;

  switch(*in_ptr) {
    case ACCESS_ACCEPT: {
      access_accept_t *accept = (access_accept_t *)in_ptr;  
      break;
    }
    case ACCESS_REJECT: {
      access_reject_t *reject = (access_reject_t *)in_ptr;  
      break;
    }
    case ACCESS_CHALLENGE: {
      uint8_t mac[ETH_ALEN];
      uint8_t *rsp_ptr = NULL;
      uint32_t rsp_len = 0;

      memset((void *)mac, 0, sizeof(mac));
      access_challenge_t *challenge = (access_challenge_t *)in_ptr;
      eapol_get_mac(conn_id, mac);
      session = eapol_get_session(mac);
      assert(session != NULL);
      /**/
      fprintf(stderr, "\n%s:%d challenge length %X\n", __FILE__, __LINE__, challenge->state_len);
      utility_hex_dump(in_ptr, in_len);
      session->state_len = challenge->state_len;
      memcpy((void *)session->state, challenge->state, session->state_len); 

      rsp_ptr = eapol_build_md5_challenge_req(conn_id, 
                                              challenge->eap, 
                                              &rsp_len);
      if(rsp_len) {
        eapol_sendto(session->fd, session->calling_mac, rsp_ptr, rsp_len);
        fprintf(stderr, "\n%s:%d Being sent to supplicant\n", __FILE__, __LINE__);
        utility_hex_dump(rsp_ptr, rsp_len);
        free(rsp_ptr);
      }
    }
      break;

    default:
      break;
  }   

  return(0);
}/*eapol_process_radius_response*/

int32_t eapol_radius_recv(int32_t fd, 
                          uint8_t *out, 
                          uint32_t max_size, 
                          uint32_t *olen) {
  ssize_t ret;
  ret = recv(fd, out, max_size, 0);

  if(ret > 0) {
    *olen = ret;
    ret = 0;
  }

  return(ret);
}/*eapol_radius_recv*/

void *eapol_recv_main(void *tid) {

  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  int32_t ret = -1;
  fd_set rd_fd;
  int32_t max_fd;
  uint32_t conn_cnt = 0;
  uint32_t idx;
  int32_t *conn_list = NULL;
  struct timeval to;

  for(;;) {

    max_fd = 0;
    FD_ZERO(&rd_fd);
    conn_cnt = eapol_get_session_count();

    if(conn_cnt > 0) {
      /*connection is established with radiusS*/
      conn_list = (int32_t *)malloc(sizeof(int32_t) * conn_cnt);
      assert(conn_list != NULL);
      memset((void *)conn_list, 0, sizeof(int32_t) * conn_cnt);
      eapol_get_session_list(conn_list);

      for(idx = 0; idx < conn_cnt; idx++) {
        FD_SET(conn_list[idx], &rd_fd);
        max_fd = (max_fd > conn_list[idx]) ? max_fd : conn_list[idx];
      }

      to.tv_sec = 2;
      to.tv_usec = 0;
      ret = select(max_fd + 1, &rd_fd, NULL, NULL, &to);

      if(ret > 0) {
        for(idx = 0; idx < conn_cnt; idx++) {
          if(FD_ISSET(conn_list[idx], &rd_fd)) {
            /*Read response from radiusS*/
            uint8_t *in_ptr = NULL;
            uint32_t max_size = 1500;
            uint32_t in_len = 0;

            in_ptr = (uint8_t *)malloc(sizeof(uint8_t) * 1500);
            assert(in_ptr != NULL);
            memset((void *)in_ptr, 0, sizeof(uint8_t) * 1500);
            eapol_radius_recv(conn_list[idx], in_ptr, max_size, &in_len);

            if(in_len) {
              eapol_process_radius_response(conn_list[idx], in_ptr, in_len);
              free(in_ptr);
            } else {
              /*connection is being closed*/
              eapol_del_session(&pEapolCtx->session_ptr, conn_list[idx]); 
            }
          }
        }
      }
      free(conn_list);
    }
  } 

  return(0);
}/*eapol_recv_main*/

struct session_t *eapol_get_session(uint8_t *mac_ptr) {
  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  struct session_t *tmp_session = pEapolCtx->session_ptr;

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
}/*eapol_get_session*/

int32_t eapol_del_session(struct session_t **session_ptr, 
                          int32_t conn_id) {

  struct session_t *prev_session = NULL;
  struct session_t *curr_session = *session_ptr;

  if(!curr_session) {
    /*No session exists as of now*/
    return(0);
  }

  /*match found at head with only one node*/
  if(curr_session && !curr_session->next) {

    if(conn_id == curr_session->conn_id) {
      (*session_ptr) = NULL;
      free(curr_session);
      return(0);
    }
  }
  
  /*Is calling mac exists?*/
  while(curr_session && curr_session->next) {

    if(conn_id == curr_session->conn_id) {
      /*found at head*/
      if(curr_session == *session_ptr) {
        *session_ptr = curr_session->next;
      } else {
        /*found in the middle*/
        prev_session->next = curr_session->next;
      }

      free(curr_session);
      return(0); 
    }
 
    prev_session = curr_session;
    curr_session = curr_session->next;
  }

  return(1);
}/*eapol_del_session*/

uint32_t eapol_get_session_count(void) {
  
  struct session_t *tmp_session = NULL;
  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  uint32_t count = 0;

  for(tmp_session = pEapolCtx->session_ptr; 
      tmp_session; 
      tmp_session = tmp_session->next) {
    count++;
  }

  return(count);
}/*eapol_get_session_count*/

int32_t eapol_get_session_list(int32_t *conn_list) {
   
  struct session_t *tmp_session = NULL;
  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  uint32_t idx = 0;

  for(tmp_session = pEapolCtx->session_ptr; 
      tmp_session; 
      tmp_session = tmp_session->next, idx++) {
    conn_list[idx] = tmp_session->conn_id;
  }

  return(0);
}/*eapol_get_session_list*/

int32_t eapol_get_mac(int32_t conn_id, uint8_t *mac) {
  struct session_t *tmp_session = NULL;
  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;

  for(tmp_session = pEapolCtx->session_ptr; 
      tmp_session; 
      tmp_session = tmp_session->next) {

    if(conn_id == tmp_session->conn_id) {
      memcpy((void *)mac, tmp_session->calling_mac, ETH_ALEN);
      return(0);
    } 
  }

  return(1);
}/*eapol_get_mac*/

int32_t eapol_insert_session(int32_t fd,
                             struct session_t **session_ptr, 
                             uint8_t *in_ptr) {

  struct session_t *tmp_session = *session_ptr;
  struct session_t *new_session = NULL;

  new_session = (struct session_t *)malloc(sizeof(struct session_t));
  assert(new_session != NULL);

  memset((void *)new_session, 0, sizeof(struct session_t));
  memcpy((void *)new_session->calling_mac, &in_ptr[ETH_ALEN], ETH_ALEN);
  memcpy((void *)new_session->self_mac, in_ptr, ETH_ALEN);
  new_session->fd = fd;
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
}/*eapol_insert_session*/


int32_t eapol_init(uint8_t *eth_name,
                   uint32_t radiusC_ip,
                   uint32_t radiusC_port) {

  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  int32_t fd;
  struct ifreq ifr;

  memset((void *)pEapolCtx->eth_name, 0, sizeof(pEapolCtx->eth_name));
  strncpy((void *)pEapolCtx->eth_name, eth_name, sizeof(pEapolCtx->eth_name) - 1);

  memset((void *)&ifr, 0, sizeof(struct ifreq));

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, eth_name, IFNAMSIZ);

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation failed\n", __FILE__, __LINE__);
    perror("fd:");
    return(1);
  }

  /*Retrieving Ethernet interface index*/
  if(ioctl(fd, SIOCGIFINDEX, &ifr)) {
    fprintf(stderr, "\n%s:%dGetting index failed\n", __FILE__, __LINE__);
    perror("INDEX:");
    close(fd);
    return(2);
  }
  
  pEapolCtx->intf_idx = ifr.ifr_ifindex;
  pEapolCtx->radiusC_ip = radiusC_ip;
  pEapolCtx->radiusC_port = radiusC_port;
  return(0); 
}/*eapol_init*/

int32_t eapol_sendto(int32_t fd, 
                     uint8_t *dst_mac, 
                     uint8_t *packet, 
                     uint32_t packet_len) {
  int ret = -1;
  struct sockaddr_ll sa;
  uint16_t offset = 0;
  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  socklen_t addr_len = sizeof(sa);


  if(!packet) {
    return (-1);
  }

  memset((void *)&sa, 0, sizeof(sa));
  sa.sll_family   = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex  = pEapolCtx->intf_idx;
  sa.sll_halen    = ETH_ALEN;

  memcpy((void *)sa.sll_addr, (void *)dst_mac, ETH_ALEN);

  do {
    ret = sendto(fd, 
                (const void *)&packet[offset], 
                (packet_len - offset), 
                0, 
                (struct sockaddr *)&sa, 
                addr_len);

    if(ret > 0) {
      offset += ret;

      if(!(packet_len - offset)) {
        ret = 0;
      }
    }

  }while((ret == -1) && (errno == EINTR));
 
  return (ret);
}/*eapol_sendto*/

int32_t eapol_radius_connect(uint32_t *conn_id) {

  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;
  int32_t fd;
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
  if(fd < 0) {
    fprintf(stderr, "\n%s:%d Creation of socket failed\n", __FILE__, __LINE__);
    return(1);
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(pEapolCtx->radiusC_ip);
  addr.sin_port = htons(pEapolCtx->radiusC_port);
  memset((void *)addr.sin_zero, 0, sizeof(addr.sin_zero));

  if(connect(fd, (struct sockaddr *)&addr, addr_len) < 0) {
    fprintf(stderr, "\n%s:%d Connect to radiusC failed\n", __FILE__, __LINE__);
    perror("connection failed");
    return(2);
  } 

  *conn_id = fd;
  return(0);
}/*eapol_radius_connect*/


int32_t eapol_radius_send(uint8_t *src_mac, 
                          uint8_t *req_ptr, 
                          uint32_t req_len) {

  struct session_t *session_ptr = NULL;
  uint32_t offset = 0;
  int32_t ret = -1;

  session_ptr = eapol_get_session(src_mac);
  assert(session_ptr != NULL);

  if(!session_ptr->conn_id) {
    eapol_radius_connect(&session_ptr->conn_id);
  }

  do {

    ret = send(session_ptr->conn_id, 
               &req_ptr[offset], 
               (size_t)(req_len - offset), 
               0);
    
    if(ret > 0) {
      offset += ret;

      if(offset == req_len) {
        offset = 0;
      }
    }

  }while(offset);
  
  return(0);
}/*eapol_radius_send*/

int32_t eapol_build_access_req(int32_t fd, 
                               uint8_t *in_ptr, 
                               uint8_t *req_ptr, 
                               uint32_t *req_len) {
  
  struct eapol *eapol_ptr;
  uint8_t user_id[255];
  uint32_t user_id_len = 0;
  struct session_t *session = NULL;

  session = eapol_get_session(&in_ptr[ETH_ALEN]);
  assert(session != NULL);

  eapol_ptr = (struct eapol *)&in_ptr[sizeof(struct eth) + 
              sizeof(struct ieee802dot1x)];

  if(EAP_TYPE_IDENTITY == eapol_ptr->type) {
    /*copying the user id*/
    memset((void *)user_id, 0, sizeof(user_id));
    user_id_len = ntohs(eapol_ptr->length) - 5;
    memcpy((void *)user_id, eapol_ptr->payload, user_id_len);

    /*copying into session for later use*/
    memset((void *)session->user_id, 0, sizeof(session->user_id));
    strncpy(session->user_id, eapol_ptr->payload, user_id_len);
  } else {

    /*copying the user id*/
    memset((void *)user_id, 0, sizeof(user_id));
    user_id_len = strlen(session->user_id);
    memcpy((void *)user_id, session->user_id, user_id_len);
  }

  access_request_t *access_req_ptr = 
               (access_request_t *)req_ptr;

  *req_len = sizeof(access_request_t);
  
  access_req_ptr->message_type = ACCESS_REQUEST;
  access_req_ptr->txn_id = fd;
  access_req_ptr->user_id_len = user_id_len;
  memcpy((void *)access_req_ptr->user_id, 
         (const void *)user_id, 
         user_id_len);

  /*fill eap*/
  access_req_ptr->eap_len = ntohs(eapol_ptr->length);
  memcpy((void *)access_req_ptr->eap, eapol_ptr, ntohs(eapol_ptr->length)); 

  /*Filling suplicant calling station id (MAC)*/
  memset((void *)access_req_ptr->supplicant_id, 
         0, 
         sizeof(access_req_ptr->supplicant_id));

  access_req_ptr->supplicant_id_len = snprintf(access_req_ptr->supplicant_id,
                                               sizeof(access_req_ptr->supplicant_id),
                                               "%X-%X-%X-%X-%X-%X",
                                               in_ptr[ETH_ALEN + 0],
                                               in_ptr[ETH_ALEN + 1],
                                               in_ptr[ETH_ALEN + 2],
                                               in_ptr[ETH_ALEN + 3],
                                               in_ptr[ETH_ALEN + 4],
                                               in_ptr[ETH_ALEN + 5]);
  access_req_ptr->password_len = 0;

  if(session && session->state_len) {
    access_req_ptr->state_len = session->state_len;
    memcpy((void *)access_req_ptr->state, session->state, session->state_len);
  }

  return(0);
}/*eapol_build_access_req*/

int32_t eapol_process_rsp(int32_t fd, uint8_t *in_ptr, uint32_t in_len) {
  struct eapol *eapol_ptr;
  uint8_t *req_ptr = NULL;
  uint32_t req_len = 0;

  eapol_ptr = (struct eapol *)&in_ptr[sizeof(struct eth) + 
              sizeof(struct ieee802dot1x)];

  switch(eapol_ptr->type) {

    case EAP_TYPE_IDENTITY:
    case EAP_TYPE_NAK:

      req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * 256);
      assert(req_ptr != NULL);
      memset((void *)req_ptr, 0, sizeof(uint8_t) * 256);
      /*Build Access Request*/
      eapol_build_access_req(fd, in_ptr, req_ptr, &req_len);
      eapol_radius_send(&in_ptr[ETH_ALEN], req_ptr, req_len); 
      free(req_ptr);
      break;

    default:
      fprintf(stderr, "\n%s:%d not supported\n", __FILE__, __LINE__);
      break; 

  }

  return(0);
}/*eapol_process_rsp*/

uint8_t *eapol_build_md5_challenge_req(int32_t fd, 
                                       uint8_t *eap_ptr, 
                                       uint32_t *rsp_len) {

  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_size = sizeof(uint8_t) * 256;
  struct eth *eth_ptr = NULL;
  struct ieee802dot1x *dot1x_ptr = NULL;
  struct eapol *eapol_ptr = NULL;
  struct eapol *eap_req_ptr = NULL;
  uint8_t mac[ETH_ALEN];
  struct session_t *session_ptr = NULL;

  rsp_ptr = (uint8_t *)malloc(rsp_size);
  assert(rsp_ptr != NULL);
  memset((void *)rsp_ptr, 0, rsp_size);

  eth_ptr = (struct eth *)rsp_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&rsp_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&rsp_ptr[sizeof(struct eth) + 
                                       sizeof(struct ieee802dot1x)];

  /*eap received from radiusS*/
  eap_req_ptr = (struct eapol *)eap_ptr;

  memset((void *)mac, 0, sizeof(mac));
  eapol_get_mac(fd, mac);
  session_ptr = eapol_get_session(mac);
  assert(session_ptr != NULL);

  /*Populating Ethernet Header*/
  memcpy((void *)eth_ptr->h_dest, session_ptr->calling_mac, ETH_ALEN);
  memcpy((void *)eth_ptr->h_source, session_ptr->self_mac, ETH_ALEN);
  eth_ptr->h_proto = htons(0x888e);

  /*Populating 802.1x header*/
  dot1x_ptr->ver = 1;
  /*802.1x containing EAP Payload*/
  dot1x_ptr->type = EAPOL_TYPE_EAP;
  /*802.1x payload length*/ 
  dot1x_ptr->len = eap_req_ptr->length;

  /*Populating EAP Request*/
  eapol_ptr->code = eap_req_ptr->code;
  /*ip to be copied from Access-Challenge*/
  eapol_ptr->id = eap_req_ptr->id;
  eapol_ptr->length = eap_req_ptr->length;
  eapol_ptr->type = eap_req_ptr->type;
  /*copy eap payload*/
  memcpy((void *)eapol_ptr->payload, 
         eap_req_ptr->payload, 
         ntohs(eap_req_ptr->length) - 5);
 
  *rsp_len = sizeof(struct eth) + 
             sizeof(struct ieee802dot1x) + 
             ntohs(eap_req_ptr->length);

  return(rsp_ptr); 
}/*eapol_build_md5_challenge_req*/


uint8_t *eapol_build_failure_req(int32_t fd, 
                                 uint8_t *in_ptr, 
                                 uint32_t *rsp_len) {

  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_size = sizeof(uint8_t) * 256;
  struct eth *eth_ptr = NULL;
  struct ieee802dot1x *dot1x_ptr = NULL;
  struct eapol *eapol_ptr = NULL;

  rsp_ptr = (uint8_t *)malloc(rsp_size);
  assert(rsp_ptr != NULL);
  memset((void *)rsp_ptr, 0, rsp_size);

  eth_ptr = (struct eth *)rsp_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&rsp_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&rsp_ptr[sizeof(struct eth) + sizeof(struct ieee802dot1x)];

  /*Populating Ethernet Header*/
  memcpy((void *)eth_ptr->h_source, ((struct eth *)in_ptr)->h_dest, ETH_ALEN);
  memcpy((void *)eth_ptr->h_dest, ((struct eth *)in_ptr)->h_source, ETH_ALEN);
  eth_ptr->h_proto = ((struct eth *)in_ptr)->h_proto;

  /*Populating 802.1x header*/
  dot1x_ptr->ver = 1;
  /*802.1x containing EAP Payload*/
  dot1x_ptr->type = EAPOL_TYPE_EAP;
  /*802.1x payload length*/ 
  dot1x_ptr->len = htons(5);

  /*Populating EAP Request*/
  eapol_ptr->code = EAP_CODE_FAILURE;
  /*ip to be copied from Access-Reject*/
  eapol_ptr->id = 1;
  eapol_ptr->length = htons(4);
 
  *rsp_len = sizeof(struct eth) + sizeof(struct ieee802dot1x) + 4;

  return(rsp_ptr); 
}/*eapol_build_failure_req*/


uint8_t *eapol_build_success_req(int32_t fd, 
                                 uint8_t *in_ptr, 
                                 uint32_t *rsp_len) {

  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_size = sizeof(uint8_t) * 256;
  struct eth *eth_ptr = NULL;
  struct ieee802dot1x *dot1x_ptr = NULL;
  struct eapol *eapol_ptr = NULL;

  rsp_ptr = (uint8_t *)malloc(rsp_size);
  assert(rsp_ptr != NULL);
  memset((void *)rsp_ptr, 0, rsp_size);

  eth_ptr = (struct eth *)rsp_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&rsp_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&rsp_ptr[sizeof(struct eth) + sizeof(struct ieee802dot1x)];

  /*Populating Ethernet Header*/
  memcpy((void *)eth_ptr->h_source, ((struct eth *)in_ptr)->h_dest, ETH_ALEN);
  memcpy((void *)eth_ptr->h_dest, ((struct eth *)in_ptr)->h_source, ETH_ALEN);
  eth_ptr->h_proto = ((struct eth *)in_ptr)->h_proto;

  /*Populating 802.1x header*/
  dot1x_ptr->ver = 1;
  /*802.1x containing EAP Payload*/
  dot1x_ptr->type = EAPOL_TYPE_EAP;
  /*802.1x payload length*/ 
  dot1x_ptr->len = htons(5);

  /*Populating EAP Request*/
  eapol_ptr->code = EAP_CODE_SUCCESS;
  /*ip to be copied from Access-Acept*/
  eapol_ptr->id = 1;
  eapol_ptr->length = htons(4);
 
  *rsp_len = sizeof(struct eth) + sizeof(struct ieee802dot1x) + 4;

  return(rsp_ptr); 
}/*eapol_build_success_req*/


uint8_t *eapol_build_identity_req(int32_t fd, 
                                  uint8_t *in_ptr, 
                                  uint32_t *rsp_len) {

  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_size = sizeof(uint8_t) * 256;
  struct eth *eth_ptr = NULL;
  struct ieee802dot1x *dot1x_ptr = NULL;
  struct eapol *eapol_ptr = NULL;

  rsp_ptr = (uint8_t *)malloc(rsp_size);
  assert(rsp_ptr != NULL);
  memset((void *)rsp_ptr, 0, rsp_size);

  eth_ptr = (struct eth *)rsp_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&rsp_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&rsp_ptr[sizeof(struct eth) + sizeof(struct ieee802dot1x)];

  /*Populating Ethernet Header*/
  memcpy((void *)eth_ptr->h_source, ((struct eth *)in_ptr)->h_dest, ETH_ALEN);
  memcpy((void *)eth_ptr->h_dest, ((struct eth *)in_ptr)->h_source, ETH_ALEN);
  eth_ptr->h_proto = ((struct eth *)in_ptr)->h_proto;

  /*Populating 802.1x header*/
  dot1x_ptr->ver = 1;
  /*802.1x containing EAP Payload*/
  dot1x_ptr->type = EAPOL_TYPE_EAP;
  /*802.1x payload length*/ 
  dot1x_ptr->len = htons(5);

  /*Populating EAP Request*/
  eapol_ptr->code = EAP_CODE_REQUEST;
  eapol_ptr->id = 1;
  eapol_ptr->length = htons(5);
  eapol_ptr->type = EAP_TYPE_IDENTITY;
 
  *rsp_len = sizeof(struct eth) + sizeof(struct ieee802dot1x) + 5;

  return(rsp_ptr); 
}/*eapol_build_identity_req*/

int32_t eapol_main(int32_t fd, uint8_t *in_ptr, uint32_t inlen) {
  uint8_t multicast_mac[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
  struct eth *eth_ptr;
  struct ieee802dot1x *dot1x_ptr;
  struct eapol *eapol_ptr;
  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_len = 0;
  eapol_ctx_t *pEapolCtx = &eapol_ctx_g;

  eth_ptr = (struct eth *)in_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&in_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&in_ptr[sizeof(struct eth) + sizeof(struct ieee802dot1x)];

  if(!memcmp(multicast_mac, eth_ptr->h_dest, ETH_ALEN)) {
    fprintf(stderr, "\n%s:%d EAPOL Multicast Packet Received\n",
                      __FILE__, __LINE__);    
  }

  switch(dot1x_ptr->type) {

    case EAPOL_TYPE_EAP:
      /*EAP Response Packet*/
      eapol_process_rsp(fd, in_ptr, inlen);
      break;

    case EAPOL_TYPE_START:
      /*Create a session for calling suplicant*/
      eapol_insert_session(fd, &pEapolCtx->session_ptr, in_ptr);
      rsp_ptr = eapol_build_identity_req(fd, in_ptr, &rsp_len);

      if(rsp_len) {
        uint8_t dst_mac[ETH_ALEN];
        memcpy(dst_mac, rsp_ptr, ETH_ALEN);
        eapol_sendto(fd, dst_mac, rsp_ptr, rsp_len);
        free(rsp_ptr);
      }

      break;

    case EAPOL_TYPE_LOGOFF:
      break;

    case EAPOL_TYPE_KEY:
      break;

    case EAPOL_TYPE_ENCAPSULATED:
      break;

    default:
      fprintf(stderr, "\n%s:%d Invalid 802.1x packet type %d", 
                       __FILE__, __LINE__, dot1x_ptr->type);
      break;
  }

  return(0);
}/*eapol_main*/




#endif /* __EAPOL_C__ */
