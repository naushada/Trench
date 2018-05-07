#ifndef __HTTP_C__
#define __HTTP_C__

#include <sys/stat.h>
#include <signal.h>
#include <type.h>
#include <common.h>
#include <utility.h>
#include "http.h"

/********************************************************************
 *  Global Instance Declaration
 ********************************************************************/
http_ctx_t g_http_ctx;

http_req_handler_t g_handler_http[] = {

  {"/img",                        4, http_process_image_req},
  {"/favicon.ico",               12, http_process_favicon_req},
  {"/login.html",                11, http_process_login_req},
  {"/ui.html",                    8, http_process_ui_req},
  {"/sign_in.html",              13, http_process_sign_in_req},
  {"/register.html",             14, http_process_register_req},
  {"/login_with_mobile_no.html", 26, http_process_login_with_mobile_no_req},
  {"/index.html",                11, http_process_login_req},
  /*Prompt for Aadhaar Number*/
  {"/aadhaar_ui.html",           16, http_process_aadhaar_ui_req},
  /*Provide the Aadhaar Number*/
  {"/aadhaar_uid.html",          17, http_process_aadhaar_uid_req},
  /*Provide the OTP value*/
  {"/aadhaar_otp.html",          17, http_process_aadhaar_otp_req},
  /*Authentication based on OTP*/
  {"/aadhaar_auth_otp.html",     22, http_process_aadhaar_auth_otp_req},
  {"/aadhaar_auth_pi.html",      21, http_process_aadhaar_auth_pi_req},
  /*Final Response of Auth*/
  {"/aadhaar_auth.html",         18, http_process_aadhaar_auth_req},
  /*google sign-in*/
  {"/google_ui.html",            15, http_process_google_ui_req},
  /*gmail-auth*/
  {"/google_access_code.html",   24, http_process_google_access_code_req},
  {"/google_access_token.html",  25, http_process_google_access_token_req},
  /*twitter sign-in*/
  {"/twitter_ui.html",           16, http_process_twitter_ui_req},
  /*fb sign-in*/
  {"/fb_ui.html",                11, http_process_fb_ui_req},

  /*New callback to be inserted above this*/
  {"/",                           1, http_process_login_req},
  {NULL,                          0, NULL}

};


/********************************************************************
 *Function Definition
 ********************************************************************/

int32_t http_process_google_access_token_req(uint32_t conn_id,
                                             uint8_t **response_ptr,
                                             uint32_t *response_len_ptr) {

  /*GET /response_callback?auth_type=gmail&conn_id=14 HTTP/1.1*/
  uint8_t *req = NULL;
  uint32_t req_len;
  uint8_t *state_ptr = NULL;
  uint8_t *code_ptr = NULL;
  uint8_t ip_str[32];

  http_session_t *session = NULL;

  req = (uint8_t *)malloc(512);
  assert(req != NULL);
  memset((void *)req, 0, 512);

  session = http_get_session(conn_id);
  assert(session != NULL);
  state_ptr = http_get_gparam(session->uri, strlen(session->uri), "state"); 
  code_ptr = http_get_gparam(session->uri, strlen(session->uri), "code");

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(session->peer_addr.sin_addr.s_addr, ip_str);
  req_len = 0;
  req_len = snprintf(req, 
                     512,
                     "%s%d%s%s%s"
                     "%s%s%s%s%s"
                     "%s",
                     "GET /response_callback?auth_type=gmail&subtype=access_token&conn_id=",
                     conn_id,
                     "&state=",
                     state_ptr,
                     "&code=",
                     code_ptr,
                     "&ip=",
                     ip_str,
                     " HTTP/1.1\r\n",
                     "Connection: Keep-alive\r\n",
                     "Content-Length: 0\r\n");

  fprintf(stderr, "\n%s:%d Access Token Request %s\n", __FILE__, __LINE__, req);
  /*send to NAS*/
  http_send_to_nas(conn_id, req, req_len);

  /*Freeing the heap memory*/
  free(state_ptr);
  free(code_ptr);
  free(req);
  req = NULL;

  return(0);
}/*http_process_google_access_token_req*/

int32_t http_process_google_access_code_req(uint32_t conn_id,
                                            uint8_t **response_ptr,
                                            uint32_t *response_len_ptr) {

  uint8_t *refresh_uri = "/google_access_code.html";
  http_session_t *session = NULL;
  session = http_get_session(conn_id);
  assert(session != NULL); 

  if(!session->oauth2_param.oauth2_rsp) {
  
    /*Making Browser to wait to response for 1sec*/
    http_process_wait_req(conn_id,
                        response_ptr,
                        response_len_ptr,
                        refresh_uri);
  } else {
    http_process_wait_req(conn_id,
                        response_ptr,
                        response_len_ptr,
                        session->oauth2_param.gmail_url);

    free(session->oauth2_param.gmail_url);
    session->oauth2_param.gmail_url = NULL;
    fprintf(stderr, "\n%s:%d Response %s\n", __FILE__, __LINE__, *response_ptr);
  }

  return(0);
}/*http_process_google_access_code_req*/

int32_t http_process_google_ui_req(uint32_t conn_id, 
                                   uint8_t **response_ptr,
                                   uint32_t *response_len_ptr) {

  /*GET /response_callback?auth_type=gmail&conn_id=14 HTTP/1.1*/
  uint8_t *req = NULL;
  uint8_t ip_str[32];
  uint32_t req_len;
  uint8_t *refresh_uri = "/google_access_code.html";
  http_session_t *session = NULL;

  req = (uint8_t *)malloc(512);
  assert(req != NULL);
  memset((void *)req, 0, 512);
  memset((void *)ip_str, 0, sizeof(ip_str));
  session = http_get_session(conn_id);
  assert(session != NULL);
  
  utility_ip_int_to_str(session->peer_addr.sin_addr.s_addr, ip_str);
  req_len = 0;
  req_len = snprintf(req, 
                     512,
                     "%s%d%s%s%s"
                     "%s%s",
                     "GET /response_callback?auth_type=gmail&subtype=access_code&conn_id=",
                     conn_id,
                     "&ip=",
                     ip_str,
                     " HTTP/1.1\r\n",
                     "Connection: Keep-alive\r\n",
                     "Content-Length: 0\r\n");

  fprintf(stderr, "\n%s:%d Auth gmail %s\n", __FILE__, __LINE__, req);
  /*send to NAS*/
  http_send_to_nas(conn_id, req, req_len);
  free(req);
  req = NULL;

  session->oauth2_param.oauth2_rsp = 0;
  /*Making Browser to wait for response*/
  http_process_wait_req(conn_id,
                        response_ptr,
                        response_len_ptr,
                        refresh_uri);
  return(0); 
}/*http_process_google_ui_req*/

int32_t http_process_twitter_ui_req(uint32_t conn_id, 
                                    uint8_t **response_ptr,
                                    uint32_t *response_len_ptr) {
}/*http_process_twitter_ui_req*/

int32_t http_process_fb_ui_req(uint32_t conn_id, 
                               uint8_t **response_ptr,
                               uint32_t *response_len_ptr) {
}/*http_process_fb_ui_req*/

int32_t http_build_aadhaar_auth_pi_req(uint32_t conn_id, uint8_t *req, uint32_t *req_len) {

  uint8_t param[8][2][64];
  uint8_t *uid_ptr = NULL;
  uint8_t *name_ptr = NULL;
  uint8_t *mv_ptr = NULL;
  uint8_t ip_str[32];

  http_session_t *session = NULL;
  session = http_get_session(conn_id);
  assert(session != NULL);
  
  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(session->peer_addr.sin_addr.s_addr, ip_str);

  memset((void *)param, 0, sizeof(param));
  fprintf(stderr, "\n%s:%d uri %s\n", __FILE__, __LINE__, session->uri);
  http_parse_param(param, session->uri);

  uid_ptr = http_get_param(param, "uid");
  name_ptr = http_get_param(param, "r_name");
  mv_ptr = http_get_param(param, "ms");
  /*GET /response_callback?auth_type=aadhaar&subtype=auth&subsubtype=otp&aadhaar_no=9701361361&otp_value=XXXX&rc=y&ver=2.0&conn_id=14 HTTP/1.1*/
  sprintf(req,
          "%s%s%s%s%s"
          "%s%s%s%d%s"
          "%s%s%s%s",
          "GET /response_callback?auth_type=aadhaar&subtype=auth&subsubtype=pi&aadhaar_no=",
          uid_ptr,
          "&name=",
           name_ptr,
          "&ms=",
          mv_ptr,
          "&rc=y&ver=2.0&",
          "conn_id=",
          conn_id,
          "&ip=",
          ip_str,
          " HTTP/1.1\r\n",
          "Connection: Keep-alive\r\n",
          "Content-Length: 0\r\n");

  *req_len = strlen(req);

  session->uidai_param.uidai_rsp = 0;
  return(0);
}/*http_build_aadhaar_auth_pi_req*/

int32_t http_process_aadhaar_auth_pi_req(uint32_t conn_id, 
                                         uint8_t **response_ptr,
                                         uint32_t *response_len_ptr) {
  uint8_t *req = NULL;
  uint32_t req_len;
  uint8_t *refresh_uri = "/aadhaar_auth.html";

  req = (uint8_t *)malloc(1024);
  assert(req != NULL);
  memset((void *)req, 0, 1024);
  req_len = 0;
  http_build_aadhaar_auth_pi_req(conn_id, req, &req_len);
  fprintf(stderr, "\n%s:%d Auth %s\n", __FILE__, __LINE__, req);
  /*send to NAS*/
  http_send_to_nas(conn_id, req, req_len);
  free(req);
  req = NULL;
  /*Making Browser to wait for response*/
  http_process_wait_req(conn_id,
                        response_ptr,
                        response_len_ptr,
                        refresh_uri);
 
}/*http_process_aadhaar_auth_pi_req*/

int32_t http_process_aadhaar_auth_req(uint32_t conn_id, 
                                      uint8_t **response_ptr, 
                                      uint32_t *response_len_ptr) {

  uint8_t *refresh_uri = "/aadhaar_auth.html";
  http_process_wait_req(conn_id,
                        response_ptr,
                        response_len_ptr,
                        refresh_uri);
  return(0);
}/*http_process_aadhaar_auth_req*/

int32_t http_process_aadhaar_auth_otp_req(uint32_t conn_id, 
                                          uint8_t **response_ptr, 
                                          uint32_t *response_len_ptr) {
  uint8_t req[512];
  uint32_t req_len;
  uint8_t *refresh_uri = "/aadhaar_auth.html";

  memset((void *)req, 0, sizeof(req));
  req_len = 0;
  http_build_aadhaar_auth_otp_req(conn_id, req, &req_len);
  fprintf(stderr, "\n%s:%d Auth %s\n", __FILE__, __LINE__, req);
  /*send to NAS*/
  http_send_to_nas(conn_id, req, req_len);

  /*Making Browser to wait for response*/
  http_process_wait_req(conn_id,
                        response_ptr,
                        response_len_ptr,
                        refresh_uri);
  return(0);
}/*http_process_aadhaar_auth_otp_req*/

int32_t http_parse_param(uint8_t (*param)[2][64], uint8_t *rsp_ptr) {
  uint8_t *line_ptr;
  uint8_t tmp_uri[512];
  uint32_t idx = 0;
  char *save_ptr;

  memset((void *)tmp_uri, 0, sizeof(tmp_uri));

  sscanf(rsp_ptr, "%*[^?]?%s", tmp_uri);

  line_ptr = strtok_r(tmp_uri, "&", &save_ptr);

  while(line_ptr) {
    sscanf(line_ptr, "%[^=]=%s",
                      param[idx][0],
                      param[idx][1]);
    line_ptr = strtok_r(NULL, "&", &save_ptr);
    idx++;  
  }

  /*NULL terminated the array*/
  param[idx][0][0] = '\0';
  param[idx][1][0] = '\0';

  return(0);
}/*http_parse_param*/

uint8_t *http_get_param_ex(uint8_t (*param)[2][255], uint8_t *arg) {

  uint32_t idx;

  for(idx = 0; param[idx][0][0]; idx++) {
    if(!strncmp(param[idx][0], arg, strlen(arg))) {
      return(param[idx][1]);
    }    
  }
  
  return(NULL);
}/*http_get_param_ex*/

uint8_t *http_get_param(uint8_t (*param)[2][64], uint8_t *arg) {

  uint32_t idx;

  for(idx = 0; param[idx][0][0]; idx++) {
    if(!strncmp(param[idx][0], arg, strlen(arg))) {
      return(param[idx][1]);
    }    
  }
  
  return(NULL);
}/*http_get_param*/

uint8_t *http_get_gparam(uint8_t *req_ptr, uint32_t req_len, uint8_t *p_name) {

  uint8_t *tmp_req_ptr = NULL;
  uint8_t *line_ptr = NULL;
  uint8_t param_name[32];
  uint8_t *param_value = NULL;
  char *save_ptr;
  uint8_t flag = 0;

  tmp_req_ptr = (uint8_t *) malloc(sizeof(uint8_t) * req_len);
  assert(tmp_req_ptr != NULL);
  memset((void *)tmp_req_ptr, 0, (sizeof(uint8_t) * req_len));

  memset((void *)param_name, 0, sizeof(param_name));
  param_value = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
  assert(param_value != NULL);
  memset((void *)param_value, 0, (sizeof(uint8_t) * 1024));
  
  sscanf(req_ptr, "%*[^?]?%s", tmp_req_ptr);
  line_ptr = strtok_r(tmp_req_ptr, "&", &save_ptr);

  while(line_ptr) {
    sscanf(line_ptr, "%[^=]=%s", param_name, param_value);

    if(!strncmp(param_name, p_name, strlen(p_name))) {
      flag = 1;
      break;      
    }
    line_ptr = strtok_r(NULL, "&", &save_ptr);
  }

  free(tmp_req_ptr);
  if(flag) {
    return(param_value);
  }

  return(NULL);
}/*http_get_gparam*/

int32_t http_process_login_rsp(uint8_t *packet_ptr, uint32_t packet_length) {

  uint8_t *conn_ptr = NULL;
  uint8_t *status_ptr = NULL;
  uint8_t body[255];
  uint8_t rsp[512];
  uint32_t rsp_len = 0;
  
  conn_ptr = http_get_gparam(packet_ptr, packet_length, "conn_id");
  status_ptr = http_get_gparam(packet_ptr, packet_length, "status");

  if(!conn_ptr || status_ptr) {
    fprintf(stderr, "\n%s:%d Either conn_ptr or status_ptr is NULL", __FILE__, __LINE__);    
    return(1);
  }

  memset((void *)body, 0, sizeof(body));
  memset((void *)rsp, 0, sizeof(rsp));

  if(!strncmp(status_ptr, "success", 7)) {
    /*User is authenticated successfully*/
    rsp_len = snprintf(body,
                       sizeof(body),
                       "%s%s%s%s%s"
                       "%s%s%s%s%s",
                       "<html><head>",
                       "<title>",
                       "</title>",
                       "</head>",
                       "<body>",
                       "<h1>",
                       "You have successfully been Authenticated by Balaagh",
                       "</h1>",
                       "</body>",
                       "<html>");
    snprintf(rsp,
             sizeof(rsp),
             "%s%s%s%s%s"
             "%s%d%s%s%s",
             "HTTP/1.1 302 Moved Temporarily\r\n",
             "Location: https://balaagh.com\r\n",
             "Host: balaagh.com\r\n",
             "Content-Type: text/html\r\n",
             "Connection: close\r\n",
             "Content-Length: ",
             rsp_len,
             "\r\n",
             /*Body delimiter*/
             "\r\n",
             body);

    http_send(atoi(conn_ptr), rsp, strlen(rsp));
    free(status_ptr);

  } else if(!strncmp(status_ptr, "rejected", 8)) {
    /*User is authenticated successfully*/
    rsp_len = snprintf(body,
                       sizeof(body),
                       "%s%s%s%s%s"
                       "%s%s%s%s%s",
                       "<html><head>",
                       "<title>",
                       "</title>",
                       "</head>",
                       "<body>",
                       "<h1>",
                       "You have Invalid user id or password",
                       "</h1>",
                       "</body>",
                       "<html>");
    snprintf(rsp,
             sizeof(rsp),
             "%s%s%s%s%s"
             "%s%d%s%s%s",
             "HTTP/1.1 302 Moved Temporarily\r\n",
             "Location: http://adam.balaagh.com:3990\r\n",
             "Host: adam.balaagh.com\r\n",
             "Content-Type: text/html\r\n",
             "Connection: Keep-alive\r\n",
             "Content-Length: ",
             rsp_len,
             "\r\n",
             /*Body delimiter*/
             "\r\n",
             body);

    http_send(atoi(conn_ptr), rsp, strlen(rsp));
    free(status_ptr);
  }

  return(0);
}/*http_process_login_rsp*/

int32_t http_process_google_rsp(uint8_t *packet_ptr, 
                                uint32_t packet_length) {
  uint8_t *type = NULL;
  uint8_t *subtype_ptr = NULL;
  uint8_t *status_ptr = NULL;
  uint8_t *conn_ptr = NULL;
  http_session_t *session = NULL;
  uint8_t *pArr[10];
  uint32_t idx; 
  uint32_t max_arg = 0;

  /*/response?type=gmail&location=<>&conn_id=14*/
  conn_ptr = http_get_gparam(packet_ptr, packet_length, "conn_id");
  subtype_ptr = http_get_gparam(packet_ptr, packet_length, "subtype");

  if(!conn_ptr) {
    fprintf(stderr, "\n%s:%d connection is NULL\n", __FILE__, __LINE__);
    return(1);
  }

  if(!strncmp(subtype_ptr, "redirect", 8)) { 
    session = http_get_session(atoi(conn_ptr));
    free(conn_ptr);

    if(!session) {
      fprintf(stderr, "\n%s:%d getting session failed\n", __FILE__, __LINE__);
      return(2);
    }  

    session->oauth2_param.gmail_url = (uint8_t *)malloc(sizeof(uint8_t) * 1024);
    memset((void *)session->oauth2_param.gmail_url, 0, 1024);
    snprintf(session->oauth2_param.gmail_url, 
             1024,
             "%s%s%s%s%s"
             "%s%s%s%s%s"
             "%s%s%s%s%s",
             pArr[0] = http_get_gparam(packet_ptr, packet_length, "uri"),
             "?scope=",
             pArr[1] = http_get_gparam(packet_ptr, packet_length, "scope"),
             "&access_type=",
             pArr[2] = http_get_gparam(packet_ptr, packet_length, "access_type"),
             "&state=",
             pArr[3] = http_get_gparam(packet_ptr, packet_length, "state"),
             "&redirect_uri=",
             pArr[4] = http_get_gparam(packet_ptr, packet_length, "redirect_uri"),
             "&response_type=",
             pArr[5] = http_get_gparam(packet_ptr, packet_length, "response_type"),
             "&client_id=",
             pArr[6] = http_get_gparam(packet_ptr, packet_length, "client_id"),
             "&prompt=",
             pArr[7] = http_get_gparam(packet_ptr, packet_length, "prompt"));

    max_arg = 8;
    session->oauth2_param.oauth2_rsp = 1;
    for(idx = 0; idx < max_arg; idx++) {
      free(pArr[idx]);
    }

  } else if(!strncmp(subtype_ptr, "auth", 4)) {
     uint8_t body[255];
     uint8_t rsp[512];
     uint32_t rsp_len = 0;

     memset((void *)body, 0, sizeof(body));
     memset((void *)rsp, 0, sizeof(rsp));
  
     status_ptr = http_get_gparam(packet_ptr, packet_length, "status");
     if(!strncmp(status_ptr, "success", 7)) {
       /*User is authenticated successfully*/
       rsp_len = snprintf(body,
                          sizeof(body),
                          "%s%s%s%s%s"
                          "%s%s%s%s%s",
                          "<html><head>",
                          "<title>",
                          "</title>",
                          "</head>",
                          "<body>",
                          "<h1>",
                          "You have successfully been Authenticated by Google",
                          "</h1>",
                          "</body>",
                          "<html>");
       snprintf(rsp,
                sizeof(rsp),
                "%s%s%s%s%s"
                "%s%d%s%s%s",
                "HTTP/1.1 302 Moved Temporarily\r\n",
                "Location: https://balaagh.com\r\n",
                "Host: balaagh.com\r\n",
                "Content-Type: text/html\r\n",
                "Connection: close\r\n",
                "Content-Length: ",
                rsp_len,
                "\r\n",
                /*Body delimiter*/
                "\r\n",
                body);

       http_send(atoi(conn_ptr), rsp, strlen(rsp));
       free(status_ptr);
       
     } else {
       
     }
  }


  return(0);
}/*http_process_google_rsp*/


int32_t http_process_aadhaar_rsp(uint8_t *packet_ptr,
                                 uint32_t packet_length) {

  uint8_t *uid_ptr = NULL;
  uint8_t *name_ptr = NULL;
  uint8_t *status_ptr = NULL;
  uint8_t *reason_ptr = NULL;
  uint8_t *conn_id_ptr = NULL;
  http_session_t *session = NULL;

  conn_id_ptr = http_get_gparam(packet_ptr, packet_length, "conn_id");
  uid_ptr = http_get_gparam(packet_ptr, packet_length, "uid");
  name_ptr = http_get_gparam(packet_ptr, packet_length, "name");
  status_ptr = http_get_gparam(packet_ptr, packet_length, "status");

  session = http_get_session(atoi(conn_id_ptr));
  assert(session != NULL);

  if(!strncmp(status_ptr, "failed", 6)) {
    reason_ptr = http_get_gparam(packet_ptr, packet_length, "reason");

    if(reason_ptr) {
      memset((void *)session->uidai_param.reason, 0, sizeof(session->uidai_param.reason));
      strncpy(session->uidai_param.reason, reason_ptr, strlen(reason_ptr));
    }
  }

  memset((void *)session->uidai_param.uid, 0, sizeof(session->uidai_param.uid));
  /*-1 to ensure the null terminated string*/
  strncpy(session->uidai_param.uid, uid_ptr, sizeof(session->uidai_param.uid) - 1);
   
  memset((void *)session->uidai_param.uid_name, 0, sizeof(session->uidai_param.uid_name));
  strncpy(session->uidai_param.uid_name, name_ptr, sizeof(session->uidai_param.uid_name) - 1);

  memset((void *)session->uidai_param.status, 0, sizeof(session->uidai_param.status));
  strncpy(session->uidai_param.status, status_ptr, strlen(status_ptr));

  /*Response has been received*/
  session->uidai_param.uidai_rsp = 1;

  return(0);
}/*http_process_aadhaar_rsp*/

int32_t http_process_nas_rsp(int32_t nas_fd, 
                             uint8_t *packet_ptr, 
                             uint32_t packet_length) {

  uint8_t *auth_type = NULL;
  uint8_t param[8][2][255];

  /*/response?type=otp&uid=9701361361&conn_id=14&status=success*/
  memset((void *)param, 0, sizeof(param));
  auth_type = http_get_gparam(packet_ptr, packet_length, "type");
  
  if(!strncmp(auth_type, "otp", 3) || 
     !strncmp(auth_type, "auth", 4)) {
    http_process_aadhaar_rsp(packet_ptr, packet_length);

  } else if(!strncmp(auth_type, "gmail", 5)) {
    free(auth_type);
    http_process_google_rsp(packet_ptr, packet_length); 

  } else if(!strncmp(auth_type, "login", 5)) {
    free(auth_type);
    http_process_login_rsp(packet_ptr, packet_length); 
  }

  fprintf(stderr, "\n%s:%d Response received from NAS is %s\n", 
                  __FILE__, 
                  __LINE__, 
                  packet_ptr);

  return(0);
}/*http_process_nas_rsp*/

int32_t http_connect_nas(void) {
  http_ctx_t *pHttpCtx = &g_http_ctx;
  int32_t fd;
  int32_t ret = -1;
  struct sockaddr_in addr;
  size_t addr_len = sizeof(addr);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket Creation Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(pHttpCtx->nas_ip);
  addr.sin_port = htons(pHttpCtx->nas_port);
  memset((void *)addr.sin_zero, 0, sizeof(addr.sin_zero));

  ret = connect(fd, (struct sockaddr *)&addr, addr_len);

  if(ret < 0) {
    fprintf(stderr, "\n%s:%d connection to nas failed\n", __FILE__, __LINE__);
    return(-2);
  }

  pHttpCtx->nas_fd = fd;

  return(0);
}/*http_connect_nas*/

int32_t http_send_to_nas(uint32_t conn_id, uint8_t *req, uint32_t req_len) {
  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *session = NULL;

  if(pHttpCtx->nas_fd < 0) {

    if(http_connect_nas() < 0) {
      fprintf(stderr, "\n%s:%d Connection to nas failed\n", __FILE__, __LINE__);
      return(-1);
    }
  }

  session = http_get_session(conn_id);
  if(session) {
    /*Response is not yet received*/
    session->uidai_param.uidai_rsp = 0;
  }

  if(http_send(pHttpCtx->nas_fd, req, req_len) < 0) {
    fprintf(stderr, "\n%s:%d Send to NAS Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  fprintf(stderr, "\n%s:%d Request %s\n", __FILE__, __LINE__,req);

  return(0);
}/*http_send_to_nas*/

void http_print_session(void) {
  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *tmp_session = pHttpCtx->session;

  while(tmp_session) {
    fprintf(stderr, "%d ", tmp_session->conn); 
    tmp_session = tmp_session->next;
  }

  fprintf(stderr, "\n");
}/*http_print_session*/


http_session_t *http_add_session(uint32_t conn_id) {
  http_ctx_t *pHttpCtx = &g_http_ctx;

  if(NULL == pHttpCtx->session) {
    /*First session to be created*/
    pHttpCtx->session = (http_session_t *)malloc(sizeof(http_session_t));

    if(NULL == pHttpCtx->session) {
      /*Allocation of Memory from Heap failed*/
      fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
      exit(0);
    }

    /*Memory allocated successfully, continue initialization*/
    memset((void *)pHttpCtx->session, 0, sizeof(http_session_t));

    pHttpCtx->session->conn = conn_id;
    /*This is the only session so to set its next to NULL*/
    pHttpCtx->session->next = NULL;
    return(pHttpCtx->session);

  } else {
    /*new session to inserted into existing session list*/
    http_session_t *new_session = pHttpCtx->session;

    /*get to the end of the list*/
    while(NULL != new_session->next) {
      new_session = new_session->next;
    }

    /*got to the end of the list*/
    new_session->next = (http_session_t *)malloc(sizeof(http_session_t));

    if(NULL == new_session->next) {
      /*Memory allocation from Heap Failed*/
      fprintf(stderr, "\n%s:%d Memory allocation from Heap failed\n", __FILE__, __LINE__);
      exit(0);
    }

    memset((void *)new_session->next, 0, sizeof(http_session_t));
    new_session = new_session->next;
    /*New session is allocated*/
    new_session->conn = conn_id;
    /*End of the session list*/
    new_session->next = NULL;
    return(new_session);
  }

  /*Immpossible case to get here*/
  return(NULL);
}/*http_add_session*/


http_session_t *http_get_session(uint32_t conn_id) {
  http_ctx_t *pHttpCtx = &g_http_ctx;
  /*Always preserve the start address of the session*/
  http_session_t *tmp_session = pHttpCtx->session;
  
  while(tmp_session) {
    if(conn_id == tmp_session->conn) {
      return(tmp_session);
    }
    /*look for next session's conn_id*/
    tmp_session = tmp_session->next;
  }
  /*Invalid session- no connection is found*/
  return(NULL);
}/*http_get_session*/


int32_t http_remove_session(uint32_t conn_id) {
  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *prev_session = NULL;
  http_session_t *curr_session = pHttpCtx->session;
  http_session_t *tobe_deleted = NULL;

  while(curr_session) {

    if(conn_id == curr_session->conn) {
      /*Got the conn_id and it is to be removed*/
      if(NULL == prev_session) {
        /*Heade Node to be deleted*/
        tobe_deleted = curr_session;
        /*Modify the Heade node*/
        pHttpCtx->session = curr_session->next;
        curr_session = pHttpCtx->session;
        free(tobe_deleted);
        continue;
 
      } else {
        /*Mid Node to be deleted*/
        tobe_deleted = curr_session;
        prev_session->next = curr_session->next;
        curr_session = curr_session->next;
        free(tobe_deleted);
        continue; 
      }
    }

    prev_session = curr_session;
    curr_session = curr_session->next;
  }
 
  return(0); 
}/*http_remove_session*/

/**
 * This will de-allocate the memory of entire allocated session
 * while signal handling.
 */
void http_free_session(http_session_t *session) {
  
  if(session) {
    http_free_session(session->next);
    free(session);
  }
  exit(0);  

}/*http_free_session*/


void http_signal_handler(int32_t signo, 
                         siginfo_t *info, 
                         void *context) {
  http_ctx_t *pHttpCtx = &g_http_ctx;

  if(SIGINT == signo) {
    /*CTRL+C has been pressed*/
    fprintf(stderr, "\n%s:%d Ctrl + C has been pressed\n",
                    __FILE__,
                    __LINE__);

    http_free_session(pHttpCtx->session); 
  }

}/*http_free_session*/


int32_t http_register_signal(uint32_t sig) {
  struct sigaction sa;

  memset((void *)&sa, 0, sizeof(struct sigaction));
  sa.sa_sigaction = http_signal_handler;
  sa.sa_flags = SA_SIGINFO;

  if(sigaction(sig, &sa, NULL)) {
    fprintf(stderr, "\n%s:%d Installing of signal Failed\n", 
                    __FILE__, 
                    __LINE__);
    return(-1);
  }

  return(0);
}/*http_register_signal*/

int32_t http_decode_reserved_delim_qs(uint8_t hex_digit, uint8_t *delim) {

  uint16_t idx;
  uint8_t delim_ascii[][2] = {/*https://tools.ietf.org/html/rfc3986#page-11 */
                               {':',  0x3A},
                               {'/',  0x2F},
                               {'?',  0x3F},
                               {'#',  0x23},
                               {'[',  0x5B},
                               {']',  0x5D},
                               {'@',  0x40},
                               {'!',  0x21},
                               {'*',  0x2A},
                               {'\'', 0x27},
                               {'$',  0x24},
                               {'(',  0x28},
                               {')',  0x29},
                               {';',  0x3B},
                               {'=',  0x3D},
                               {'+',  0x2B},
                               {',',  0x2C},
                               {'%',  0x25},
                               
                               /*New ROW to be added above this*/
                               { 0 , 0x00}
                             };

  for(idx = 0; delim_ascii[idx][1]; idx++) {
    if(hex_digit == delim_ascii[idx][1]) {
      *delim = delim_ascii[idx][0];
      break;
    }
  }

    if(!(*delim)) {
      fprintf(stderr, "\n%s:%d Invalid ASCII valus is received\n", __FILE__, __LINE__);
      return(-1);
    }
  return(0);
}/*http_decode_reserved_delim_qs*/

int32_t http_decode_perct_digit(uint8_t *dest_ptr, uint8_t *src_ptr) {

  uint16_t src_offset;
  uint16_t dest_offset;
  uint8_t hex_str[16];
  uint8_t hex_digit;

  for(src_offset = 0, dest_offset = 0; 
      src_offset < strlen((const char *)src_ptr); 
      dest_offset++, src_offset++) {

    if('%' == src_ptr[src_offset]) {
      memset((void *)hex_str, 0, sizeof(hex_str));
      snprintf((char *)hex_str, 
               sizeof(hex_str),
               "0x%c%c",
               src_ptr[src_offset + 1],
               src_ptr[src_offset + 2]);

      src_offset += 2;
      sscanf((const char *)hex_str, "0x%X", (uint32_t *)&hex_digit);
      http_decode_reserved_delim_qs(hex_digit, (uint8_t *)&dest_ptr[dest_offset]);

    } else {
      dest_ptr[dest_offset] = src_ptr[src_offset];
    }
  }

  /*NULL Terminate the string*/
  dest_ptr[dest_offset] = 0;

  return(0);
}/*http_decode_perct_digit*/

/********************************************************************
 * Function Definition starts
 ********************************************************************/
int32_t http_recv(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint32_t *packet_length) {
  int32_t  ret = -1;
  uint16_t max_length = 3000;
  do {
    ret = recv(fd, packet_ptr, max_length, 0);

  }while((ret == -1) && (EINTR == errno));

  *packet_length = (uint16_t)ret;
  return(ret);

}/*http_recv*/

int32_t http_send(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint32_t packet_length) {
  int32_t  ret = -1;
  uint16_t offset = 0;

  do {
    ret = send(fd, (void *)&packet_ptr[offset], (packet_length - offset), 0);
  
    if(ret < 0) {
      return(ret);
    }
    
    offset += ret;
    if(!(packet_length - offset)) {
      ret = 0;
    }

  }while(ret);

  return(offset);
}/*http_send*/

int32_t http_is_connection_closed(uint32_t conn_id) {

  uint16_t idx;
  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *session = http_get_session(conn_id);
  assert(session != NULL);

  if(!strncmp(session->method, "HTTP/1.0", 8)) {
    for(idx = 0; idx < session->mime_header_count; idx++) {
      if((!strncmp(session->mime_header[idx][0], "Connection", 10)) &&
         (!strncmp(session->mime_header[idx][1], "close", 5))) {
        return(1);
      }  
    }
  }

  return(0);
}/*http_is_connection_closed*/

int32_t http_parse_req(uint32_t conn_id,
                        uint8_t *packet_ptr,
                        uint16_t packet_length) {

  uint8_t *line_ptr;
  uint8_t *tmp_ptr = NULL;
  uint16_t idx = 0;
  uint8_t method[8];
  uint8_t *uri_ptr;
  uint16_t uri_len;
  uint8_t protocol[8];
  uint16_t tmp_len;
  uint16_t line_len;
  uint8_t url[1024];
  char *save_ptr;

  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *session = http_get_session(conn_id);
  assert(session != NULL);

  tmp_ptr = (uint8_t *)malloc(packet_length);
  assert(tmp_ptr != NULL);

  memset((void *)tmp_ptr, 0, packet_length);
  memcpy(tmp_ptr, packet_ptr, packet_length);

  line_ptr = strtok_r(tmp_ptr, "\r\n", &save_ptr);

  sscanf((const char *)line_ptr, 
         "%s %*s %s", 
         method, 
         protocol);

  uri_len = strlen((const char *)line_ptr) - 
            (strlen((const char *)method) + 
             strlen((const char *)protocol));

  uri_ptr = (uint8_t *) malloc(uri_len);

  if(!uri_ptr) {
    fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
    free(tmp_ptr);
    return(-1);
  }

  memset((void *)uri_ptr, 0, uri_len);
  sscanf((const char *)line_ptr, 
         "%*s %s %*s", 
         uri_ptr);

  memset((void *)session->method, 0, sizeof(session->method));
  memset((void *)session->protocol, 0, sizeof(session->protocol));
  memset((void *)session->uri, 0, sizeof(session->uri));

  strncpy(session->method, method, sizeof(session->method));
  strncpy(session->protocol, protocol, sizeof(session->protocol));
  strncpy(session->uri, uri_ptr, sizeof(session->uri));

  free(uri_ptr);
  uri_ptr = NULL;

  /*copying URL into session*/
  if(!strncmp((const char *)session->uri, "/login.html", 11)) { 
    memset((void *)url, 0, sizeof(url));
    memset((void *)session->url, 0, sizeof(session->url));
    sscanf((const char *)session->uri,
           "%*[^?]?url=%s HTTP/1.1",
           url);
    strncpy(session->url, url, strlen((const char *)url));
  }

  memset((void *)session->mime_header, 
         0, 
         sizeof(session->mime_header));
  session->mime_header_count = 0;

  while((line_ptr = strtok_r(NULL, "\r\n", &save_ptr))) { 

    sscanf((const char *)line_ptr, 
           "%[^:]:%*s",
           session->mime_header[idx][0]);

    tmp_len = strlen((const char *)session->mime_header[idx][0]);
    line_len = strlen((const char *)line_ptr);

    if(line_len > tmp_len) {
      memcpy((void *)&session->mime_header[idx][1], 
             (const void *)&line_ptr[tmp_len + 2], 
             (line_len - (tmp_len + 2)));
      idx++;
    }
  }

  session->mime_header_count = idx;

  free(tmp_ptr);
  tmp_ptr = NULL;

  return(0);  
}/*http_parse_req*/

int32_t http_process_image_req(uint32_t conn_id,
                               uint8_t **response_ptr, 
                               uint32_t *response_len_ptr) {
  uint32_t fd;
  struct stat statbuff;
  uint8_t http_header[255];
  uint8_t file_name[255];
  uint16_t tmp_len;
  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *session = http_get_session(conn_id);

  memset((void *)file_name, 0, sizeof(file_name));
 
  snprintf((char *)file_name, sizeof(file_name),
           "..%s",
           session->uri);
  
  fd = open(file_name, O_RDONLY);

  if(fd > 0) {
    fstat(fd, &statbuff);
    tmp_len = snprintf((char *)http_header,
                       sizeof(http_header), 
                       "%s%s%s%d%s"
                       "%s%s",
                       "HTTP/1.1 200 OK\r\n",
                       "Content-Type: image/gif; image/png;image/ico\r\n",
                       "Content-Length: ",
                       (int32_t)statbuff.st_size,
                       "\r\n",
                       "Connection: Keep-alive\r\n",
                       "\r\n");

    (*response_ptr) = (uint8_t *)malloc(statbuff.st_size + tmp_len);

    if(!(*response_ptr)) {
      fprintf(stderr, "\n%s:%d memory Allocation Failed\n", __FILE__, __LINE__);
      return(-1);
    }

    memset((void *)(*response_ptr), 0, (statbuff.st_size + tmp_len));
    memcpy((void *)(*response_ptr), (const void *)http_header, tmp_len);

    *response_len_ptr = read(fd, (void *)&(*response_ptr)[tmp_len], statbuff.st_size);
    *response_len_ptr += tmp_len;

    close(fd);
  }
  return(0);
 
}/*http_process_image_req*/

int32_t http_process_favicon_req(uint32_t conn_id,
                                 uint8_t **response_ptr, 
                                 uint32_t *response_len_ptr) {
  uint32_t fd;
  struct stat statbuff;
  uint8_t http_header[255];
  uint8_t file_name[255];
  uint16_t tmp_len;
  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *session = http_get_session(conn_id);

  memset((void *)file_name, 0, sizeof(file_name));
 
  snprintf((char *)file_name, sizeof(file_name),
           "../img%s",
           session->uri);
  
  fd = open(file_name, O_RDONLY);

  if(fd > 0) {
    fstat(fd, &statbuff);
    tmp_len = snprintf((char *)http_header,
                       sizeof(http_header), 
                       "%s%s%s%d%s"
                       "%s%s",
                       "HTTP/1.1 200 OK\r\n",
                       "Content-Type: image/gif; image/png;image/ico\r\n",
                       "Content-Length: ",
                       (int32_t)statbuff.st_size,
                       "\r\n",
                       "Connection: Keep-alive\r\n",
                       "\r\n");

    (*response_ptr) = (uint8_t *)malloc(statbuff.st_size + tmp_len);

    if(!(*response_ptr)) {
      fprintf(stderr, "\n%s:%d memory Allocation Failed\n", __FILE__, __LINE__);
      return(-1);
    }

    memset((void *)(*response_ptr), 0, (statbuff.st_size + tmp_len));
    memcpy((void *)(*response_ptr), (const void *)http_header, tmp_len);

    *response_len_ptr = read(fd, (void *)&(*response_ptr)[tmp_len], statbuff.st_size);
    *response_len_ptr += tmp_len;

    close(fd);
  }
  return(0);
 
}/*http_process_favicon_req*/


int32_t http_process_wait_req(uint32_t conn_id,
                              uint8_t **response_ptr, 
                              uint32_t *response_len_ptr,
                              uint8_t *refresh_uri) {
  uint8_t html_body[1024];
  uint16_t html_body_len;
  int32_t ret = -1;

  memset((void *)html_body, 0, sizeof(html_body));

  html_body_len = snprintf((char *)html_body, 
                           sizeof(html_body),
                           "%s%s%s%s%s"
                           "%s%s%s%s",
                           "<html><head><title></title>",
                           "<meta http-equiv=\"refresh\" content=\"1;URL='",
                           refresh_uri,
                           "'\">",
                           "</head>",
                           "<body><center><table align = center style =\"position:relative; margin-top:10%\">",
                           "<tr><td align=center>",
                           "<img src=../img/wait.gif>",
                           "</td></tr></table></center></body></html>"); 

  (*response_ptr) = (uint8_t *)malloc(html_body_len + 255);

  if(!(*response_ptr)) {
    fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)(*response_ptr), 0, (255 + html_body_len));

  ret = snprintf((char *)(*response_ptr),
                 (255 + html_body_len),
                 "%s%s%s%s%d"
                 "%s",
                 "HTTP/1.1 200 OK\r\n",
                 "Content-Type: text/html\r\n",
                 "Connection: Keep-alive\r\n",
                 "Content-Length: ",
                 html_body_len,
                 "\r\n\r\n");

  memcpy((void *)&(*response_ptr)[ret], (const void *)html_body, html_body_len);
  *response_len_ptr = ret + html_body_len; 

  return(0);
}/*http_process_wait_req*/


int32_t http_process_auth_failed_req(uint32_t conn_id,
                                     uint8_t **response_ptr,
                                     uint32_t *response_len_ptr) {
  uint8_t html_body[255];
  uint16_t html_body_len;
  int32_t ret = -1;

  memset((void *)html_body, 0, sizeof(html_body));

  html_body_len = snprintf((char *)html_body, 
                           sizeof(html_body),
                           "%s%s%s%s%s"
                           "%s%s%s%s",
                           "<html><head><title></title>",
                           "<meta http-equiv=\"refresh\" content=\"2;URL='",
                           "ui.html",
                           "'\"",
                           "</head>",
                           "<body><center><table align = center style =\"position:relative; margin-top:10%\">",
                           "<tr><td align=center>",
                           "<h2>Authentication Failed",
                           "</td></tr></table></center></body></html>"); 

  (*response_ptr) = (uint8_t *)malloc(html_body_len + 255);

  if(!(*response_ptr)) {
    fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)(*response_ptr), 0, (255 + html_body_len));

  ret = snprintf((char *)(*response_ptr),
                 (255 + html_body_len),
                 "%s%s%s%s%d"
                 "%s",
                 "HTTP/1.1 200 OK\r\n",
                 "Content-Type: text/html\r\n",
                 "Connection: Keep-alive\r\n",
                 "Content-Length: ",
                 html_body_len,
                 "\r\n\r\n");
  memcpy((void *)&(*response_ptr)[ret], (const void *)html_body, html_body_len);

  *response_len_ptr = ret + html_body_len; 

  return(0);
}/*http_process_auth_failed_req*/

int32_t http_process_login_req(uint32_t conn_id,
                               uint8_t **response_ptr, 
                               uint32_t *response_len_ptr) {
  uint8_t *refresh_uri = "/ui.html";

  http_process_wait_req(conn_id,
                        response_ptr,
                        response_len_ptr,
                        refresh_uri);
  return(0);
}/*http_process_login_req*/

int32_t http_build_aadhaar_auth_otp_req(uint32_t conn_id, uint8_t *req, uint32_t *req_len) {

  uint8_t param[4][2][64];
  uint8_t *otp_value_ptr = NULL;
  uint8_t ip_str[32];
  http_session_t *session = NULL;
  session = http_get_session(conn_id);
  assert(session != NULL);
  
  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(session->peer_addr.sin_addr.s_addr, ip_str);

  memset((void *)param, 0, sizeof(param));
  http_parse_param(param, session->uri);

  otp_value_ptr = http_get_param(param, "otp_value");
  /*GET /response_callback?auth_type=aadhaar&subtype=auth&subsubtype=otp&aadhaar_no=9701361361&otp_value=XXXX&rc=y&ver=2.0&conn_id=14 HTTP/1.1*/
  sprintf(req,
          "%s%s%s%s%s"
          "%s%d%s%s%s"
          "%s%s",
          "GET /response_callback?auth_type=aadhaar&subtype=auth&subsubtype=otp&aadhaar_no=",
          session->uidai_param.uid,
          "&otp_value=",
           otp_value_ptr,
          "&rc=y&ver=2.0&",
          "conn_id=",
          conn_id,
          "&ip=",
          ip_str,
          " HTTP/1.1\r\n",
          "Connection: Keep-alive\r\n",
          "Content-Length: 0\r\n");

  *req_len = strlen(req);
  return(0); 
}/*http_build_aadhaar_auth_otp_req*/

int32_t http_process_aadhaar_otp_req(uint32_t conn_id,
                                     uint8_t **response_ptr,
                                     uint32_t *response_len_ptr) {
  uint8_t req[512];
  uint32_t req_len;
  uint8_t *refresh_uri = "/aadhaar_otp.html";

  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *session = NULL;

  /*update that otp auth response has not yet received*/
  session = http_get_session(conn_id);
  assert(session != NULL);

  if(!session->uidai_param.uidai_rsp) {
    /*Making Browser to wait for response*/
    http_process_wait_req(conn_id,
                          response_ptr,
                          response_len_ptr,
                          refresh_uri);
  } else {
   /*Prompt for OTP value*/
   http_build_otp_in_form(conn_id, response_ptr, response_len_ptr);
  }
#if 0
  memset((void *)req, 0, sizeof(req));
  req_len = 0;
  http_parse_aadhaar_otp_req(conn_id, req, &req_len);
  /*send to NAS*/
  http_send_to_nas(conn_id, req, req_len);
#endif
  
 return(0);
}/*http_process_aadhaar_otp_req*/

int32_t http_urldecode(uint8_t *in, uint8_t *out) {

  while(*in != '\0') {
    if(*in == '+') {
      *out++ = ' ';
      in++;
      continue;
    }
    *out++ = *in++;
  }
  /*copy the null character*/
  *out = *in;

  return(0);
}/*http_urldecode*/

int32_t http_parse_aadhaar_uid_req(uint32_t conn_id, 
                                  uint8_t *req_ptr, 
                                  uint32_t *req_len_ptr) {

  uint8_t *aadhaar_no_ptr;
  uint8_t *rc_ptr;
  uint8_t *name_ptr;
  uint8_t *otp_ptr;
  uint32_t ret;
  /*Resident Consent*/
  uint8_t rc[4];
  uint8_t ip_str[32];
  uint8_t name_str[80];
  http_session_t *session = NULL;
  http_ctx_t *pHttpCtx = &g_http_ctx;
  uint8_t response_qs[512];
  
  /*Send Request to Auth Client to Authneticate the USER*/
  memset((void *)response_qs, 0, sizeof(response_qs));

  session = http_get_session(conn_id);
  assert(session != NULL);

  rc_ptr = http_get_gparam(session->uri, strlen(session->uri), "rc");
  name_ptr = http_get_gparam(session->uri, strlen(session->uri), "name");
  aadhaar_no_ptr = http_get_gparam(session->uri, strlen(session->uri), "uid");
  otp_ptr = http_get_gparam(session->uri, strlen(session->uri), "otp");

  if(!rc_ptr || !name_ptr || !aadhaar_no_ptr || !otp_ptr) {
    fprintf(stderr, "\n%s:%d Parameter is NULL\n", __FILE__, __LINE__);  
    return(1);
  }

  //http_urldecode(name_ptr, name_str);

  memset((void *)rc, 0, sizeof(rc));
  /*Copy the rc value*/
  if(!strncmp(rc_ptr, "on", 2)) {
    strncpy(rc, "y", 1);
  } else {
    strncpy(rc, "n", 1);
  }

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(session->peer_addr.sin_addr.s_addr, ip_str);

  ret = snprintf(response_qs, 
                 sizeof(response_qs),
                 "%s%s%s%s%s"
                 "%s%s%d%s%s"
                 "%s%s%s",
                 "GET /response_callback?auth_type=aadhaar&subtype=otp&aadhaar_no=",
                 aadhaar_no_ptr,
                 "&rc=",
                 rc,
                 "&name=",
                 name_ptr,
                 "&ver=1.6&conn_id=",
                 conn_id,
                 "&ip=",
                 ip_str,
                 " HTTP/1.1\r\n",
                 "Connection: keep-alive\r\n",
                 "Content-Length:0\r\n");

  memcpy((void *)req_ptr, response_qs, ret);
  *req_len_ptr = ret;

  /*makesure that response is not yet received*/
  session->uidai_param.uidai_rsp = 0;
  fprintf(stderr, "\n%s:%d nas request %s\n", __FILE__, __LINE__, response_qs);

  free(rc_ptr);
  free(name_ptr);
  free(aadhaar_no_ptr);
  free(otp_ptr);

  return(0);
}/*http_parse_aadhaar_uid_req*/

int32_t http_build_otp_in_form(uint32_t conn_id,
                               uint8_t **response_ptr,
                               uint32_t *response_len_ptr) {
  uint8_t html[1024];
  uint32_t html_body_len;
  int32_t ret = -1;
  uint8_t name_str[128];
  http_session_t *session = NULL;

  session = http_get_session(conn_id);
  assert(session != NULL);

  http_urldecode(session->uidai_param.uid_name, name_str);

  memset((void *)html, 0, sizeof(html));

  html_body_len = snprintf((char *)html, 
                           sizeof(html),
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s",
                           "<html><head><title></title>",
                           /*For Responsive Web Page*/
                           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
                           "<style>",
                           ".box2 {",
                           "position:absolute;",
                           "top: 50%;left: 64%;height:14em;margin-top:-9em;margin-left:-15em;",
                           "border:none;background-color: white;}",
                           "</style></head>",
                           "<body><div class=\"box2\">",
                           "<form method=GET action=/aadhaar_auth_pi.html>",
                           "<fieldset><legend>OTP</legend>",
                           "<table><tr><td><input type=text name=otp_value placeholder=\"Enter received OTP\"></td>",
                           "</tr><tr><td><input type=submit value=\"Submit OTP\"></td></tr>",
                           "<tr><td><input type=button value=\"Resent OTP\">",
                           "</td></tr>",
                           "<tr><td><input type=hidden name=uid value=",
                           session->uidai_param.uid,
                           "></td></tr>",
                           "<tr><td><input type=hidden name=r_name value=\"",
                           name_str,
                           "\"></td></tr>",
                           "<tr><td><input type=hidden name=ms value=\"E\"></td></tr>",
                           "</table></form></fieldset>",
                           "</body></html>");

  //fprintf(stderr, "\n%s:%d HTML FORM %s\n", __FILE__, __LINE__, html);
  (*response_ptr) = (uint8_t *)malloc(html_body_len + 255/*For Http Header*/);

  if(!(*response_ptr)) {
    fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)(*response_ptr), 0, (255 + html_body_len));

  ret = snprintf((char *)(*response_ptr),
                 (255 + html_body_len),
                 "%s%s%s%s%d"
                 "%s",
                 "HTTP/1.1 200 OK\r\n",
                 "Content-Type: text/html\r\n",
                 "Connection: Keep-alive\r\n",
                 "Content-Length: ",
                 html_body_len,
                 "\r\n\r\n");
  memcpy((void *)&(*response_ptr)[ret], (const void *)html, html_body_len);

  *response_len_ptr = ret + html_body_len; 

  return(0);
}/*http_build_otp_in_form*/

int32_t http_process_aadhaar_uid_req(uint32_t conn_id,
                                     uint8_t **response_ptr,
                                     uint32_t *response_len_ptr) {
  uint8_t req[512];
  uint32_t req_len;
  uint8_t *refresh_uri = "/aadhaar_otp.html";

  memset((void *)req, 0, sizeof(req));
  req_len = 0;
  http_parse_aadhaar_uid_req(conn_id, req, &req_len);
  /*send to NAS*/
  http_send_to_nas(conn_id, req, req_len);

  /*Making Browser to wait for response*/
  http_process_wait_req(conn_id,
                        response_ptr,
                        response_len_ptr,
                        refresh_uri);
  return(0);
}/*http_process_aadhaar_uid_req*/

int32_t http_process_aadhaar_ui_req(uint32_t conn_id,
                                    uint8_t **response_ptr,
                                    uint32_t *response_len_ptr) {
  uint8_t html[1024];
  uint32_t html_body_len;
  int32_t ret = -1;

  memset((void *)html, 0, sizeof(html));

  html_body_len = snprintf((char *)html, 
                           sizeof(html),
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s",
                           "<html><head><title></title>",
                           /*For Responsive Web Page*/
                           "<style> .box1 {",
                           "position:absolute;",
                           "top: 40%;left: 60%;height:14em;margin-top: 2%;",
                           "margin-left: 10%;border: none;background-color: #ffffff;}",
                           "</style></head>",
                           "<body><div id=aadhaar_pi class=\"box1\">",
                           "<fieldset><legend>Aadhaar Pi + OTP</legend>",
                           "<form method=GET action=/aadhaar_uid.html>",
                           "<table><tr>",
                           "<td><input type=text name=uid placeholder=\"Provide 12 digits the aadhaar number\"></td>",
                           "</tr>",
                           "<tr><td><input type=text name=name placeholder=\"Provide the Name\"></td>",
                           "</tr><tr>",
                           "<td><input type=checkbox name=otp checked=yes style=\"vertical-align:middle;width:30px\">OTP",
                           "<input type=checkbox name=rc checked=yes style=\"vertical-align:middle;width:30px\">I Agree</td>",
                           "</tr><tr>",
                           "<td><input type=submit name=sign_in value=\"Generate OTP to sign in\" style=\"height:30px\"></td>",
                           "</tr></table></form></fieldset></div></body></html>");

  (*response_ptr) = (uint8_t *)malloc(html_body_len + 255/*For Http Header*/);

  if(!(*response_ptr)) {
    fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)(*response_ptr), 0, (255 + html_body_len));

  ret = snprintf((char *)(*response_ptr),
                 (255 + html_body_len),
                 "%s%s%s%s%d"
                 "%s",
                 "HTTP/1.1 200 OK\r\n",
                 "Content-Type: text/html\r\n",
                 "Connection: Keep-alive\r\n",
                 "Content-Length: ",
                 html_body_len,
                 "\r\n\r\n");
  memcpy((void *)&(*response_ptr)[ret], (const void *)html, html_body_len);

  *response_len_ptr = ret + html_body_len; 

  return(0);
}/*http_process_aadhaar_ui_req*/

int32_t http_process_ui_req(uint32_t conn_id,
                            uint8_t **response_ptr, 
                            uint32_t *response_len_ptr) {

  uint8_t html_body[1<<15];
  uint16_t html_body_len;
  int32_t ret = -1;

  memset((void *)html_body, 0, sizeof(html_body));

  html_body_len = snprintf((char *)html_body,
                           sizeof(html_body),
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s",
                           "<html>"
                           "<head>"
                           "<title>"
                           "</title>"
                           "<style>",
                           ".box2 { position:absolute; top: 10%; left: 40%; height:14em; margin-top: 3em;", 
                           "margin-left: 5em;", 
                           "border: none;",
                           "background-color: white;",
                           "border-left-style: solid;}",
                           ".box1 {",
                           "position:absolute;top: 10%;left: 30%;height:14em;margin-top: 3em;",
                           "margin-left:1em ;border: none;background-color: #ffffff;}",
                           "</style></head><body>",
                           "<div id=form_in class=\"box1\">",
                           "<form method=GET action=/sign_in.html>",
                           "<table height=100px><tr>",
                           "<td style=\"width:120px\"><input type=text name=id placeholder=\"Provide the user ID\"></td>",
                           "</tr><tr>",
                           "<td style=\"width:120px\"><input type=password name=password placeholder=\"Provide the password\"></td>",
                           "</tr><tr>",
                           "<td><input type=submit name=sign_in value=SignIn style=\"height:30px; width:90px\">",
                           "<input type=button name=register value=Register style=\"height:30px; width:90px\"></td>",
                           "</tr></table></form></div>",
                           "<div class=\"box2\">",
                           "<table><tr>",
                           "<td cellpadding=\"2px\"><a href=/aadhaar_ui.html><img src=../img/aadhaar-logo_en-GB.jpg></a></td>",
                           "</tr><tr>",
                           "<td cellpadding=\"2px\"><a href=/twitter_ui.html><img src=../img/sign-in-with-twitter-gray.png></a></td>",
                           "</tr><tr>",
                           "<td cellpadding=2px><a href=/fb_ui.html><img src=../img/fb_logo.png height=28px width=200px></a></td>",
                           "</tr><tr>",
                           "<td cellpadding=2px><a href=/google_ui.html><img src=../img/1x/btn_google_signin_light_focus_web.png></a></td>",
                           "</tr></table>",
                           "</div></body></html>");

  (*response_ptr) = (uint8_t *)malloc(html_body_len + 255/*For Http Header*/);

  if(!(*response_ptr)) {
    fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)(*response_ptr), 0, (255 + html_body_len));

  ret = snprintf((char *)(*response_ptr),
                 (255 + html_body_len),
                 "%s%s%s%s%d"
                 "%s",
                 "HTTP/1.1 200 OK\r\n",
                 "Content-Type: text/html\r\n",
                 "Connection: Keep-alive\r\n",
                 "Content-Length: ",
                 html_body_len,
                 "\r\n\r\n");
  memcpy((void *)&(*response_ptr)[ret], (const void *)html_body, html_body_len);

  *response_len_ptr = ret + html_body_len; 

  return(0);
}/*http_process_ui_req*/

int32_t http_process_register_req(uint32_t conn_id,
                                  uint8_t **response_ptr, 
                                  uint32_t *response_len_ptr) {

  return(0);
}/*http_process_register_req*/

int32_t http_process_sign_in_req(uint32_t conn_id,
                                 uint8_t **response_ptr, 
                                 uint32_t *response_len_ptr) {
  int32_t ret = -1;
  uint8_t *response_qs;
  uint32_t response_qs_size = 512;
  uint8_t user_id[255];
  uint8_t password[255];
  uint8_t ip_str[32];
  http_session_t *session = NULL;

  session = http_get_session(conn_id);
  uint8_t *email_ptr = NULL;
  uint8_t *pwd_ptr = NULL;
  /** 
   * Replace %XX with equivalent character, 
   * where XX is the ASCII value in hex.
   */
  email_ptr = http_get_gparam(session->uri, strlen(session->uri), "email_id");
  http_decode_perct_digit(user_id, email_ptr);
  free(email_ptr);
  pwd_ptr = http_get_gparam(session->uri, strlen(session->uri), "password");

  /*sending subscriber credentials to NAS for Authentication*/
  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(session->peer_addr.sin_addr.s_addr, ip_str);

  response_qs = (uint8_t *)malloc(sizeof(uint8_t) * response_qs_size);
  assert(response_qs != NULL);
  memset((void *)response_qs, 0, response_qs_size * sizeof(uint8_t));

  snprintf(response_qs, 
           response_qs_size,
           "%s%s%s%s%s"
           "%s%s%s%d%s"
           "%s%s",
           "GET ",
           "/response_callback?auth_type=login&email_id=",
           user_id,
           "&password=",
           pwd_ptr,
           "&ip=",
           ip_str,
           "&conn_id=",
           conn_id,
           " HTTP/1.1\r\n",
           "Connection: Keep-alive\r\n",
           "Content-Length: 0\r\n");

  free(pwd_ptr);
  http_send_to_nas(conn_id, response_qs, strlen(response_qs));
  /*Make web-browser to wait*/
  *response_len_ptr = 0;

  free(response_qs);
  return(0);
}/*http_process_sign_in_req*/


int32_t http_process_redirect_req(uint32_t conn_id,
                                  uint8_t **response_ptr,
                                  uint32_t *response_len_ptr,
                                  uint8_t *location_uri) {

  (*response_ptr) = (uint8_t *) malloc(2048);

  if(!(*response_ptr)) {
    fprintf(stderr, "\n%s:%d memory Allocation Failed\n", __FILE__, __LINE__);
    return(-4);
  }

  memset((void *)(*response_ptr), 0, 2048);

  *response_len_ptr = sprintf((char *)(*response_ptr), 
                            "%s%s%s%s%s"
                            "%s%s%s%s%s"
                            "%s",
                            "HTTP/1.1 302 Moved Temporarily\r\n",
                            "Connection: Keep-alive\r\n",
                            /*"Connection: close\r\n",*/
                            "Location: ",
                            location_uri,
                            "\r\n",
                            "Content-Type: text/html\r\n",
                            "Accept-Language: en-US,en;q=0.5\r\n",
                            "Accept: text/*;q=0.3, text/html;q=0.7, text/html;level=1,",
                            "text/html;level=2;q=0.4, */*;q=0.5\r\n",
                            "Content-Length: 0",
                            /*Delimiter B/W Header and Body*/
                            "\r\n\r\n");


  return(0);
}/*http_process_redirect_req*/

int32_t http_process_login_with_mobile_no_req(uint32_t conn_id,
                                              uint8_t **response_ptr, 
                                              uint32_t *response_len_ptr) {

  return(0);

}/*http_process_login_with_mobile_no_req*/

int32_t http_process_uri(uint32_t conn_id,
                         uint8_t **response_ptr,
                         uint32_t *response_len_ptr) {

  uint16_t idx;
  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *session = http_get_session(conn_id);
  for(idx = 0; pHttpCtx->pHandler[idx].uri; idx++) {

    if(!strncmp(session->uri, 
                pHttpCtx->pHandler[idx].uri, 
                pHttpCtx->pHandler[idx].uri_len)) {

      pHttpCtx->pHandler[idx].http_req_cb(conn_id, 
                                          response_ptr, 
                                          response_len_ptr);
      break;
    }
  }

 return(0);
}/*http_process_uri*/
                          
int32_t http_process_req(uint32_t conn_id, 
                         uint8_t *packet_ptr, 
                         uint32_t packet_length) {

  /*Build temporary HTTP Response*/
  uint8_t *http_ptr = NULL;
  uint32_t http_len = 0;
  int32_t ret = -1;

  fprintf(stderr, "\n%s:%d (conn_id %d) %s", 
                  __FILE__,
                  __LINE__,
                  conn_id,
                  packet_ptr);

  ret = http_parse_req(conn_id, packet_ptr, packet_length);

  if(ret) {
    fprintf(stderr, "\n%s:%d Connection is being closed\n", __FILE__, __LINE__);
    return(ret);
  }

  /*This function loop through the static uri table*/
  http_process_uri(conn_id, &http_ptr, &http_len);

  if(http_len > 0) {
    if(http_send(conn_id, http_ptr, http_len) < 0) {
      perror("http send Failed:");
      return(-1); 
    }

    free(http_ptr);
    http_ptr = NULL;
    //return(http_is_connection_closed(conn_id));
  }

  return(0);
}/*http_process_req*/

int32_t http_init(uint32_t uam_ip, 
                  uint16_t uam_port,
                  uint32_t nas_ip,
                  uint16_t nas_port) {

  int32_t fd = -1;
  struct sockaddr_in http_addr;
  size_t http_addr_len;
  http_ctx_t *pHttpCtx = &g_http_ctx;

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d creation of socket failed\n", __FILE__, __LINE__);
    return(-1);
  }

  http_addr_len = sizeof(struct sockaddr_in);
  http_addr.sin_addr.s_addr = htonl(uam_ip);
  http_addr.sin_port = htons(uam_port);
  http_addr.sin_family = AF_INET;
  memset((void *)http_addr.sin_zero, 0, sizeof(http_addr.sin_zero));

  if(bind(fd, (struct sockaddr *)&http_addr, http_addr_len) < 0) {
    fprintf(stderr, "\n%s:%d bind to given address failed\n", __FILE__, __LINE__);
    perror("Bind Failed: ");
    return(-1);
  }
  
  /*Max Pending connection which is 128 as of now*/
  if(listen(fd, 128) < 0) {
    fprintf(stderr, "\n%s:%d listen to given ip failed\n", __FILE__, __LINE__);
    return(-2);
  }
  
   /*Closing fd on exit*/
   utility_coe(fd);

  pHttpCtx->uam_ip = uam_ip;
  pHttpCtx->uam_port = uam_port;
  pHttpCtx->uam_fd = fd;

  pHttpCtx->session = NULL;

  /*Initializing array of objects*/
  pHttpCtx->pHandler = g_handler_http;

  /*Connect with radiusC - Radius Client*/
  pHttpCtx->nas_ip = nas_ip;
  pHttpCtx->nas_port = nas_port;
  pHttpCtx->nas_fd = -1;

  return(0); 
}/*http_init*/

int32_t http_set_fd(http_session_t *session, fd_set *rd) {

  while(session) {
    FD_SET(session->conn, rd);
    session = session->next;
  }

  return(0);
}/*http_set_fd*/

uint32_t http_get_max_fd(http_session_t *session) {
  uint32_t max_fd = 0;

  while(session) {
    max_fd = (max_fd > session->conn)? max_fd: session->conn;
    session = session->next;
  }

  return(max_fd);
}/*http_get_max_fd*/

/* @brief This function is the entry point of thread for Redirect
 *
 * @param1 pointer to void received while spawning the thread.
 *
 * @return pointer to void
 */
void *http_main(void *argv) {

  http_ctx_t *pHttpCtx = &g_http_ctx;
  int32_t ret;
  int32_t new_conn;
  struct timeval to;
  struct sockaddr_in peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);
  uint8_t packet_buffer[3000];
  uint32_t packet_length;
  fd_set rd;
  uint16_t max_fd;
  http_session_t *session = NULL;

  /*Installing signal handler for clean up of memory*/ 
  http_register_signal(SIGINT);
 
  for(;;) {
    to.tv_sec = 2;
    to.tv_usec = 0;
    
    FD_ZERO(&rd);
    FD_SET(pHttpCtx->uam_fd, &rd);

    /*Remove session with conn_id == 0*/
    http_remove_session((uint32_t)0);
    http_set_fd(pHttpCtx->session, &rd);

    max_fd = http_get_max_fd(pHttpCtx->session);
    max_fd = (max_fd > pHttpCtx->uam_fd) ? 
              max_fd : 
              pHttpCtx->uam_fd;
 
    if(pHttpCtx->nas_fd > 0) { 
      FD_SET(pHttpCtx->nas_fd, &rd);
      max_fd = (max_fd > pHttpCtx->nas_fd) ? 
                max_fd : 
                pHttpCtx->nas_fd;
    }

    max_fd += 1;
    ret = select(max_fd, &rd, NULL, NULL, &to);
    
    if(ret > 0) {
      if(FD_ISSET(pHttpCtx->uam_fd, &rd)) {
        /*New Connection accept it.*/
        new_conn = accept(pHttpCtx->uam_fd, 
                          (struct sockaddr *)&peer_addr, 
                          (socklen_t *)&peer_addr_len);

        if(peer_addr.sin_addr.s_addr) {
          session = http_add_session(new_conn);
          session->peer_addr = peer_addr;
          fprintf(stderr, "\n%s:%d New connection ip_addr %s port %d\n",
                          __FILE__,
                          __LINE__,
                          inet_ntoa(peer_addr.sin_addr),
                          ntohs(peer_addr.sin_port));

        } else {
          /* Connection is from 0.0.0.0 IP Address,
           * accept system call expects non-zero in addr_len, 
           * if addr_len is zero or not initialized then accept
           * system call will fill ip as 0.0.0.0 and port as 0
           * upon receipt of first connection.
           */
          fprintf(stderr, "\n%s:%d closing the connection ip_addr %s port %d\n",
                          __FILE__,
                          __LINE__,
                          inet_ntoa(peer_addr.sin_addr),
                          ntohs(peer_addr.sin_port));
          close(new_conn);
        }

      } else if((pHttpCtx->nas_fd > 0) && (FD_ISSET(pHttpCtx->nas_fd, &rd))) {
        /*Process nas reply*/
        /*Either connection is closed or data has been received.*/
        memset((void *)packet_buffer, 0, sizeof(packet_buffer));
        packet_length = 0;
        http_recv(pHttpCtx->nas_fd, packet_buffer, &packet_length);

        if(!packet_length) {
          /*Closing the connected conn_id*/
          close(pHttpCtx->nas_fd);
          pHttpCtx->nas_fd = -1;
        } else {
          /*Process the NAS reply*/
          http_process_nas_rsp(pHttpCtx->nas_fd, packet_buffer, packet_length);
          fprintf(stderr, "\n%s:%d Got the Reply from NAS %s\n", __FILE__, __LINE__, packet_buffer);
        }
      } else {
        for(session = pHttpCtx->session; session; session = session->next) {

          if(FD_ISSET(session->conn, &rd)) {
            /*Either connection is closed or data has been received.*/
            memset((void *)packet_buffer, 0, sizeof(packet_buffer));
            packet_length = 0;
            http_recv(session->conn, packet_buffer, &packet_length);

            if(!packet_length) {
              /*Closing the connected conn_id*/
              close(session->conn);
              session->conn = 0;

            } else {

              if(1 == http_process_req(session->conn, 
                                       packet_buffer, 
                                       packet_length)) {
                /*Closing the connected conn_id*/
                close(session->conn);
                session->conn = 0;
              }
            }
          }  
        }
      }
    } else if(!ret) {
      //fprintf(stderr, "\n%s:%d Got the timeout\n", __FILE__, __LINE__);
    }
  }
  
}/*http_main*/

#endif /* __HTTP_C__ */
