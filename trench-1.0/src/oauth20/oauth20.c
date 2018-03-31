#ifndef __OAUTH20_C__
#define __OAUTH20_C__

#include <type.h>
#include <uidai/common.h>
#include <uidai/util.h>
#include "sslc.h"
#include "oauth20.h"

oauth20_ctx_t oauth20_ctx_g;

int32_t oauth20_process_google_api_rsp(uint32_t oauth2_fd, 
                                       uint8_t *rsp_ptr, 
                                       uint32_t rsp_len, 
                                       uint32_t nas_fd) {
  uint8_t *tmp_ptr = NULL;
  uint8_t *token_ptr = NULL;
  uint8_t *req_ptr = NULL;
  uint32_t req_ptr_size = 512;
  uint32_t req_len = 0;
  uint8_t email[64];
  uint8_t email_type[32];
  uint8_t display_name[255];
  uint32_t uam_conn_id;
  uint32_t redir_conn_id;
  sslc_session_t *session = NULL;

  tmp_ptr = (uint8_t *)malloc(sizeof(uint8_t) * rsp_len);
  assert(tmp_ptr != NULL);
  memset((void *)tmp_ptr, 0, sizeof(uint8_t) * rsp_len);
  memcpy((void *)tmp_ptr, rsp_ptr, sizeof(uint8_t) * rsp_len);
  
  for(token_ptr = strtok(tmp_ptr, "\n"); token_ptr; token_ptr = strtok(NULL, "\n")) {
    if(!strncmp(&token_ptr[4], "value", 5)) {
      /*extract the e-mail*/
      memset((void *)email, 0, sizeof(email));
      sscanf(token_ptr, "%*[^:]:%*[^\"]\"%[^\"]\"", email);
      fprintf(stderr, "\n%s:%d email %s\n", __FILE__, __LINE__, email);

    } else if(!strncmp(&token_ptr[4], "type", 4)) {
      /*email type*/ 
      memset((void *)email_type, 0, sizeof(email_type));
      sscanf(token_ptr, "%*[^:]:%*[^\"]\"%[^\"]\"", email_type);
      fprintf(stderr, "\n%s:%d email type %s\n", __FILE__, __LINE__, email_type);
       
    } else if(!strncmp(&token_ptr[2], "displayName", 11)) {
      /*display name*/
      memset((void *)display_name, 0, sizeof(display_name));
      sscanf(token_ptr, "%*[^:]:%*[^\"]\"%[^\"]\"", display_name);
      fprintf(stderr, "\n%s:%d display Name %s\n", __FILE__, __LINE__, display_name);
    }
  }

  session = sslc_get_session(oauth2_fd);
  if(!session) {
    fprintf(stderr, "\n%s:%d getting session failed\n", __FILE__, __LINE__);
    return(1);
  }
   
  uam_conn_id = session->uam_conn_id;
  redir_conn_id = session->redir_conn_id;

  req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * req_ptr_size);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, sizeof(uint8_t) * req_ptr_size);

  req_len = snprintf(req_ptr,
                     req_ptr_size,
                     "%s%s%s%s%s"
                     "%s%d%s%d%s"
                     "%s%s%s",
                     "/response?type=gmail",
                     "&subtype=auth",
                     "&status=success",
                     "&email=",
                     email,
                     "&ext_conn_id=",
                     uam_conn_id,
                     "&conn_id=",
                     redir_conn_id,
                     "&ip=",
                     session->ip,
                     "&name=",
                     display_name);
 
  oauth20_send(nas_fd, req_ptr, req_len);
  free(req_ptr);
  free(tmp_ptr);
  sslc_close(session->tcp_fd);
  sslc_del_session(oauth2_fd);
  
  return(0);
}/*oauth20_process_google_api_rsp*/

int32_t oauth20_process_access_token_rsp(uint32_t oauth2_fd, uint8_t *rsp_ptr, uint32_t rsp_len) {

  uint8_t *tmp_ptr = NULL;
  uint8_t *token_ptr = NULL;
  uint8_t *access_token = NULL;
  uint8_t token_type[32];
  uint8_t expires[16];
  uint8_t *api_req_ptr = NULL;
  uint32_t api_req_size = 1024;
  uint32_t req_len = 0;

  tmp_ptr = (uint8_t *) malloc(sizeof(uint8_t) * rsp_len);

  if(!tmp_ptr) {
    fprintf(stderr, "\n%s:%d Memory allocation failed\n", __FILE__, __LINE__);  
    return(1);
  }

  memset((void *)tmp_ptr, 0, rsp_len);
  memcpy((void *)tmp_ptr, rsp_ptr, rsp_len);

  for(token_ptr = strtok(tmp_ptr, "\n"); token_ptr; token_ptr = strtok(NULL, "\n")) {

    //fprintf(stderr, "\n%s:%d \ntoken_ptr %s len %d\n", __FILE__, __LINE__, token_ptr, strlen(token_ptr));
    /*Note: there are two white spaces at begining of every row*/ 
    if(!strncmp(&token_ptr[2], "access_token", 12)) {
      /*"access_token": "ya29.GluEBXGRImWQKe_hdKRHKwCV-rkeUztGk6Fw6vlyr5hkX-7scv8IC0Tafwk9t9UFs0Bb8H9P1OKc8rPaXAdvenIkctsJlT7zR_MqB2fcQ6Euj1Ei9gp1GoN5FSBQ",*/
      access_token = (uint8_t *) malloc(sizeof(uint8_t) * 512);
      assert(access_token != NULL);
      memset((void *)access_token, 0, 512);
      sscanf(token_ptr, "%*[^:]:%*[^\"]\"%[^\"]\"", access_token);
      
      fprintf(stderr, "\n%s:%d access_token %s\n", __FILE__, __LINE__, access_token);
    } else if(!strncmp(&token_ptr[2], "token_type", 10)) {
      /*"token_type": "Bearer",*/
       memset((void *)token_type, 0, sizeof(token_type));
       sscanf(token_ptr, "%*[^:]:%*[^\"]\"%[^\"]\"", token_type);
      fprintf(stderr, "\n%s:%d token_type %s\n", __FILE__, __LINE__, token_type);

    } else if(!strncmp(&token_ptr[2], "expires_in", 10)) {
      /*"expires_in": 3599,*/
       memset((void *)expires, 0, sizeof(expires));
       sscanf(token_ptr, "%*[^:]:%[^,],", expires);
      fprintf(stderr, "\n%s:%d  expires %s\n", __FILE__, __LINE__, expires);
    }
  }

  /*Prepare oauth20 request to get user's email address*/
  /*GET /people/v1/people/me HTTP/1.1
   Authorization: Bearer <access_token>
   Host: www.googleapis.com */
   api_req_ptr = (uint8_t *) malloc(sizeof(uint8_t) * api_req_size);
   assert(api_req_ptr != NULL);
   memset((void *)api_req_ptr, 0, sizeof(uint8_t) * api_req_size);

   req_len = snprintf(api_req_ptr,
                      api_req_size,
                      "%s%s%s%s%s"
                      "%s%s",
                      "GET https://www.googleapis.com/plus/v1/people/me?",
                      "access_token=",
                      access_token,
                      " HTTP/1.1\r\n",
                      "Host: www.googleapis.com\r\n" ,
                      "Connection: Keep-Alive\r\n",
                      "Content-Length: 0\r\n\n");

  fprintf(stderr, "\n%s:%d google api request %s\n", __FILE__, __LINE__, api_req_ptr);
  sslc_set_rsp_st(oauth2_fd, (uint32_t)CALLING_GOOGLE_API_ST); 
  sslc_write(oauth2_fd, api_req_ptr, req_len);
  free(access_token);
  free(api_req_ptr);
  return(0);  
}/*oauth20_process_access_token_rsp*/


int32_t oauth20_process_rsp(uint32_t oauth2_fd, 
                            uint8_t *rsp_ptr, 
                            uint32_t rsp_len, 
                            uint32_t nas_fd) {
  uint32_t rsp_st;
  
  rsp_st = sslc_get_rsp_st(oauth2_fd);

  if(!rsp_st) {
    fprintf(stderr, "\n%s:%d incorrect rsp state\n", __FILE__, __LINE__);
    return(1);
  }
 
  if(ACCESS_TOKEN_ST == rsp_st) {
    oauth20_process_access_token_rsp(oauth2_fd, rsp_ptr, rsp_len);

  } else if(CALLING_GOOGLE_API_ST == rsp_st) {
    /*Process the received user credential response*/
    fprintf(stderr, "\n%s:%d google api response\n%s\n", __FILE__, __LINE__, rsp_ptr);
    oauth20_process_google_api_rsp(oauth2_fd, rsp_ptr, rsp_len, nas_fd);

  } else {
    fprintf(stderr, "\n%s:%d invalid state\n", __FILE__, __LINE__);
  }


  return(0);
}/*oauth20_process_rsp*/

int32_t oauth20_compute_state(uint8_t *b64, 
                              uint32_t *b64_len) {
  int32_t fd;
  uint8_t st[32];
  int32_t ret = -1;

  memset((void *)st, 0, sizeof(st));
  fd = open("/dev/urandom", O_RDONLY);
  if(fd < 0) {
    fprintf(stderr, "\n%s:%d opening of device file failed\n", __FILE__, __LINE__);
    return(1);
  }

  ret = read(fd, st, sizeof(st));
  if(ret <= 0) {
    fprintf(stderr, "\n%s:%d reading of device file failed\n", __FILE__, __LINE__);
    return(2);
  }  

  close(fd);
  util_base64(st, (uint16_t)ret, b64, (uint16_t *)b64_len);
   
  return(0);
}/*oauth20_compute_state*/

int32_t oauth20_urlencode_qs(uint8_t *qs_ptr, uint8_t *urlencode_qs) {

  uint32_t offset;
  uint32_t idx;

  for(offset = 0, idx = 0; qs_ptr[idx]; idx++) {
    if('/' == qs_ptr[idx]) {
      urlencode_qs[offset++] = '%';
      urlencode_qs[offset++] = '2';
      urlencode_qs[offset++] = 'F';
      
    } else if(':' == qs_ptr[idx]) {
      urlencode_qs[offset++] = '%';
      urlencode_qs[offset++] = '3';
      urlencode_qs[offset++] = 'A';

    } else {
      urlencode_qs[offset++] = qs_ptr[idx];
    }
  }

  return(0);
}/*oauth20_urlencode_qs*/

int32_t oauth20_build_access_token_req(uint8_t *req_ptr, 
                                       uint8_t *rsp_ptr, 
                                       uint32_t rsp_size, 
                                       uint32_t *rsp_len) {

  uint8_t *redirect_ptr = "http://adam.balaagh.com:3990/google_access_token.html";
  //uint8_t *redirect_ptr = "";
  /*value of scope would be - email, profile and openid, 
    more than one value shall be space seperated
   */
  uint8_t *code_ptr = NULL;
  /*reference : https://developers.google.com/identity/protocols/OAuth2WebServer*/
  /*"https://www.googleapis.com/oauth2/v4/token";*/
  uint8_t *qs_ptr = NULL;
  uint32_t qs_size = 1024;

  code_ptr = oauth20_get_param(req_ptr, "code");

  qs_ptr = (uint8_t *) malloc(sizeof(uint8_t) * qs_size);
  assert(qs_ptr != NULL);
  memset((void *)qs_ptr, 0, sizeof(uint8_t) * qs_size); 

  snprintf(qs_ptr, 
           qs_size,    
           "%s%s%s%s%s"
           "%s%s%s%s%s",
           "code=",
           code_ptr,
           "&client_id=",
           CLIENT_ID,
           "&client_secret=",
           CLIENT_S,
           "&redirect_uri=",
           redirect_ptr,
           "&scope=email",
           "&grant_type=authorization_code");
  
  fprintf(stderr, "\n%s:%d urlencode %s\n", __FILE__, __LINE__, qs_ptr); 
  /*POST /oauth2/v4/token HTTP/1.1
    Host: www.googleapis.com
    Content-Type: application/x-www-form-urlencoded

    code=4/P7q7W91a-oMsCeLvIaQm6bTrgtp7&
    client_id=your_client_id&
    client_secret=your_client_secret&
    redirect_uri=https://oauth2.example.com/code&
    grant_type=authorization_code*/

  *rsp_len = snprintf(rsp_ptr,
                      rsp_size,
                      "%s%s%s%s%s"
                      "%s%d%s%s%s",
                      "POST /oauth2/v4/token",
                      " HTTP/1.1\r\n",
                      "Host: www.googleapis.com\r\n",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      "Connection: Keep-Alive\r\n",
                      "Content-Length: ",
                      (uint32_t)strlen(qs_ptr),
                      "\r\n",
                      /*Query string for POST*/
                      "\n",
                      qs_ptr);
  free(qs_ptr);
  free(code_ptr);
  fprintf(stderr, "\n%s:%d TOKEN REQUEST %s\n", __FILE__, __LINE__, rsp_ptr);

  return(0);
}/*oauth20_build_access_token_req*/

int32_t oauth20_build_access_code_rsp(uint8_t *req_ptr, 
                                      uint8_t *rsp_ptr,
                                      uint32_t rsp_size, 
                                      uint32_t *rsp_len) {
  uint8_t b64[64];
  uint32_t b64_len = 0;
  uint8_t *redirect_ptr = "http://adam.balaagh.com:3990/google_access_token.html";
  /*value of scope would be - email, profile and openid, 
    more than one value shall be space seperated
   */
  uint8_t *scope_ptr = "email";
  uint8_t *response_type_ptr = "code";
  /*reference : https://developers.google.com/identity/protocols/OAuth2WebServer*/
  uint8_t *url_ptr = "https://accounts.google.com/o/oauth2/v2/auth";
  uint8_t *acc_type_ptr = "online";
  /*Optional. A space-delimited, case-sensitive list of prompts to present the user. 
    If you don't specify this parameter, the user will be prompted only the first time your app requests access. 
    Possible values are: 
    none, consent, select_account
   */
  uint8_t *prompt_ptr = "consent";
  uint8_t *conn_ptr = NULL;
  uint8_t *ext_conn_ptr = NULL;
  uint8_t *ip_ptr = NULL;

  conn_ptr = oauth20_get_param(req_ptr, "conn_id");
  ext_conn_ptr = oauth20_get_param(req_ptr, "ext_conn_id");
  ip_ptr = oauth20_get_param(req_ptr, "ip");
  
  if(!conn_ptr || !ext_conn_ptr || !ip_ptr) {
    fprintf(stderr, "\n%s:%d conn_id or ext_conn_id is meiising\n", __FILE__, __LINE__);
    return(1);
  }
  
  memset((void *)b64, 0, sizeof(b64));
  oauth20_compute_state(b64, &b64_len);
  /*https://accounts.google.com/o/oauth2/v2/auth?
    scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.metadata.readonly&
    access_type=offline&
    include_granted_scopes=true&
    state=state_parameter_passthrough_value&
    redirect_uri=http%3A%2F%2Foauth2.example.com%2Fcallback&
    response_type=code&
    client_id=client_id
  */

  *rsp_len = snprintf(rsp_ptr,
                      rsp_size,
                      "%s%s%s%s%s"
                      "%s%s%s%s%s"
                      "%s%s%s%s%s"
                      "%s%s%s%s%s"
                      "%s%s",
                      "/response?type=auth&subtype=redirect&uri=",
                      url_ptr,
                      "&scope=",
                      scope_ptr,
                      "&access_type=",
                      acc_type_ptr,
                      "&state=",
                      /*state is b64 encoded*/
                      b64,
                      "&redirect_uri=",
                      redirect_ptr,
                      "&prompt=",
                      prompt_ptr,
                      "&response_type=",
                      response_type_ptr,
                      "&client_id=",
                      CLIENT_ID,
                      "&ext_conn_id=",
                      ext_conn_ptr,
                      "&conn_id=",
                      conn_ptr,
                      "&ip=",
                      ip_ptr);
  fprintf(stderr, "\n%s:%d RESPONSE %s\n", __FILE__, __LINE__, rsp_ptr);
  free(conn_ptr);
  free(ext_conn_ptr);
  free(ip_ptr);
  return(0);
}/*oauth20_build_access_code_rsp*/

uint8_t *oauth20_get_param(uint8_t *packet_ptr, uint8_t *p_name) {

  uint8_t *param_value = NULL;
  uint32_t param_max_size = 512; 
  uint8_t *tmp_ptr = NULL;
  uint8_t *line_ptr = NULL;
  uint8_t param_name[32];
  uint8_t is_found = 0; 

  param_value = (uint8_t *)malloc(param_max_size);
  assert(param_value != NULL);
  tmp_ptr = (uint8_t *)malloc(strlen(packet_ptr));
  assert(tmp_ptr != NULL);
  memset((void *)tmp_ptr, 0, strlen(packet_ptr));
  sscanf(packet_ptr, "%*[^?]?%s", tmp_ptr);  

  line_ptr = strtok(tmp_ptr, "&");
  while(line_ptr) {
    memset((void *)param_name, 0, sizeof(param_name));
    memset((void *)param_value, 0, param_max_size);
    sscanf(line_ptr, "%[^=]=%s", param_name, param_value);

    if(!strncmp(param_name, p_name, strlen(p_name))) {
      is_found = 1; 
      break;  
    }    

    line_ptr = strtok(NULL, "&");
  }

  if(is_found) {
    free(tmp_ptr);
    return(param_value);
  }

  free(tmp_ptr);
  free(param_value);
  return(NULL);
}/*oauth20_get_param*/

int32_t oauth20_process_nas_req(int32_t conn_id, 
                                uint8_t *req_ptr, 
                                uint32_t req_len) {

  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_len = 0;
  uint32_t rsp_size = 1024;
  uint8_t *type_ptr = NULL;

  /*/request?type=auth&ext_conn_id=<>&conn_id=*/
  type_ptr = oauth20_get_param(req_ptr, "type");

  if(!type_ptr) {
    fprintf(stderr, "\n%s:%d type not found\n", __FILE__, __LINE__);
    return(1);
  }
  fprintf(stderr, "\n%s:%d type %s\n", __FILE__, __LINE__, type_ptr);

  if(!strncmp(type_ptr, "google_access_code", 18)) {
    /*Prepare the response for nas*/
    rsp_ptr = (uint8_t *) malloc(sizeof(uint8_t) * rsp_size);
    assert(rsp_ptr != NULL);
    memset((void *)rsp_ptr, 0, (sizeof(uint8_t) * rsp_size)); 
    oauth20_build_access_code_rsp(req_ptr, rsp_ptr, rsp_size, &rsp_len);

    /*Send response to NAS*/
    if(rsp_len) {
      oauth20_send(conn_id, rsp_ptr, rsp_len);
    }

  } else if(!strncmp(type_ptr, "google_access_token", 19)) {
    /*Prepare the response for nas*/
    rsp_ptr = (uint8_t *) malloc(sizeof(uint8_t) * rsp_size);
    assert(rsp_ptr != NULL);
    memset((void *)rsp_ptr, 0, (sizeof(uint8_t) * rsp_size)); 
    oauth20_build_access_token_req(req_ptr, rsp_ptr, rsp_size, &rsp_len);
    /*Send Request to google*/
    uint32_t google_fd = 0;

    if(sslc_connect("googleapis.com", 443, &google_fd, req_ptr)) {
      fprintf(stderr, "\n%s:%d Connection to googleapis failed\n", __FILE__, __LINE__);
      return(1);
    }

    sslc_write(google_fd, rsp_ptr, rsp_len);
  }

  free(type_ptr);
  free(rsp_ptr);

  return(0);
}/*oauth20_process_nas_req*/

int32_t oauth20_recv(int32_t fd, 
                     uint8_t *req_ptr, 
                     uint32_t req_ptr_size, 
                     uint32_t *req_ptr_len) {
  int32_t ret = -1;

  ret = recv(fd, req_ptr, req_ptr_size, 0);

  if(ret > 0) {
    *req_ptr_len = (uint32_t)ret;
  } else {
    *req_ptr_len = 0;
  }

  return(ret);
}/*oauth20_recv*/

int32_t oauth20_send(int32_t fd, 
                     uint8_t *rsp_ptr, 
                     uint32_t rsp_ptr_len) {
  uint32_t offset = 0;
  int32_t ret = -1;

  do {
    ret = send(fd, (rsp_ptr + offset), (rsp_ptr_len - offset), 0);

    if(ret > 0) {
      offset += ret;
    }
   
  }while((ret - offset));

  return(0);
}/*oauth20_send*/

int32_t oauth20_init(uint8_t *host_name,
                     uint32_t nas_ip,
                     uint16_t nas_port) {

  oauth20_ctx_t *pOauth20Ctx = &oauth20_ctx_g;
  const SSL_METHOD *method;
  int32_t fd;
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

  memset((void *)pOauth20Ctx->host_name, 0, sizeof(pOauth20Ctx->host_name));
  strncpy(pOauth20Ctx->host_name, host_name, strlen(host_name));

  memset((void *)pOauth20Ctx->state, 0, sizeof(pOauth20Ctx->state));
  memset((void *)pOauth20Ctx->scope, 0, sizeof(pOauth20Ctx->scope));
  memset((void *)pOauth20Ctx->redirect_uri, 0, sizeof(pOauth20Ctx->redirect_uri));

  pOauth20Ctx->nas_ip = nas_ip;
  pOauth20Ctx->nas_port = nas_port;

  /*Creating fd for nas request*/  
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation failed\n", __FILE__, __LINE__);
    return(1);
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(nas_ip);
  addr.sin_port = htons(nas_port);
  memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

  if(bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
    fprintf(stderr, "\n%s:%d Bind to given socket failed\n", __FILE__, __LINE__);
    return(2);
  }

  /*making socket to listen*/
  listen(fd, 5);
  pOauth20Ctx->nas_fd = fd;

  return(0);
}/*oauth20_init*/

void *oauth20_main(void *tid) {

  int32_t max_fd = 0;
  fd_set rd;
  struct timeval to;
  int32_t ret = 0;
  int32_t new_fd = -1;
  uint32_t oauth2_fd[255];
  uint32_t oauth2_fd_count = 0;
  uint32_t idx;
  oauth20_ctx_t *pOauth20Ctx = &oauth20_ctx_g;
  /*Initialize the SSL Client context*/
  sslc_init();

  FD_ZERO(&rd);

  for(;;) {
    to.tv_sec = 2;
    to.tv_usec = 0;
    FD_SET(pOauth20Ctx->nas_fd, &rd);
    max_fd = max_fd > pOauth20Ctx->nas_fd ? max_fd : pOauth20Ctx->nas_fd;
    
    if(sslc_get_session_count() > 0) {
      memset((void *)oauth2_fd, 0, sizeof(oauth2_fd));
      sslc_get_session_list(oauth2_fd, &oauth2_fd_count);
      fprintf(stderr, "\n%s:%d session count %d\n", __FILE__, __LINE__, oauth2_fd_count);
      for(idx = 0; idx < oauth2_fd_count; idx++) {
        FD_SET(oauth2_fd[idx], &rd);
        max_fd = max_fd > oauth2_fd[idx] ? max_fd : oauth2_fd[idx];
      }
    }

    if(new_fd > 0) {
      FD_SET(new_fd, &rd);
      max_fd = max_fd > new_fd ? max_fd : new_fd;
    }

    max_fd = max_fd + 1;
    ret = select(max_fd, &rd, NULL, NULL, &to);

    if(ret < 0) {
      //fprintf(stderr, "\n%s:%d error in select\n", __FILE__, __LINE__);
      continue;
    }

    if(FD_ISSET(pOauth20Ctx->nas_fd, &rd)) {
      /*new connection from nas*/
      struct sockaddr_in addr;
      socklen_t addr_len = sizeof(addr);
      new_fd = accept(pOauth20Ctx->nas_fd, (struct sockaddr *)&addr, &addr_len);
    }

    if(oauth2_fd_count > 0) {
      /*Process response from google oauth20 server*/
      for(idx = 0; idx < oauth2_fd_count; idx++) {
        if(FD_ISSET(oauth2_fd[idx], &rd)) {
          /*Response received from oauth20 server*/
          int32_t ret_status = -1;
          uint32_t rsp_len = 2048;
          uint32_t offset = 0;
          uint8_t *rsp_ptr = (uint8_t *) malloc(sizeof(uint8_t) * rsp_len);
          memset((void *)rsp_ptr, 0, sizeof(uint8_t) * rsp_len);

          do {
            sslc_read(oauth2_fd[idx], rsp_ptr + offset, &rsp_len);
            ret_status = sslc_pre_process_rsp(rsp_ptr, rsp_len + offset);
            offset += rsp_len;
            rsp_len = 2048;
          }while(ret_status);

          /*last chunked will be of length 0 followed by\r\n*/
          sslc_read(oauth2_fd[idx], rsp_ptr + offset, &rsp_len);
          offset += rsp_len;

          if(!offset) {
            fprintf(stderr, "\n%s:%d SSL has been closed\n", __FILE__, __LINE__);
            sslc_close(oauth2_fd[idx]);
            sslc_del_session(oauth2_fd[idx]);
          } else {
            /*Process the response*/
            fprintf(stderr, "\n%s:%d Response received from oauth2 server\n%s\n", __FILE__, __LINE__, rsp_ptr);
            oauth20_process_rsp(oauth2_fd[idx], rsp_ptr, offset, new_fd/*nas fd*/);
            free(rsp_ptr);
          }
        }
      } 
    }

    if((new_fd > 0) && (FD_ISSET(new_fd, &rd))) {
      /*Process Request from nas*/
      uint8_t req_buffer[512];
      uint32_t req_len = 0;
      memset((void *)req_buffer, 0, sizeof(req_buffer));
      oauth20_recv(new_fd, req_buffer, sizeof(req_buffer), &req_len);

      if(!req_len) {
        /*connection is closed*/
        close(new_fd);
        new_fd = -1;
      } else {
        oauth20_process_nas_req(new_fd, req_buffer, req_len);
      }
    }
  }

  return(0);
}/*oauth20_main*/


#endif /* __OAUTH20_C__ */
