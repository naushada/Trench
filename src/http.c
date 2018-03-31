#ifndef __HTTP_C__
#define __HTTP_C__

#include <sys/stat.h>
#include <signal.h>
#include <type.h>
#include <common.h>
#include <utility.h>
#include <http.h>

/********************************************************************
 *  Global Instance Declaration
 ********************************************************************/
http_ctx_t g_http_ctx;

http_req_handler_t g_handler_http[] = {

  {"/img",                        4, http_process_image_req},
  {"/login.html",                11, http_process_login_req},
  {"/ui.html",                    8, http_process_ui_req},
  {"/sign_in.html",              13, http_process_sign_in_req},
  {"/register.html",             14, http_process_register_req},
  {"/login_with_mobile_no.html", 26, http_process_login_with_mobile_no_req},
  {"/index.html",                11, http_process_login_req},

  /*New callback to be inserted above this*/
  {"/",                           1, http_process_login_req},
  {NULL,                          0, NULL}

};


/********************************************************************
 *Function Definition
 ********************************************************************/
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
  
  while(NULL != tmp_session) {
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
        fprintf(stderr, "\n%s:%d Head node (conn_id %d)\n", 
                        __FILE__,
                        __LINE__,
                       conn_id);
        continue;
 
      } else {
        /*Mid Node to be deleted*/
        tobe_deleted = curr_session;
        prev_session->next = curr_session->next;
        curr_session = curr_session->next;
        fprintf(stderr, "\n%s:%d Mid node (conn_id %d\n", 
                        __FILE__,
                        __LINE__,
                       conn_id);
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
                   uint16_t *packet_length) {
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
                   uint16_t packet_length) {
  int32_t  ret = -1;
  uint16_t offset = 0;

  do {
    ret = send(fd, (void *)&packet_ptr[offset], (packet_length - offset), 0);
    
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

  for(idx = 0; idx < session->mime_header_count; idx++) {
    if((!strncmp(session->mime_header[idx][0], "Connection", 10)) &&
       (!strncmp(session->mime_header[idx][1], "close", 5))) {
      return(1);
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

  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *session = http_get_session(conn_id);

  tmp_ptr = (uint8_t *)malloc(packet_length);

  if(!tmp_ptr) {
    fprintf(stderr, "\n%s:%d Allocation of Memory failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)tmp_ptr, 0, packet_length);
  memcpy(tmp_ptr, packet_ptr, packet_length);

  line_ptr = strtok(tmp_ptr, "\r\n");

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

  strncpy(session->method, method, strlen((const char *)method));
  strncpy(session->protocol, protocol, strlen((const char *)protocol));
  strncpy(session->uri, uri_ptr, strlen((const char *)uri_ptr));

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

  while((line_ptr = strtok(NULL, "\r\n"))) { 

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

  session->mime_header_count = idx - 1;

  free(tmp_ptr);
  tmp_ptr = NULL;

  if(http_is_connection_closed(conn_id)) {
    fprintf(stderr, "\n%s:%d (Connection: close) HTTP Connection is closed\n", 
                     __FILE__, 
                     __LINE__);
    return(1);
  }
 
  return(0);  
}/*http_parse_req*/

int32_t http_process_image_req(uint32_t conn_id,
                               uint8_t **response_ptr, 
                               uint16_t *response_len_ptr) {
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
                       "Connection: Keep-Alive\r\n",
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


int32_t http_process_wait_req(uint32_t conn_id,
                              uint8_t **response_ptr, 
                              uint16_t *response_len_ptr,
                              uint8_t *refresh_uri) {
  uint8_t html_body[255];
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
                 "Connection: Keep-Alive\r\n",
                 "Content-Length: ",
                 html_body_len,
                 "\r\n\r\n");

  memcpy((void *)&(*response_ptr)[ret], (const void *)html_body, html_body_len);

  *response_len_ptr = ret + html_body_len; 

  return(0);

}/*http_process_wait_req*/


int32_t http_process_auth_failed_req(uint32_t conn_id,
                                     uint8_t **response_ptr,
                                     uint16_t *response_len_ptr) {
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
                 "Connection: Keep-Alive\r\n",
                 "Content-Length: ",
                 html_body_len,
                 "\r\n\r\n");
  memcpy((void *)&(*response_ptr)[ret], (const void *)html_body, html_body_len);

  *response_len_ptr = ret + html_body_len; 

  return(0);
}/*http_process_auth_failed_req*/

int32_t http_process_login_req(uint32_t conn_id,
                               uint8_t **response_ptr, 
                               uint16_t *response_len_ptr) {
  uint8_t *refresh_uri = "/ui.html";

  http_process_wait_req(conn_id,
                        response_ptr,
                        response_len_ptr,
                        refresh_uri);
  return(0);
}/*http_process_login_req*/

int32_t http_process_ui_req(uint32_t conn_id,
                            uint8_t **response_ptr, 
                            uint16_t *response_len_ptr) {

  uint8_t html_body[1<<15];
  uint16_t html_body_len;
  int32_t ret = -1;

  memset((void *)html_body, 0, sizeof(html_body));

  html_body_len = snprintf((char *)html_body, 
                           sizeof(html_body),
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s%s%s"
                           "%s%s%s",
                           "<html><head><title></title>",
                           /*For Responsive Web Page*/
                           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
                           "</head>",
                           "<body><center><table>",
                           "<tr><form method=GET action=/sign_in.html>",
                           "<td><input type=email name=email_id placeholder=\"E-mail id\"></td>",
                           "</tr><tr><td><input type=password name=password placeholder=\"Password\"></td>",
                           "</tr><tr><td><input type=submit value=\"Sign in\">",
                           "<input type=submit value=\"Register\"></td></tr></form>",
                           "<tr><td><input type=button name=or value=\"OR\" disabled></td>",
                           "</tr><tr><form method GET action=/login_with_mobile_no.html>",
                           "<td><input type=text name=mobile_no placeholder=\"10 digits Mobile Number\"></td>",
                           "</tr><tr><td><input type=submit value=\"Sign in\"></td></tr></form>",
                           /*Image Logog starts*/
                           "<tr><td><img src=../img/1x/btn_google_signin_dark_normal_web.png></td></tr>",
                           "<tr><td><img src=../img/sign-in-with-twitter-gray.png></td></tr>",
                           /*Logo Dimension is gouverned by face book*/
                           "<tr><td><img src=../img/fb_logo.png height=28px width=200px></td></tr>",
                           "<tr><td><img src=../img/aadhaar-logo_en-GB.png></tr></td>",
                           "</table></center></body></html>"); 

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
                 "Connection: Keep-Alive\r\n",
                 "Content-Length: ",
                 html_body_len,
                 "\r\n\r\n");
  memcpy((void *)&(*response_ptr)[ret], (const void *)html_body, html_body_len);

  *response_len_ptr = ret + html_body_len; 

  return(0);
}/*http_process_ui_req*/

int32_t http_process_register_req(uint32_t conn_id,
                                  uint8_t **response_ptr, 
                                  uint16_t *response_len_ptr) {

  return(0);
}/*http_process_register_req*/

int32_t http_process_sign_in_req(uint32_t conn_id,
                                 uint8_t **response_ptr, 
                                 uint16_t *response_len_ptr) {
  uint8_t param_name[255];
  uint8_t param_value[255];
  uint8_t qs[1024];
  int32_t ret = -1;
  uint8_t *line_ptr = NULL;
  uint8_t response_qs[2024];
  uint8_t user_id[255];
  uint8_t password[255];
  uint8_t ip_str[32];
  http_session_t *session = NULL;
  http_ctx_t *pHttpCtx = &g_http_ctx;

  
  /*Send Request to Auth Client to Authneticate the USER*/
  memset((void *)response_qs, 0, sizeof(response_qs));
  memset((void *)qs, 0, sizeof(qs));

  session = http_get_session(conn_id);

  ret = sscanf((const char *)session->uri,
               "%*[^?]?%s",
               qs);
 
  line_ptr = strtok(qs, "&");

  do {
    memset((void *)param_name, 0, sizeof(param_name));
    memset((void *)param_value, 0, sizeof(param_value));

    ret = sscanf((const char *)line_ptr,
                "%[^=]=%s",
                 param_name,
                 param_value);

    if(!strncmp((const char *)param_name, "email_id", 8)) {

      /** 
       * Replace %XX with equivalent character, 
       * where XX is the ASCII value in hex.
       */
      http_decode_perct_digit(user_id, param_value);

    } else if(!strncmp((const char *)param_name, "password", 8)) {

      /*Copy the Password Value*/
      memcpy((void *)password, 
             (const void *)param_value, 
             strlen((const char *)param_value));

    }
  }while(NULL != (line_ptr = strtok(NULL, "&"))); 

  /*sending subscriber credentials to NAS for Authentication*/
  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(htonl(pHttpCtx->nas_ip), ip_str);

  snprintf(response_qs, 
           sizeof(response_qs),
           "%s%s%s%d%s"
           "%s%s%s%s%s",
           "http://",
           ip_str,
           ":",
           pHttpCtx->nas_port,
           "/response_callback?auth_type=login&email_id=",
           user_id,
           "&password=",
           password,
           "&url=",
           session->url);

  http_process_redirect_req(conn_id,
                            response_ptr,
                            response_len_ptr,
                            response_qs);
  #if 0
  http_process_wait_req(conn_id, 
                        response_ptr, 
                        response_len_ptr,
                        response_qs);
  #endif

  return(0);
}/*http_process_sign_in_req*/


int32_t http_process_redirect_req(uint32_t conn_id,
                                  uint8_t **response_ptr,
                                  uint16_t *response_len_ptr,
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
                            "Connection: Keep-Alive\r\n",
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
                                              uint16_t *response_len_ptr) {

  return(0);

}/*http_process_login_with_mobile_no_req*/

int32_t http_process_uri(uint32_t conn_id,
                         uint8_t **response_ptr,
                         uint16_t *response_len_ptr) {

  uint16_t idx;
  http_ctx_t *pHttpCtx = &g_http_ctx;
  http_session_t *session = http_get_session(conn_id);
#if 0
  fprintf(stderr, "\n%s:%d conn_id %d uri %s\n",
                  __FILE__,
                  __LINE__,
                  conn_id,
                  session->uri);
#endif
  for(idx = 0; pHttpCtx->pHandler[idx].uri; idx++) {
#if 0
    fprintf(stderr, "\n%s:%d conn_id %d uri %s\n",
                  __FILE__,
                  __LINE__,
                  conn_id,
                  session->uri);
#endif
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
                         uint16_t packet_length) {

  /*Build temporary HTTP Response*/
  uint8_t *http_ptr = NULL;
  uint16_t http_len = 0;
  int32_t ret = -1;

  ret = http_parse_req(conn_id, packet_ptr, packet_length);

  if(ret) {
    fprintf(stderr, "\n%s:%d Connection is being closed\n", __FILE__, __LINE__);
    return(ret);
  }

  /*This function loop through the static uri table*/
  http_process_uri(conn_id, &http_ptr, &http_len);

  if(http_send(conn_id, http_ptr, http_len) < 0) {
    perror("http send Failed:");
    return(-1); 
  }

  free(http_ptr);
  http_ptr = NULL;

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
  
  /*Max Pending connection which is 10 as of now*/
  if(listen(fd, 5) < 0) {
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
  size_t peer_addr_len;
  uint8_t packet_buffer[3000];
  uint16_t packet_length;
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
    max_fd = (max_fd > pHttpCtx->uam_fd) ? max_fd : pHttpCtx->uam_fd;
   
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

        } else {
          /*Connection is from 0.0.0.0 IP Address*/
          close(new_conn);
        }

      } else {
        for(session = pHttpCtx->session; session; session = session->next) {

          if(FD_ISSET(session->conn, &rd)) {
            /*Either connection is closed or data has been received.*/
            memset((void *)packet_buffer, 0, sizeof(packet_buffer));
            packet_length = 0;
            http_recv(session->conn, packet_buffer, &packet_length);
            fprintf(stderr, "\n%s:%d Got Request (%d) %s\n",
                            __FILE__,
                            __LINE__,
                            session->conn,
                            packet_buffer);

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
