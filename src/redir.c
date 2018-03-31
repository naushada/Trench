#ifndef __REDIR_C__
#define __REDIR_C__

#include <sys/stat.h>
#include <type.h>
#include <common.h>
#include <db.h>
#include <utility.h>
#include <radiusC.h>
#include <redir.h>

/********************************************************************
 *  Global Instance Declaration
 ********************************************************************/
redir_ctx_t redir_ctx_g;

/********************************************************************
 * Function Definition starts
 ********************************************************************/

redir_req_handler_t g_handler_redir[] = {
  {"/img",                 4, redir_process_image_req},
  {"/response_callback",  18, redir_process_response_callback_req},
  {"/time_out",            9, redir_process_time_out_req},
  {"/auth_rejected.html", 19, redir_process_rejected_req},
  {"/",                    1, redir_process_redirect_req},
  /*This shall be the last row in this table*/
  {NULL,                   0, NULL}
};


int32_t redir_process_rejected_req(uint32_t conn_id,
                                   uint8_t **response_ptr,
                                   uint16_t *response_len_ptr) {
  uint8_t html_body[255];
  uint16_t html_body_len;
  int32_t ret = -1;
  uint8_t ip_str[32];
  redir_ctx_t *pRedirCtx = &redir_ctx_g;

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(pRedirCtx->uam_ip, ip_str);

  memset((void *)html_body, 0, sizeof(html_body));
  html_body_len = snprintf((char *)html_body, 
                           sizeof(html_body),
                           "%s%s%s%s%s"
                           "%d%s%s%s%s"
                           "%s%s%s",
                           "<html><head><title></title>",
                           "<meta http-equiv=\"refresh\" content=\"2;URL='",
                           "http://",
                           ip_str,
                           ":",
                           pRedirCtx->uam_port, 
                           "/ui.html",
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
}/*redir_process_rejected_req*/

int32_t redir_process_image_req(uint32_t conn_id,
                                uint8_t **response_ptr, 
                                uint16_t *response_len_ptr) {
  uint32_t fd;
  struct stat statbuff;
  uint8_t http_header[255];
  uint8_t file_name[255];
  uint16_t tmp_len;
  redir_ctx_t *pRedirpCtx = &redir_ctx_g;
  redir_session_t *session = redir_get_session(conn_id);

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
}/*redir_process_image_req*/


int32_t redir_update_conn_status_success(uint32_t conn_id) {

  uint8_t sql_query[255];
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  redir_session_t *session = redir_get_session(conn_id);

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%s%s",
           "INSERT INTO ",
           pRedirCtx->conn_auth_status_table,
           " (ip_address, auth_state) VALUES ('",
           inet_ntoa(session->peer_addr.sin_addr),
           "', '",
           "SUCCESS'", 
           ")"); 
  if(db_exec_query(sql_query)) {
    fprintf(stderr, "\n%s:%d Execution of Query Failed\n",
                    __FILE__,
                    __LINE__);
    return(-1);
  }
 
  return(0);
}/*redir_update_conn_status_success*/

int32_t redir_process_response_callback_req(uint32_t conn_id,
                                            uint8_t **response_ptr,
                                            uint16_t *response_len_ptr) {

  redir_session_t *session = redir_get_session(conn_id);
  redir_process_response_callback_uri(conn_id, session->uri);
  redir_process_wait_req(conn_id, 
                         response_ptr, 
                         response_len_ptr, 
                         "/time_out");
  
  return(0);
}/*redir_process_response_callback_req*/

int32_t redir_process_auth_response(uint32_t conn_id,
                                    uint8_t **response_ptr,
                                    uint16_t *response_len_ptr,
                                    uint8_t *location_ptr) {

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
                            location_ptr,
                            "\r\n",
                            "Content-Type: text/html\r\n",
                            "Accept-Language: en-US,en;q=0.5\r\n",
                            "Accept: text/*;q=0.3, text/html;q=0.7, text/html;level=1,",
                            "text/html;level=2;q=0.4, */*;q=0.5\r\n",
                            "Content-Length: 0",
                            /*Delimiter B/W Header and Body*/
                            "\r\n\r\n");

  return(0);
}/*redir_process_auth_response*/

int32_t redir_process_time_out_req(uint32_t conn_id,
                                   uint8_t **response_ptr,
                                   uint16_t *response_len_ptr) {

  redir_session_t *session = redir_get_session(conn_id);

  if(AUTH_INPROGRESS == session->auth_status) {
    redir_process_wait_req(conn_id,
                           response_ptr,
                           response_len_ptr,
                           "/time_out"); 

  } else if(AUTH_SUCCESS == session->auth_status) {
    /*Update in db that USER is authenticated successfully*/
    redir_update_conn_status_success(conn_id);
    redir_process_auth_response(conn_id,
                                response_ptr,
                                response_len_ptr,
                                session->url);

  } else if(AUTH_REJECTED == session->auth_status) {
    redir_process_wait_req(conn_id,
                           response_ptr,
                           response_len_ptr,
                           "/auth_rejected.html"); 
  } else {
    fprintf(stderr, "\n%s:%d Invalid Auth Status %d conn_id %d\n",
                   __FILE__,
                   __LINE__,
                   session->auth_status,
                   conn_id);
  }

  return(0);
}/*redir_process_time_out_req*/

int32_t redir_process_wait_req(uint32_t conn_id,
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

}/*redir_process_wait_req*/

int32_t redir_radiusC_connect(void) {
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  int32_t fd;
  int32_t ret = -1;
  struct sockaddr_in radiusC;
  socklen_t addr_len = sizeof(radiusC);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  radiusC.sin_family = AF_INET;
  radiusC.sin_addr.s_addr = htonl(pRedirCtx->redir_listen_ip);
  radiusC.sin_port = htons(pRedirCtx->radiusC_port);
  memset((void *)radiusC.sin_zero, 0, sizeof(radiusC.sin_zero));

  if(!(ret = connect(fd, (struct sockaddr *)&radiusC, addr_len))) {
    pRedirCtx->radiusC_fd = fd;
  }

  return(ret);
}/*redir_radiusC_connect*/

int32_t redir_build_access_request(uint32_t conn_id, 
                                   uint8_t *email_id, 
                                   uint8_t *password, 
                                   uint8_t *url) {
  uint8_t acc_req[1024];
  uint16_t acc_req_len = 0;
  redir_ctx_t *pRedirCtx = &redir_ctx_g;

  memset((void *)acc_req, 0, sizeof(acc_req));

  access_request_t *access_req_ptr = 
               (access_request_t *)acc_req;

  acc_req_len = sizeof(access_request_t);
  redir_session_t *session = redir_get_session(conn_id);

  session->auth_status = AUTH_INPROGRESS;
  /*copying the URL into session*/
  strncpy((char *)session->url, url, strlen((const char *)url));
  
  access_req_ptr->message_type = ACCESS_REQUEST;
  access_req_ptr->txn_id = conn_id;
  access_req_ptr->user_id_len = strlen((const char *)email_id);
  strncpy((char *)access_req_ptr->user_id, 
          (const char *)email_id, 
          strlen((const char *)email_id));

  access_req_ptr->password_len = strlen((const char *)password);
  strncpy((char *)access_req_ptr->password, 
          (const char *)password, 
          strlen((const char *)password));

  if(pRedirCtx->radiusC_fd < 0) {
    redir_radiusC_connect();
  }

  redir_send(pRedirCtx->radiusC_fd, acc_req, acc_req_len);

  return(0); 
}/*redir_build_access_request*/

int32_t redir_process_response_callback_uri(uint32_t conn_id, 
                                            uint8_t *uri) {

  uint8_t auth_type[32];
  uint8_t url[2048]; 

  memset((void *)auth_type, 0, sizeof(auth_type));
  sscanf((const char *)uri, "%*[^?]?auth_type=%[^&]", auth_type);
  memset((void *)url, 0, sizeof(url));
  
  if(!strncmp((const char *)auth_type, "login", 5)) {
    uint8_t email_id[128];
    uint8_t password[64];
    sscanf((const char *)uri, 
           "%*[^?]?auth_type=%*[^&]&email_id=%[^&]&password=%[^&]&url=%s", 
            email_id,
            password,
            url);
    redir_build_access_request(conn_id, email_id, password, url);    
     
  } else if(!strncmp((const char *)auth_type, "registration",12 )) {

  } else if(!strncmp((const char *)auth_type, "fb", 2)) {
    /*login with Facebook*/
  } else if(!strncmp((const char *)auth_type, "gmail", 5)) {
    
  } else if(!strncmp((const char *)auth_type, "twitter", 7)) {
 
  } else if(!strncmp((const char *)auth_type, "aadhaar", 7)) {
    
  }
}/*redir_process_response_callback_uri*/

int32_t redir_update_conn_status_ex(uint32_t conn_id, 
                                    uint8_t *uri_ptr, 
                                    uint8_t *host_name_ptr) {
  uint8_t sql_query[255];
  int32_t ret;
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  redir_session_t *session;
  uint16_t idx;
  uint8_t record[2][16][32];
  uint32_t row;
  uint32_t col;
  uint16_t src_port;

  session = redir_get_session(conn_id);

  if(!strncmp((const char *)session->uri, "/response_callback", 18)) {
    /*Retrieve the src_port at which the subscriber was authenticated*/
    sscanf((const char *)session->uri, "%*[^=]=%d", (int32_t *)&src_port);

    /*Retrieve the original URL to that subscriber can be redirected to it*/
    ret = snprintf((char *)sql_query,
                   sizeof(sql_query),
                   "%s%s%s%s%s"
                   "%d%s",
                   "SELECT * FROM ",
                   pRedirCtx->conn_auth_status_table,
                   " WHERE (ip_address ='",
                   inet_ntoa(session->peer_addr.sin_addr),
                   "' AND src_port='",
                   src_port,
                   "')");
    fprintf(stderr, "\n%s:%d (%s) \n", __FILE__, __LINE__, sql_query);
    if(!db_exec_query(sql_query)) {
      memset((void *)record, 0, sizeof(record));
      row = 0, col = 0;
      if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
        if(row) {
          strncpy((char *)uri_ptr, 
                  (const char *)record[0][2], 
                  strlen((const char *)record[0][2]));

          strncpy((char *)host_name_ptr, 
                  (const char *)record[0][3], 
                  strlen((const char *)record[0][3]));
        }
      }  
    }
  } else {
    uint8_t host_name[255];
    memset((void *)host_name, 0, sizeof(host_name));
    /*Retrieving Host Name from Http Request*/
    for(idx = 0; idx < session->mime_header_count; idx++) {

      if(!strncmp((char *)session->mime_header[idx][0], "Host", 4)) {
        memset((void *)host_name, 0, sizeof(host_name));
        strncpy((char *)host_name, 
                (const char *)session->mime_header[idx][1], 
                strlen((const char *)session->mime_header[idx][1]));
        break;
      }
    }

    ret = snprintf((char *)sql_query, 
                   sizeof(sql_query),
                   "%s%s%s%s%s"
                   "%s%s%s%s%d"
                   "%s",
                   "UPDATE ",
                   pRedirCtx->conn_auth_status_table,
                   " SET uri='",
                   session->uri,
                   "', host_name='",
                   host_name,
                   "' WHERE (ip_address='",
                   inet_ntoa(session->peer_addr.sin_addr),
                   "' AND src_port ='",
                   ntohs(session->peer_addr.sin_port),
                   "')");

    if(db_exec_query(sql_query)) {
      fprintf(stderr, "\n%s:%d Execution of Query Failed\n", __FILE__, __LINE__);
      return(-2);
    }
  }

  return(0);
}/*redir_update_conn_status_ex*/

int32_t redir_update_conn_status(uint32_t conn_id, 
                                 uint8_t *orig_uri_ptr, 
                                 uint8_t *host_name_ptr) {

  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  uint16_t idx;
  uint8_t sql_query[255];
  int32_t ret = -1;
  uint8_t record[2][16][32];
  uint32_t row;
  uint32_t col;
  redir_session_t *session = NULL;

  session = redir_get_session(conn_id);

  /*Valid Connection found, update the db*/
  memset((void *)sql_query, 0, sizeof(sql_query));
  ret = snprintf((char *)sql_query,
                 sizeof(sql_query),
                 "%s%s%s%s%s",
                 "SELECT * FROM ",
                 pRedirCtx->conn_auth_status_table,
                 " WHERE ip_address ='",
                 inet_ntoa(session->peer_addr.sin_addr),
                 "'");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, sizeof(record));
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      if(row) {
        /*Record Found*/
        if(!strncmp((const char *)session->uri, "/authstate_success", 18)) {
          strncpy((char *)orig_uri_ptr, 
                  (const char *)record[0][2], 
                  strlen((const char *)record[0][2]));

          strncpy((char *)host_name_ptr, 
                  (const char *)record[0][3], 
                  strlen((const char *)record[0][3]));
          
          /*Update the STATUS in Database*/
          memset((void *)sql_query, 0, sizeof(sql_query));

          ret = snprintf((char *)sql_query, 
                         sizeof(sql_query),
                         "%s%s%s%s%s"
                         "%s",
                         "UPDATE ",
                         pRedirCtx->conn_auth_status_table,
                         " SET auth_state = 'SUCCESS' ",
                         "WHERE ip_address = '",
                         inet_ntoa(session->peer_addr.sin_addr),
                         "'");

          if(db_exec_query(sql_query)) {
            fprintf(stderr, "\n%s:%d Execution of Query Failed\n", __FILE__, __LINE__);
            return(-1);
          }

        }
      } else {
        /*No Record Found*/
        uint8_t mac_address[64];
        memset((void *)sql_query, 0, sizeof(sql_query));
        ret = snprintf((char *)sql_query,
                       sizeof(sql_query),  
                       "%s%s%s%d%s",
                       "SELECT * FROM ",
                       pRedirCtx->ip_allocation_table,
                       " WHERE (host_id ='",
                       ((session->peer_addr.sin_addr.s_addr & 0xFF000000) >> 24),
                       "' AND ip_allocation_status ='ASSIGNED')");

        if(!db_exec_query(sql_query)) {
          memset((void *)record, 0, sizeof(record));

          if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
            if(row) {
              strncpy((char *)mac_address, (const char *)record[0][1], 17);
              /*Insert New Record*/
              uint8_t host_name[255];

              /*Retrieving Host Name from Http Request*/
              for(idx = 0; idx < session->mime_header_count; idx++) {

                if(!strncmp((char *)session->mime_header[idx][0], "Host", 4)) {
                  memset((void *)host_name, 0, sizeof(host_name));
                  strncpy((char *)host_name, 
                          (const char *)session->mime_header[idx][1], 
                          strlen((const char *)session->mime_header[idx][1]));

                  fprintf(stderr, "\nHost Name is found and is %s\n", host_name);
                  break;
                }
              }

              ret = snprintf((char *)sql_query, 
                             sizeof(sql_query),
                             "%s%s%s%s%s"
                             "%s%s%s%s%s"
                             "%s%s%s",
                             "INSERT INTO ",
                             pRedirCtx->conn_auth_status_table,
                             " (ip_address, mac_address, uri, host_name, auth_state)",
                             " VALUES ('",
                             inet_ntoa(session->peer_addr.sin_addr),
                             "', '",
                             mac_address,
                             "', '",
                             session->uri,
                             "', '",
                             host_name,
                             "', '",
                             "INPROGRESS')");

              if(db_exec_query(sql_query)) {
                fprintf(stderr, "\n%s:%d Execution of Query Failed\n", __FILE__, __LINE__);
                return(-2);
              }
            }
          }
        }               
      }  
    } 
  }               
  return(0); 
}/*redir_update_conn_status*/

int32_t redir_recv(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint16_t *packet_length) {
  int32_t  ret = -1;
  uint16_t max_length = 1500;
  do {
    ret = recv(fd, packet_ptr, max_length, 0);

  }while((ret == -1) && (EINTR == errno));

  *packet_length = (uint16_t)ret;
  return(ret);

}/*redir_recv*/

int32_t redir_send(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint16_t packet_length) {
  int32_t  ret = -1;
  do {
    ret = send(fd, packet_ptr, packet_length, 0);

  }while((ret == -1) && (EINTR == errno));

  return(ret);
}/*redir_send*/

int32_t redir_set_fd(redir_session_t *session, fd_set *rd) {

  while(session) {
    FD_SET(session->conn, rd);
    session = session->next;
  }

  return(0);
}/*redir_set_fd*/


redir_session_t *redir_add_session(uint32_t conn_id) {
  redir_ctx_t *pRedirCtx = &redir_ctx_g;

  if(NULL == pRedirCtx->session) {
    /*First session to be created*/
    pRedirCtx->session = (redir_session_t *)malloc(sizeof(redir_session_t));

    if(NULL == pRedirCtx->session) {
      /*Allocation of Memory from Heap failed*/
      fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
      exit(0);
    }

    /*Memory allocated successfully, continue initialization*/
    memset((void *)pRedirCtx->session, 0, sizeof(redir_session_t));

    pRedirCtx->session->conn = conn_id;
    /*This is the only session so to set its next to NULL*/
    pRedirCtx->session->next = NULL;
    return(pRedirCtx->session);

  } else {
    /*new session to inserted into existing session list*/
    redir_session_t *new_session = pRedirCtx->session;

    /*get to the end of the list*/
    while(NULL != new_session->next) {
      new_session = new_session->next;
    }

    /*got to the end of the list*/
    new_session->next = (redir_session_t *)malloc(sizeof(redir_session_t));

    if(NULL == new_session->next) {
      /*Memory allocation from Heap Failed*/
      fprintf(stderr, "\n%s:%d Memory allocation from Heap failed\n", __FILE__, __LINE__);
      exit(0);
    }
    
     memset((void *)new_session->next, 0, sizeof(redir_session_t));
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


redir_session_t *redir_get_session(uint32_t conn_id) {
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  /*Always preserve the start address of the session*/
  redir_session_t *tmp_session = pRedirCtx->session;
  
  while(NULL != tmp_session) {
    if(conn_id == tmp_session->conn) {
#if 0
      fprintf(stderr, "\n%s:%d conn_id %d found in the session\n",
                      __FILE__,
                      __LINE__,
                      tmp_session->conn);
#endif
      return(tmp_session);
    }
    /*look for next session's conn_id*/
    tmp_session = tmp_session->next;
  }

  /*Invalid session- no connection is found*/
  return(NULL);
}/*redir_get_session*/


int32_t redir_remove_session(uint32_t conn_id) {
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  redir_session_t *prev_session = NULL;
  redir_session_t *curr_session = pRedirCtx->session;
  redir_session_t *tobe_deleted = NULL;

  while(curr_session) {

    if(conn_id == curr_session->conn) {
      /*Got the conn_id and it is to be removed*/
      if(NULL == prev_session) {
        /*Heade Node to be deleted*/
        tobe_deleted = curr_session;
        /*Modify the Heade node*/
        pRedirCtx->session = curr_session->next;
        curr_session = pRedirCtx->session;
        free(tobe_deleted);
        fprintf(stderr, "\n%s:%d Removed the Head node (%d)",
                        __FILE__,
                        __LINE__,
                        conn_id);
        continue;

      } else {
        tobe_deleted = curr_session;
        prev_session->next = curr_session->next;
        curr_session = curr_session->next;
        free(tobe_deleted);
        fprintf(stderr, "\n%s:%d Removed the mid node (%d)",
                        __FILE__,
                        __LINE__,
                        conn_id);
        continue;
      }
    }

    prev_session = curr_session;
    curr_session = curr_session->next;
  }
 
  return(0); 
}/*redir_remove_session*/


uint32_t redir_get_max_fd(redir_session_t *session) {
  uint32_t max_fd = 0;

  while(session) {
    max_fd = (max_fd > session->conn)? max_fd: session->conn;
    session = session->next;
  }

  return(max_fd);
}/*redir_get_max_fd*/

int32_t redir_parse_req(uint32_t conn_id,
                        uint8_t *packet_ptr,
                        uint16_t packet_length) {

  uint8_t *line_ptr;
  uint8_t *tmp_ptr = NULL;
  uint16_t idx = 0;
  uint16_t mime_idx;
  uint8_t method[8];
  uint8_t *uri_ptr;
  uint16_t uri_len;
  uint8_t protocol[8];
  uint16_t tmp_len = 0;
  uint16_t line_len = 0;
  redir_session_t *session = NULL;

  redir_ctx_t *pRedirCtx = &redir_ctx_g;

  tmp_ptr = (uint8_t *)malloc(packet_length);

  if(NULL == tmp_ptr) {
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

  if(NULL == uri_ptr) {
    fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
    free(tmp_ptr);
    return(-1);
  }

  memset((void *)uri_ptr, 0, uri_len);
  sscanf((const char *)line_ptr, 
         "%*s %s %*s", 
         uri_ptr);

  session = redir_get_session(conn_id);
  memset((void *)session->method, 0, sizeof(session->method));
  memset((void *)session->protocol, 0, sizeof(session->protocol));
  memset((void *)session->uri, 0, sizeof(session->uri));

  strncpy(session->method, method, strlen((const char *)method));
  strncpy(session->protocol, protocol, strlen((const char *)protocol));
  strncpy(session->uri, uri_ptr, strlen((const char *)uri_ptr));

  free(uri_ptr);
  uri_ptr = NULL;

  memset((void *)session->mime_header, 0, sizeof(session->mime_header));

  mime_idx = 0;
  while((line_ptr = strtok(NULL, "\r\n"))) { 
    sscanf((const char *)line_ptr, 
           "%[^:]:%*s",
           session->mime_header[mime_idx][0]);

    tmp_len = strlen((const char *)session->mime_header[mime_idx][0]);
    line_len = strlen((const char *)line_ptr);

    /*If Method is POST then Payload would be followed by an empty line \r\n*/
    if(line_len > tmp_len) {
      memcpy((void *)&session->mime_header[mime_idx][1], 
             (void *)&line_ptr[tmp_len + 2], 
             (line_len - (tmp_len + 2)));
      mime_idx++;
    }
  }

  session->mime_header_count = mime_idx - 1;
  free(tmp_ptr);
 
  return(0);  
}/*redir_parse_req*/

int32_t redir_process_redirect_req(uint32_t conn_id,
                                   uint8_t **response_ptr,
                                   uint16_t *response_len_ptr) {
  uint16_t idx;
  uint8_t *referer_ptr;
  uint16_t referer_len;
  uint8_t location_buff[1024];
  uint8_t ip_str[32];
  redir_session_t *session = NULL;

  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(htonl(pRedirCtx->uam_ip), ip_str);

  session = redir_get_session(conn_id);

  for(idx = 0; idx < session->mime_header_count; idx++) {

    if(!strncmp((const char *)session->mime_header[idx][0], "Host", 4)) {
      referer_len = strlen((const char *)session->mime_header[idx][1]) +
                      strlen((const char *)session->uri) + 50;

      referer_ptr = (uint8_t *)malloc(referer_len);

      if(!referer_ptr) {
        fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
        return(-1);
      }
  
      memset((void *)referer_ptr, 0, referer_len); 
      snprintf((char *)referer_ptr, 
               referer_len,
               "%s%s%s",
               "Referer: http://",
               session->mime_header[idx][1],
               session->uri);

      /*Prepare location string*/
      memset((void *)location_buff, 0, sizeof(location_buff));
      snprintf((char *)location_buff, 
               sizeof(location_buff),
               "%s%s%s%d%s"
               "%s%s",
               "http://",
               ip_str,
               ":",
               pRedirCtx->uam_port, 
               "/login.html?url=http://",
               session->mime_header[idx][1],
               session->uri);
      break;
    } 
  }
  
  if(idx == session->mime_header_count) {
    fprintf(stderr, "\n%s:%d Host Header not found in mime header\n", __FILE__, __LINE__);
    return(-3);
  }

  (*response_ptr) = (uint8_t *) malloc(2048);

  if(!(*response_ptr)) {
    fprintf(stderr, "\n%s:%d memory Allocation Failed\n", __FILE__, __LINE__);
    return(-4);
  }

  memset((void *)(*response_ptr), 0, 2048);

  *response_len_ptr = sprintf((char *)(*response_ptr), 
                            "%s%s%s%s%s"
                            "%s%s%s%s%s"
                            "%s%s%s",
                            "HTTP/1.1 302 Moved Temporarily\r\n",
                            referer_ptr,
                            "\r\n",
                            "Connection: Keep-Alive\r\n",
                            /*"Connection: close\r\n",*/
                            "Location: ",
                            location_buff,
                            "\r\n",
                            "Content-Type: text/html\r\n",
                            "Accept-Language: en-US,en;q=0.5\r\n",
                            "Accept: text/*;q=0.3, text/html;q=0.7, text/html;level=1,",
                            "text/html;level=2;q=0.4, */*;q=0.5\r\n",
                            "Content-Length: 0",
                            /*Delimiter B/W Header and Body*/
                            "\r\n\r\n");

  free(referer_ptr);
  referer_ptr = NULL;


}/*redir_process_redirect_req*/


int32_t redir_process_uri(uint32_t conn_id,
                          uint8_t **response_ptr,
                          uint16_t *response_len_ptr) {
  uint16_t idx;
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  redir_session_t *session = redir_get_session(conn_id);

  for(idx = 0; pRedirCtx->pHandler[idx].uri; idx++) {

    if(!strncmp(session->uri,
                pRedirCtx->pHandler[idx].uri,
                pRedirCtx->pHandler[idx].uri_len)) {

      pRedirCtx->pHandler[idx].redir_req_cb(conn_id, 
                                            response_ptr, 
                                            response_len_ptr);
      break;

    } 
  }

  return(0);
}/*redir_process_uri*/
                          
int32_t redir_process_req(uint32_t conn_id, 
                          uint8_t *packet_ptr, 
                          uint16_t packet_length) {

  /*Build temporary HTTP Response*/
  uint8_t *redir_ptr = NULL;
  uint16_t redir_len = 0;

  redir_parse_req(conn_id, packet_ptr, packet_length);

  redir_process_uri(conn_id, &redir_ptr, &redir_len);

  if(redir_send(conn_id, redir_ptr, redir_len) < 0) {
    perror("redir send Failed:");
    return(-1); 
  }

  free(redir_ptr);
  return(0);
}/*redir_process_req*/

int32_t redir_process_radiusS_response(int32_t radiusC_fd,
                                       uint8_t *packet_ptr,
                                       uint16_t packet_length) {

  redir_session_t *session = NULL;
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  radiusC_message_t *rsp_ptr = (radiusC_message_t *)packet_ptr;
 
  switch(*packet_ptr) {
    case ACCESS_ACCEPT:
     session = redir_get_session(rsp_ptr->access_accept.txn_id);
     session->auth_status = AUTH_SUCCESS; 

    break;
    case ACCESS_REJECT:
     session = redir_get_session(rsp_ptr->access_reject.txn_id);
     session->auth_status = AUTH_REJECTED; 

    break;
    case ACCOUNTING_RESPONSE:
    break;
    default:
      fprintf(stderr, "\n%s:%d Unknown Response from radiusS\n", 
                      __FILE__,
                      __LINE__);
    break;
  } 



}/*redir_process_radiusS_response*/

int32_t redir_init(uint32_t redir_listen_ip, 
                   uint16_t redir_listen_port, 
                   uint32_t uam_ip, 
                   uint16_t uam_port,
                   uint16_t radiusC_port,
                   uint8_t *conn_auth_status_table,
                   uint8_t *ip_allocation_table) {

  int32_t fd = -1;
  struct sockaddr_in redir_addr;
  size_t redir_addr_len;
  redir_ctx_t *pRedirCtx = &redir_ctx_g;

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(fd < 0) {
    fprintf(stderr, "\n%s:%d creation of socket failed\n", __FILE__, __LINE__);
    return(-1);
  }
  redir_addr_len = sizeof(struct sockaddr_in);
  redir_addr.sin_addr.s_addr = htonl(redir_listen_ip);
  redir_addr.sin_port = htons(redir_listen_port);
  redir_addr.sin_family = AF_INET;
  memset((void *)redir_addr.sin_zero, 0, sizeof(redir_addr.sin_zero));

  if(bind(fd, (struct sockaddr *)&redir_addr, redir_addr_len) < 0) {
    fprintf(stderr, "\n%s:%d bind to given address failed\n", __FILE__, __LINE__);
    perror("Bind Failed: ");
    return(-1);
  }
  
  /*Max Pending connection which is 10 as of now*/
  if(listen(fd, 5) < 0) {
    fprintf(stderr, "\n%s:%d listen to given ip failed\n", __FILE__, __LINE__);
    return(-1);
  }

  /*Closing on exit*/
  utility_coe(fd);

  pRedirCtx->redir_listen_ip = redir_listen_ip;
  pRedirCtx->redir_listen_port = redir_listen_port;
  pRedirCtx->uam_ip = uam_ip;
  pRedirCtx->uam_port = uam_port;
  pRedirCtx->radiusC_port = radiusC_port;
  pRedirCtx->redir_fd = fd;

  pRedirCtx->session = NULL;
  pRedirCtx->pHandler = g_handler_redir;
  pRedirCtx->radiusC_fd = -1;
   
  strncpy((char *)pRedirCtx->conn_auth_status_table, 
          (const char *)conn_auth_status_table, 
          strlen((const char *)conn_auth_status_table)); 

  strncpy((char *)pRedirCtx->ip_allocation_table, 
          (const char *)ip_allocation_table, 
          strlen((const char *)ip_allocation_table)); 
  return(0); 
}/*redir_init*/

/* @brief This function is the entry point of thread for Redirect
 *
 * @param1 pointer to void received while spawning the thread.
 *
 * @return pointer to void
 */
void *redir_main(void *argv) {

  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  int32_t ret;
  int32_t new_conn;
  struct timeval to;
  struct sockaddr_in peer_addr;
  uint16_t idx;
  size_t peer_addr_len;
  uint8_t packet_buffer[3500];
  uint16_t packet_length;
  int32_t max_fd;
  fd_set rd;
  redir_session_t *session = NULL;
  
  for(;;) {
    to.tv_sec = 2;
    to.tv_usec = 0;
    
    FD_ZERO(&rd);
    FD_SET(pRedirCtx->redir_fd, &rd);

    /*Upon receipt of connection close, conn_id is set 0*/
    redir_remove_session((uint32_t)0);

    redir_set_fd(pRedirCtx->session, &rd);

    max_fd = redir_get_max_fd(pRedirCtx->session);

    if(pRedirCtx->radiusC_fd > 0) {

      FD_SET(pRedirCtx->radiusC_fd, &rd);
      max_fd = (max_fd > pRedirCtx->radiusC_fd) ? 
                max_fd : 
                pRedirCtx->radiusC_fd;
    }

    max_fd = (max_fd > pRedirCtx->redir_fd ? 
                 max_fd : 
                 pRedirCtx->redir_fd) + 1;


    ret = select(max_fd, &rd, NULL, NULL, &to);
   
    if(ret > 0) {

      if(FD_ISSET(pRedirCtx->redir_fd, &rd)) {
        /*New Connection accept it.*/
        new_conn = accept(pRedirCtx->redir_fd, 
                          (struct sockaddr *)&peer_addr, 
                          (socklen_t *)&peer_addr_len);

        session = redir_add_session(new_conn); 
        session->peer_addr = peer_addr;
        #if 0
        if(peer_addr.sin_addr.s_addr) {
          session = redir_add_session(new_conn); 
          session->peer_addr = peer_addr;
          fprintf(stderr, "\n%s:%d New Connection received conn %d ip %s\n", 
                     __FILE__,
                     __LINE__,
                     new_conn, 
                     inet_ntoa(peer_addr.sin_addr));
        } else {
          /*Connect Request from 0.0.0.0 ip Address*/
          fprintf(stderr, "\n%s:%d Closing the connection\n", __FILE__, __LINE__);
          close(new_conn);
        }
        #endif
      } else if((pRedirCtx->radiusC_fd > 0) && (FD_ISSET(pRedirCtx->radiusC_fd, &rd))) {
        /*Process RadiusS Response*/
        memset((void *)packet_buffer, 0, sizeof(packet_buffer));
        packet_length = 0;
        redir_recv(pRedirCtx->radiusC_fd, packet_buffer, &packet_length);

        if(!packet_length) {
          close(pRedirCtx->radiusC_fd);
          pRedirCtx->radiusC_fd = -1;
        } else {
          redir_process_radiusS_response(pRedirCtx->radiusC_fd,
                                         packet_buffer,
                                         packet_length);
        }
      } else {

        for(session = pRedirCtx->session; session != NULL; session = session->next) {
          if(FD_ISSET(session->conn, &rd)) {
            /*Either connection is closed or data has been received.*/
            memset((void *)packet_buffer, 0, sizeof(packet_buffer));
            packet_length = 0;
            redir_recv(session->conn, packet_buffer, &packet_length);

            if(!packet_length) {
              /*Closing the connected conn_id*/
              close(session->conn);
              fprintf(stderr, "\n%s:%d conn_id %d is being cloed\n",
                              __FILE__,
                              __LINE__,
                              session->conn);
              session->conn = 0;

            } else {
              fprintf(stderr, "\n%s:%d (conn_id %d) %s\n",
                              __FILE__,
                              __LINE__,
                             session->conn,
                             packet_buffer);

              redir_process_req(session->conn, 
                                packet_buffer, 
                                packet_length);
            }
          }  
        }
      }
    } else if(!ret) {
      //fprintf(stderr, "\n%s:%d Got the timeout\n", __FILE__, __LINE__);
    } else {
      perror("Redir:");
    }
  }
  
}/*redir_main*/

#endif /* __REDIR_C__ */
