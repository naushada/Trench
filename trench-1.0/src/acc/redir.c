#ifndef __REDIR_C__
#define __REDIR_C__

#include <sys/stat.h>
#include <netdb.h>
#include <type.h>
#include <common.h>
#include <db.h>
#include <utility.h>
#include <radiusC.h>
#include <subscriber.h>
#include <redir.h>
#include <dhcp.h>

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
  {"/auth_rejected.html", 19, redir_process_rejected_req},
  {"/",                    1, redir_process_redirect_req},
  /*This shall be the last row in this table*/
  {NULL,                   0, NULL}
};

int32_t redir_update_dns(uint8_t *host_name, uint8_t *ip_str) {

  uint8_t sql_query[128];
  
  memset((void *)sql_query, 0, sizeof(sql_query));
  snprintf(sql_query,
            sizeof(sql_query),
            "%s%s%s%s%s"
            "%s%s",
            "UPDATE ",
            REDIR_DNS_TABLE,
            " SET host_ip=\'",
            ip_str,
            "\' WHERE host_name=\'",
            host_name,
            "\'");
  
  if(db_exec_query(sql_query)) {
    fprintf(stderr, "\n%s:%d Execution of DB query failed\n", __FILE__, __LINE__);
    return(1);
  }

  return(0);
}/*redir_update_dns*/

int32_t redir_resolve_dns(uint8_t *host_name) {

  uint8_t ip_str[32];
  struct hostent *he;
  struct in_addr **addr_list;
  uint32_t i;
  /**/
  memset((void *)ip_str, 0, sizeof(ip_str));
  if((he = gethostbyname(host_name))) {
    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++) {
      strcpy(ip_str ,inet_ntoa(*addr_list[i]));
      fprintf(stderr, "\n%s:%d ip address %s\n", __FILE__, __LINE__, ip_str);
      redir_update_dns(host_name, ip_str);
      break;
    }

  } else {
    return(1);
  }

  return(0); 
}/*redir_resolve_dns*/

int32_t redir_populate_dns(uint8_t *table_name) {
  uint8_t sql_query[32];
  int32_t ret = -1;
  int32_t row;
  int32_t col;
  uint8_t idx = 0;
  uint8_t record[8][16][32];

  memset((void *)sql_query, 0, sizeof(sql_query));
  snprintf(sql_query,
           sizeof(sql_query),
           "%s%s",
           "SELECT * FROM ",
           table_name);

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, sizeof(record));
    row = 0, col = 0;
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      if(row) {
        for(idx = 0; idx < row; idx++) {
          if(redir_resolve_dns(record[idx][0])) {
            return(1);
          }
        }
      } else {
        fprintf(stderr, "\n%s:%d No record found %s\n", __FILE__, __LINE__, sql_query);
        return(2);
      }
    }
  } 

  return(0); 
}/*redir_populate_dns*/

int32_t redir_send_to_oauth2(uint32_t conn_id, uint8_t *oauth2_req, uint32_t oauth2_len) {
 
 redir_ctx_t *pRedirCtx = &redir_ctx_g;

  if(pRedirCtx->oauth2_fd < 0) {
    /*Populate DNS table for oauth20*/
    redir_populate_dns(REDIR_DNS_TABLE);
    redir_oauth2_connect(); 
  } 

  if(pRedirCtx->oauth2_fd > 0) {
    redir_send(pRedirCtx->oauth2_fd, oauth2_req, oauth2_len); 
  }

  return(0);
}/*redir_send_to_oauth2*/

int32_t redir_send_to_uidai(uint32_t conn_id, uint8_t *uidai_req, uint32_t uidai_req_len) {
  
 redir_ctx_t *pRedirCtx = &redir_ctx_g;

  if(pRedirCtx->uidaiC_fd < 0) {
    redir_uidaiC_connect(); 
  } 

  if(pRedirCtx->uidaiC_fd > 0) {
    redir_send(pRedirCtx->uidaiC_fd, uidai_req, uidai_req_len); 
  }

  return(0);
}/*redir_send_to_uidai*/

uint8_t *redir_get_param(uint8_t *req_ptr, uint8_t *p_name) {

  uint8_t *tmp_req_ptr = NULL;
  uint8_t *line_ptr = NULL;
  uint8_t param_name[32];
  uint8_t *param_value = NULL;
  char *save_ptr;
  uint8_t flag = 0;
  uint32_t req_len = strlen(req_ptr);

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
    if(!strncmp(param_name, p_name, sizeof(param_name))) {
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
}/*redir_get_param*/

int32_t redir_build_auth_pi_req(uint8_t *req_ptr, uint8_t *uidai_req, uint32_t conn_id) {

  /*Prepare uidai request for OTP*/
  uint8_t *uid = NULL;
  uint8_t *ext_conn_id = NULL;
  uint8_t *rc = NULL;
  uint8_t *name = NULL;
  uint8_t *ver = NULL;
  uint8_t *ms = NULL;
  uint8_t *ip_ptr = NULL;
  int32_t ret = -1;

  uid = redir_get_param(req_ptr, "aadhaar_no");
  ext_conn_id = redir_get_param(req_ptr, "conn_id");
  rc = redir_get_param(req_ptr, "rc");
  name = redir_get_param(req_ptr, "name");
  ver = redir_get_param(req_ptr, "ver");
  ms = redir_get_param(req_ptr, "ms");
  ip_ptr = redir_get_param(req_ptr, "ip");

  ret = sprintf(uidai_req, 
                "%s%s%s%s%s"
                "%s%s%s%s%d"
                "%s%s%s%s%s"
                "%s",
                "/request?type=auth&subtype=pi&uid=",
                uid,
                "&ext_conn_id=",
                ext_conn_id,
                "&rc=",
                rc,
                "&ver=",
                ver,
                "&conn_id=",
                conn_id,
                "&name=",
                name,
                "&ms=",
                ms,
                "&ip=",
                ip_ptr);

  free(ip_ptr);
  free(uid);
  free(ext_conn_id);
  free(rc);
  free(name);
  free(ver);
  free(ms);

  return(ret);
}/*redir_build_auth_pi_req*/


int32_t redir_build_auth_otp_req(uint8_t *req_ptr, uint8_t *uidai_req, uint32_t conn_id) {

  /*Prepare uidai request for OTP*/
  uint8_t *uid = NULL;
  uint8_t *ext_conn_id = NULL;
  uint8_t *rc = NULL;
  uint8_t *otp = NULL;
  uint8_t *ver = NULL;
  uint8_t *ip_ptr = NULL;
  int32_t ret = -1;

  uid = redir_get_param(req_ptr, "aadhaar_no");
  ext_conn_id = redir_get_param(req_ptr, "conn_id");
  rc = redir_get_param(req_ptr, "rc");
  otp = redir_get_param(req_ptr, "otp_value");
  ver = redir_get_param(req_ptr, "ver");
  ip_ptr = redir_get_param(req_ptr, "ip");

  ret = sprintf(uidai_req, 
                "%s%s%s%s%s"
                "%s%s%s%s%d"
                "%s%s%s%s",
                "/request?type=auth&subtype=otp&uid=",
                uid,
                "&ext_conn_id=",
                ext_conn_id,
                "&rc=",
                rc,
                "&ver=",
                ver,
                "&conn_id=",
                conn_id,
                "&otp_value=",
                otp,
                "&ip=",
                ip_ptr);

  free(uid);
  free(ext_conn_id);
  free(rc);
  free(otp);
  free(ver);
  free(ip_ptr);

  return(ret);
}/*redir_build_auth_otp_req*/


int32_t redir_process_aadhaar_req(uint32_t conn_id, uint8_t *uri) {

  uint8_t uidai_req[512];
  int32_t ret = -1;
  uint8_t *subtype;
  uint8_t *subsubtype;

  memset((void *)uidai_req, 0, sizeof(uidai_req));

  subtype = redir_get_param(uri, "subtype");

  if(!strncmp(subtype, "auth", 4)) {
    subsubtype = redir_get_param(uri, "subsubtype");

    if(!(strncmp(subsubtype, "otp", 3))) {
      /*Prepare uidai auth with OTP value*/
      redir_build_auth_otp_req(uri, uidai_req, conn_id);
      ret = strlen(uidai_req);

    } else if(!(strncmp(subsubtype, "pi", 2))) {
      /*Prepare uidai auth with pi value*/
      redir_build_auth_pi_req(uri, uidai_req, conn_id);
      ret = strlen(uidai_req);

    } else if(!(strncmp(subsubtype, "pa", 2))) {
      /*Prepare uidai auth with pa value*/
    }

    free(subsubtype);
  } else {
    /*Prepare uidai request for OTP*/
    uint8_t *uid = NULL;
    uint8_t *ext_conn_id = NULL;
    uint8_t *rc = NULL;
    uint8_t *ip_ptr = NULL;
    uint8_t *name_ptr = NULL;

    uid = redir_get_param(uri, "aadhaar_no");
    ext_conn_id = redir_get_param(uri, "conn_id");
    rc = redir_get_param(uri, "rc");
    ip_ptr = redir_get_param(uri, "ip");
    name_ptr = redir_get_param(uri, "name");

    ret = snprintf(uidai_req, 
                   sizeof(uidai_req),
                   "%s%s%s%s%s"
                   "%s%s%d%s%s"
                   "%s%s",
                   "/request?type=otp&uid=",
                   uid,
                   "&ext_conn_id=",
                   ext_conn_id,
                   "&rc=",
                   rc,
                   "&ver=1.6&conn_id=",
                   conn_id,
                   "&ip=",
                   ip_ptr,
                   "&name=",
                   name_ptr);
    free(uid);
    free(ext_conn_id);
    free(rc);
    free(ip_ptr);
    free(name_ptr);
  }

  free(subtype);
  fprintf(stderr, "\n%s:%d Being sent to uidaiC %s\n", __FILE__, __LINE__, uidai_req);
  redir_send_to_uidai(conn_id, uidai_req, ret);  
  return(0);  
}/*redir_process_aadhaar_req*/

uint8_t *redir_get_oauth2_param(uint8_t *packet_ptr, uint8_t *p_name) {

  uint8_t *param_value = NULL;
  uint32_t param_max_size = 512;
  uint8_t *tmp_ptr = NULL;
  uint8_t *line_ptr = NULL;
  uint8_t param_name[32];
  char *save_ptr;
  uint8_t is_found = 0;

  param_value = (uint8_t *)malloc(param_max_size);
  assert(param_value != NULL);
  tmp_ptr = (uint8_t *)malloc(strlen(packet_ptr));
  assert(tmp_ptr != NULL);
  memset((void *)tmp_ptr, 0, strlen(packet_ptr));
  sscanf(packet_ptr, "%*[^?]?%s", tmp_ptr);  

  line_ptr = strtok_r(tmp_ptr, "&", &save_ptr);
  while(line_ptr) {
    memset((void *)param_name, 0, sizeof(param_name));
    memset((void *)param_value, 0, param_max_size);
    sscanf(line_ptr, "%[^=]=%s", param_name, param_value);

    if(!strncmp(param_name, p_name, strlen(p_name))) {
      is_found = 1;
      break;  
    }
    line_ptr = strtok_r(NULL, "&", &save_ptr);
  }

  if(is_found) {
    free(tmp_ptr);
    return(param_value);
  }

  free(tmp_ptr);
  free(param_value);
  return(NULL);
}/*redir_get_oauth2_param*/

int32_t redir_compute_ts(uint8_t *ts, uint32_t ts_size) {

  time_t curr_time;
  struct tm *local_time;

  /*Retrieving the current time*/
  curr_time = time(NULL);
  local_time = localtime(&curr_time);

  memset((void *)ts, 0, ts_size);
  snprintf(ts, 
           ts_size,
           "%04d-%02d-%02dT%02d:%02d:%02d", 
           local_time->tm_year+1900, 
           local_time->tm_mon+1, 
           local_time->tm_mday, 
           local_time->tm_hour, 
           local_time->tm_min, 
           local_time->tm_sec);

}/*redir_compute_ts*/

int32_t redir_update_stats(uint32_t conn_id, uint8_t *packet_ptr, uint32_t packet_length) {

  uint8_t sql_query[512];
  uint8_t ts[32];
  uint8_t mac[6];
  uint8_t mac_str[32];
  uint32_t ip;
  uint32_t idx;
  uint8_t *pArr[10];

  memset((void *)sql_query, 0, sizeof(sql_query));
  memset((void *)ts, 0, sizeof(ts));
  memset((void *)mac, 0, sizeof(mac));
  memset((void *)mac_str, 0, sizeof(mac_str));

  pArr[0] = redir_get_oauth2_param(packet_ptr, "name");
  pArr[1] = redir_get_oauth2_param(packet_ptr, "ip");
  pArr[2] = redir_get_oauth2_param(packet_ptr, "status");
  pArr[3] = redir_get_oauth2_param(packet_ptr, "email");

  redir_compute_ts(ts, sizeof(ts));

  ip = utility_ip_str_to_int(pArr[1]);
  dhcp_get_mac(htonl(ip), mac);
  utility_mac_int_to_str(mac, mac_str);

  snprintf(sql_query,
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s",
           "INSERT INTO acc_stats",
           " (ip, mac, in_time, out_time, status, id, name)",
           " VALUES (",
           "'",
           /*ip-address*/
           pArr[1],
           "','",
           mac_str,
           "','",
           ts,
           "',",
           /*out_time*/
           "'','",
           /*status*/
           pArr[2],
           "','",
           /*email-id*/
           pArr[3],
           "','",
           pArr[0],
           "')"); 
      
  if(db_exec_query(sql_query)) {
    fprintf(stderr, "\n%s:%d Execution of query (%s) failed\n", __FILE__, __LINE__, sql_query); 
  } 

  /*Subscriber is authenticated*/
  subscriber_update_conn_status(pArr[1], "SUCCESS");

  /*Freeing the memory*/
  for(idx = 0; idx < 4; idx++) {
    free(pArr[idx]);
  }
  
  return(0);
}/*redir_update_stats*/

int32_t redir_process_oauth2_response(uint32_t conn_id, 
                                      uint8_t *packet_ptr, 
                                      uint32_t packet_length) {
  
  uint8_t *uam_conn_ptr = NULL;
  uint8_t *subtype_ptr = NULL;
  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_size = 1024;
  uint32_t rsp_len = 0;
  uint8_t *pArr[20];
  uint32_t max_arg;
  redir_session_t *session = NULL;

  /*/response?type=gmail&subtype=redirect&location=&ext_conn_id=14&status=success&conn_id=20*/
  fprintf(stderr, "\n%s:%d received \n%s\n", __FILE__, __LINE__, packet_ptr);
  uam_conn_ptr = redir_get_oauth2_param(packet_ptr, "conn_id");
  assert(uam_conn_ptr != NULL);
  subtype_ptr = redir_get_oauth2_param(packet_ptr, "subtype");
  assert(subtype_ptr != NULL);
 
  rsp_ptr = (uint8_t *)malloc(rsp_size);
  assert(rsp_ptr != NULL);
  memset((void *)rsp_ptr, 0, rsp_size);

  if(!strncmp(subtype_ptr, "redirect", 8)) {
    /*Prepare Response*/
    rsp_len = snprintf(rsp_ptr, 
                       rsp_size,
                       "%s%s%s%s%s"
                       "%s%s%s%s%s"
                       "%s%s%s%s%s"
                       "%s%s%s%s%s",
                       "/response?type=gmail&subtype=",
                       subtype_ptr,
                       "&uri=",
                       pArr[0] = redir_get_oauth2_param(packet_ptr, "uri"),
                       "&scope=",
                       pArr[1] = redir_get_oauth2_param(packet_ptr, "scope"),
                       "&access_type=",
                       pArr[2] = redir_get_oauth2_param(packet_ptr, "access_type"),
                       "&state=",
                       pArr[3] = redir_get_oauth2_param(packet_ptr, "state"),
                       "&redirect_uri=",
                       pArr[4] = redir_get_oauth2_param(packet_ptr, "redirect_uri"),
                       "&response_type=",
                       pArr[5] = redir_get_oauth2_param(packet_ptr, "response_type"),
                       "&client_id=",
                       pArr[6] = redir_get_oauth2_param(packet_ptr, "client_id"),
                       "&conn_id=",
                       pArr[7] = redir_get_oauth2_param(packet_ptr, "ext_conn_id"),
                       "&prompt=",
                       pArr[8] = redir_get_oauth2_param(packet_ptr, "prompt"));
    max_arg = 9;

  } else if(!strncmp(subtype_ptr, "auth", 4)) {

    rsp_len = snprintf(rsp_ptr, 
                       rsp_size,
                       "%s%s%s%s%s"
                       "%s%s%s",
                       "/response?type=gmail",
                       "&subtype=auth",
                       "&status=",
                       pArr[0] = redir_get_oauth2_param(packet_ptr, "status"),
                       "&email=",
                       pArr[1] = redir_get_oauth2_param(packet_ptr, "email"),
                       "&conn_id=",
                       pArr[2] = redir_get_oauth2_param(packet_ptr, "ext_conn_id"));

    if(!strncmp(pArr[0], "success", 7)) {
      redir_update_stats(conn_id, packet_ptr, packet_length);
    }
    max_arg = 3;
  }

  fprintf(stderr, "\n%s:%d response ptr %s\n", __FILE__, __LINE__, rsp_ptr);  
  redir_send(atoi(uam_conn_ptr), rsp_ptr, rsp_len);
  /*Free the allocated memory*/
  free(uam_conn_ptr);
  free(subtype_ptr);
  free(rsp_ptr);
  uint32_t idx;

  for(idx = 0; idx < max_arg; idx++) {
    free(pArr[idx]);
  }
  
  return(0); 
}/*redir_process_oauth2_response*/

int32_t redir_process_uidai_response(uint32_t conn_id, 
                                     uint8_t *packet_ptr, 
                                     uint32_t packet_length) {
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  uint8_t *uam_conn_id = NULL;
  uint8_t *status = NULL;
  uint8_t *rsp_ptr = NULL;
  uint8_t *type_ptr = NULL;
  uint8_t *subtype_ptr = NULL;
  uint32_t rsp_len = 0;
  uint8_t *pArr[10];
  uint32_t max_idx = 0;
  
  fprintf(stderr, "\n%s:%d UIDAI received response %s\n", __FILE__, __LINE__, packet_ptr);
  /*/response?type=otp&uid=9701361361&ext_conn_id=14&status=success&conn_id=20*/
  /*/response?type=otp&uid=429182154684&ext_conn_id=14&status=failed&reason=998&actn=A202&conn_id=20*/

  uam_conn_id = redir_get_param(packet_ptr, "conn_id");
  status = redir_get_param(packet_ptr, "status");

  /*allocate and init to zero*/
  rsp_ptr = malloc(512);
  assert(rsp_ptr != NULL);
  memset((void *)rsp_ptr, 0, 512);

  rsp_len = snprintf(rsp_ptr, 
                     512,    
                     "%s%s%s%s%s"
                     "%s%s%s%s%s",
                     "/response?type=",
                     pArr[0] = redir_get_param(packet_ptr, "type"),
                     "&uid=",
                     pArr[1] = redir_get_param(packet_ptr, "uid"),
                     "&conn_id=",
                     pArr[2] = redir_get_param(packet_ptr, "ext_conn_id"),
                     "&status=",
                     pArr[3] = redir_get_param(packet_ptr, "status"),
                     "&name=",
                     pArr[4] = redir_get_param(packet_ptr, "name"));

  if(!strncmp(status, "failed", 6)) {
    rsp_len += snprintf(&rsp_ptr[rsp_len], 
                       512 - rsp_len,    
                       "%s%s",
                       "&reason=",
                       pArr[5] = redir_get_param(packet_ptr, "reason"));
    max_idx = 6;
    pArr[6] = redir_get_param(packet_ptr, "actn"); 
    if(pArr[6]) {
      max_idx += 1;
      rsp_len += sprintf(&rsp_ptr[rsp_len], "&actn=%s", pArr[6]);
    }
  }

  free(status);
  type_ptr = redir_get_param(packet_ptr, "type");

  if(!strncmp(type_ptr, "auth", 4)) {
    rsp_len = snprintf((char *)&rsp_ptr[rsp_len],
                       (512 - rsp_len),
                       "%s%s",
                       "&subtype=",
                       subtype_ptr = redir_get_param(packet_ptr, "subtype"));
    free(subtype_ptr);
  } 

  free(type_ptr);
  rsp_len = strlen(rsp_ptr);
  fprintf(stderr, "\n%s:%d UIDAI response sent to UAM  %s\n", __FILE__, __LINE__, rsp_ptr);
  redir_send(atoi(uam_conn_id), rsp_ptr, rsp_len);
  free(uam_conn_id);
  free(rsp_ptr);

  uint32_t idx;
  for(idx = 0; idx < max_idx; idx++) {
    free(pArr[idx]);
  } 

  return(0);
}/*redir_process_uidai_response*/

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

int32_t redir_process_response_callback_req(uint32_t conn_id,
                                            uint8_t **response_ptr,
                                            uint16_t *response_len_ptr) {

  redir_session_t *session = redir_get_session(conn_id);
  redir_process_response_callback_uri(conn_id, session->uri);
  
#if 0
  redir_process_wait_req(conn_id, 
                         response_ptr, 
                         response_len_ptr, 
                         "/time_out");
#endif
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
                            /*"Connection: Keep-Alive\r\n",*/
                            "Connection: close\r\n",
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

int32_t redir_oauth2_connect(void) {
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  int32_t fd;
  int32_t ret = -1;
  struct sockaddr_in oauth2;
  socklen_t addr_len = sizeof(oauth2);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation Failed\n", __FILE__, __LINE__);
    return(1);
  }

  oauth2.sin_family = AF_INET;
  oauth2.sin_addr.s_addr = htonl(pRedirCtx->redir_listen_ip);
  oauth2.sin_port = htons(pRedirCtx->oauth2_port);

  memset((void *)oauth2.sin_zero, 0, sizeof(oauth2.sin_zero));

  if(!(ret = connect(fd, (struct sockaddr *)&oauth2, addr_len))) {
    pRedirCtx->oauth2_fd = fd;
  }

  if(ret < 0) {
    fprintf(stderr, "\n%s:%d Connection failed to oauth2\n", __FILE__, __LINE__);
    perror("oauth20:");
  }
  return(ret);
}/*redir_oauth2_connect*/

int32_t redir_uidaiC_connect(void) {
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  int32_t fd;
  int32_t ret = -1;
  struct sockaddr_in uidaiC;
  socklen_t addr_len = sizeof(uidaiC);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  uidaiC.sin_family = AF_INET;
  uidaiC.sin_addr.s_addr = htonl(pRedirCtx->redir_listen_ip);
  uidaiC.sin_port = htons(pRedirCtx->uidaiC_port);

  memset((void *)uidaiC.sin_zero, 0, sizeof(uidaiC.sin_zero));

  if(!(ret = connect(fd, (struct sockaddr *)&uidaiC, addr_len))) {
    pRedirCtx->uidaiC_fd = fd;
  }

  return(ret);
}/*redir_uidaiC_connect*/

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
                                   uint8_t *password) {
  uint8_t acc_req[512];
  uint16_t acc_req_len = 0;
  redir_ctx_t *pRedirCtx = &redir_ctx_g;

  memset((void *)acc_req, 0, sizeof(acc_req));

  access_request_t *access_req_ptr = 
               (access_request_t *)acc_req;

  acc_req_len = sizeof(access_request_t);
  redir_session_t *session = redir_get_session(conn_id);

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

int32_t redir_process_gmail_req(uint32_t conn_id, uint8_t *uri) {

  uint8_t *ext_conn_id = NULL;
  uint8_t req[255];
  uint32_t req_len = 0;
  uint8_t *subtype = NULL;
  uint8_t *ip_ptr = NULL;

  subtype = redir_get_oauth2_param(uri, "subtype");
  ext_conn_id = redir_get_oauth2_param(uri, "conn_id");
  ip_ptr = redir_get_oauth2_param(uri, "ip");

  memset((void *)req, 0, sizeof(req));

  if(!strncmp(subtype, "access_code", 11)) {
    req_len = snprintf(req, 
                       sizeof(req),
                       "%s%s%s%s%d"
                       "%s%s",
                       "/request?type=google_access_code",
                       "&ext_conn_id=",
                       ext_conn_id,
                       "&conn_id=",
                       conn_id,
                       "&ip=",
                       ip_ptr);
  } else if(!strncmp(subtype, "access_token", 12)) {

    uint8_t *code_ptr = redir_get_oauth2_param(uri, "code");
    uint8_t *state_ptr = redir_get_oauth2_param(uri, "state");

    req_len = snprintf(req, 
                       sizeof(req),
                       "%s%s%s%s%s"
                       "%s%s%s%d%s"
                       "%s",
                       "/request?type=google_access_token",
                       "&state=",
                       state_ptr,
                       "&code=",
                       code_ptr,
                       "&ext_conn_id=",
                       ext_conn_id,
                       "&conn_id=",
                       conn_id,
                       "&ip=",
                       ip_ptr);
    free(state_ptr); 
    free(code_ptr);
  }

  fprintf(stderr, "\n%s:%d received for oauth20 %s\n", __FILE__, __LINE__, req);
  redir_send_to_oauth2(conn_id, req, req_len); 

  free(subtype);
  free(ext_conn_id);

  return(0);
}/*redir_process_gmail_req*/

int32_t redir_process_login_req(uint32_t conn_id, uint8_t *uri) {

  uint8_t *ext_conn_ptr = NULL;
  uint8_t *email_ptr = NULL;
  uint8_t *pwd_ptr = NULL;
  uint8_t *ip_ptr = NULL;
  redir_session_t *session = NULL;

  ext_conn_ptr = redir_get_oauth2_param(uri, "conn_id");
  email_ptr = redir_get_oauth2_param(uri, "email_id");
  pwd_ptr = redir_get_oauth2_param(uri, "password");
  ip_ptr = redir_get_oauth2_param(uri, "ip");

  if(ext_conn_ptr && 
     email_ptr &&
     pwd_ptr &&
     ip_ptr) {
    session = redir_get_session(conn_id);
    assert(session != NULL);
    session->conn = conn_id;
    session->ext_conn = atoi(ext_conn_ptr);
    memset(session->ip_str, 0, sizeof(session->ip_str));
    strncpy(session->ip_str, ip_ptr, sizeof(session->ip_str));
    free(ext_conn_ptr);
    free(ip_ptr);
    redir_build_access_request(conn_id, email_ptr, pwd_ptr);    
    free(email_ptr);
    free(pwd_ptr);
    return(0);
  }
  
  return(1);
}/*redir_process_login_req*/

int32_t redir_process_response_callback_uri(uint32_t conn_id, 
                                            uint8_t *uri) {

  uint8_t auth_type[32];

  memset((void *)auth_type, 0, sizeof(auth_type));
  sscanf((const char *)uri, "%*[^?]?auth_type=%[^&]", auth_type);
  
  if(!strncmp((const char *)auth_type, "login", 5)) {
    redir_process_login_req(conn_id, uri);
     
  } else if(!strncmp((const char *)auth_type, "registration",12 )) {

  } else if(!strncmp((const char *)auth_type, "fb", 2)) {
    /*login with Facebook*/
  } else if(!strncmp((const char *)auth_type, "gmail", 5)) {
    redir_process_gmail_req(conn_id, uri);

  } else if(!strncmp((const char *)auth_type, "twitter", 7)) {
 
  } else if(!strncmp((const char *)auth_type, "aadhaar", 7)) {
    redir_process_aadhaar_req(conn_id, uri); 
  }

  return(0);
}/*redir_process_response_callback_uri*/

int32_t redir_recv(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint16_t *packet_length) {
  int32_t  ret = -1;
  uint16_t max_length = 1500;
  do {
    ret = recv(fd, packet_ptr, max_length, 0);

  }while((ret == -1) && (EINTR == errno));

  *packet_length = (ret < 0) ? 0 : ret;

  return(ret);
}/*redir_recv*/

int32_t redir_send(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint16_t packet_length) {
  int32_t  ret = -1;
  int32_t offset = 0;

  do {
    ret = send(fd, 
               (const void *)&packet_ptr[offset], 
               (packet_length - offset), 
               0);

    if(ret > 0) {
      offset += ret;

      if(!(packet_length - offset)) {
        ret = 0;
      }
    }

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
        continue;

      } else {
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
  char *save_ptr;
  uint16_t tmp_len = 0;
  uint16_t line_len = 0;
  redir_session_t *session = NULL;

  redir_ctx_t *pRedirCtx = &redir_ctx_g;

  tmp_ptr = (uint8_t *)malloc(packet_length);

  if(!tmp_ptr) {
    fprintf(stderr, "\n%s:%d Allocation of Memory failed\n", __FILE__, __LINE__);
    return(-1);
  }

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

  session = redir_get_session(conn_id);
  memset((void *)session->method, 0, sizeof(session->method));
  memset((void *)session->protocol, 0, sizeof(session->protocol));
  memset((void *)session->uri, 0, sizeof(session->uri));

  strncpy(session->method, method, sizeof(session->method) - 1);
  strncpy(session->protocol, protocol, sizeof(session->protocol) - 1);
  strncpy(session->uri, uri_ptr, sizeof(session->uri) - 1);

  free(uri_ptr);
  uri_ptr = NULL;

  memset((void *)session->mime_header, 0, sizeof(session->mime_header));

  mime_idx = 0;
  while((line_ptr = strtok_r(NULL, "\r\n", &save_ptr))) { 
    //fprintf(stderr, "\n%s:%d line_ptr %s\n", __FILE__, __LINE__, line_ptr);
    sscanf((const char *)line_ptr, 
           "%[^:]:%*s",
           session->mime_header[mime_idx][0]);

    tmp_len = strlen((const char *)session->mime_header[mime_idx][0]);
    line_len = strlen((const char *)line_ptr);
   #if 0 
    if(!strncmp(session->method, "GET", 3)) {
      
    }
   #endif
    /*If Method is POST then Payload would be followed by an empty line \r\n*/
    if(line_len > tmp_len) {
      memcpy((void *)&session->mime_header[mime_idx][1], 
             (void *)&line_ptr[tmp_len + 2], 
             (line_len - (tmp_len + 2)));
      mime_idx++;
    }
  }

  session->mime_header_count = mime_idx;
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
               /*ip_str*/
               "adam.balaagh.com",
               ":",
               pRedirCtx->uam_port, 
               "/login.html?url=http://",
               session->mime_header[idx][1],
               session->uri);
      break;
    } 
  }
 
  if(idx == session->mime_header_count) {
    fprintf(stderr, "\n%s:%d Host Header not found in mime header\n", 
                     __FILE__, 
                     __LINE__);
    free(referer_ptr);
    referer_ptr = NULL;
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
                            /*"Connection: Keep-Alive\r\n",*/
                            "Connection: close\r\n",
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

int32_t redir_is_connection_close(uint32_t conn_id) {
  redir_session_t *session = NULL;
  uint32_t idx;

  session = redir_get_session(conn_id);
  assert(session != NULL);

  for(idx = 0; idx < session->mime_header_count; idx++) {
    if((!strncmp(session->mime_header[idx][0], "Connection", 10)) && 
       (!strncmp(session->mime_header[idx][1], "close", 5))) {
      return(1);
    }
  }   

  return(0);
}/*redir_is_connection_close*/

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

  //fprintf(stderr, "\n%s:%d REQ(%d) %s\n", __FILE__, __LINE__, conn_id, packet_ptr);
  redir_parse_req(conn_id, packet_ptr, packet_length);

  if(redir_is_connection_close(conn_id)) {
    /*Connection is being closed*/
    return(1);
 
  } else {
    redir_process_uri(conn_id, &redir_ptr, &redir_len);
  }

  if(redir_len) {
    if(redir_send(conn_id, redir_ptr, redir_len) < 0) {
      perror("redir send Failed:");
      return(-1); 
    }

    free(redir_ptr);
  }

  return(0);
}/*redir_process_req*/

int32_t redir_process_radiusS_response(int32_t radiusC_fd,
                                       uint8_t *packet_ptr,
                                       uint16_t packet_length) {

  redir_session_t *session = NULL;
  redir_ctx_t *pRedirCtx = &redir_ctx_g;
  radiusC_message_t *rsp_ptr = (radiusC_message_t *)packet_ptr;
  uint8_t rsp[512];
  uint32_t rsp_len = 0;
 
  memset((void *)rsp, 0, sizeof(rsp));
  session = redir_get_session(rsp_ptr->access_accept.txn_id);

  switch(*packet_ptr) {
    case ACCESS_ACCEPT:
     rsp_len = snprintf(rsp,
                        sizeof(rsp),
                        "%s%s%s%s%d"
                        "%s%s",
                        "/response?type=login",
                        "&subtype=auth",
                        "&status=success",
                        "&conn_id=",
                        session->ext_conn,
                        "&ip=",
                        session->ip_str);

     /*Subscriber is authenticated*/
     subscriber_update_conn_status(session->ip_str, "SUCCESS");
     /*send Response to UAM*/
     redir_send(session->conn, rsp, rsp_len);

    break;
    case ACCESS_REJECT:
     rsp_len = snprintf(rsp,
                        sizeof(rsp),
                        "%s%s%s%s%d"
                        "%s%s",
                        "/response?type=login",
                        "&subtype=auth",
                        "&status=rejected",
                        "&conn_id=",
                        session->ext_conn,
                        "&ip=",
                        session->ip_str);

     /*Subscriber is authenticated*/
     subscriber_update_conn_status(session->ip_str, "REJECTED");
     /*send Response to UAM*/
     redir_send(session->conn, rsp, rsp_len);

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
                   uint16_t uidaiC_port,
                   uint16_t oauth2_port,
                   uint8_t *conn_auth_status_table,
                   uint8_t *ip_allocation_table) {

  int32_t fd = -1;
  struct sockaddr_in redir_addr;
  size_t redir_addr_len;
  redir_ctx_t *pRedirCtx = &redir_ctx_g;

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(fd < 0) {
    fprintf(stderr, "\n%s:%d creation of socket failed\n", 
                    __FILE__, 
                    __LINE__);
    return(-1);
  }
  redir_addr_len = sizeof(struct sockaddr_in);
  redir_addr.sin_addr.s_addr = htonl(redir_listen_ip);
  redir_addr.sin_port = htons(redir_listen_port);
  redir_addr.sin_family = AF_INET;
  memset((void *)redir_addr.sin_zero, 0, sizeof(redir_addr.sin_zero));

  if(bind(fd, (struct sockaddr *)&redir_addr, redir_addr_len) < 0) {
    fprintf(stderr, "\n%s:%d bind to given address failed\n", 
                    __FILE__, 
                    __LINE__);
    perror("Bind Failed: ");
    return(-1);
  }
  
  /*Max Pending connection which is 10 as of now*/
  if(listen(fd, 5) < 0) {
    fprintf(stderr, "\n%s:%d listen to given ip failed\n", 
                    __FILE__, 
                    __LINE__);
    return(-1);
  }

  /*Closing on exit*/
  utility_coe(fd);

  pRedirCtx->redir_listen_ip = redir_listen_ip;
  pRedirCtx->redir_listen_port = redir_listen_port;
  pRedirCtx->uam_ip = uam_ip;
  pRedirCtx->uam_port = uam_port;
  pRedirCtx->radiusC_port = radiusC_port;
  pRedirCtx->uidaiC_port = uidaiC_port;
  pRedirCtx->uidaiC_fd = -1;
  pRedirCtx->oauth2_port = oauth2_port;
  pRedirCtx->oauth2_fd = -1;
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
  size_t peer_addr_len = sizeof(peer_addr);
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

    if(pRedirCtx->uidaiC_fd > 0) {
      FD_SET(pRedirCtx->uidaiC_fd, &rd);
      max_fd = (max_fd > pRedirCtx->uidaiC_fd) ? 
                max_fd : 
                pRedirCtx->uidaiC_fd;
    }

    if(pRedirCtx->oauth2_fd > 0) {
      FD_SET(pRedirCtx->oauth2_fd, &rd);
      max_fd = (max_fd > pRedirCtx->oauth2_fd) ? 
                max_fd : 
                pRedirCtx->oauth2_fd;
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
#if 0
        fprintf(stderr, "\n%s:%d New Connection received conn %d ip %s (port %d)\n", 
                   __FILE__,
                   __LINE__,
                   new_conn, 
                   inet_ntoa(peer_addr.sin_addr),
                   ntohs(peer_addr.sin_port));
#endif
        session = redir_add_session(new_conn); 
        session->peer_addr = peer_addr;
      } 

      if((pRedirCtx->radiusC_fd > 0) && (FD_ISSET(pRedirCtx->radiusC_fd, &rd))) {
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
      } 

      if((pRedirCtx->oauth2_fd > 0) && (FD_ISSET(pRedirCtx->oauth2_fd, &rd))){
        /*Process Response from oauth2*/
        memset((void *)packet_buffer, 0, sizeof(packet_buffer));
        packet_length = 0;
        redir_recv(pRedirCtx->oauth2_fd, packet_buffer, &packet_length);

        if(!packet_length) {
          close(pRedirCtx->oauth2_fd);
          pRedirCtx->oauth2_fd = -1;

        } else {
          redir_process_oauth2_response(pRedirCtx->oauth2_fd, 
                                        packet_buffer, 
                                        packet_length);
        }
      }

      if((pRedirCtx->uidaiC_fd > 0) && (FD_ISSET(pRedirCtx->uidaiC_fd, &rd))) {
        /*Process Request/Response for uidai server*/
        memset((void *)packet_buffer, 0, sizeof(packet_buffer));
        packet_length = 0;
        redir_recv(pRedirCtx->uidaiC_fd, packet_buffer, &packet_length);

        if(!packet_length) {
          close(pRedirCtx->uidaiC_fd);
          pRedirCtx->uidaiC_fd = -1;

        } else {
          redir_process_uidai_response(pRedirCtx->uidaiC_fd, packet_buffer, packet_length);
        }

      }

      /*Process request either from UAM or un-authenticated subscriber*/
      for(session = pRedirCtx->session; session; session = session->next) {
        if(FD_ISSET(session->conn, &rd)) {
          /*Either connection is closed or data has been received.*/
          memset((void *)packet_buffer, 0, sizeof(packet_buffer));
          packet_length = 0;
          redir_recv(session->conn, packet_buffer, &packet_length);

          if((!packet_length) || 
            redir_process_req(session->conn, 
                              packet_buffer, 
                              packet_length)) {
            fprintf(stderr, "\n%s:%d src port %d being closed for zero length\n", 
                          __FILE__,
                          __LINE__,
                          ntohs(peer_addr.sin_port));
            /*Closing the connected conn_id*/
            close(session->conn);
            session->conn = 0;
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
