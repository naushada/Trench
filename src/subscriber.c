#ifndef __SUBSCRIBER_C__
#define __SUBSCRIBER_C__

#include <type.h>
#include <common.h>
#include <db.h>
#include <subscriber.h>

subscriber_ctx_t subscriber_ctx_g;

/********************************************************************
 *Function Definitions
 *
 ********************************************************************/

int32_t subscriber_init(uint8_t *conn_auth_status_table) {
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  strncpy((char *)pSubscriberCtx->conn_auth_status_table, 
          (const char *)conn_auth_status_table,
          strlen((const char *)conn_auth_status_table));

}/*subscriber_init*/

int32_t subscriber_is_authenticated(uint32_t subscriber_ip, uint16_t src_port) { 

  uint8_t ip_str[32];
  uint8_t sql_query[255];
  uint8_t record[2][16][32];
  uint32_t row = 0;
  uint32_t col = 0;  
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(subscriber_ip, ip_str);

  snprintf((char *)sql_query, 
           sizeof(sql_query), 
           "%s%s%s%s%s"
           "%s%s",
           "SELECT * FROM ",
           pSubscriberCtx->conn_auth_status_table,
           " WHERE (ip_address ='",
           ip_str,
           "' AND auth_state ='",
           "SUCCESS",
           "')");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, sizeof(record));

    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      if(row) {
        if(!strncmp((const char *)record[0][4], "INPROGRESS", 10)) {
          return(1);
        } else {
          /*SUCCESS*/
          return(2);
        }
      } 
    }    
  }

  return(0);
}/*subscriber_is_authenticated*/

int32_t subscriber_add_subscriber(uint32_t ip_address, 
                                  uint8_t *src_mac_ptr, 
                                  uint16_t src_port) {

  uint8_t sql_query[255];
  uint8_t ip_str[32];
  uint8_t mac_str[32];
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(ip_address, ip_str);
 
  memset((void *)mac_str, 0, sizeof(mac_str));
  utility_mac_int_to_str(src_mac_ptr, mac_str);

  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%s%s%d%s",
           "INSERT INTO ",
           pSubscriberCtx->conn_auth_status_table,
           " (ip_address, mac_address, uri, host_name, auth_state, src_port) VALUES ('",
           ip_str,
           "', '", 
           mac_str,
           "', '', '', 'INPROGRESS', '",
           src_port,
           "')");

  if(db_exec_query(sql_query)) {
   fprintf(stderr, "\n%s:%d Execution of SQL Query Failed (%s)", __FILE__, __LINE__, sql_query);
   return(-1);
  }

  return(0);
}/*subscriber_add_subscriber*/


int32_t subscriber_add_info(uint32_t ip_address,
                            uint16_t dest_port,
                            uint8_t *uri,
                            uint8_t *auth_state) {

  uint8_t sql_query[255];
  uint8_t ip_str[32];
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(ip_address, ip_str);
 
  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%d%s%s%s%s"
           "%s",
           "INSERT INTO ",
           pSubscriberCtx->conn_auth_status_table,
           " (ip_address, dest_port, uri, auth_state) VALUES ('",
           ip_str,
           "', '", 
           dest_port,
           "', '",
           uri,
           "', '",
           auth_state,
           "')");

  if(db_exec_query(sql_query)) {
   fprintf(stderr, "\n%s:%d Execution of SQL Query Failed (%s)", __FILE__, __LINE__, sql_query);
   return(-1);
  }
  return(0);

}/*subscriber_add_info*/


int32_t subscriber_get_auth_state(uint32_t ip_address, 
                                  uint8_t *auth_state) {

  uint8_t sql_query[255];
  uint8_t ip_str[32];
  uint32_t row;
  uint32_t col;
  uint8_t record[2][16][32];
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(ip_address, ip_str);
 
  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s",
           "SELECT * FROM ",
           pSubscriberCtx->conn_auth_status_table,
           " WHERE ip_address='",
           ip_str,
           "'");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, 2*16*32);
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      if(row) {
        strncpy(auth_state, record[0][3], strlen((const char *)record[0][3]));
        return(0);
      }
    }
  }
  return(-1);
 
}/*subscriber_get_auth_state*/


int32_t subscriber_update_auth_state(uint32_t ip_address, 
                                     uint8_t *auth_state) {

  uint8_t sql_query[255];
  uint8_t ip_str[32];
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(ip_address, ip_str);
 
  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%s%s",
           "UPDATE ",
           pSubscriberCtx->conn_auth_status_table,
           " SET auth_state='",
           auth_state,
           "' WHERE ip_address='",
           ip_str,
           "'");

  if(db_exec_query(sql_query)) {
   fprintf(stderr, "\n%s:%d Execution of SQL Query Failed (%s)", __FILE__, __LINE__, sql_query);
   return(-1);
  }
  return(0);
 
}/*subscriber_update_auth_state*/



#endif /* __SUBSCRIBER_C__ */
