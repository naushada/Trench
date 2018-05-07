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

int32_t subscriber_init(uint8_t *conn_auth_status_table,
                        uint8_t *dns_table) {
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  strncpy((char *)pSubscriberCtx->conn_auth_status_table, 
          (const char *)conn_auth_status_table,
          strlen((const char *)conn_auth_status_table));

  strncpy((char *)pSubscriberCtx->dns_table, 
          (const char *)dns_table,
          strlen((const char *)dns_table));

  return(0);
}/*subscriber_init*/

int32_t subscriber_is_authenticated(uint32_t subscriber_ip) { 

  uint8_t ip_str[32];
  uint8_t sql_query[255];
  uint8_t record[2][16][32];
  uint32_t row = 0;
  uint32_t col = 0;  
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(subscriber_ip, ip_str);
  memset((void *)sql_query, 0, sizeof(sql_query));

  /*If it's allowed DNS*/
  snprintf(sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s",
           "SELECT * FROM ",
           pSubscriberCtx->dns_table,
           " WHERE host_ip=\'",
           ip_str,
           "\'");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, sizeof(record));

    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      if(row) {
        /*Allow the request*/
        return(2);
      }
    }
  }
  
  memset((void *)sql_query, 0, sizeof(sql_query));
  snprintf((char *)sql_query, 
           sizeof(sql_query), 
           "%s%s%s%s%s",
           "SELECT * FROM ",
           pSubscriberCtx->conn_auth_status_table,
           " WHERE ip_address ='",
           ip_str,
           "'");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, sizeof(record));

    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      if(row) {
        if(!strncmp((const char *)record[0][1], "INPROGRESS", 10)) {
          return(1);
        } else if(!strncmp((const char *)record[0][1], "SUCCESS", 7)) {
          /*SUCCESS*/
          return(2);
        } else {
          return(0);
        }
      } 
    }    
  }

  return(0);
}/*subscriber_is_authenticated*/

int32_t subscriber_is_present(uint8_t *ip_str) {

  uint8_t sql_query[255];
  uint8_t record[2][16][32];
  uint32_t row = 0;
  uint32_t col = 0;  
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  memset((void *)sql_query, 0, sizeof(sql_query));
  (void)snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s",
           "SELECT * FROM ",
           pSubscriberCtx->conn_auth_status_table,
           " WHERE ip_address='",
           ip_str,
           "'");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, sizeof(record));
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      return(row);  
    }
  }

  return(0);
}/*subscriber_is_present*/


int32_t subscriber_update_conn_status(uint8_t *ip_str,
                                      uint8_t *status) {

  uint8_t sql_query[255];
  subscriber_ctx_t *pSubscriberCtx = &subscriber_ctx_g;

  if(!subscriber_is_present(ip_str)) {
    memset((void *)sql_query, 0, sizeof(sql_query));
    (void)snprintf((char *)sql_query, 
             sizeof(sql_query),
             "%s%s%s%s%s"
             "%s%s",
             "INSERT INTO ",
             pSubscriberCtx->conn_auth_status_table,
             " (ip_address, auth_state) VALUES ('",
             ip_str,
             "', '",
             status, 
             "')"); 

    if(db_exec_query(sql_query)) {
      fprintf(stderr, "\n%s:%d Execution of Query Failed\n",
                      __FILE__,
                      __LINE__);
      return(-1);
    }
  }
 
  return(0);
}/*subscriber_update_conn_status*/




#endif /* __SUBSCRIBER_C__ */
