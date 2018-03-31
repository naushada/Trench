#ifndef __DB_C__
#define __DB_C__

#include <common.h>
#include <db.h>

db_ctx_t mysql_ctx_g;

int db_init(uint8_t *db_conn_info[]) {
  int ret = 0;
  db_ctx_t *pDbCtx = &mysql_ctx_g;

  /*Extracting sql db connection configuration*/
  strncpy((void *)pDbCtx->server_config.server_ip, (const void *)db_conn_info[0], strlen((const char *)db_conn_info[0]));
  strncpy((void *)pDbCtx->server_config.db_name,   (const void *)db_conn_info[1], strlen((const char *)db_conn_info[1]));
  strncpy((void *)pDbCtx->server_config.user_name, (const void *)db_conn_info[2], strlen((const char *)db_conn_info[2]));
  strncpy((void *)pDbCtx->server_config.password,  (const void *)db_conn_info[3], strlen((const char *)db_conn_info[3]));
  pDbCtx->server_config.server_port = (uint16_t)atoi(db_conn_info[4]); 

#ifdef DB_MYSQL
  /*mysql_conn will be allocated by mysql_init and will be freed by invoking mysql_close*/
  pDbCtx->server_handle.mysql_conn = mysql_init(NULL);

  if(NULL == pDbCtx->server_handle.mysql_conn) {
    fprintf(stderr, "\nInsufficient memory to allocate a new object");
    return(ret); 
  }
#elif DB_SQLITE3
  pDbCtx->server_handle.dbHandle = NULL;
  ret = sqlite3_open(pDbCtx->server_config.db_name, &pDbCtx->server_handle.dbHandle);

  if(SQLITE_OK != ret) {
    fprintf(stderr, "\n%s:%d sqlite3 opening Failed\n", __FILE__, __LINE__);
    return(ret);
  }
#endif /* DB_MYSQL */

  return(ret);

}/*db_init*/



int db_connect(void) {
  int ret = -1;

#ifdef DB_MYSQL
  db_ctx_t *pDbCtx = &mysql_ctx_g;
  MYSQL *pConn = NULL;

  ret = -1;
  /*MYSQL *mysql_real_connect(MYSQL *mysql, const char *host, const char *user, 
                              const char *passwd, const char *db, unsigned int port, 
                              const char *unix_socket, unsigned long client_flag)*/
  pConn = mysql_real_connect(pDbCtx->server_handle.mysql_conn,
                             pDbCtx->server_config.server_ip,
                             pDbCtx->server_config.user_name,
                             pDbCtx->server_config.password,
                             pDbCtx->server_config.db_name,
                             pDbCtx->server_config.server_port,
                             NULL, 0);
  
  if((NULL == pConn) || (pConn != pDbCtx->server_handle.mysql_conn)) {
    /*free the allocated memory*/
    mysql_close(pDbCtx->server_handle.mysql_conn);
    pDbCtx->server_handle.mysql_conn = NULL;
    fprintf(stderr, "\nConnection to database failed");
    return(ret);
  }
#endif /* DB_MYSQL */
  /*upon success pConn will be same as pDbCtx->server_handle.mysql_conn*/
  ret = 0;
  return(ret);
}/*db_connect*/

int db_exec_query(uint8_t *sql_query) {
  int ret = -1;
  db_ctx_t *pDbCtx = &mysql_ctx_g;
 
#ifdef DB_MYSQL 
  /*int mysql_query(MYSQL *mysql, const char *stmt_str)*/ 
  ret = mysql_query(pDbCtx->server_handle.mysql_conn, (const char *)sql_query);

  if(ret) {
    fprintf(stderr, "\nExecution of query %s failed", sql_query);
    return(ret);
  }
  
  pDbCtx->server_handle.mysql_query_result = mysql_store_result(pDbCtx->server_handle.mysql_conn);

#elif DB_SQLITE3
  pDbCtx->server_handle.query_result = NULL;
  pDbCtx->server_handle.rows = 0;
  pDbCtx->server_handle.cols = 0;   
#if 0
  int sqlite3_get_table(
  sqlite3 *db,          /* An open database */
  const char *zSql,     /* SQL to be evaluated */
  char ***pazResult,    /* Results of the query */
  int *pnRow,           /* Number of result rows written here */
  int *pnColumn,        /* Number of result columns written here */
  char **pzErrmsg       /* Error msg written here */
);
#endif
  ret = sqlite3_get_table(pDbCtx->server_handle.dbHandle,
                          (const char *)sql_query,
                          &pDbCtx->server_handle.query_result,
                          &pDbCtx->server_handle.rows, 
                          &pDbCtx->server_handle.cols, 
                          pDbCtx->server_handle.err_msg);
  if(SQLITE_OK != ret) {
   fprintf(stderr, "\n%s:%d Execution of Query (%s) Failed\n", __FILE__, __LINE__, sql_query); 
   return(-1);
  } 
#endif /* DB_MYSQL */
  return(0);
 
}/*db_exec_query*/

int db_process_query_result(int *row_count, int *column_count, uint8_t (*result)[16][32]) {
  int ret = -1;
  int row = -1;
  int col = -1;
  uint16_t len;
  db_ctx_t *pDbCtx = &mysql_ctx_g;

#ifdef DB_MYSQL
  MYSQL_ROW  record;
  /*my_ulonglong mysql_num_rows(MYSQL_RES *result)*/
  row = (int) mysql_num_rows(pDbCtx->server_handle.mysql_query_result);
  *row_count = row;

  /*unsigned int mysql_field_count(MYSQL *mysql)*/ 
  col = (unsigned int) mysql_field_count(pDbCtx->server_handle.mysql_conn);
  *column_count = col;

  for(row = 0; row < *row_count; row++) {
    /*Retrieve the row of a given table*/
    record = mysql_fetch_row(pDbCtx->server_handle.mysql_query_result);
     
    /*unsigned long *mysql_fetch_lengths(MYSQL_RES *result)*/
    len = mysql_fetch_lengths(pDbCtx->server_handle.mysql_query_result);

    for(col = 0; col < *column_count; col++) {
      memcpy((void *)result[row][col], record[col], len[col]);
    }
  }

#elif DB_SQLITE3
  *row_count = pDbCtx->server_handle.rows;
  *column_count = pDbCtx->server_handle.cols;
 
  /*In SQLITE3 , first row and col represents the Actual field name*/
  /*(N+1)*M elements in the array. Where N = ROWS and M = Column*/
  uint16_t tmp_col; uint16_t tmp_row;
  /*First row is the Table Header in SQLITE3*/
  for(tmp_row = 0, row = 0; row < *row_count; row++, tmp_row++) {
    for(tmp_col = 0, col = 0; col < *column_count; tmp_col++, col++) {
#if 0
      fprintf(stderr, "\n%s:%d (%d) %s\n",
                       __FILE__, 
                       __LINE__,
                       *row_count,
                       pDbCtx->server_handle.query_result[((row + 1) * *column_count) + col]);
#endif
      if((NULL == pDbCtx->server_handle.query_result[((row + 1) * *column_count) + col]) && (1 == *column_count)) {
        /*(N+1)*M elements in the array. Where N = ROWS and M = Column*/
        *row_count = 0;
        break;
      } else {
        len = strlen((const char *)pDbCtx->server_handle.query_result[((row + 1) * *column_count) + col]);
        memcpy((void *)result[tmp_row][tmp_col], 
               (const void *)pDbCtx->server_handle.query_result[((row + 1) * *column_count) + col], 
               len);
      }
    }
  }

  /*Freeing the Heap allocated by SQLITE3*/
  sqlite3_free_table(pDbCtx->server_handle.query_result);
  pDbCtx->server_handle.query_result = NULL;

#endif /* DB_MYSQL */
  ret = 0;
  return(ret);
}/*db_process_query_result*/

#endif /* __DB_C__ */

