#ifndef __DB_C__
#define __DB_C__

#include <common.h>
#include <db.h>

db_ctx_t mysql_ctx_g;

int db_init(uint8_t *db_name) {
  int ret = 0;
  db_ctx_t *pDbCtx = &mysql_ctx_g;

  strncpy((void *)pDbCtx->server_config.db_name,
          (const void *)db_name, 
          strlen((const char *)db_name));

  pDbCtx->server_handle.dbHandle = NULL;
  ret = sqlite3_open(pDbCtx->server_config.db_name, 
                     &pDbCtx->server_handle.dbHandle);

  if(SQLITE_OK != ret) {
    fprintf(stderr, "\n%s:%d sqlite3 opening Failed\n", __FILE__, __LINE__);
    return(ret);
  }

  return(ret);
}/*db_init*/

int db_exec_query(uint8_t *sql_query) {
  int ret = -1;
  db_ctx_t *pDbCtx = &mysql_ctx_g;

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
   fprintf(stderr, "\n%s:%d Execution of Query (%s) Failed\n", 
                    __FILE__, 
                    __LINE__, 
                    sql_query); 
   return(-1);
  }
 
  return(0);
}/*db_exec_query*/

int db_process_query_result(int *row_count, 
                            int *column_count, 
                            uint8_t (*result)[16][32]) {
  int ret = -1;
  int row = -1;
  int col = -1;
  uint16_t len;
  db_ctx_t *pDbCtx = &mysql_ctx_g;

  *row_count = pDbCtx->server_handle.rows;
  *column_count = pDbCtx->server_handle.cols;
 
  /*In SQLITE3 , first row and col represents the Actual field name*/
  /*(N+1)*M elements in the array. Where N = ROWS and M = Column*/
  uint16_t tmp_col; uint16_t tmp_row;
  /*First row is the Table Header in SQLITE3*/
  for(tmp_row = 0, row = 0; row < *row_count; row++, tmp_row++) {
    for(tmp_col = 0, col = 0; col < *column_count; tmp_col++, col++) {
      if((1 == *column_count) && 
        (NULL == pDbCtx->server_handle.query_result[((row + 1) * *column_count) + col])) {
        /*(N+1)*M elements in the array. Where N = ROWS and M = Column*/
        *row_count = 0;
        break;
      } else {
        if(pDbCtx->server_handle.query_result) {
          len = strlen((const char *)pDbCtx->server_handle.query_result[((row + 1) * *column_count) + col]);
          memcpy((void *)result[tmp_row][tmp_col], 
                 (const void *)pDbCtx->server_handle.query_result[((row + 1) * *column_count) + col], 
                 len);
        }
      }
    }
  }

  /*Freeing the Heap allocated by SQLITE3*/
  sqlite3_free_table(pDbCtx->server_handle.query_result);
  pDbCtx->server_handle.query_result = NULL;

  ret = 0;
  return(ret);
}/*db_process_query_result*/

#endif /* __DB_C__ */

