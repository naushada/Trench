#ifndef __DB_H__
#define __DB_H__

#ifdef DB_MYSQL
#include <mysql.h>
#elif DB_SQLITE3
#include <sqlite3.h>
#endif /* DB_MYSQL */

#ifdef DB_SQLITE3
#define DB_NAME ".dd_s_db"
#endif /* DB_SQLITE3 */

typedef struct {
  uint8_t server_ip[32];
  uint8_t db_name[32];
  uint8_t user_name[32];
  uint8_t password[32];  
  uint16_t server_port;
}db_cfg_t;

#ifdef DB_MYSQL
typedef struct {
  MYSQL     *mysql_conn;
  MYSQL_RES *mysql_query_result;
 
}db_mysql_handle_t;

#elif DB_SQLITE3
typedef struct {
  sqlite3 *dbHandle;
  char **query_result;
  int32_t rows;
  int32_t cols;
  char  **err_msg;
  
}db_sqlite3_handle_t;
#endif /* DB_MYSQL */

typedef struct {
  db_cfg_t server_config;

#ifdef DB_MYSQL
  db_mysql_handle_t server_handle;
#elif DB_SQLITE3
  db_sqlite3_handle_t server_handle;
#endif /* DB_MYSQL */

}db_ctx_t;

int db_init(uint8_t *db_conn_info[]);
int db_connect(void);
int db_exec_query(uint8_t *sql_query);
int db_process_query_result(int *row_count, 
                            int *column_count, 
                            uint8_t  (*result)[16][32]);

#endif /* __DB_H__ */
