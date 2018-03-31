#ifndef __DB_H__
#define __DB_H__

#include <sqlite3.h>

typedef struct {
  uint8_t server_ip[32];
  uint8_t db_name[32];
  uint8_t user_name[32];
  uint8_t password[32];  
  uint16_t server_port;
}db_cfg_t;

typedef struct {
  sqlite3 *dbHandle;
  char **query_result;
  int32_t rows;
  int32_t cols;
  char  **err_msg;
  
}db_sqlite3_handle_t;

typedef struct {
  db_cfg_t server_config;
  db_sqlite3_handle_t server_handle;

}db_ctx_t;

int db_init(uint8_t *db_name);
int db_exec_query(uint8_t *sql_query);
int db_process_query_result(int *row_count, 
                            int *column_count, 
                            uint8_t  (*result)[16][32]);

#endif /* __DB_H__ */
