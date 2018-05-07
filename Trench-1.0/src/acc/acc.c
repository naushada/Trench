#ifndef __ACC_C__
#define __ACC_C__

#include <common.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <type.h>
#include <eapol/eapol.h>
#include <dhcp.h>
#include <dns.h>
#include <acc.h>
#include <db.h>
#include <redir.h>
#include <uam/http.h>
#include <icmp.h>
#include <nat.h>
#include <net.h>
#include <tcp.h>
#include <utility.h>
#include <tun.h>
#include <arp.h>
#include <radiusC.h>
#include <subscriber.h>
#include <uidai/uidai.h>
#include <oauth20/oauth20.h>

acc_ctx_t acc_ctx_g;

/** @brief This function invoked when user has pressed CTRL + C and then 
 *         it sends the same signal to all running thread for its clean up
 *
 *  @param signo is the gignal number has been received
 *  @param info is the pointer to siginfo which is not used as of now
 *  @param context which is the pointer to void and not used as of now
 */
void acc_signal_handler(int32_t signo, 
                        siginfo_t *info, 
                        void *context) {
  acc_ctx_t *pAccCtx = &acc_ctx_g;
  uint16_t idx;

  if(SIGINT == signo) {
    /*CTRL+C has been pressed*/
    fprintf(stderr, "\n%s:%d Ctrl + C has been pressed\n",
                    __FILE__,
                    __LINE__);

    for(idx = 0; idx < 7; idx++) {
      pthread_kill(pAccCtx->tid[idx], SIGINT);
    }
  }

}/*acc_signal_handler*/

/** @brief this function is used to register the signal handler
 *
 *  @param sig is the signal number for which signal handler to be registered
 *
 *  @return upon success, it returns 0 else < 0
 */
int32_t acc_register_signal(uint32_t sig) {
  struct sigaction sa;

  memset((void *)&sa, 0, sizeof(struct sigaction));
  sa.sa_sigaction = acc_signal_handler;
  sa.sa_flags = SA_SIGINFO;

  if(sigaction(sig, &sa, NULL)) {
    fprintf(stderr, "\n%s:%d Installing of signal Failed\n", 
                    __FILE__, 
                    __LINE__);
    return(-1);
  }

  return(0);
}/*acc_register_signal*/

/** @brief This function establishes connection with DB
 *         be it sqlit3 or mysql
 *  @param server_ip ppointer to DB Server IP
 *  @param server_port is the DB server port listening to connection
 *  @param db_name is the data base name
 *  @param password is the password required to connect mysql server
 *
 *  @return upon success returns 0 else < 0
 */
int32_t acc_preinit(uint8_t *db_name) {

  db_init(db_name);

  return(0);
}/*acc_preinit*/

/** @brief This function initializes the global with configuration
 *
 *  @param row this is the row number of record
 *  @param record is holding the record read from DB
 *  @return upon success returns 0 else < 0
 */
int32_t acc_init_conf(int32_t row, uint8_t (*record)[16][32]) {
  uint16_t idx;
  acc_ctx_t *pAccCtx = &acc_ctx_g;

  for(idx = 0; idx < row; idx++) {

    if(!strncmp(record[idx][0], "ip_addr", 7)) {
      pAccCtx->ip_addr = utility_ip_str_to_int(record[idx][1]);
      pAccCtx->dhcpS_param.ns1 = pAccCtx->ip_addr;

    } else if(!strncmp(record[idx][0], "lan_interface", 13)) {
      strncpy(pAccCtx->eth_name, record[idx][1], strlen((const char *)record[idx][1]));

    } else if(!strncmp(record[idx][0], "network_id", 10)) {
      pAccCtx->dhcpS_param.network_id = utility_network_id_str_to_int(record[idx][1]);

    } else if(!strncmp(record[idx][0], "host_id", 7)) {
      pAccCtx->dhcpS_param.host_id_start = atoi(record[idx][1]);

    } else if(!strncmp(record[idx][0], "max_host_id", 11)) {
      pAccCtx->dhcpS_param.host_id_end = atoi(record[idx][1]);

    } else if(!strncmp(record[idx][0], "cidr", 4)) {
      pAccCtx->cidr = atoi(record[idx][1]);
      pAccCtx->dhcpS_param.subnet_mask = 0xFFFFFFFF & ((~0) << (32 - pAccCtx->cidr));

    } else if(!strncmp(record[idx][0], "domain_name", 11)) {
      strncpy(pAccCtx->dhcpS_param.domain_name, record[idx][1], strlen((const char *)record[idx][1]));
      
    } else if(!strncmp(record[idx][0], "mtu", 3)) {
      pAccCtx->dhcpS_param.mtu = atoi(record[idx][1]);

    } else if(!strncmp(record[idx][0], "lease", 5)) {
      pAccCtx->dhcpS_param.lease = atoi(record[idx][1]);
      
    } else if(!strncmp(record[idx][0], "dns1", 4)) {
      pAccCtx->dns1 = utility_ip_str_to_int(record[idx][1]);

    } else if(!strncmp(record[idx][0], "dns2", 4)) {
      pAccCtx->dns2 = utility_ip_str_to_int(record[idx][1]);
    
    } else if(!strncmp(record[idx][0], "ntp_server", 10)) {
      pAccCtx->dhcpS_param.ntp_ip = utility_ip_str_to_int(record[idx][1]);
      
    } else if(!strncmp(record[idx][0], "time_server", 11)) {
      pAccCtx->dhcpS_param.time_ip = utility_ip_str_to_int(record[idx][1]);

    } else if(!strncmp(record[idx][0], "uamS_ip", 7)) {
      pAccCtx->uamS_ip = utility_ip_str_to_int(record[idx][1]);
   
    } else if(!strncmp(record[idx][0], "uamS_port", 9)) {
      pAccCtx->uamS_port = atoi(record[idx][1]);
   
    } else if(!strncmp(record[idx][0], "radiusC_ip", 10)) {
      pAccCtx->radiusC_ip = utility_ip_str_to_int(record[idx][1]);
   
    } else if(!strncmp(record[idx][0], "radiusC_port", 12)) {
      pAccCtx->radiusC_port = atoi(record[idx][1]);
   
    } else if(!strncmp(record[idx][0], "radiusS_ip", 10)) {
      pAccCtx->radiusS_ip = utility_ip_str_to_int(record[idx][1]);
   
    } else if(!strncmp(record[idx][0], "redir_port", 10)) {
      pAccCtx->redir_port = atoi(record[idx][1]);
   
    } else if(!strncmp(record[idx][0], "redir_ip", 8)) {
      pAccCtx->redir_ip = utility_ip_str_to_int(record[idx][1]);
   
    } else if(!strncmp(record[idx][0], "uidaiC_port", 11)) {
      pAccCtx->uidaiC_port = atoi(record[idx][1]);
   
    } else if(!strncmp(record[idx][0], "oauth2_port", 11)) {
      pAccCtx->oauth2_port = atoi(record[idx][1]);
   
    }

  }
  
  return(0);
}/*acc_init_conf*/

/** @brief this function initialises DB connection and global 
 *         parameters required for other sub-component.
 *  @param argv pointer to an array of char which holds the connection parameters
 *         for database
 *
 *  @return upon success it returns 0 else < 0
 */
int32_t acc_init(char *argv[]) {

  uint8_t sql_query[64];
  int32_t row;
  int32_t col;
  uint8_t record[40][16][32];

  acc_preinit(argv[1]);

  snprintf(sql_query,
           sizeof(sql_query),
           "%s%s",
           "SELECT * FROM ",
           ACC_CONF_TABLE);

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, sizeof(record));
    row = 0, col = 0;
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      if(row) {
        acc_init_conf(row, record);
        return(0); 
      }
    }
  }   

  return(0);
}/*acc_int*/

/** @brief This function is the main function for access controller 
 *         which spawns several threads.
 *  @param argv pointer to char for command line arguments
 *
 *  @return upon success returns 0 else < 0
 */
int32_t acc_main(char *argv[]) {

  acc_ctx_t *pAccCtx = &acc_ctx_g;

  /*Registering the SIGNAL*/
  acc_register_signal(SIGINT);

  acc_init(argv);

  dhcp_init(pAccCtx->eth_name,
            pAccCtx->ip_addr,
            &pAccCtx->dhcpS_param,
            ACC_IP_ALLOCATION_TABLE); 

  net_init(pAccCtx->eth_name);

  nat_init(pAccCtx->ip_addr,
           pAccCtx->dns1,
           pAccCtx->dns2, 
           pAccCtx->redir_ip,
           /*redir_port*/
           pAccCtx->redir_port,
           pAccCtx->uamS_ip,
           pAccCtx->uamS_port,
           ACC_CACHE_TABLE);

  eapol_init(pAccCtx->eth_name,
             pAccCtx->radiusC_ip,
             pAccCtx->radiusC_port);

  subscriber_init(ACC_CON_AUTH_STATUS_TABLE,
                  ACC_DNS_TABLE);

  /* The Flow of message is 
   * LAN <--> TUN <--> WAN Interface
   * It is tunnel mode communication.
   */
  tun_init(pAccCtx->ip_addr, 
           pAccCtx->ip_addr, 
           pAccCtx->dhcpS_param.subnet_mask,
           pAccCtx->eth_name);
  
  pthread_create(&pAccCtx->tid[0], 
                 NULL, 
                 tun_main, 
                 (void *)&pAccCtx->tid[0]);

  redir_init(pAccCtx->redir_ip,
             /*Listening Port*/
             pAccCtx->redir_port,
             pAccCtx->uamS_ip,
             pAccCtx->uamS_port,
             pAccCtx->radiusC_port,
             pAccCtx->uidaiC_port,
             pAccCtx->oauth2_port,
             ACC_CON_AUTH_STATUS_TABLE,
             ACC_IP_ALLOCATION_TABLE); 

  pthread_create(&pAccCtx->tid[1], 
                 NULL, 
                 redir_main, 
                 (void *)&pAccCtx->tid[1]);

  radiusC_init(pAccCtx->radiusC_ip,
               /*radiusC_listen Port*/
               pAccCtx->radiusC_port,
               /*Radius Server IP*/
               pAccCtx->radiusS_ip,
               "radius_server_secret");

  pthread_create(&pAccCtx->tid[2], 
                 NULL, 
                 radiusC_main, 
                 (void *)&pAccCtx->tid[2]);
 
  /*http thread must spawned after radiusC - radius Client*/ 
  http_init(pAccCtx->uamS_ip,
            pAccCtx->uamS_port,
            /*uamC IP*/
            pAccCtx->redir_ip,
            /*uamC_port*/
            pAccCtx->redir_port);

  pthread_create(&pAccCtx->tid[3], 
                 NULL, 
                 http_main, 
                 (void *)pAccCtx->tid[3]);
  
  dns_init(pAccCtx->dhcpS_param.domain_name,
           pAccCtx->ip_addr,
           /*NULL means it will reads the system's name*/
           NULL,
           ACC_IP_ALLOCATION_TABLE,
           ACC_DNS_TABLE);

  arp_init(pAccCtx->eth_name, 
           pAccCtx->ip_addr); 

  icmp_init(pAccCtx->ip_addr, 
            pAccCtx->dhcpS_param.subnet_mask);

  tcp_init(pAccCtx->ip_addr, 
           pAccCtx->dhcpS_param.subnet_mask,
           pAccCtx->uamS_port,
           pAccCtx->redir_port);

  uidai_init(pAccCtx->ip_addr,
             pAccCtx->uidaiC_port,
             "developer.uidai.gov.in",
             80,
             "public",
             "public",
             "MEaMX8fkRa6PqsqK6wGMrEXcXFl_oXHA-YuknI2uf0gKgZ80HaZgG3A",
             "../keys/uidai_auth_stage.cer"
             /*"../keys/uidai_auth_sign_preprod.cer"*/
             /*"../keys/uidai_auth_encrypt_preprod.cer"*/
             /*"../keys/uidai_auth_prod.cer"*/,
             "../keys/Staging_Signature_PrivateKey.p12");

  pthread_create(&pAccCtx->tid[4], 
                 NULL, 
                 uidai_main, 
                 (void *)pAccCtx->tid[4]);

  oauth20_init("googleapis.com",
               pAccCtx->ip_addr,
               pAccCtx->oauth2_port);
  
  pthread_create(&pAccCtx->tid[5], 
                 NULL, 
                 oauth20_main, 
                 (void *)pAccCtx->tid[5]);

  pthread_create(&pAccCtx->tid[6], 
                 NULL, 
                 dhcp_main, 
                 (void *)pAccCtx->tid[6]);

  pthread_create(&pAccCtx->tid[7], 
                 NULL, 
                 eapol_recv_main, 
                 (void *)pAccCtx->tid[7]);
 
}/*acc_main*/

/** @brief This function is the main function for executable 
 *         which spawns several threads.
 *  @param argv pointer to char for command line arguments
 *
 *  @return upon success returns 0 else < 0
 */
int main(int32_t argc, char *argv[]) {
  uint16_t idx;
  acc_ctx_t *pAccCtx = &acc_ctx_g;
  void *tret_id;

  acc_main(argv);  

  for(idx = 0; idx < 8; idx++ ) {
    pthread_join(pAccCtx->tid[idx], &tret_id);
  }

}/*main*/

#endif /* __ACC_C__ */
