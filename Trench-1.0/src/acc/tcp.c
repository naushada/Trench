#ifndef __TCP_C__
#define __TCP_C__

#include <type.h>
#include <transport.h>
#include <common.h>
#include <tun.h>
#include <utility.h>
#include <nat.h>
#include <net.h>
#include <tcp.h>
#include <subscriber.h>

/********************************************************************
 *Global Definition
 *
 ********************************************************************/
tcp_ctx_t tcp_ctx_g;

/********************************************************************
 *Function Definitions
 *
 ********************************************************************/
int32_t tcp_init(uint32_t ip_addr, 
                 uint32_t ip_mask,
                 uint16_t uamS_port,
                 uint16_t redir_port) {

  tcp_ctx_t *pTcpCtx = &tcp_ctx_g;

  pTcpCtx->ip_addr = ip_addr;
  pTcpCtx->ip_mask = ip_mask;
  pTcpCtx->uamS_port = uamS_port;
  pTcpCtx->redir_port = redir_port;
 
  return(0); 
}/*tcp_init*/

uint16_t tcp_checksum(uint8_t *packet_ptr) {
  uint8_t *tcp_pseudo_header = NULL;
  uint16_t tmp_len = 0;
  uint16_t offset = 0;
  uint16_t ip_header_len = 0;
  uint16_t checksum = 0;
  struct iphdr *iphdr_ptr = (struct iphdr *)packet_ptr;

  ip_header_len = (iphdr_ptr->ip_len * 4);

  /*TCP pseudo header*/
  tmp_len = (ntohs(iphdr_ptr->ip_tot_len) - ip_header_len) + 12/*pseudo header length*/;

  tcp_pseudo_header = (uint8_t *)malloc(tmp_len);

  if(NULL == tcp_pseudo_header) {
    fprintf(stderr, "\n%s:%d memory allocation failed\n", 
                    __FILE__, 
                    __LINE__);
    exit(0);
  }
  memset((void *)tcp_pseudo_header, 0, tmp_len);
        
  /*Source IP*/
  *((uint32_t *)&tcp_pseudo_header[offset]) = iphdr_ptr->ip_src_ip;
  offset += 4;
  /*Destination IP*/
  *((uint32_t *)&tcp_pseudo_header[offset]) = iphdr_ptr->ip_dest_ip;
  offset += 4;
  /*Reserved*/
  tcp_pseudo_header[offset] = 0;
  offset += 1;
  /*Protocol from ip header*/
  tcp_pseudo_header[offset] = iphdr_ptr->ip_proto;
  offset += 1;

  /*TCP Length*/
  *((uint16_t *)&tcp_pseudo_header[offset]) = 
               htons(ntohs(iphdr_ptr->ip_tot_len) - ip_header_len);
  offset += 2;

  /*copy the header + payload*/
  memcpy((void *)&tcp_pseudo_header[offset], 
         (const void *)&packet_ptr[ip_header_len], 
         (ntohs(iphdr_ptr->ip_tot_len) - ip_header_len));

  offset += ntohs(iphdr_ptr->ip_tot_len) - ip_header_len;

  checksum = utility_cksum((void *)tcp_pseudo_header, offset);

  /*freeing the allocated one*/
  free(tcp_pseudo_header);
  tcp_pseudo_header = NULL;

  return(checksum);
}/*tcp_checksum*/

int32_t tcp_reset_tcp(uint8_t *packet_ptr, 
                      uint16_t packet_length, 
                      uint8_t *rsp_ptr, 
                      uint16_t *rsp_len_ptr) {

  struct iphdr *req_ip_ptr;
  struct tcp *req_tcp_ptr;
  struct eth *req_eth_ptr;

  struct iphdr *rsp_ip_ptr;
  struct tcp *rsp_tcp_ptr;
  struct eth *rsp_eth_ptr;

  uint16_t tmp_flags;

  req_eth_ptr = (struct eth *)packet_ptr;
  req_ip_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)];
  req_tcp_ptr = (struct tcp *)&packet_ptr[sizeof(struct eth) + sizeof(struct iphdr)];
  
  rsp_eth_ptr = (struct eth *)rsp_ptr;
  rsp_ip_ptr = (struct iphdr *)&rsp_ptr[sizeof(struct eth)];
  rsp_tcp_ptr = (struct tcp *)&rsp_ptr[sizeof(struct eth) + sizeof(struct iphdr)];

  /*copy received ether nemt frame into response buffer*/
  memcpy((void *)rsp_ptr, (const void *)packet_ptr, packet_length);

  /*Prepare response ethernet frame by swapping ether net address*/
  memcpy((void *)rsp_eth_ptr->h_dest, req_eth_ptr->h_source, ETH_ALEN);
  memcpy((void *)rsp_eth_ptr->h_source, req_eth_ptr->h_dest, ETH_ALEN);

  /*swap the ip address*/
  rsp_ip_ptr->ip_src_ip = req_ip_ptr->ip_dest_ip;
  rsp_ip_ptr->ip_dest_ip = req_ip_ptr->ip_src_ip;
  /*Reset checksum*/
  rsp_ip_ptr->ip_chksum = 0;

  /*swap the TCP port*/ 
  rsp_tcp_ptr->src_port = req_tcp_ptr->dest_port;
  rsp_tcp_ptr->dest_port = req_tcp_ptr->src_port;
  /*Updating Sequence Number*/
  rsp_tcp_ptr->seq_num = req_tcp_ptr->ack_number;
  /*No ACK is expected*/
  rsp_tcp_ptr->ack_number = 0;
  rsp_tcp_ptr->window = 0;
  
  /*resetting the checksum*/
  rsp_tcp_ptr->check_sum = 0;
  /*modifying the TCP flags to exhibits the RST bit*/
  tmp_flags = ntohs(rsp_tcp_ptr->flags);
  tmp_flags = htons((tmp_flags & ~(0x3F)) | TCP_RST_BIT);
  rsp_tcp_ptr->flags = tmp_flags; 

  /*calculate the check sum*/
  rsp_ip_ptr->ip_chksum = utility_cksum((void *)rsp_ip_ptr, (4 * rsp_ip_ptr->ip_len));
  rsp_tcp_ptr->check_sum = tcp_checksum((uint8_t *)rsp_ip_ptr);
 
  *rsp_len_ptr = packet_length;

  return(0); 
}/*tcp_reset_tcp*/

int32_t tcp_main(uint16_t fd, 
                 uint8_t *packet_ptr, 
                 uint16_t packet_length) {

  struct iphdr *iphdr_ptr;
  struct tcp *tcphdr_ptr;
  tcp_ctx_t *pTcpCtx = &tcp_ctx_g;
  uint8_t  rsp[1500];
  uint16_t rsp_len = 0;
  uint8_t dest_mac[ETH_ALEN];
  int32_t  ret = -1;

  iphdr_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)];
  tcphdr_ptr = (struct tcp *)&packet_ptr[sizeof(struct eth) + sizeof(struct iphdr)];

  memset((void *)rsp, 0, sizeof(rsp));
  rsp_len = 0;

  /*Passthrough the walled gardened*/
  if(2 == subscriber_is_authenticated(iphdr_ptr->ip_dest_ip)) {
 
    /*Subscriber is Authenticated Successfully, Pass the packet on*/
    rsp_len = packet_length - sizeof(struct eth);
    memcpy((void *)rsp, 
           (const void *)&packet_ptr[sizeof(struct eth)], 
           rsp_len);

    ret = tun_write(rsp, rsp_len);

    if(ret < 0) {
      perror("\nwriting to tun failed\n");
      return(-1);
    }

    return(0);
  }

  ret = subscriber_is_authenticated(iphdr_ptr->ip_src_ip);
  /* TCP Connection will be marked as INPROGRESS when 3-way
   * hand shake is performed for any connection and is done in redir.c
   * because redir.c operates at tcp layer and only it knows when 3-way hand shake is done
   * i.e. after accepting a new connection by accept system call.
   */
  if((2/*AUTHENTICATED*/ == ret) ||
     (ntohs(tcphdr_ptr->dest_port) == pTcpCtx->uamS_port) ||
     (ntohs(tcphdr_ptr->dest_port) == pTcpCtx->redir_port)) {

    /*Subscriber is Authenticated Successfully, Pass the packet on*/
    rsp_len = packet_length - sizeof(struct eth);
    memcpy((void *)rsp, 
           (const void *)&packet_ptr[sizeof(struct eth)], 
           rsp_len);

    ret = tun_write(rsp, rsp_len);

    if(ret < 0) {
      perror("\nwriting to tun failed\n");
      return(-1);
    }   
  } else if((1/*INPROGRESS*/ == ret) && 
            (!nat_query_cache(ntohs(tcphdr_ptr->src_port),
                              iphdr_ptr->ip_src_ip,
                               NULL, NULL, NULL))) {
    /* There could be possibility that subsequent packet may 
     * be sent at detination port other than 80
     */
    /*Reset the connection*/  
    tcp_reset_tcp(packet_ptr, packet_length, rsp, &rsp_len);
    memset((void *)dest_mac, 0, sizeof(dest_mac));
    /*copying the destination MAC Address*/
    memcpy((void *)dest_mac, rsp, ETH_ALEN);
    write_eth_frame(fd, dest_mac, rsp, rsp_len);

  } else {
    /*SYN Packet for new TCP connection*/
    if(80 != ntohs(tcphdr_ptr->dest_port)) {
      /*Reset the connection*/  
      tcp_reset_tcp(packet_ptr, packet_length, rsp, &rsp_len);
      memset((void *)dest_mac, 0, sizeof(dest_mac));
      /*copying the destination MAC Address*/
      memcpy((void *)dest_mac, rsp, ETH_ALEN);
      write_eth_frame(fd, dest_mac, rsp, rsp_len);

    } else {
      /*Request is for other*/
      nat_perform_snat(packet_ptr, 
                       packet_length, 
                       (uint8_t *)rsp, 
                       &rsp_len);

      //utility_hex_dump(buffer, buffer_len);
      ret = tun_write(rsp, rsp_len);

      if(ret < 0) {
        perror("\nwriting to tun failed\n");
        return(-1);
      }
    }
  }

  return(0);
}/*tcp_main*/


#endif /* __TCP_C__ */
