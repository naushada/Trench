#ifndef __DNS_C__
#define __DNS_C__

#include <type.h>
#include <transport.h>
#include <db.h>
#include <subscriber.h>
#include <dns.h>
#include <utility.h>
#include <tun.h>
#include <nat.h>
#include <net.h>

/*Global Variable*/
dns_ctx_t dns_ctx_g;

/** @brief this function initialises the global param for its subsequent use
 *
 *  @param domain_name is the domain name controlled by name server
 *  @param ip_addr is the ip address of name server
 *  @param host_name is the name of name server
 *  @param ip_allocation_table is the name of the database table
 *
 *  @return upon success it returns 0 else < 0
 */
uint32_t dns_init(uint8_t *domain_name,
                  uint32_t ip_addr,
                  uint8_t *ns1_name,
                  uint8_t *ip_allocation_table,
                  uint8_t *dns_table) {

  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  
  pDnsCtx->ns1_ip = ip_addr;
  
  memcpy((void *)pDnsCtx->domain_name, 
         (const void *)domain_name, 
         strlen((const char *)domain_name));

  if(!ns1_name) {
    gethostname(pDnsCtx->ns1_name, sizeof(pDnsCtx->ns1_name));

  } else {
    memcpy((void *)pDnsCtx->ns1_name, 
           (const void *)ns1_name, 
           strlen((const char *)ns1_name));
  }

  memcpy((void *)pDnsCtx->ip_allocation_table, 
         (const void *)ip_allocation_table, 
         strlen((const char *)ip_allocation_table));

  memcpy((void *)pDnsCtx->walled_garden_table, 
         (const void *)dns_table, 
         strlen((const char *)dns_table));

  return(0);
}/*dns_init*/

int32_t dns_build_dns_req(uint8_t *wall_gardened) {
  uint32_t idx;
  uint8_t *req_ptr = NULL;
  uint32_t req_size = 1500;
  uint32_t offset = 0;
  uint8_t tmp_dname[1024];
  uint8_t *line_ptr = NULL;
  int32_t ret = -1;
  dns_ctx_t *pDnsCtx = &dns_ctx_g;

  req_ptr = (uint8_t *)malloc(sizeof(uint8_t) * req_size);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, (sizeof(uint8_t) * req_size));

  struct iphdr  *ip_ptr  = (struct iphdr  *)req_ptr;
  struct udphdr *udp_ptr = (struct udphdr *)&req_ptr[sizeof(struct iphdr)];
  struct dnshdr *dns_ptr = (struct dnshdr *)&req_ptr[sizeof(struct iphdr) + sizeof(struct udphdr)];

  /*Filling IP Header*/
  ip_ptr->ip_len         = 0x5;
  ip_ptr->ip_ver         = 0x4;
  ip_ptr->ip_tos         = 0x00;
  /*to be updated later*/
  ip_ptr->ip_tot_len     = 0x00;
  ip_ptr->ip_id          = htons(random() % 65535);
  ip_ptr->ip_flag_offset = htons(0x1 << 14);
  ip_ptr->ip_ttl         = 0x10;
  ip_ptr->ip_proto       = 0x11;
  /*To be calculated later*/
  ip_ptr->ip_chksum      = 0x00;

  ip_ptr->ip_src_ip  = htonl(pDnsCtx->ns1_ip);
  /*ip address of google dns - 8.8.8.8 or 8.8.4.4*/
  ip_ptr->ip_dest_ip = htonl(utility_ip_str_to_int("8.8.8.8"));

  /*populating UDP Header*/
  udp_ptr->udp_src_port  = htons(8989);
  udp_ptr->udp_dest_port = htons(DNS_PORT); 
  udp_ptr->udp_len       = 0x00;
  /*To be calculated later*/
  udp_ptr->udp_chksum    = 0x00;

  /*populating DNS Reply with RR*/
  dns_ptr->xid     = htons(8844);
  dns_ptr->qr      = 0x0;
  dns_ptr->opcode  = DNS_QUERY ;
  dns_ptr->aa      = 0x0;
  dns_ptr->tc      = 0x0;
  dns_ptr->rd      = 0x1;
  dns_ptr->ra      = 0x00;
  dns_ptr->z       = 0x00;
  dns_ptr->rcode   = DNS_NO_ERROR;
  dns_ptr->qdcount = htons(0x01);
  dns_ptr->ancount = htons(0x00);
  dns_ptr->nscount = htons(0x00);
  dns_ptr->arcount = htons(0x00);
  /*Filling up the payload of dns query*/

  offset = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr);
  
  memset((void *)tmp_dname, 0, (sizeof(tmp_dname))); 
  strncpy(tmp_dname, wall_gardened, strlen(wall_gardened));
  line_ptr = strtok(tmp_dname, ".");

  while(line_ptr) {
    req_ptr[offset++] = strlen(line_ptr);
    strncpy((char *)&req_ptr[offset], line_ptr, strlen(line_ptr));
    offset += strlen(line_ptr);
    line_ptr = strtok(NULL, ".");
  }

  /*domain name label terminator*/
  req_ptr[offset++] = 0;
  /*QTYPE*/ 
  req_ptr[offset++] = (A & 0xFF00) >> 8;
  req_ptr[offset++] = (A & 0x00FF);
  /*QCLASS*/ 
  req_ptr[offset++] = (IN & 0xFF00) >> 8;
  req_ptr[offset++] = (IN & 0x00FF);
 
  /*populating length in respective Header filed*/ 
  ip_ptr->ip_tot_len = htons(offset);
  udp_ptr->udp_len   = htons(offset - sizeof(struct iphdr));
  ip_ptr->ip_chksum  = utility_cksum((void *)ip_ptr,  (sizeof(uint32_t) * ip_ptr->ip_len));
  udp_ptr->udp_chksum = utility_udp_checksum((uint8_t *)ip_ptr);

  ret = tun_write(req_ptr, offset);
  if(ret < 0) {
    fprintf(stderr, "\n%s:%d write to tunnel failed\n", __FILE__, __LINE__);
    perror("tun:");
    return(1);
  }

  utility_hex_dump(req_ptr, offset);
  free(req_ptr);
  return(0);
}/*dns_build_dns_req*/

uint32_t dns_is_dns_query(int16_t fd, 
                          uint8_t *packet_ptr, 
                          uint16_t packet_length) {

  struct dnshdr *dns_packet = (struct dnshdr *)&packet_ptr[sizeof(struct eth)   +
                                                           sizeof(struct iphdr) +
                                                           sizeof(struct udphdr)];
  return(!dns_packet->ra && !dns_packet->opcode);
  
}/*dns_is_dns_query*/

uint32_t dns_get_label(uint8_t *domain_name, uint8_t **label_str) {
  uint32_t idx = 0;

  sscanf((const char *)domain_name, "%s.%s", label_str[0], label_str[1]);
  (void)idx;

  return(0);
}/*dns_get_label*/

uint32_t dns_perform_snat(int16_t fd, 
                          uint8_t *packet_ptr, 
                          uint16_t packet_length) {

  int32_t ret = -1;
  uint8_t buffer[1500];
  uint16_t buffer_length;
  struct iphdr *ip_ptr;
  dns_ctx_t *pDnsCtx = &dns_ctx_g;

  ip_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)]; 
  if(!subscriber_is_authenticated(ip_ptr->ip_src_ip)) {

    memset((void *)pDnsCtx->host_ip, 0, sizeof(pDnsCtx->host_ip));
    utility_ip_int_to_str(htonl(pDnsCtx->ns1_ip), pDnsCtx->host_ip);
    dns_build_rr_reply(fd, packet_ptr, packet_length, 0);

  } else { 

    memset((void *)buffer, 0, sizeof(buffer)) ;
    ret = nat_perform_snat(packet_ptr, 
                           packet_length, 
                           (uint8_t *)buffer, 
                           &buffer_length); 
  
    ret = tun_write(buffer, 
                    buffer_length);
    if(ret < 0) {
      fprintf(stderr, "\n%s:%d write to tunnel failed\n", __FILE__, __LINE__);
      perror("tun:");
      return(-1);
    }
  }

  return (0);
}/*dns_perform_snat*/

uint32_t dns_perform_dnat(int16_t fd, 
                          uint8_t *packet_ptr, 
                          uint16_t packet_length) {
  uint8_t buffer[1500];
  uint16_t buffer_len = 0x00;
  uint8_t  dst_mac[ETH_ALEN];

  memset((void *)buffer, 0, sizeof(buffer));

  nat_perform_dnat(packet_ptr, 
                   packet_length, 
                   buffer, 
                   &buffer_len);
  
  memset((void *)dst_mac, 0, sizeof(dst_mac));
  memcpy((void *)dst_mac, (const void *)buffer, ETH_ALEN);

  write_eth_frame(fd, dst_mac, buffer, buffer_len);

  return(0);
}/*dns_perform_dnat*/

uint32_t dns_build_walled_garden_reply(int32_t fd, 
                                       uint8_t *packet_ptr, 
                                       uint32_t packet_length, 
                                       uint8_t *ip_str) {


  uint8_t *rsp_ptr = NULL;
  uint32_t offset = 0;
  uint32_t idx = 0;
  uint8_t label_str[2][255];
 
  rsp_ptr = (uint8_t *)malloc(sizeof(uint8_t) * 1500);
  assert(rsp_ptr != NULL);
  memset((void *)rsp_ptr, 0, sizeof(uint8_t) * 1500); 
  dns_ctx_t *pDnsCtx = &dns_ctx_g;
 
  struct eth    *eth_ptr  = (struct eth    *)packet_ptr;
  struct iphdr  *ip_ptr   = (struct iphdr  *)&packet_ptr[sizeof(struct eth)];
  struct udphdr *udp_ptr  = (struct udphdr *)&packet_ptr[sizeof(struct eth) + 
                                                         sizeof(struct iphdr)];
  struct dnshdr *dns_ptr  = (struct dnshdr *)&packet_ptr[sizeof(struct eth) + 
                                                         sizeof(struct iphdr) + 
                                                         sizeof(struct udphdr)];
 
  struct eth    *eth_rsp_ptr  = (struct eth    *)rsp_ptr;
  struct iphdr  *ip_rsp_ptr   = (struct iphdr  *)&rsp_ptr[sizeof(struct eth)];
  struct udphdr *udp_rsp_ptr  = (struct udphdr *)&rsp_ptr[sizeof(struct eth) + 
                                                          sizeof(struct iphdr)];
  struct dnshdr *dns_rsp_ptr  = (struct dnshdr *)&rsp_ptr[sizeof(struct eth) + 
                                                          sizeof(struct iphdr) + 
                                                          sizeof(struct udphdr)];
  /*populating MAC Header for Response*/
  memcpy((void *)&eth_rsp_ptr->h_source, (const void *)&eth_ptr->h_dest,   6);
  memcpy((void *)&eth_rsp_ptr->h_dest,   (const void *)&eth_ptr->h_source, 6);
  eth_rsp_ptr->h_proto = eth_ptr->h_proto;

  /*populating IP Header for response*/ 
  ip_rsp_ptr->ip_len         = 0x5;
  ip_rsp_ptr->ip_ver         = 0x4;
  ip_rsp_ptr->ip_tos         = 0x00;
  /*to be updated later*/
  ip_rsp_ptr->ip_tot_len     = 0x00;
  ip_rsp_ptr->ip_id          = htons(random() % 65535);
  ip_rsp_ptr->ip_flag_offset = htons(0x1 << 14);
  ip_rsp_ptr->ip_ttl         = 0x10;
  ip_rsp_ptr->ip_proto       = 0x11;
  ip_rsp_ptr->ip_chksum      = 0x00;

  /*swapping the ip*/
  ip_rsp_ptr->ip_src_ip  = ip_ptr->ip_dest_ip;
  ip_rsp_ptr->ip_dest_ip = ip_ptr->ip_src_ip;

  /*populating UDP Header*/
  udp_rsp_ptr->udp_src_port  = udp_ptr->udp_dest_port;
  udp_rsp_ptr->udp_dest_port = udp_ptr->udp_src_port; 
  udp_rsp_ptr->udp_len       = 0x00;
  udp_rsp_ptr->udp_chksum    = 0x00;

  /*populating DNS Reply with RR*/
  dns_rsp_ptr->xid     = dns_ptr->xid;
  dns_rsp_ptr->qr      = 0x1;
  dns_rsp_ptr->opcode  = DNS_QUERY ;
  dns_rsp_ptr->aa      = 0x1;
  dns_rsp_ptr->tc      = 0x0;
  dns_rsp_ptr->rd      = dns_ptr->rd;
  dns_rsp_ptr->ra      = 0x00;
  dns_rsp_ptr->z       = 0x00;
  dns_rsp_ptr->rcode   = DNS_NO_ERROR;
  dns_rsp_ptr->qdcount = htons(0x01);
  dns_rsp_ptr->ancount = htons(0x01);
  dns_rsp_ptr->nscount = htons(0x00);
  dns_rsp_ptr->arcount = htons(0x00);

  /*populating DNS Payload*/
  offset = sizeof(struct dnshdr) +
           sizeof(struct udphdr) +
           sizeof(struct iphdr)  +
           sizeof(struct eth);

  /*copy query from request into response*/
  for(idx = 0; idx <pDnsCtx->qdata.qname_count; idx++) {
    rsp_ptr[offset++] = pDnsCtx->qdata.qname[idx].len;

    memcpy((void *)&rsp_ptr[offset], 
           pDnsCtx->qdata.qname[idx].value, 
           pDnsCtx->qdata.qname[idx].len);

    offset += pDnsCtx->qdata.qname[idx].len;
  }

  /*This marks the end of qname RR*/
  rsp_ptr[offset++] = 0;

  /*AN SECTION (1) - Answer Section of RR*/

  /*TYPE is A for Host Address*/
  rsp_ptr[offset++] = (A & 0xFF00) >> 8;
  rsp_ptr[offset++] = (A & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*domain name*/ 
  for(idx = 0; idx <pDnsCtx->qdata.qname_count; idx++) {
    rsp_ptr[offset++] = pDnsCtx->qdata.qname[idx].len;

    memcpy((void *)&rsp_ptr[offset], 
           pDnsCtx->qdata.qname[idx].value, 
           pDnsCtx->qdata.qname[idx].len);

    offset += pDnsCtx->qdata.qname[idx].len;
  }

  /*This marks the end of qname RR*/
  rsp_ptr[offset++] = 0;

  /*AN SECTION (1) - Answer Section of RR*/

  /*TYPE is A for Host Address*/
  rsp_ptr[offset++] = (A & 0xFF00) >> 8;
  rsp_ptr[offset++] = (A & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*Type is TTl in seconds*/
  rsp_ptr[offset++] = (0x0100 & 0xFF000000) >> 24;
  rsp_ptr[offset++] = (0x0100 & 0x00FF0000) >> 16;
  rsp_ptr[offset++] = (0x0100 & 0x0000FF00) >> 8;
  rsp_ptr[offset++] = (0x0100 & 0x000000FF);

  /*Type is RDLENGTH*/
  rsp_ptr[offset++] = (0x04 & 0xFF00) >> 8;
  rsp_ptr[offset++] = (0x04 & 0x00FF);

  /*Type is RDATA*/
  *((uint32_t *)&rsp_ptr[offset]) = htonl(utility_ip_str_to_int(ip_str));
  offset += 4;
 
  /*populating length in respective Header filed*/ 
  ip_rsp_ptr->ip_tot_len = htons(offset - sizeof(struct eth));
  udp_rsp_ptr->udp_len   = htons(offset - (sizeof(struct eth) + sizeof(struct iphdr)));
  ip_rsp_ptr->ip_chksum  = utility_cksum((void *)ip_rsp_ptr,  (sizeof(unsigned int) * ip_rsp_ptr->ip_len));

  udp_rsp_ptr->udp_chksum = utility_udp_checksum((uint8_t *)ip_rsp_ptr);
 
  write_eth_frame(fd, (uint8_t *)eth_rsp_ptr->h_dest, rsp_ptr, offset);
  free(rsp_ptr);

  return(0);
}/*dns_build_walled_garden_reply*/

uint32_t dns_build_rr_reply(int16_t fd, 
                            uint8_t *packet_ptr, 
                            uint16_t packet_length,
                            uint32_t ttl) {
  uint8_t rr_reply[1500];

  uint8_t  *rsp_ptr    = rr_reply;
  uint32_t  offset     = 0;
  uint32_t  idx        = 0;
  uint8_t   label_str[2][255];
  
  dns_ctx_t *pDnsCtx   = &dns_ctx_g;
 
  struct eth    *eth_ptr  = (struct eth    *)packet_ptr;
  struct iphdr  *ip_ptr   = (struct iphdr  *)&packet_ptr[sizeof(struct eth)];
  struct udphdr *udp_ptr  = (struct udphdr *)&packet_ptr[sizeof(struct eth) + 
                                                         sizeof(struct iphdr)];

  struct dnshdr *dns_ptr  = (struct dnshdr *)&packet_ptr[sizeof(struct eth) + 
                                                         sizeof(struct iphdr) + 
                                                         sizeof(struct udphdr)];
 
  struct eth    *eth_rsp_ptr  = (struct eth    *)rsp_ptr;
  struct iphdr  *ip_rsp_ptr   = (struct iphdr  *)&rsp_ptr[sizeof(struct eth)];
  struct udphdr *udp_rsp_ptr  = (struct udphdr *)&rsp_ptr[sizeof(struct eth) + 
                                                          sizeof(struct iphdr)];

  struct dnshdr *dns_rsp_ptr  = (struct dnshdr *)&rsp_ptr[sizeof(struct eth) + 
                                                          sizeof(struct iphdr) + 
                                                          sizeof(struct udphdr)];

  /*populating MAC Header for Response*/
  memcpy((void *)&eth_rsp_ptr->h_source, (const void *)&eth_ptr->h_dest,   6);
  memcpy((void *)&eth_rsp_ptr->h_dest,   (const void *)&eth_ptr->h_source, 6);
  eth_rsp_ptr->h_proto = eth_ptr->h_proto;

  /*populating IP Header for response*/ 
  ip_rsp_ptr->ip_len         = 0x5;
  ip_rsp_ptr->ip_ver         = 0x4;
  ip_rsp_ptr->ip_tos         = 0x00;
  /*to be updated later*/
  ip_rsp_ptr->ip_tot_len     = 0x00;
  ip_rsp_ptr->ip_id          = htons(random() % 65535);
  ip_rsp_ptr->ip_flag_offset = htons(0x1 << 14);
  ip_rsp_ptr->ip_ttl         = 0x10;
  ip_rsp_ptr->ip_proto       = 0x11;
  ip_rsp_ptr->ip_chksum      = 0x00;

  /*swapping the ip*/
  ip_rsp_ptr->ip_src_ip  = htonl(pDnsCtx->ns1_ip);
  ip_rsp_ptr->ip_dest_ip = ip_ptr->ip_src_ip;

  /*populating UDP Header*/
  udp_rsp_ptr->udp_src_port  = udp_ptr->udp_dest_port;
  udp_rsp_ptr->udp_dest_port = udp_ptr->udp_src_port; 
  udp_rsp_ptr->udp_len       = 0x00;
  udp_rsp_ptr->udp_chksum    = 0x00;

  /*populating DNS Reply with RR*/
  dns_rsp_ptr->xid     = dns_ptr->xid;
  dns_rsp_ptr->qr      = 0x1;
  dns_rsp_ptr->opcode  = DNS_QUERY ;
  dns_rsp_ptr->aa      = 0x1;
  dns_rsp_ptr->tc      = 0x0;
  dns_rsp_ptr->rd      = dns_ptr->rd;
  dns_rsp_ptr->ra      = 0x00;
  dns_rsp_ptr->z       = 0x00;
  dns_rsp_ptr->rcode   = DNS_NO_ERROR;
  dns_rsp_ptr->qdcount = htons(0x01);
  dns_rsp_ptr->ancount = htons(0x02);
  dns_rsp_ptr->nscount = htons(0x01);
  dns_rsp_ptr->arcount = htons(0x00);

  /*populating DNS Payload*/
  offset = sizeof(struct dnshdr) +
           sizeof(struct udphdr) +
           sizeof(struct iphdr)  +
           sizeof(struct eth);

  /*copy query from request into response*/
  for(idx = 0; idx <pDnsCtx->qdata.qname_count; idx++) {
    rsp_ptr[offset++] = pDnsCtx->qdata.qname[idx].len;

    memcpy((void *)&rsp_ptr[offset], 
           pDnsCtx->qdata.qname[idx].value, 
           pDnsCtx->qdata.qname[idx].len);

    offset += pDnsCtx->qdata.qname[idx].len;
  }

  /*This marks the end of qname RR*/
  rsp_ptr[offset++] = 0;

  /*AN SECTION (1) - Answer Section of RR*/

  /*TYPE is A for Host Address*/
  rsp_ptr[offset++] = (A & 0xFF00) >> 8;
  rsp_ptr[offset++] = (A & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*domain name*/ 
  for(idx = 0; idx <pDnsCtx->qdata.qname_count; idx++) {
    rsp_ptr[offset++] = pDnsCtx->qdata.qname[idx].len;

    memcpy((void *)&rsp_ptr[offset], 
           pDnsCtx->qdata.qname[idx].value, 
           pDnsCtx->qdata.qname[idx].len);

    offset += pDnsCtx->qdata.qname[idx].len;
  }

  /*This marks the end of qname RR*/
  rsp_ptr[offset++] = 0;

  /*TYPE is A for Host Address*/
  rsp_ptr[offset++] = (A & 0xFF00) >> 8;
  rsp_ptr[offset++] = (A & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*Type is TTl in seconds*/
  rsp_ptr[offset++] = (ttl & 0xFF000000) >> 24;
  rsp_ptr[offset++] = (ttl & 0x00FF0000) >> 16;
  rsp_ptr[offset++] = (ttl & 0x0000FF00) >> 8;
  rsp_ptr[offset++] = (ttl & 0x000000FF);

  /*Type is RDLENGTH*/
  rsp_ptr[offset++] = (0x04 & 0xFF00) >> 8;
  rsp_ptr[offset++] = (0x04 & 0x00FF);

  /*Type is RDATA*/
  *((uint32_t *)&rsp_ptr[offset]) = htonl(utility_ip_str_to_int(pDnsCtx->host_ip));
  offset += 4;

  /*AN Section (2) */
  rsp_ptr[offset++] = strlen((const char *)pDnsCtx->ns1_name);

  memcpy((void *)&rsp_ptr[offset], 
         pDnsCtx->ns1_name, 
         strlen((const char *)pDnsCtx->ns1_name));

  offset += strlen((const char *)pDnsCtx->ns1_name);

  rsp_ptr[offset++] = 0;
  /*TYPE it belongs to*/
  rsp_ptr[offset++] = (A & 0xFF00) >> 8;
  rsp_ptr[offset++] = (A & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*Type is TTl in seconds*/
  rsp_ptr[offset++] = (ttl & 0xFF000000) >> 24;
  rsp_ptr[offset++] = (ttl & 0x00FF0000) >> 16;
  rsp_ptr[offset++] = (ttl & 0x0000FF00) >> 8;
  rsp_ptr[offset++] = (ttl & 0x000000FF);
  
  rsp_ptr[offset++] = (0x04 & 0xFF00) >> 8;
  rsp_ptr[offset++] = (0x04 & 0x00FF);
  
  /*Type is RDATA*/

  *((uint32_t *)&rsp_ptr[offset]) = htonl(pDnsCtx->ns1_ip);
  offset += 4;
 
  /*NS SECTION - Name Server Section of RR*/

  idx = strlen((const char *)pDnsCtx->ns1_name);
  rsp_ptr[offset++] = idx & 0xFF;
  memcpy((void *)&rsp_ptr[offset], pDnsCtx->ns1_name, idx);
  offset += idx;
  
  sscanf((const char *)pDnsCtx->domain_name, "%[^.].%s", label_str[0], label_str[1]);

  idx = strlen((const char *)label_str[0]);
  rsp_ptr[offset++] = idx & 0xFF;
  memcpy((void *)&rsp_ptr[offset], label_str[0], idx);
  offset += idx;

  idx = strlen((const char *)label_str[1]);
  rsp_ptr[offset++] = idx & 0xFF;
  memcpy((void *)&rsp_ptr[offset], (const void *)label_str[1], idx);
  offset += idx;
 
  /*marking the end of FQDN name for ns1*/
  rsp_ptr[offset++] = 0;

  /*TYPE it belongs to*/
  rsp_ptr[offset++] = (NS & 0xFF00) >> 8;
  rsp_ptr[offset++] = (NS & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*Type is TTl in seconds*/
  rsp_ptr[offset++] = (ttl & 0xFF000000) >> 24;
  rsp_ptr[offset++] = (ttl & 0x00FF0000) >> 16;
  rsp_ptr[offset++] = (ttl & 0x0000FF00) >> 8;
  rsp_ptr[offset++] = (ttl & 0x000000FF);

  /*Type is RDLENGTH*/
  rsp_ptr[offset++] = (0x00 & 0xFF00) >> 8;
  rsp_ptr[offset++] = (0x00 & 0x00FF);
  

  /*populating length in respective Header filed*/ 
  ip_rsp_ptr->ip_tot_len = htons(offset - sizeof(struct eth));
  udp_rsp_ptr->udp_len   = htons(offset - (sizeof(struct eth) + sizeof(struct iphdr)));
  ip_rsp_ptr->ip_chksum  = utility_cksum((void *)ip_rsp_ptr,  (sizeof(unsigned int) * ip_rsp_ptr->ip_len));

  udp_rsp_ptr->udp_chksum = utility_udp_checksum((uint8_t *)ip_rsp_ptr);
 
  write_eth_frame(fd, (uint8_t *)eth_rsp_ptr->h_dest, rr_reply, offset);

  return(0);
}/*dns_build_rr_reply*/

uint32_t dns_is_walled_garden(uint8_t *ip_str) {

  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  uint8_t  sql_query[255];
  uint8_t  domain_name[255];
  uint32_t idx;
  uint32_t offset = 0;

  uint8_t  record[2][16][32];
  int32_t  row = 0;
  int32_t  col = 0;
 
  memset((void *)domain_name, 0, sizeof(domain_name));
  for(idx = 0; idx < pDnsCtx->qdata.qname_count; idx++) {
    offset += snprintf(domain_name + offset,
                       sizeof(domain_name) - offset,
                       "%s%s",
                       pDnsCtx->qdata.qname[idx].value,
                       ".");
  } 
  /*Remove the trailing .*/
  domain_name[offset -1] = '\0';
  //fprintf(stderr, "\n%s:%d constructed domain name is %s\n", __FILE__, __LINE__, domain_name);

  memset((void *)sql_query, 0, sizeof(sql_query));
  snprintf(sql_query,
           sizeof(sql_query),
           "%s%s%s%s%s",
           "SELECT * FROM ",
           pDnsCtx->walled_garden_table,
           " WHERE host_name=\'",
           domain_name,
           "\'"); 

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, sizeof(record));
    if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      if(row) {
        strncpy(ip_str, record[0][1], strlen(record[0][1]));
        return(0);
      }
    }
  }

  return(1);
}/*dns_is_walled_garden*/

uint32_t dns_process_dns_query(int16_t fd, 
                               uint8_t *packet_ptr, 
                               uint16_t packet_length) {

  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  uint8_t  sql_query[512];
  uint8_t  domain_name[255];

  uint8_t  record[2][16][32];
  int32_t  row = 0;
  int32_t  col = 0;

  memset((void *)&domain_name, 0, sizeof(domain_name));

  snprintf((char *)domain_name, 
            sizeof(domain_name),
            "%s%s%s",
            pDnsCtx->qdata.qname[pDnsCtx->qdata.qname_count - 2].value,
            ".",
            pDnsCtx->qdata.qname[pDnsCtx->qdata.qname_count - 1].value);
   
  /*check if DNS query is for local DNS or external one.*/
  if(!strncmp((const char *)pDnsCtx->domain_name, 
              (const char *)domain_name, 
              strlen((const char *)pDnsCtx->domain_name))) {

    memset((void *)&sql_query, 0, sizeof(sql_query));
    snprintf((char *)sql_query, 
             sizeof(sql_query),
             "%s%s%s%s%s",
             "SELECT * FROM ",
             pDnsCtx->ip_allocation_table,
             " WHERE host_name ='",
             pDnsCtx->qdata.qname[0].value,
             "'");

    if(!db_exec_query((char *)sql_query)) {

      memset((void *)record, 0, sizeof(record));
      if(!db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
 
        if(row) {
          memset((void *)pDnsCtx->host_ip, 0, sizeof(pDnsCtx->host_ip));
          snprintf(pDnsCtx->host_ip, sizeof(pDnsCtx->host_ip),
                   "%s.%s",
                   record[0][2],
                   record[0][3]);

          memset((void *)pDnsCtx->host_name, 0, sizeof(pDnsCtx->host_name));
          memcpy((void *)pDnsCtx->host_name, 
                 (const void *)pDnsCtx->qdata.qname[0].value, 
                 strlen((const char *)pDnsCtx->qdata.qname[0].value));

          /*Prepare the RR (Resource Record for DNS Reply*/
          dns_build_rr_reply(fd, packet_ptr, packet_length, 256);

        } else {
          /*DNS Request for ns1*/
          uint8_t host_name[32];
          size_t host_len = sizeof(host_name);
          memset((void *)host_name, 0, host_len);
          if(!gethostname(host_name, host_len)) {
            if(!strncmp(host_name, pDnsCtx->qdata.qname[0].value, strlen(host_name))) {
              /*DNS Query for ns*/
              memset((void *)pDnsCtx->host_ip, 0, sizeof(pDnsCtx->host_ip));
              utility_ip_int_to_str(htonl(pDnsCtx->ns1_ip), pDnsCtx->host_ip);
              /*Prepare the RR (Resource Record for DNS Reply*/
              dns_build_rr_reply(fd, packet_ptr, packet_length, 256);
            } else {
              /*IP is not managed by this DHCP Server*/
              dns_perform_snat(fd, packet_ptr, packet_length);
            }
          } else {    
            /*IP is not managed by this DHCP Server*/
            /*This is unreachable code*/
            dns_perform_snat(fd, packet_ptr, packet_length);
          }
        }
      }
    }
  } else {
    /*If dns is walled garden*/
    uint8_t ip_str[64];
    memset((void *)ip_str, 0, sizeof(ip_str));
    if(!dns_is_walled_garden(ip_str)) {
      /*This is required because dns query for same domain returns different IP address*/
      dns_build_walled_garden_reply(fd, packet_ptr, packet_length, ip_str);

    } else {
      dns_perform_snat(fd, packet_ptr, packet_length);
    }
  }

  return(0);
}/*dns_process_dns_query*/


void dns_display_char(uint8_t *label, uint16_t label_len) {
  uint16_t idx = 0;

  fprintf(stderr, "\nThe Length is %d\n", label_len);

  for(idx = 0; idx < label_len; idx++) {
    fprintf(stderr, "%c", label[idx]);
  }

  fprintf(stderr, "\n");
}/*dns_display_char*/

uint32_t dns_get_qname_len(void) {
  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  uint32_t idx = 0;
  uint32_t tot_len = 0;

  for(idx = 0; idx <pDnsCtx->qdata.qname_count; idx++) {
    tot_len += pDnsCtx->qdata.qname[idx].len;    
  }

  return(tot_len);
}/*dns_get_qname_len*/


uint32_t dns_parse_qdsection(int16_t fd, 
                             uint8_t *packet_ptr, 
                             uint16_t packet_length) {

  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  uint8_t *pQdata    = NULL;
  uint8_t  idx       = 0;
  uint16_t offset    = 0;

  pQdata = (uint8_t *)&packet_ptr[sizeof(struct eth)     + 
                                  sizeof(struct iphdr)   + 
                                  sizeof(struct udphdr)  + 
                                  sizeof(struct dnshdr)];


  memset((void *)&pDnsCtx->qdata, 0, sizeof(dns_qddata_t));

  pDnsCtx->qdata.qname[idx].len = pQdata[offset++];

  while(pDnsCtx->qdata.qname[idx].len > 0) {

    memset((void *)pDnsCtx->qdata.qname[idx].value, 
           0, 
           sizeof(pDnsCtx->qdata.qname[idx].value));

    memcpy((void *)pDnsCtx->qdata.qname[idx].value, 
           (void *)&pQdata[offset], 
           pDnsCtx->qdata.qname[idx].len);

    offset += pDnsCtx->qdata.qname[idx].len;
    idx++ ; 
    pDnsCtx->qdata.qname[idx].len = pQdata[offset++];
  }
        
  pDnsCtx->qdata.qname_count = idx;
  pDnsCtx->qdata.qtype = ntohs(*(uint16_t *)&pQdata[offset]);

  offset += 2;
  pDnsCtx->qdata.qclass = ntohs(*(uint16_t *)&pQdata[offset]);
  
  dns_process_dns_query(fd, packet_ptr, packet_length);

  return(offset);
}/*dns_parse_qdsection*/


uint32_t dns_process_ansection(int16_t   fd, 
                               uint8_t  *packet_ptr, 
                               uint16_t  packet_length) {
  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  uint8_t *pAndata  = NULL;
  uint8_t  idx      = 0;
  uint16_t offset   = 0;

        
  pAndata = (uint8_t *)&packet_ptr[sizeof(struct eth)    + 
                                   sizeof(struct iphdr)  + 
                                   sizeof(struct udphdr) + 
                                   sizeof(struct dnshdr) +
                                   sizeof(pDnsCtx->qdata.qtype) +
                                   sizeof(pDnsCtx->qdata.qclass) +
                                   dns_get_qname_len()];

  memset((void *)&pDnsCtx->andata, 0, sizeof(dns_andata_t));
  pDnsCtx->andata.name[idx].len = pAndata[offset++];
  
  while(pDnsCtx->andata.name[idx].len > 0) {
    memcpy((void *)&pDnsCtx->andata.name[idx].value, (void *)&pAndata[offset], pDnsCtx->andata.name[idx].len);
    offset += pDnsCtx->andata.name[idx].len;
    dns_display_char(pDnsCtx->andata.name[idx].value, pDnsCtx->andata.name[idx].len);
    idx += 1; 

    pDnsCtx->andata.name[idx].len = pAndata[offset++];
  }
  /*A length of zero is meant for root node in domain hierarchy*/
  offset++;      
  pDnsCtx->andata.name_count = idx;
  pDnsCtx->andata.type = ntohs(*(uint16_t *)&pAndata[offset]);

  offset += 2;
  pDnsCtx->andata.rdata_class = ntohs(*(uint16_t *)&pAndata[offset]);
  offset += 2;
  pDnsCtx->andata.ttl = ntohl(*(uint16_t *)&pAndata[offset]);
  offset += 4;

  pDnsCtx->andata.rdlength = ntohs(*(uint16_t *)&pAndata[offset]);
  offset += 2;

  memcpy((void *)&pDnsCtx->andata.rdata, (void *)&pAndata[offset], pDnsCtx->andata.rdlength);
  offset += pDnsCtx->andata.rdlength;

  return(offset);   
}/*dns_process_ansection*/

uint32_t dns_process_nssection(int16_t   fd, 
                               uint8_t *packet_ptr, 
                               uint16_t  packet_length) {
  return(0);
}/*dns_process_nssection*/


uint32_t dns_process_arsection(int16_t   fd, 
                               uint8_t *packet_ptr, 
                               uint16_t  packet_length) {
  return(0);
}/*dns_process_arsection*/


uint32_t dns_main(int16_t fd, 
                  uint8_t *packet_ptr, 
                  uint16_t packet_length) {

  uint32_t offset = 0;
  struct dnshdr  *dns_ptr = (struct dnshdr *)&packet_ptr[sizeof(struct eth) + 
                            sizeof(struct iphdr) + 
                            sizeof(struct udphdr)];
  
  switch(dns_ptr->opcode) {
    case DNS_QUERY:
      /*Is it for local DNS or the public one*/
      if((ntohs(dns_ptr->qdcount) > 0) && (!dns_ptr->qr)) {
       offset = dns_parse_qdsection(fd, packet_ptr, packet_length);
      }
      
      if((ntohs(dns_ptr->ancount > 0)) && (dns_ptr->qr)) {
        offset = dns_process_ansection(fd, packet_ptr, packet_length);
      }
    
      if(ntohs(dns_ptr->nscount > 0)) {
        offset = dns_process_nssection(fd, packet_ptr, packet_length); 
      }
      
      if(ntohs(dns_ptr->arcount > 0)) {
        offset = dns_process_arsection(fd, packet_ptr, packet_length);
      }
    break;

    case DNS_INVERSE_QUERY:
    break;
    case DNS_STATUS:
    break;
    default:
    break;
  }
  (void)offset;
  return(0);
}/*dns_main*/


#endif /* __DNS_C__ */
