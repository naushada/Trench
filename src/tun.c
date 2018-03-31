#ifndef __TUN_C__
#define __TUN_C__

#include <type.h>
#include <transport.h>
#include <common.h>
#include <string.h>
#include <linux/if_tun.h>
#include <utility.h>
#include <nat.h>
#include <tun.h>

/********************************************************************
 *  Global Instance Declaration
 ********************************************************************/
tun_ctx_t tun_ctx_g;

/********************************************************************
 * Function Definition starts
 ********************************************************************/
int32_t tun_read(uint8_t **packet_ptr, uint16_t *packet_length) {
  int32_t ret = -1;
  uint16_t max_bytes = 1500;

  tun_ctx_t *pTunCtx = &tun_ctx_g;

  *packet_ptr = (uint8_t *)malloc(max_bytes);

  if(!(*packet_ptr)) {
    fprintf(stderr, "\n%s:%d Allocation of Memory Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)(*packet_ptr), 0, max_bytes);

  do {
    ret = read(pTunCtx->tun_fd, (void *)(*packet_ptr), max_bytes);
   
  }while((ret == -1) && (ret == EINTR));

  *packet_length = ret;
  return(ret);

}/*tun_read*/

int32_t tun_write(uint8_t *packet_ptr, uint16_t packet_length) {
  tun_ctx_t *pTunCtx = &tun_ctx_g;
  int32_t ret = -1;

  do {
    ret = write(pTunCtx->tun_fd, packet_ptr, packet_length);
  } while (ret == -1 && errno == EINTR);

  return(ret);
}/*tun_write*/

int32_t tun_set_flags(uint32_t flags) {
  struct ifreq ifr;
  int32_t fd;

  tun_ctx_t *pTunCtx = &tun_ctx_g;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;

  strncpy(ifr.ifr_name, (const char *)pTunCtx->tun_devname, IFNAMSIZ);

  if(ioctl(fd, SIOCSIFFLAGS, &ifr)) {
    perror("Setting of Flags Failed");
    return(-1);
  }
  
  close(fd);

  return(0);
}/*tun_set_flags*/


int32_t tun_setaddr(uint32_t ip_addr, 
                    uint32_t dst_addr, 
                    uint32_t netmask_addr) {
  int32_t fd;
  struct ifreq ifr;
  tun_ctx_t *pTunCtx = &tun_ctx_g;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  memset((void *)&ifr, 0, sizeof(struct ifreq));

  strncpy(ifr.ifr_name, (const char *)pTunCtx->tun_devname, IFNAMSIZ);

  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;
  ifr.ifr_netmask.sa_family = AF_INET;

  /*Make sure to null terminate*/
  ifr.ifr_name[IFNAMSIZ-1] = 0;

  if(ip_addr) {
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = htonl(ip_addr);

    if (ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0) {
     fprintf(stderr, "Setting of interface address failed\n");
     return(-1);
    }
  }

  if(dst_addr) {
    ((struct sockaddr_in *)&ifr.ifr_dstaddr)->sin_addr.s_addr = htonl(dst_addr);

    if(ioctl(fd, SIOCSIFDSTADDR, (void *) &ifr) < 0) {
     fprintf(stderr, "Setting of interface DESTINATION IP FAILED failed\n");
     return(-1);
    }
  }
  
  if(netmask_addr) {
    ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr = htonl((netmask_addr));

    if(ioctl(fd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
     fprintf(stderr, "\n%s:%dSetting of interface NETMASK failed\n", __FILE__, __LINE__);
     perror("\nSetting of netmask failed:");
     return(-1);
    }
  }
  close(fd);

  if(tun_set_flags((IFF_UP | IFF_RUNNING))) {
    perror("setting of flags failed");
    return(-1);
  }

  return(0);

}/*tun_setaddr*/

int32_t tun_open_tun(void) {
  
  struct ifreq ifr;
  int32_t fd;
  struct ifreq nifr;

  tun_ctx_t *pTunCtx = &tun_ctx_g;

  pTunCtx->tun_fd = open(TUN_DEV_PATH, O_RDWR);

  if(pTunCtx->tun_fd < 0) {
    fprintf(stderr, "Opening of Virtual Device Failed\n");
    perror("tun:");
    return(-1);
  }
  
  utility_coe(pTunCtx->tun_fd);

  memset((void *)&ifr, 0, sizeof(struct ifreq));

  ifr.ifr_flags = IFF_TUN       | 
                  IFF_NO_PI     | 
                  IFF_MULTICAST |
                  IFF_BROADCAST | 
                  IFF_PROMISC   |
                  IFF_ONE_QUEUE;

  if(ioctl(pTunCtx->tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
    perror("ioctl failed");
    return(-1);
  }

  strncpy((char *)pTunCtx->tun_devname, ifr.ifr_name, IFNAMSIZ);

  /*Set Transmit Queue Length*/ 
  memset((void *)&nifr, 0, sizeof(struct ifreq));

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  if(fd < 0) {
    perror("socket Creation Failed");
    return(-1);
  }
  strncpy(nifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
  nifr.ifr_qlen = 100;

  if(ioctl(fd, SIOCSIFTXQLEN, (void *) &nifr)) {
    perror("Setting of TXQLEN Failed\n");
    return(-1);
  }
  
  strncpy((char *)pTunCtx->tun_devname, ifr.ifr_name, IFNAMSIZ);
  ioctl(pTunCtx->tun_fd, TUNSETNOCSUM, 1); /* Disable checksums */ 

  /*Set the MTU*/
  memset((void *)&nifr, 0, sizeof(struct ifreq));
  strncpy(nifr.ifr_name, (const char *)pTunCtx->tun_devname, sizeof(nifr.ifr_name));
  ifr.ifr_mtu = 1500;

  if(ioctl(fd, SIOCSIFMTU, &ifr) < 0) {
    perror("ioctl Failed:");
    return(-1);
  }
 
  close(fd);

  return(0);
}/*tun_open_tun*/

int32_t tun_process_response(uint8_t *packet_ptr, uint16_t packet_length) {

  uint8_t *buffer_ptr;
  uint16_t buffer_length;
  uint8_t dst_mac[ETH_ALEN];
  uint32_t fd;
  struct sockaddr_ll sa;
  int32_t ret = -1;
  uint16_t offset = 0;
  tun_ctx_t *pTunCtx = &tun_ctx_g;

  buffer_ptr = NULL;
  buffer_length = 0;

  buffer_ptr = (uint8_t *)malloc(packet_length + 14 /*For Ethernet Header*/);

  if(!buffer_ptr) {
    fprintf(stderr, "\n%s:%d Memory Allocation Failed\n", __FILE__, __LINE__);
    return(-1);
  } 

  memset((void *)buffer_ptr, 0, (packet_length + 14));

  nat_perform_dnat(packet_ptr, 
                   packet_length, 
                   buffer_ptr, 
                   &buffer_length);

  memset((void *)dst_mac, 0, sizeof(dst_mac));
  memcpy((void *)dst_mac, (void *)buffer_ptr, sizeof(dst_mac));

  fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  memset((void *)&sa, 0, sizeof(sa));
  sa.sll_family   = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex  = pTunCtx->ifindex;
  sa.sll_halen    = ETH_ALEN;
  memcpy((void *)sa.sll_addr, (const void *)dst_mac, ETH_ALEN);

  do {

    ret = sendto(fd, 
                 (void *)&buffer_ptr[offset], 
                 (buffer_length - offset), 
                 0, 
                 (struct sockaddr *)&sa, 
                 sizeof(struct sockaddr_ll));

    offset += ret; 
    if(!(packet_length - offset)) {
      ret = 0; 
    }
  }while(ret);

  free(buffer_ptr);
  buffer_ptr = NULL;
  close(fd);

  return(0);
}/*tun_process_response*/

int32_t tun_post_init(void) {

  tun_ctx_t *pTunCtx = &tun_ctx_g;
  struct ifreq ifr;
  uint32_t fd;
  struct sockaddr_ll sa;

  fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  /*Initializing to zero*/
  memset((void *)&ifr, 0, sizeof(ifr));
  strncpy((char *)ifr.ifr_name, 
          (const char *)pTunCtx->eth_name, 
          sizeof(ifr.ifr_name));

  if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
    fprintf(stderr, "\nioctl failed");
    syslog(LOG_ERR, "%s: ioctl(SIOCFIGINDEX) failed", strerror(errno));
  }
  pTunCtx->ifindex = ifr.ifr_ifindex;
  close(fd);
  
}/*tun_post_init*/


int32_t tun_init(uint32_t src_ip, 
                 uint32_t dest_ip, 
                 uint32_t net_mask,
                 uint8_t *eth_name) {

  tun_ctx_t *pTunCtx = &tun_ctx_g;

  tun_open_tun();
  tun_setaddr(src_ip, dest_ip, net_mask);

  strncpy(pTunCtx->eth_name, 
          (const char *)eth_name, 
          strlen((const char *)eth_name));

  tun_post_init();
 
  return(0);
}/*tun_init*/

void *tun_main(void *argv) {

  uint8_t *packet_ptr;
  uint16_t packet_length;

  for(;;) {
    packet_ptr = NULL;
    packet_length = 0;

    tun_read(&packet_ptr, &packet_length);
    
    if(packet_length > 0) {
      tun_process_response(packet_ptr, packet_length);  
      free(packet_ptr);
    }
  }
}/*tun_main*/

#endif /*__TUN_C__*/
