#ifndef __NET_C__
#define __NET_C__


#include <common.h>
#include <net.h>

/********************************************************************
 * Global Instance creation
 ********************************************************************/
net_ctx_t net_ctx_g;

/** @brief This function initialises global for its further use
 *
 *  @param eth_param the name of ethernet interface
 *
 *  @return uopn success it returns 0 else < 0
 */
int32_t net_init(uint8_t *eth_name) {
  net_ctx_t *pNetCtx = &net_ctx_g;
  struct ifreq ifr;
  int32_t fd;
  
  fd = socket(AF_INET, SOCK_DGRAM, 0);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d Opening of fd failed\n", __FILE__, __LINE__);
    return(-1);
  }

  /* Get ifindex */
  memset((void *)&ifr, 0, sizeof(ifr));
  strncpy((char *)ifr.ifr_name, (const char *)eth_name, sizeof(ifr.ifr_name));

  if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
    fprintf(stderr, "\n%s:%d ioctl failed\n", __FILE__, __LINE__);
    syslog(LOG_ERR, "%s: ioctl(SIOCFIGINDEX) failed", strerror(errno));
    close(fd);
    return(-2);
  }

  pNetCtx->intf_idx = ifr.ifr_ifindex;
  strncpy(pNetCtx->eth_name, eth_name, strlen((const char *)eth_name));
  return(0);
 
}/*net_init*/


int32_t net_setaddr(uint8_t *interface_name,
                    uint32_t ip_addr, 
                    uint32_t netmask_addr) {
  int32_t fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  memset((void *)&ifr, 0, sizeof(struct ifreq));
  strncpy((char *)ifr.ifr_name, (const char *)interface_name, IFNAMSIZ);

  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;
  ifr.ifr_netmask.sa_family = AF_INET;

  /*Make sure to null terminate*/
  ifr.ifr_name[IFNAMSIZ-1] = 0;

  ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = ip_addr;

  if (ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0) {
    fprintf(stderr, "Setting of interface address failed\n");
    close(fd);
    return(-1);
  }
  
  if(netmask_addr) {
    ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr = netmask_addr;

    if(ioctl(fd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
      fprintf(stderr, "\n%s:%d Setting of interface NETMASK failed\n", __FILE__, __LINE__);
      perror("netmask failed");
      close(fd);
      return(-2);
    }
  }

  close(fd);
  return(0);
}/*net_setaddr*/

int32_t ndelay_on(int32_t fd) {
  int got = fcntl(fd, F_GETFL);
  return (got == -1) ? -1 : fcntl(fd, F_SETFL, got | O_NONBLOCK);
}/*ndelay_on*/


int32_t coe(int32_t fd) {
  register int flags = fcntl(fd, F_GETFD, 0);
  if (flags == -1) return -1;
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}/*coe*/

int32_t read_eth_frame(int fd, uint8_t *packet, uint16_t *packet_len) {
  int ret = -1;
  int max_len = 1500;
  struct sockaddr_ll sa;
  socklen_t addr_len = sizeof(sa);

  if(!packet) {
    return (ret);
  }

  do {
    ret = recvfrom(fd, 
                   packet, 
                   max_len, 
                   0, 
                   (struct sockaddr *)&sa, 
                   &addr_len);

  }while((ret == -1) && (errno == EINTR));

  *packet_len = ret;
  return(ret);
}/*read_eth_frame*/

int32_t write_eth_frame(int32_t fd, 
                        uint8_t *dst_mac, 
                        uint8_t *packet, 
                        uint16_t packet_len) {
  int32_t ret = -1;
  net_ctx_t *pNetCtx = &net_ctx_g;
  struct sockaddr_ll sa;
  socklen_t addr_len = sizeof(sa);
  uint16_t offset = 0;

  if(!packet) {
    return (-1);
  }

  memset((void *)&sa, 0, sizeof(sa));
  sa.sll_family   = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex  = pNetCtx->intf_idx;
  sa.sll_halen    = ETH_ALEN;
  memcpy((void *)sa.sll_addr, (void *)dst_mac, ETH_ALEN);

  do {
    ret = sendto(fd, 
                 (const void *)&packet[offset], 
                 (packet_len - offset), 
                 0, 
                 (struct sockaddr *)&sa, 
                 addr_len);

    if(ret > 0) {
      offset += ret;
      if(!(packet_len - offset)) {
        ret = 0;
      }
    }

  }while((ret == -1) && (errno == EINTR));
 
  return(ret);
}/*write_eth_frame*/

#endif
