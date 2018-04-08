#ifndef __EAPOL_C__
#define __EAPOL_C__

#include <common.h>
#include <transport.h>
#include <type.h>
#include <eapol.h>


int32_t eapol_main(int32_t fd, uint8_t *in_ptr, uint32_t inlen) {
  uint8_t multicast_mac[] = {};
  struct eth *eth_ptr;
  struct ieee802dot1x *dot1x_ptr;
  struct eapol *eapol_ptr;

  eth_ptr = (struct eth *)in_ptr;
  dot1x_ptr = (struct ieee802dot1x *)&in_ptr[sizeof(struct eth)];
  eapol_ptr = (struct eapol *)&in_ptr[sizeof(struct eth) + sizeof(struct ieee802dot1x)];

  if(!memcmp(multicast_mac, eth_ptr->h_dest, ETH_ALEN)) {
  }


}/*eapol_main*/
#endif /* __EAPOL_C__ */
