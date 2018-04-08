#ifndef __EAPOL_H__
#define __EAPOL_H___

/*ieee802.1x Payload length*/
#define EAPOL_LEN       10240

struct ieee802dot1x {
  uint8_t  ver;
  uint8_t  type;
  uint16_t len;
} __attribute__((packed));

struct eapol {
  uint8_t  code;
  uint8_t  id;
  uint16_t length;
  uint8_t  type;
  uint8_t  payload[EAPOL_LEN];
} __attribute__((packed));


int32_t eapol_main(int32_t fd, uint8_t *in, uint32_t inlen);

#endif /* __EAPOL_H__ */
