#ifndef __TIMER_H__
#define __TIMER_H__

#include <type.h>

/*This is the callback registed with sigaction*/
typedef void (*timer_callback_t)(int32_t signo, siginfo_t *info, void *context);

/*This is the callback registed with timer*/
typedef int32_t (*notify_callback_t)(void *context_data);

struct timer_list {
  timer_t timer_id;
  notify_callback_t notify_callback;
  siginfo_t  sa;
  void *ctx_data;
  struct timer_list *next_node;  
};

typedef struct timer_list timer_list_t;

typedef struct {

  timer_list_t *pTimer;

  
}timer_ctx_t;


void timer_expire_callback(int32_t sig_num, 
                           siginfo_t *info, 
                           void *context);

uint32_t timer_set_timer(uint32_t sec, 
                         uint32_t micro_sec, 
                         void *ctx_data, 
                         timer_t tid);

uint32_t timer_clear_timer(void);

uint32_t timer_main(void);
 
void *timer_get_ctx_data(timer_t *tid, notify_callback_t *pCb);

#endif
