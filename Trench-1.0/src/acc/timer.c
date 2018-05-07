#ifndef __TIMER_C__
#define __TIMER_C__

#include <common.h>
#include <signal.h>
#include <time.h>

#include <timer.h>

timer_ctx_t timer_ctx_g;

extern void net_set_timer_fd(int32_t (*pCb)(void *), void *ctx);

void timer_expire_callback(int32_t sig_num, 
                           siginfo_t *info, 
                           void *context) {
  void *ctx = NULL;
  timer_t *tid;
  notify_callback_t pCb;

  tid = (timer_t *)info->si_value.sival_ptr;

  ctx = timer_get_ctx_data(tid, &pCb);
}/*timer_expire_callback*/


uint32_t timer_clear_timer(void) {

  setitimer(ITIMER_REAL, NULL, NULL);
  return(0);

}/*timer_clear_timer*/


void *timer_get_ctx_data(timer_t *tid, notify_callback_t *pCb) {
  timer_ctx_t *pTimerCtx = &timer_ctx_g;
  timer_list_t *base_ptr = pTimerCtx->pTimer;

  for(; base_ptr; base_ptr= base_ptr->next_node) {

    if(*tid == base_ptr->timer_id) {
      *pCb = base_ptr->notify_callback;
      return((void *)base_ptr->ctx_data); 
    }
  }
  return(NULL);
}/*timer_get_ctx_data*/


timer_t timer_get_context_tid(timer_t tid, void *ctx) {
  timer_ctx_t *pTimerCtx = &timer_ctx_g;
  timer_list_t *base_ptr = pTimerCtx->pTimer;

  for(; base_ptr; base_ptr=base_ptr->next_node) {
    if(base_ptr->timer_id == tid) {
      base_ptr->ctx_data = ctx;
      return(base_ptr->timer_id);
    }
  }

  return(0);  
}/*timer_get_context*/

uint32_t timer_set_timer(uint32_t sec, 
                         uint32_t nano_sec, 
                         void *ctx_data, 
                         timer_t tid) {

  struct timespec to;
  struct itimerspec time_out;
  timer_t timer_id;

  to.tv_sec = sec;
  to.tv_nsec = nano_sec;

  time_out.it_value    = to;
  time_out.it_interval.tv_sec = 3;
  time_out.it_interval.tv_nsec = 0;

  timer_id = timer_get_context_tid(tid, ctx_data);
  timer_settime(timer_id, 0, &time_out, NULL);
  return(0);
}/*timer_set_timer*/

timer_t timer_create_timer(notify_callback_t callback_handler) {

  struct sigevent se;
  struct sigaction sa;
  timer_ctx_t *pTimerCtx = &timer_ctx_g;
  timer_list_t *base_addr = pTimerCtx->pTimer;
  
  if(!base_addr) {
     base_addr = pTimerCtx->pTimer = (timer_list_t *)malloc(sizeof(timer_list_t));

  } else {
    base_addr = pTimerCtx->pTimer;
    
    /*Get to the END node*/
    while(base_addr->next_node) 
      base_addr = base_addr->next_node;

    base_addr->next_node = (timer_list_t *)malloc(sizeof(timer_list_t));
    base_addr = base_addr->next_node;
  }
  
  memset((void *)base_addr, 0, sizeof(timer_list_t));
  memset((void *)&se, 0, sizeof(sizeof(struct sigevent)));

  se.sigev_notify = SIGEV_SIGNAL;
  se.sigev_signo = SIGALRM;
  se.sigev_notify_attributes = NULL;

  se.sigev_value.sival_ptr = &base_addr->timer_id;
 
  if(timer_create(CLOCK_REALTIME, &se, &base_addr->timer_id)) {
    fprintf(stderr, "Timer Creation Failed\n");
    return(NULL);
  }

  base_addr->notify_callback = callback_handler;
  base_addr->next_node = NULL;

  /*Registering Callback for Signal Processing*/
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = timer_expire_callback;

  if(sigaction(SIGALRM, &sa, NULL)) {
    fprintf(stderr, "sigaction Failed\n"); 
    return(NULL);
  }
   
  return(base_addr->timer_id); 
}/*timer_create_timer*/

uint32_t timer_main(void) {
  struct sigaction sa;

  memset((void *)&sa, 0, sizeof(struct sigaction));

  sa.sa_sigaction = timer_expire_callback;

  /*Registering timer callback*/
  sigaction(SIGALRM, &sa, NULL);
  
  return(0);
}/*timer_main*/

#endif

