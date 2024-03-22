#ifndef __LWIP_TCP_SERVER_H
#define __LWIP_TCP_SERVER_H

#include <string.h>
#include "lwip/tcp.h"

enum tcp_server_states
{
    ES_NONE = 0,
    ES_ACCEPTED,
    ES_RECEIVED,
    ES_CLOSING
};

struct tcp_server_struct
{
    uint8_t state;       /* connection status */
    uint8_t retries;     /* number of retries */
    struct tcp_pcb *pcb; /* pointer on the current tcp_pcb */
    struct pbuf *p;      /* pointer on the received (but not yet sent) data */
};

// typedef struct
// {
//     struct tcp_pcb *pcb; /* pointer on the current tcp_pcb */
//     struct tcp_server_struct *es;
// } ring_buffer_element_t;

void tcp_server_init(void);
static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err);
static err_t tcp_server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
static void tcp_server_error(void *arg, err_t err);
static err_t tcp_server_poll(void *arg, struct tcp_pcb *pcb);
static err_t tcp_server_sent(void *arg, struct tcp_pcb *pcb, u16_t len);
static void tcp_server_send(struct tcp_pcb *pcb, struct tcp_server_struct *es);
static void tcp_server_close(struct tcp_pcb *pcb, struct tcp_server_struct *es);
static void tcp_server_handle_input(struct tcp_pcb *pcb, struct tcp_server_struct *es);
#endif // !__LWIP_TCP_SERVER_H