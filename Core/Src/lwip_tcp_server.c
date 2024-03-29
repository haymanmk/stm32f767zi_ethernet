#include "lwip_tcp_server.h"

void tcp_server_init(void)
{
    struct tcp_pcb *pcb;
    err_t err;

    /* Create a new TCP control block  */
    pcb = tcp_new();

    if (pcb != NULL)
    {
        /* Bind pcb to port 8500 */
        // ip_addr_t ipaddr;
        // IP_ADDR4(&ipaddr, 172, 16, 0, 10);
        // err = tcp_bind(pcb, &ipaddr, 8500);
        err = tcp_bind(pcb, IP4_ADDR_ANY, 8500);

        if (err == ERR_OK)
        {
            /* Put the TCP connection into LISTEN state */
            pcb = tcp_listen(pcb);

            /* Initialize LwIP tcp_accept callback function */
            tcp_accept(pcb, tcp_server_accept);
        }
        else
        {
            /* deallocate the PCB */
            memp_free(MEMP_TCP_PCB, pcb);
        }
    }
}

static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    err_t ret_err;
    struct tcp_server_struct *es;

    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(err);

    /* Set priority for the newly accepted tcp connection newpcb */
    tcp_setprio(newpcb, TCP_PRIO_MIN);

    /* Allocate structure es to maintain tcp connection information */
    es = (struct tcp_server_struct *)mem_malloc(sizeof(struct tcp_server_struct));
    if (es != NULL)
    {
        es->state = ES_ACCEPTED;
        es->pcb = newpcb;
        es->retries = 0;
        es->p = NULL;

        /* pass newly allocated es structure as argument to newpcb */
        tcp_arg(newpcb, es);

        /* initialize lwip tcp_recv callback function for newpcb  */
        tcp_recv(newpcb, tcp_server_recv);

        /* initialize lwip tcp_err callback function for newpcb  */
        tcp_err(newpcb, tcp_server_error);

        /* initialize lwip tcp_poll callback function for newpcb */
        tcp_poll(newpcb, tcp_server_poll, 0);

        ret_err = ERR_OK;
    }
    else
    {
        ret_err = ERR_MEM;
    }

    return ret_err;
}

static err_t tcp_server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct tcp_server_struct *es;
    err_t ret_err;

    LWIP_ASSERT("arg != NULL", arg != NULL);

    es = (struct tcp_server_struct *)arg;

    /* if we receive an empty tcp frame from client, close the connection */
    if (p == NULL)
    {
        /* remote host closed connection */
        es->state = ES_CLOSING;
        if (es->p == NULL)
        {
            /* we're done sending, close it */
            tcp_server_close(pcb, es);
        }
        else
        {
            /* we're not done yet */
            /* acknowledge received packet */
            tcp_sent(pcb, tcp_server_sent);
            /* send remaining data */
            tcp_server_send(pcb, es);
        }
        ret_err = ERR_OK;
    }
    /* else : a non empty frame was received from client but for some reason err != ERR_OK */
    else if (err != ERR_OK)
    {
        /* free received pbuf */
        if (p != NULL)
        {
            pbuf_free(p);
        }
        ret_err = err;
    }
    else if (es->state == ES_ACCEPTED)
    {
        /* first data chunk in p->payload */
        es->state = ES_RECEIVED;
        /* store reference to incoming pbuf (chain) */
        es->p = p;
        /* initialize LwIP tcp_sent callback function */
        tcp_sent(pcb, tcp_server_sent);
        /* handle received data */
        tcp_server_send(pcb, es);

        ret_err = ERR_OK;
    }
    else if (es->state == ES_RECEIVED)
    {
        /* read some more data */
        if (es->p == NULL)
        {
            es->p = p;
            tcp_server_handle_input(pcb, es);
        }
        else
        {
            struct pbuf *ptr;
            /* chain pbufs to the end of what we recv'ed previously  */
            ptr = es->p;
            LWIP_ASSERT("Same pbuf", ptr != p);
            pbuf_chain(ptr, p);
        }
        ret_err = ERR_OK;
    }
    else if (es->state == ES_CLOSING)
    {
        /* odd case, remote side closing twice, trash data */
        if (p != NULL)
        {
            /* free received pbuf */
            pbuf_free(p);
        }
    }
    else
    {
        /* unkown es->state, trash data */
        tcp_server_close(pcb, es);
        ret_err = ERR_OK;
    }
    return ret_err;
}

static void tcp_server_error(void *arg, err_t err)
{
    struct tcp_server_struct *es;

    LWIP_UNUSED_ARG(err);

    es = (struct tcp_server_struct *)arg;
    if (es != NULL)
    {
        mem_free(es);
    }
}

static err_t tcp_server_poll(void *arg, struct tcp_pcb *pcb)
{
    err_t ret_err;
    struct tcp_server_struct *es;

    es = (struct tcp_server_struct *)arg;
    if (es != NULL)
    {
        if (es->p != NULL)
        {
            /* there is a remaining pbuf (chain)  */
            tcp_sent(pcb, tcp_server_sent);
            tcp_server_send(pcb, es);
        }
        else
        {
            /* no remaining pbuf (chain)  */
            if (es->state == ES_CLOSING)
            {
                /* close tcp connection */
                tcp_server_close(pcb, es);
            }
        }
        ret_err = ERR_OK;
    }
    else
    {
        /* nothing to be done */
        tcp_abort(pcb);
        ret_err = ERR_ABRT;
    }
    return ret_err;
}

static err_t tcp_server_sent(void *arg, struct tcp_pcb *pcb, uint16_t len)
{
    struct tcp_server_struct *es;
    LWIP_UNUSED_ARG(len);

    es = (struct tcp_server_struct *)arg;
    es->retries = 0;

    if (es->p != NULL)
    {
        /* still got pbufs to send */
        tcp_sent(pcb, tcp_server_sent);
        tcp_server_send(pcb, es);
    }
    else
    {
        /* no more pbufs to send */
        if (es->state == ES_CLOSING)
        {
            tcp_server_close(pcb, es);
        }
    }
    return ERR_OK;
}

static void tcp_server_send(struct tcp_pcb *pcb, struct tcp_server_struct *es)
{
    struct pbuf *ptr;
    err_t wr_err = ERR_OK;

    printf("Sending data\n");

    while ((wr_err == ERR_OK) &&
           (es->p != NULL) &&
           (es->p->len <= tcp_sndbuf(pcb)))
    {
        /* get pointer on pbuf from es structure */
        ptr = es->p;
        printf("Sending ptr: 0x%08x\n", ptr);

        /* enqueue data for transmission */
        wr_err = tcp_write(pcb, ptr->payload, ptr->len, 1);

        if (wr_err == ERR_OK)
        {
            uint16_t plen;
            uint8_t freed;

            plen = ptr->len;
            /* continue with next pbuf in chain (if any) */
            es->p = ptr->next;
            if (es->p != NULL)
            {
                /* new reference! */
                pbuf_ref(es->p);
            }

            if (ptr->ref == 0)
            {
                printf("Ref count is 0\n");
            }

            /* chop first pbuf from chain */
            do
            {
                /* try hard to free pbuf */
                freed = pbuf_free(ptr);
            } while (freed == 0);
            /* we can read more data now */
            tcp_recved(pcb, plen);
        }
        else if (wr_err == ERR_MEM)
        {
            /* we are low on memory, try later, defer to poll */
            es->p = ptr;
        }
        else
        {
            /* other problem ?? */
        }
    }
}

static void tcp_server_close(struct tcp_pcb *pcb, struct tcp_server_struct *es)
{
    /* remove callbacks */
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_err(pcb, NULL);
    tcp_poll(pcb, NULL, 0);

    /* delete es structure */
    if (es != NULL)
    {
        mem_free(es);
    }

    /* close tcp connection */
    tcp_close(pcb);
}

static void tcp_server_handle_input(struct tcp_pcb *pcb, struct tcp_server_struct *es)
{
    struct tcp_server_struct *esTx;

    /* get the Remote IP */
    ip4_addr_t inIP = pcb->remote_ip;
    uint16_t inPort = pcb->remote_port;

    /* Extract the IP */
    char *remIP = ipaddr_ntoa(&inIP);

    esTx->state = es->state;
    esTx->pcb = es->pcb;
    esTx->p = es->p;

    char buf[100];
    memset(buf, '\0', 100);

    strncpy(buf, (char *)es->p->payload, es->p->tot_len);
    char additionalString[100];
    sprintf(additionalString, " from %s:%d", remIP, inPort);
    strcat(buf, additionalString);

    esTx->p->payload = (void *)buf;
    esTx->p->tot_len = (es->p->tot_len - es->p->len) + strlen(buf);
    esTx->p->len = strlen(buf);

    tcp_server_send(pcb, esTx);

    // pbuf_free(es->p);
}