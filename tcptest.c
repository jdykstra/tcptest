/*
 * tcptest.c
 *
 *  Created on: Jan 12, 2014
 *      Author: jdykstra
 */

/*
 * Copyright (c) 2014 Cray Inc.  All rights reserved.
  */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/sysinfo.h>
#include <netdb.h>                  /* for gethostbyname */
#include <netinet/in.h>             /* for struct in_addr */
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>
#include <stdarg.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <poll.h>
#include <pthread.h>


#define IN
#define OUT
#define INOUT

#define TEST_REPEAT_COUNT 100
#define THRESHOLD 4
#define PRINT_ALL_STEPS 1


#define MAX_NODENAME_LENGTH	100

/* macros for handling errors.  If _pmi_abort_on_error is non-zero
   both of these macros lead to job abort */
/* macro for handling errors  - warning version*/
#define ERROR_WARN(message,args...) \
   {fprintf(stderr,message, ##args); }
/* macro for handling errors  - abort version*/
#define ERROR_FATAL(message,args...) \
   {fprintf(stderr,message, ##args); exit(1);}

/*
 * the port below is assigned to Fujitsu Config Protocol,
 * which ought not to be available on cray systems
 */
#define PMI_DEFAULT_TCP_PORT 1371
#define PMI_DEFAULT_CONNECT_TIMEOUT 2
#define PMI_DEFAULT_LISTEN_QUEUE_SIZE 128


static int listen_sock;		/* File descriptor we're listening on */
char client_name[MAX_NODENAME_LENGTH];   /* Node names of client and server */
char server_name[MAX_NODENAME_LENGTH];


void
log_tcp_info(int sfd, char *label)
{
    int tcp_info_len, threshold_exceeded;
    static char emsg[512];
    struct tcp_info tcp_info;
    time_t time2;

    if (sfd < 0) {
        snprintf(emsg, sizeof(emsg), "Invalid socket fd %d", sfd);
        ERROR_WARN("Error from log_tcp_info: %s", emsg);
        return;
    }
    tcp_info_len = sizeof(struct tcp_info);
    if (getsockopt(sfd, SOL_TCP, TCP_INFO, &tcp_info,
        (socklen_t *)&tcp_info_len) != 0) {
        snprintf(emsg, sizeof(emsg),"Socket %d getsockopt TCP_INFO failure: %s",
            sfd, strerror(errno));
        ERROR_WARN("Error from log_tcp_info: %s", emsg);
        return;
    }

    threshold_exceeded = tcp_info.tcpi_rto > THRESHOLD*1000000;

    if (PRINT_ALL_STEPS || threshold_exceeded)
    	fprintf(stdout, "fd %d %s tcpi_unacked %u retrans %u total_retrans %u snd_cwnd %u "
    		"last_data %u retransmits %u backoff %u snd_ssthres %u rto %u rtt %u rttvar %u rcv_rtt %u at %s\n",
                           sfd,
                           label,
                           tcp_info.tcpi_unacked,
                           tcp_info.tcpi_retrans,
                           tcp_info.tcpi_total_retrans,
                           tcp_info.tcpi_snd_cwnd,
                           tcp_info.tcpi_last_data_sent,
                           tcp_info.tcpi_retransmits,
                           tcp_info.tcpi_backoff,
                           tcp_info.tcpi_snd_ssthresh,
                           tcp_info.tcpi_rto,
                           tcp_info.tcpi_rtt,
                           tcp_info.tcpi_rttvar,
                           tcp_info.tcpi_rcv_rtt,
                           asctime(localtime(&time2)));

    /* Break out of the test if we see what we're looking for.  */
    if (threshold_exceeded){
    	fprintf(stdout, "Excessive RTO of %u us. seen.  Client %s server %s\n", tcp_info.tcpi_rto, client_name, server_name);
    }
}

static int
inet_create(void)
{
    int s;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        ERROR_WARN("inet_create: error opening socket %s\n", strerror(errno));
    }

    return s;
}

static int
inet_set_opts(int s)
{
    int arg, rc;
    int flags;

    arg = 1;
    rc = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &arg, sizeof (int));
    if (rc < 0) {
        ERROR_WARN("inet_set_opts: set setsockopt(TCP_NODELAY) failed %s\n", strerror(errno));
    }

    arg = 1048576;
    rc = setsockopt(s, SOL_SOCKET, SO_SNDBUF, &arg, sizeof (int));
    if (rc < 0) {
        ERROR_WARN("inet_set_opts: set setsockopt(SO_SNDBUF) failed %s\n", strerror(errno));
    }

    arg = 1048576;
    rc = setsockopt(s, SOL_SOCKET, SO_RCVBUF, &arg, sizeof (int));
    if (rc < 0) {
        ERROR_WARN("inet_set_opts: set setsockopt(SO_RCVBUF) failed %s\n", strerror(errno));
    }

    flags = fcntl(s, F_GETFL, 0);
    if (flags == -1) {
        rc = -1;
        ERROR_WARN("inet_setup_opts:fcntl(F_GETFL) failed %s\n",strerror(errno));
    }

    rc = fcntl(s, F_SETFL, flags | O_NONBLOCK);
    if (rc == -1) {
        ERROR_WARN("inet_setup_opts:fcntl(F_SETFL) failed %s\n",strerror(errno));
    }

    return rc;
}

static int
inet_ipaddr_from_dev(char *iface, struct in_addr *ip_addr)
{
    struct sockaddr_in *sin;
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        ERROR_WARN("inet_ipaddr_from_dev: socket call failed %s\n", strerror(errno));
        return -1;
    }

    /*
     * if iface is null, try to get eth0 interface address
     */

    ifr.ifr_addr.sa_family = AF_INET;
    if (iface == NULL) {
        sprintf(ifr.ifr_name,"eth0");
    } else {
        strcpy(ifr.ifr_name,iface);
    }

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        if(getenv("PMI_DEBUG_INET_IPADDR_FROM_DEV")) {
            ERROR_WARN("inet_ipaddr_from_dev: ioctl SIOCGIFADDR call failed %s\n", strerror(errno));
        }
        close(s);
        return -1;
    }

    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip_addr = sin->sin_addr;
    return 0;
}



/*
 * Function: inet_send
 *
 * Description: send a message over a socket in the TCP control network
 * Arguments:  s - socket
 *             nid - receiver nid
 *             buff - pointer to beginning of message
 *             nbytes - size of message
 *             ft_policy - fault tolerance policy
 * Returns:    on success, PMI_SUCCESS returned otherwise another pMI error
 *
 */

static int
inet_send(int s, int nid, void *buff, int nbytes )
{
    int n, sub, rc, flag, sock_errno;
    struct pollfd fd;
    char dummy;
    int nodes_down_start;
    int pmi_errno = 0;

    sub = 0;

    /*
     * TODO: use poll to be able to check for readability in case of FIN
     * from receiving process crashing.
     */
    do {

        fd.fd = s;
        fd.events = POLLIN | POLLOUT;
        fd.revents = 0;

        do {
            rc = poll(&fd, 1, 0);
        } while ((rc < 0) && (errno == EINTR));

        if (rc == 0) continue;

        if (rc == -1) {
            ERROR_WARN("inet_send: error on socket while writing %s\n", strerror(errno));
            goto fn_exit;
        }

        assert(rc == 1);

        /*
         * first check for hangups, double check by trying to peek at any
         * data to be read
         */

        if (fd.revents & POLLRDHUP) {
            rc = recv(s, &dummy, sizeof(char), MSG_PEEK);
            if (rc < 0) {
                ERROR_WARN("inet_send: hang up on socket while writing %s\n", strerror(errno));
                	pmi_errno = errno;
                goto fn_exit;
            }
        }
        log_tcp_info(s, "After recv()");

        /*
         * now check for socket errors - if ETIMEDOUT or EHOSTUNREACH that means
         * the receiver node has probably died , so return PMI_ERR_RANK_FAIL_STOP,
         * any other socket error, return PMI_FAIL.
         */

        if (fd.revents & POLLERR) {
            socklen_t len = sizeof(sock_errno);
            getsockopt(s, SOL_SOCKET, SO_ERROR, &sock_errno, &len);
            ERROR_WARN("socket error state %s\n", strerror(sock_errno));
            if ((sock_errno == ETIMEDOUT) || (sock_errno == EHOSTUNREACH)) {
            	pmi_errno = sock_errno;
                goto fn_exit;
            }
        }
        log_tcp_info(s, "After getsockopt()");

        if (fd.revents & POLLOUT) {
            do {
                n = send(s, (char *) buff + sub, nbytes - sub, 0);
            } while (n < 0 && (errno == EINTR || errno == EAGAIN));

           /*
            * handle error while sending, if it occured
            */

            if (n < 0) {

                switch (errno) {

                case ECONNRESET:    /* somehow rank at other end died and we didn't already catch error above */
                	pmi_errno = errno;
                	goto fn_exit;

                case EPIPE:        /* somehow we got pipe error even though we hadn't gotten ETIMEDOUT
                                  of EHOSTUNREACH socket error above, are we trapping SIGPIPE? */
                	pmi_errno = errno;
                    goto fn_exit;

                default:           /* all other errors treat as fatal PMI_FAIL */

                	pmi_errno = errno;
                    goto fn_exit;

                }
            }

            sub += n;
        }
        log_tcp_info(s, "After send()");

    } while (sub < nbytes);

  fn_exit:
    return pmi_errno;
}


static int
inet_connect(struct in_addr host_addr, int portnum, int nodeId,
             unsigned int timeout, unsigned int retry)
{
    struct sockaddr_in sin;
    int s, rc;
    static int firsttime=1;
    unsigned int initial_retries = retry;
    struct pollfd fd;
    int sock_errno;
    socklen_t len;

    s = inet_create();
    if (s < 0)
        goto fn_exit;
    log_tcp_info(s, "After socket()");

    rc = inet_set_opts(s);
    if (rc < 0) {
        s = -1;
        goto fn_exit;
    }

    memset(&sin, 0, sizeof (sin));

    sin.sin_addr = host_addr;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(portnum & 0xffff);

  fn_retry:

    errno = 0;
    rc = connect(s, (void *) &sin, sizeof (sin));
    log_tcp_info(s, "After connect()");
    if ((rc < 0) && (errno == EINPROGRESS)) {
        fd.fd = s;
        fd.events = POLLOUT;
        fd.revents = 0;
        do {
             errno = 0;
             rc = poll(&fd, 1, -1);
        } while ((rc < 0) && (errno == EINTR));

        /*
         * see if some error on the socket
         */

        if (fd.revents & POLLERR) {
            len = sizeof(sock_errno);
            getsockopt(s, SOL_SOCKET, SO_ERROR, &sock_errno, &len);
            if (sock_errno == ECONNREFUSED) {
                rc = -1;
                errno = sock_errno;
            } else {
                ERROR_WARN("socket error state %s\n", strerror(sock_errno));
                s = -1;
                goto fn_exit;
            }
        }
    }

    if (rc < 0) {

        /*
         * if ECONNREFUSED or ECONNABORTED, there is a chance that the controller
         * has not had time to set up its listening socket, wait
         * for 'timeout' seconds and retry
         */

        if ((errno == ECONNREFUSED) || (errno == ECONNABORTED)) {

            if (errno == ECONNABORTED) {
                close(s);
                s = inet_create();
                if (s < 0)
                    goto fn_exit;

                 rc = inet_set_opts(s);
                if (rc < 0) {
                    s = -1;
                    goto fn_exit;
                }

                memset(&sin, 0, sizeof (sin));
                sin.sin_addr = host_addr;
                sin.sin_family = AF_INET;
                sin.sin_port = htons(portnum & 0xffff);
            }

            if (firsttime) {

                /* It is likely this condition will be hit now that
                 * the PMI tcp network must be fully functional prior
                 * to the alps_sync call.  This leads to race
                 * conditions with the controller.
                 *
                 * We will sleep only for a half-second the first time,
                 * so we don't incur a noticeable delay on every launch.
                 */

                usleep(500000);  /* microseconds */
                firsttime=0;
                goto fn_retry;
            }

            if (!retry) {

                ERROR_WARN("inet_connect: connect failed after %d attempts\n", initial_retries+1);
                s = -1;
                goto fn_exit;

            } else {

                retry--;
                sleep(timeout);
                goto fn_retry;
            }

        } else {

            ERROR_WARN("connect returned with error = %s (%d)\n", strerror(errno),errno);
            s = -1;
            goto fn_exit;

        }
    }

    log_tcp_info(s, "After socket writable");
    rc = inet_send(s, nodeId, &nodeId, sizeof (int));
    if (rc != 0) {
        ERROR_WARN("inet_send returned with -1\n");
        s = -1;
        goto fn_exit;
    }

  fn_exit:

    return s;
}


/*
 * Function: inet_recv
 *
 * Description: receives a message over a socket in the TCP control network
 * Arguments:  s - socket
 *             nid - sender nid
 *             buff - pointer to beginning of buffer where message will
 *                    will be received
 *             nbytes - size of message to receive
 * Returns:    on success, PMI_SUCCESS, otherwise a PMI error
 *
 * Notes: A EOF is treated as an error unless the nbytes arguement is zero.
 */

static int
inet_recv(int s, int nid, void *buff, int nbytes)
{
    int n, sub, flag;
    int pmi_errno = 0;
    int nodes_down_start,nodes_down_now;

    sub = 0;

    do {
        do {

            errno = 0;
            n = recv(s, (char *) buff + sub, nbytes - sub, 0);
            if (n > 0) continue;   /* we're reading data, keep going */

            /*
             * EOF is treated as okay if nbytes == 0, otherwise error
             */

            if (n == 0) {
                if (nbytes == 0) {
                    pmi_errno = 0;
                    goto fn_exit;
                } else {
                    ERROR_WARN("inet_recv: unexpected EOF %s\n", strerror(errno));
                    pmi_errno = 999;
                    goto fn_exit;
                }
            }

           /*
            * handle error while reading, if it happened. Any socket
            * error results in PMI_FAIL except for EINTER and EAGAIN
            */

            if ((n < 0)  && !(errno == EINTR || errno == EAGAIN)) {
                ERROR_WARN("inet_recv: recv error (fd=%d) %s\n", s,strerror(errno));
                pmi_errno = 999;
                goto fn_exit;
            }


        } while (n < 0 && (errno == EINTR || errno == EAGAIN));

        sub += n;

    } while (sub < nbytes);

  fn_exit:
    return pmi_errno;
}


static int
inet_accept_with_address(int sock)
{
    struct sockaddr_in from;
    int s, rc, nid=0;
    socklen_t fromlen;
    struct pollfd fd;
    int flags;
    int data;

    fromlen = sizeof (struct sockaddr_in);

    fd.fd = sock;
    fd.events = POLLIN;
    fd.revents = 0;

    do {
         rc = poll(&fd, 1, -1);
    } while ((rc < 0) && (errno == EINTR));

    s = accept(sock, (void *) &from, (void *)&fromlen);
    if (s < 0) {
        ERROR_WARN("inet_accept: accept failed %s\n",strerror(errno));
    }

    flags = fcntl(s, F_GETFL, 0);
    if (flags == -1) {
        rc = -1;
        ERROR_WARN("inet_setup_opts:fcntl(F_GETFL) failed %s\n",strerror(errno));
    }

    rc = fcntl(s, F_SETFL, flags | O_NONBLOCK);
    if (rc == -1) {
        ERROR_WARN("inet_setup_opts:fcntl(F_SETFL) failed %s\n",strerror(errno));
    }

    rc = inet_recv(s, nid, &data, sizeof (int));
    if (rc != 0) {
        ERROR_WARN("inet_accept: inet_recv returned error %s\n", strerror(errno));
        s = -1;
    }

    return s;
}

/*
 * Function: inet_listen_socket_setup
 *
 * Description: Set up the listening socket for the TCP control network.
 *
 * Returns:     on success return socket, otherwise -1 or -errno
 */
static int
inet_listen_socket_setup(struct in_addr *host_addr, int portnum, int backlog)
{
    int s, rc, sinlen, on = 1;
    struct sockaddr_in sin;
    struct in_addr ip_addr;
    int listen_sock;

    listen_sock = inet_create();
    if (listen_sock < 0) {

        ERROR_WARN("socket create failed\n");
        s = -1;
        goto fn_exit;

    }

    rc = inet_set_opts(listen_sock);
    if (rc < 0) {
        ERROR_WARN("set sockopts failed\n");
        s = -1;
        goto fn_exit;

    }

    /*
     * set the SO_REUSEADDR sock opt
     */

    rc = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on,
                    sizeof (int));
    if (rc < 0) {
        ERROR_WARN("set setsockopt(SO_REUSEADDR) failed %s\n",
                   strerror(errno));
        s = -1;
        goto fn_exit;

    }

    if (host_addr) {
        ip_addr = *host_addr;
    } else {
        rc = inet_ipaddr_from_dev(NULL,&ip_addr);
        if (rc < 0) {
            ERROR_WARN("inet_listen_socket_setup: using wildcard bind IP addr %s\n",strerror(errno));
            ip_addr.s_addr = htonl(INADDR_ANY);
            s = -1;
        }
    }

    sin.sin_family = AF_INET;
    sin.sin_addr =  ip_addr;
    sin.sin_port = htons(portnum);

    sinlen = sizeof (sin);

    rc = bind(listen_sock, (void *) &sin, sinlen);
    if (rc < 0) {
        ERROR_WARN("inet_setup_listen_socket: bind failed port %d listen_sock = %d %s\n", portnum, listen_sock, strerror(errno));
        s = -1;
        goto fn_exit;
    }

    rc = listen(listen_sock, backlog);
    if (rc < 0) {
        ERROR_WARN("inet_setup_listen_socket: listen failed %s\n", strerror(errno));
        s = -1;
        goto fn_exit;
    }

    s = listen_sock;

  fn_exit:

    return s;
}

int
inet_addr_to_use(OUT struct in_addr *addr_to_use)
{
    char *str;
    char gni[]="ipogif0";
    int rc;
    struct in_addr addr;

	/*
	 * check for Aries/Gemini interface
	 */

	rc = inet_ipaddr_from_dev(gni,&addr);
	if (rc == 0) goto fn_exit;

	 /*
	 * no gemini, seastar or knc, use default
	 */
	rc = inet_ipaddr_from_dev(NULL,&addr);

fn_exit:

    *addr_to_use = addr;

    return rc;

}



int do_server_side()
{
	struct in_addr addr_to_use;
	int rc, s, repeat_count = TEST_REPEAT_COUNT;

	rc = inet_addr_to_use(&addr_to_use);
	if (rc != 0) {
		ERROR_WARN("failed to find interface to use for tcp network\n");
		exit(1);
	}

	listen_sock = inet_listen_socket_setup(&addr_to_use, PMI_DEFAULT_TCP_PORT,
			PMI_DEFAULT_LISTEN_QUEUE_SIZE);

	while (repeat_count--){
		s = inet_accept_with_address(listen_sock);
		close(s);
	}

	return 0;
}


int do_client_side(char *server_name)
{
    struct in_addr server_addr;
    struct hostent *hptr=NULL;
	int data = 0xcafebabe, s, repeat_count = TEST_REPEAT_COUNT;

    hptr = gethostbyname(server_name);
    if (hptr == NULL) {
        ERROR_WARN("gethostbyname failed for hostname %s error %s\n",
        		server_name,hstrerror(h_errno));
        return 1;
    }
    assert(hptr->h_addrtype == AF_INET);
    server_addr = *(struct in_addr *)(*hptr->h_addr_list);

    while (repeat_count--){
    	s = inet_connect(server_addr, PMI_DEFAULT_TCP_PORT, data, 10, 5);
    	close(s);
    }

	return 0;
}

int main(int argc, char *argv[])
{
	char hostname[MAX_NODENAME_LENGTH];
	int we_are_server;

	if (argc != 2){
		fprintf(stderr, "Usage:  tcptest [server-nid]");
		return 0;
	}

	if (gethostname(hostname, sizeof(hostname)) != 0)
		fprintf(stderr, "Error returned from gethostname.\n");

	if (strcmp(argv[1], hostname) == 0){
		strncpy(client_name, "(unknown)", MAX_NODENAME_LENGTH);
		strncpy(server_name, hostname, MAX_NODENAME_LENGTH);
		fprintf(stdout, "We (%s) are the server.\n,", server_name);
		(void) do_server_side();
	}
	else {
		strncpy(client_name, hostname, MAX_NODENAME_LENGTH);
		strncpy(server_name, argv[1], MAX_NODENAME_LENGTH);
		fprintf(stdout, "We (%s) are the client.  %s is the server\n,", client_name, server_name);
		(void)do_client_side(server_name);
	}

	fprintf(stdout, "Successful completion of %d trials.\n", TEST_REPEAT_COUNT);
	return 1;
}
