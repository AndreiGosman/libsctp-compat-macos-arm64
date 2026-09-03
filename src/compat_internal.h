/*
 * Internal state for libsctp-compat.
 *
 * Copyright (C) 2026 Andrei Gosman
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef LIBSCTP_COMPAT_INTERNAL_H
#define LIBSCTP_COMPAT_INTERNAL_H

#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <usrsctp.h>

/* Our public header and usrsctp.h both describe SCTP. Only the .c files
 * that talk to the backend include usrsctp.h; they use the layouts below
 * for the application-facing types. Keep this struct byte-identical to
 * struct sctp_sndrcvinfo in include/netinet/sctp.h. */
struct lsc_sndrcvinfo {
	uint16_t sinfo_stream;
	uint16_t sinfo_ssn;
	uint16_t sinfo_flags;
	uint32_t sinfo_ppid;
	uint32_t sinfo_context;
	uint32_t sinfo_timetolive;
	uint32_t sinfo_tsn;
	uint32_t sinfo_cumtsn;
	uint32_t sinfo_assoc_id;
};

#define LSC_FRAME_MAGIC 0x53435450u /* "SCTP" */

/*
 * One datagram on the AF_UNIX socketpair carries this header followed by
 * the payload. AF_UNIX SOCK_DGRAM keeps message boundaries, which is what
 * SCTP SOCK_SEQPACKET callers expect.
 */
struct lsc_frame {
	uint32_t                magic;
	int32_t                 flags;       /* MSG_NOTIFICATION, MSG_EOR */
	uint32_t                payload_len;
	uint32_t                fromlen;
	struct sockaddr_storage from;
	struct lsc_sndrcvinfo   sri;
};

/* Largest SCTP message we forward through the pump. */
#define LSC_MAX_MSG (256 * 1024)

struct lsc_conn {
	int             app_fd;   /* returned to the application */
	int             pump_fd;  /* written by the usrsctp callback */
	struct socket  *us;       /* usrsctp socket */
	int             type;     /* SOCK_SEQPACKET or SOCK_STREAM */
	int             domain;
	int             closing;
	/* Peer recorded by connect(). usrsctp will not infer the association
	 * of a one-to-many socket from a previous connect the way Linux does,
	 * so we supply the address again on every send that omits one. */
	struct sockaddr_storage peer;
	socklen_t               peerlen;
	unsigned                connects;
	pthread_mutex_t tx_lock;
};

/* Registry. Lookups happen on every intercepted libc call, so the table is
 * a flat array under a read-mostly lock. */
void            lsc_registry_init(void);
struct lsc_conn *lsc_lookup(int fd);
struct lsc_conn *lsc_create(int domain, int type);
void            lsc_destroy(struct lsc_conn *c);

/* Lazy one-time usrsctp_init. Returns 0 on success, -1 with errno set. */
int lsc_backend_init(void);

/* The usrsctp receive callback. Frames data onto pump_fd. */
int lsc_recv_cb(struct socket *sock, union sctp_sockstore addr, void *data,
                size_t datalen, struct sctp_rcvinfo rcv, int flags,
                void *ulp_info);

/* Real libc entry points, resolved once with dlsym. */
int  lsc_real_socket(int domain, int type, int protocol);
int  lsc_real_close(int fd);
int  lsc_real_bind(int fd, const struct sockaddr *addr, socklen_t len);
int  lsc_real_listen(int fd, int backlog);
int  lsc_real_connect(int fd, const struct sockaddr *addr, socklen_t len);
int  lsc_real_setsockopt(int fd, int level, int name, const void *val,
                         socklen_t len);
int  lsc_real_getsockopt(int fd, int level, int name, void *val,
                         socklen_t *len);
int  lsc_real_getsockname(int fd, struct sockaddr *addr, socklen_t *len);
int  lsc_real_getpeername(int fd, struct sockaddr *addr, socklen_t *len);
int  lsc_real_shutdown(int fd, int how);

/* Debug logging, enabled by LIBSCTP_COMPAT_DEBUG=1. */
void lsc_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif /* LIBSCTP_COMPAT_INTERNAL_H */
