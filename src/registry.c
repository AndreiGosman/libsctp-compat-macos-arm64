/*
 * fd registry, backend bring-up and the receive pump.
 *
 * Copyright (C) 2026 Andrei Gosman
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * usrsctp has no file descriptors. It hands data to a callback on its own
 * thread and identifies sockets by pointer. Callers written for Linux want
 * an int fd they can poll(), recv() and close(). The bridge is one AF_UNIX
 * SOCK_DGRAM socketpair per SCTP socket: the application holds one end, the
 * receive callback writes framed messages into the other. Message
 * boundaries survive, so SOCK_SEQPACKET semantics survive with them, and
 * poll() works because the fd is a real kernel object.
 */

#include "compat_internal.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LSC_MAX_CONNS 256

static struct lsc_conn  *g_conns[LSC_MAX_CONNS];
static pthread_rwlock_t  g_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_once_t    g_backend_once = PTHREAD_ONCE_INIT;
static int               g_backend_rc = -1;
static int               g_debug = -1;
static uint16_t          g_encaps_port;
static uint16_t          g_encaps_remote_port;

/* ------------------------------------------------------------------ */
/* logging                                                             */
/* ------------------------------------------------------------------ */

void lsc_log(const char *fmt, ...)
{
	va_list ap;

	if (g_debug < 0) {
		const char *e = getenv("LIBSCTP_COMPAT_DEBUG");
		g_debug = (e != NULL && *e == '1') ? 1 : 0;
	}
	if (!g_debug)
		return;

	fputs("[libsctp-compat] ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void lsc_usrsctp_debug(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* ------------------------------------------------------------------ */
/* real libc entry points                                              */
/* ------------------------------------------------------------------ */

/*
 * This library exports socket(), bind() and friends so that the link editor
 * binds the application to us instead of libSystem. To reach the real
 * implementation we must skip ourselves. RTLD_NEXT does that when we are
 * ahead of libSystem in the load order; if the resolved address is our own
 * symbol we fall back to an explicit handle on libSystem.
 */
static void *lsc_real_sym(const char *name, void *self)
{
	static void *libsystem;
	void        *p;

	p = dlsym(RTLD_NEXT, name);
	if (p != NULL && p != self)
		return p;

	if (libsystem == NULL)
		libsystem = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
	if (libsystem == NULL) {
		lsc_log("cannot open libSystem to resolve %s", name);
		abort();
	}
	p = dlsym(libsystem, name);
	if (p == NULL) {
		lsc_log("cannot resolve %s in libSystem", name);
		abort();
	}
	return p;
}

#define LSC_REAL(ret, name, params, args)                                  \
	ret lsc_real_##name params                                         \
	{                                                                  \
		static ret (*fn) params;                                   \
		if (fn == NULL)                                            \
			fn = (ret (*) params)lsc_real_sym(#name,           \
			                                  (void *)name);   \
		return fn args;                                            \
	}

int socket(int, int, int);
int close(int);
int bind(int, const struct sockaddr *, socklen_t);
int listen(int, int);
int connect(int, const struct sockaddr *, socklen_t);
int setsockopt(int, int, int, const void *, socklen_t);
int getsockopt(int, int, int, void *, socklen_t *);
int getsockname(int, struct sockaddr *, socklen_t *);
int getpeername(int, struct sockaddr *, socklen_t *);
int shutdown(int, int);
ssize_t sendmsg(int, const struct msghdr *, int);
ssize_t recvmsg(int, struct msghdr *, int);
int accept(int, struct sockaddr *, socklen_t *);

LSC_REAL(int, socket, (int d, int t, int p), (d, t, p))
LSC_REAL(int, close, (int fd), (fd))
LSC_REAL(int, bind, (int fd, const struct sockaddr *a, socklen_t l), (fd, a, l))
LSC_REAL(int, listen, (int fd, int b), (fd, b))
LSC_REAL(int, connect, (int fd, const struct sockaddr *a, socklen_t l), (fd, a, l))
LSC_REAL(int, setsockopt, (int fd, int lv, int n, const void *v, socklen_t l), (fd, lv, n, v, l))
LSC_REAL(int, getsockopt, (int fd, int lv, int n, void *v, socklen_t *l), (fd, lv, n, v, l))
LSC_REAL(int, getsockname, (int fd, struct sockaddr *a, socklen_t *l), (fd, a, l))
LSC_REAL(int, getpeername, (int fd, struct sockaddr *a, socklen_t *l), (fd, a, l))
LSC_REAL(int, shutdown, (int fd, int h), (fd, h))
LSC_REAL(ssize_t, sendmsg, (int fd, const struct msghdr *m, int f), (fd, m, f))
LSC_REAL(ssize_t, recvmsg, (int fd, struct msghdr *m, int f), (fd, m, f))
LSC_REAL(int, accept, (int fd, struct sockaddr *a, socklen_t *l), (fd, a, l))

/* ------------------------------------------------------------------ */
/* backend bring-up                                                    */
/* ------------------------------------------------------------------ */

static uint16_t lsc_port_env(const char *name)
{
	const char *v = getenv(name);
	long        n;

	if (v == NULL || *v == '\0')
		return 0;
	n = strtol(v, NULL, 10);
	return (n > 0 && n < 65536) ? (uint16_t)n : 0;
}

/*
 * usrsctp_init returns void. If it cannot bind the UDP tunnelling port,
 * because another process on the host already holds it, it carries on with no
 * transport at all: sends go nowhere and connect() still reports success on a
 * one-to-many socket, because that call only queues the INIT. Check the port
 * first so the failure is visible instead of looking like a silent network.
 */
static int lsc_port_is_free(uint16_t port)
{
	struct sockaddr_in addr;
	int                fd, rc, on = 1;

	fd = lsc_real_socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return 1; /* cannot tell; do not block the caller */

	(void)lsc_real_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&addr, 0, sizeof(addr));
	addr.sin_len         = sizeof(addr);
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	rc = lsc_real_bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	lsc_real_close(fd);
	return rc == 0;
}

static void lsc_backend_once(void)
{
	uint16_t port = lsc_port_env("LIBSCTP_COMPAT_UDP_ENCAPS_PORT");

	/* Two processes on one host cannot share a tunnelling port, so each
	 * needs its own and has to be told the peer's. Default to the local
	 * one, which is right for a single process talking to a remote host. */
	g_encaps_remote_port = lsc_port_env("LIBSCTP_COMPAT_UDP_ENCAPS_REMOTE_PORT");
	if (g_encaps_remote_port == 0)
		g_encaps_remote_port = port;

	if (port != 0 && !lsc_port_is_free(port)) {
		fprintf(stderr,
		        "[libsctp-compat] UDP encapsulation port %u is already in "
		        "use; another process holds it. Set "
		        "LIBSCTP_COMPAT_UDP_ENCAPS_PORT to a free port and point "
		        "the peer at it with "
		        "LIBSCTP_COMPAT_UDP_ENCAPS_REMOTE_PORT.\n",
		        port);
		g_backend_rc = -1;
		return;
	}

	/*
	 * Port 0 puts usrsctp on raw IPPROTO_SCTP sockets, which is what a
	 * real peer expects on the wire. Darwin needs root for that. A
	 * non-zero port selects UDP encapsulation (RFC 6951) instead, which
	 * needs no privilege but needs a peer that also encapsulates.
	 */
	usrsctp_init(port, NULL, g_debug == 1 ? lsc_usrsctp_debug : NULL);
	usrsctp_sysctl_set_sctp_blackhole(2);
	/* Loopback traffic must still carry a checksum, otherwise an
	 * encapsulated association to 127.0.0.1 is dropped as corrupt. */
	usrsctp_sysctl_set_sctp_no_csum_on_loopback(0);
	g_encaps_port = port;
	if (port != 0)
		lsc_log("usrsctp up, UDP encapsulation, local port %u, peer port %u",
		        port, g_encaps_remote_port);
	else
		lsc_log("usrsctp up, raw sockets (needs root)");
	g_backend_rc = 0;
}

int lsc_backend_init(void)
{
	pthread_once(&g_backend_once, lsc_backend_once);
	if (g_backend_rc != 0)
		errno = EPROTONOSUPPORT;
	return g_backend_rc;
}

/* ------------------------------------------------------------------ */
/* registry                                                            */
/* ------------------------------------------------------------------ */

struct lsc_conn *lsc_lookup(int fd)
{
	struct lsc_conn *c = NULL;
	int              i;

	if (fd < 0)
		return NULL;

	pthread_rwlock_rdlock(&g_lock);
	for (i = 0; i < LSC_MAX_CONNS; i++) {
		if (g_conns[i] != NULL && g_conns[i]->app_fd == fd) {
			c = g_conns[i];
			break;
		}
	}
	pthread_rwlock_unlock(&g_lock);
	return c;
}

/*
 * Everything a connection needs except the usrsctp socket: the socketpair
 * that gives the application a pollable descriptor, and a slot in the
 * table. socket() then creates a usrsctp socket, accept() adopts one that
 * usrsctp has already made for us.
 */
static struct lsc_conn *lsc_alloc(int domain, int type)
{
	struct lsc_conn *c;
	int              sv[2];
	int              bufsz = LSC_MAX_MSG;

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
		free(c);
		return NULL;
	}

	/*
	 * The default AF_UNIX datagram buffer on Darwin is a few kilobytes,
	 * well under one SCTP message. Raise both ends; ignore failure, a
	 * smaller buffer only costs us large messages.
	 */
	(void)lsc_real_setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
	(void)lsc_real_setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));

	c->app_fd  = sv[0];
	c->pump_fd = sv[1];
	c->domain  = domain;
	c->type    = type;
	pthread_mutex_init(&c->tx_lock, NULL);
	pthread_mutex_init(&c->acc_lock, NULL);
	return c;
}

static void lsc_free(struct lsc_conn *c)
{
	lsc_real_close(c->app_fd);
	lsc_real_close(c->pump_fd);
	pthread_mutex_destroy(&c->tx_lock);
	pthread_mutex_destroy(&c->acc_lock);
	free(c);
}

/* Defined below, next to the receive callback it shares its framing with. */
static void lsc_catch_up(struct lsc_conn *c);

struct lsc_conn *lsc_lookup_sock(struct socket *us)
{
	struct lsc_conn *c = NULL;
	int              i;

	if (us == NULL)
		return NULL;

	pthread_rwlock_rdlock(&g_lock);
	for (i = 0; i < LSC_MAX_CONNS; i++) {
		if (g_conns[i] != NULL && g_conns[i]->us == us) {
			c = g_conns[i];
			break;
		}
	}
	pthread_rwlock_unlock(&g_lock);
	return c;
}

/* Publish a fully built connection. Returns 0, or -1 with the table full. */
static int lsc_publish(struct lsc_conn *c)
{
	int slot;

	pthread_rwlock_wrlock(&g_lock);
	for (slot = 0; slot < LSC_MAX_CONNS; slot++) {
		if (g_conns[slot] == NULL) {
			g_conns[slot] = c;
			break;
		}
	}
	pthread_rwlock_unlock(&g_lock);

	if (slot == LSC_MAX_CONNS) {
		errno = EMFILE;
		return -1;
	}
	return 0;
}

/* Remove a connection from the table without touching its usrsctp socket. */
static void lsc_unpublish(struct lsc_conn *c)
{
	int i;

	pthread_rwlock_wrlock(&g_lock);
	for (i = 0; i < LSC_MAX_CONNS; i++) {
		if (g_conns[i] == c) {
			g_conns[i] = NULL;
			break;
		}
	}
	pthread_rwlock_unlock(&g_lock);
}

/*
 * usrsctp sends to a peer over UDP encapsulation only when the socket has
 * been told which remote port to encapsulate towards. The port given to
 * usrsctp_init governs receive alone.
 */
static void lsc_set_encaps(struct lsc_conn *c)
{
	struct sctp_udpencaps enc;

	if (g_encaps_port == 0)
		return;

	memset(&enc, 0, sizeof(enc));
	enc.sue_address.ss_family = (sa_family_t)c->domain;
	enc.sue_address.ss_len    = sizeof(enc.sue_address);
	enc.sue_port              = htons(g_encaps_remote_port);
	if (usrsctp_setsockopt(c->us, IPPROTO_SCTP,
	                       SCTP_REMOTE_UDP_ENCAPS_PORT, &enc,
	                       sizeof(enc)) != 0)
		lsc_log("cannot set remote encapsulation port: %s",
		        strerror(errno));
}

struct lsc_conn *lsc_create(int domain, int type)
{
	struct lsc_conn *c;

	if (lsc_backend_init() != 0)
		return NULL;

	c = lsc_alloc(domain, type);
	if (c == NULL)
		return NULL;

	c->us = usrsctp_socket(domain, type, IPPROTO_SCTP, lsc_recv_cb, NULL, 0, c);
	if (c->us == NULL) {
		int saved = errno;
		lsc_free(c);
		errno = saved ? saved : EPROTONOSUPPORT;
		return NULL;
	}

	lsc_set_encaps(c);

	if (lsc_publish(c) != 0) {
		usrsctp_close(c->us);
		lsc_free(c);
		return NULL;
	}

	lsc_log("socket type=%d app_fd=%d us=%p", type, c->app_fd, (void *)c->us);
	return c;
}

struct lsc_conn *lsc_adopt(int domain, int type, struct socket *us)
{
	struct lsc_conn *c = lsc_alloc(domain, type);

	if (c == NULL)
		return NULL;

	c->us = us;

	/*
	 * Publish before touching ulp_info. An accepted socket inherits the
	 * listener's receive callback and the listener's ulp_info, so until
	 * that is repointed a message on the new association would be framed
	 * onto the listener's descriptor and lost. The receive callback
	 * resolves the connection by socket for exactly that reason, and it
	 * can only do so once the connection is in the table. Registering
	 * first therefore closes the window rather than widening it.
	 */
	if (lsc_publish(c) != 0) {
		lsc_free(c);
		return NULL;
	}

	/* register_ulp_info reports success as 1, not 0. It is the odd one
	 * out: usrsctp_set_upcall and the rest use the POSIX convention. */
	if (usrsctp_set_ulpinfo(us, c) != 1) {
		lsc_unpublish(c);
		lsc_free(c);
		errno = EINVAL;
		return NULL;
	}

	lsc_set_encaps(c);

	/* Anything the peer sent before we got here is already queued on the
	 * socket and will not be announced again. Take it now. */
	lsc_catch_up(c);

	lsc_log("adopt type=%d app_fd=%d us=%p", type, c->app_fd, (void *)us);
	return c;
}

/* One readiness token on a listener's pump. */
static int lsc_pump_token(struct lsc_conn *c)
{
	unsigned char token = 0;
	struct iovec  iov;
	struct msghdr msg;

	iov.iov_base = &token;
	iov.iov_len  = sizeof(token);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	return (int)lsc_real_sendmsg(c->pump_fd, &msg, 0);
}

/* Append an adopted association to a listener's queue. */
static void lsc_accept_push(struct lsc_conn *l, struct lsc_conn *nc)
{
	pthread_mutex_lock(&l->acc_lock);
	nc->acc_next = NULL;
	if (l->acc_tail != NULL)
		l->acc_tail->acc_next = nc;
	else
		l->acc_head = nc;
	l->acc_tail = nc;
	pthread_mutex_unlock(&l->acc_lock);
}

struct lsc_conn *lsc_accept_pop(struct lsc_conn *l)
{
	struct lsc_conn *nc;

	pthread_mutex_lock(&l->acc_lock);
	nc = l->acc_head;
	if (nc != NULL) {
		l->acc_head = nc->acc_next;
		if (l->acc_head == NULL)
			l->acc_tail = NULL;
		nc->acc_next = NULL;
	}
	pthread_mutex_unlock(&l->acc_lock);
	return nc;
}

void lsc_accept_drain(struct lsc_conn *l)
{
	struct lsc_conn *nc;

	while ((nc = lsc_accept_pop(l)) != NULL) {
		lsc_log("dropping unaccepted association app_fd=%d", nc->app_fd);
		lsc_destroy(nc);
	}
}

/*
 * A listening socket produces no data, so nothing ever writes to its pump
 * and poll() on the application descriptor would never fire.
 *
 * Asking usrsctp whether the socket is readable is not good enough.
 * soreadable() is also true when so_error is set, and a non-blocking
 * usrsctp_accept() answers EWOULDBLOCK without ever clearing that error, so
 * the descriptor would stay readable and a poll driven caller would spin.
 *
 * Take the associations here instead. Everything usrsctp has ready is
 * accepted, adopted and queued, and exactly one token goes on the pump per
 * queued entry. A readable descriptor then always means accept() has
 * something to return.
 */
static void lsc_listen_upcall(struct socket *so, void *arg, int flags)
{
	struct lsc_conn *c = arg;

	(void)flags;
	(void)so;

	if (c == NULL || c->closing)
		return;

	for (;;) {
		struct sockaddr_storage ss;
		socklen_t               alen = sizeof(ss);
		struct socket          *ns;
		struct lsc_conn        *nc;

		memset(&ss, 0, sizeof(ss));
		ns = usrsctp_accept(c->us, (struct sockaddr *)&ss, &alen);
		if (ns == NULL)
			break; /* EWOULDBLOCK, or nothing left to take */

		nc = lsc_adopt(c->domain, c->type, ns);
		if (nc == NULL) {
			lsc_log("cannot adopt an accepted association: %s",
			        strerror(errno));
			usrsctp_close(ns);
			continue;
		}

		/* Remember the peer so accept() can hand it back. */
		if (alen > 0 && alen <= sizeof(nc->peer)) {
			memcpy(&nc->peer, &ss, alen);
			nc->peerlen = alen;
		}

		lsc_accept_push(c, nc);

		if (lsc_pump_token(c) < 0)
			lsc_log("listen pump write failed on app_fd=%d: %s",
			        c->app_fd, strerror(errno));
	}
}

int lsc_listen_arm(struct lsc_conn *c)
{
	/*
	 * usrsctp_accept() waits on a condition variable when the queue is
	 * empty. The upcall runs on a usrsctp thread, so a wait there would
	 * stall the stack itself. Non-blocking turns it into EWOULDBLOCK,
	 * which is how the loop above knows it is done.
	 */
	usrsctp_set_non_blocking(c->us, 1);
	c->listening = 1;
	return usrsctp_set_upcall(c->us, lsc_listen_upcall, c);
}

void lsc_destroy(struct lsc_conn *c)
{
	int i;

	if (c == NULL)
		return;

	pthread_rwlock_wrlock(&g_lock);
	for (i = 0; i < LSC_MAX_CONNS; i++) {
		if (g_conns[i] == c) {
			g_conns[i] = NULL;
			break;
		}
	}
	c->closing = 1;
	pthread_rwlock_unlock(&g_lock);

	lsc_log("close app_fd=%d", c->app_fd);

	/* Associations that arrived but were never accepted still own a
	 * usrsctp socket and a socketpair. Closing the listener has to take
	 * them with it. */
	if (c->listening)
		lsc_accept_drain(c);

	if (c->us != NULL)
		usrsctp_close(c->us);
	if (c->pump_fd >= 0)
		lsc_real_close(c->pump_fd);
	/* app_fd is closed by the caller of close(), not here. */

	pthread_mutex_destroy(&c->tx_lock);
	free(c);
}

void lsc_registry_init(void)
{
	/* Static initialisers do the work; kept for symmetry. */
}

/* ------------------------------------------------------------------ */
/* the pump                                                            */
/* ------------------------------------------------------------------ */

/*
 * Frame one received message onto a connection's pump. Shared by the usrsctp
 * receive callback and by the catch-up read that adoption performs.
 */
static void lsc_pump_frame(struct lsc_conn *c, const void *data, size_t datalen,
                           const struct sockaddr_storage *from, socklen_t fromlen,
                           const struct sctp_rcvinfo *rcv, int flags)
{
	struct lsc_frame hdr;
	struct iovec     iov[2];
	struct msghdr    msg;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic       = LSC_FRAME_MAGIC;
	hdr.flags       = flags;
	hdr.payload_len = 0;

	if (data != NULL && datalen > 0) {
		if (datalen > LSC_MAX_MSG) {
			lsc_log("dropping %zu byte message, over %d limit",
			        datalen, LSC_MAX_MSG);
			return;
		}
		hdr.payload_len = (uint32_t)datalen;
	}

	if (from != NULL && fromlen > 0 && fromlen <= sizeof(hdr.from)) {
		memcpy(&hdr.from, from, fromlen);
		hdr.fromlen = fromlen;
	}

	hdr.sri.sinfo_stream   = rcv->rcv_sid;
	hdr.sri.sinfo_ssn      = rcv->rcv_ssn;
	/*
	 * Do not pass rcv_flags through. usrsctp reports the DATA chunk's
	 * fragmentation bits here, shifted into the high byte: a complete
	 * message arrives as 0x0300, which is first-fragment and last-fragment
	 * together. The send side reads that same byte as SCTP_EOF and
	 * SCTP_ABORT. Callers commonly keep the received sctp_sndrcvinfo and
	 * hand it back to sctp_send to answer on the same association, and on
	 * Linux that is safe because those bits never appear there. Here it
	 * would shut the association down and abort it, with the send still
	 * reporting success, so the peer simply stops hearing anything.
	 *
	 * Report only what Linux reports: whether the message was unordered.
	 */
	hdr.sri.sinfo_flags    = (rcv->rcv_flags & SCTP_UNORDERED) ? SCTP_UNORDERED : 0;
	hdr.sri.sinfo_ppid     = rcv->rcv_ppid;
	hdr.sri.sinfo_context  = rcv->rcv_context;
	hdr.sri.sinfo_tsn      = rcv->rcv_tsn;
	hdr.sri.sinfo_cumtsn   = rcv->rcv_cumtsn;
	hdr.sri.sinfo_assoc_id = rcv->rcv_assoc_id;

	iov[0].iov_base = &hdr;
	iov[0].iov_len  = sizeof(hdr);
	iov[1].iov_base = (void *)data;
	iov[1].iov_len  = hdr.payload_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov    = iov;
	msg.msg_iovlen = hdr.payload_len > 0 ? 2 : 1;

	/* lsc_real_sendmsg, not sendmsg: we export the latter now, and a
	 * plain call would bind to our own definition and recurse. */
	if (lsc_real_sendmsg(c->pump_fd, &msg, 0) < 0)
		lsc_log("pump write failed on app_fd=%d: %s",
		        c->app_fd, strerror(errno));
}

/*
 * Read whatever usrsctp already holds for a freshly adopted socket.
 *
 * The receive callback fires once, when a message is queued. A peer that
 * sends immediately after connect() can have its data queued on the accepted
 * socket before this library ever sees the association: the callback for it
 * has already been and gone, and nothing fires again. Without this read the
 * message sits in the socket buffer for good and the peer waits forever for
 * an answer. It is one message in tens under load, which is exactly the kind
 * of loss that looks like a network problem.
 */
static void lsc_catch_up(struct lsc_conn *c)
{
	char *buf = malloc(LSC_MAX_MSG);

	if (buf == NULL)
		return;

	for (;;) {
		struct sockaddr_storage from;
		struct sctp_rcvinfo     rcv;
		socklen_t               fromlen  = sizeof(from);
		socklen_t               infolen  = sizeof(rcv);
		unsigned int            infotype = 0;
		int                     msg_flags = 0;
		ssize_t                 n;

		memset(&from, 0, sizeof(from));
		memset(&rcv, 0, sizeof(rcv));

		n = usrsctp_recvv(c->us, buf, LSC_MAX_MSG,
		                  (struct sockaddr *)&from, &fromlen,
		                  &rcv, &infolen, &infotype, &msg_flags);
		if (n <= 0)
			break;

		if (infotype != SCTP_RECVV_RCVINFO)
			memset(&rcv, 0, sizeof(rcv));

		lsc_log("catch-up: %zd bytes already queued on app_fd=%d", n,
		        c->app_fd);
		lsc_pump_frame(c, buf, (size_t)n, &from, fromlen, &rcv, msg_flags);
	}

	free(buf);
}

int lsc_recv_cb(struct socket *sock, union sctp_sockstore addr, void *data,
                size_t datalen, struct sctp_rcvinfo rcv, int flags,
                void *ulp_info)
{
	struct lsc_conn        *c = (struct lsc_conn *)ulp_info;
	struct sockaddr_storage from;
	socklen_t               fromlen = 0;

	/*
	 * An accepted socket keeps the listener's ulp_info until adoption
	 * repoints it, and a message can arrive inside that window. Framing it
	 * onto the listener's descriptor would lose the payload and hand the
	 * listener a readiness report with no connection behind it, so resolve
	 * by socket whenever ulp_info names a different one.
	 */
	if (c == NULL || c->us != sock) {
		struct lsc_conn *real = lsc_lookup_sock(sock);

		if (real != NULL)
			c = real;
	}

	if (c == NULL) {
		free(data);
		return 1;
	}

	memset(&from, 0, sizeof(from));
	switch (addr.sa.sa_family) {
	case AF_INET:
		memcpy(&from, &addr.sin, sizeof(addr.sin));
		fromlen = sizeof(addr.sin);
		break;
	case AF_INET6:
		memcpy(&from, &addr.sin6, sizeof(addr.sin6));
		fromlen = sizeof(addr.sin6);
		break;
	default:
		break;
	}

	lsc_pump_frame(c, data, datalen, &from, fromlen, &rcv, flags);

	free(data);
	return 1;
}
