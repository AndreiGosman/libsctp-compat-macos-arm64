/*
 * Interposition of the socket calls that carry SCTP traffic.
 *
 * Copyright (C) 2026 Andrei Gosman
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Only calls on an SCTP descriptor are diverted to usrsctp. Everything
 * else is handed straight to libSystem, so UDP and TCP in the same process
 * behave exactly as before.
 */

#include "compat_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * usrsctp is built with HAVE_SA_LEN and HAVE_SIN_LEN, so it reads sa_len.
 * Code written for Linux zeroes the sockaddr and never sets that field,
 * because Linux has no such field. Fill it in on the way through.
 */
static const struct sockaddr *lsc_fix_sa(const struct sockaddr *sa,
                                         socklen_t len,
                                         struct sockaddr_storage *out)
{
	if (sa == NULL || len == 0 || len > sizeof(*out))
		return sa;

	memcpy(out, sa, len);

	switch (out->ss_family) {
	case AF_INET:
		out->ss_len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		out->ss_len = sizeof(struct sockaddr_in6);
		break;
	default:
		if (out->ss_len == 0)
			out->ss_len = (uint8_t)len;
		break;
	}
	return (const struct sockaddr *)out;
}

int socket(int domain, int type, int protocol)
{
	struct lsc_conn *c;

	if (protocol != IPPROTO_SCTP)
		return lsc_real_socket(domain, type, protocol);

	if (domain != AF_INET && domain != AF_INET6) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	if (type != SOCK_SEQPACKET && type != SOCK_STREAM) {
		errno = ESOCKTNOSUPPORT;
		return -1;
	}

	c = lsc_create(domain, type);
	if (c == NULL)
		return -1;

	return c->app_fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	struct sockaddr_storage ss;
	struct lsc_conn        *c = lsc_lookup(fd);

	if (c == NULL)
		return lsc_real_bind(fd, addr, len);

	return usrsctp_bind(c->us, (struct sockaddr *)lsc_fix_sa(addr, len, &ss),
	                    len);
}

int listen(int fd, int backlog)
{
	struct lsc_conn *c = lsc_lookup(fd);

	if (c == NULL)
		return lsc_real_listen(fd, backlog);

	if (usrsctp_listen(c->us, backlog) != 0)
		return -1;

	c->listening = 1;

	/*
	 * Only a one-to-one socket hands out connections through accept(), and
	 * only its descriptor needs the readiness pump. On a one-to-many socket
	 * listen() merely allows incoming associations: the data arrives on
	 * this same descriptor through the receive callback, which is how
	 * srsRAN's MME uses it. Arming the accept machinery there would set
	 * the backend non-blocking and take over a descriptor that is carrying
	 * real traffic.
	 */
	if (c->type != SOCK_STREAM)
		return 0;

	/* From here on the descriptor reports readable when an association
	 * is waiting, so poll() driven servers work unchanged. */
	if (lsc_listen_arm(c) != 0) {
		lsc_log("cannot arm listen pump on fd=%d: %s", fd,
		        strerror(errno));
		return -1;
	}
	return 0;
}

int accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct lsc_conn *c = lsc_lookup(fd);
	struct lsc_conn *nc;
	unsigned char    token;
	struct iovec     iov;
	struct msghdr    mh;

	if (c == NULL)
		return lsc_real_accept(fd, addr, addrlen);

	if (!c->listening) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * The association was already taken off usrsctp and adopted by the
	 * upcall, so there is nothing to wait for here. Take one entry and
	 * one token, keeping the two in step: a descriptor that still reads
	 * as readable means another connection is queued behind this one.
	 */
	iov.iov_base = &token;
	iov.iov_len  = sizeof(token);
	memset(&mh, 0, sizeof(mh));
	mh.msg_iov    = &iov;
	mh.msg_iovlen = 1;

	nc = lsc_accept_pop(c);
	if (nc == NULL) {
		/*
		 * Nothing queued, so anything sitting on the pump is stale.
		 * Take one datagram off anyway. The upcall queues the
		 * connection before it writes the token, so a token always has
		 * its entry behind it; leaving a stray one would keep the
		 * descriptor readable and spin the caller's event loop.
		 */
		(void)lsc_real_recvmsg(c->app_fd, &mh, MSG_DONTWAIT);
		errno = EAGAIN;
		return -1;
	}

	iov.iov_base = &token;
	iov.iov_len  = sizeof(token);
	memset(&mh, 0, sizeof(mh));
	mh.msg_iov    = &iov;
	mh.msg_iovlen = 1;
	(void)lsc_real_recvmsg(c->app_fd, &mh, MSG_DONTWAIT);

	if (addr != NULL && addrlen != NULL && nc->peerlen > 0) {
		socklen_t want = nc->peerlen < *addrlen ? nc->peerlen : *addrlen;
		memcpy(addr, &nc->peer, want);
		*addrlen = nc->peerlen;
	}

	return nc->app_fd;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	struct sockaddr_storage ss;
	struct lsc_conn        *c = lsc_lookup(fd);

	if (c == NULL)
		return lsc_real_connect(fd, addr, len);

	if (usrsctp_connect(c->us,
	                    (struct sockaddr *)lsc_fix_sa(addr, len, &ss),
	                    len) != 0)
		return -1;

	c->connects++;

	if (c->connects > 1) {
		/* Several associations on one socket. There is no single
		 * default any more, so stop pretending there is one. */
		c->peerlen = 0;
		lsc_log("fd=%d has %u associations, default peer dropped",
		        fd, c->connects);
	} else if (len > 0 && len <= sizeof(c->peer)) {
		memcpy(&c->peer, &ss, len);
		c->peerlen = len;
	}
	return 0;
}

int close(int fd)
{
	struct lsc_conn *c = lsc_lookup(fd);

	if (c != NULL)
		lsc_destroy(c);

	return lsc_real_close(fd);
}

int shutdown(int fd, int how)
{
	struct lsc_conn *c = lsc_lookup(fd);

	if (c == NULL)
		return lsc_real_shutdown(fd, how);

	return usrsctp_shutdown(c->us, how);
}

/*
 * Linux numbers SCTP_EVENTS 0x0b. FreeBSD and usrsctp number the same
 * option 0x0c. Our header uses the Linux value, so translate here.
 */
#define LINUX_SCTP_EVENTS   0x0000000b
#define USRSCTP_SCTP_EVENTS 0x0000000c

static int lsc_map_sctp_opt(int name)
{
	if (name == LINUX_SCTP_EVENTS)
		return USRSCTP_SCTP_EVENTS;
	return name;
}

int setsockopt(int fd, int level, int name, const void *val, socklen_t len)
{
	struct lsc_conn *c = lsc_lookup(fd);

	if (c == NULL)
		return lsc_real_setsockopt(fd, level, name, val, len);

	/*
	 * Timeouts and buffer sizes belong to the descriptor the caller
	 * actually reads from, which is our end of the socketpair. Leaving
	 * SO_RCVTIMEO here is what lets a receive loop see EAGAIN on idle,
	 * the behaviour srsRAN and Osmocom both depend on.
	 */
	if (level == SOL_SOCKET) {
		switch (name) {
		case SO_RCVTIMEO:
		case SO_SNDTIMEO:
		case SO_RCVBUF:
		case SO_SNDBUF:
		/*
		 * usrsctp_setsockopt() rejects SOL_SOCKET with EINVAL, and an
		 * SCTP server in libosmocore sets SO_REUSEADDR before it binds,
		 * so forwarding these keeps that path working. usrsctp owns the
		 * UDP encapsulation socket underneath, so the option cannot
		 * reach the descriptor that actually carries the association.
		 * The call therefore succeeds without giving the Linux TIME_WAIT
		 * rebinding semantics.
		 */
		case SO_REUSEADDR:
		case SO_REUSEPORT:
			return lsc_real_setsockopt(fd, level, name, val, len);
#ifdef SO_NOSIGPIPE
		/*
		 * libosmo-netif sets SO_NOSIGPIPE on every stream client and
		 * server connection where the option exists. usrsctp never
		 * raises SIGPIPE, and usrsctp_setsockopt() would answer EINVAL
		 * for SOL_SOCKET, which the caller logs as an error on every
		 * association. Accept the request as a no-op.
		 */
		case SO_NOSIGPIPE:
			return 0;
#endif
		default:
			break;
		}
	}

	if (level == IPPROTO_SCTP)
		name = lsc_map_sctp_opt(name);

	return usrsctp_setsockopt(c->us, level, name, val, len);
}

int getsockopt(int fd, int level, int name, void *val, socklen_t *len)
{
	struct lsc_conn *c = lsc_lookup(fd);

	if (c == NULL)
		return lsc_real_getsockopt(fd, level, name, val, len);

	if (level == SOL_SOCKET) {
		switch (name) {
		case SO_RCVTIMEO:
		case SO_SNDTIMEO:
		case SO_RCVBUF:
		case SO_SNDBUF:
			return lsc_real_getsockopt(fd, level, name, val, len);
		default:
			break;
		}
	}

	if (level == IPPROTO_SCTP)
		name = lsc_map_sctp_opt(name);

	return usrsctp_getsockopt(c->us, level, name, val, len);
}

/*
 * usrsctp exposes no getsockname or getpeername. The address lists give
 * the same information; return the first entry, which is the primary.
 */
static int lsc_first_addr(struct sockaddr *addrs, int count,
                          struct sockaddr *out, socklen_t *outlen)
{
	socklen_t want;

	if (count <= 0 || addrs == NULL) {
		errno = ENOTCONN;
		return -1;
	}

	switch (addrs->sa_family) {
	case AF_INET:
		want = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		want = sizeof(struct sockaddr_in6);
		break;
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (*outlen < want)
		want = *outlen;
	memcpy(out, addrs, want);
	*outlen = want;
	return 0;
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len)
{
	struct lsc_conn *c = lsc_lookup(fd);
	struct sockaddr *addrs = NULL;
	int              n, rc;

	if (c == NULL)
		return lsc_real_getsockname(fd, addr, len);

	n  = usrsctp_getladdrs(c->us, 0, &addrs);
	rc = lsc_first_addr(addrs, n, addr, len);
	if (addrs != NULL)
		usrsctp_freeladdrs(addrs);
	return rc;
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *len)
{
	struct lsc_conn *c = lsc_lookup(fd);
	struct sockaddr *addrs = NULL;
	int              n, rc;

	if (c == NULL)
		return lsc_real_getpeername(fd, addr, len);

	n  = usrsctp_getpaddrs(c->us, 0, &addrs);
	rc = lsc_first_addr(addrs, n, addr, len);
	if (addrs != NULL)
		usrsctp_freepaddrs(addrs);
	return rc;
}

/* ------------------------------------------------------------------ */
/* raw sendmsg and recvmsg on an SCTP descriptor                        */
/* ------------------------------------------------------------------ */

/*
 * Ancillary data on IPPROTO_SCTP. Our public netinet/sctp.h names these,
 * but that header and usrsctp.h cannot both be included here, so the two
 * values this library understands are repeated. They follow lksctp.
 */
#define LSC_CMSG_SNDRCV  1
#define LSC_CMSG_SNDINFO 2

/*
 * Callers that use osmo_io, or any other layer that drives sockets through
 * sendmsg and recvmsg rather than the sctp_*() helpers, reach these. The
 * SCTP parameters travel in a control message instead of in arguments; the
 * payload travels in an iovec instead of one flat buffer. Unpack both and
 * join the same path that sctp_sendmsg uses.
 */
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	struct lsc_conn        *c = lsc_lookup(fd);
	const struct cmsghdr   *cm;
	struct lsc_sndrcvinfo   sri;
	struct sockaddr_storage ss;
	const struct sockaddr  *dst = NULL;
	socklen_t               dstlen = 0;
	unsigned char          *buf = NULL;
	const void             *payload;
	size_t                  total = 0;
	ssize_t                 rc;
	int                     i;

	if (c == NULL)
		return lsc_real_sendmsg(fd, msg, flags);

	if (msg == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(&sri, 0, sizeof(sri));

	for (cm = CMSG_FIRSTHDR((struct msghdr *)msg); cm != NULL;
	     cm = CMSG_NXTHDR((struct msghdr *)msg, (struct cmsghdr *)cm)) {
		if (cm->cmsg_level != IPPROTO_SCTP)
			continue;

		if (cm->cmsg_type == LSC_CMSG_SNDRCV &&
		    cm->cmsg_len >= CMSG_LEN(sizeof(sri))) {
			memcpy(&sri, CMSG_DATA((struct cmsghdr *)cm), sizeof(sri));
		} else if (cm->cmsg_type == LSC_CMSG_SNDINFO &&
		           cm->cmsg_len >= CMSG_LEN(sizeof(struct sctp_sndinfo))) {
			struct sctp_sndinfo si;

			memcpy(&si, CMSG_DATA((struct cmsghdr *)cm), sizeof(si));
			sri.sinfo_stream   = si.snd_sid;
			sri.sinfo_flags    = si.snd_flags;
			sri.sinfo_ppid     = si.snd_ppid;
			sri.sinfo_context  = si.snd_context;
			sri.sinfo_assoc_id = si.snd_assoc_id;
		}
	}

	if (msg->msg_name != NULL && msg->msg_namelen > 0) {
		dst    = lsc_fix_sa(msg->msg_name, msg->msg_namelen, &ss);
		dstlen = msg->msg_namelen;
	}

	for (i = 0; i < (int)msg->msg_iovlen; i++)
		total += msg->msg_iov[i].iov_len;

	if (total > LSC_MAX_MSG) {
		errno = EMSGSIZE;
		return -1;
	}

	/* One buffer is the common case and needs no copy. */
	if (msg->msg_iovlen == 1) {
		payload = msg->msg_iov[0].iov_base;
	} else {
		size_t off = 0;

		buf = malloc(total ? total : 1);
		if (buf == NULL) {
			errno = ENOMEM;
			return -1;
		}
		for (i = 0; i < (int)msg->msg_iovlen; i++) {
			memcpy(buf + off, msg->msg_iov[i].iov_base,
			       msg->msg_iov[i].iov_len);
			off += msg->msg_iov[i].iov_len;
		}
		payload = buf;
	}

	rc = lsc_sendv(c, payload, total, dst, dstlen, sri.sinfo_ppid,
	               sri.sinfo_flags, sri.sinfo_stream, sri.sinfo_context,
	               sri.sinfo_assoc_id, flags);

	free(buf);
	return rc;
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
	struct lsc_conn *c = lsc_lookup(fd);
	struct lsc_frame hdr;
	unsigned char   *buf;
	struct iovec     riov[2];
	struct msghdr    rmh;
	ssize_t          n;
	size_t           payload, copied = 0;
	int              i;

	if (c == NULL)
		return lsc_real_recvmsg(fd, msg, flags);

	if (msg == NULL) {
		errno = EINVAL;
		return -1;
	}

	buf = malloc(LSC_MAX_MSG);
	if (buf == NULL) {
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Read the whole frame first. Scattering straight into the caller's
	 * iovec would work only while the header and the payload land on the
	 * boundary the caller happens to have chosen.
	 */
	riov[0].iov_base = &hdr;
	riov[0].iov_len  = sizeof(hdr);
	riov[1].iov_base = buf;
	riov[1].iov_len  = LSC_MAX_MSG;

	memset(&rmh, 0, sizeof(rmh));
	rmh.msg_iov    = riov;
	rmh.msg_iovlen = 2;

	n = lsc_real_recvmsg(c->app_fd, &rmh, flags);
	if (n < 0) {
		free(buf);
		return -1;
	}
	if ((size_t)n < sizeof(hdr) || hdr.magic != LSC_FRAME_MAGIC) {
		lsc_log("malformed frame on app_fd=%d, %zd bytes", c->app_fd, n);
		free(buf);
		errno = EPROTO;
		return -1;
	}

	payload = (size_t)n - sizeof(hdr);

	for (i = 0; i < (int)msg->msg_iovlen && copied < payload; i++) {
		size_t take = payload - copied;

		if (take > msg->msg_iov[i].iov_len)
			take = msg->msg_iov[i].iov_len;
		memcpy(msg->msg_iov[i].iov_base, buf + copied, take);
		copied += take;
	}

	msg->msg_flags = hdr.flags | (rmh.msg_flags & MSG_TRUNC);
	if (copied < payload)
		msg->msg_flags |= MSG_TRUNC;

	if (msg->msg_name != NULL && msg->msg_namelen > 0 && hdr.fromlen > 0) {
		socklen_t want = hdr.fromlen;

		if (want > msg->msg_namelen)
			want = msg->msg_namelen;
		memcpy(msg->msg_name, &hdr.from, want);
		msg->msg_namelen = hdr.fromlen;
	} else {
		msg->msg_namelen = 0;
	}

	/*
	 * Hand the sender information back as an SCTP_SNDRCV control message,
	 * which is where a caller written for lksctp looks for it. Too small
	 * a control buffer is reported the way the kernel reports it, with
	 * MSG_CTRUNC, rather than as a failure.
	 */
	if (msg->msg_control != NULL &&
	    msg->msg_controllen >= CMSG_SPACE(sizeof(hdr.sri))) {
		struct cmsghdr *cm = CMSG_FIRSTHDR(msg);

		cm->cmsg_level = IPPROTO_SCTP;
		cm->cmsg_type  = LSC_CMSG_SNDRCV;
		cm->cmsg_len   = CMSG_LEN(sizeof(hdr.sri));
		memcpy(CMSG_DATA(cm), &hdr.sri, sizeof(hdr.sri));
		msg->msg_controllen = CMSG_SPACE(sizeof(hdr.sri));
	} else {
		if (msg->msg_controllen > 0)
			msg->msg_flags |= MSG_CTRUNC;
		msg->msg_controllen = 0;
	}

	free(buf);
	return (ssize_t)copied;
}
