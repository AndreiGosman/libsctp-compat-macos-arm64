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

	return usrsctp_listen(c->us, backlog);
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

	if (len > 0 && len <= sizeof(c->peer)) {
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
			return lsc_real_setsockopt(fd, level, name, val, len);
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
