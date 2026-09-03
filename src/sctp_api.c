/*
 * The lksctp function API on top of usrsctp.
 *
 * Copyright (C) 2026 Andrei Gosman
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Sends go straight into usrsctp_sendv. Receives come off the socketpair
 * that the pump in registry.c feeds, so the caller keeps a pollable fd and
 * an honest EAGAIN on timeout.
 */

#include "compat_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Declared by our public header, opaque here: this file talks to usrsctp,
 * whose header describes the same protocol with different types. */
struct sctp_sndrcvinfo;

/* Mirrors the layout in include/netinet/sctp.h. */
struct sctp_sndrcvinfo_pub {
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

static const struct sockaddr *lsc_fix_sa_local(const struct sockaddr *sa,
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

static ssize_t lsc_sendv(struct lsc_conn *c, const void *msg, size_t len,
                         const struct sockaddr *to, socklen_t tolen,
                         uint32_t ppid, uint16_t flags, uint16_t stream,
                         uint32_t context, uint32_t assoc_id, int sendflags)
{
	struct sctp_sndinfo     info;
	struct sockaddr_storage ss;
	const struct sockaddr  *dst;
	ssize_t                 rc;

	memset(&info, 0, sizeof(info));
	info.snd_sid      = stream;
	info.snd_flags    = flags;
	info.snd_ppid     = ppid;
	info.snd_context  = context;
	info.snd_assoc_id = assoc_id;

	dst = lsc_fix_sa_local(to, tolen, &ss);

	/*
	 * An association identified only by its id is not enough to reach the
	 * peer when UDP encapsulation is in use. usrsctp then takes the
	 * encapsulation port from the association rather than from the socket,
	 * and an association accepted from an incoming INIT does not carry one,
	 * so the reply leaves as bare SCTP and is lost. The send still reports
	 * success, which makes it look like the peer stopped answering.
	 *
	 * Supplying the address as well puts the send back on the path that
	 * honours the socket's setting. The lookup costs an allocation per
	 * send, which is acceptable on the control plane this serves; callers
	 * that pass an address already skip it.
	 */
	if (dst == NULL && assoc_id != 0) {
		struct sockaddr *paddrs = NULL;
		int              n      = usrsctp_getpaddrs(c->us, assoc_id, &paddrs);

		lsc_log("send by assoc %u: getpaddrs -> %d", assoc_id, n);

		if (n > 0 && paddrs != NULL) {
			socklen_t plen = 0;

			switch (paddrs->sa_family) {
			case AF_INET:
				plen = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				plen = sizeof(struct sockaddr_in6);
				break;
			default:
				break;
			}
			if (plen > 0 && plen <= sizeof(ss)) {
				/* Normalise sa_len as for any other address:
				 * usrsctp reads it and what getpaddrs returns
				 * is not guaranteed to carry one. */
				dst   = lsc_fix_sa_local(paddrs, plen, &ss);
				tolen = plen;
				lsc_log("send by assoc %u: peer family %d len %u",
				        assoc_id, (int)paddrs->sa_family, (unsigned)plen);
				/* Clear the id: given both, usrsctp resolves by
				 * association and the address is ignored, which
				 * is the path that loses the encapsulation port. */
				info.snd_assoc_id = 0;
			}
			usrsctp_freepaddrs(paddrs);
		}
	}

	/*
	 * With neither a destination nor an association id, usrsctp returns
	 * ENOENT. RFC 6458 section 3.1.3 agrees with usrsctp here: on a
	 * one-to-many socket connect() creates an association but no default
	 * destination. Code written against Linux is often looser than that,
	 * so we fall back to the peer of a single connect() as a convenience.
	 * The fallback is dropped once a second connect() makes the choice
	 * ambiguous, because guessing between two associations would send
	 * data to the wrong peer without saying so.
	 */
	if (dst == NULL && assoc_id == 0 && c->peerlen > 0) {
		dst    = (const struct sockaddr *)&c->peer;
		tolen  = c->peerlen;
	}

	pthread_mutex_lock(&c->tx_lock);
	rc = usrsctp_sendv(c->us, msg, len, (struct sockaddr *)dst,
	                   dst != NULL ? 1 : 0, &info, sizeof(info),
	                   SCTP_SENDV_SNDINFO, sendflags);
	pthread_mutex_unlock(&c->tx_lock);

	return rc;
}

ssize_t sctp_sendmsg(int sd, const void *msg, size_t len,
                     struct sockaddr *to, socklen_t tolen,
                     uint32_t ppid, uint32_t flags,
                     uint16_t stream_no, uint32_t timetolive,
                     uint32_t context)
{
	struct lsc_conn *c = lsc_lookup(sd);

	/*
	 * timetolive is a partial reliability parameter. usrsctp carries it
	 * in a separate prinfo block; the callers this library targets always
	 * pass zero, so a non-zero value is reported rather than dropped in
	 * silence.
	 */
	if (timetolive != 0)
		lsc_log("sctp_sendmsg timetolive=%u ignored", timetolive);

	if (c == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	return lsc_sendv(c, msg, len, to, tolen, ppid, (uint16_t)flags,
	                 stream_no, context, 0, 0);
}

ssize_t sctp_send(int sd, const void *msg, size_t len,
                  const struct sctp_sndrcvinfo *sinfo, int flags)
{
	const struct sctp_sndrcvinfo_pub *s =
	    (const struct sctp_sndrcvinfo_pub *)sinfo;
	struct lsc_conn *c = lsc_lookup(sd);

	if (c == NULL) {
		errno = ENOTSOCK;
		return -1;
	}
	if (s == NULL) {
		errno = EINVAL;
		return -1;
	}

	return lsc_sendv(c, msg, len, NULL, 0, s->sinfo_ppid,
	                 s->sinfo_flags, s->sinfo_stream, s->sinfo_context,
	                 s->sinfo_assoc_id, flags);
}

ssize_t sctp_recvmsg(int sd, void *msg, size_t len,
                     struct sockaddr *from, socklen_t *fromlen,
                     struct sctp_sndrcvinfo *sinfo, int *msg_flags)
{
	struct sctp_sndrcvinfo_pub *out = (struct sctp_sndrcvinfo_pub *)sinfo;
	struct lsc_conn            *c   = lsc_lookup(sd);
	struct lsc_frame            hdr;
	struct iovec                iov[2];
	struct msghdr               mh;
	ssize_t                     n;
	size_t                      copy;

	if (c == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	iov[0].iov_base = &hdr;
	iov[0].iov_len  = sizeof(hdr);
	iov[1].iov_base = msg;
	iov[1].iov_len  = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_iov    = iov;
	mh.msg_iovlen = 2;

	/*
	 * One datagram in, one message out. A short user buffer truncates the
	 * payload exactly as a kernel SCTP socket would, and the kernel sets
	 * MSG_TRUNC for us on the socketpair read.
	 */
	n = recvmsg(c->app_fd, &mh, 0);
	if (n < 0)
		return -1;

	if ((size_t)n < sizeof(hdr) || hdr.magic != LSC_FRAME_MAGIC) {
		lsc_log("malformed frame on app_fd=%d, %zd bytes", c->app_fd, n);
		errno = EPROTO;
		return -1;
	}

	copy = (size_t)n - sizeof(hdr);
	if (copy > len)
		copy = len;

	if (from != NULL && fromlen != NULL && hdr.fromlen > 0) {
		socklen_t want = hdr.fromlen;
		if (want > *fromlen)
			want = *fromlen;
		memcpy(from, &hdr.from, want);
		*fromlen = want;
	} else if (fromlen != NULL) {
		*fromlen = 0;
	}

	if (out != NULL) {
		memcpy(out, &hdr.sri, sizeof(*out));
	}

	if (msg_flags != NULL)
		*msg_flags = hdr.flags | (mh.msg_flags & MSG_TRUNC);

	return (ssize_t)copy;
}

/* ------------------------------------------------------------------ */
/* address and option helpers                                          */
/* ------------------------------------------------------------------ */

int sctp_bindx(int sd, struct sockaddr *addrs, int addrcnt, int flags)
{
	struct lsc_conn *c = lsc_lookup(sd);
	int              i;
	struct sockaddr *p = addrs;

	if (c == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	/*
	 * usrsctp_bindx takes one address at a time. Walk the packed array
	 * the caller supplied; entries are variable length by family.
	 */
	for (i = 0; i < addrcnt; i++) {
		struct sockaddr_storage ss;
		socklen_t               step;

		switch (p->sa_family) {
		case AF_INET:
			step = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			step = sizeof(struct sockaddr_in6);
			break;
		default:
			errno = EAFNOSUPPORT;
			return -1;
		}

		if (usrsctp_bindx(c->us,
		                  (struct sockaddr *)lsc_fix_sa_local(p, step, &ss),
		                  1, flags) != 0)
			return -1;

		p = (struct sockaddr *)((char *)p + step);
	}
	return 0;
}

int sctp_connectx(int sd, struct sockaddr *addrs, int addrcnt,
                  sctp_assoc_t *id)
{
	struct lsc_conn *c = lsc_lookup(sd);

	if (c == NULL) {
		errno = ENOTSOCK;
		return -1;
	}
	return usrsctp_connectx(c->us, addrs, addrcnt, id);
}

int sctp_getpaddrs(int sd, sctp_assoc_t id, struct sockaddr **addrs)
{
	struct lsc_conn *c = lsc_lookup(sd);

	if (c == NULL) {
		errno = ENOTSOCK;
		return -1;
	}
	return usrsctp_getpaddrs(c->us, id, addrs);
}

/*
 * usrsctp_freepaddrs steps backwards from the caller's pointer to reach a
 * hidden header, so a NULL argument becomes a free() on a wild address.
 * lksctp treats NULL as a no-op and callers rely on that in cleanup paths.
 */
int sctp_freepaddrs(struct sockaddr *addrs)
{
	if (addrs == NULL)
		return 0;
	usrsctp_freepaddrs(addrs);
	return 0;
}

int sctp_getladdrs(int sd, sctp_assoc_t id, struct sockaddr **addrs)
{
	struct lsc_conn *c = lsc_lookup(sd);

	if (c == NULL) {
		errno = ENOTSOCK;
		return -1;
	}
	return usrsctp_getladdrs(c->us, id, addrs);
}

int sctp_freeladdrs(struct sockaddr *addrs)
{
	if (addrs == NULL)
		return 0;
	usrsctp_freeladdrs(addrs);
	return 0;
}

int sctp_opt_info(int sd, sctp_assoc_t id, int opt, void *arg,
                  socklen_t *size)
{
	struct lsc_conn *c = lsc_lookup(sd);

	if (c == NULL) {
		errno = ENOTSOCK;
		return -1;
	}
	return usrsctp_opt_info(c->us, id, opt, arg, size);
}

/*
 * sctp_peeloff turns one association of a one-to-many socket into its own
 * one-to-one socket. usrsctp can do the split, but the result would need a
 * second socketpair and its own pump registration, and no caller in the
 * target set uses it. Refuse plainly instead of returning a broken fd.
 */
int sctp_peeloff(int sd, sctp_assoc_t id)
{
	(void)sd;
	(void)id;
	errno = EOPNOTSUPP;
	return -1;
}
