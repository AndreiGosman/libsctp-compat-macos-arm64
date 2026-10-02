# Changelog

Versions are git tags. Each entry lists what changed for a caller and the
symptom that made the change necessary.

## v0.4.0, 2026-10-01

The RFC 6458 per-event subscription and six Linux semantics that the OCUDU
gNB (the srsRAN Project successor, https://gitlab.com/ocudu/ocudu) relies on.
OCUDU drives NGAP, F1-C and E1 through the RFC 6458 API rather than the older
lksctp one; porting its gateway library and tests to macOS exposed every item
below.

- `SCTP_EVENT` (singular) with `struct sctp_event` and the `SCTP_FUTURE_ASSOC`,
  `SCTP_CURRENT_ASSOC`, `SCTP_ALL_ASSOC` selectors; `struct sctp_sndinfo` for
  `SCTP_SNDINFO` control messages; `struct sctp_rcvinfo`, `struct sctp_nxtinfo`,
  `SCTP_RECVRCVINFO`, `SCTP_RECVNXTINFO`; `struct sctp_paddrparams` and the
  `SPP_*` flags in usrsctp layout with lksctp member names. Before, a caller
  that subscribed through `SCTP_EVENT` did not compile against the header.
- `enum sctp_sn_type` renumbered to usrsctp's list and completed with
  `sctp_stream_reset_event`, `sctp_assoc_reset_event`,
  `sctp_stream_change_event` and `sctp_send_failed_event` in
  `union sctp_notification`. Until v0.3.2 `SCTP_SENDER_DRY_EVENT` was 0x0009,
  which is usrsctp's `SCTP_STREAM_RESET_EVENT`, so a sender-dry notification
  compared equal to nothing. `SCTP_NOTIFICATIONS_STOPPED_EVENT` is a macro
  outside the enum so that a complete `switch` over the lksctp set still
  builds under `-Wswitch`.
- `setsockopt(IPPROTO_SCTP, SCTP_EVENT)` for `SCTP_DATA_IO_EVENT` succeeds as
  a no-op. usrsctp does not know that event type and answered EINVAL, which
  made OCUDU's subscription routine fail on every new socket. The receive
  information is delivered regardless.
- A zero-length `sendmsg` or `sctp_sendmsg` carrying `SCTP_EOF` or `SCTP_ABORT`
  shuts the association down, as on Linux. `usrsctp_sendv` rejects a NULL data
  pointer with EFAULT before it looks at the length; the library now hands it
  a valid pointer to nothing. This is how OCUDU's server closes an association.
- `sctp_connectx` normalises `sa_len` on every entry of the packed address
  list, as `sctp_bindx` already did. A list built by Linux code leaves the
  field at zero and usrsctp answered EINVAL.
- `sctp_peeloff` is implemented: `usrsctp_peeloff`, then the same adoption as
  `accept()` (own descriptor pair, ulp_info, encapsulation port, catch-up
  read), with the new socket set non-blocking before adoption. OCUDU's SCTP
  server peels every new association off its listener; before, the call
  returned `EOPNOTSUPP`. `sctp_link_test` now expects ENOTSOCK on a plain
  descriptor, like every other helper.
- `shutdown(fd, SHUT_RDWR)` acts on the write half only. Linux SCTP ignores
  `SHUT_RD`, so a Linux caller that issues `SHUT_RDWR` still receives
  `SCTP_SHUTDOWN_COMP`. usrsctp honours `SHUT_RD`, cancels receive and drops
  that notification; OCUDU's client waited for it forever, logging
  `Socket timeout reached` once a second.
- `getsockname` on an unbound socket answers the wildcard address of its
  family with port 0, as on Linux, instead of ENOTCONN.
- `setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)` is accepted as a no-op: a usrsctp
  IPv6 socket is dual stack already, and usrsctp answers ENOPROTOOPT for that
  level. Setting it to 1 answers `EOPNOTSUPP`.

Verified with a two-process exchange in the OCUDU shape (one-to-many sockets
on both ends, subscriptions through `SCTP_EVENT`, request and reply by
association id, EOF through `sendmsg` with `SCTP_SNDINFO`): `SCTP_COMM_UP` on
both ends, `SCTP_SHUTDOWN_EVENT` on the listener, `SCTP_SHUTDOWN_COMP` on both,
no `SCTP_COMM_LOST`; by the OCUDU gateway unit tests; and by the six shim
tests. The OCUDU gNB then completed NG Setup, a 5G SA registration and a PDU
session against an Open5GS AMF through this library
(https://github.com/AndreiGosman/ocudu-macos-arm64).

## v0.3.2, 2026-09-08

- `setsockopt(SOL_SOCKET, SO_NOSIGPIPE)` succeeds as a no-op. libosmo-netif
  sets it on every stream connection; forwarded to usrsctp it answered EINVAL
  and every association logged `Failed setting SO_NOSIGPIPE: Invalid
  argument`. usrsctp never raises SIGPIPE.
- `getsockopt(IPPROTO_SCTP, SCTP_STATUS)` passes through unchanged (RFC 6458
  layout, identical in lksctp and usrsctp) and is covered by
  `sctp_interpose_test` on the client and on the accepted descriptor.

## v0.3.1, 2026-09-07

- A one-to-one listener's pump carries tokens only. usrsctp reports
  notifications on a listening socket; framed onto the pump they left a
  datagram that `accept()` had no connection for, the descriptor stayed
  readable and the event loop span.
- `accept()` discards a stale token when its queue is empty; `listen()` arms
  the accept machinery for one-to-one sockets only.

## v0.3.0, 2026-09-07

- `accept()` redesigned as adopt-and-queue: the listen upcall accepts, adopts
  and queues each association, and `accept()` only pops that queue. Removes a
  poll loop at 100% CPU and a blocking `accept()` inside a single-threaded
  daemon's own event callback, both seen against osmo-stp.
- `struct sctp_paddrinfo` and `struct sctp_authkey_event` in usrsctp member
  order, so `SCTP_GET_PEER_ADDR_INFO` and `sstat_primary` return real data.
- Stress test with fifty concurrent clients through `accept()`.

## v0.2.0, 2026-09-06

- `sendmsg`, `recvmsg` and `accept` interposed, which is the path layers such
  as Osmocom's `osmo_io` use instead of the `sctp_*()` helpers; SCTP
  parameters travel in an `SCTP_SNDRCV` control message. A listening
  descriptor becomes readable when an association is pending.
- The lksctp notification and state groups get their enum types, with
  usrsctp's values.

## v0.1.0, 2026-09-03

- First release: the lksctp API (`sctp_*()` helpers, `socket()` with
  `IPPROTO_SCTP`, `setsockopt`/`getsockopt` at `IPPROTO_SCTP`) over usrsctp,
  with a socketpair per socket as the descriptor bridge, raw mode and RFC 6951
  UDP encapsulation, pkg-config files `sctp` and `libsctp`.
