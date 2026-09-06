/*
 * netinet/sctp.h - Linux lksctp API for macOS, backed by usrsctp.
 *
 * Part of libsctp-compat-macos-arm64.
 * Copyright (C) 2026 Andrei Gosman
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * XNU has no SCTP. This header declares the subset of the Linux lksctp
 * API that Osmocom and srsRAN use, so that Linux sources compile on
 * Darwin without modification. The implementation in libsctp.dylib maps
 * each call onto the usrsctp userspace stack.
 *
 * Struct layouts follow usrsctp (which follows FreeBSD and RFC 6458) so
 * that option values pass through to the backend with no translation.
 * The one deliberate divergence is SCTP_EVENTS: Linux numbers it 0x0b,
 * FreeBSD and usrsctp number it 0x0c. This header uses the Linux value
 * and the shim translates it.
 */

#ifndef _NETINET_SCTP_H_
#define _NETINET_SCTP_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Linux defines SOL_SCTP as an alias of IPPROTO_SCTP. Darwin declares
 * IPPROTO_SCTP in netinet/in.h but implements nothing behind it. */
#ifndef SOL_SCTP
#define SOL_SCTP IPPROTO_SCTP
#endif

#ifndef MSG_NOTIFICATION
#define MSG_NOTIFICATION 0x2000
#endif

typedef uint32_t sctp_assoc_t;

/* ------------------------------------------------------------------ */
/* Socket options                                                      */
/* ------------------------------------------------------------------ */

#define SCTP_RTOINFO                0x00000001
#define SCTP_ASSOCINFO              0x00000002
#define SCTP_INITMSG                0x00000003
#define SCTP_NODELAY                0x00000004
#define SCTP_AUTOCLOSE              0x00000005
#define SCTP_PRIMARY_ADDR           0x00000007
#define SCTP_ADAPTATION_LAYER       0x00000008
#define SCTP_DISABLE_FRAGMENTS      0x00000009
#define SCTP_PEER_ADDR_PARAMS       0x0000000a
#define SCTP_EVENTS                 0x0000000b  /* Linux value, see note */
#define SCTP_I_WANT_MAPPED_V4_ADDR  0x0000000c
#define SCTP_MAXSEG                 0x0000000d
#define SCTP_STATUS                 0x00000100
#define SCTP_GET_PEER_ADDR_INFO     0x00000101

/* ------------------------------------------------------------------ */
/* sinfo_flags / snd_flags                                             */
/* ------------------------------------------------------------------ */

#define SCTP_EOF        0x0100
#define SCTP_ABORT      0x0200
#define SCTP_UNORDERED  0x0400
#define SCTP_ADDR_OVER  0x0800
#define SCTP_SENDALL    0x1000
#define SCTP_EOR        0x2000

/* ------------------------------------------------------------------ */
/* Notification types and states                                       */
/* ------------------------------------------------------------------ */

/* lksctp gives each of these groups a named enum type, and application code
 * uses those names as function parameter and struct field types. The names
 * must therefore exist as types here, not only as constants. Every group
 * below follows the lksctp idiom of an enum plus a self-referential #define
 * per member, so that "#ifdef SCTP_FOO" still answers the question that
 * portable code asks with it.
 *
 * The VALUES are usrsctp's, not Linux's, wherever usrsctp reports the field
 * at runtime. The two stacks disagree: lksctp numbers sctp_sac_state from 0,
 * usrsctp from 1. Taking the Linux numbers would mistranslate every
 * notification this library delivers.
 *
 * A member marked "not reported by usrsctp" exists only so that code which
 * enumerates the full lksctp set still compiles. It is given a value that
 * collides with nothing in its group, and it never arrives from the stack.
 */

/* sn_type: the notification type in sctp_tlv.sn_type */
enum sctp_sn_type {
	SCTP_ASSOC_CHANGE           = 0x0001,
	SCTP_PEER_ADDR_CHANGE       = 0x0002,
	SCTP_REMOTE_ERROR           = 0x0003,
	SCTP_SEND_FAILED            = 0x0004,
	SCTP_SHUTDOWN_EVENT         = 0x0005,
	SCTP_ADAPTATION_INDICATION  = 0x0006,
	SCTP_PARTIAL_DELIVERY_EVENT = 0x0007,
	SCTP_AUTHENTICATION_EVENT   = 0x0008,
	SCTP_SENDER_DRY_EVENT       = 0x0009,
};
#define SCTP_ASSOC_CHANGE           SCTP_ASSOC_CHANGE
#define SCTP_PEER_ADDR_CHANGE       SCTP_PEER_ADDR_CHANGE
#define SCTP_REMOTE_ERROR           SCTP_REMOTE_ERROR
#define SCTP_SEND_FAILED            SCTP_SEND_FAILED
#define SCTP_SHUTDOWN_EVENT         SCTP_SHUTDOWN_EVENT
#define SCTP_ADAPTATION_INDICATION  SCTP_ADAPTATION_INDICATION
#define SCTP_PARTIAL_DELIVERY_EVENT SCTP_PARTIAL_DELIVERY_EVENT
#define SCTP_AUTHENTICATION_EVENT   SCTP_AUTHENTICATION_EVENT
#define SCTP_SENDER_DRY_EVENT       SCTP_SENDER_DRY_EVENT

/* sac_state: sctp_assoc_change.sac_state */
enum sctp_sac_state {
	SCTP_COMM_UP        = 0x0001,
	SCTP_COMM_LOST      = 0x0002,
	SCTP_RESTART        = 0x0003,
	SCTP_SHUTDOWN_COMP  = 0x0004,
	SCTP_CANT_STR_ASSOC = 0x0005,
};
#define SCTP_COMM_UP        SCTP_COMM_UP
#define SCTP_COMM_LOST      SCTP_COMM_LOST
#define SCTP_RESTART        SCTP_RESTART
#define SCTP_SHUTDOWN_COMP  SCTP_SHUTDOWN_COMP
#define SCTP_CANT_STR_ASSOC SCTP_CANT_STR_ASSOC

/* spc_state: sctp_paddr_change.spc_state */
enum sctp_spc_state {
	SCTP_ADDR_AVAILABLE   = 0x0001,
	SCTP_ADDR_UNREACHABLE = 0x0002,
	SCTP_ADDR_REMOVED     = 0x0003,
	SCTP_ADDR_ADDED       = 0x0004,
	SCTP_ADDR_MADE_PRIM   = 0x0005,
	SCTP_ADDR_CONFIRMED   = 0x0006,
};
#define SCTP_ADDR_AVAILABLE   SCTP_ADDR_AVAILABLE
#define SCTP_ADDR_UNREACHABLE SCTP_ADDR_UNREACHABLE
#define SCTP_ADDR_REMOVED     SCTP_ADDR_REMOVED
#define SCTP_ADDR_ADDED       SCTP_ADDR_ADDED
#define SCTP_ADDR_MADE_PRIM   SCTP_ADDR_MADE_PRIM
#define SCTP_ADDR_CONFIRMED   SCTP_ADDR_CONFIRMED

/* sn_error: sctp_paddr_change.spc_error and sctp_remote_error.sre_error.
 * usrsctp does not report this set. It puts an errno-like value in spc_error
 * instead, so every member here is informational and the numbering follows
 * lksctp. */
enum sctp_sn_error {
	SCTP_FAILED_THRESHOLD       = 0,
	SCTP_RECEIVED_SACK          = 1,
	SCTP_HEARTBEAT_SUCCESS      = 2,
	SCTP_RESPONSE_TO_USER_REQ   = 3,
	SCTP_INTERNAL_ERROR         = 4,
	SCTP_SHUTDOWN_GUARD_EXPIRES = 5,
	SCTP_PEER_FAULTY            = 6,
};
#define SCTP_FAILED_THRESHOLD       SCTP_FAILED_THRESHOLD
#define SCTP_RECEIVED_SACK          SCTP_RECEIVED_SACK
#define SCTP_HEARTBEAT_SUCCESS      SCTP_HEARTBEAT_SUCCESS
#define SCTP_RESPONSE_TO_USER_REQ   SCTP_RESPONSE_TO_USER_REQ
#define SCTP_INTERNAL_ERROR         SCTP_INTERNAL_ERROR
#define SCTP_SHUTDOWN_GUARD_EXPIRES SCTP_SHUTDOWN_GUARD_EXPIRES
#define SCTP_PEER_FAULTY            SCTP_PEER_FAULTY

/* spinfo_state: sctp_paddrinfo.spinfo_state. usrsctp values. */
enum sctp_spinfo_state {
	SCTP_ACTIVE      = 0x0001,
	SCTP_INACTIVE    = 0x0002,
	SCTP_PF          = 0x0004,  /* not reported by usrsctp */
	SCTP_UNCONFIRMED = 0x0200,
	SCTP_UNKNOWN     = 0xffff,  /* not reported by usrsctp */
};
#define SCTP_ACTIVE      SCTP_ACTIVE
#define SCTP_INACTIVE    SCTP_INACTIVE
#define SCTP_PF          SCTP_PF
#define SCTP_UNCONFIRMED SCTP_UNCONFIRMED
#define SCTP_UNKNOWN     SCTP_UNKNOWN

/* sstat_state: sctp_status.sstat_state. usrsctp values. */
enum sctp_sstat_state {
	SCTP_CLOSED            = 0x0000,
	SCTP_COOKIE_WAIT       = 0x0002,
	SCTP_COOKIE_ECHOED     = 0x0004,
	SCTP_ESTABLISHED       = 0x0008,
	SCTP_SHUTDOWN_SENT     = 0x0010,
	SCTP_SHUTDOWN_RECEIVED = 0x0020,
	SCTP_SHUTDOWN_ACK_SENT = 0x0040,
	SCTP_SHUTDOWN_PENDING  = 0x0080,
	SCTP_BOUND             = 0x1000,
	SCTP_LISTEN            = 0x2000,
	SCTP_EMPTY             = 0x8000,  /* not reported by usrsctp */
};
#define SCTP_CLOSED            SCTP_CLOSED
#define SCTP_COOKIE_WAIT       SCTP_COOKIE_WAIT
#define SCTP_COOKIE_ECHOED     SCTP_COOKIE_ECHOED
#define SCTP_ESTABLISHED       SCTP_ESTABLISHED
#define SCTP_SHUTDOWN_SENT     SCTP_SHUTDOWN_SENT
#define SCTP_SHUTDOWN_RECEIVED SCTP_SHUTDOWN_RECEIVED
#define SCTP_SHUTDOWN_ACK_SENT SCTP_SHUTDOWN_ACK_SENT
#define SCTP_SHUTDOWN_PENDING  SCTP_SHUTDOWN_PENDING
#define SCTP_BOUND             SCTP_BOUND
#define SCTP_LISTEN            SCTP_LISTEN
#define SCTP_EMPTY             SCTP_EMPTY

/* cmsg_type for ancillary data on IPPROTO_SCTP, lksctp numbering.
 *
 * WARNING: this library does not interpose sendmsg() or recvmsg(). Code that
 * builds or parses these control messages talks straight to libc, which knows
 * nothing about the usrsctp association behind the descriptor. The constants
 * are here so that such code compiles; it will not carry SCTP data. Use
 * sctp_sendmsg() and sctp_recvmsg(), which this library does implement.
 */
enum sctp_cmsg_type {
	SCTP_INIT    = 0,
	SCTP_SNDRCV  = 1,
	SCTP_SNDINFO = 2,
	SCTP_RCVINFO = 3,
	SCTP_NXTINFO = 4,
};
#define SCTP_INIT    SCTP_INIT
#define SCTP_SNDRCV  SCTP_SNDRCV
#define SCTP_SNDINFO SCTP_SNDINFO
#define SCTP_RCVINFO SCTP_RCVINFO
#define SCTP_NXTINFO SCTP_NXTINFO

/* sctp_bindx flags */
#define SCTP_BINDX_ADD_ADDR 0x00008001
#define SCTP_BINDX_REM_ADDR 0x00008002

/* ------------------------------------------------------------------ */
/* Data structures                                                     */
/* ------------------------------------------------------------------ */

struct sctp_sndrcvinfo {
	uint16_t     sinfo_stream;
	uint16_t     sinfo_ssn;
	uint16_t     sinfo_flags;
	uint32_t     sinfo_ppid;
	uint32_t     sinfo_context;
	uint32_t     sinfo_timetolive;
	uint32_t     sinfo_tsn;
	uint32_t     sinfo_cumtsn;
	sctp_assoc_t sinfo_assoc_id;
};

struct sctp_event_subscribe {
	uint8_t sctp_data_io_event;
	uint8_t sctp_association_event;
	uint8_t sctp_address_event;
	uint8_t sctp_send_failure_event;
	uint8_t sctp_peer_error_event;
	uint8_t sctp_shutdown_event;
	uint8_t sctp_partial_delivery_event;
	uint8_t sctp_adaptation_layer_event;
	uint8_t sctp_authentication_event;
	uint8_t sctp_sender_dry_event;
	uint8_t sctp_stream_reset_event;
};

struct sctp_initmsg {
	uint16_t sinit_num_ostreams;
	uint16_t sinit_max_instreams;
	uint16_t sinit_max_attempts;
	uint16_t sinit_max_init_timeo;
};

struct sctp_rtoinfo {
	sctp_assoc_t srto_assoc_id;
	uint32_t     srto_initial;
	uint32_t     srto_max;
	uint32_t     srto_min;
};

struct sctp_assocparams {
	sctp_assoc_t sasoc_assoc_id;
	uint32_t     sasoc_peer_rwnd;
	uint32_t     sasoc_local_rwnd;
	uint32_t     sasoc_cookie_life;
	uint16_t     sasoc_asocmaxrxt;
	uint16_t     sasoc_number_peer_destinations;
};

struct sctp_paddrinfo {
	sctp_assoc_t            spinfo_assoc_id;
	struct sockaddr_storage spinfo_address;
	int32_t                 spinfo_state;
	uint32_t                spinfo_cwnd;
	uint32_t                spinfo_srtt;
	uint32_t                spinfo_rto;
	uint32_t                spinfo_mtu;
};

struct sctp_status {
	sctp_assoc_t          sstat_assoc_id;
	int32_t               sstat_state;
	uint32_t              sstat_rwnd;
	uint16_t              sstat_unackdata;
	uint16_t              sstat_penddata;
	uint16_t              sstat_instrms;
	uint16_t              sstat_outstrms;
	uint32_t              sstat_fragmentation_point;
	struct sctp_paddrinfo sstat_primary;
};

/* --- notifications ------------------------------------------------- */

struct sctp_assoc_change {
	uint16_t     sac_type;
	uint16_t     sac_flags;
	uint32_t     sac_length;
	uint16_t     sac_state;
	uint16_t     sac_error;
	uint16_t     sac_outbound_streams;
	uint16_t     sac_inbound_streams;
	sctp_assoc_t sac_assoc_id;
	uint8_t      sac_info[];
};

struct sctp_paddr_change {
	uint16_t                spc_type;
	uint16_t                spc_flags;
	uint32_t                spc_length;
	struct sockaddr_storage spc_aaddr;
	uint32_t                spc_state;
	uint32_t                spc_error;
	sctp_assoc_t            spc_assoc_id;
};

struct sctp_remote_error {
	uint16_t     sre_type;
	uint16_t     sre_flags;
	uint32_t     sre_length;
	uint16_t     sre_error;
	sctp_assoc_t sre_assoc_id;
	uint8_t      sre_data[];
};

struct sctp_send_failed {
	uint16_t               ssf_type;
	uint16_t               ssf_flags;
	uint32_t               ssf_length;
	uint32_t               ssf_error;
	struct sctp_sndrcvinfo ssf_info;
	sctp_assoc_t           ssf_assoc_id;
	uint8_t                ssf_data[];
};

struct sctp_shutdown_event {
	uint16_t     sse_type;
	uint16_t     sse_flags;
	uint32_t     sse_length;
	sctp_assoc_t sse_assoc_id;
};

struct sctp_adaptation_event {
	uint16_t     sai_type;
	uint16_t     sai_flags;
	uint32_t     sai_length;
	uint32_t     sai_adaptation_ind;
	sctp_assoc_t sai_assoc_id;
};

struct sctp_pdapi_event {
	uint16_t     pdapi_type;
	uint16_t     pdapi_flags;
	uint32_t     pdapi_length;
	uint32_t     pdapi_indication;
	uint32_t     pdapi_stream;
	uint32_t     pdapi_seq;
	sctp_assoc_t pdapi_assoc_id;
};

struct sctp_authkey_event {
	uint16_t     auth_type;
	uint16_t     auth_flags;
	uint32_t     auth_length;
	uint16_t     auth_keynumber;
	uint16_t     auth_altkeynumber;
	uint32_t     auth_indication;
	sctp_assoc_t auth_assoc_id;
};

struct sctp_sender_dry_event {
	uint16_t     sender_dry_type;
	uint16_t     sender_dry_flags;
	uint32_t     sender_dry_length;
	sctp_assoc_t sender_dry_assoc_id;
};

union sctp_notification {
	struct sctp_tlv {
		uint16_t sn_type;
		uint16_t sn_flags;
		uint32_t sn_length;
	} sn_header;
	struct sctp_assoc_change     sn_assoc_change;
	struct sctp_paddr_change     sn_paddr_change;
	struct sctp_remote_error     sn_remote_error;
	struct sctp_send_failed      sn_send_failed;
	struct sctp_shutdown_event   sn_shutdown_event;
	struct sctp_adaptation_event sn_adaptation_event;
	struct sctp_pdapi_event      sn_pdapi_event;
	struct sctp_authkey_event    sn_auth_event;
	struct sctp_sender_dry_event sn_sender_dry_event;
};

/* ------------------------------------------------------------------ */
/* lksctp function API                                                 */
/* ------------------------------------------------------------------ */

ssize_t sctp_sendmsg(int sd, const void *msg, size_t len,
                     struct sockaddr *to, socklen_t tolen,
                     uint32_t ppid, uint32_t flags,
                     uint16_t stream_no, uint32_t timetolive,
                     uint32_t context);

ssize_t sctp_send(int sd, const void *msg, size_t len,
                  const struct sctp_sndrcvinfo *sinfo, int flags);

ssize_t sctp_recvmsg(int sd, void *msg, size_t len,
                     struct sockaddr *from, socklen_t *fromlen,
                     struct sctp_sndrcvinfo *sinfo, int *msg_flags);

int sctp_bindx(int sd, struct sockaddr *addrs, int addrcnt, int flags);
int sctp_connectx(int sd, struct sockaddr *addrs, int addrcnt,
                  sctp_assoc_t *id);
int sctp_getpaddrs(int sd, sctp_assoc_t id, struct sockaddr **addrs);
/* lksctp-tools returns int from both free helpers, FreeBSD returns void.
 * int is the safe declaration: callers that ignore it still compile. */
int sctp_freepaddrs(struct sockaddr *addrs);
int sctp_getladdrs(int sd, sctp_assoc_t id, struct sockaddr **addrs);
int sctp_freeladdrs(struct sockaddr *addrs);
int sctp_opt_info(int sd, sctp_assoc_t id, int opt, void *arg,
                  socklen_t *size);
int sctp_peeloff(int sd, sctp_assoc_t id);

#ifdef __cplusplus
}
#endif

#endif /* _NETINET_SCTP_H_ */
