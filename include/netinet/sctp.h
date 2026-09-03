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

#define SCTP_ASSOC_CHANGE           0x0001
#define SCTP_PEER_ADDR_CHANGE       0x0002
#define SCTP_REMOTE_ERROR           0x0003
#define SCTP_SEND_FAILED            0x0004
#define SCTP_SHUTDOWN_EVENT         0x0005
#define SCTP_ADAPTATION_INDICATION  0x0006
#define SCTP_PARTIAL_DELIVERY_EVENT 0x0007
#define SCTP_AUTHENTICATION_EVENT   0x0008
#define SCTP_SENDER_DRY_EVENT       0x0009

/* sac_state */
#define SCTP_COMM_UP        0x0001
#define SCTP_COMM_LOST      0x0002
#define SCTP_RESTART        0x0003
#define SCTP_SHUTDOWN_COMP  0x0004
#define SCTP_CANT_STR_ASSOC 0x0005

/* spc_state */
#define SCTP_ADDR_AVAILABLE   0x0001
#define SCTP_ADDR_UNREACHABLE 0x0002
#define SCTP_ADDR_REMOVED     0x0003
#define SCTP_ADDR_ADDED       0x0004
#define SCTP_ADDR_MADE_PRIM   0x0005
#define SCTP_ADDR_CONFIRMED   0x0006

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
void sctp_freepaddrs(struct sockaddr *addrs);
int sctp_getladdrs(int sd, sctp_assoc_t id, struct sockaddr **addrs);
void sctp_freeladdrs(struct sockaddr *addrs);
int sctp_opt_info(int sd, sctp_assoc_t id, int opt, void *arg,
                  socklen_t *size);
int sctp_peeloff(int sd, sctp_assoc_t id);

#ifdef __cplusplus
}
#endif

#endif /* _NETINET_SCTP_H_ */
