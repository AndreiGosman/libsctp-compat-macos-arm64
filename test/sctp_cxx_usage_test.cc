/*
 * Compile compatibility with the way srsRAN and Osmocom use lksctp.
 *
 * The header is consumed from C++, so extern "C" linkage, the flexible
 * array member inside union sctp_notification, and every constant those
 * projects reference all have to survive a C++ translation unit.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <netinet/sctp.h>

#include <cstdio>
#include <cstring>
#include <unistd.h>

/* Copied in shape from srsRAN lib/src/common/network_utils.cc. */
static bool subscribe_to_events(int fd)
{
	struct sctp_event_subscribe evnts = {};
	evnts.sctp_data_io_event  = 1;
	evnts.sctp_shutdown_event = 1;
	evnts.sctp_address_event  = 1;
	return setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &evnts,
	                  sizeof(evnts)) == 0;
}

static bool set_rto_opts(int fd, int rto_max)
{
	sctp_rtoinfo rto_opts;
	socklen_t    rto_sz = sizeof(sctp_rtoinfo);
	rto_opts.srto_assoc_id = 0;
	if (getsockopt(fd, SOL_SCTP, SCTP_RTOINFO, &rto_opts, &rto_sz) < 0)
		return false;
	rto_opts.srto_max = rto_max;
	return setsockopt(fd, SOL_SCTP, SCTP_RTOINFO, &rto_opts, rto_sz) == 0;
}

static bool set_init_msg_opts(int fd, int attempts, int timeo)
{
	sctp_initmsg init_opts;
	socklen_t    init_sz = sizeof(sctp_initmsg);
	if (getsockopt(fd, SOL_SCTP, SCTP_INITMSG, &init_opts, &init_sz) < 0)
		return false;
	init_opts.sinit_max_attempts   = attempts;
	init_opts.sinit_max_init_timeo = timeo;
	return setsockopt(fd, SOL_SCTP, SCTP_INITMSG, &init_opts, init_sz) == 0;
}

/* Copied in shape from srsenb/src/stack/s1ap/s1ap.cc. */
static int inspect_notification(uint8_t *msg)
{
	union sctp_notification *n = (union sctp_notification *)msg;
	uint32_t hdr_size = sizeof(((union sctp_notification *)NULL)->sn_header);
	(void)hdr_size;

	switch (n->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		switch (n->sn_assoc_change.sac_state) {
		case SCTP_COMM_UP:
		case SCTP_COMM_LOST:
		case SCTP_RESTART:
		case SCTP_SHUTDOWN_COMP:
		case SCTP_CANT_STR_ASSOC:
			return (int)n->sn_assoc_change.sac_assoc_id;
		default:
			break;
		}
		break;
	case SCTP_SHUTDOWN_EVENT:
		return (int)n->sn_shutdown_event.sse_assoc_id;
	case SCTP_PEER_ADDR_CHANGE:
		if (n->sn_paddr_change.spc_state == SCTP_ADDR_UNREACHABLE)
			return (int)n->sn_paddr_change.spc_assoc_id;
		break;
	case SCTP_REMOTE_ERROR:
	default:
		break;
	}
	return 0;
}

int main()
{
	int failures = 0;
	int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);

	if (fd < 0) {
		std::printf("socket() failed, cannot exercise the option paths\n");
		return 1;
	}

	struct { const char *name; bool ok; } checks[] = {
		{"sctp_subscribe_to_events", subscribe_to_events(fd)},
		{"sctp_set_rto_opts",        set_rto_opts(fd, 6000)},
		{"sctp_set_init_msg_opts",   set_init_msg_opts(fd, 3, 5)},
	};

	for (auto &c : checks) {
		std::printf("%-28s %s\n", c.name, c.ok ? "ok" : "FAILED");
		if (!c.ok)
			failures++;
	}

	/* Notification decoding must compile and run on a zeroed buffer. */
	uint8_t buf[512];
	std::memset(buf, 0, sizeof(buf));
	union sctp_notification *n = (union sctp_notification *)buf;
	n->sn_header.sn_type = SCTP_SHUTDOWN_EVENT;
	n->sn_shutdown_event.sse_assoc_id = 42;
	bool decoded = inspect_notification(buf) == 42;
	std::printf("%-28s %s\n", "notification decoding",
	            decoded ? "ok" : "FAILED");
	if (!decoded)
		failures++;

	/* sinfo_assoc_id is the only sndrcvinfo field srsRAN reads. */
	struct sctp_sndrcvinfo sri;
	std::memset(&sri, 0, sizeof(sri));
	sri.sinfo_assoc_id = 7;
	bool sri_ok = sri.sinfo_assoc_id == 7 &&
	              sizeof(sri) == 32;
	std::printf("%-28s %s\n", "sndrcvinfo layout",
	            sri_ok ? "ok" : "FAILED");
	if (!sri_ok)
		failures++;

	close(fd);
	std::printf("\n%s\n", failures == 0 ? "C++ usage test passed"
	                                    : "C++ usage test FAILED");
	return failures == 0 ? 0 : 1;
}
