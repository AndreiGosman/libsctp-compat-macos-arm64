/*
 * Loopback test: one real SCTP association, end to end, in one process.
 *
 * This is the test that matters. It proves the bridge carries data: the
 * usrsctp receive callback frames a message onto the socketpair, poll()
 * reports the descriptor readable, and sctp_recvmsg returns the payload
 * with the association id attached.
 *
 * UDP encapsulation keeps the test unprivileged. Raw SCTP needs root.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <netinet/sctp.h>

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Not the conventional 9899: the suite has to run while something else
 * on the machine is using it. */
#define ENCAPS_PORT "39899"
#define SERVER_PORT 36412
#define PAYLOAD     "S1AP-SETUP-REQUEST"

static int failures;

static void check(const char *what, int ok)
{
	printf("%-34s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok)
		failures++;
}

static void fill(struct sockaddr_in *a, uint16_t port)
{
	memset(a, 0, sizeof(*a));
	a->sin_family = AF_INET;
	a->sin_port   = htons(port);
	a->sin_addr.s_addr = inet_addr("127.0.0.1");
}

int main(void)
{
	struct sctp_event_subscribe evnts;
	struct sctp_sndrcvinfo      sri;
	struct sockaddr_in          srv_addr, cli_addr, from;
	struct pollfd               pfd;
	socklen_t                   fromlen;
	char                        buf[512];
	int                         srv, cli, flags, rc, got_payload = 0;
	int                         tries;

	setenv("LIBSCTP_COMPAT_UDP_ENCAPS_PORT", ENCAPS_PORT, 1);

	/* Server, one-to-many, exactly the shape srsRAN's MME uses. */
	srv = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
	check("server socket", srv >= 0);
	if (srv < 0)
		return 1;

	memset(&evnts, 0, sizeof(evnts));
	evnts.sctp_data_io_event  = 1;
	evnts.sctp_shutdown_event = 1;
	evnts.sctp_address_event  = 1;
	check("subscribe to SCTP_EVENTS",
	      setsockopt(srv, IPPROTO_SCTP, SCTP_EVENTS, &evnts,
	                 sizeof(evnts)) == 0);

	fill(&srv_addr, SERVER_PORT);
	check("server bind",
	      bind(srv, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == 0);
	check("server listen", listen(srv, 8) == 0);

	/* Client. */
	cli = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
	check("client socket", cli >= 0);

	fill(&cli_addr, 0);
	check("client bind",
	      bind(cli, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) == 0);

	rc = connect(cli, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	check("client connect", rc == 0);
	if (rc != 0) {
		printf("  connect failed: %s\n", strerror(errno));
		printf("  UDP encapsulation on port %s may be blocked\n",
		       ENCAPS_PORT);
		return 1;
	}

	{
		ssize_t sent = sctp_sendmsg(cli, PAYLOAD, strlen(PAYLOAD),
		                            NULL, 0, htonl(18), 0, 0, 0, 0);
		if (sent != (ssize_t)strlen(PAYLOAD))
			printf("  sctp_sendmsg returned %zd: %s\n", sent,
			       strerror(errno));
		check("client sctp_sendmsg", sent == (ssize_t)strlen(PAYLOAD));
	}

	/*
	 * Read until the payload arrives. Notifications for the new
	 * association arrive first, which is itself the behaviour srsRAN
	 * depends on when it inspects sn_assoc_change.
	 */
	for (tries = 0; tries < 10 && !got_payload; tries++) {
		pfd.fd     = srv;
		pfd.events = POLLIN;
		rc = poll(&pfd, 1, 2000);
		if (rc <= 0)
			break;

		memset(&sri, 0, sizeof(sri));
		fromlen = sizeof(from);
		flags   = 0;
		rc = sctp_recvmsg(srv, buf, sizeof(buf),
		                  (struct sockaddr *)&from, &fromlen, &sri,
		                  &flags);
		if (rc < 0)
			break;

		if (flags & MSG_NOTIFICATION) {
			union sctp_notification *n = (union sctp_notification *)buf;
			printf("  notification type %u\n", n->sn_header.sn_type);
			continue;
		}

		if ((size_t)rc == strlen(PAYLOAD) &&
		    memcmp(buf, PAYLOAD, rc) == 0) {
			got_payload = 1;
			check("poll reported readable", 1);
			check("payload matches", 1);
			check("association id set", sri.sinfo_assoc_id != 0);
			check("peer address returned",
			      fromlen >= sizeof(struct sockaddr_in) &&
			          from.sin_family == AF_INET);
		}
	}

	check("server received payload", got_payload);

	close(cli);
	close(srv);

	printf("\n%s\n", failures == 0 ? "loopback test passed"
	                               : "loopback test FAILED");
	return failures == 0 ? 0 : 1;
}
