/*
 * Link and error-path test.
 *
 * Every symbol that srsRAN and the Osmocom stack expect from lksctp must
 * resolve, and each one must fail cleanly on a descriptor that is not an
 * SCTP socket rather than crash.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <netinet/sctp.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void check(const char *what, int ok)
{
	printf("%-28s %s\n", what, ok ? "ok" : "FAILED");
	if (!ok)
		failures++;
}

int main(void)
{
	struct sctp_sndrcvinfo sri;
	struct sockaddr_in     addr;
	struct sockaddr       *paddrs = NULL;
	socklen_t              len;
	char                   buf[64];
	int                    flags = 0;
	int                    fd;

	memset(&sri, 0, sizeof(sri));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	/* A plain UDP descriptor is not registered with the shim. Every SCTP
	 * call on it must return -1 with ENOTSOCK, not misbehave. */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	check("plain UDP socket", fd >= 0);

	len = sizeof(addr);
	check("sctp_sendmsg rejects",
	      sctp_sendmsg(fd, "x", 1, (struct sockaddr *)&addr, len,
	                   0, 0, 0, 0, 0) == -1 && errno == ENOTSOCK);
	check("sctp_send rejects",
	      sctp_send(fd, "x", 1, &sri, 0) == -1 && errno == ENOTSOCK);
	check("sctp_recvmsg rejects",
	      sctp_recvmsg(fd, buf, sizeof(buf), (struct sockaddr *)&addr,
	                   &len, &sri, &flags) == -1 && errno == ENOTSOCK);
	check("sctp_bindx rejects",
	      sctp_bindx(fd, (struct sockaddr *)&addr, 1,
	                 SCTP_BINDX_ADD_ADDR) == -1 && errno == ENOTSOCK);
	check("sctp_connectx rejects",
	      sctp_connectx(fd, (struct sockaddr *)&addr, 1, NULL) == -1 &&
	          errno == ENOTSOCK);
	check("sctp_getpaddrs rejects",
	      sctp_getpaddrs(fd, 0, &paddrs) == -1 && errno == ENOTSOCK);
	check("sctp_getladdrs rejects",
	      sctp_getladdrs(fd, 0, &paddrs) == -1 && errno == ENOTSOCK);
	len = sizeof(buf);
	check("sctp_opt_info rejects",
	      sctp_opt_info(fd, 0, SCTP_RTOINFO, buf, &len) == -1 &&
	          errno == ENOTSOCK);
	check("sctp_peeloff rejects",
	      sctp_peeloff(fd, 0) == -1 && errno == EOPNOTSUPP);

	/* The free helpers must tolerate NULL. */
	sctp_freepaddrs(NULL);
	sctp_freeladdrs(NULL);
	check("free helpers take NULL", 1);

	close(fd);

	/* Non-SCTP traffic must still work through the interposed calls. */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	check("TCP socket unaffected", fd >= 0);
	if (fd >= 0)
		close(fd);

	printf("\n%s\n", failures == 0 ? "link test passed"
	                               : "link test FAILED");
	return failures == 0 ? 0 : 1;
}
