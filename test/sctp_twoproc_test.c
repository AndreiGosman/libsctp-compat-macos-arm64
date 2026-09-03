/*
 * Two processes, one association, in the shape S1AP uses.
 *
 * A one-to-many listener accepts a connection, reads a message, and answers
 * twice: once addressed explicitly with sctp_sendmsg, and once with sctp_send
 * carrying only the association id from the sctp_sndrcvinfo it just received.
 * Both are what real callers do, and only the first is exercised by a test
 * that keeps both ends in one process.
 *
 * The test re-executes itself for the client role, so the two stacks really
 * are in separate address spaces with separate encapsulation ports.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <netinet/sctp.h>

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT       36413
#define REQ        "S1SetupRequest"
#define RSP_ADDR   "ByAddress"
#define RSP_ASSOC  "ByAssociation"

static int fails;
static void check(const char* w, int ok) { printf("%-38s %s\n", w, ok ? "ok" : "FAILED"); if (!ok) fails++; }

static void fill(struct sockaddr_in* a, uint16_t port)
{
  memset(a, 0, sizeof(*a));
  a->sin_family      = AF_INET;
  a->sin_port        = htons(port);
  a->sin_addr.s_addr = inet_addr("127.0.0.1");
}

static int open_sock(void)
{
  struct sctp_event_subscribe ev;
  int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if (fd < 0) {
    return -1;
  }
  memset(&ev, 0, sizeof(ev));
  ev.sctp_data_io_event  = 1;
  ev.sctp_shutdown_event = 1;
  ev.sctp_address_event  = 1;
  setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &ev, sizeof(ev));
  return fd;
}

/* Reads one data message, skipping notifications. Returns its length. */
static ssize_t read_data(int fd, char* buf, size_t len, struct sctp_sndrcvinfo* sri,
                         struct sockaddr_in* from, socklen_t* fromlen, int tries)
{
  int i;
  for (i = 0; i < tries; i++) {
    struct pollfd p = {fd, POLLIN, 0};
    int           flags = 0;
    ssize_t       n;

    if (poll(&p, 1, 500) <= 0) {
      continue;
    }
    memset(sri, 0, sizeof(*sri));
    n = sctp_recvmsg(fd, buf, len, (struct sockaddr*)from, fromlen, sri, &flags);
    if (n > 0 && !(flags & MSG_NOTIFICATION)) {
      return n;
    }
  }
  return -1;
}

static int run_client(void)
{
  struct sockaddr_in a;
  char               buf[256];
  struct sctp_sndrcvinfo sri;
  socklen_t          fl = sizeof(a);
  int                fd = open_sock();
  int                got_addr = 0, got_assoc = 0, i;

  if (fd < 0) {
    return 1;
  }
  fill(&a, 0);
  if (bind(fd, (struct sockaddr*)&a, sizeof(a)) != 0) {
    return 1;
  }
  fill(&a, PORT);
  if (connect(fd, (struct sockaddr*)&a, sizeof(a)) != 0) {
    return 1;
  }
  if (sctp_sendmsg(fd, REQ, strlen(REQ), (struct sockaddr*)&a, sizeof(a),
                   htonl(18), 0, 0, 0, 0) != (ssize_t)strlen(REQ)) {
    return 1;
  }

  for (i = 0; i < 2; i++) {
    ssize_t n = read_data(fd, buf, sizeof(buf), &sri, &a, &fl, 12);
    if (n <= 0) {
      break;
    }
    if ((size_t)n == strlen(RSP_ADDR) && memcmp(buf, RSP_ADDR, n) == 0) {
      got_addr = 1;
    }
    if ((size_t)n == strlen(RSP_ASSOC) && memcmp(buf, RSP_ASSOC, n) == 0) {
      got_assoc = 1;
    }
  }
  close(fd);
  return (got_addr ? 0 : 1) | (got_assoc ? 0 : 2);
}

int main(int argc, char** argv)
{
  struct sockaddr_in     addr, from;
  struct sctp_sndrcvinfo sri;
  socklen_t              fromlen = sizeof(from);
  char                   buf[256];
  pid_t                  pid;
  int                    fd, status = 0;
  ssize_t                n;

  setvbuf(stdout, NULL, _IONBF, 0);

  if (argc > 1 && strcmp(argv[1], "client") == 0) {
    return run_client();
  }

  /* Each process needs its own tunnelling port; they cannot share one. */
  setenv("LIBSCTP_COMPAT_UDP_ENCAPS_PORT", "29899", 1);
  setenv("LIBSCTP_COMPAT_UDP_ENCAPS_REMOTE_PORT", "29900", 1);

  fd = open_sock();
  check("server socket", fd >= 0);
  if (fd < 0) {
    return 1;
  }
  fill(&addr, PORT);
  check("server bind", bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
  check("server listen", listen(fd, 8) == 0);

  pid = fork();
  if (pid == 0) {
    setenv("LIBSCTP_COMPAT_UDP_ENCAPS_PORT", "29900", 1);
    setenv("LIBSCTP_COMPAT_UDP_ENCAPS_REMOTE_PORT", "29899", 1);
    execl(argv[0], argv[0], "client", (char*)NULL);
    _exit(127);
  }
  check("client process started", pid > 0);

  n = read_data(fd, buf, sizeof(buf), &sri, &from, &fromlen, 16);
  check("request received", n == (ssize_t)strlen(REQ) && memcmp(buf, REQ, n) == 0);
  check("association id reported", sri.sinfo_assoc_id != 0);

  /*
   * The flags of a received message must be safe to hand straight back to
   * sctp_send. usrsctp reports the fragmentation bits here, and those overlap
   * SCTP_EOF and SCTP_ABORT on the send side.
   */
  check("received flags carry no send command",
        (sri.sinfo_flags & (SCTP_EOF | SCTP_ABORT)) == 0);

  check("reply by address",
        sctp_sendmsg(fd, RSP_ADDR, strlen(RSP_ADDR), (struct sockaddr*)&from, fromlen,
                     htonl(18), 0, 0, 0, 0) == (ssize_t)strlen(RSP_ADDR));

  check("reply by association id",
        sctp_send(fd, RSP_ASSOC, strlen(RSP_ASSOC), &sri, MSG_NOSIGNAL) ==
            (ssize_t)strlen(RSP_ASSOC));

  waitpid(pid, &status, 0);
  {
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    check("client received the addressed reply", (rc & 1) == 0);
    check("client received the association reply", (rc & 2) == 0);
  }

  close(fd);
  printf("\n%s\n", fails == 0 ? "two process test passed" : "two process test FAILED");
  return fails == 0 ? 0 : 1;
}
