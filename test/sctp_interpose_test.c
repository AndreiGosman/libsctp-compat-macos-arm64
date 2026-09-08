/*
 * Two processes, one association, driven entirely through raw socket calls.
 *
 * This is the path osmo_io takes: no sctp_sendmsg or sctp_recvmsg, but
 * sendmsg and recvmsg with the SCTP parameters in a control message, and a
 * one-to-one socket whose connections arrive through accept(). None of that
 * reaches usrsctp unless this library interposes those three calls, so a
 * shim that passes the sctp_*() tests can still fail every one of these.
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

#define PORT 36414
#define REQ  "RawSendmsgRequest"
#define RSP  "RawSendmsgReply"
#define PPID 0x0a0b0c0dU
#define SID  0

static int fails;
static void check(const char* w, int ok)
{
  printf("%-44s %s\n", w, ok ? "ok" : "FAILED");
  if (!ok) {
    fails++;
  }
}

static void fill(struct sockaddr_in* a, uint16_t port)
{
  memset(a, 0, sizeof(*a));
  a->sin_family      = AF_INET;
  a->sin_port        = htons(port);
  a->sin_addr.s_addr = inet_addr("127.0.0.1");
}

/* Send through raw sendmsg, with the SCTP parameters in an SCTP_SNDRCV
 * control message. This is what osmo_io builds. */
static ssize_t raw_send(int fd, const char* payload, uint32_t ppid)
{
  struct msghdr          mh;
  struct iovec           iov;
  struct cmsghdr*        cm;
  struct sctp_sndrcvinfo sri;
  char                   cbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];

  memset(&sri, 0, sizeof(sri));
  sri.sinfo_ppid   = ppid;
  sri.sinfo_stream = SID;

  iov.iov_base = (void*)payload;
  iov.iov_len  = strlen(payload);

  memset(cbuf, 0, sizeof(cbuf));
  memset(&mh, 0, sizeof(mh));
  mh.msg_iov        = &iov;
  mh.msg_iovlen     = 1;
  mh.msg_control    = cbuf;
  mh.msg_controllen = sizeof(cbuf);

  cm             = CMSG_FIRSTHDR(&mh);
  cm->cmsg_level = IPPROTO_SCTP;
  cm->cmsg_type  = SCTP_SNDRCV;
  cm->cmsg_len   = CMSG_LEN(sizeof(sri));
  memcpy(CMSG_DATA(cm), &sri, sizeof(sri));
  mh.msg_controllen = cm->cmsg_len;

  return sendmsg(fd, &mh, 0);
}

/* Receive through raw recvmsg and pull the sender information back out of
 * the control message. Skips notifications. */
static ssize_t raw_recv(int fd, char* buf, size_t len, uint32_t* ppid, int tries)
{
  int i;

  for (i = 0; i < tries; i++) {
    struct pollfd   p = {fd, POLLIN, 0};
    struct msghdr   mh;
    struct iovec    iov;
    struct cmsghdr* cm;
    char            cbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)) + 64];
    ssize_t         n;

    if (poll(&p, 1, 500) <= 0) {
      continue;
    }

    iov.iov_base = buf;
    iov.iov_len  = len;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov        = &iov;
    mh.msg_iovlen     = 1;
    mh.msg_control    = cbuf;
    mh.msg_controllen = sizeof(cbuf);

    n = recvmsg(fd, &mh, 0);
    if (n <= 0 || (mh.msg_flags & MSG_NOTIFICATION)) {
      continue;
    }

    if (ppid != NULL) {
      *ppid = 0;
      for (cm = CMSG_FIRSTHDR(&mh); cm != NULL; cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_level == IPPROTO_SCTP && cm->cmsg_type == SCTP_SNDRCV) {
          struct sctp_sndrcvinfo got;
          memcpy(&got, CMSG_DATA(cm), sizeof(got));
          *ppid = got.sinfo_ppid;
        }
      }
    }
    return n;
  }
  return -1;
}

static int run_client(void)
{
  struct sockaddr_in a;
  char               buf[256];
  uint32_t           ppid = 0;
  ssize_t            n;
  int                fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

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
#ifdef SO_NOSIGPIPE
  /*
   * libosmo-netif sets this on every connection; the shim has to accept it
   * (usrsctp never raises SIGPIPE) instead of failing with EINVAL.
   */
  {
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) {
      return 3;
    }
  }
#endif
  /* SCTP_STATUS on an established one-to-one client: real state and peer */
  {
    struct sctp_status st;
    socklen_t          sl = sizeof(st);
    memset(&st, 0, sizeof(st));
    if (getsockopt(fd, IPPROTO_SCTP, SCTP_STATUS, &st, &sl) != 0 || st.sstat_state == 0) {
      return 4;
    }
  }
  if (raw_send(fd, REQ, PPID) != (ssize_t)strlen(REQ)) {
    return 1;
  }

  n = raw_recv(fd, buf, sizeof(buf), &ppid, 16);
  close(fd);

  if (n != (ssize_t)strlen(RSP) || memcmp(buf, RSP, n) != 0) {
    return 2;
  }
  return 0;
}

int main(int argc, char** argv)
{
  struct sockaddr_in addr, from;
  socklen_t          fromlen = sizeof(from);
  char               buf[256];
  uint32_t           ppid = 0;
  pid_t              pid;
  int                fd, conn, status = 0;
  ssize_t            n;
  struct pollfd      p;

  setvbuf(stdout, NULL, _IONBF, 0);

  if (argc > 1 && strcmp(argv[1], "client") == 0) {
    return run_client();
  }

  /* Each process needs its own tunnelling port; they cannot share one. */
  setenv("LIBSCTP_COMPAT_UDP_ENCAPS_PORT", "29901", 1);
  setenv("LIBSCTP_COMPAT_UDP_ENCAPS_REMOTE_PORT", "29902", 1);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  check("server socket, one to one", fd >= 0);
  if (fd < 0) {
    return 1;
  }
  fill(&addr, PORT);
  check("server bind", bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
  check("server listen", listen(fd, 8) == 0);

  pid = fork();
  if (pid == 0) {
    setenv("LIBSCTP_COMPAT_UDP_ENCAPS_PORT", "29902", 1);
    setenv("LIBSCTP_COMPAT_UDP_ENCAPS_REMOTE_PORT", "29901", 1);
    execl(argv[0], argv[0], "client", (char*)NULL);
    _exit(127);
  }
  check("client process started", pid > 0);

  /*
   * A listening descriptor must become readable when an association is
   * waiting. Without that a poll driven server never calls accept at all.
   */
  p.fd      = fd;
  p.events  = POLLIN;
  p.revents = 0;
  check("listening fd reports readable", poll(&p, 1, 8000) == 1);

  conn = accept(fd, (struct sockaddr*)&from, &fromlen);
  check("accept returns a descriptor", conn >= 0);
  check("accepted descriptor differs from listener", conn != fd);
  if (conn < 0) {
    kill(pid, SIGTERM);
    waitpid(pid, &status, 0);
    return 1;
  }

  {
    /*
     * SCTP_STATUS on the accepted descriptor: osmo-hnbgw's "show hnb"
     * asks for it and prints the state, streams, windows and primary peer.
     */
    struct sctp_status  st;
    socklen_t           sl = sizeof(st);
    struct sockaddr_in* prim = (struct sockaddr_in*)&st.sstat_primary.spinfo_address;
    int                 rc;
    memset(&st, 0, sizeof(st));
    rc = getsockopt(conn, IPPROTO_SCTP, SCTP_STATUS, &st, &sl);
    check("SCTP_STATUS on the accepted descriptor", rc == 0);
    check("SCTP_STATUS reports an established state", rc == 0 && st.sstat_state == SCTP_ESTABLISHED);
    check("SCTP_STATUS reports the peer as primary",
          rc == 0 && prim->sin_family == AF_INET && prim->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    if (rc == 0) {
      printf("  sstat_state %d rwnd %u instrms %u outstrms %u primary %s:%u\n",
             st.sstat_state, st.sstat_rwnd, st.sstat_instrms, st.sstat_outstrms,
             inet_ntoa(prim->sin_addr), ntohs(prim->sin_port));
    }
  }

  n = raw_recv(conn, buf, sizeof(buf), &ppid, 16);
  check("request received through raw recvmsg",
        n == (ssize_t)strlen(REQ) && memcmp(buf, REQ, n) == 0);
  check("ppid survived the control message", ppid == PPID);

  check("reply sent through raw sendmsg",
        raw_send(conn, RSP, PPID) == (ssize_t)strlen(RSP));

  waitpid(pid, &status, 0);
  {
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    check("client completed", rc == 0 || rc == 2);
    check("client SO_NOSIGPIPE accepted", rc != 3);
    check("client SCTP_STATUS after connect", rc != 4);
    check("client received the reply", rc == 0);
  }

  close(conn);
  close(fd);
  printf("\n%s\n", fails == 0 ? "interpose test passed" : "interpose test FAILED");
  return fails == 0 ? 0 : 1;
}
