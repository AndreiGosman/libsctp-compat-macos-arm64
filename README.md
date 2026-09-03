# libsctp-compat-macos-arm64

A drop-in `libsctp` for macOS on Apple Silicon. It gives Linux SCTP code the
`netinet/sctp.h` header and the `libsctp` symbols it expects, and carries the
traffic on the usrsctp userspace stack.

## Motivation

The XNU kernel has no SCTP. Darwin declares `IPPROTO_SCTP` in `netinet/in.h`
and implements nothing behind it, so `socket(AF_INET, SOCK_SEQPACKET,
IPPROTO_SCTP)` fails with `EPROTONOSUPPORT` and there is no `netinet/sctp.h`
in the SDK. Every project that speaks S1AP, NGAP, M3UA or IUA therefore stops
at the first compile, and srsRAN 4G stops earlier still: `lib/src/common/
CMakeLists.txt` links `srsran_common` against `${SCTP_LIBRARIES}`, and
`srsran_common` is what `srsue` is built on, so even a cell search build needs
the library present.

## Architecture

usrsctp is a userspace port of the FreeBSD kernel SCTP stack. It is a good
protocol engine and a poor fit for Linux application code, because it has no
file descriptors. `usrsctp_socket()` returns a `struct socket *`, delivers
received data through a callback on its own thread, and cannot be passed to
`poll()`, `select()` or `read()`.

This library closes that gap with one AF_UNIX `SOCK_DGRAM` socketpair per SCTP
socket. The application holds one end and treats it as an ordinary descriptor.
The usrsctp receive callback writes each message into the other end, prefixed
by a small header carrying the flags, the sender address and the
`sctp_sndrcvinfo`. Datagram boundaries survive the trip, so `SOCK_SEQPACKET`
semantics survive with them, and `poll()` works because the descriptor is a
real kernel object.

The socket calls that carry SCTP are interposed. `socket()`, `bind()`,
`listen()`, `connect()`, `close()`, `setsockopt()`, `getsockopt()`,
`getsockname()`, `getpeername()` and `shutdown()` are exported by this library,
so the link editor binds an application to them instead of libSystem. Each one
checks whether the descriptor belongs to us and hands everything else straight
back to libc. UDP and TCP in the same process are untouched. No
`DYLD_INSERT_LIBRARIES` is needed, and none should be used: the two-level
namespace is what keeps usrsctp's own socket calls from recursing into us.

`SO_RCVTIMEO`, `SO_SNDTIMEO`, `SO_RCVBUF` and `SO_SNDBUF` are applied to the
socketpair rather than the usrsctp socket, because that is the descriptor the
caller reads from. A receive loop that waits for `EAGAIN` on idle, which is
what srsRAN and Osmocom both do, keeps working unchanged.

## Build

```
source ~/sdr-lab/env.sh
scripts/install_usrsctp.sh          # builds and installs the backend
cd src/libsctp-compat
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$HOME/sdr-lab/local -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)
ctest --output-on-failure
make install
```

The install writes `lib/libsctp.dylib`, `include/netinet/sctp.h`, and two
pkg-config files. srsRAN's `FindSCTP.cmake` asks pkg-config for `sctp`;
Osmocom asks for `libsctp`. Both names are installed, so neither project needs
a patch.

## Transport modes

usrsctp can put SCTP on the wire two ways.

Raw mode is the default. usrsctp opens raw `IPPROTO_SCTP` sockets and speaks
to any standard SCTP peer, which is what a real MME or AMF expects. macOS
requires root for raw sockets, so the process must run privileged.

UDP encapsulation, RFC 6951, is selected by setting
`LIBSCTP_COMPAT_UDP_ENCAPS_PORT` to a port number, conventionally 9899. It
needs no privilege, and it needs a peer that also encapsulates. The library
sets the remote encapsulation port on every socket as well, because usrsctp
otherwise sends raw SCTP no matter what the local setting says.

Two processes on one host cannot share a tunnelling port. Give each its own
`LIBSCTP_COMPAT_UDP_ENCAPS_PORT` and point it at the other with
`LIBSCTP_COMPAT_UDP_ENCAPS_REMOTE_PORT`, which otherwise defaults to the local
port. The port is checked before the stack starts: `usrsctp_init` returns void
and carries on with no transport when the bind fails, which looks like a silent
network rather than an error, so a conflict is reported and refused instead.

Set `LIBSCTP_COMPAT_DEBUG=1` for a trace of socket creation, the receive pump
and the backend.

## API mapping

| lksctp | backend |
| --- | --- |
| `socket(…, IPPROTO_SCTP)` | `usrsctp_socket()` plus a socketpair |
| `bind`, `listen`, `connect`, `shutdown` | `usrsctp_bind`, `_listen`, `_connect`, `_shutdown` |
| `setsockopt`, `getsockopt` at `IPPROTO_SCTP` | `usrsctp_setsockopt`, `usrsctp_getsockopt` |
| `setsockopt` at `SOL_SOCKET` for timeouts and buffers | the socketpair descriptor |
| `getsockname`, `getpeername` | first entry of `usrsctp_getladdrs`, `_getpaddrs` |
| `sctp_sendmsg`, `sctp_send` | `usrsctp_sendv` with `SCTP_SENDV_SNDINFO` |
| `sctp_recvmsg` | `recvmsg` on the socketpair, fed by the receive callback |
| `sctp_bindx` | `usrsctp_bindx`, one address per call |
| `sctp_connectx`, `sctp_getpaddrs`, `sctp_getladdrs`, `sctp_opt_info` | the matching `usrsctp_*` call |
| `sctp_freepaddrs`, `sctp_freeladdrs` | the matching call, with a NULL guard |
| `sctp_peeloff` | not implemented, returns `EOPNOTSUPP` |

## Differences from Linux that callers can see

`SCTP_EVENTS` is numbered `0x0b` on Linux and `0x0c` on FreeBSD and usrsctp.
The header uses the Linux value and the shim translates it, so code that
hardcodes `0x0b` still works.

`sctp_freepaddrs(NULL)` is a no-op on Linux, where lksctp-tools implements it
as a bare `free(addrs)`. usrsctp inherits the FreeBSD libc version, which steps
backwards from the pointer to reach a hidden header and frees a wild address.
Neither is wrong: NULL is simply not a documented argument. This library
guards it so that cleanup paths written against Linux do not abort.

lksctp-tools declares `sctp_freepaddrs` and `sctp_freeladdrs` as returning
`int`; FreeBSD and usrsctp return `void`. The header here uses `int`, which
compiles for callers written against either.

A send on a one-to-many socket with neither a destination address nor an
association id returns `ENOENT`. usrsctp is right to do so: RFC 6458 section
3.1.3 states that `connect()` on a one-to-many socket creates an association
but no default destination, and that repeated `connect()` calls create several
associations on the same socket. Code written against Linux is often looser
than the specification allows, so this library remembers the peer of a single
`connect()` and supplies it. That convenience is withdrawn as soon as a second
`connect()` makes the choice ambiguous, because picking between two
associations would deliver data to the wrong peer in silence.

usrsctp is built with `HAVE_SA_LEN` and `HAVE_SIN_LEN`, so it reads the
`sin_len` field that Linux sockaddrs do not have. Every address the caller
passes is normalised before it reaches the backend.

`sctp_peeloff` is refused rather than half-implemented. Splitting one
association off a one-to-many socket would need a second socketpair and its own
pump registration, and no target project calls it.

The `timetolive` argument of `sctp_sendmsg` is not forwarded. usrsctp carries
partial reliability in a separate `sctp_prinfo` block. A non-zero value is
logged rather than silently dropped.

Messages larger than 256 KB are dropped by the pump and logged.

## Tested against

srsRAN 4G 25.10.0 configures cleanly with this library in place, and the three
socket-option helpers in `srsran/common/network_utils.cc` compile and run
against the header unchanged. Building srsRAN itself on Darwin needs further
work that has nothing to do with SCTP: srsRAN passes `-mfloat-abi=hard
-mfpu=neon`, which Apple clang rejects on arm64, and `srsran/common/threads.h`
includes the Linux-only `sys/timerfd.h`.

osmo-bts and the Osmocom core network are the next targets and are not yet
tested.

## Upstream

Nothing here is filed against usrsctp. The two behaviours this library works
around are inherited FreeBSD semantics rather than defects: `sctp_freepaddrs`
is a verbatim copy of the FreeBSD libc function, and the `ENOENT` on an
unaddressed one-to-many send is what RFC 6458 section 3.1.3 calls for. Both are
documented above as differences a caller can see, which is where they belong.

## Status

The loopback test establishes a real SCTP association between two sockets in
one process, sends a payload, and reads it back through `poll()` and
`sctp_recvmsg` with the association id and peer address intact.

A separate two process exchange has also been run over loopback, in the shape
S1AP uses: a one-to-many listener, a client that connects and sends, an
association notification and a payload delivered with the right association id,
and a reply back. That works with distinct encapsulation ports.

A conversation with a separate host running a kernel SCTP stack has not been
tested yet.

One behaviour to know when reading logs: `connect()` on a one-to-many socket
returns once the INIT is queued, not once the association is up, so a
successful return is not by itself evidence of a peer. Wait for the
`SCTP_ASSOC_CHANGE` notification.

## License

LGPL-2.1-or-later. usrsctp itself is BSD-2-Clause.
