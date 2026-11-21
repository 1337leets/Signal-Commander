# Signal Commander

A terminal UI for network path diagnostics, written from scratch in C with raw sockets and
ncurses. It traces and pings over ICMP, TCP and UDP, resolves names with its own DNS client and
can keep many probes in flight at once. It needs nothing beyond libc and ncurses. Every ICMP and
TCP probe is assembled by hand and every reply is parsed byte by byte.

## Screens

**Track Signal.** ICMP trace to `one.one.one.one` with DNS on and 16 probes in flight.

```
Target: one.one.one.one -> 1.1.1.1
┌─[ TRACK SIGNAL ]─[ ICMP ]──────────────────────────────────────────────────[ DONE ]─┐
│ HOP  IP ADDRESS        RTT 1     RTT 2     RTT 3           NAME                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  1   172.25.x.x         0.79 ms   0.81 ms   0.82 ms        MY-PC.mshome.net         │
│  2   192.168.x.x        4.19 ms   4.99 ms   5.63 ms                                 │
│  3   10.x.x.x          10.22 ms  10.79 ms  10.79 ms                                 │
│  4   10.x.x.x          29.37 ms  29.71 ms  30.37 ms                                 │
│  5   172.16.x.x        14.04 ms  21.32 ms      *                                    │
│  6   * * *                                                                          │
│  7   172.16.x.x        27.99 ms  26.09 ms  26.27 ms                                 │
│  8   * * *                                                                          │
│  9   172.16.x.x        20.71 ms  17.26 ms  14.33 ms                                 │
│ 10   * * *                                                                          │
│ 11   172.16.x.x         6.43 ms   6.99 ms   7.24 ms                                 │
│ 12   10.x.x.x           8.60 ms   9.03 ms   7.75 ms                                 │
│ 13   10.x.x.x              *      4.61 ms      *                                    │
│ 14   80.231.6.2        45.15 ms  44.56 ms  42.66 ms        ix-ae-3-0.tcore1.ekco3-g │
│ 15   195.219.87.170    46.80 ms  45.09 ms  56.50 ms        if-ae-44-11.tcore2.fnm-f │
│ 16   * * *                                                                          │
│ 17   195.219.87.51     47.90 ms  59.48 ms  61.99 ms        if-bundle-11-2.qcore2.f2 │
│ 18   1.1.1.1           56.67 ms  50.86 ms  48.23 ms        one.one.one.one          │
└─────────────────────────────────────────────────────────────────────────────────────┘
  [ ESC ] abort   [ UP/DOWN ] scroll
```

**Send Signal.** TCP ping to `dns.google` on port 443. Each row is the time from SYN to SYN-ACK.

```
Target: dns.google -> 8.8.8.8
┌─[ SEND SIGNAL ]──────────────────[ RUNNING ]─┐
│ PING 8.8.8.8  [ TCP 443 ]                    │
│ SEQ    RESULT                                │
├──────────────────────────────────────────────┤
│   1    time=31.40 ms  open                   │
│   2    time=74.39 ms  open                   │
│   3    time=27.17 ms  open                   │
│   4    time=61.63 ms  open                   │
│   5    time=55.01 ms  open                   │
│   6    time=28.97 ms  open                   │
│   7    time=58.62 ms  open                   │
├──────────────────────────────────────────────┤
│ sent 7  recv 7  loss 0%                      │
│ min/avg/max = 27.17/48.17/74.39 ms           │
└──────────────────────────────────────────────┘
  [ ESC ] stop
```

**Settings.**

```
┌─[ SETTINGS ]────────┬───────────────────────[ NAV MODE ]─┐
│ FIELD               │ VALUE                              │
├─────────────────────┼────────────────────────────────────┤
│  Probes per hop     │  3                                 │
│  Hop timeout (ms)   │  2000                              │
│  Parallel probes    │  16                                │
│  UDP mode           │  Paris                             │
│  Resolve DNS        │  ON                                │
├─────────────────────┴────────────────────────────────────┤
│          [ SAVE ]                     [ CANCEL ]         │
└──────────────────────────────────────────────────────────┘
  UP/DOWN navigate   ENTER edit/select   q quit
```

## Features

- **Track Signal.** Live traceroute over ICMP, TCP SYN or UDP. The table fills in as replies
  arrive, scrolls, follows new hops and marks the verdict (`open` or `closed`, or an unreachable
  mark such as `!H`). A `+1` or `+2` right after an address means that many other routers
  answered the same hop, the sign of a path split by load balancing.
- **Send Signal.** Continuous ping over the same three protocols with a rolling result window
  and live min / avg / max and packet-loss statistics. Over TCP it measures SYN to SYN-ACK, which
  still works where ICMP is filtered.
- **Configuration.** Target host (IPv4 or hostname), port, TTL and protocol, each checked when it
  is committed.
- **Settings.** Probes per hop (1 to 5), hop timeout (100 to 10000 ms), parallel probes (1 to 32),
  UDP mode (Paris or Classic) and a Resolve DNS switch.
- **DNS.** Hostname targets and a reverse name for every hop, from a hand-built DNS client that
  never blocks the UI.
- **Standalone tools.** `trace`, `tcptrace`, `udptrace` and `dnsq` are the CLI testbeds each
  engine was proven in before it moved into the TUI.

## Build

Requires a Linux kernel (native or WSL2), gcc, and the ncurses development headers.

```sh
sudo apt install libncurses-dev     # Debian / Kali / Ubuntu
make
```

Raw sockets need privilege. Either run with sudo:

```sh
sudo ./signal_commander
```

or grant the capability once and then run normally:

```sh
make setcap
./signal_commander
```

## Usage

- `./signal_commander` starts the TUI. Arrow keys navigate, Enter selects, and ESC or q backs out.
- `./trace [ipv4]` runs an ICMP traceroute.
- `./tcptrace [ipv4] [port]` runs a TCP SYN traceroute, port 443 by default.
- `./udptrace [-p] [ipv4] [port]` runs a UDP traceroute, port 33434 by default. `-p` picks Paris
  mode. It also lists every router that answered a hop and counts the hops that split.
- `./dnsq <name> [server]` and `./dnsq -x <ipv4> [server]` run a forward or reverse lookup. This
  one needs no root.

The traceroute tools default to 8.8.8.8 when no address is given.

## Design notes

- **Hand-built ICMP.** Packets are assembled in a byte buffer (a `struct icmphdr` overlaid on a
  `char[]`) and checksummed with a 16-bit one's-complement sum computed while the checksum field
  is zero. Replies are parsed by stepping over the raw IP header (`ihl * 4`) to reach the ICMP
  payload.
- **The TTL trick.** Traceroute sends probes with a deliberately small TTL. Each router that
  decrements the TTL to zero returns an ICMP Time Exceeded message whose source address *is* that
  router, so climbing the TTL from 1 upward reveals the path one hop at a time.
- **Never blocking.** A TUI must never freeze, but waiting for a reply is inherently blocking.
  Every screen runs a tick loop instead. On each tick `select()` polls the sockets with a 60 ms
  timeout while the keyboard is polled separately, so the table updates live and ESC always
  responds.
- **One tag per probe.** Each probe carries a unique tag (`ttl * probes + probe`). ICMP carries it
  in the echo sequence number, TCP in the low 16 bits of the SYN sequence number, Classic UDP in
  the source port and Paris UDP in the IP ID. A late reply can never be credited to the wrong
  probe, and the same tag lets a reply find its slot when many probes are in flight.
- **Embedded-packet parsing.** A Time Exceeded reply carries the original probe's IP header plus
  the first 8 bytes of its payload. The parser digs through the outer IP header, the 8-byte ICMP
  header and the embedded IP header to recover the original ports and tag. Every step checks the
  buffer length first.
- **TCP SYN by hand.** The TCP checksum covers a 12-byte pseudo-header that includes the source
  IP, but the kernel picks that address. A UDP socket connected to the target makes the kernel run
  its route lookup, and `getsockname()` reads the chosen source back without a single packet
  leaving. The target answers with SYN-ACK (open) or RST (closed). The kernel then answers that
  SYN-ACK with its own RST, since it never opened the connection.
- **Classic UDP.** Probes are ordinary datagrams with a chosen TTL and source port. The whole UDP
  header fits in the 8 bytes a Time Exceeded message quotes, so the source port carries the tag.
  An ICMP Port Unreachable from the target means the trace has arrived. The catch is that a new
  source port means a new flow, and load balancers (ECMP) are free to send each flow down a
  different path.
- **Paris UDP.** The Paris traceroute idea is to keep every field a load balancer hashes on fixed
  for the whole trace. Here both ports, the length and therefore the checksum never change, and
  the IP and UDP headers are written by hand (`IP_HDRINCL`). The tag rides in the IP ID instead,
  which load balancers do not hash and which comes back whole inside the quoted IP header.
- **Why not the checksum.** The Paris paper hides the tag in the UDP checksum, solved through a
  2-byte payload word. That was the first try here, and a capture showed why it failed behind
  WSL2. The Windows NAT rewrites the checksum on the way out but never restores it inside the
  quoted header on the way back, so every reply past hop 1 came back off by the same constant.
  The IP ID came back untouched through all three NATs on the path.
- **Strict aliasing.** The first Paris probes all went out with a wrong UDP checksum. The packet
  was filled through struct pointers and read back through an `unsigned short` pointer, which
  breaks C's strict aliasing rule, and gcc at `-O2` moved the loads ahead of the stores. The same
  source built with `-fno-strict-aliasing` was correct. Every checksum now loads its words with
  `memcpy`, which is alias-safe and still compiles to a single load.
- **Parallel probing.** Track keeps a window of probes in flight (16 by default, the same as Linux
  traceroute). Each probe owns a slot, replies go straight to their slot by tag, and slots time out
  on their own. When a probe reaches the target the trace stops at that hop and drops the probes
  already sent past it. A window of 1 gives the original one-at-a-time behavior.
- **One 4-tuple, many SYNs.** With a fixed source port, parallel SYNs to the target all share one
  4-tuple. A packet capture showed the answers turning into a mix of SYN-ACK, RST and silence, so
  the verdict flipped between `open` and `closed` from run to run. In parallel mode every SYN now
  gets its own source port, and a SYN-ACK always outranks a later RST. Three captured runs after
  the change each showed 55 SYNs from 55 ports, 7 SYN-ACKs and no RST.
- **Hand-built DNS.** Queries are written byte by byte and sent over UDP to the first nameserver
  in `/etc/resolv.conf`. The socket is polled inside the tick loop, so a slow answer (an NXDOMAIN
  took about 1 s here) never freezes the screen. The query ID comes from `/dev/urandom`, because a
  guessable ID is what cache poisoning relies on. Name decompression only follows pointers that
  point backward and gives up after 16 jumps. Unprintable bytes in a name are shown as `?`. A
  hostile answer can neither loop the parser nor write escape codes to the terminal, and both
  cases were tested against a fake server.
- **Data-driven forms.** Configuration and Settings are both generated from field-metadata tables
  through one form engine, so adding a field is a table entry rather than new code.

## Measurements

Wall time until `[ DONE ]` for a trace to 8.8.8.8, 3 probes per hop, 2000 ms timeout.

| Protocol  | 1 probe in flight | 16 probes in flight |
|-----------|-------------------|---------------------|
| ICMP      | 14.7 s            | 1.8 s               |
| TCP 443   | 43.8 s to 50.0 s  | 3.9 s to 4.0 s      |
| UDP 33434 | not measured      | 2.0 s to 3.8 s      |

Path splits with `udptrace` (one probe in flight), counting hops where more than one router
answered within a single trace.

| UDP mode | Traces | Reached the target | Split hops per trace |
|----------|--------|--------------------|----------------------|
| Classic  | 4      | 4                  | 1, 2, 1, 1           |
| Paris    | 5      | 5                  | 0, 0, 0, 0, 0        |

Paris keeps each trace on one path. A new trace gets a new source port, so it may take a
different path than the previous one, and that is expected.

These come from WSL2 on a single home connection, so they illustrate the effect rather than
benchmark it.

## Caveats

- Parallel probing trades some accuracy for speed. Routers rate limit the ICMP errors they send,
  so a burst shows more `*`, and RTTs can read higher in a burst than one probe at a time.
- In parallel mode TCP changes the source port for every probe, so routers that balance traffic
  across several paths (ECMP) may send probes down different ones. Setting Parallel probes to 1
  keeps a single TCP source port and therefore a single path. Paris UDP keeps one path at any
  window size.
- Paris UDP relies on NATs leaving the quoted IP ID alone. If replies stop matching past some hop,
  switching UDP mode to Classic is the fallback.
- Some routers answer ICMP probes but stay silent for TCP or UDP ones, so the same path can show
  different gaps per protocol.
- Under WSL2 the first hop is the Windows NAT gateway. The WSL DNS proxy also answers PTR lookups
  for private addresses with the address itself. Those names are hidden.
- A resolver that rewrites NXDOMAIN answers can make a mistyped hostname resolve to some other
  address. The target line above the table always shows the IP actually in use.
- Routers rate limit Destination Unreachable messages too. Right after a parallel trace has used
  up that budget, a ping to an unreachable host can show `timeout` instead of `unreachable`.

## Unreachable marks

A Destination Unreachable stops the trace at the hop that sent it, in every protocol. The code in
the message picks the mark, the same way Linux traceroute does.

| Mark | ICMP codes | Meaning                                          |
|------|------------|--------------------------------------------------|
| `!N` | 0, 6, 11   | Network unreachable or unknown                   |
| `!H` | 1, 7, 12   | Host unreachable or unknown                      |
| `!X` | 9, 10, 13  | Administratively prohibited (a filter said no)   |
| `!P` | 2          | Protocol unreachable                             |
| `!F` | 4          | Fragmentation needed but DF was set              |
| `!U` | any other  | Some other unreachable                           |

Over UDP, a Port Unreachable (code 3) from the target means the trace arrived and the port is
closed, so it shows as `closed` instead.

## Status

Traceroute and ping over ICMP, TCP and UDP (Paris or Classic), DNS, scrolling, parallel probing,
split markers and per-code unreachable marks all work.

Not done yet is IPv6.

## Requirements & notes

- Linux only, because it uses raw sockets. On Windows, WSL2 works because it runs a real kernel.
- IPv4 only for now.

## License

Apache-2.0. See [LICENSE](LICENSE).
