# Signal Commander

A terminal UI for ICMP network diagnostics (traceroute and ping), built from
scratch in C with raw sockets and ncurses. It needs nothing beyond libc and
ncurses. Every ICMP packet is assembled by hand and every reply is parsed byte
by byte.

<!-- TODO: add a screenshot or GIF here, e.g. docs/track-signal.png -->

## Features

- **Configuration.** Edit target host, port, TTL and protocol in a navigable
  form with per-field validation (IPv4 format, integer ranges, cycling options).
- **Track Signal.** Live traceroute. It climbs the TTL hop by hop with 3 probes
  per hop and fills the table as replies arrive. The loop never blocks, so the
  UI stays responsive and ESC aborts a trace midway.
- **Send Signal.** Continuous ping with a rolling result window and live
  min / avg / max and packet-loss statistics.
- **`trace`.** A standalone CLI traceroute that shares the same engine.

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
- `./trace <ipv4>` runs a standalone traceroute to a single target.

## Design notes

- **Hand-built ICMP.** Packets are assembled in a byte buffer (a `struct icmphdr`
  overlaid on a `char[]`) and checksummed with a 16-bit one's-complement sum
  computed while the checksum field is zero. Replies are parsed by stepping over
  the raw IP header (`ihl * 4`) to reach the ICMP payload.
- **The TTL trick.** Traceroute sends probes with a deliberately small TTL. Each
  router that decrements the TTL to zero returns an ICMP Time Exceeded message
  whose source address *is* that router, so climbing the TTL from 1 upward
  reveals the path one hop at a time. The destination replies with an Echo Reply
  instead, which is how the trace knows it has arrived.
- **Non-blocking FSM.** A TUI must never freeze, but waiting for a reply is
  inherently blocking. Track Signal is a small state machine with SEND, WAIT and
  DONE states, driven by a tick loop. On each tick `select()` polls the socket
  with a short timeout while the keyboard is polled separately, so the table
  updates live and ESC always responds.
- **Unique per-probe sequence numbers.** Each probe is stamped with a unique ICMP
  sequence (`ttl * PROBES + probe`), so a late reply can't be attributed to the
  wrong probe. This also lays the groundwork for firing probes in parallel.
- **Embedded-packet parsing.** A Time Exceeded reply carries the original probe's
  IP header plus the first 8 bytes of its payload. The parser digs through the
  outer IP header, the 8-byte Time Exceeded header and the embedded IP header to
  recover the original sequence number and confirm the reply belongs to this trace.
- **Data-driven config.** The configuration screen is generated from a
  field-metadata table, so adding a field is a table entry rather than new code.

## Status

ICMP traceroute, ping and the configuration screen work today.

Planned work includes TCP and UDP probing (SYN / ICMP port-unreachable), a
Settings screen, a scrollable hop table, optional DNS resolution, and parallel
(pipelined) probing.

## Requirements & notes

- Linux only, because it uses raw sockets. On Windows, WSL2 works because it runs a real kernel.
- IPv4 only for now.

## License

Apache-2.0. See [LICENSE](LICENSE).
