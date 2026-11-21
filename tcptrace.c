// Signal Commander // tcptrace.c _________________________________________________________________
// TCP SYN traceroute. Hand-builds SYN probes with a climbing TTL, routers answer with ICMP Time
// Exceeded and the target answers with SYN-ACK (open) or RST (closed). Standalone testbed, the
// engine moves into the TUI once this is proven.
// Build:  gcc tcptrace.c -o tcptrace
// Run:    sudo ./tcptrace 8.8.8.8 443   (raw sockets need root or CAP_NET_RAW)
////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define MAX_HOPS    30
#define TIMEOUT_SEC 2
#define PROBES      3

// One probe's answer. Filled by wait_reply.
typedef struct {
  char   ip[INET_ADDRSTRLEN]; // Who answered, empty on timeout
  double rtt;                 // Round trip in ms, -1 means no reply
  int    reached;             // 1 if the trace should stop here
  char   flag;                // 'O' SYN-ACK, 'C' RST, 'U' unreachable, 0 plain router hop
} Reply;

// One hop, PROBES probes folded together. Filled by track_hop, printed by print_hop.
typedef struct {
  char   ip[INET_ADDRSTRLEN]; // Responder for this hop, empty if none answered
  double rtt[PROBES];         // One RTT per probe, -1 for the ones that timed out
  int    reached;             // 1 if any probe ended the trace
  char   flag;                // Strongest verdict any probe got
} Hop;

// The 12 bytes TCP checksums over but never sends. Mirrors the IP header the kernel will build.
struct pseudo_hdr {
  uint32_t src, dst;          // Source and destination IP, network order
  uint8_t  zero, proto;       // Always 0, then IPPROTO_TCP
  uint16_t len;               // TCP header + payload length, network order
};

// Checksum ______________________________________________________________________________________
// 16-bit one's complement sum over the whole packet, folded, then inverted.
// Words are loaded with memcpy. The packet is filled through struct pointers, and reading it back
// through an unsigned short pointer breaks strict aliasing, which let gcc -O2 reorder the loads
// ahead of the stores in udptrace (measured). memcpy is alias-safe and still compiles to one load.
unsigned short checksum(const void *b, int len) {
  const unsigned char *p = b; unsigned int sum = 0; unsigned short result;
  for (; len > 1; len -= 2, p += 2) {             // Sums word by word
    unsigned short w; memcpy(&w, p, 2); sum += w;
  }
  if (len == 1) sum += *p;                        // Adds the lone trailing byte if odd
  sum = (sum >> 16) + (sum & 0xFFFF); sum += (sum >> 16); // Folds the carry back in twice
  result = ~sum; return result;                   // Inverts every bit
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Open Sockets __________________________________________________________________________________
int open_raw_socket(int proto) {
  int s = socket(AF_INET, SOCK_RAW, proto); // Raw, kernel still builds the outer IP hdr
  if (s < 0) { perror("socket (need root or CAP_NET_RAW)"); exit(1); } // Dies early if unprivileged
  return s;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Resolve Target ________________________________________________________________________________
struct sockaddr_in resolve_target(const char *ip, int port) {
  struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET;
  if (inet_pton(AF_INET, ip, &a.sin_addr) <= 0) {  // Parses the dotted quad, does no DNS
    fprintf(stderr, "Not a valid IPv4 address: %s\n", ip); exit(1);
  }
  if (port < 1 || port > 65535) { fprintf(stderr, "Port out of range: %d\n", port); exit(1); }
  a.sin_port = htons(port);                        // Rides along, raw sendto ignores it
  return a;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Find Source IP ________________________________________________________________________________
// Pseudo-header needs the source IP, but the kernel picks it. A connected UDP socket makes the
// kernel run its route lookup and tell me the answer. Nothing goes on the wire.
struct in_addr find_source_ip(struct sockaddr_in *target) {
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0 || connect(s, (struct sockaddr *)target, sizeof(*target)) < 0) {
    perror("route lookup"); exit(1);               // No route to the target at all
  }
  struct sockaddr_in local; socklen_t l = sizeof(local);
  getsockname(s, (struct sockaddr *)&local, &l);   // Reads back the source the route chose
  close(s);
  return local.sin_addr;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Send Probe ____________________________________________________________________________________
// Builds pseudo-header + TCP header back to back, checksums both, sends only the TCP part.
struct timespec send_probe(int sock, struct sockaddr_in *target, struct in_addr src,
                             uint16_t sport, int ttl, uint32_t seq) {
  setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)); // Sets the TTL, the one thing bumped each hop

  char packet[sizeof(struct pseudo_hdr) + sizeof(struct tcphdr)]; memset(packet, 0, sizeof(packet));
  struct pseudo_hdr *ph  = (struct pseudo_hdr *)packet;                     // First 12 bytes
  struct tcphdr     *tcp = (struct tcphdr *)(packet + sizeof(struct pseudo_hdr)); // Real header after

  tcp->source = htons(sport);             // Fixed for the whole run, keeps the flow on one ECMP path
  tcp->dest   = target->sin_port;          // The port under test
  tcp->seq    = htonl(seq);               // Carries pid + probe tag, survives in the ICMP quote
  tcp->doff   = 5;                        // 5 words = 20 bytes, no options
  tcp->syn    = 1;                        // SYN only, a fresh handshake
  tcp->window = htons(64240);             // Plausible window, some boxes drop 0

  ph->src   = src.s_addr;                 // Same source the kernel will stamp
  ph->dst   = target->sin_addr.s_addr;
  ph->proto = IPPROTO_TCP;
  ph->len   = htons(sizeof(struct tcphdr));
  tcp->check = checksum(packet, sizeof(packet)); // Checksums pseudo + TCP with the field at 0

  struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); // Grabs the send instant for RTT
  if (sendto(sock, tcp, sizeof(struct tcphdr), 0, (struct sockaddr *)target, sizeof(*target)) <= 0)
    perror("sendto"); // On fail this probe just shows *, loop carries on
  return t;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Parse ICMP ____________________________________________________________________________________
// Time Exceeded or Dest Unreachable quoting my SYN. Returns 1 and fills c if it is mine.
int parse_icmp(char *buf, int n, struct sockaddr_in *target, uint16_t sport, uint32_t seq, Reply *c) {
  if (n < (int)sizeof(struct iphdr) + 8) return 0;
  struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;       // Steps over the outer IP
  if (n < iplen + 8) return 0;
  struct icmphdr *icmp = (struct icmphdr *)(buf + iplen);
  if (icmp->type != ICMP_TIME_EXCEEDED && icmp->type != ICMP_DEST_UNREACH) return 0; // Unrelated ICMP

  int off = iplen + 8;                                                     // Skips the 8 byte ICMP header
  if (n < off + (int)sizeof(struct iphdr)) return 0;
  struct iphdr *iip = (struct iphdr *)(buf + off); int iiplen = iip->ihl * 4; // Embedded original IP
  if (iip->protocol != IPPROTO_TCP || iip->daddr != target->sin_addr.s_addr) return 0; // Not my flow
  if (n < off + iiplen + 8) return 0;                                      // Only 8 bytes are promised
  struct tcphdr *itcp = (struct tcphdr *)(buf + off + iiplen);             // Ports + seq, nothing past
  if (ntohs(itcp->source) != sport || itcp->dest != target->sin_port ||
      ntohl(itcp->seq) != seq) return 0;                                   // Someone else's probe

  if (icmp->type == ICMP_DEST_UNREACH) { c->reached = 1; c->flag = 'U'; }  // Filtered, trace ends here
  return 1;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Parse TCP _____________________________________________________________________________________
// SYN-ACK or RST from the target answering my SYN. Matched on ports and ack = seq + 1.
int parse_tcp(char *buf, int n, struct sockaddr_in *target, uint16_t sport, uint32_t seq, Reply *c) {
  if (n < (int)sizeof(struct iphdr)) return 0;
  struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;
  if (ip->saddr != target->sin_addr.s_addr) return 0;                      // Not from the target
  if (n < iplen + (int)sizeof(struct tcphdr)) return 0;
  struct tcphdr *tcp = (struct tcphdr *)(buf + iplen);
  if (tcp->source != target->sin_port || ntohs(tcp->dest) != sport) return 0; // Other connection
  if (!tcp->ack || ntohl(tcp->ack_seq) != seq + 1) return 0;               // Acks some other SYN

  if (tcp->syn)      c->flag = 'O';                                        // SYN-ACK, port open
  else if (tcp->rst) c->flag = 'C';                                        // RST, port closed
  else return 0;
  c->reached = 1;
  return 1;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Wait Reply ____________________________________________________________________________________
// Watches both sockets until a reply for this seq shows up or the deadline passes.
Reply wait_reply(int isock, int tsock, struct sockaddr_in *target, uint16_t sport,
                  uint32_t seq, struct timespec t0) {
  Reply c = { .ip = "", .rtt = -1.0, .reached = 0, .flag = 0 }; // Defaults to a timed-out probe
  double deadline = (t0.tv_sec + TIMEOUT_SEC) * 1000.0 + t0.tv_nsec / 1000000.0; // Pins the deadline once
  char buf[1024]; struct sockaddr_in from; socklen_t klen;
  int maxfd = (isock > tsock) ? isock : tsock;

  while (1) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    double left = deadline - (now.tv_sec * 1000.0 + now.tv_nsec / 1000000.0); // Time left this pass
    if (left <= 0) break;                                       // Out of time, returns the default

    struct timeval tv; tv.tv_sec = (time_t)(left / 1000.0);     // select reads {0,0} as poll, no floor needed
    tv.tv_usec = (suseconds_t)((left - tv.tv_sec * 1000.0) * 1000.0);
    fd_set r; FD_ZERO(&r); FD_SET(isock, &r); FD_SET(tsock, &r);
    if (select(maxfd + 1, &r, NULL, NULL, &tv) <= 0) continue;   // Timeout or signal, loop rechecks the clock

    int mine = 0;
    if (FD_ISSET(isock, &r)) {                                   // A router or firewall talking
      klen = sizeof(from);
      int n = recvfrom(isock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &klen);
      if (n > 0) mine = parse_icmp(buf, n, target, sport, seq, &c);
    }
    if (!mine && FD_ISSET(tsock, &r)) {                          // The target itself talking
      klen = sizeof(from);
      int n = recvfrom(tsock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &klen);
      if (n > 0) mine = parse_tcp(buf, n, target, sport, seq, &c);
    }
    if (!mine) continue;                                         // Somebody else's packet, keep waiting

    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    c.rtt = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1000000.0; // Measures RTT from send
    inet_ntop(AF_INET, &from.sin_addr, c.ip, sizeof(c.ip));   // Records the responder address
    break;
  }
  return c;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Track Hop _____________________________________________________________________________________
// Fires PROBES SYNs at one ttl, folds their answers into a single Hop.
Hop track_hop(int isock, int tsock, struct sockaddr_in *target, struct in_addr src,
             uint16_t sport, uint16_t my_id, int ttl) {
  Hop h; memset(&h, 0, sizeof(h));
  for (int p = 0; p < PROBES; p++) h.rtt[p] = -1.0; // Marks every probe as timed out until proven otherwise

  for (int p = 0; p < PROBES; p++) {
    uint32_t seq = ((uint32_t)my_id << 16) | (uint32_t)(ttl * PROBES + p); // pid on top, probe tag below
    struct timespec t0 = send_probe(tsock, target, src, sport, ttl, seq);
    Reply c = wait_reply(isock, tsock, target, sport, seq, t0);

    h.rtt[p] = c.rtt;
    if (c.rtt >= 0) strcpy(h.ip, c.ip);             // Keeps the responder from whichever probe answered
    if (c.reached)  h.reached = 1;
    if (c.flag)     h.flag = c.flag;                // Any verdict beats a plain hop
  }
  return h;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Print Hop _____________________________________________________________________________________
void print_hop(int ttl, Hop *h) {
  if (h->ip[0] == 0) { printf("%2d  * * *\n", ttl); return; } // No probe answered at all, dead or filtered
  printf("%2d  %-15s", ttl, h->ip);
  for (int p = 0; p < PROBES; p++)
    (h->rtt[p] < 0) ? printf("   *    ") : printf("  %.2f ms", h->rtt[p]);
  if      (h->flag == 'O') printf("  [open]");    // SYN-ACK came back
  else if (h->flag == 'C') printf("  [closed]");  // RST came back
  else if (h->flag == 'U') printf("  !U");        // Unreachable, something filtered it
  printf("\n");
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Logic _________________________________________________________________________________________
int main(int argc, char *argv[]) {
  const char *target_ip = (argc > 1) ? argv[1] : "8.8.8.8"; // Defaults to Google DNS if no arg given
  int port = (argc > 2) ? atoi(argv[2]) : 443;             // Defaults to HTTPS, open almost everywhere

  struct sockaddr_in target = resolve_target(target_ip, port);  // Validates args before hitting the root wall
  struct in_addr src = find_source_ip(&target);
  int isock = open_raw_socket(IPPROTO_ICMP);                  // Hears Time Exceeded and Unreachable
  int tsock = open_raw_socket(IPPROTO_TCP);                   // Sends SYNs, hears SYN-ACK and RST

  uint16_t my_id = getpid() & 0xFFFF;
  uint16_t sport = 40000 + (getpid() % 20000);             // One source port per run

  char sbuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &src, sbuf, sizeof(sbuf));
  printf("TCP traceroute to %s:%d from %s:%u, %d hops max\n\n", target_ip, port, sbuf, sport, MAX_HOPS);

  for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
    Hop h = track_hop(isock, tsock, &target, src, sport, my_id, ttl);
    print_hop(ttl, &h);
    if (h.reached) break;                                  // Stops on SYN-ACK, RST or unreachable
  }
  close(isock); close(tsock);
  return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////
