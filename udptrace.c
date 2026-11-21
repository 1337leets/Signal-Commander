// Signal Commander // udptrace.c _________________________________________________________________
// UDP traceroute in two flavors. Classic: the kernel builds each datagram, I pick its TTL and a
// source port that doubles as the probe tag. Paris (-p): I build the IP and UDP headers myself,
// keep the whole UDP header fixed so every probe has the same 5-tuple, and carry the tag in the
// IP ID. Routers answer with ICMP Time Exceeded, the target with ICMP Port Unreachable.
// Build:  gcc udptrace.c -o udptrace
// Run:    sudo ./udptrace [-p] 8.8.8.8 33434   (raw sockets need root or CAP_NET_RAW)
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
#include <netinet/udp.h>
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
  char   flag;                // 'C' port unreachable, 'U' other unreachable, 0 plain router hop
} Reply;

// One hop, PROBES probes folded together. Filled by track_hop, printed by print_hop.
typedef struct {
  char   ip[INET_ADDRSTRLEN];        // Responder for this hop, empty if none answered
  char   ips[PROBES][INET_ADDRSTRLEN]; // Responder per probe, shows when ECMP splits a hop
  double rtt[PROBES];                // One RTT per probe, -1 for the ones that timed out
  int    reached;                    // 1 if any probe ended the trace
  char   flag;                       // Strongest verdict any probe got
} Hop;

// Everything one run needs to send and match probes
typedef struct {
  int                paris;  // 1 = fixed ports, tag in the checksum
  struct sockaddr_in target; // Destination address and port
  struct in_addr     src;    // Source IP, Paris needs it for the pseudo-header
  uint16_t           sport;  // Classic: block start. Paris: the one fixed source port
  int                rsock;  // Raw UDP socket for Paris sends, -1 in classic mode
} Run;

// UDP checksum covers these 12 bytes too, a summary of the IP header the kernel will build
struct pseudo_hdr {
  uint32_t src, dst;
  uint8_t  zero, proto;
  uint16_t len;
};

// Checksum ______________________________________________________________________________________
// Folded 16-bit one's complement sum, not yet inverted. The caller inverts it for the checksum.
// Words are loaded with memcpy. Reading the buffer through a uint16_t pointer after filling it
// through struct pointers breaks strict aliasing, and at -O2 gcc reordered the loads ahead of the
// stores: measured, every Paris probe went out with a wrong checksum until this changed.
uint16_t ones_sum(const void *b, int len) {
  const uint8_t *p = b; uint32_t sum = 0;
  for (; len > 1; len -= 2, p += 2) {             // Sums word by word
    uint16_t w; memcpy(&w, p, 2); sum += w;       // memcpy is alias-safe and still compiles to one load
  }
  if (len == 1) sum += *p;                        // Adds the lone trailing byte if odd
  sum = (sum >> 16) + (sum & 0xFFFF); sum += (sum >> 16); // Folds the carry back in twice
  return (uint16_t)sum;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Open Sockets __________________________________________________________________________________
int open_raw_socket(int proto) {
  int s = socket(AF_INET, SOCK_RAW, proto);        // Kernel still builds the outer IP header
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
  a.sin_port = htons(port);                        // Real destination port, both modes use it
  return a;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Find Source IP ________________________________________________________________________________
// A connected UDP socket makes the kernel run its route lookup, getsockname reads the answer.
// Nothing goes on the wire.
struct in_addr find_source_ip(struct sockaddr_in *target) {
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0 || connect(s, (struct sockaddr *)target, sizeof(*target)) < 0) { perror("route lookup"); exit(1); }
  struct sockaddr_in local; socklen_t l = sizeof(local);
  getsockname(s, (struct sockaddr *)&local, &l);
  close(s);
  return local.sin_addr;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Send Classic Probe ____________________________________________________________________________
// One fresh UDP socket per probe, bound to the source port that tags it. Empty payload.
// Returns the send instant, or {0,0} if the probe never left.
struct timespec send_classic(Run *r, int ttl, int tag) {
  struct timespec t = {0, 0};
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) { perror("socket"); return t; }

  struct sockaddr_in local; memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(r->sport + tag);                     // The source port is the probe tag
  if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0) { // Port taken, this probe shows *
    perror("bind"); close(s); return t;
  }
  setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));       // Sets the TTL, the one thing bumped each hop

  clock_gettime(CLOCK_MONOTONIC, &t);                         // Grabs the send instant for RTT
  if (sendto(s, "", 0, 0, (struct sockaddr *)&r->target, sizeof(r->target)) < 0) {
    perror("sendto"); t.tv_sec = 0; t.tv_nsec = 0;            // Never left, report it as lost
  }
  close(s);                                                   // Reply comes back on the raw ICMP socket anyway
  return t;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Send Paris Probe ______________________________________________________________________________
// Same ports, same length, same checksum every time, so ECMP hashes every probe onto one path.
// The tag rides in the IP ID instead, which load balancers never hash on and which the Time
// Exceeded quote brings back whole (the full embedded IP header comes back).
// First try put the tag in the UDP checksum (solved through a 2 byte payload word, the Paris
// paper's way). Measured on WSL2: the Windows NAT rewrites that checksum on the way out but does
// not restore it inside the quoted header on the way back, every quote past hop 1 came back off by
// the same constant. The IP ID came back untouched through all three NATs, so the tag lives there.
// IP_HDRINCL means I write the IP header. The kernel still fills in tot_len and the IP checksum.
struct timespec send_paris(Run *r, int ttl, int tag) {
  uint8_t pkt[sizeof(struct iphdr) + sizeof(struct udphdr)]; memset(pkt, 0, sizeof(pkt));
  struct iphdr  *ip  = (struct iphdr *)pkt;
  struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct iphdr));

  ip->version  = 4; ip->ihl = 5;                  // 20 byte header, no options
  ip->ttl      = ttl;                             // The one thing bumped each hop
  ip->protocol = IPPROTO_UDP;
  ip->id       = htons((uint16_t)(tag + 1));      // Tag, never 0 (0 would let the kernel pick one)
  ip->saddr    = r->src.s_addr;
  ip->daddr    = r->target.sin_addr.s_addr;

  udp->source = htons(r->sport);                  // Fixed for the whole run
  udp->dest   = r->target.sin_port;               // Fixed too, the 5-tuple never moves
  udp->len    = htons(sizeof(struct udphdr));     // Empty payload, fixed length

  uint8_t sum[sizeof(struct pseudo_hdr) + sizeof(struct udphdr)]; memset(sum, 0, sizeof(sum));
  struct pseudo_hdr *ph = (struct pseudo_hdr *)sum;   // UDP checksum is over pseudo-header + UDP
  ph->src = ip->saddr; ph->dst = ip->daddr; ph->proto = IPPROTO_UDP; ph->len = udp->len;
  memcpy(sum + sizeof(struct pseudo_hdr), udp, sizeof(struct udphdr));
  uint16_t c = (uint16_t)~ones_sum(sum, sizeof(sum));
  udp->check = c ? c : 0xFFFF;                    // A computed 0 goes out as all ones, 0 means "none"
  struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
  if (sendto(r->rsock, pkt, sizeof(pkt), 0, (struct sockaddr *)&r->target, sizeof(r->target)) < 0) {
    perror("sendto"); t.tv_sec = 0; t.tv_nsec = 0;
  }
  return t;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Parse ICMP ____________________________________________________________________________________
// Time Exceeded or Dest Unreachable quoting my datagram. Returns 1 and fills c if it is mine.
int parse_icmp(char *buf, int n, Run *r, int tag, Reply *c) {
  if (n < (int)sizeof(struct iphdr) + 8) return 0;
  struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;       // Steps over the outer IP
  if (n < iplen + 8) return 0;
  struct icmphdr *icmp = (struct icmphdr *)(buf + iplen);
  if (icmp->type != ICMP_TIME_EXCEEDED && icmp->type != ICMP_DEST_UNREACH) return 0; // Unrelated ICMP

  int off = iplen + 8;                                                     // Skips the 8 byte ICMP header
  if (n < off + (int)sizeof(struct iphdr)) return 0;
  struct iphdr *iip = (struct iphdr *)(buf + off); int iiplen = iip->ihl * 4; // Embedded original IP
  if (iip->protocol != IPPROTO_UDP || iip->daddr != r->target.sin_addr.s_addr) return 0; // Not my flow
  if (n < off + iiplen + (int)sizeof(struct udphdr)) return 0;            // UDP header is exactly the 8 quoted bytes
  struct udphdr *iudp = (struct udphdr *)(buf + off + iiplen);
  if (iudp->dest != r->target.sin_port) return 0;                         // Some other destination port

  if (r->paris) {
    if (ntohs(iudp->source) != r->sport) return 0;                        // Not my fixed port
    if (ntohs(iip->id) != tag + 1) return 0;                              // The quoted IP ID carries the tag
  } else {
    if (ntohs(iudp->source) != r->sport + tag) return 0;                  // Source port carries the tag
  }

  if (icmp->type == ICMP_DEST_UNREACH) {                                   // Trace ends either way
    c->reached = 1;
    c->flag = (icmp->code == ICMP_PORT_UNREACH) ? 'C' : 'U';              // Port closed vs filtered somewhere
  }
  return 1;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Wait Reply ____________________________________________________________________________________
// Listens until the reply for this tag comes back or the deadline passes.
Reply wait_reply(int sock, Run *r, int tag, struct timespec t0) {
  Reply c = { .ip = "", .rtt = -1.0, .reached = 0, .flag = 0 }; // Defaults to a timed-out probe
  if (t0.tv_sec == 0 && t0.tv_nsec == 0) return c;               // Probe never left, nothing to wait for
  double deadline = (t0.tv_sec + TIMEOUT_SEC) * 1000.0 + t0.tv_nsec / 1000000.0; // Pins the deadline once
  char buf[1024]; struct sockaddr_in from; socklen_t klen;

  while (1) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    double left = deadline - (now.tv_sec * 1000.0 + now.tv_nsec / 1000000.0); // Time left this pass
    if (left <= 0) break;                                       // Out of time, returns the default

    struct timeval tv; tv.tv_sec = (time_t)(left / 1000.0);
    tv.tv_usec = (suseconds_t)((left - tv.tv_sec * 1000.0) * 1000.0);
    fd_set rf; FD_ZERO(&rf); FD_SET(sock, &rf);
    if (select(sock + 1, &rf, NULL, NULL, &tv) <= 0) continue;   // Timeout or signal, loop rechecks the clock

    klen = sizeof(from);
    int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &klen);
    if (n <= 0 || !parse_icmp(buf, n, r, tag, &c)) continue;    // Not mine, keep waiting

    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    c.rtt = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1000000.0; // Measures RTT from send
    inet_ntop(AF_INET, &from.sin_addr, c.ip, sizeof(c.ip));   // Records the responder address
    break;
  }
  return c;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Track Hop _____________________________________________________________________________________
// Fires PROBES datagrams at one ttl, folds their answers into a single Hop.
Hop track_hop(int isock, Run *r, int ttl) {
  Hop h; memset(&h, 0, sizeof(h));
  for (int p = 0; p < PROBES; p++) h.rtt[p] = -1.0; // Marks every probe as timed out until proven otherwise

  for (int p = 0; p < PROBES; p++) {
    int tag = ttl * PROBES + p;                     // Unique per probe, same invariant as the ICMP seq
    struct timespec t0 = r->paris ? send_paris(r, ttl, tag) : send_classic(r, ttl, tag);
    Reply c = wait_reply(isock, r, tag, t0);

    h.rtt[p] = c.rtt;
    strcpy(h.ips[p], c.ip);                         // Keeps every responder, not just the last
    if (c.rtt >= 0) strcpy(h.ip, c.ip);
    if (c.reached)  h.reached = 1;
    if (c.flag)     h.flag = c.flag;                // Any verdict beats a plain hop
  }
  return h;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Print Hop _____________________________________________________________________________________
// Returns how many different routers answered this hop.
int print_hop(int ttl, Hop *h) {
  if (h->ip[0] == 0) { printf("%2d  * * *\n", ttl); return 0; } // No probe answered at all, dead or filtered
  printf("%2d  %-15s", ttl, h->ip);
  for (int p = 0; p < PROBES; p++)
    (h->rtt[p] < 0) ? printf("   *    ") : printf("  %.2f ms", h->rtt[p]);
  if      (h->flag == 'C') printf("  [closed]");  // Port Unreachable, the target itself said no
  else if (h->flag == 'U') printf("  !U");        // Some other unreachable, filtered on the way

  int distinct = 1;                               // Lists responders other than the one shown
  for (int p = 0; p < PROBES; p++) {
    if (!h->ips[p][0] || strcmp(h->ips[p], h->ip) == 0) continue;
    int seen = 0;
    for (int q = 0; q < p; q++) if (strcmp(h->ips[q], h->ips[p]) == 0) seen = 1;
    if (!seen) { printf("  +%s", h->ips[p]); distinct++; }
  }
  printf("\n");
  return distinct;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Logic _________________________________________________________________________________________
int main(int argc, char *argv[]) {
  int a = 1, paris = 0;
  if (argc > 1 && strcmp(argv[1], "-p") == 0) { paris = 1; a++; }  // -p picks Paris mode
  const char *target_ip = (argc > a) ? argv[a] : "8.8.8.8";        // Defaults to Google DNS if no arg given
  int port = (argc > a + 1) ? atoi(argv[a + 1]) : 33434;          // Classic traceroute port, nothing listens there

  Run r; memset(&r, 0, sizeof(r));
  r.paris  = paris;
  r.target = resolve_target(target_ip, port);              // Validates args before hitting the root wall
  r.rsock  = -1;
  int isock = open_raw_socket(IPPROTO_ICMP);               // Hears Time Exceeded and Unreachable
  if (paris) {
    r.src   = find_source_ip(&r.target);
    r.rsock = open_raw_socket(IPPROTO_UDP);                // Sends my own IP + UDP headers
    int on = 1;
    if (setsockopt(r.rsock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) { perror("IP_HDRINCL"); exit(1); }
    r.sport = 40000 + (getpid() % 20000);                  // One fixed port for the whole run
  } else {
    r.sport = 40000 + (getpid() % 200) * 100;              // Per-run block of 100 ports, room for 30 x 3 probes
  }

  printf("UDP traceroute (%s) to %s:%d, source port %s%u, %d hops max\n\n",
         paris ? "Paris" : "classic", target_ip, port, paris ? "" : "from ",
         paris ? r.sport : r.sport + PROBES, MAX_HOPS);

  int split = 0;
  for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
    Hop h = track_hop(isock, &r, ttl);
    if (print_hop(ttl, &h) > 1) split++;                   // Counts hops where probes met different routers
    if (h.reached) break;                                  // Stops on any Destination Unreachable
  }
  printf("\nhops with more than one responder: %d\n", split);
  close(isock);
  if (r.rsock >= 0) close(r.rsock);
  return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////
