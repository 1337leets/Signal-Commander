// Signal Commander // udptrace.c _________________________________________________________________
// UDP traceroute. The kernel builds and sends each datagram, I only pick its TTL and source port.
// Routers answer with ICMP Time Exceeded, the target with ICMP Port Unreachable. Every reply is
// parsed by hand off a raw ICMP socket. Standalone testbed before the engine goes into the TUI.
// Build:  gcc udptrace.c -o udptrace
// Run:    sudo ./udptrace 8.8.8.8 33434   (the raw ICMP listener needs root or CAP_NET_RAW)
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

// One probe's answer. Filled by cevap_bekle.
typedef struct {
  char   ip[INET_ADDRSTRLEN]; // Who answered, empty on timeout
  double rtt;                 // Round trip in ms, -1 means no reply
  int    reached;             // 1 if the trace should stop here
  char   flag;                // 'C' port unreachable, 'U' other unreachable, 0 plain router hop
} Cevap;

// One hop, PROBES probes folded together. Filled by hop_izle, printed by hop_bas.
typedef struct {
  char   ip[INET_ADDRSTRLEN]; // Responder for this hop, empty if none answered
  double rtt[PROBES];         // One RTT per probe, -1 for the ones that timed out
  int    reached;             // 1 if any probe ended the trace
  char   flag;                // Strongest verdict any probe got
} Hop;

// Open Socket ___________________________________________________________________________________
int icmp_soket_ac(void) {
  int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // Listener only, the probes go out on UDP sockets
  if (s < 0) { perror("socket (need root or CAP_NET_RAW)"); exit(1); } // Dies early if unprivileged
  return s;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Resolve Target ________________________________________________________________________________
struct sockaddr_in hedefi_coz(const char *ip, int port) {
  struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET;
  if (inet_pton(AF_INET, ip, &a.sin_addr) <= 0) {  // Parses the dotted quad, does no DNS
    fprintf(stderr, "Not a valid IPv4 address: %s\n", ip); exit(1);
  }
  if (port < 1 || port > 65535) { fprintf(stderr, "Port out of range: %d\n", port); exit(1); }
  a.sin_port = htons(port);                        // Real destination port this time, the kernel uses it
  return a;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Send Probe ____________________________________________________________________________________
// One fresh UDP socket per probe, bound to the source port that tags it. Empty payload.
// Returns the send instant, or {0,0} if the probe never left.
struct timespec probe_gonder(struct sockaddr_in *hedef, uint16_t sport, int ttl) {
  struct timespec t = {0, 0};
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) { perror("socket"); return t; }

  struct sockaddr_in yerel; memset(&yerel, 0, sizeof(yerel));
  yerel.sin_family = AF_INET; yerel.sin_addr.s_addr = htonl(INADDR_ANY);
  yerel.sin_port = htons(sport);                              // The source port is the probe tag
  if (bind(s, (struct sockaddr *)&yerel, sizeof(yerel)) < 0) { // Port taken, this probe shows *
    perror("bind"); close(s); return t;
  }
  setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));       // Sets the TTL, the one thing bumped each hop

  clock_gettime(CLOCK_MONOTONIC, &t);                         // Grabs the send instant for RTT
  if (sendto(s, "", 0, 0, (struct sockaddr *)hedef, sizeof(*hedef)) < 0) {
    perror("sendto"); t.tv_sec = 0; t.tv_nsec = 0;            // Never left, report it as lost
  }
  close(s);                                                   // Reply comes back on the raw ICMP socket anyway
  return t;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Parse ICMP ____________________________________________________________________________________
// Time Exceeded or Dest Unreachable quoting my datagram. Returns 1 and fills c if it is mine.
int icmp_coz(char *buf, int n, struct sockaddr_in *hedef, uint16_t sport, Cevap *c) {
  if (n < (int)sizeof(struct iphdr) + 8) return 0;
  struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;       // Steps over the outer IP
  if (n < iplen + 8) return 0;
  struct icmphdr *icmp = (struct icmphdr *)(buf + iplen);
  if (icmp->type != ICMP_TIME_EXCEEDED && icmp->type != ICMP_DEST_UNREACH) return 0; // Unrelated ICMP

  int off = iplen + 8;                                                     // Skips the 8 byte ICMP header
  if (n < off + (int)sizeof(struct iphdr)) return 0;
  struct iphdr *iip = (struct iphdr *)(buf + off); int iiplen = iip->ihl * 4; // Embedded original IP
  if (iip->protocol != IPPROTO_UDP || iip->daddr != hedef->sin_addr.s_addr) return 0; // Not my flow
  if (n < off + iiplen + (int)sizeof(struct udphdr)) return 0;            // UDP header is exactly the 8 quoted bytes
  struct udphdr *iudp = (struct udphdr *)(buf + off + iiplen);
  if (ntohs(iudp->source) != sport || iudp->dest != hedef->sin_port) return 0; // Someone else's probe

  if (icmp->type == ICMP_DEST_UNREACH) {                                   // Trace ends either way
    c->reached = 1;
    c->flag = (icmp->code == ICMP_PORT_UNREACH) ? 'C' : 'U';              // Port closed vs filtered somewhere
  }
  return 1;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Wait Reply ____________________________________________________________________________________
// Listens until the reply quoting sport comes back or the deadline passes.
Cevap cevap_bekle(int sock, struct sockaddr_in *hedef, uint16_t sport, struct timespec t0) {
  Cevap c = { .ip = "", .rtt = -1.0, .reached = 0, .flag = 0 }; // Defaults to a timed-out probe
  if (t0.tv_sec == 0 && t0.tv_nsec == 0) return c;               // Probe never left, nothing to wait for
  double deadline = (t0.tv_sec + TIMEOUT_SEC) * 1000.0 + t0.tv_nsec / 1000000.0; // Pins the deadline once
  char buf[1024]; struct sockaddr_in kaynak; socklen_t klen;

  while (1) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    double kalan = deadline - (now.tv_sec * 1000.0 + now.tv_nsec / 1000000.0); // Time left this pass
    if (kalan <= 0) break;                                       // Out of time, returns the default

    struct timeval tv; tv.tv_sec = (time_t)(kalan / 1000.0);
    tv.tv_usec = (suseconds_t)((kalan - tv.tv_sec * 1000.0) * 1000.0);
    fd_set r; FD_ZERO(&r); FD_SET(sock, &r);
    if (select(sock + 1, &r, NULL, NULL, &tv) <= 0) continue;    // Timeout or signal, loop rechecks the clock

    klen = sizeof(kaynak);
    int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&kaynak, &klen);
    if (n <= 0 || !icmp_coz(buf, n, hedef, sport, &c)) continue; // Not mine, keep waiting

    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    c.rtt = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1000000.0; // Measures RTT from send
    inet_ntop(AF_INET, &kaynak.sin_addr, c.ip, sizeof(c.ip));   // Records the responder address
    break;
  }
  return c;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Track Hop _____________________________________________________________________________________
// Fires PROBES datagrams at one ttl, folds their answers into a single Hop.
Hop hop_izle(int isock, struct sockaddr_in *hedef, uint16_t base, int ttl) {
  Hop h; memset(&h, 0, sizeof(h));
  for (int p = 0; p < PROBES; p++) h.rtt[p] = -1.0; // Marks every probe as timed out until proven otherwise

  for (int p = 0; p < PROBES; p++) {
    uint16_t sport = base + ttl * PROBES + p;       // Unique per probe, same invariant as the ICMP seq
    struct timespec t0 = probe_gonder(hedef, sport, ttl);
    Cevap c = cevap_bekle(isock, hedef, sport, t0);

    h.rtt[p] = c.rtt;
    if (c.rtt >= 0) strcpy(h.ip, c.ip);             // Keeps the responder from whichever probe answered
    if (c.reached)  h.reached = 1;
    if (c.flag)     h.flag = c.flag;                // Any verdict beats a plain hop
  }
  return h;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Print Hop _____________________________________________________________________________________
void hop_bas(int ttl, Hop *h) {
  if (h->ip[0] == 0) { printf("%2d  * * *\n", ttl); return; } // No probe answered at all, dead or filtered
  printf("%2d  %-15s", ttl, h->ip);
  for (int p = 0; p < PROBES; p++)
    (h->rtt[p] < 0) ? printf("   *    ") : printf("  %.2f ms", h->rtt[p]);
  if      (h->flag == 'C') printf("  [closed]");  // Port Unreachable, the target itself said no
  else if (h->flag == 'U') printf("  !U");        // Some other unreachable, filtered on the way
  printf("\n");
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Logic _________________________________________________________________________________________
int main(int argc, char *argv[]) {
  const char *hedef_ip = (argc > 1) ? argv[1] : "8.8.8.8"; // Defaults to Google DNS if no arg given
  int port = (argc > 2) ? atoi(argv[2]) : 33434;           // Classic traceroute port, nothing listens there

  struct sockaddr_in hedef = hedefi_coz(hedef_ip, port);  // Validates args before hitting the root wall
  int isock = icmp_soket_ac();

  uint16_t base = 40000 + (getpid() % 200) * 100;          // Per-run block of 100 ports, room for 30 x 3 probes

  printf("UDP traceroute to %s:%d, source ports from %u, %d hops max\n\n",
         hedef_ip, port, base + PROBES, MAX_HOPS);

  for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
    Hop h = hop_izle(isock, &hedef, base, ttl);
    hop_bas(ttl, &h);
    if (h.reached) break;                                  // Stops on any Destination Unreachable
  }
  close(isock);
  return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////
