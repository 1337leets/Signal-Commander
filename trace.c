// Signal Commander // trace.c ____________________________________________________________________
// ICMP traceroute. Sends echo probes with a climbing TTL, prints each hop it flushes out.
// 3 probes per hop now, each with its own seq so stale replies cant cross-attribute.
// Build:  gcc trace.c -o trace
// Run:    sudo ./trace 8.8.8.8      (raw socket needs root or CAP_NET_RAW)
////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define MAX_HOPS    30
#define TIMEOUT_SEC 2
#define PROBES      3

// One probe's answer. Filled by wait_reply.
typedef struct {
  char   ip[INET_ADDRSTRLEN]; // Who answered, empty on timeout
  double rtt;                 // Round trip in ms, -1 means no reply
  int    reached;             // 1 if this was the destination itself
} Reply;

// One hop, PROBES probes folded together. Filled by track_hop, printed by print_hop.
typedef struct {
  char   ip[INET_ADDRSTRLEN]; // Responder for this hop, empty if none answered
  double rtt[PROBES];         // One RTT per probe, -1 for the ones that timed out
  int    reached;             // 1 if any probe hit the target
} Hop;

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

// Open Socket ___________________________________________________________________________________
int open_icmp_socket(void) {
  int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // Raw ICMP, kernel still builds the outer IP hdr
  if (s < 0) { perror("socket (need root or CAP_NET_RAW)"); exit(1); } // Dies early if unprivileged
  return s;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Resolve Target ________________________________________________________________________________
struct sockaddr_in resolve_target(const char *ip) {
  struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET;
  if (inet_pton(AF_INET, ip, &a.sin_addr) <= 0) {  // Parses the dotted quad, does no DNS
    fprintf(stderr, "Not a valid IPv4 address: %s\n", ip); exit(1);
  }
  return a;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Send Probe ____________________________________________________________________________________
// ttl sets how far the packet gets, seq is the tag I match the reply against.
struct timespec send_probe(int sock, struct sockaddr_in *target, int ttl, int seq) {
  setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)); // Sets the TTL, the one thing bumped each hop

  char packet[64]; memset(packet, 0, sizeof(packet)); // Declares & zeroes the packet buffer
  struct icmphdr *icmp = (struct icmphdr *)packet;    // Overlays the icmp header onto the buffer start

  icmp->type = ICMP_ECHO; icmp->code = 0;             // Echo request, type 8 code 0
  icmp->un.echo.id       = htons(getpid() & 0xFFFF);  // id = pid, fixed the whole run, my signature
  icmp->un.echo.sequence = htons(seq);                // seq is unique per probe, matches the right reply

  memset(packet + sizeof(struct icmphdr), 'A', 32);   // Fills 32 bytes of junk payload
  icmp->checksum = checksum(packet, sizeof(struct icmphdr) + 32); // Checksums with the field at 0, else dropped

  struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); // Grabs the send instant for RTT
  if (sendto(sock, packet, sizeof(struct icmphdr) + 32, 0, (struct sockaddr *)target, sizeof(*target)) <= 0)
    perror("sendto"); // On fail this probe just shows *, loop carries on
  return t; // Returns the send instant
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Wait Reply ____________________________________________________________________________________
// Listens until the reply carrying want_seq comes back or the deadline passes.
Reply wait_reply(int sock, int want_seq, struct timespec t0) {
  Reply c = { .ip = "", .rtt = -1.0, .reached = 0 }; // Defaults to a timed-out probe
  uint16_t my_id = getpid() & 0xFFFF;

  double deadline = (t0.tv_sec + TIMEOUT_SEC) * 1000.0 + t0.tv_nsec / 1000000.0; // Pins the deadline once

  char buf[1024]; struct sockaddr_in from; socklen_t klen = sizeof(from);

  while (1) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    double left = deadline - (now.tv_sec * 1000.0 + now.tv_nsec / 1000000.0); // Recomputes the time left each pass
    if (left <= 0) break; // Out of time, returns the timeout default

    struct timeval tv; tv.tv_sec = (time_t)(left / 1000.0);
    tv.tv_usec = (suseconds_t)((left - tv.tv_sec * 1000.0) * 1000.0);
    if (tv.tv_sec == 0 && tv.tv_usec == 0) tv.tv_usec = 1; // Floors to 1us, else {0,0} blocks forever
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); // Caps this recvfrom at whatever is left

    int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &klen);
    if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; continue; } // Real timeout vs stray wakeup

    if (n < (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr)) continue; // Too short to hold both headers
    struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4; // Real IP header length from IHL
    if (n < iplen + (int)sizeof(struct icmphdr)) continue; // Too short past the real IP header
    struct icmphdr *icmp = (struct icmphdr *)(buf + iplen); // Steps over the outer IP into ICMP

    if (icmp->type == ICMP_ECHOREPLY) {                // Case A: this is the target answering
      if (ntohs(icmp->un.echo.id) != my_id || ntohs(icmp->un.echo.sequence) != want_seq) continue; // Not mine
      c.reached = 1;
    }
    else if (icmp->type == ICMP_TIME_EXCEEDED) {       // Case B: a router burned the TTL to 0
      int off = iplen + 8; // Skips outer IP + 8 byte time exceeded header to my embedded original
      if (n < off + (int)sizeof(struct iphdr)) continue;
      struct iphdr *iip = (struct iphdr *)(buf + off); int iiplen = iip->ihl * 4; // Embedded IP header length
      if (n < off + iiplen + (int)sizeof(struct icmphdr)) continue;
      struct icmphdr *iicmp = (struct icmphdr *)(buf + off + iiplen); // My original echo header, buried inside
      if (ntohs(iicmp->un.echo.id) != my_id || ntohs(iicmp->un.echo.sequence) != want_seq) continue; // Not mine
    }
    else continue; // Some unrelated ICMP, ignore it

    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    c.rtt = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1000000.0; // Measures RTT from send
    inet_ntop(AF_INET, &from.sin_addr, c.ip, sizeof(c.ip)); // Records the responder address
    break;
  }
  return c;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Track Hop _____________________________________________________________________________________
// Fires PROBES probes at one ttl, folds their answers into a single Hop.
Hop track_hop(int sock, struct sockaddr_in *target, int ttl) {
  Hop h; memset(&h, 0, sizeof(h)); // Zeroes the hop, ip empty and reached 0
  for (int p = 0; p < PROBES; p++) h.rtt[p] = -1.0; // Marks every probe as timed out until proven otherwise

  for (int p = 0; p < PROBES; p++) {
    int seq = ttl * PROBES + p; // Unique per probe so a late reply cant land on the wrong slot
    struct timespec t0 = send_probe(sock, target, ttl, seq);
    Reply c = wait_reply(sock, seq, t0);

    h.rtt[p] = c.rtt;                             // Stores this probe's RTT, stays -1 if it timed out
    if (c.rtt >= 0) strcpy(h.ip, c.ip);           // Keeps the responder from whichever probe answered
    if (c.reached) h.reached = 1;                 // Flags the hop as target if any probe reached it
  }
  return h;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Print Hop _____________________________________________________________________________________
void print_hop(int ttl, Hop *h) {
  if (h->ip[0] == 0) { printf("%2d  * * *\n", ttl); return; } // No probe answered at all, dead or filtered
  printf("%2d  %-15s", ttl, h->ip);                           // Hop number and responder
  for (int p = 0; p < PROBES; p++)                            // Then one column per probe
    (h->rtt[p] < 0) ? printf("   *    ") : printf("  %.2f ms", h->rtt[p]);
  printf("\n");
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Logic _________________________________________________________________________________________
int main(int argc, char *argv[]) {
  const char *target_ip = (argc > 1) ? argv[1] : "8.8.8.8"; // Defaults to Google DNS if no arg given

  struct sockaddr_in target = resolve_target(target_ip); // Validates the arg before hitting the root wall
  int sock = open_icmp_socket();

  printf("Traceroute to %s, %d hops max\n\n", target_ip, MAX_HOPS);

  for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
    Hop h = track_hop(sock, &target, ttl);       // Fires 3 probes at this TTL, folds the answers
    print_hop(ttl, &h);                          // Prints the row
    if (h.reached) { printf("\nReached the target\n"); break; } // Stops once the target itself answers
  }
  close(sock);
  return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////
