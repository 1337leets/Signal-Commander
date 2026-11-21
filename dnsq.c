// Signal Commander // dnsq.c ____________________________________________________________________
// Hand-built DNS client. Builds the query byte by byte, sends it over plain UDP to the resolver in
// /etc/resolv.conf, walks the answer section including compressed names. A and PTR only, the two
// the TUI needs. Standalone testbed before the TUI gets non-blocking lookups.
// Build:  gcc dnsq.c -o dnsq
// Run:    ./dnsq google.com            forward lookup, A records
//         ./dnsq -x 8.8.8.8            reverse lookup, PTR via in-addr.arpa
//         ./dnsq google.com 1.1.1.1    same, but asks that server instead of resolv.conf
// No root needed, it is an ordinary UDP socket.
////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define DNS_PORT    53
#define TIMEOUT_MS  2000
#define T_A         1
#define T_CNAME     5
#define T_PTR       12
#define MAX_JUMPS   16          // Compression pointers followed per name before calling it a loop

// Find Resolver _________________________________________________________________________________
// First IPv4 nameserver line in resolv.conf wins, IPv6 ones are skipped.
int find_resolver(struct in_addr *out) {
  FILE *f = fopen("/etc/resolv.conf", "r");
  if (!f) return 0;
  char line[256], ip[64]; int ok = 0;
  while (fgets(line, sizeof(line), f))
    if (sscanf(line, " nameserver %63s", ip) == 1 && inet_pton(AF_INET, ip, out) == 1) { ok = 1; break; }
  fclose(f);
  return ok;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Random ID _____________________________________________________________________________________
// DNS has no handshake, the 16-bit ID and the source port are all that stop a spoofed answer.
// A guessable ID is how cache poisoning works, so this one comes from the kernel RNG.
uint16_t random_id(void) {
  uint16_t id = 0; int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0 || read(fd, &id, sizeof(id)) != sizeof(id))
    id = (uint16_t)(getpid() ^ time(NULL));        // Falls back to something, still better than 0
  if (fd >= 0) close(fd);
  return id;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Encode Name ___________________________________________________________________________________
// "www.google.com" becomes 3www6google3com0. Returns bytes written, -1 if a label or the name is
// too long or empty. A trailing dot is fine.
int encode_name(const char *name, unsigned char *out, int cap) {
  int n = 0; const char *p = name;
  while (*p) {
    const char *dot = strchr(p, '.');
    int len = dot ? (int)(dot - p) : (int)strlen(p);
    if (len == 0 || len > 63) return -1;           // Double dot, or over the 6-bit length field
    if (n + 1 + len + 1 > cap || n + 1 + len + 1 > 255) return -1; // Wire names cap at 255 bytes
    out[n++] = (unsigned char)len;                 // Length byte, then the raw label
    memcpy(out + n, p, len); n += len;
    p += len; if (*p == '.') p++;
  }
  if (n + 1 > cap) return -1;
  out[n++] = 0;                                    // Zero length label = root, ends the name
  return n;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Build Query ___________________________________________________________________________________
// 12 byte header written byte by byte, no struct, so endianness and padding never come up.
int build_query(unsigned char *buf, int cap, uint16_t id, const char *name, uint16_t qtype) {
  if (cap < 12 + 1 + 4) return -1;
  memset(buf, 0, 12);
  buf[0] = id >> 8; buf[1] = id & 0xFF;            // ID, the answer must echo it
  buf[2] = 0x01;                                   // RD=1, asks the resolver to do the recursion
  buf[5] = 1;                                      // QDCOUNT = 1, the rest stay 0
  int n = encode_name(name, buf + 12, cap - 12 - 4);
  if (n < 0) return -1;
  int off = 12 + n;
  buf[off++] = qtype >> 8; buf[off++] = qtype & 0xFF; // QTYPE
  buf[off++] = 0;          buf[off++] = 1;            // QCLASS = IN
  return off;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Reverse Name __________________________________________________________________________________
// 8.8.4.4 becomes 4.4.8.8.in-addr.arpa, octets flipped so the tree is walked from the network down.
void ptr_name(struct in_addr a, char *out, int cap) {
  unsigned char *b = (unsigned char *)&a.s_addr;   // Network order, b[0] is the first octet
  snprintf(out, cap, "%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1], b[0]);
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Decode Name ___________________________________________________________________________________
// Reads a possibly compressed name at off into dotted text. Returns the offset just past the name
// where it sits in the record (not where a pointer jumped to), -1 on anything malformed.
int decode_name(const unsigned char *msg, int len, int off, char *out, int cap) {
  int pos = off, end = -1, w = 0, jumps = 0;
  if (cap < 1) return -1;
  while (1) {
    if (pos >= len) return -1;                     // Runs off the end of the packet
    unsigned char c = msg[pos];
    if (c == 0) { pos++; break; }                  // Root label ends the name
    if ((c & 0xC0) == 0xC0) {                      // Top bits 11, a 14-bit pointer into the message
      if (pos + 1 >= len) return -1;
      int target = ((c & 0x3F) << 8) | msg[pos + 1];
      if (end < 0) end = pos + 2;                  // The name in place ends after the first pointer
      if (target >= pos || ++jumps > MAX_JUMPS) return -1; // Backward only, and capped, or it can loop
      pos = target; continue;
    }
    if (c & 0xC0) return -1;                       // Prefixes 01 and 10 are reserved
    if (pos + 1 + c > len) return -1;              // Label claims more bytes than the packet has
    if (w + (w ? 1 : 0) + c + 1 > cap) return -1;  // Out buffer too small
    if (w) out[w++] = '.';
    for (int i = 0; i < c; i++) {                  // Copies the label, masks anything unprintable
      unsigned char ch = msg[pos + 1 + i];
      out[w++] = (ch > 32 && ch < 127) ? (char)ch : '?'; // A PTR could carry escape codes, never print those raw
    }
    pos += 1 + c;
  }
  out[w] = '\0';
  return (end >= 0) ? end : pos;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Parse Answer __________________________________________________________________________________
// Returns 1 if this was the answer to my query (and prints it), 0 if not mine, -1 if mine but broken.
int parse_answer(const unsigned char *msg, int len, uint16_t id) {
  static const char *RCODE[] = { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED" };
  if (len < 12) return 0;
  if (((msg[0] << 8) | msg[1]) != id) return 0;    // Some other query's answer
  int flags = (msg[2] << 8) | msg[3];
  if (!(flags & 0x8000)) return 0;                 // QR=0, a query not a response
  int rcode = flags & 0x0F, qd = (msg[4] << 8) | msg[5], an = (msg[6] << 8) | msg[7];

  printf(";; rcode %s  answers %d%s\n", rcode < 6 ? RCODE[rcode] : "?", an,
         (flags & 0x0200) ? "  (truncated, TC set)" : "");

  int off = 12; char name[256];
  for (int i = 0; i < qd; i++) {                   // Skips the echoed question section
    off = decode_name(msg, len, off, name, sizeof(name));
    if (off < 0 || off + 4 > len) return -1;
    off += 4;                                      // QTYPE + QCLASS
  }
  for (int i = 0; i < an; i++) {
    off = decode_name(msg, len, off, name, sizeof(name));
    if (off < 0 || off + 10 > len) return -1;      // Fixed part: type, class, ttl, rdlength
    int type  = (msg[off] << 8) | msg[off + 1];
    uint32_t ttl = ((uint32_t)msg[off + 4] << 24) | (msg[off + 5] << 16) | (msg[off + 6] << 8) | msg[off + 7];
    int rdlen = (msg[off + 8] << 8) | msg[off + 9];
    off += 10;
    if (off + rdlen > len) return -1;              // RDATA claims more than is there

    char val[256];
    if (type == T_A && rdlen == 4) {
      inet_ntop(AF_INET, msg + off, val, sizeof(val));
      printf("%-32s A      %-16s ttl %u\n", name, val, ttl);
    } else if (type == T_PTR || type == T_CNAME) {  // Both carry a name, maybe compressed
      if (decode_name(msg, len, off, val, sizeof(val)) < 0) return -1;
      printf("%-32s %-6s %-16s ttl %u\n", name, type == T_PTR ? "PTR" : "CNAME", val, ttl);
    } else {
      printf("%-32s type %d, %d bytes skipped\n", name, type, rdlen);
    }
    off += rdlen;
  }
  return 1;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Logic _________________________________________________________________________________________
int main(int argc, char *argv[]) {
  if (argc < 2) { fprintf(stderr, "usage: %s <name> [server] | %s -x <ipv4> [server]\n", argv[0], argv[0]); return 1; }

  int reverse = (strcmp(argv[1], "-x") == 0);
  const char *arg = reverse ? (argc > 2 ? argv[2] : NULL) : argv[1];
  const char *srv = reverse ? (argc > 3 ? argv[3] : NULL) : (argc > 2 ? argv[2] : NULL);
  if (!arg) { fprintf(stderr, "-x needs an IPv4 address\n"); return 1; }

  char qname[256]; uint16_t qtype;
  if (reverse) {
    struct in_addr a;
    if (inet_pton(AF_INET, arg, &a) != 1) { fprintf(stderr, "Not a valid IPv4 address: %s\n", arg); return 1; }
    ptr_name(a, qname, sizeof(qname)); qtype = T_PTR;
  } else {
    snprintf(qname, sizeof(qname), "%s", arg); qtype = T_A;
  }

  struct sockaddr_in ns; memset(&ns, 0, sizeof(ns));
  ns.sin_family = AF_INET; ns.sin_port = htons(DNS_PORT);
  if (srv ? inet_pton(AF_INET, srv, &ns.sin_addr) != 1 : !find_resolver(&ns.sin_addr)) {
    fprintf(stderr, "No usable nameserver\n"); return 1;
  }

  unsigned char q[512]; uint16_t id = random_id();
  int qlen = build_query(q, sizeof(q), id, qname, qtype);
  if (qlen < 0) { fprintf(stderr, "Bad name: %s\n", qname); return 1; }

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0 || connect(s, (struct sockaddr *)&ns, sizeof(ns)) < 0) { perror("socket"); return 1; } // Connected, so only the server's datagrams get in

  char nsbuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ns.sin_addr, nsbuf, sizeof(nsbuf));
  printf(";; %s %s  via %s  id 0x%04x  %d byte query\n", qtype == T_PTR ? "PTR" : "A", qname, nsbuf, id, qlen);

  struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
  if (send(s, q, qlen, 0) != qlen) { perror("send"); return 1; }

  double deadline = t0.tv_sec * 1000.0 + t0.tv_nsec / 1e6 + TIMEOUT_MS;
  unsigned char r[1500];
  while (1) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    double left = deadline - (now.tv_sec * 1000.0 + now.tv_nsec / 1e6);
    if (left <= 0) { printf(";; timeout after %d ms\n", TIMEOUT_MS); return 2; }
    struct timeval tv = { (time_t)(left / 1000), (suseconds_t)((left - (int)(left / 1000) * 1000) * 1000) };
    fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
    if (select(s + 1, &rf, NULL, NULL, &tv) <= 0) continue;

    int n = recv(s, r, sizeof(r), 0);
    if (n <= 0) continue;                          // ICMP port unreachable from a dead server lands here too
    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    int rc = parse_answer(r, n, id);
    if (rc == 0) continue;                         // Stale or foreign, keep waiting
    if (rc < 0) { printf(";; malformed answer, %d bytes\n", n); return 3; }
    printf(";; %d byte answer in %.2f ms\n", n,
           (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6);
    break;
  }
  close(s);
  return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////
