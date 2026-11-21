// Signal Commander // signal_commander.c ______________________________________________________
// ncurses TUI for ICMP, TCP and UDP traceroute and ping. Every probe is built by hand on raw
// sockets (UDP lets the kernel build the datagram), every reply is parsed byte by byte, and DNS is
// a hand-built client too. Nothing beyond libc and ncurses.
// Build:  make            (or gcc signal_commander.c -o signal_commander -lncurses)
// Run:    sudo ./signal_commander   (raw sockets need root or CAP_NET_RAW, see make setcap)
////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <arpa/inet.h>        // INET_ADDRSTRLEN
#include <unistd.h>           // getpid, close
#include <time.h>             // clock_gettime, CLOCK_MONOTONIC
#include <sys/time.h>         // struct timeval
#include <sys/socket.h>
#include <sys/select.h>       // select, fd_set
#include <netinet/ip.h>       // struct iphdr
#include <netinet/ip_icmp.h>  // struct icmphdr, ICMP_*
#include <netinet/tcp.h>      // struct tcphdr
#include <netinet/udp.h>      // struct udphdr
#include <stdint.h>           // uint16_t, uint32_t
#include <fcntl.h>            // open, for /dev/urandom

#define MAX_HOPS    30
#define MAX_PROBES  5            // Sizes the HopResult array, Settings stays under it

#define PING_TTL          64     // Ping keeps a big fixed TTL so it reaches the target
#define PING_RING         16     // Last ping rows kept on screen
#define PING_INTERVAL_MS  1000   // Gap between pings, doubles as the reply window

// Data Model __________________________________________________________________________________
typedef struct {
    char ip[64];
    int  port;
    int  ttl;
    char proto[8];
} Config;

static Config current_cfg = {"127.0.0.1", 80, 64, "ICMP"};

// Runtime knobs the Settings screen edits. These used to be #defines.
typedef struct {
    int probes;                  // Probes per hop, 1..MAX_PROBES
    int timeout_ms;              // Reply window per probe in Track
    int dns;                     // 1 = hostname targets + hop names (PTR)
    int window;                  // Probes in flight at once, 1 = one at a time (old behavior)
} Settings;

#define MAX_WINDOW 32

static Settings settings = { 3, 2000, 0, 16 };   // 16 = Linux traceroute's default

// One hop, settings.probes results folded into one row.
typedef struct {
    int    hop;
    char   ip[INET_ADDRSTRLEN];  // Empty means no probe answered, row shows * * *
    double rtt[MAX_PROBES];      // -1 = that probe timed out
    int    reached;              // 1 = the target itself answered
    char   flag;                 // 'O' open, 'C' closed, 'N' 'H' 'X' 'P' 'F' 'U' unreachable kinds. 0 = plain hop
    char   name[64];             // PTR name, empty when DNS is off or nothing came back
} HopResult;

// One ping result. ok=0 means timeout, or unreachable when flag is one of the unreachable kinds.
typedef struct {
    int    seq;
    double rtt;
    int    ok;
    char   flag;                 // Same letters as HopResult
} PingRow;
////////////////////////////////////////////////////////////////////////////////////////////////

// Field Metadata ______________________________________________________________________________
// FLD_IP    : "x.x.x.x", every octet 0-255
// FLD_INT   : integer, min_val..max_val
// FLD_STR   : free printable ASCII
// FLD_CYCLE : steps through fixed options with LEFT/RIGHT
// FLD_HOST  : IPv4 or hostname (letters, digits, dots, hyphens)
typedef enum { FLD_STR, FLD_INT, FLD_IP, FLD_CYCLE, FLD_HOST } FldType;

typedef struct {
    const char  *label;
    FldType      type;
    int          maxlen;        // Input buffer size for text fields
    int          min_val;       // FLD_INT lower bound
    int          max_val;       // FLD_INT upper bound
    const char **options;       // FLD_CYCLE choices
    int          opt_count;
} FldMeta;

static const char *PROTO_OPTS[] = { "ICMP", "TCP", "UDP" };
static const char *ONOFF_OPTS[] = { "OFF", "ON" };

#define CFG_FIELDS 4

static const FldMeta FIELDS[CFG_FIELDS] = {
    { "Target Host", FLD_HOST,  31, 0,     0, NULL,       0 },   // 31 = what fits in the value cell
    { "Port",        FLD_INT,    5, 0, 65535, NULL,       0 },
    { "TTL",         FLD_INT,    3, 0,   255, NULL,       0 },
    { "Protocol",    FLD_CYCLE,  0, 0,     0, PROTO_OPTS, 3 },
};

#define SET_FIELDS 4

static const FldMeta SET_META[SET_FIELDS] = {
    { "Probes per hop",   FLD_INT,   1,   1, MAX_PROBES,  NULL,       0 },
    { "Hop timeout (ms)", FLD_INT,   5, 100,      10000,  NULL,       0 },
    { "Parallel probes",  FLD_INT,   2,   1, MAX_WINDOW,  NULL,       0 },
    { "Resolve DNS",      FLD_CYCLE, 0,   0,          0,  ONOFF_OPTS, 2 },
};

// Recipe for one form: title, field table and the data to string converters.
// Configuration and Settings share the engine, a new form is just a new recipe.
typedef struct {
    const char    *title;
    const FldMeta *fields;
    int            count;
    void         (*to_str)(const void *d, int idx, char *out, int outlen);
    void         (*from_str)(void *d, int idx, const char *s);
} FormDef;

// Settings struct to and from strings
static void settings_to_str(const void *d, int idx, char *out, int outlen) {
    const Settings *a = d;
    switch (idx) {
        case 0: snprintf(out, outlen, "%d", a->probes);     break;
        case 1: snprintf(out, outlen, "%d", a->timeout_ms); break;
        case 2: snprintf(out, outlen, "%d", a->window);     break;
        case 3: snprintf(out, outlen, "%s", a->dns ? "ON" : "OFF"); break;
    }
}

static void str_to_settings(void *d, int idx, const char *s) {
    Settings *a = d;
    if (!s || s[0] == '\0') return;
    switch (idx) {
        case 0: a->probes     = atoi(s); break;
        case 1: a->timeout_ms = atoi(s); break;
        case 2: a->window     = atoi(s); break;
        case 3: a->dns        = (strcmp(s, "ON") == 0); break;
    }
}

// Config struct to and from strings
static void config_to_str(const void *d, int idx, char *out, int outlen) {
    const Config *c = d;
    switch (idx) {
        case 0: snprintf(out, outlen, "%s", c->ip);    break;
        case 1: snprintf(out, outlen, "%d", c->port);  break;
        case 2: snprintf(out, outlen, "%d", c->ttl);   break;
        case 3: snprintf(out, outlen, "%s", c->proto); break;
    }
}

static void str_to_config(void *d, int idx, const char *s) {
    Config *c = d;
    if (!s || s[0] == '\0') return;
    switch (idx) {
        case 0: snprintf(c->ip,    sizeof(c->ip),    "%s", s); break;
        case 1: c->port = atoi(s); break;
        case 2: c->ttl  = atoi(s); break;
        case 3: snprintf(c->proto, sizeof(c->proto), "%s", s); break;
    }
}

static const FormDef CFG_FORM = { "[ CONFIGURATION ]", FIELDS,   CFG_FIELDS,
                                  config_to_str,   str_to_config };
static const FormDef SET_FORM = { "[ SETTINGS ]",      SET_META, SET_FIELDS,
                                  settings_to_str, str_to_settings };
////////////////////////////////////////////////////////////////////////////////////////////////

// Layout ______________________________________________________________________________________
// Layout constants are mutable globals behind same-named macros. recompute_layout() refreshes
// them from the terminal size before every draw, so code using BOX_Y, BOX_X and friends stayed
// untouched but the box now re-centers on resize.
static int g_box_y = 2, g_box_x = 2;
static int g_box_w = 56, g_box_h = 10;
static int g_l_w   = 20;

#define BOX_Y       g_box_y
#define BOX_X       g_box_x
#define BOX_W       g_box_w
#define BOX_H       g_box_h
#define L_W         g_l_w

#define HEADER_ROW  (BOX_Y + 1)
#define FIRST_ROW   (BOX_Y + 3)
#define BTN_ROW     (BOX_Y + BOX_H - 2)
#define STATUS_ROW  (BOX_Y + BOX_H + 2)

#define L_X         (BOX_X + 2)
#define SEP_X       (BOX_X + L_W + 2)
#define R_X         (SEP_X + 2)
#define R_W         (BOX_W - L_W - 7)

// Color pairs
#define CP_NORMAL  1
#define CP_ERROR   2
#define CP_OK      3

// Centers the box on the terminal and clamps its width to 40..60 columns.
static void recompute_layout(int nfields) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    g_box_w = cols - 4;                    // Fits the terminal, within sane bounds
    if (g_box_w > 60) g_box_w = 60;
    if (g_box_w < 40) g_box_w = 40;

    g_box_h = nfields + 6;     // Top, header, divider, fields, divider, buttons, bottom

    g_box_x = (cols - g_box_w) / 2;        // Centers horizontally
    if (g_box_x < 1) g_box_x = 1;

    int needed = g_box_h + 4;              // Leaves room below for footer + status
    g_box_y = (rows - needed) / 2;         // Centers vertically
    if (g_box_y < 1) g_box_y = 1;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Box Drawing _________________________________________________________________________________
static void draw_hline(int y, int x, int w,
                       chtype left, chtype right,
                       int sep_col, chtype sep_ch) {
    mvaddch(y, x, left);
    for (int i = 1; i < w - 1; i++) {
        int col = x + i;
        if (col == sep_col) mvaddch(y, col, sep_ch);
        else                mvaddch(y, col, ACS_HLINE);
    }
    mvaddch(y, x + w - 1, right);
}

static void draw_box_frame(int nfields) {
    draw_hline(BOX_Y, BOX_X, BOX_W,
               ACS_ULCORNER, ACS_URCORNER, SEP_X, ACS_TTEE);

    for (int i = 1; i < BOX_H - 1; i++) {
        int row = BOX_Y + i;
        mvaddch(row, BOX_X,             ACS_VLINE);
        mvaddch(row, BOX_X + BOX_W - 1, ACS_VLINE);
        int is_header = (row == HEADER_ROW);
        int is_field  = (row >= FIRST_ROW && row < FIRST_ROW + nfields);
        if (is_header || is_field)
            mvaddch(row, SEP_X, ACS_VLINE);
    }

    draw_hline(HEADER_ROW + 1, BOX_X, BOX_W,
               ACS_LTEE, ACS_RTEE, SEP_X, ACS_PLUS);
    draw_hline(FIRST_ROW + nfields, BOX_X, BOX_W,
               ACS_LTEE, ACS_RTEE, SEP_X, ACS_BTEE);
    draw_hline(BOX_Y + BOX_H - 1, BOX_X, BOX_W,
               ACS_LLCORNER, ACS_LRCORNER, -1, 0);
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Status Bar __________________________________________________________________________________
// These move the cursor to the status row, but text input needs it where it was. So each one
// saves the cursor, does its work and puts it back.
static void clear_status(void) {
    int cy, cx;
    getyx(stdscr, cy, cx);
    move(STATUS_ROW, 0);
    clrtoeol();
    move(cy, cx);
}

static void show_error(const char *msg) {
    int cy, cx;
    getyx(stdscr, cy, cx);
    move(STATUS_ROW, 0);
    clrtoeol();
    attron(COLOR_PAIR(CP_ERROR) | A_BOLD);
    mvprintw(STATUS_ROW, BOX_X, " ! %s ", msg);
    attroff(COLOR_PAIR(CP_ERROR) | A_BOLD);
    move(cy, cx);
    refresh();
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Validation (on commit) ______________________________________________________________________
static int validate_ipv4(const char *s) {
    int octets = 0, val = 0, digits = 0;
    for (int i = 0; ; i++) {
        char ch = s[i];
        if (ch == '.' || ch == '\0') {
            if (digits == 0 || val > 255) return 0;
            octets++;
            val = 0;
            digits = 0;
            if (ch == '\0') break;
        } else if (ch >= '0' && ch <= '9') {
            val = val * 10 + (ch - '0');
            digits++;
            if (digits > 3) return 0;
        } else {
            return 0;
        }
    }
    return (octets == 4);
}

// IPv4 or hostname? Digits and dots only must be a full IPv4, so 1.2.3 is not taken as a name.
// Name labels are 1-63 long, never start or end with a hyphen, never empty.
static int validate_host(const char *s) {
    int has_alpha = 0;
    for (const char *p = s; *p; p++)
        if (!((*p >= '0' && *p <= '9') || *p == '.')) has_alpha = 1;
    if (!has_alpha) return validate_ipv4(s);

    int len = 0; char prev = '.';
    for (const char *p = s; ; p++) {
        if (*p == '.' || *p == '\0') {
            if (len == 0 || len > 63 || prev == '-') return 0;
            len = 0;
            if (*p == '\0') break;
        } else {
            if (len == 0 && *p == '-') return 0;
            len++;
        }
        prev = *p;
    }
    return 1;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Form Screen _________________________________________________________________________________
typedef enum { MODE_NAV, MODE_EDIT } CfgMode;

static void draw_form(const FormDef *f, const void *tmp, int sel, CfgMode mode) {
    recompute_layout(f->count);
    erase();
    draw_box_frame(f->count);

    mvprintw(BOX_Y, BOX_X + 2, "%s", f->title);
    const char *mode_str = (mode == MODE_NAV) ? "[ NAV MODE ]" : "[ EDIT MODE ]";
    mvprintw(BOX_Y, BOX_X + BOX_W - (int)strlen(mode_str) - 2, "%s", mode_str);

    attron(A_BOLD);
    mvprintw(HEADER_ROW, L_X, "%-*s", L_W - 1, "FIELD");
    mvprintw(HEADER_ROW, R_X, "VALUE");
    attroff(A_BOLD);

    char valbuf[64];
    for (int i = 0; i < f->count; i++) {
        int row    = FIRST_ROW + i;
        int is_sel = (sel == i);

        f->to_str(tmp, i, valbuf, sizeof(valbuf));

        int lattr = 0;                                   // Label cell
        if (is_sel)
            lattr = (mode == MODE_NAV) ? A_REVERSE : A_BOLD;

        if (lattr) attron(lattr);
        mvprintw(row, L_X, " %-*s ", L_W - 3, f->fields[i].label);
        if (lattr) attroff(lattr);

        // Value cell. Selected text field in EDIT mode gets an underlined input area,
        // everything else shows its current value, highlighted when selected.
        if (is_sel && mode == MODE_EDIT && f->fields[i].type != FLD_CYCLE) {
            int ml = f->fields[i].maxlen;
            mvaddch(row, R_X, ' ');
            for (int j = 0; j < ml; j++)
                mvaddch(row, R_X + 1 + j, ' ' | A_UNDERLINE);
            for (int j = ml; j < R_W - 2; j++)
                mvaddch(row, R_X + 1 + j, ' ');
            mvaddch(row, R_X + R_W - 1, ' ');
        } else {
            int rattr = 0;
            if (is_sel)
                rattr = (mode == MODE_NAV) ? A_REVERSE : (A_REVERSE | A_BOLD);
            if (rattr) attron(rattr);
            mvprintw(row, R_X, " %-*s ", R_W - 2, valbuf);
            if (rattr) attroff(rattr);
        }
    }

    int save_sel   = (sel == f->count);
    int cancel_sel = (sel == f->count + 1);

    // Centers each button in its half of the box, stays centered if BOX_W changes
    int sw = 12;  // "  [ SAVE ]  " width
    int cw = 14;  // "  [ CANCEL ]  " width
    int half = BOX_W / 2;
    int save_x   = BOX_X + (half - sw) / 2;
    int cancel_x = BOX_X + half + (half - cw) / 2;

    if (save_sel)   attron(A_REVERSE);
    mvprintw(BTN_ROW, save_x,   "  [ SAVE ]  ");
    if (save_sel)   attroff(A_REVERSE);

    if (cancel_sel) attron(A_REVERSE);
    mvprintw(BTN_ROW, cancel_x, "  [ CANCEL ]  ");
    if (cancel_sel) attroff(A_REVERSE);

    const char *hint;                                    // Footer
    if (mode == MODE_NAV) {
        if (sel >= f->count)
            hint = "  LEFT/RIGHT swap   ENTER select   UP back to fields";
        else
            hint = "  UP/DOWN navigate   ENTER edit/select   q quit";
    } else if (sel < f->count && f->fields[sel].type == FLD_CYCLE)
        hint = "  LEFT/RIGHT cycle   ENTER commit   ESC abort";
    else
        hint = "  type value   ENTER commit   ESC abort";
    mvprintw(BOX_Y + BOX_H + 1, BOX_X, "%s", hint);

    refresh();
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Text Input (FLD_STR, FLD_INT, FLD_IP, FLD_HOST) _____________________________________________
// noecho() stays on for good. Characters are drawn by hand with addch(), echo() would make
// ncurses print every key a second time.
static int read_text(int y, int x, const FldMeta *meta, char *buf) {
    curs_set(1);

    for (int i = 0; i < meta->maxlen; i++)               // Underlined input area, the visual limit
        mvaddch(y, x + i, ' ' | A_UNDERLINE);
    move(y, x);
    refresh();

    int len = 0;
    buf[0] = '\0';

    while (1) {
        int c = getch();

        if (c == '\n' || c == KEY_ENTER) {               // ENTER validates and commits
            buf[len] = '\0';

            if (meta->type == FLD_INT && len > 0) {
                long v = atol(buf);
                if (v < meta->min_val || v > meta->max_val) {
                    char msg[64];
                    snprintf(msg, sizeof(msg),
                             "Value out of range (%d-%d)", meta->min_val, meta->max_val);
                    show_error(msg);
                    continue;
                }
            }

            if (meta->type == FLD_IP && len > 0) {
                if (!validate_ipv4(buf)) {
                    show_error("Invalid IPv4 format (need a.b.c.d, each 0-255)");
                    continue;
                }
            }

            if (meta->type == FLD_HOST && len > 0) {
                if (!validate_host(buf)) {
                    show_error("Invalid IPv4 or hostname");
                    continue;
                }
            }

            clear_status();
            break;
        }

        if (c == 27) {                                   // ESC aborts
            buf[0] = '\0';
            curs_set(0);
            clear_status();
            return 0;
        }

        if (c == KEY_BACKSPACE || c == 127 || c == 8) {  // Backspace works off len, not the cursor
            if (len > 0) {
                len--;
                buf[len] = '\0';
                mvaddch(y, x + len, ' ' | A_UNDERLINE);
                move(y, x + len);
                refresh();
                clear_status();
            }
            continue;
        }

        if (len >= meta->maxlen) continue;               // Plain character, filtered per type

        int accept = 0;

        if (meta->type == FLD_IP) {
            if (c == '.') {
                int dots = 0;
                for (int i = 0; i < len; i++) if (buf[i] == '.') dots++;
                if (len > 0 && buf[len-1] != '.' && dots < 3)
                    accept = 1;
            } else if (c >= '0' && c <= '9') {
                int octet_digits = 0;
                for (int i = len - 1; i >= 0 && buf[i] != '.'; i--)
                    octet_digits++;
                if (octet_digits < 3) accept = 1;
            }
        } else if (meta->type == FLD_INT) {
            if (c >= '0' && c <= '9') {
                if (!(len == 1 && buf[0] == '0'))
                    accept = 1;
            }
        } else if (meta->type == FLD_HOST) {      // The remaining rules run in validate_host on ENTER
            accept = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '.' || c == '-';
        } else {
            accept = (c >= 32 && c <= 126);
        }

        if (accept) {
            mvaddch(y, x + len, c | A_UNDERLINE);
            buf[len++] = (char)c;
            buf[len]   = '\0';
            refresh();
        }
    }

    curs_set(0);
    return 1;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Cycle Input (FLD_CYCLE) _____________________________________________________________________
// Shows "< ICMP >", the brackets hint at the LEFT/RIGHT keys. Padding keeps the cell R_W wide.
static int read_cycle(int y, int x, const FldMeta *meta,
                      const char *initial, char *buf) {
    int idx = 0;
    for (int i = 0; i < meta->opt_count; i++)
        if (strcmp(initial, meta->options[i]) == 0) { idx = i; break; }

    while (1) {
        char display[64];
        snprintf(display, sizeof(display), "< %s >", meta->options[idx]);

        attron(A_REVERSE | A_BOLD);
        mvprintw(y, x, "%-*s", R_W - 2, display);
        attroff(A_REVERSE | A_BOLD);
        refresh();

        int c = getch();
        if (c == KEY_LEFT)
            idx = (idx > 0) ? idx - 1 : meta->opt_count - 1;
        else if (c == KEY_RIGHT)
            idx = (idx < meta->opt_count - 1) ? idx + 1 : 0;
        else if (c == '\n' || c == KEY_ENTER) {
            snprintf(buf, 8, "%s", meta->options[idx]);
            return 1;
        }
        else if (c == 27) {
            buf[0] = '\0';
            return 0;
        }
    }
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Form Loop (Configuration + Settings) ________________________________________________________
// live is the real data, tmp a working copy of the same type. SAVE copies tmp into live,
// CANCEL or q throws it away.
static void open_form(const FormDef *f, void *live, void *tmp, size_t size) {
    memcpy(tmp, live, size);
    int sel    = 0;
    CfgMode mode = MODE_NAV;

    // Navigation (n = f->count):
    //   sel 0..n-1  fields, one vertical group
    //   sel n       SAVE button
    //   sel n+1     CANCEL button
    // UP/DOWN walk the fields. DOWN on the last field or UP on the first lands on SAVE.
    // On a button UP returns to the last field, DOWN wraps to the first, LEFT/RIGHT swap.
    while (1) {
        draw_form(f, tmp, sel, mode);
        int key = getch();

        switch (key) {
        case KEY_UP:
            if (sel >= f->count)
                sel = f->count - 1;          // Button back to the last field
            else
                sel = (sel > 0) ? sel - 1 : f->count;  // First field up to SAVE
            clear_status();
            break;
        case KEY_DOWN:
            if (sel < f->count)
                sel = (sel < f->count - 1) ? sel + 1 : f->count;
            else
                sel = 0;                       // Button wraps to the first field
            clear_status();
            break;
        case KEY_LEFT:
        case KEY_RIGHT:
            if (sel >= f->count)
                sel = (sel == f->count) ? f->count + 1 : f->count;
            clear_status();
            break;
        case '\n':
        case KEY_ENTER:
            if (sel < f->count) {
                const FldMeta *meta = &f->fields[sel];
                mode = MODE_EDIT;
                draw_form(f, tmp, sel, mode);

                char buf[64] = {0};
                int  row = FIRST_ROW + sel;
                int  ok;

                if (meta->type == FLD_CYCLE) {
                    char init[8];
                    f->to_str(tmp, sel, init, sizeof(init));
                    ok = read_cycle(row, R_X + 1, meta, init, buf);
                } else {
                    ok = read_text(row, R_X + 1, meta, buf);
                }

                if (ok && buf[0] != '\0')
                    f->from_str(tmp, sel, buf);

                mode = MODE_NAV;
            } else if (sel == f->count) {
                memcpy(live, tmp, size);
                return;
            } else {
                return;
            }
            break;
        case 'q':
        case 'Q':
            return;
        }
    }
}

void open_configuration(void) {
    Config tmp;
    open_form(&CFG_FORM, &current_cfg, &tmp, sizeof(tmp));
}

void open_settings(void) {
    Settings tmp;
    open_form(&SET_FORM, &settings, &tmp, sizeof(tmp));
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Track Signal Table __________________________________________________________________________
// Turns a flag letter into screen text. The unreachable marks follow Linux traceroute.
static const char *flag_text(char f) {
    switch (f) {
        case 'O': return "open";
        case 'C': return "closed";
        case 'N': return "!N";                   // Network unreachable
        case 'H': return "!H";                   // Host unreachable
        case 'X': return "!X";                   // Administratively prohibited, a filter said no
        case 'P': return "!P";                   // Protocol unreachable
        case 'F': return "!F";                   // Fragmentation needed but DF was set
        case 'U': return "!U";                   // Any other unreachable code
    }
    return "";
}

// When one hop gets several verdicts the strongest stays. Only a listening port sends SYN-ACK,
// so that is the strongest proof. Then the target's RST or port unreachable, weakest is an
// unreachable from somewhere on the path. All unreachable kinds rank the same.
static int flag_rank(char f) {
    if (f == 'O') return 3;
    if (f == 'C') return 2;
    if (f && strchr("NHXPFU", f)) return 1;      // f first, strchr would match the terminator on 0
    return 0;
}

// Maps a Destination Unreachable code (RFC 792, RFC 1812) to its flag letter
static char unreach_flag(int code) {
    switch (code) {
        case 0: case 6: case 11: return 'N';     // Net unreachable, net unknown, net for TOS
        case 1: case 7: case 12: return 'H';     // Host unreachable, host unknown, host for TOS
        case 9: case 10: case 13: return 'X';    // Net, host or communication prohibited
        case 2:                  return 'P';
        case 4:                  return 'F';
    }
    return 'U';
}

// scroll_off is the hop index at the top of the table. While follow is 1 every draw sticks to
// the bottom so new hops stay visible. Bounds get clamped here because only the draw knows how
// many rows fit.
static void draw_track(HopResult *hops, int count, int running, const char *label, int probes,
                       int *scroll_off, int *follow, int dns_on, const char *target_str) {
    erase();
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int flag_x = 24 + probes * 10;                 // Verdict column right after the RTT columns
    int name_x = flag_x + 7;                       // Name column on the far right when DNS is on
    int w = flag_x + 8 + (dns_on ? 25 : 0);        // 3 probes + DNS off = 62, same as before
    if (w > cols - 4) w = cols - 4;
    int x = (cols - w) / 2; if (x < 2) x = 2;
    int y = 2;

    int first   = y + 3;                    // First hop row
    int maxrows = rows - first - 3;         // Leaves room for the footer
    int shown   = (count < maxrows) ? count : maxrows;
    if (shown < 0) shown = 0;
    int bottom  = first + shown;            // Bottom frame row

    int max_off = count - shown;            // The bottom-most window
    if (*follow || *scroll_off >= max_off) { *scroll_off = max_off; *follow = 1; } // Hitting bottom turns follow back on
    if (*scroll_off < 0) *scroll_off = 0;

    mvprintw(y - 1, x, "Target: %s", target_str);    // Shows the resolved IP too, so a hijack is visible

    draw_hline(y, x, w, ACS_ULCORNER, ACS_URCORNER, -1, 0);   // Top frame + titles
    mvprintw(y, x + 2, "[ TRACK SIGNAL ]");
    mvprintw(y, x + 19, "[ %s ]", label);           // Which protocol and port
    const char *st = running ? "[ RUNNING ]" : "[ DONE ]";
    mvprintw(y, x + w - (int)strlen(st) - 2, "%s", st);

    mvaddch(y + 1, x, ACS_VLINE); mvaddch(y + 1, x + w - 1, ACS_VLINE);   // Column headers
    attron(A_BOLD);
    mvprintw(y + 1, x + 2,  "HOP");
    mvprintw(y + 1, x + 7,  "IP ADDRESS");
    for (int p = 0; p < probes; p++) {              // Header and values both right aligned so they line up
        char lbl[8]; snprintf(lbl, sizeof(lbl), "RTT %d", p + 1);
        mvprintw(y + 1, x + 24 + p * 10, "%6s", lbl);
    }
    if (dns_on && name_x + 4 < w - 1) mvprintw(y + 1, x + name_x, "NAME");
    attroff(A_BOLD);

    draw_hline(y + 2, x, w, ACS_LTEE, ACS_RTEE, -1, 0);  // Header divider

    for (int i = 0; i < shown; i++) {               // Hop rows
        int ry = first + i;
        mvaddch(ry, x, ACS_VLINE); mvaddch(ry, x + w - 1, ACS_VLINE);
        HopResult *h = &hops[*scroll_off + i];          // The window may be scrolled

        if (h->ip[0] == '\0') {                         // Nobody answered
            mvprintw(ry, x + 2, "%2d   * * *", h->hop);
        } else {
            mvprintw(ry, x + 2, "%2d   %-15s", h->hop, h->ip);
            for (int p = 0; p < probes; p++) {          // Each probe in its own right aligned column
                int cx = x + 24 + p * 10;
                (h->rtt[p] < 0) ? mvprintw(ry, cx, "%6s", "*")
                                : mvprintw(ry, cx, "%6.2f ms", h->rtt[p]);
            }
            if (h->flag && flag_x + 6 < w - 1)          // TCP/UDP verdict, kept inside the frame
                mvprintw(ry, x + flag_x, "%s", flag_text(h->flag));
            int room = w - name_x - 2;                  // Space left in the name column
            if (dns_on && h->name[0] && room > 0)       // Long names get clipped, the frame stays intact
                mvprintw(ry, x + name_x, "%.*s", room, h->name);
        }
    }

    draw_hline(bottom, x, w, ACS_LLCORNER, ACS_LRCORNER, -1, 0);
    mvprintw(bottom + 2, x, "  [ ESC ] abort   [ UP/DOWN ] scroll");
    if (count > shown && shown > 0)                     // Shows where we are when it does not fit
        printw("   hops %d-%d of %d", *scroll_off + 1, *scroll_off + shown, count);
    refresh();
}
////////////////////////////////////////////////////////////////////////////////////////////////

// ICMP Engine (raw echo) ______________________________________________________________________
// Proven boxes from trace.c. The one difference is waiting no longer blocks. Parsing lives in
// parse_icmp, select + recvfrom run inside the Track tick loop.
static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b; unsigned int sum = 0; unsigned short result;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF); sum += (sum >> 16);
    result = ~sum; return result;
}

// Raw ICMP socket. -1 means no privilege (needs sudo), the caller handles it.
static int open_icmp_socket(void) {
    return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

// Builds and sends one echo probe. ttl sets how far it gets, seq is the tag the reply is matched on.
// Returns the send instant, RTT is measured from it.
static struct timespec send_icmp_probe(int sock, struct sockaddr_in *target, int ttl, int seq) {
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));   // The one thing bumped each hop

    char packet[64]; memset(packet, 0, sizeof(packet));
    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO; icmp->code = 0;                    // Echo request, type 8
    icmp->un.echo.id       = htons(getpid() & 0xFFFF);         // id = pid, my signature
    icmp->un.echo.sequence = htons(seq);                       // Unique per probe
    memset(packet + sizeof(struct icmphdr), 'A', 32);
    icmp->checksum = checksum(packet, sizeof(struct icmphdr) + 32);  // Computed with the field at 0

    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);     // Clock right before it leaves
    if (sendto(sock, packet, sizeof(struct icmphdr) + 32, 0,
               (struct sockaddr *)target, sizeof(*target)) < 0) {}  // On fail this probe shows as a timeout
    return t;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// TCP Engine (raw SYN) ________________________________________________________________________
// Proven boxes from tcptrace.c. I build the SYN, the kernel builds the IP header. Routers answer
// with ICMP Time Exceeded, the target with SYN-ACK (open) or RST (closed).
// Identity: the probe tag rides in the TCP seq, seq = pid << 16 | tag. The ICMP quote only
// promises the first 8 bytes (ports + seq), so matching works off those. One at a time the
// source port stays fixed so ECMP keeps one path, in parallel each SYN gets its own port.

// The 12 bytes the TCP checksum covers but never sends, a summary of the IP header the
// kernel is about to build.
struct pseudo_hdr {
    uint32_t src, dst;            // Source + destination IP, network order
    uint8_t  zero, proto;         // Always 0, then IPPROTO_TCP
    uint16_t len;                 // TCP header + payload length
};

// One session's engine (Track or Send): protocol, sockets, identity.
// ICMP only fills isock. TCP adds tsock, src and sport.
// UDP uses sport as the start of a port block, every probe leaves from its own socket.
// TCP with port_block = 1 (parallel Track) also gives every SYN its own port from the block.
typedef struct {
    int                proto;      // IPPROTO_ICMP, IPPROTO_TCP or IPPROTO_UDP
    struct sockaddr_in target;     // sin_port matters for TCP and UDP
    struct in_addr     src;        // Source IP for the pseudo-header
    unsigned short     my_id;      // pid, my signature
    uint16_t           sport;      // TCP: fixed source port or block start. UDP: block start
    int                port_block; // TCP: 1 = port per probe, 0 = one fixed port (Paris)
    int                isock;      // Raw ICMP: echo reply, time exceeded, unreachable
    int                tsock;      // Raw TCP: sends SYNs, hears SYN-ACK and RST. -1 for ICMP
} Engine;

#define PORT_BLOCK 200                  // Ports per session, Track uses at most 30*5+4 = 154 tags

// TCP seq: pid in the top 16 bits, probe tag in the bottom 16
static uint32_t syn_seq(const Engine *m, int tag) {
    return ((uint32_t)m->my_id << 16) | (uint16_t)tag;
}

// Source port for a SYN. A fixed port means many SYNs on one 4-tuple at once, which was measured
// to come back as a mix of SYN-ACK, RST and silence. In parallel each SYN gets its own 4-tuple,
// the price is ECMP path consistency.
static uint16_t tcp_port(const Engine *m, int tag) {
    return m->port_block ? m->sport + (uint16_t)(tag % PORT_BLOCK) : m->sport;
}

// Is our side's port in the packet ours, and consistent with the tag?
static int tcp_port_matches(const Engine *m, int port, int tag) {
    return port == tcp_port(m, tag);
}

// The pseudo-header needs the source IP, but the kernel picks it. A connected UDP socket makes the
// kernel run its route lookup and getsockname reads the answer back. Nothing goes on the wire.
// 0 = no route.
static int find_source_ip(struct sockaddr_in *target, struct in_addr *out) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    if (connect(s, (struct sockaddr *)target, sizeof(*target)) < 0) { close(s); return 0; }
    struct sockaddr_in local; socklen_t l = sizeof(local);
    int ok = (getsockname(s, (struct sockaddr *)&local, &l) == 0);
    close(s);
    if (ok) *out = local.sin_addr;
    return ok;
}

// Builds and sends one SYN. Pseudo + TCP header sit back to back, the checksum covers both,
// only the TCP part is sent.
static struct timespec send_tcp_probe(Engine *m, int ttl, int tag) {
    uint32_t seq = syn_seq(m, tag);
    setsockopt(m->tsock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));   // The one thing bumped each hop

    char packet[sizeof(struct pseudo_hdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct pseudo_hdr *ph  = (struct pseudo_hdr *)packet;
    struct tcphdr     *tcp = (struct tcphdr *)(packet + sizeof(struct pseudo_hdr));

    tcp->source = htons(tcp_port(m, tag));     // One at a time: fixed. Parallel: one per probe
    tcp->dest   = m->target.sin_port;          // The port under test
    tcp->seq    = htonl(seq);                  // pid + tag, comes back in the ICMP quote
    tcp->doff   = 5;                           // 20 bytes, no options
    tcp->syn    = 1;
    tcp->window = htons(64240);                // Plausible window, some boxes drop 0

    ph->src   = m->src.s_addr;                 // Same source the kernel will stamp
    ph->dst   = m->target.sin_addr.s_addr;
    ph->proto = IPPROTO_TCP;
    ph->len   = htons(sizeof(struct tcphdr));
    tcp->check = checksum(packet, sizeof(packet));   // Computed with the field at 0

    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    if (sendto(m->tsock, tcp, sizeof(struct tcphdr), 0,
               (struct sockaddr *)&m->target, sizeof(m->target)) < 0) {}  // On fail it shows as a timeout
    return t;
}
////////////////////////////////////////////////////////////////////////////////////////////////

// UDP Engine (kernel sends) ___________________________________________________________________
// Boxes from udptrace.c. The kernel builds the datagram, I only pick the TTL and source port.
// Routers answer with Time Exceeded, the target with Port Unreachable, both read off the raw
// ICMP socket.
// Identity: the 8 quoted bytes are the whole UDP header. The destination port is fixed by the
// config, so the tag lives in the source port: port = block start + tag % PORT_BLOCK. The price
// is a 5-tuple that changes per probe, so the ECMP path may shift.

static uint16_t udp_port(const Engine *m, int tag) {
    return m->sport + (uint16_t)(tag % PORT_BLOCK);
}

// One datagram: fresh socket, bind to the tag port, TTL, empty payload, close.
// If bind or sendto fails it returns {0,0} and the FSM counts that probe as timed out at once.
static struct timespec send_udp_probe(Engine *m, int ttl, int tag) {
    struct timespec t = {0, 0};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return t;

    struct sockaddr_in local; memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(udp_port(m, tag));                  // Source port = probe tag
    if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0) { close(s); return t; }
    setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));      // The one thing bumped each hop

    clock_gettime(CLOCK_MONOTONIC, &t);
    if (sendto(s, "", 0, 0, (struct sockaddr *)&m->target, sizeof(m->target)) < 0) {
        t.tv_sec = 0; t.tv_nsec = 0;                            // Never left
    }
    close(s);                                                  // The reply lands on the raw ICMP socket anyway
    return t;
}

// Sends the right kind of probe for the protocol. tag = ICMP seq, low half of the TCP seq or
// UDP port offset.
static struct timespec fire_probe(Engine *m, int ttl, int tag) {
    if (m->proto == IPPROTO_TCP) return send_tcp_probe(m, ttl, tag);
    if (m->proto == IPPROTO_UDP) return send_udp_probe(m, ttl, tag);
    return send_icmp_probe(m->isock, &m->target, ttl, tag);
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Reply Parsing _______________________________________________________________________________
// Parses a packet off the ICMP socket. Is it the answer to one of my probes? If so it writes WHICH
// probe to tag_out, the responder to ip_out, the stop decision to reached_out and the verdict
// letter to flag_out, then returns 1. It does not ask for an expected tag, it finds the tag,
// since in parallel many probes are in flight at once. Branches on the embedded packet's
// protocol: ICMP matches id + seq, TCP ports + seq, UDP ports.
static int parse_icmp(char *buf, int n, struct sockaddr_in *from, Engine *m, int *tag_out,
                      char *ip_out, int *reached_out, char *flag_out) {
    if (n < (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr)) return 0;
    struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;    // Steps over the outer IP header
    if (n < iplen + (int)sizeof(struct icmphdr)) return 0;
    struct icmphdr *icmp = (struct icmphdr *)(buf + iplen);
    *flag_out = 0;

    if (icmp->type == ICMP_ECHOREPLY) {                     // Case A: the target answered
        if (m->proto != IPPROTO_ICMP) return 0;             // In TCP/UDP mode an echo reply cannot be mine
        if (ntohs(icmp->un.echo.id) != m->my_id) return 0;  // Not mine
        *tag_out = ntohs(icmp->un.echo.sequence);           // seq = tag
        *reached_out = 1;
    } else if (icmp->type == ICMP_TIME_EXCEEDED ||          // Case B: a router burned the TTL
               icmp->type == ICMP_DEST_UNREACH) {           // Case C: someone cut the path
        int off = iplen + 8;                                // Outer IP + 8 bytes reaches the embedded original
        if (n < off + (int)sizeof(struct iphdr)) return 0;
        struct iphdr *iip = (struct iphdr *)(buf + off); int iiplen = iip->ihl * 4;
        if (iip->protocol != m->proto) return 0;            // Error about some other protocol
        if (n < off + iiplen + 8) return 0;                 // Only 8 bytes are promised

        if (m->proto == IPPROTO_ICMP) {
            if (iip->daddr != m->target.sin_addr.s_addr) return 0;          // Echo to some other target
            struct icmphdr *iicmp = (struct icmphdr *)(buf + off + iiplen); // My original echo header, buried inside
            if (ntohs(iicmp->un.echo.id) != m->my_id) return 0;             // Not my probe
            *tag_out = ntohs(iicmp->un.echo.sequence);
        } else if (m->proto == IPPROTO_TCP) {
            if (iip->daddr != m->target.sin_addr.s_addr) return 0;          // SYN to some other target
            struct tcphdr *itcp = (struct tcphdr *)(buf + off + iiplen);    // Ports + seq, nothing past that
            uint32_t s = ntohl(itcp->seq);
            if (itcp->dest != m->target.sin_port || (s >> 16) != m->my_id ||
                !tcp_port_matches(m, ntohs(itcp->source), s & 0xFFFF)) return 0; // Not my SYN
            *tag_out = s & 0xFFFF;                                          // Low half of seq = tag
        } else {
            if (iip->daddr != m->target.sin_addr.s_addr) return 0;          // Datagram to some other target
            struct udphdr *iudp = (struct udphdr *)(buf + off + iiplen);    // The 8 quoted bytes are the whole UDP header
            int sp = ntohs(iudp->source);
            if (sp < m->sport || sp >= m->sport + PORT_BLOCK ||
                iudp->dest != m->target.sin_port) return 0;                 // Not from my block
            *tag_out = sp - m->sport;                                       // Offset in the block = tag
        }

        if (icmp->type == ICMP_DEST_UNREACH) {              // The trace ends here
            *reached_out = 1;
            *flag_out = (m->proto == IPPROTO_UDP && icmp->code == ICMP_PORT_UNREACH)
                      ? 'C' : unreach_flag(icmp->code);     // UDP port unreachable = reached, port closed
        }
        else *reached_out = 0;
    } else return 0;                                        // Unrelated ICMP

    inet_ntop(AF_INET, &from->sin_addr, ip_out, INET_ADDRSTRLEN);       // Who answered
    return 1;
}

// Parses a packet off the TCP socket. Did the target answer my SYN with SYN-ACK or RST?
// Ports + ack = seq + 1 must hold. The raw TCP socket gets a copy of EVERY TCP packet on the
// host, so the filter is mandatory.
static int parse_tcp(char *buf, int n, struct sockaddr_in *from, Engine *m, int *tag_out,
                     char *ip_out, int *reached_out, char *flag_out) {
    if (n < (int)sizeof(struct iphdr)) return 0;
    struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;
    if (ip->saddr != m->target.sin_addr.s_addr) return 0;                 // Not from the target
    if (n < iplen + (int)sizeof(struct tcphdr)) return 0;
    struct tcphdr *tcp = (struct tcphdr *)(buf + iplen);
    if (tcp->source != m->target.sin_port) return 0;                      // Some other connection
    uint32_t s = ntohl(tcp->ack_seq) - 1;                                  // ack = my seq + 1
    if (!tcp->ack || (s >> 16) != m->my_id ||
        !tcp_port_matches(m, ntohs(tcp->dest), s & 0xFFFF)) return 0;     // Answer to some other SYN
    *tag_out = s & 0xFFFF;

    if (tcp->syn)      *flag_out = 'O';                    // SYN-ACK, port open
    else if (tcp->rst) *flag_out = 'C';                    // RST, port closed
    else return 0;
    *reached_out = 1;
    inet_ntop(AF_INET, &from->sin_addr, ip_out, INET_ADDRSTRLEN);
    return 1;
}

// Polls the sockets for at most tick_us and parses one packet.
// 1 = answer to one of my probes (tag_out filled), 0 = foreign packet, -1 = nothing to read.
// While it returns 0 or 1 the caller can call again with tick_us=0 to drain what piled up.
static int read_reply(Engine *m, int tick_us, int *tag_out,
                      char *ip_out, int *reached_out, char *flag_out) {
    fd_set rfds; FD_ZERO(&rfds); FD_SET(m->isock, &rfds);
    int maxfd = m->isock;
    if (m->tsock >= 0) { FD_SET(m->tsock, &rfds); if (m->tsock > maxfd) maxfd = m->tsock; }
    struct timeval tv = { 0, tick_us };
    if (select(maxfd + 1, &rfds, NULL, NULL, &tv) <= 0) return -1;

    char buf[1024]; struct sockaddr_in from; socklen_t kl;
    if (FD_ISSET(m->isock, &rfds)) {                        // A router, a firewall or an echo reply
        kl = sizeof(from);
        int n = recvfrom(m->isock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &kl);
        if (n > 0 && parse_icmp(buf, n, &from, m, tag_out, ip_out, reached_out, flag_out)) return 1;
    }
    if (m->tsock >= 0 && FD_ISSET(m->tsock, &rfds)) {       // The target itself
        kl = sizeof(from);
        int n = recvfrom(m->tsock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &kl);
        if (n > 0 && parse_tcp(buf, n, &from, m, tag_out, ip_out, reached_out, flag_out)) return 1;
    }
    return 0;
}

// Is the incoming tag the same probe as the expected one? The field carrying the tag narrows by
// protocol: 16 bits for ICMP and TCP, the block offset for UDP. Ping seq grows and wraps, so the
// compare has to narrow the same way.
static int same_tag(const Engine *m, int got, int want) {
    if (m->proto == IPPROTO_UDP) return got == want % PORT_BLOCK;
    return got == (want & 0xFFFF);
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Engine Setup ________________________________________________________________________________
// Builds the engine from the config. Returns a message to show on error, NULL otherwise.
// engine_close must be called on error too. parallel = 1 makes TCP use a source port per probe.
static const char *engine_open(Engine *m, struct in_addr target_ip, int parallel) {
    static int session = 0;                    // Every session gets fresh source ports
    memset(m, 0, sizeof(*m));
    m->isock = m->tsock = -1;
    m->target.sin_family = AF_INET;
    m->target.sin_addr   = target_ip;          // resolve_target already did it, via DNS for a hostname

    if      (strcmp(current_cfg.proto, "TCP") == 0) m->proto = IPPROTO_TCP;
    else if (strcmp(current_cfg.proto, "UDP") == 0) m->proto = IPPROTO_UDP;
    else                                            m->proto = IPPROTO_ICMP;
    m->my_id = getpid() & 0xFFFF;

    m->isock = open_icmp_socket();             // TCP/UDP need it too, Time Exceeded arrives here
    if (m->isock < 0) return "Cannot open raw socket. Run with sudo (root needed).";

    if (m->proto == IPPROTO_TCP) {
        if (current_cfg.port < 1) return "TCP needs a port between 1 and 65535.";
        m->target.sin_port = htons(current_cfg.port);
        if (!find_source_ip(&m->target, &m->src)) return "No route to target.";
        m->tsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (m->tsock < 0) return "Cannot open raw TCP socket. Run with sudo (root needed).";
        m->port_block = parallel;
        if (parallel) m->sport = 40000 + ((getpid() + session++) % 100) * PORT_BLOCK;  // One block per session
        else          m->sport = 40000 + ((getpid() + session++) % 20000);  // Keeps a late SYN-ACK from an old session out
    }
    if (m->proto == IPPROTO_UDP) {
        if (current_cfg.port < 1) return "UDP needs a port between 1 and 65535.";
        m->target.sin_port = htons(current_cfg.port);
        m->sport = 40000 + ((getpid() + session++) % 100) * PORT_BLOCK;  // One block per session, tops out at 59999
    }
    return NULL;
}

static void engine_close(Engine *m) {
    if (m->isock >= 0) close(m->isock);
    if (m->tsock >= 0) close(m->tsock);
    m->isock = m->tsock = -1;
}

// Protocol label for the title bar: "ICMP", "TCP 443" or "UDP 33434"
static void engine_label(const Engine *m, char *out, int len) {
    if      (m->proto == IPPROTO_TCP) snprintf(out, len, "TCP %d", ntohs(m->target.sin_port));
    else if (m->proto == IPPROTO_UDP) snprintf(out, len, "UDP %d", ntohs(m->target.sin_port));
    else                              snprintf(out, len, "ICMP");
}

// Shows why the engine could not start, returns to the menu on any key
static void error_screen(const char *msg) {
    erase();
    mvprintw(2, 4, "%s", msg);
    mvprintw(4, 4, "Press any key to return.");
    refresh(); getch();
}
////////////////////////////////////////////////////////////////////////////////////////////////

// DNS Engine (hand-built queries) _____________________________________________________________
// Proven boxes from dnsq.c. The query is built byte by byte, sent over plain UDP to the server
// in resolv.conf, and the answer is parsed by hand, compressed names included.
// Never blocks: the socket is polled with MSG_DONTWAIT inside the tick loop. Unlike getaddrinfo
// it does not freeze the UI (an NXDOMAIN took about 1 s, measured).
// Identity: a random 16-bit ID. DNS has no handshake, ID + source port are all that stop a
// spoofed answer.
#define DNS_PORT        53
#define DNS_TIMEOUT_MS  2000
#define T_A             1
#define T_PTR           12
#define DNS_MAX_JUMPS   16             // Pointers followed per name before calling it a loop

static double ms_between(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1000000.0;
}

// UDP socket connected to the first IPv4 nameserver in resolv.conf. -1 = none.
static int dns_open(void) {
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (!f) return -1;
    char line[256], ip[64]; struct sockaddr_in ns; memset(&ns, 0, sizeof(ns));
    int ok = 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, " nameserver %63s", ip) == 1 && inet_pton(AF_INET, ip, &ns.sin_addr) == 1) { ok = 1; break; }
    fclose(f);
    if (!ok) return -1;
    ns.sin_family = AF_INET; ns.sin_port = htons(DNS_PORT);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    if (connect(s, (struct sockaddr *)&ns, sizeof(ns)) < 0) { close(s); return -1; } // Only the server's datagrams get in
    return s;
}

// A guessable ID is how cache poisoning works, so this one comes from the kernel RNG
static uint16_t random_id(void) {
    uint16_t id = 0; int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, &id, sizeof(id)) != sizeof(id))
        id = (uint16_t)(getpid() ^ time(NULL));
    if (fd >= 0) close(fd);
    return id;
}

// "www.google.com" becomes 3www6google3com0. -1 = empty or long label, or name too long
static int encode_name(const char *name, unsigned char *out, int cap) {
    int n = 0; const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len == 0 || len > 63) return -1;                       // Double dot, or over the 6-bit length
        if (n + 1 + len + 1 > cap || n + 1 + len + 1 > 255) return -1;
        out[n++] = (unsigned char)len;                             // Length byte, then the label
        memcpy(out + n, p, len); n += len;
        p += len; if (*p == '.') p++;
    }
    if (n + 1 > cap) return -1;
    out[n++] = 0;                                                  // Root label ends the name
    return n;
}

// Builds and sends one query. The header is written byte by byte, no struct, so endianness and
// padding never come up. Writes the ID to id_out for matching. 0 = bad name or send failed
static int dns_ask(int s, const char *qname, uint16_t qtype, uint16_t *id_out) {
    unsigned char q[300]; uint16_t id = random_id();
    memset(q, 0, 12);
    q[0] = id >> 8; q[1] = id & 0xFF;          // ID, the answer must echo it
    q[2] = 0x01;                               // RD=1, asks the resolver to do the recursion
    q[5] = 1;                                  // QDCOUNT = 1
    int n = encode_name(qname, q + 12, sizeof(q) - 12 - 4);
    if (n < 0) return 0;
    int off = 12 + n;
    q[off++] = qtype >> 8; q[off++] = qtype & 0xFF;     // QTYPE
    q[off++] = 0;          q[off++] = 1;                // QCLASS = IN
    if (send(s, q, off, 0) != off) return 0;
    *id_out = id;
    return 1;
}

// 8.8.4.4 becomes 4.4.8.8.in-addr.arpa, flipped so the tree is walked from the network down
static void ptr_name(struct in_addr a, char *out, int cap) {
    unsigned char *b = (unsigned char *)&a.s_addr;
    snprintf(out, cap, "%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1], b[0]);
}

// Reads a possibly compressed name at off. Returns where the name ends in the record (not where
// a pointer jumped to), -1 if malformed. Pointers must point backward and are capped, or walking
// forward after a jump can reach the same pointer again and loop. Unprintable bytes become '?'
// so an escape code inside a PTR cannot mess up the screen.
static int decode_name(const unsigned char *msg, int len, int off, char *out, int cap) {
    int pos = off, end = -1, w = 0, jumps = 0;
    if (cap < 1) return -1;
    while (1) {
        if (pos >= len) return -1;
        unsigned char c = msg[pos];
        if (c == 0) { pos++; break; }                           // Root, the name is done
        if ((c & 0xC0) == 0xC0) {                               // 11xxxxxx = 14-bit pointer
            if (pos + 1 >= len) return -1;
            int target = ((c & 0x3F) << 8) | msg[pos + 1];
            if (end < 0) end = pos + 2;
            if (target >= pos || ++jumps > DNS_MAX_JUMPS) return -1;
            pos = target; continue;
        }
        if (c & 0xC0) return -1;                                // Prefixes 01 and 10 are reserved
        if (pos + 1 + c > len) return -1;
        if (w + (w ? 1 : 0) + c + 1 > cap) return -1;
        if (w) out[w++] = '.';
        for (int i = 0; i < c; i++) {
            unsigned char ch = msg[pos + 1 + i];
            out[w++] = (ch > 32 && ch < 127) ? (char)ch : '?';
        }
        pos += 1 + c;
    }
    out[w] = '\0';
    return (end >= 0) ? end : pos;
}

// Parses an answer (the caller already matched the ID). Writes the first record of qtype to out:
// IP text for A, the name for PTR. 1 = found, 0 = none, NXDOMAIN or malformed.
// A CNAME chain is skipped, the resolver puts the A record at the end of it.
static int dns_parse(const unsigned char *msg, int len, uint16_t qtype, char *out, int cap) {
    if (len < 12) return 0;
    int flags = (msg[2] << 8) | msg[3];
    if (!(flags & 0x8000) || (flags & 0x0F)) return 0;      // Not a response, or rcode != NOERROR
    int qd = (msg[4] << 8) | msg[5], an = (msg[6] << 8) | msg[7];
    int off = 12; char name_buf[256];
    for (int i = 0; i < qd; i++) {                          // Skips the echoed question
        off = decode_name(msg, len, off, name_buf, sizeof(name_buf));
        if (off < 0 || off + 4 > len) return 0;
        off += 4;
    }
    for (int i = 0; i < an; i++) {
        off = decode_name(msg, len, off, name_buf, sizeof(name_buf));
        if (off < 0 || off + 10 > len) return 0;            // type, class, ttl, rdlength
        int type  = (msg[off] << 8) | msg[off + 1];
        int rdlen = (msg[off + 8] << 8) | msg[off + 9];
        off += 10;
        if (off + rdlen > len) return 0;                    // RDATA longer than the packet
        if (type == qtype && qtype == T_A && rdlen == 4) {
            inet_ntop(AF_INET, msg + off, out, cap);
            return 1;
        }
        if (type == qtype && qtype == T_PTR) {
            if (decode_name(msg, len, off, name_buf, sizeof(name_buf)) < 0) return 0;
            snprintf(out, cap, "%s", name_buf);
            return 1;
        }
        off += rdlen;
    }
    return 0;
}

// Turns the target into an IP. An IPv4 returns at once. A hostname sends an A query and waits
// tick by tick (the UI never freezes, ESC cancels). 1 = out filled, 0 = cancelled or failed
// (the error was already shown).
static int resolve_target(const char *host, struct in_addr *out) {
    if (inet_pton(AF_INET, host, out) == 1) return 1;          // Already an IP, no DNS needed
    if (!settings.dns) { error_screen("Target is a hostname but Resolve DNS is OFF (see Settings)."); return 0; }

    int s = dns_open();
    if (s < 0) { error_screen("No usable nameserver in /etc/resolv.conf."); return 0; }
    uint16_t id;
    if (!dns_ask(s, host, T_A, &id)) { close(s); error_screen("Could not send the DNS query."); return 0; }

    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    const char *err = NULL; int found = 0;
    nodelay(stdscr, TRUE);
    while (1) {
        int k = getch();
        if (k == 27 || k == 'q' || k == 'Q') break;            // User gave up, no message

        erase();
        mvprintw(2, 4, "Resolving %s ...", host);
        mvprintw(4, 4, "[ ESC ] cancel");
        refresh();

        fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
        struct timeval tv = { 0, 60000 };                      // Same 60 ms tick
        if (select(s + 1, &rf, NULL, NULL, &tv) > 0) {
            unsigned char buf[1500];
            int n = recv(s, buf, sizeof(buf), 0);
            if (n >= 2 && ((buf[0] << 8) | buf[1]) == id) {    // The answer to my query
                char ip[INET_ADDRSTRLEN];
                if (dns_parse(buf, n, T_A, ip, sizeof(ip)) && inet_pton(AF_INET, ip, out) == 1) found = 1;
                else err = "Host not found (no A record).";
                break;
            }
        }
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        if (ms_between(t0, now) > DNS_TIMEOUT_MS) { err = "DNS timeout, the resolver did not answer."; break; }
    }
    nodelay(stdscr, FALSE);
    close(s);
    if (err) error_screen(err);
    return found;
}

// Target line above the table: "8.8.8.8" or "dns.google -> 8.8.8.8"
static void target_text(const char *host, struct in_addr ip, char *out, int cap) {
    char ipbuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ip, ipbuf, sizeof(ipbuf));
    if (strcmp(host, ipbuf) == 0) snprintf(out, cap, "%s", ipbuf);
    else                          snprintf(out, cap, "%s -> %s", host, ipbuf);
}

// PTR job per hop: 0 not asked, 1 waiting, 2 done (found or given up)
typedef struct {
    int             state;
    uint16_t        id;
    struct timespec t;
    char            ip[INET_ADDRSTRLEN];   // Which IP was asked, asks again if the hop IP changes
} PtrJob;

// Every tick: sends a PTR for hops whose IP just showed up, hands incoming answers to hops by ID,
// gives up on ones silent for 2 s. Never blocks.
static void ptr_tick(int s, HopResult *hops, int count, PtrJob *p) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    for (int i = 0; i < count; i++) {
        if (hops[i].ip[0] == '\0') continue;
        if (p[i].state != 0 && strcmp(p[i].ip, hops[i].ip) != 0) {   // ECMP: the hop IP changed
            p[i].state = 0; hops[i].name[0] = '\0';
        }
        if (p[i].state == 0) {
            struct in_addr a; char q[64];
            inet_pton(AF_INET, hops[i].ip, &a); ptr_name(a, q, sizeof(q));
            if (dns_ask(s, q, T_PTR, &p[i].id)) { p[i].state = 1; p[i].t = now; }
            else p[i].state = 2;
            snprintf(p[i].ip, sizeof(p[i].ip), "%s", hops[i].ip);
        } else if (p[i].state == 1 && ms_between(p[i].t, now) > DNS_TIMEOUT_MS) {
            p[i].state = 2;                                          // No answer, it stays nameless
        }
    }

    unsigned char buf[1500]; int n;
    while ((n = recv(s, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {      // Drains what piled up, never waits
        if (n < 2) continue;
        uint16_t id = (buf[0] << 8) | buf[1];
        for (int i = 0; i < count; i++) {
            if (p[i].state != 1 || p[i].id != id) continue;
            char name[256];
            if (dns_parse(buf, n, T_PTR, name, sizeof(name)) && strcmp(name, p[i].ip) != 0)
                snprintf(hops[i].name, sizeof(hops[i].name), "%.*s",       // A name equal to the IP is hidden (WSL)
                         (int)sizeof(hops[i].name) - 1, name);              // Long names get clipped on purpose
            p[i].state = 2;
            break;
        }
    }
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Track Signal (parallel FSM) _________________________________________________________________
// Non-blocking tick loop. Probes live in slots: slot[hop][p] = 0 not sent, 1 in flight, 2 done.
// The tag ttl*probes+p is unique, so a reply goes straight to its slot. Every tick:
//   1. keyboard
//   2. send the next probes until the window is full
//   3. drain incoming replies (at most 64 per tick)
//   4. time out the expired ones
//   5. DONE once everything up to stop_ttl is settled
// Stopping: when a probe reaches the target stop_ttl drops to that hop, nothing goes past it and
// probes still in flight beyond it are dropped. Window 1 = the old one-at-a-time behavior.
enum { ST_SEND, ST_WAIT, ST_DONE };               // send_signal still uses these
#define MAX_TICK_PACKETS 64                       // The raw TCP socket sees every TCP packet on the host, keeps the loop from locking up

void track_signal(void) {
    struct in_addr target_ip;                  // Resolves the target (DNS for a hostname), opens sockets
    if (!resolve_target(current_cfg.ip, &target_ip)) return;
    Engine m;
    const char *err = engine_open(&m, target_ip, settings.window > 1);   // Parallel TCP gets a port per probe
    if (err) { engine_close(&m); error_screen(err); return; }   // Raw sockets need root
    char label[16]; engine_label(&m, label, sizeof(label));
    char target_str[96]; target_text(current_cfg.ip, target_ip, target_str, sizeof(target_str));

    int dsock = settings.dns ? dns_open() : -1;    // For hop names, carries on nameless if it fails
    PtrJob ptr[MAX_HOPS]; memset(ptr, 0, sizeof(ptr));

    int limit = current_cfg.ttl;               // Config TTL = max hop
    if (limit > MAX_HOPS) limit = MAX_HOPS;
    if (limit < 1) limit = 1;

    int probes = settings.probes;              // Frozen at session start, no changes mid-trace
    if (probes < 1) probes = 1;
    if (probes > MAX_PROBES) probes = MAX_PROBES;
    double timeout_ms = settings.timeout_ms;
    int window = settings.window;              // At most this many probes in flight
    if (window < 1) window = 1;
    if (window > MAX_WINDOW) window = MAX_WINDOW;

    HopResult hops[MAX_HOPS]; memset(hops, 0, sizeof(hops));
    int slot[MAX_HOPS][MAX_PROBES]; memset(slot, 0, sizeof(slot));  // Slot state: 0 / 1 in flight / 2 done
    struct timespec slot_at[MAX_HOPS][MAX_PROBES];                  // Send instant per slot

    int next_ttl = 1, next_p = 0;              // Next probe to send
    int stop_ttl = limit;                      // Shrinks once the target is found
    int in_flight = 0, count = 0, running = 1;
    int scroll_off = 0, follow = 1;            // Table window, follows the bottom at first

    nodelay(stdscr, TRUE);                     // getch must not block, the loop keeps turning

    while (1) {
        int k = getch();                                 // 1. Keyboard
        if (k == 27 || k == 'q' || k == 'Q') break;      // ESC back to the menu
        if (k == KEY_UP)   { scroll_off--; follow = 0; } // Looking up stops following
        if (k == KEY_DOWN) { scroll_off++; }             // draw_track turns follow back on at the bottom

        if (running) {
            while (in_flight < window && next_ttl <= stop_ttl) {   // 2. Fills the window
                int t = next_ttl - 1;
                if (next_p == 0) {             // New hop, resets its row
                    hops[t].hop = next_ttl;
                    for (int p = 0; p < MAX_PROBES; p++) hops[t].rtt[p] = -1.0;
                    hops[t].ip[0] = '\0';
                    hops[t].reached = 0;
                    hops[t].flag = 0;
                    hops[t].name[0] = '\0';
                    if (next_ttl > count) count = next_ttl;
                }
                slot_at[t][next_p] = fire_probe(&m, next_ttl, next_ttl * probes + next_p);  // Tag unique per probe
                slot[t][next_p] = 1; in_flight++;
                if (++next_p >= probes) { next_p = 0; next_ttl++; }
            }

            int tick_us = 60000;                // 3. Drains replies. First wait 60 ms, the UI never freezes
            for (int i = 0; i < MAX_TICK_PACKETS; i++) {
                char ip[INET_ADDRSTRLEN]; int reached = 0, tag = -1; char flag = 0;
                int r = read_reply(&m, tick_us, &tag, ip, &reached, &flag);
                if (r < 0) break;               // Nothing left to read
                tick_us = 0;                    // After the first, only take what piled up
                if (r == 0) continue;           // Foreign packet

                int t = tag / probes - 1, p = tag % probes;          // Tag to slot
                if (tag < probes || t >= limit || slot[t][p] != 1) continue;   // Late or already dropped
                slot[t][p] = 2; in_flight--;

                struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
                hops[t].rtt[p] = ms_between(slot_at[t][p], now);
                strcpy(hops[t].ip, ip);
                if (flag_rank(flag) > flag_rank(hops[t].flag)) hops[t].flag = flag;   // A weak verdict never overwrites a strong one
                if (reached) {
                    hops[t].reached = 1;
                    if (t + 1 < stop_ttl) {                          // Found the target closer in
                        stop_ttl = t + 1;
                        for (int tt = stop_ttl; tt < limit; tt++)    // Drops the in-flight probes past it
                            for (int pp = 0; pp < probes; pp++)
                                if (slot[tt][pp] == 1) { slot[tt][pp] = 2; in_flight--; }
                        if (count > stop_ttl) count = stop_ttl;      // Nothing past the target shows in the table
                    }
                }
            }

            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);   // 4. Expired ones time out, rtt stays -1
            for (int t = 0; t < count; t++)
                for (int p = 0; p < probes; p++)
                    if (slot[t][p] == 1 && ms_between(slot_at[t][p], now) >= timeout_ms) { slot[t][p] = 2; in_flight--; }

            if (next_ttl > stop_ttl) {          // 5. DONE once everything up to stop_ttl is settled
                int pending = 0;
                for (int t = 0; t < stop_ttl; t++)
                    for (int p = 0; p < probes; p++)
                        if (slot[t][p] == 1) pending = 1;
                if (!pending) running = 0;
            }
        } else {
            napms(30);                          // DONE: no busy loop, DNS names keep arriving
        }

        if (dsock >= 0) ptr_tick(dsock, hops, count, ptr);   // PTR for new IPs, names keep filling in after DONE

        draw_track(hops, count, running, label, probes, &scroll_off, &follow, dsock >= 0, target_str);
    }

    if (dsock >= 0) close(dsock);
    engine_close(&m);
    nodelay(stdscr, FALSE);                     // Back to the menu's blocking getch
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Send Signal Table ___________________________________________________________________________
static void draw_ping(const char *target_ip, const char *target_str, const char *label, PingRow *ring, int ring_count,
                      int sent, int recv, double rmin, double rmax, double rsum,
                      int running) {
    erase();
    int rows, cols; getmaxyx(stdscr, rows, cols);

    int w = 48; if (w > cols - 4) w = cols - 4;
    int x = (cols - w) / 2; if (x < 2) x = 2;
    int y = 2;

    int first   = y + 4;                          // First ping row, after PING + header rows
    int maxrows = rows - first - 4;               // Leaves room for stats + footer
    int total   = (ring_count < PING_RING) ? ring_count : PING_RING;
    int shown   = (total < maxrows) ? total : maxrows;
    if (shown < 0) shown = 0;
    int bottom  = first + shown;

    draw_hline(y, x, w, ACS_ULCORNER, ACS_URCORNER, -1, 0);   // Top frame + title
    mvprintw(y - 1, x, "Target: %s", target_str);
    mvprintw(y, x + 2, "[ SEND SIGNAL ]");
    const char *st = running ? "[ RUNNING ]" : "[ DONE ]";
    mvprintw(y, x + w - (int)strlen(st) - 2, "%s", st);

    mvaddch(y + 1, x, ACS_VLINE); mvaddch(y + 1, x + w - 1, ACS_VLINE);   // Target row + column headers
    mvprintw(y + 1, x + 2, "PING %s  [ %s ]", target_ip, label);
    mvaddch(y + 2, x, ACS_VLINE); mvaddch(y + 2, x + w - 1, ACS_VLINE);
    attron(A_BOLD);
    mvprintw(y + 2, x + 2, "SEQ");
    mvprintw(y + 2, x + 9, "RESULT");
    attroff(A_BOLD);
    draw_hline(y + 3, x, w, ACS_LTEE, ACS_RTEE, -1, 0);

    int start = ring_count - shown;               // Last 'shown' pings, oldest first
    for (int i = 0; i < shown; i++) {
        int ry = first + i;
        PingRow *p = &ring[(start + i) % PING_RING];
        mvaddch(ry, x, ACS_VLINE); mvaddch(ry, x + w - 1, ACS_VLINE);
        if (p->ok)              mvprintw(ry, x + 2, "%3d    time=%.2f ms  %s", p->seq, p->rtt,
                                         flag_text(p->flag));   // open / closed for TCP
        else if (flag_rank(p->flag) == 1)
                                mvprintw(ry, x + 2, "%3d    unreachable %s", p->seq,
                                         flag_text(p->flag));   // !N, !H, !X ...
        else                    mvprintw(ry, x + 2, "%3d    timeout", p->seq);
    }

    draw_hline(bottom, x, w, ACS_LTEE, ACS_RTEE, -1, 0);   // Stats divider

    int loss = sent ? (int)((sent - recv) * 100.0 / sent + 0.5) : 0;   // Stats rows
    mvaddch(bottom + 1, x, ACS_VLINE); mvaddch(bottom + 1, x + w - 1, ACS_VLINE);
    mvprintw(bottom + 1, x + 2, "sent %d  recv %d  loss %d%%", sent, recv, loss);
    mvaddch(bottom + 2, x, ACS_VLINE); mvaddch(bottom + 2, x + w - 1, ACS_VLINE);
    if (recv > 0)
        mvprintw(bottom + 2, x + 2, "min/avg/max = %.2f/%.2f/%.2f ms",
                 rmin, rsum / recv, rmax);
    else
        mvprintw(bottom + 2, x + 2, "min/avg/max = -/-/-");

    draw_hline(bottom + 3, x, w, ACS_LLCORNER, ACS_LRCORNER, -1, 0);
    mvprintw(bottom + 5, x, "  [ ESC ] stop");
    refresh();
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Send Signal (ping until ESC) ________________________________________________________________
void send_signal(void) {
    struct in_addr target_ip;
    if (!resolve_target(current_cfg.ip, &target_ip)) return;
    Engine m;
    const char *err = engine_open(&m, target_ip, 0);           // Pings go one at a time, a fixed port is enough
    if (err) { engine_close(&m); error_screen(err); return; }
    char label[16]; engine_label(&m, label, sizeof(label));
    char target_str[96]; target_text(current_cfg.ip, target_ip, target_str, sizeof(target_str));
    char ipbuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &target_ip, ipbuf, sizeof(ipbuf));

    PingRow ring[PING_RING]; int ring_count = 0;
    int sent = 0, recv = 0, seq = 1;
    double rmin = 0, rmax = 0, rsum = 0;

    int state = ST_SEND, recorded = 0;
    struct timespec sent_at = {0, 0};

    nodelay(stdscr, TRUE);

    while (1) {
        int k = getch();
        if (k == 27 || k == 'q' || k == 'Q') break;

        if (state == ST_SEND) {
            sent_at = fire_probe(&m, PING_TTL, seq);   // Fixed TTL, aimed at the target
            sent++; recorded = 0;
            state = ST_WAIT;
        }
        else {  // ST_WAIT: a 1 s window, reply or timeout, then the next ping
            char ip[INET_ADDRSTRLEN]; int reached = 0; char flag = 0;
            int tag = -1;
            int got = (read_reply(&m, 60000, &tag, ip, &reached, &flag) == 1 &&  // Polls every pass so it never spins
                       same_tag(&m, tag, seq));                                 // A late reply to the previous ping does not count
            if (!recorded && got) {
                struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
                double rtt = (now.tv_sec - sent_at.tv_sec) * 1000.0 +
                             (now.tv_nsec - sent_at.tv_nsec) / 1000000.0;
                if (flag_rank(flag) == 1) {                         // Path cut, does not count as a success
                    ring[ring_count % PING_RING] = (PingRow){ seq, rtt, 0, flag };
                } else {
                    ring[ring_count % PING_RING] = (PingRow){ seq, rtt, 1, flag };
                    recv++;
                    if (recv == 1 || rtt < rmin) rmin = rtt;
                    if (rtt > rmax) rmax = rtt;
                    rsum += rtt;
                }
                ring_count++; recorded = 1;
            }

            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
            double elapsed = (now.tv_sec - sent_at.tv_sec) * 1000.0 +
                             (now.tv_nsec - sent_at.tv_nsec) / 1000000.0;
            if (!recorded && elapsed >= PING_INTERVAL_MS) {       // Window closed, no reply
                ring[ring_count % PING_RING] = (PingRow){ seq, 0, 0, 0 };
                ring_count++; recorded = 1;
            }
            if (elapsed >= PING_INTERVAL_MS) { seq++; state = ST_SEND; }  // Next ping
        }

        draw_ping(ipbuf, target_str, label, ring, ring_count, sent, recv, rmin, rmax, rsum, 1);
    }

    engine_close(&m);
    nodelay(stdscr, FALSE);
}
////////////////////////////////////////////////////////////////////////////////////////////////

// Main Menu ___________________________________________________________________________________
static const char *menu_options[] = {
    "Send Signal",
    "Track Signal",
    "Configuration",
    "Settings",
    "Quit",
};
#define MENU_SIZE ((int)(sizeof(menu_options) / sizeof(menu_options[0])))

static void draw_main_menu(int highlight) {
    erase();

    int rows, cols;                                      // Centers on the terminal
    getmaxyx(stdscr, rows, cols);

    int block_w = 60;  // Left menu + right summary, roughly
    int block_h = 4 + MENU_SIZE + 2;
    int ox = (cols - block_w) / 2;
    int oy = (rows - block_h) / 2;
    if (ox < 2) ox = 2;
    if (oy < 1) oy = 1;

    attron(A_BOLD);
    mvprintw(oy, ox, " Signal Commander TUI ");
    attroff(A_BOLD);
    mvhline(oy + 1, ox, ACS_HLINE, 22);

    for (int i = 0; i < MENU_SIZE; i++) {
        if (i == highlight) attron(A_REVERSE);
        mvprintw(oy + 3 + i, ox + 2, "  %-18s", menu_options[i]);
        if (i == highlight) attroff(A_REVERSE);
    }

    mvprintw(oy + 3, ox + 28, "Current target:");        // Config summary on the right
    mvprintw(oy + 4, ox + 30, "Host  : %s", current_cfg.ip);
    mvprintw(oy + 5, ox + 30, "Port  : %d", current_cfg.port);
    mvprintw(oy + 6, ox + 30, "TTL   : %d", current_cfg.ttl);
    mvprintw(oy + 7, ox + 30, "Proto : %s", current_cfg.proto);

    mvprintw(oy + 3 + MENU_SIZE + 1, ox, "  UP/DOWN navigate   ENTER select");
    refresh();
}

int main(void) {
    initscr();
    cbreak();
    noecho();                  // Never turned back on
    keypad(stdscr, TRUE);
    curs_set(0);

    if (has_colors()) {
        start_color();
        init_pair(CP_NORMAL, COLOR_WHITE, COLOR_BLACK);
        init_pair(CP_ERROR,  COLOR_WHITE, COLOR_RED);
        init_pair(CP_OK,     COLOR_BLACK, COLOR_GREEN);
    }

    int highlight = 0;

    while (1) {
        draw_main_menu(highlight);
        int ch = getch();
        switch (ch) {
        case KEY_UP:
            highlight = (highlight > 0) ? highlight - 1 : MENU_SIZE - 1;
            break;
        case KEY_DOWN:
            highlight = (highlight < MENU_SIZE - 1) ? highlight + 1 : 0;
            break;
        case '\n':
        case KEY_ENTER:
            if (highlight == 0)         send_signal();
            else if (highlight == 1)    track_signal();
            else if (highlight == 2)    open_configuration();
            else if (highlight == 3)    open_settings();
            else if (highlight == 4)    goto quit;
            break;
        }
    }

quit:
    endwin();
    printf("Signal Commander is down. Out!\n");
    return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////
