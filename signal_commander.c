/*
 * signal_commander.c  —  ncurses TUI for ping/traceroute style tool
 *
 * Derleme:  gcc signal_commander.c -lncurses -o signal_commander
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <arpa/inet.h>        /* INET_ADDRSTRLEN icin */
#include <unistd.h>           /* getpid, close */
#include <time.h>             /* clock_gettime, CLOCK_MONOTONIC */
#include <sys/time.h>         /* struct timeval */
#include <sys/socket.h>
#include <sys/select.h>       /* select, fd_set */
#include <netinet/ip.h>       /* struct iphdr */
#include <netinet/ip_icmp.h>  /* struct icmphdr, ICMP_* */
#include <netinet/tcp.h>      /* struct tcphdr */
#include <netinet/udp.h>      /* struct udphdr */
#include <stdint.h>           /* uint16_t, uint32_t */

#define MAX_HOPS    30
#define PROBES      3
#define TIMEOUT_SEC 2

#define PING_TTL          64     /* ping'de TTL sabit-buyuk, hedefe ulassin */
#define PING_RING         16     /* ekranda tutulan son ping satiri sayisi */
#define PING_INTERVAL_MS  1000   /* pingler arasi sure + cevap penceresi */

/* ═══════════════════════════════════════════════════
 *  DATA MODEL
 * ═══════════════════════════════════════════════════ */
typedef struct {
    char ip[64];
    int  port;
    int  ttl;
    char proto[8];
} Config;

static Config current_cfg = {"127.0.0.1", 80, 64, "ICMP"};

/* Bir hop: PROBES kadar probe'un sonucu tek satirda */
typedef struct {
    int    hop;
    char   ip[INET_ADDRSTRLEN];  /* bos ise hicbir probe cevap vermedi -> * * * */
    double rtt[PROBES];          /* -1 = o probe timeout */
    int    reached;              /* 1 = hedefin kendisi cevapladi */
    char   flag;                 /* TCP/UDP: 'O' acik, 'C' kapali, 'U' ulasilamaz. 0 = duz hop */
} HopResult;

/* Bir ping sonucu: seq numarasi + rtt. ok=0 ise timeout (flag 'U' ise unreachable) */
typedef struct {
    int    seq;
    double rtt;
    int    ok;
    char   flag;                 /* HopResult ile ayni harfler */
} PingSat;

/* ═══════════════════════════════════════════════════
 *  FIELD METADATA
 *
 *  FLD_IP    : "x.x.x.x" formatı, her octet 0-255
 *  FLD_INT   : tam sayı, max_val'a kadar
 *  FLD_STR   : printable ASCII serbest metin
 *  FLD_CYCLE : önceden tanımlı seçenekler arasında ←/→ ile gezinme
 * ═══════════════════════════════════════════════════ */
typedef enum { FLD_STR, FLD_INT, FLD_IP, FLD_CYCLE } FldType;

typedef struct {
    const char  *label;
    FldType      type;
    int          maxlen;        /* string buffer boyutu (FLD_STR/IP için) */
    int          max_val;       /* FLD_INT üst sınırı */
    const char **options;       /* FLD_CYCLE seçenekleri */
    int          opt_count;
} FldMeta;

static const char *PROTO_OPTS[] = { "ICMP", "TCP", "UDP" };

#define CFG_FIELDS 4

static const FldMeta FIELDS[CFG_FIELDS] = {
    { "Target Host", FLD_IP,    15,     0, NULL,       0 },
    { "Port",        FLD_INT,    5, 65535, NULL,       0 },
    { "TTL",         FLD_INT,    3,   255, NULL,       0 },
    { "Protocol",    FLD_CYCLE,  0,     0, PROTO_OPTS, 3 },
};

/* Config struct <-> string dönüşümleri */
static void field_to_str(const Config *c, int idx, char *out, int outlen) {
    switch (idx) {
        case 0: snprintf(out, outlen, "%s", c->ip);    break;
        case 1: snprintf(out, outlen, "%d", c->port);  break;
        case 2: snprintf(out, outlen, "%d", c->ttl);   break;
        case 3: snprintf(out, outlen, "%s", c->proto); break;
    }
}

static void str_to_field(Config *c, int idx, const char *s) {
    if (!s || s[0] == '\0') return;
    switch (idx) {
        case 0: snprintf(c->ip,    sizeof(c->ip),    "%s", s); break;
        case 1: c->port = atoi(s); break;
        case 2: c->ttl  = atoi(s); break;
        case 3: snprintf(c->proto, sizeof(c->proto), "%s", s); break;
    }
}

/* ═══════════════════════════════════════════════════
 *  LAYOUT
 *
 *  Layout sabitleri "mutable" globaller + ayni isimli
 *  makrolar olarak. recompute_layout() terminal boyutuna
 *  gore bunlari her cizimden once gunceller, makrolar
 *  kullanildigi yerde guncel degeri okur.
 *
 *  Bu sayede mevcut kod (BOX_Y, BOX_X, ...) hic
 *  degismeden kaliyor ama artik dinamik.
 * ═══════════════════════════════════════════════════ */
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

/* Renk çiftleri */
#define CP_NORMAL  1
#define CP_ERROR   2
#define CP_OK      3

/*
 * Terminal boyutuna gore kutuyu ortala ve gerekirse
 * genisligi terminale sigdir. Min 40, max 60 kolon
 * genisliginde tutar; dikeyde de ortalar.
 */
static void recompute_layout(void) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    /* Genislik: terminale uygun ama makul sinirlar icinde */
    g_box_w = cols - 4;
    if (g_box_w > 60) g_box_w = 60;
    if (g_box_w < 40) g_box_w = 40;

    g_box_h = 10;

    /* Yatayda ortala */
    g_box_x = (cols - g_box_w) / 2;
    if (g_box_x < 1) g_box_x = 1;

    /* Dikeyde ortala (footer + status icin asagida pay birak) */
    int needed = g_box_h + 4;
    g_box_y = (rows - needed) / 2;
    if (g_box_y < 1) g_box_y = 1;
}

/* ═══════════════════════════════════════════════════
 *  KUTU ÇİZİMİ
 * ═══════════════════════════════════════════════════ */
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

static void draw_box_frame(void) {
    draw_hline(BOX_Y, BOX_X, BOX_W,
               ACS_ULCORNER, ACS_URCORNER, SEP_X, ACS_TTEE);

    for (int i = 1; i < BOX_H - 1; i++) {
        int row = BOX_Y + i;
        mvaddch(row, BOX_X,             ACS_VLINE);
        mvaddch(row, BOX_X + BOX_W - 1, ACS_VLINE);
        int is_header = (row == HEADER_ROW);
        int is_field  = (row >= FIRST_ROW && row < FIRST_ROW + CFG_FIELDS);
        if (is_header || is_field)
            mvaddch(row, SEP_X, ACS_VLINE);
    }

    draw_hline(HEADER_ROW + 1, BOX_X, BOX_W,
               ACS_LTEE, ACS_RTEE, SEP_X, ACS_PLUS);
    draw_hline(FIRST_ROW + CFG_FIELDS, BOX_X, BOX_W,
               ACS_LTEE, ACS_RTEE, SEP_X, ACS_BTEE);
    draw_hline(BOX_Y + BOX_H - 1, BOX_X, BOX_W,
               ACS_LLCORNER, ACS_LRCORNER, -1, 0);
}

/* ═══════════════════════════════════════════════════
 *  STATUS BAR
 *
 *  KRITIK: Bu fonksiyonlar imleci status satirina tasiyor
 *  ama input siralinda imlec gerek. O yuzden mevcut
 *  imlec pozisyonunu kaydet, isi yap, geri yukle.
 * ═══════════════════════════════════════════════════ */
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

/* ═══════════════════════════════════════════════════
 *  IP DOĞRULAMA  (commit anında)
 * ═══════════════════════════════════════════════════ */
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

/* ═══════════════════════════════════════════════════
 *  CONFIG EKRANI — STATE MACHINE
 * ═══════════════════════════════════════════════════ */
typedef enum { MODE_NAV, MODE_EDIT } CfgMode;

static void draw_config(const Config *tmp, int sel, CfgMode mode) {
    recompute_layout();
    erase();
    draw_box_frame();

    mvprintw(BOX_Y, BOX_X + 2, "[ CONFIGURATION ]");
    const char *mode_str = (mode == MODE_NAV) ? "[ NAV MODE ]" : "[ EDIT MODE ]";
    mvprintw(BOX_Y, BOX_X + BOX_W - (int)strlen(mode_str) - 2, "%s", mode_str);

    attron(A_BOLD);
    mvprintw(HEADER_ROW, L_X, "%-*s", L_W - 1, "FIELD");
    mvprintw(HEADER_ROW, R_X, "VALUE");
    attroff(A_BOLD);

    char valbuf[64];
    for (int i = 0; i < CFG_FIELDS; i++) {
        int row    = FIRST_ROW + i;
        int is_sel = (sel == i);

        field_to_str(tmp, i, valbuf, sizeof(valbuf));

        /* Label hucresi */
        int lattr = 0;
        if (is_sel)
            lattr = (mode == MODE_NAV) ? A_REVERSE : A_BOLD;

        if (lattr) attron(lattr);
        mvprintw(row, L_X, " %-*s ", L_W - 3, FIELDS[i].label);
        if (lattr) attroff(lattr);

        /* Value hucresi:
         * EDIT modunda + secili + text field ise underscore'lu giris alani goster.
         * Diger durumlarda mevcut degeri yaz (gerekiyorsa highlight ile). */
        if (is_sel && mode == MODE_EDIT && FIELDS[i].type != FLD_CYCLE) {
            int ml = FIELDS[i].maxlen;
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

    int save_sel   = (sel == CFG_FIELDS);
    int cancel_sel = (sel == CFG_FIELDS + 1);

    /* Butonlari kutu yarilarinin ortasina yerlestir
     * (BOX_W degisirse yine ortali kalsin diye dinamik) */
    int sw = 12;  /* "  [ SAVE ]  " genisligi   */
    int cw = 14;  /* "  [ CANCEL ]  " genisligi */
    int half = BOX_W / 2;
    int save_x   = BOX_X + (half - sw) / 2;
    int cancel_x = BOX_X + half + (half - cw) / 2;

    if (save_sel)   attron(A_REVERSE);
    mvprintw(BTN_ROW, save_x,   "  [ SAVE ]  ");
    if (save_sel)   attroff(A_REVERSE);

    if (cancel_sel) attron(A_REVERSE);
    mvprintw(BTN_ROW, cancel_x, "  [ CANCEL ]  ");
    if (cancel_sel) attroff(A_REVERSE);

    /* Footer */
    const char *hint;
    if (mode == MODE_NAV) {
        if (sel >= CFG_FIELDS)
            hint = "  LEFT/RIGHT swap   ENTER select   UP back to fields";
        else
            hint = "  UP/DOWN navigate   ENTER edit/select   q quit";
    } else if (sel < CFG_FIELDS && FIELDS[sel].type == FLD_CYCLE)
        hint = "  LEFT/RIGHT cycle   ENTER commit   ESC abort";
    else
        hint = "  type value   ENTER commit   ESC abort";
    mvprintw(BOX_Y + BOX_H + 1, BOX_X, "%s", hint);

    refresh();
}

/* ═══════════════════════════════════════════════════
 *  TEXT INPUT — FLD_STR, FLD_INT, FLD_IP
 *
 *  KRITIK: noecho() aktif kalir. Karakterleri ELLE
 *  addch() ile yazdiririz. echo() acarsak ncurses
 *  her tusa otomatik basar, biz de basariz -> cift yazim.
 * ═══════════════════════════════════════════════════ */
static int read_text(int y, int x, const FldMeta *meta, char *buf) {
    curs_set(1);

    /* Underscore'lu giris alani: gorsel sinir */
    for (int i = 0; i < meta->maxlen; i++)
        mvaddch(y, x + i, ' ' | A_UNDERLINE);
    move(y, x);
    refresh();

    int len = 0;
    buf[0] = '\0';

    while (1) {
        int c = getch();

        /* ── ENTER -> validate + commit ─────────────── */
        if (c == '\n' || c == KEY_ENTER) {
            buf[len] = '\0';

            if (meta->type == FLD_INT && len > 0) {
                long v = atol(buf);
                if (v < 0 || v > meta->max_val) {
                    char msg[64];
                    snprintf(msg, sizeof(msg),
                             "Value out of range (0-%d)", meta->max_val);
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

            clear_status();
            break;
        }

        /* ── ESC -> abort ────────────────────────────── */
        if (c == 27) {
            buf[0] = '\0';
            curs_set(0);
            clear_status();
            return 0;
        }

        /* ── Backspace: len-based, cursor-bagimsiz ─── */
        if (c == KEY_BACKSPACE || c == 127 || c == 8) {
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

        /* ── Normal karakter: filtre ─────────────────── */
        if (len >= meta->maxlen) continue;

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

/* ═══════════════════════════════════════════════════
 *  CYCLE INPUT — FLD_CYCLE (Protocol)
 *
 *  Goruntu: " < ICMP >  "  — okkucuk olar sol/sag tuslarini
 *  cagristirir (affordance). Yan paddingler hucreyi
 *  R_W chars genis tutar.
 * ═══════════════════════════════════════════════════ */
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

/* ─── Config ekrani ana dongusu ─────────────────────── */
void open_configuration(void) {
    Config tmp = current_cfg;
    int sel    = 0;
    CfgMode mode = MODE_NAV;

    /*
     * Navigasyon modeli:
     *   sel 0..3   : field'lar (dikey grup)
     *   sel 4      : SAVE buton
     *   sel 5      : CANCEL buton
     *
     *   Field icinde:  UP/DOWN field'lar arasi
     *   Field 3 + DOWN -> butonlara gec (SAVE)
     *   Field 0 + UP   -> butonlara cik (SAVE)
     *   Buton + UP     -> son field'a don
     *   Buton + DOWN   -> ilk field'a wrap
     *   Buton + LEFT/RIGHT -> butonlar arasi swap
     */
    while (1) {
        draw_config(&tmp, sel, mode);
        int key = getch();

        switch (key) {
        case KEY_UP:
            if (sel >= CFG_FIELDS)
                sel = CFG_FIELDS - 1;          /* buton -> son field */
            else
                sel = (sel > 0) ? sel - 1 : CFG_FIELDS;  /* 0 -> Save */
            clear_status();
            break;
        case KEY_DOWN:
            if (sel < CFG_FIELDS)
                sel = (sel < CFG_FIELDS - 1) ? sel + 1 : CFG_FIELDS;
            else
                sel = 0;                       /* buton -> ilk field */
            clear_status();
            break;
        case KEY_LEFT:
        case KEY_RIGHT:
            if (sel >= CFG_FIELDS)
                sel = (sel == CFG_FIELDS) ? CFG_FIELDS + 1 : CFG_FIELDS;
            clear_status();
            break;
        case '\n':
        case KEY_ENTER:
            if (sel < CFG_FIELDS) {
                const FldMeta *meta = &FIELDS[sel];
                mode = MODE_EDIT;
                draw_config(&tmp, sel, mode);

                char buf[64] = {0};
                int  row = FIRST_ROW + sel;
                int  ok;

                if (meta->type == FLD_CYCLE) {
                    char init[8];
                    field_to_str(&tmp, sel, init, sizeof(init));
                    ok = read_cycle(row, R_X + 1, meta, init, buf);
                } else {
                    ok = read_text(row, R_X + 1, meta, buf);
                }

                if (ok && buf[0] != '\0')
                    str_to_field(&tmp, sel, buf);

                mode = MODE_NAV;
            } else if (sel == CFG_FIELDS) {
                current_cfg = tmp;
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

/* ═══════════════════════════════════════════════════
 *  TRACK SIGNAL — HOP TABLOSU CIZIMI
 * ═══════════════════════════════════════════════════ */
/* Flag harfini ekranda okunur hale getir */
static const char *flag_yazi(char f) {
    if (f == 'O') return "open";
    if (f == 'C') return "closed";
    if (f == 'U') return "!U";
    return "";
}

static void draw_track(HopResult *hops, int count, int running, const char *etiket) {
    erase();
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int w = 62; if (w > cols - 4) w = cols - 4;   /* IP + 3 RTT kolonu sigsin diye genis */
    int x = (cols - w) / 2; if (x < 2) x = 2;
    int y = 2;

    int first   = y + 3;                    /* ilk hop satiri */
    int maxrows = rows - first - 3;         /* asagida footer payi */
    int shown   = (count < maxrows) ? count : maxrows;
    if (shown < 0) shown = 0;
    int bottom  = first + shown;            /* alt cerceve satiri */

    /* ust cerceve + basliklar */
    draw_hline(y, x, w, ACS_ULCORNER, ACS_URCORNER, -1, 0);
    mvprintw(y, x + 2, "[ TRACK SIGNAL ]");
    mvprintw(y, x + 19, "[ %s ]", etiket);           /* hangi protokol + port ile */
    const char *st = running ? "[ RUNNING ]" : "[ DONE ]";
    mvprintw(y, x + w - (int)strlen(st) - 2, "%s", st);

    /* kolon basliklari */
    mvaddch(y + 1, x, ACS_VLINE); mvaddch(y + 1, x + w - 1, ACS_VLINE);
    attron(A_BOLD);
    mvprintw(y + 1, x + 2,  "HOP");
    mvprintw(y + 1, x + 7,  "IP ADDRESS");
    for (int p = 0; p < PROBES; p++) {              /* baslik da deger de sag hizali, alt alta gelsin */
        char lbl[8]; snprintf(lbl, sizeof(lbl), "RTT %d", p + 1);
        mvprintw(y + 1, x + 24 + p * 10, "%6s", lbl);
    }
    attroff(A_BOLD);

    draw_hline(y + 2, x, w, ACS_LTEE, ACS_RTEE, -1, 0);  /* baslik ayiraci */

    /* hop satirlari */
    for (int i = 0; i < shown; i++) {
        int ry = first + i;
        mvaddch(ry, x, ACS_VLINE); mvaddch(ry, x + w - 1, ACS_VLINE);
        HopResult *h = &hops[i];

        if (h->ip[0] == '\0') {                         /* hic cevap yok */
            mvprintw(ry, x + 2, "%2d   * * *", h->hop);
        } else {
            mvprintw(ry, x + 2, "%2d   %-15s", h->hop, h->ip);
            for (int p = 0; p < PROBES; p++) {          /* her probe kendi kolonuna, sag hizali */
                int cx = x + 24 + p * 10;
                (h->rtt[p] < 0) ? mvprintw(ry, cx, "%6s", "*")
                                : mvprintw(ry, cx, "%6.2f ms", h->rtt[p]);
            }
            if (h->flag && x + 54 + 6 < x + w - 1)     /* TCP karari, cerceveye tasmasin */
                mvprintw(ry, x + 54, "%s", flag_yazi(h->flag));
        }
    }

    draw_hline(bottom, x, w, ACS_LLCORNER, ACS_LRCORNER, -1, 0);
    mvprintw(bottom + 2, x, "  [ ESC ] abort   [ UP/DOWN ] scroll");
    refresh();
}

/* ═══════════════════════════════════════════════════
 *  SINYAL MOTORU  (raw ICMP)
 *
 *  trace.c'den gelen kanitlanmis kutular. Tek fark:
 *  cevap bekleme artik BLOKLAMIYOR. Paket cozme isi
 *  paket_coz'a ayrildi; select + recvfrom, track_signal'in
 *  tick dongusunde donuyor.
 * ═══════════════════════════════════════════════════ */
static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b; unsigned int sum = 0; unsigned short result;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF); sum += (sum >> 16);
    result = ~sum; return result;
}

/* Raw ICMP soketi. -1 donerse yetki yok (sudo lazim), cagiran hallediyor */
static int icmp_soket_ac(void) {
    return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

/* Tek probe kur ve at. ttl = ne kadar gidecek, seq = cevabi eslestirme etiketi.
 * Geri donen: gonderim ani (rtt bunun uzerinden olculur) */
static struct timespec probe_gonder(int sock, struct sockaddr_in *hedef, int ttl, int seq) {
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));   /* her hop'ta artan tek sey */

    char packet[64]; memset(packet, 0, sizeof(packet));
    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO; icmp->code = 0;                    /* echo request, type 8 */
    icmp->un.echo.id       = htons(getpid() & 0xFFFF);         /* id = pid, imzam */
    icmp->un.echo.sequence = htons(seq);                       /* probe basina benzersiz */
    memset(packet + sizeof(struct icmphdr), 'A', 32);
    icmp->checksum = checksum(packet, sizeof(struct icmphdr) + 32);  /* alan 0'ken hesapla */

    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);     /* atmadan hemen once saat */
    if (sendto(sock, packet, sizeof(struct icmphdr) + 32, 0,
               (struct sockaddr *)hedef, sizeof(*hedef)) < 0) { /* patlarsa bu probe timeout gorunur */ }
    return t;
}

/* ═══════════════════════════════════════════════════
 *  TCP MOTORU  (raw SYN)
 *
 *  tcptrace.c'den gelen kanitlanmis kutular. SYN'i elle
 *  kuruyoruz, IP header'i kernel kuruyor. Router'lar ICMP
 *  Time Exceeded ile, hedef SYN-ACK (acik) ya da RST
 *  (kapali) ile cevap veriyor.
 *
 *  Kimlik: kaynak port oturum boyu sabit (ECMP ayni yolu
 *  secsin), probe etiketi TCP seq'in icinde:
 *  seq = pid << 16 | tag. ICMP quote'unda ilk 8 bayt
 *  (portlar + seq) garanti, eslestirme oradan.
 * ═══════════════════════════════════════════════════ */

/* TCP checksum'in kapsadigi ama gonderilmeyen 12 bayt.
 * Kernel'in kuracagi IP header'in ozeti. */
struct pseudo_hdr {
    uint32_t src, dst;            /* kaynak + hedef ip, network order */
    uint8_t  zero, proto;         /* hep 0, sonra IPPROTO_TCP */
    uint16_t len;                 /* TCP header + payload uzunlugu */
};

/* Bir oturumun (track ya da send) motoru: protokol, soketler, kimlik.
 * ICMP'de sadece isock dolu. TCP'de tsock + src + sport da var.
 * UDP'de sport bir port blogunun basi, probe'lar ayri soketlerden gider. */
typedef struct {
    int                proto;     /* IPPROTO_ICMP, IPPROTO_TCP ya da IPPROTO_UDP */
    struct sockaddr_in hedef;     /* sin_port TCP ve UDP'de anlamli */
    struct in_addr     src;       /* pseudo-header icin kaynak ip */
    unsigned short     my_id;     /* pid, imzam */
    uint16_t           sport;     /* TCP: sabit kaynak port. UDP: blok basi */
    int                isock;     /* raw ICMP: echo reply, time exceeded, unreachable */
    int                tsock;     /* raw TCP: SYN at, SYN-ACK / RST dinle. ICMP'de -1 */
} Motor;

/* TCP seq: ust 16 bit pid, alt 16 bit probe etiketi */
static uint32_t syn_seq(const Motor *m, int tag) {
    return ((uint32_t)m->my_id << 16) | (uint16_t)tag;
}

/* Pseudo-header kaynak ip istiyor ama onu kernel seciyor. Connect
 * edilmis UDP soketi kernel'e rota aramasi yaptirir, getsockname
 * cevabi verir. Kabloya hicbir sey cikmaz. 0 = rota yok. */
static int kaynak_ip_bul(struct sockaddr_in *hedef, struct in_addr *out) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    if (connect(s, (struct sockaddr *)hedef, sizeof(*hedef)) < 0) { close(s); return 0; }
    struct sockaddr_in yerel; socklen_t l = sizeof(yerel);
    int ok = (getsockname(s, (struct sockaddr *)&yerel, &l) == 0);
    close(s);
    if (ok) *out = yerel.sin_addr;
    return ok;
}

/* Tek SYN kur ve at. pseudo + TCP header yan yana, ikisinin
 * checksum'i alinir, sadece TCP kismi gonderilir. */
static struct timespec tcp_probe_gonder(Motor *m, int ttl, uint32_t seq) {
    setsockopt(m->tsock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));   /* her hop'ta artan tek sey */

    char packet[sizeof(struct pseudo_hdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct pseudo_hdr *ph  = (struct pseudo_hdr *)packet;
    struct tcphdr     *tcp = (struct tcphdr *)(packet + sizeof(struct pseudo_hdr));

    tcp->source = htons(m->sport);             /* oturum boyu sabit */
    tcp->dest   = m->hedef.sin_port;           /* test edilen port */
    tcp->seq    = htonl(seq);                  /* pid + etiket, ICMP quote'unda geri gelir */
    tcp->doff   = 5;                           /* 20 bayt, opsiyon yok */
    tcp->syn    = 1;
    tcp->window = htons(64240);                /* makul pencere, 0'i dusuren kutular var */

    ph->src   = m->src.s_addr;                 /* kernel'in basacagi kaynak */
    ph->dst   = m->hedef.sin_addr.s_addr;
    ph->proto = IPPROTO_TCP;
    ph->len   = htons(sizeof(struct tcphdr));
    tcp->check = checksum(packet, sizeof(packet));   /* alan 0'ken hesapla */

    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    if (sendto(m->tsock, tcp, sizeof(struct tcphdr), 0,
               (struct sockaddr *)&m->hedef, sizeof(m->hedef)) < 0) { /* patlarsa timeout gorunur */ }
    return t;
}

/* ═══════════════════════════════════════════════════
 *  UDP MOTORU  (kernel gonderir)
 *
 *  udptrace.c'den gelen kutular. Datagrami kernel kuruyor,
 *  biz sadece TTL ve kaynak portu seciyoruz. Router'lar
 *  Time Exceeded, hedef Port Unreachable ile cevap veriyor,
 *  ikisi de raw ICMP soketinden okunuyor.
 *
 *  Kimlik: ICMP quote'unun 8 bayti UDP header'in tamami.
 *  Hedef port config'den sabit, o yuzden etiket kaynak
 *  portta: port = blok basi + tag % UDP_BLOK. Bedeli:
 *  5-tuple probe'dan probe'a degisir, ECMP yolu oynayabilir.
 * ═══════════════════════════════════════════════════ */
#define UDP_BLOK 100                   /* oturum basina port, track en fazla 92 etiket kullanir */

static uint16_t udp_port(const Motor *m, int tag) {
    return m->sport + (uint16_t)(tag % UDP_BLOK);
}

/* Tek datagram: taze soket, etiket portuna bind, TTL, bos payload, kapat.
 * bind ya da sendto patlarsa {0,0} doner, FSM o probe'u hemen timeout sayar. */
static struct timespec udp_probe_gonder(Motor *m, int ttl, int tag) {
    struct timespec t = {0, 0};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return t;

    struct sockaddr_in yerel; memset(&yerel, 0, sizeof(yerel));
    yerel.sin_family = AF_INET; yerel.sin_addr.s_addr = htonl(INADDR_ANY);
    yerel.sin_port = htons(udp_port(m, tag));                  /* kaynak port = probe etiketi */
    if (bind(s, (struct sockaddr *)&yerel, sizeof(yerel)) < 0) { close(s); return t; }
    setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));      /* her hop'ta artan tek sey */

    clock_gettime(CLOCK_MONOTONIC, &t);
    if (sendto(s, "", 0, 0, (struct sockaddr *)&m->hedef, sizeof(m->hedef)) < 0) {
        t.tv_sec = 0; t.tv_nsec = 0;                            /* hic cikmadi */
    }
    close(s);                                                  /* cevap zaten raw ICMP soketine gelir */
    return t;
}

/* Protokole gore dogru probe'u at. tag = ICMP seq, TCP seq'in alt yarisi ya da UDP port ofseti */
static struct timespec probe_at(Motor *m, int ttl, int tag) {
    if (m->proto == IPPROTO_TCP) return tcp_probe_gonder(m, ttl, syn_seq(m, tag));
    if (m->proto == IPPROTO_UDP) return udp_probe_gonder(m, ttl, tag);
    return probe_gonder(m->isock, &m->hedef, ttl, tag);
}

/* ICMP soketinden gelen paketi coz: bizim probe'umuzun cevabi mi?
 * Evetse ip_out'a cevaplayani, reached_out'a "dur" kararini,
 * flag_out'a karar harfini yazar, 1 doner.
 * Gomulu paketin protokolune gore dallanir: ICMP'de id + seq,
 * TCP'de portlar + seq, UDP'de portlar ile eslesir. */
static int paket_coz(char *buf, int n, struct sockaddr_in *kaynak, Motor *m, int tag,
                     char *ip_out, int *reached_out, char *flag_out) {
    if (n < (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr)) return 0;
    struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;    /* dis IP header'i atla */
    if (n < iplen + (int)sizeof(struct icmphdr)) return 0;
    struct icmphdr *icmp = (struct icmphdr *)(buf + iplen);
    *flag_out = 0;

    if (icmp->type == ICMP_ECHOREPLY) {                     /* A: hedef cevapladi */
        if (m->proto != IPPROTO_ICMP) return 0;             /* TCP/UDP modunda echo reply bizim olamaz */
        if (ntohs(icmp->un.echo.id) != m->my_id ||
            ntohs(icmp->un.echo.sequence) != tag) return 0; /* benim degil */
        *reached_out = 1;
    } else if (icmp->type == ICMP_TIME_EXCEEDED ||          /* B: router TTL'i bitirdi */
               icmp->type == ICMP_DEST_UNREACH) {           /* C: biri yolu kesti */
        int off = iplen + 8;                                /* dis IP + 8 bayt -> gomulu original */
        if (n < off + (int)sizeof(struct iphdr)) return 0;
        struct iphdr *iip = (struct iphdr *)(buf + off); int iiplen = iip->ihl * 4;
        if (iip->protocol != m->proto) return 0;            /* baska protokolun hatasi */
        if (n < off + iiplen + 8) return 0;                 /* sadece 8 bayt garanti */

        if (m->proto == IPPROTO_ICMP) {
            if (icmp->type != ICMP_TIME_EXCEEDED) return 0; /* ICMP modunda unreachable eskisi gibi yok sayilir */
            struct icmphdr *iicmp = (struct icmphdr *)(buf + off + iiplen); /* gomulu echo header'im */
            if (ntohs(iicmp->un.echo.id) != m->my_id ||
                ntohs(iicmp->un.echo.sequence) != tag) return 0;            /* benim probe'um degil */
        } else if (m->proto == IPPROTO_TCP) {
            if (iip->daddr != m->hedef.sin_addr.s_addr) return 0;           /* baska hedefe giden SYN */
            struct tcphdr *itcp = (struct tcphdr *)(buf + off + iiplen);    /* portlar + seq, otesi yok */
            if (ntohs(itcp->source) != m->sport || itcp->dest != m->hedef.sin_port ||
                ntohl(itcp->seq) != syn_seq(m, tag)) return 0;              /* benim SYN'im degil */
        } else {
            if (iip->daddr != m->hedef.sin_addr.s_addr) return 0;           /* baska hedefe giden datagram */
            struct udphdr *iudp = (struct udphdr *)(buf + off + iiplen);    /* quote'un 8 bayti tam UDP header */
            if (ntohs(iudp->source) != udp_port(m, tag) ||
                iudp->dest != m->hedef.sin_port) return 0;                  /* benim datagramim degil */
        }

        if (icmp->type == ICMP_DEST_UNREACH) {              /* trace burada biter */
            *reached_out = 1;
            *flag_out = (m->proto == IPPROTO_UDP && icmp->code == ICMP_PORT_UNREACH)
                      ? 'C' : 'U';                          /* UDP'de port unreachable = hedefe vardik, port kapali */
        }
        else *reached_out = 0;
    } else return 0;                                        /* alakasiz ICMP */

    inet_ntop(AF_INET, &kaynak->sin_addr, ip_out, INET_ADDRSTRLEN);     /* cevaplayanin adresi */
    return 1;
}

/* TCP soketinden gelen paketi coz: hedef SYN'imize SYN-ACK ya da RST mi dondu?
 * Portlar + ack = seq + 1 tutmali. Raw TCP soketi hosttaki BUTUN TCP'nin
 * kopyasini aliyor, filtre sart. */
static int tcp_coz(char *buf, int n, struct sockaddr_in *kaynak, Motor *m, int tag,
                   char *ip_out, int *reached_out, char *flag_out) {
    if (n < (int)sizeof(struct iphdr)) return 0;
    struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;
    if (ip->saddr != m->hedef.sin_addr.s_addr) return 0;                  /* hedeften gelmiyor */
    if (n < iplen + (int)sizeof(struct tcphdr)) return 0;
    struct tcphdr *tcp = (struct tcphdr *)(buf + iplen);
    if (tcp->source != m->hedef.sin_port || ntohs(tcp->dest) != m->sport) return 0; /* baska baglanti */
    if (!tcp->ack || ntohl(tcp->ack_seq) != syn_seq(m, tag) + 1) return 0;          /* baska SYN'in cevabi */

    if (tcp->syn)      *flag_out = 'O';                    /* SYN-ACK, port acik */
    else if (tcp->rst) *flag_out = 'C';                    /* RST, port kapali */
    else return 0;
    *reached_out = 1;
    inet_ntop(AF_INET, &kaynak->sin_addr, ip_out, INET_ADDRSTRLEN);
    return 1;
}

/* Bir tick boyunca soketleri yokla. Bizim cevap geldiyse 1 doner.
 * select en fazla tick_us bekler, UI donmaz. Yabanci paketler
 * sonraki turlarda bosalir. */
static int cevap_oku(Motor *m, int tag, int tick_us,
                     char *ip_out, int *reached_out, char *flag_out) {
    fd_set rfds; FD_ZERO(&rfds); FD_SET(m->isock, &rfds);
    int maxfd = m->isock;
    if (m->tsock >= 0) { FD_SET(m->tsock, &rfds); if (m->tsock > maxfd) maxfd = m->tsock; }
    struct timeval tv = { 0, tick_us };
    if (select(maxfd + 1, &rfds, NULL, NULL, &tv) <= 0) return 0;

    char buf[1024]; struct sockaddr_in kaynak; socklen_t kl;
    if (FD_ISSET(m->isock, &rfds)) {                        /* router, firewall ya da echo reply */
        kl = sizeof(kaynak);
        int n = recvfrom(m->isock, buf, sizeof(buf), 0, (struct sockaddr *)&kaynak, &kl);
        if (n > 0 && paket_coz(buf, n, &kaynak, m, tag, ip_out, reached_out, flag_out)) return 1;
    }
    if (m->tsock >= 0 && FD_ISSET(m->tsock, &rfds)) {       /* hedefin kendisi */
        kl = sizeof(kaynak);
        int n = recvfrom(m->tsock, buf, sizeof(buf), 0, (struct sockaddr *)&kaynak, &kl);
        if (n > 0 && tcp_coz(buf, n, &kaynak, m, tag, ip_out, reached_out, flag_out)) return 1;
    }
    return 0;
}

/* Config'e gore motoru kur. Hata varsa ekranda gosterilecek mesaji
 * doner, yoksa NULL. Hata durumunda da motor_kapat cagrilmali. */
static const char *motor_ac(Motor *m) {
    static int oturum = 0;                     /* her oturum yeni kaynak port */
    memset(m, 0, sizeof(*m));
    m->isock = m->tsock = -1;
    m->hedef.sin_family = AF_INET;
    if (inet_pton(AF_INET, current_cfg.ip, &m->hedef.sin_addr) <= 0)
        return "Invalid target IP. Set a valid IPv4 in Configuration.";

    if      (strcmp(current_cfg.proto, "TCP") == 0) m->proto = IPPROTO_TCP;
    else if (strcmp(current_cfg.proto, "UDP") == 0) m->proto = IPPROTO_UDP;
    else                                            m->proto = IPPROTO_ICMP;
    m->my_id = getpid() & 0xFFFF;

    m->isock = icmp_soket_ac();                /* TCP/UDP'de de lazim: time exceeded buradan gelir */
    if (m->isock < 0) return "Cannot open raw socket. Run with sudo (root needed).";

    if (m->proto == IPPROTO_TCP) {
        if (current_cfg.port < 1) return "TCP needs a port between 1 and 65535.";
        m->hedef.sin_port = htons(current_cfg.port);
        if (!kaynak_ip_bul(&m->hedef, &m->src)) return "No route to target.";
        m->tsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (m->tsock < 0) return "Cannot open raw TCP socket. Run with sudo (root needed).";
        m->sport = 40000 + ((getpid() + oturum++) % 20000);  /* gec gelen eski SYN-ACK karismasin */
    }
    if (m->proto == IPPROTO_UDP) {
        if (current_cfg.port < 1) return "UDP needs a port between 1 and 65535.";
        m->hedef.sin_port = htons(current_cfg.port);
        m->sport = 40000 + ((getpid() + oturum++) % 200) * UDP_BLOK;  /* oturum basina ayri blok */
    }
    return NULL;
}

static void motor_kapat(Motor *m) {
    if (m->isock >= 0) close(m->isock);
    if (m->tsock >= 0) close(m->tsock);
    m->isock = m->tsock = -1;
}

/* Basliktaki protokol etiketi: "ICMP", "TCP 443" ya da "UDP 33434" */
static void motor_etiket(const Motor *m, char *out, int len) {
    if      (m->proto == IPPROTO_TCP) snprintf(out, len, "TCP %d", ntohs(m->hedef.sin_port));
    else if (m->proto == IPPROTO_UDP) snprintf(out, len, "UDP %d", ntohs(m->hedef.sin_port));
    else                              snprintf(out, len, "ICMP");
}

/* Motor kurulamadiysa sebebini goster, tusa basinca menuye don */
static void motor_hata(const char *msg) {
    erase();
    mvprintw(2, 4, "%s", msg);
    mvprintw(4, 4, "Press any key to return.");
    refresh(); getch();
}

/* ═══════════════════════════════════════════════════
 *  TRACK SIGNAL — GERCEK FSM
 *
 *  Bloklamayan tick dongusu. Her turda: klavyeyi yokla,
 *  state makinesini bir adim ilerlet, tabloyu ciz.
 *
 *    SEND : probe at (ttl, seq), sent_at kaydet -> WAIT
 *    WAIT : select ile soketi kisa yokla + deadline'a bak
 *           cevap geldi YA DA timeout -> ilerle
 *    DONE : hedefe varildi ya da ttl limiti doldu; tablo dursun
 *
 *  ilerle: probe++ ; 3 dolunca hop++ (ya da DONE)
 * ═══════════════════════════════════════════════════ */
enum { ST_SEND, ST_WAIT, ST_DONE };

void track_signal(void) {
    /* Hedefi + protokolu config'den al, soketleri ac */
    Motor m;
    const char *hata = motor_ac(&m);
    if (hata) { motor_kapat(&m); motor_hata(hata); return; }   /* raw socket root ister */
    char etiket[16]; motor_etiket(&m, etiket, sizeof(etiket));

    int limit = current_cfg.ttl;               /* config'deki TTL = max hop */
    if (limit > MAX_HOPS) limit = MAX_HOPS;
    if (limit < 1) limit = 1;

    HopResult hops[MAX_HOPS]; memset(hops, 0, sizeof(hops));

    int ttl = 1, probe = 0, count = 0, seq = 0;
    int state = ST_SEND, running = 1;
    struct timespec sent_at = {0, 0};

    nodelay(stdscr, TRUE);                     /* getch bloklamasin, dongu donsun */

    while (1) {
        /* ── 1. Klavye ──────────────────────────────── */
        int k = getch();
        if (k == 27 || k == 'q' || k == 'Q') break;   /* ESC -> menuye don */

        /* ── 2. FSM adimi ───────────────────────────── */
        if (state == ST_SEND) {
            if (probe == 0) {                  /* yeni hop: satiri sifirla */
                hops[ttl-1].hop = ttl;
                for (int p = 0; p < PROBES; p++) hops[ttl-1].rtt[p] = -1.0;
                hops[ttl-1].ip[0] = '\0';
                hops[ttl-1].reached = 0;
                hops[ttl-1].flag = 0;
                count = ttl;
            }
            seq = ttl * PROBES + probe;         /* probe basina benzersiz */
            sent_at = probe_at(&m, ttl, seq);
            state = ST_WAIT;
        }
        else if (state == ST_WAIT) {
            int bitti = 0;                      /* bu probe icin karar verildi mi */

            char ip[INET_ADDRSTRLEN]; int reached = 0; char flag = 0;
            if (cevap_oku(&m, seq, 60000, ip, &reached, &flag)) {   /* 60 ms tick, UI donmaz */
                struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
                hops[ttl-1].rtt[probe] = (now.tv_sec - sent_at.tv_sec) * 1000.0 +
                                         (now.tv_nsec - sent_at.tv_nsec) / 1000000.0;
                strcpy(hops[ttl-1].ip, ip);
                if (reached) hops[ttl-1].reached = 1;
                if (flag)    hops[ttl-1].flag = flag;               /* TCP karari, herhangi bir probe'dan */
                bitti = 1;
            }

            if (!bitti) {                       /* cevap yoksa deadline'a bak */
                struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
                double gecen = (now.tv_sec - sent_at.tv_sec) * 1000.0 +
                               (now.tv_nsec - sent_at.tv_nsec) / 1000000.0;
                if (gecen >= TIMEOUT_SEC * 1000.0) bitti = 1;   /* rtt -1 kalir */
            }

            if (bitti) {                        /* ilerle: sonraki probe ya da sonraki hop */
                probe++;
                if (probe >= PROBES) {
                    probe = 0;
                    if (hops[ttl-1].reached || ttl >= limit) state = ST_DONE;
                    else { ttl++; state = ST_SEND; }
                } else {
                    state = ST_SEND;
                }
            }
        }
        else {                                  /* ST_DONE */
            running = 0;
            napms(30);                          /* bosa donmesin */
        }

        /* ── 3. Ciz ─────────────────────────────────── */
        draw_track(hops, count, running, etiket);
    }

    motor_kapat(&m);
    nodelay(stdscr, FALSE);                     /* menuye normal bloklayan getch ile don */
}

/* ═══════════════════════════════════════════════════
 *  SEND SIGNAL — PING TABLOSU CIZIMI
 * ═══════════════════════════════════════════════════ */
static void draw_ping(const char *hedef_ip, const char *etiket, PingSat *ring, int ring_count,
                      int sent, int recv, double rmin, double rmax, double rsum,
                      int running) {
    erase();
    int rows, cols; getmaxyx(stdscr, rows, cols);

    int w = 48; if (w > cols - 4) w = cols - 4;
    int x = (cols - w) / 2; if (x < 2) x = 2;
    int y = 2;

    int first   = y + 4;                          /* PING + baslik satirlarindan sonra ilk ping */
    int maxrows = rows - first - 4;               /* asagida stats + footer payi */
    int total   = (ring_count < PING_RING) ? ring_count : PING_RING;
    int shown   = (total < maxrows) ? total : maxrows;
    if (shown < 0) shown = 0;
    int bottom  = first + shown;

    /* ust cerceve + baslik */
    draw_hline(y, x, w, ACS_ULCORNER, ACS_URCORNER, -1, 0);
    mvprintw(y, x + 2, "[ SEND SIGNAL ]");
    const char *st = running ? "[ RUNNING ]" : "[ DONE ]";
    mvprintw(y, x + w - (int)strlen(st) - 2, "%s", st);

    /* hedef satiri + kolon basliklari */
    mvaddch(y + 1, x, ACS_VLINE); mvaddch(y + 1, x + w - 1, ACS_VLINE);
    mvprintw(y + 1, x + 2, "PING %s  [ %s ]", hedef_ip, etiket);
    mvaddch(y + 2, x, ACS_VLINE); mvaddch(y + 2, x + w - 1, ACS_VLINE);
    attron(A_BOLD);
    mvprintw(y + 2, x + 2, "SEQ");
    mvprintw(y + 2, x + 9, "RESULT");
    attroff(A_BOLD);
    draw_hline(y + 3, x, w, ACS_LTEE, ACS_RTEE, -1, 0);

    /* son 'shown' ping, eskiden yeniye */
    int start = ring_count - shown;
    for (int i = 0; i < shown; i++) {
        int ry = first + i;
        PingSat *p = &ring[(start + i) % PING_RING];
        mvaddch(ry, x, ACS_VLINE); mvaddch(ry, x + w - 1, ACS_VLINE);
        if (p->ok)              mvprintw(ry, x + 2, "%3d    time=%.2f ms  %s", p->seq, p->rtt,
                                         flag_yazi(p->flag));   /* TCP'de open / closed */
        else if (p->flag == 'U') mvprintw(ry, x + 2, "%3d    unreachable", p->seq);
        else                    mvprintw(ry, x + 2, "%3d    timeout", p->seq);
    }

    draw_hline(bottom, x, w, ACS_LTEE, ACS_RTEE, -1, 0);   /* stats ayiraci */

    /* istatistik satirlari */
    int loss = sent ? (int)((sent - recv) * 100.0 / sent + 0.5) : 0;
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

/* ─── Send Signal ekrani (ping, ESC'e kadar surer) ─── */
void send_signal(void) {
    Motor m;
    const char *hata = motor_ac(&m);
    if (hata) { motor_kapat(&m); motor_hata(hata); return; }
    char etiket[16]; motor_etiket(&m, etiket, sizeof(etiket));

    PingSat ring[PING_RING]; int ring_count = 0;
    int sent = 0, recv = 0, seq = 1;
    double rmin = 0, rmax = 0, rsum = 0;

    int state = ST_SEND, recorded = 0;
    struct timespec sent_at = {0, 0};

    nodelay(stdscr, TRUE);

    while (1) {
        int k = getch();
        if (k == 27 || k == 'q' || k == 'Q') break;

        if (state == ST_SEND) {
            sent_at = probe_at(&m, PING_TTL, seq);   /* TTL sabit, hedefe atiyoruz */
            sent++; recorded = 0;
            state = ST_WAIT;
        }
        else {  /* ST_WAIT: 1 sn'lik pencere, cevap ya da timeout, sonra sonraki ping */
            char ip[INET_ADDRSTRLEN]; int reached = 0; char flag = 0;
            int geldi = cevap_oku(&m, seq, 60000, ip, &reached, &flag);  /* her turda yokla, bos donmesin */
            if (!recorded && geldi) {
                struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
                double rtt = (now.tv_sec - sent_at.tv_sec) * 1000.0 +
                             (now.tv_nsec - sent_at.tv_nsec) / 1000000.0;
                if (flag == 'U') {                                  /* yol kesildi, basari sayilmaz */
                    ring[ring_count % PING_RING] = (PingSat){ seq, rtt, 0, flag };
                } else {
                    ring[ring_count % PING_RING] = (PingSat){ seq, rtt, 1, flag };
                    recv++;
                    if (recv == 1 || rtt < rmin) rmin = rtt;
                    if (rtt > rmax) rmax = rtt;
                    rsum += rtt;
                }
                ring_count++; recorded = 1;
            }

            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
            double gecen = (now.tv_sec - sent_at.tv_sec) * 1000.0 +
                           (now.tv_nsec - sent_at.tv_nsec) / 1000000.0;
            if (!recorded && gecen >= PING_INTERVAL_MS) {         /* pencere doldu, cevap yok */
                ring[ring_count % PING_RING] = (PingSat){ seq, 0, 0, 0 };
                ring_count++; recorded = 1;
            }
            if (gecen >= PING_INTERVAL_MS) { seq++; state = ST_SEND; }  /* sonraki ping */
        }

        draw_ping(current_cfg.ip, etiket, ring, ring_count, sent, recv, rmin, rmax, rsum, 1);
    }

    motor_kapat(&m);
    nodelay(stdscr, FALSE);
}

/* ═══════════════════════════════════════════════════
 *  ANA MENU
 * ═══════════════════════════════════════════════════ */
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

    /* Terminal boyutuna gore ortala */
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int block_w = 60;  /* sol menu + sag ozet birlikte yaklasik */
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

    /* Mevcut config ozeti — sag tarafta */
    mvprintw(oy + 3, ox + 28, "Current target:");
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
    noecho();                  /* BIR DAHA ACMAYACAGIZ */
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
            else if (highlight == 4)    goto quit;
            break;
        }
    }

quit:
    endwin();
    printf("Signal Commander is down. Out!\n");
    return 0;
}
