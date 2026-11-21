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
#include <fcntl.h>            /* open, /dev/urandom icin */

#define MAX_HOPS    30
#define MAX_PROBES  5            /* HopResult dizisinin boyutu, Settings bunun altinda kalir */

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

/* Runtime ayarlar, Settings ekrani duzenler. Eskiden #define'di */
typedef struct {
    int probes;                  /* hop basina probe, 1..MAX_PROBES */
    int timeout_ms;              /* track'te probe basina cevap penceresi */
    int dns;                     /* 1 = hostname hedef + hop isimleri (PTR) */
    int paralel;                 /* ayni anda yolda probe, 1 = sirali (eski davranis) */
} Ayar;

#define MAX_PARALEL 32

static Ayar ayar = { 3, 2000, 0, 16 };   /* 16 = Linux traceroute'un varsayilani */

/* Bir hop: ayar.probes kadar probe'un sonucu tek satirda */
typedef struct {
    int    hop;
    char   ip[INET_ADDRSTRLEN];  /* bos ise hicbir probe cevap vermedi -> * * * */
    double rtt[MAX_PROBES];      /* -1 = o probe timeout */
    int    reached;              /* 1 = hedefin kendisi cevapladi */
    char   flag;                 /* TCP/UDP: 'O' acik, 'C' kapali, 'U' ulasilamaz. 0 = duz hop */
    char   name[64];             /* PTR ismi, DNS kapaliysa ya da bulunamadiysa bos */
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
 *  FLD_INT   : tam sayı, min_val..max_val
 *  FLD_STR   : printable ASCII serbest metin
 *  FLD_CYCLE : önceden tanımlı seçenekler arasında ←/→ ile gezinme
 *  FLD_HOST  : IPv4 ya da hostname (harf, rakam, nokta, tire)
 * ═══════════════════════════════════════════════════ */
typedef enum { FLD_STR, FLD_INT, FLD_IP, FLD_CYCLE, FLD_HOST } FldType;

typedef struct {
    const char  *label;
    FldType      type;
    int          maxlen;        /* string buffer boyutu (FLD_STR/IP için) */
    int          min_val;       /* FLD_INT alt sınırı */
    int          max_val;       /* FLD_INT üst sınırı */
    const char **options;       /* FLD_CYCLE seçenekleri */
    int          opt_count;
} FldMeta;

static const char *PROTO_OPTS[] = { "ICMP", "TCP", "UDP" };
static const char *ONOFF_OPTS[] = { "OFF", "ON" };

#define CFG_FIELDS 4

static const FldMeta FIELDS[CFG_FIELDS] = {
    { "Target Host", FLD_HOST,  31, 0,     0, NULL,       0 },   /* 31 = value hucresine sigan */
    { "Port",        FLD_INT,    5, 0, 65535, NULL,       0 },
    { "TTL",         FLD_INT,    3, 0,   255, NULL,       0 },
    { "Protocol",    FLD_CYCLE,  0, 0,     0, PROTO_OPTS, 3 },
};

#define AYAR_FIELDS 4

static const FldMeta AYAR_META[AYAR_FIELDS] = {
    { "Probes per hop",   FLD_INT,   1,   1, MAX_PROBES,  NULL,       0 },
    { "Hop timeout (ms)", FLD_INT,   5, 100,      10000,  NULL,       0 },
    { "Parallel probes",  FLD_INT,   2,   1, MAX_PARALEL, NULL,       0 },
    { "Resolve DNS",      FLD_CYCLE, 0,   0,          0,  ONOFF_OPTS, 2 },
};

/* Bir formun tarifi: baslik, alan tablosu, veri <-> string cevirileri.
 * Configuration ve Settings ayni motoru kullanir, yeni form = yeni tarif. */
typedef struct {
    const char    *title;
    const FldMeta *fields;
    int            count;
    void         (*to_str)(const void *d, int idx, char *out, int outlen);
    void         (*from_str)(void *d, int idx, const char *s);
} FormDef;

/* Ayar struct <-> string dönüşümleri */
static void ayar_to_str(const void *d, int idx, char *out, int outlen) {
    const Ayar *a = d;
    switch (idx) {
        case 0: snprintf(out, outlen, "%d", a->probes);     break;
        case 1: snprintf(out, outlen, "%d", a->timeout_ms); break;
        case 2: snprintf(out, outlen, "%d", a->paralel);    break;
        case 3: snprintf(out, outlen, "%s", a->dns ? "ON" : "OFF"); break;
    }
}

static void str_to_ayar(void *d, int idx, const char *s) {
    Ayar *a = d;
    if (!s || s[0] == '\0') return;
    switch (idx) {
        case 0: a->probes     = atoi(s); break;
        case 1: a->timeout_ms = atoi(s); break;
        case 2: a->paralel    = atoi(s); break;
        case 3: a->dns        = (strcmp(s, "ON") == 0); break;
    }
}

/* Config struct <-> string dönüşümleri */
static void field_to_str(const void *d, int idx, char *out, int outlen) {
    const Config *c = d;
    switch (idx) {
        case 0: snprintf(out, outlen, "%s", c->ip);    break;
        case 1: snprintf(out, outlen, "%d", c->port);  break;
        case 2: snprintf(out, outlen, "%d", c->ttl);   break;
        case 3: snprintf(out, outlen, "%s", c->proto); break;
    }
}

static void str_to_field(void *d, int idx, const char *s) {
    Config *c = d;
    if (!s || s[0] == '\0') return;
    switch (idx) {
        case 0: snprintf(c->ip,    sizeof(c->ip),    "%s", s); break;
        case 1: c->port = atoi(s); break;
        case 2: c->ttl  = atoi(s); break;
        case 3: snprintf(c->proto, sizeof(c->proto), "%s", s); break;
    }
}

static const FormDef CFG_FORM  = { "[ CONFIGURATION ]", FIELDS,    CFG_FIELDS,
                                   field_to_str, str_to_field };
static const FormDef AYAR_FORM = { "[ SETTINGS ]",      AYAR_META, AYAR_FIELDS,
                                   ayar_to_str,  str_to_ayar };

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
static void recompute_layout(int nfields) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    /* Genislik: terminale uygun ama makul sinirlar icinde */
    g_box_w = cols - 4;
    if (g_box_w > 60) g_box_w = 60;
    if (g_box_w < 40) g_box_w = 40;

    g_box_h = nfields + 6;     /* ust, baslik, ayirac, alanlar, ayirac, butonlar, alt */

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

/* IPv4 ya da hostname mi? Sadece rakam + nokta ise IPv4 olmak zorunda
 * (1.2.3 gibi yarim adresler isim sayilmasin). Isimde etiket 1-63,
 * tire ile baslayamaz ya da bitemez, bos etiket yok. */
static int validate_host(const char *s) {
    int harf = 0;
    for (const char *p = s; *p; p++)
        if (!((*p >= '0' && *p <= '9') || *p == '.')) harf = 1;
    if (!harf) return validate_ipv4(s);

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

/* ═══════════════════════════════════════════════════
 *  CONFIG EKRANI — STATE MACHINE
 * ═══════════════════════════════════════════════════ */
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

        /* Label hucresi */
        int lattr = 0;
        if (is_sel)
            lattr = (mode == MODE_NAV) ? A_REVERSE : A_BOLD;

        if (lattr) attron(lattr);
        mvprintw(row, L_X, " %-*s ", L_W - 3, f->fields[i].label);
        if (lattr) attroff(lattr);

        /* Value hucresi:
         * EDIT modunda + secili + text field ise underscore'lu giris alani goster.
         * Diger durumlarda mevcut degeri yaz (gerekiyorsa highlight ile). */
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
        } else if (meta->type == FLD_HOST) {      /* kalan kurallar ENTER'da validate_host'ta */
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

/* ─── Form ana dongusu (Configuration + Settings) ────────
 * live = gercek veri, tmp = ayni tipte calisma kopyasi.
 * SAVE'de tmp live'a kopyalanir, CANCEL / q'da atilir. */
static void open_form(const FormDef *f, void *live, void *tmp, size_t size) {
    memcpy(tmp, live, size);
    int sel    = 0;
    CfgMode mode = MODE_NAV;

    /*
     * Navigasyon modeli (n = f->count):
     *   sel 0..n-1 : field'lar (dikey grup)
     *   sel n      : SAVE buton
     *   sel n+1    : CANCEL buton
     *
     *   Field icinde:  UP/DOWN field'lar arasi
     *   Son field + DOWN -> butonlara gec (SAVE)
     *   Field 0 + UP   -> butonlara cik (SAVE)
     *   Buton + UP     -> son field'a don
     *   Buton + DOWN   -> ilk field'a wrap
     *   Buton + LEFT/RIGHT -> butonlar arasi swap
     */
    while (1) {
        draw_form(f, tmp, sel, mode);
        int key = getch();

        switch (key) {
        case KEY_UP:
            if (sel >= f->count)
                sel = f->count - 1;          /* buton -> son field */
            else
                sel = (sel > 0) ? sel - 1 : f->count;  /* 0 -> Save */
            clear_status();
            break;
        case KEY_DOWN:
            if (sel < f->count)
                sel = (sel < f->count - 1) ? sel + 1 : f->count;
            else
                sel = 0;                       /* buton -> ilk field */
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
    Ayar tmp;
    open_form(&AYAR_FORM, &ayar, &tmp, sizeof(tmp));
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

/* Bir hop'ta birden cok karar gelirse guclu olan kalir. SYN-ACK'i sadece
 * dinleyen port uretir, en guclu kanit o. Sonra hedefin RST / port
 * unreachable'i, en zayif yoldaki bir unreachable. */
static int flag_guc(char f) {
    if (f == 'O') return 3;
    if (f == 'C') return 2;
    if (f == 'U') return 1;
    return 0;
}

/* scroll_off = tablonun en ustunde gorunen hop indeksi. takip = 1 iken
 * her cizimde en alta yapisir (yeni hop'lar hep gorunur). Sinirlar burada
 * kirpilir, cunku kac satir sigdigini sadece cizim ani biliyor. */
static void draw_track(HopResult *hops, int count, int running, const char *etiket, int probes,
                       int *scroll_off, int *takip, int dns_on, const char *hedef_yazi) {
    erase();
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int flag_x = 24 + probes * 10;                 /* RTT kolonlarindan sonra karar kolonu */
    int name_x = flag_x + 7;                       /* DNS aciksa en sagda isim kolonu */
    int w = flag_x + 8 + (dns_on ? 25 : 0);        /* 3 probe + DNS kapali = 62, eskisiyle ayni */
    if (w > cols - 4) w = cols - 4;
    int x = (cols - w) / 2; if (x < 2) x = 2;
    int y = 2;

    int first   = y + 3;                    /* ilk hop satiri */
    int maxrows = rows - first - 3;         /* asagida footer payi */
    int shown   = (count < maxrows) ? count : maxrows;
    if (shown < 0) shown = 0;
    int bottom  = first + shown;            /* alt cerceve satiri */

    int max_off = count - shown;            /* en alttaki pencere */
    if (*takip || *scroll_off >= max_off) { *scroll_off = max_off; *takip = 1; } /* dibe gelince takibe don */
    if (*scroll_off < 0) *scroll_off = 0;

    mvprintw(y - 1, x, "Target: %s", hedef_yazi);   /* hostname ise cozulen IP de, hijack gozden kacmasin */

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
    for (int p = 0; p < probes; p++) {              /* baslik da deger de sag hizali, alt alta gelsin */
        char lbl[8]; snprintf(lbl, sizeof(lbl), "RTT %d", p + 1);
        mvprintw(y + 1, x + 24 + p * 10, "%6s", lbl);
    }
    if (dns_on && name_x + 4 < w - 1) mvprintw(y + 1, x + name_x, "NAME");
    attroff(A_BOLD);

    draw_hline(y + 2, x, w, ACS_LTEE, ACS_RTEE, -1, 0);  /* baslik ayiraci */

    /* hop satirlari */
    for (int i = 0; i < shown; i++) {
        int ry = first + i;
        mvaddch(ry, x, ACS_VLINE); mvaddch(ry, x + w - 1, ACS_VLINE);
        HopResult *h = &hops[*scroll_off + i];          /* pencere kaydirilmis olabilir */

        if (h->ip[0] == '\0') {                         /* hic cevap yok */
            mvprintw(ry, x + 2, "%2d   * * *", h->hop);
        } else {
            mvprintw(ry, x + 2, "%2d   %-15s", h->hop, h->ip);
            for (int p = 0; p < probes; p++) {          /* her probe kendi kolonuna, sag hizali */
                int cx = x + 24 + p * 10;
                (h->rtt[p] < 0) ? mvprintw(ry, cx, "%6s", "*")
                                : mvprintw(ry, cx, "%6.2f ms", h->rtt[p]);
            }
            if (h->flag && flag_x + 6 < w - 1)          /* TCP/UDP karari, cerceveye tasmasin */
                mvprintw(ry, x + flag_x, "%s", flag_yazi(h->flag));
            int yer = w - name_x - 2;                   /* isim kolonunda kalan yer */
            if (dns_on && h->name[0] && yer > 0)        /* uzun isim kirpilir, cerceve bozulmaz */
                mvprintw(ry, x + name_x, "%.*s", yer, h->name);
        }
    }

    draw_hline(bottom, x, w, ACS_LLCORNER, ACS_LRCORNER, -1, 0);
    mvprintw(bottom + 2, x, "  [ ESC ] abort   [ UP/DOWN ] scroll");
    if (count > shown && shown > 0)                     /* sigmiyorsa nerede oldugumuzu goster */
        printw("   hops %d-%d of %d", *scroll_off + 1, *scroll_off + shown, count);
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
 * UDP'de sport bir port blogunun basi, probe'lar ayri soketlerden gider.
 * TCP'de port_blok = 1 ise (paralel track) her SYN de bloktan kendi portunu alir. */
typedef struct {
    int                proto;     /* IPPROTO_ICMP, IPPROTO_TCP ya da IPPROTO_UDP */
    struct sockaddr_in hedef;     /* sin_port TCP ve UDP'de anlamli */
    struct in_addr     src;       /* pseudo-header icin kaynak ip */
    unsigned short     my_id;     /* pid, imzam */
    uint16_t           sport;     /* TCP: sabit kaynak port ya da blok basi. UDP: blok basi */
    int                port_blok; /* TCP: 1 = probe basina port, 0 = sabit port (Paris) */
    int                isock;     /* raw ICMP: echo reply, time exceeded, unreachable */
    int                tsock;     /* raw TCP: SYN at, SYN-ACK / RST dinle. ICMP'de -1 */
} Motor;

#define PORT_BLOK 200                   /* oturum basina port, track en fazla 30*5+4 = 154 etiket kullanir */

/* TCP seq: ust 16 bit pid, alt 16 bit probe etiketi */
static uint32_t syn_seq(const Motor *m, int tag) {
    return ((uint32_t)m->my_id << 16) | (uint16_t)tag;
}

/* SYN'in kaynak portu. Sabit port ayni 4-tuple'dan es zamanli bircok SYN
 * demek: olculdu, hedef tarafinda SYN-ACK, RST ve sessizlik karisik donuyor.
 * Paralelde her SYN kendi 4-tuple'ini alir, bedeli ECMP yol tutarliligi. */
static uint16_t tcp_port(const Motor *m, int tag) {
    return m->port_blok ? m->sport + (uint16_t)(tag % PORT_BLOK) : m->sport;
}

/* Gelen paketteki bizim taraftaki port bizim mi, etiketle tutarli mi? */
static int tcp_port_tutar(const Motor *m, int port, int tag) {
    return port == tcp_port(m, tag);
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
static struct timespec tcp_probe_gonder(Motor *m, int ttl, int tag) {
    uint32_t seq = syn_seq(m, tag);
    setsockopt(m->tsock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));   /* her hop'ta artan tek sey */

    char packet[sizeof(struct pseudo_hdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct pseudo_hdr *ph  = (struct pseudo_hdr *)packet;
    struct tcphdr     *tcp = (struct tcphdr *)(packet + sizeof(struct pseudo_hdr));

    tcp->source = htons(tcp_port(m, tag));     /* sirali: sabit, paralel: probe basina */
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
 *  portta: port = blok basi + tag % PORT_BLOK. Bedeli:
 *  5-tuple probe'dan probe'a degisir, ECMP yolu oynayabilir.
 * ═══════════════════════════════════════════════════ */

static uint16_t udp_port(const Motor *m, int tag) {
    return m->sport + (uint16_t)(tag % PORT_BLOK);
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
    if (m->proto == IPPROTO_TCP) return tcp_probe_gonder(m, ttl, tag);
    if (m->proto == IPPROTO_UDP) return udp_probe_gonder(m, ttl, tag);
    return probe_gonder(m->isock, &m->hedef, ttl, tag);
}

/* ICMP soketinden gelen paketi coz: bizim probe'lardan birinin cevabi mi?
 * Evetse tag_out'a HANGI probe oldugunu, ip_out'a cevaplayani,
 * reached_out'a "dur" kararini, flag_out'a karar harfini yazar, 1 doner.
 * Beklenen etiketi sormaz, bulur: paralel probing'de ayni anda bircok
 * probe yolda. Gomulu paketin protokolune gore dallanir:
 * ICMP'de id + seq, TCP'de portlar + seq, UDP'de portlar. */
static int paket_coz(char *buf, int n, struct sockaddr_in *kaynak, Motor *m, int *tag_out,
                     char *ip_out, int *reached_out, char *flag_out) {
    if (n < (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr)) return 0;
    struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;    /* dis IP header'i atla */
    if (n < iplen + (int)sizeof(struct icmphdr)) return 0;
    struct icmphdr *icmp = (struct icmphdr *)(buf + iplen);
    *flag_out = 0;

    if (icmp->type == ICMP_ECHOREPLY) {                     /* A: hedef cevapladi */
        if (m->proto != IPPROTO_ICMP) return 0;             /* TCP/UDP modunda echo reply bizim olamaz */
        if (ntohs(icmp->un.echo.id) != m->my_id) return 0;  /* benim degil */
        *tag_out = ntohs(icmp->un.echo.sequence);           /* seq = etiket */
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
            if (ntohs(iicmp->un.echo.id) != m->my_id) return 0;             /* benim probe'um degil */
            *tag_out = ntohs(iicmp->un.echo.sequence);
        } else if (m->proto == IPPROTO_TCP) {
            if (iip->daddr != m->hedef.sin_addr.s_addr) return 0;           /* baska hedefe giden SYN */
            struct tcphdr *itcp = (struct tcphdr *)(buf + off + iiplen);    /* portlar + seq, otesi yok */
            uint32_t s = ntohl(itcp->seq);
            if (itcp->dest != m->hedef.sin_port || (s >> 16) != m->my_id ||
                !tcp_port_tutar(m, ntohs(itcp->source), s & 0xFFFF)) return 0; /* benim SYN'im degil */
            *tag_out = s & 0xFFFF;                                          /* seq'in alt yarisi = etiket */
        } else {
            if (iip->daddr != m->hedef.sin_addr.s_addr) return 0;           /* baska hedefe giden datagram */
            struct udphdr *iudp = (struct udphdr *)(buf + off + iiplen);    /* quote'un 8 bayti tam UDP header */
            int sp = ntohs(iudp->source);
            if (sp < m->sport || sp >= m->sport + PORT_BLOK ||
                iudp->dest != m->hedef.sin_port) return 0;                  /* benim blogumdan degil */
            *tag_out = sp - m->sport;                                       /* blok ici ofset = etiket */
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
static int tcp_coz(char *buf, int n, struct sockaddr_in *kaynak, Motor *m, int *tag_out,
                   char *ip_out, int *reached_out, char *flag_out) {
    if (n < (int)sizeof(struct iphdr)) return 0;
    struct iphdr *ip = (struct iphdr *)buf; int iplen = ip->ihl * 4;
    if (ip->saddr != m->hedef.sin_addr.s_addr) return 0;                  /* hedeften gelmiyor */
    if (n < iplen + (int)sizeof(struct tcphdr)) return 0;
    struct tcphdr *tcp = (struct tcphdr *)(buf + iplen);
    if (tcp->source != m->hedef.sin_port) return 0;                       /* baska baglanti */
    uint32_t s = ntohl(tcp->ack_seq) - 1;                                  /* ack = benim seq + 1 */
    if (!tcp->ack || (s >> 16) != m->my_id ||
        !tcp_port_tutar(m, ntohs(tcp->dest), s & 0xFFFF)) return 0;       /* baska SYN'in cevabi */
    *tag_out = s & 0xFFFF;

    if (tcp->syn)      *flag_out = 'O';                    /* SYN-ACK, port acik */
    else if (tcp->rst) *flag_out = 'C';                    /* RST, port kapali */
    else return 0;
    *reached_out = 1;
    inet_ntop(AF_INET, &kaynak->sin_addr, ip_out, INET_ADDRSTRLEN);
    return 1;
}

/* Soketleri en fazla tick_us yokla, gelen bir paketi coz.
 * 1 = bizim probe'lardan birinin cevabi (tag_out dolu), 0 = yabanci paket,
 * -1 = okunacak bir sey yok. Cagiran 0 / 1 geldikce tick_us=0 ile tekrar
 * cagirip birikenleri bosaltabilir. */
static int cevap_oku(Motor *m, int tick_us, int *tag_out,
                     char *ip_out, int *reached_out, char *flag_out) {
    fd_set rfds; FD_ZERO(&rfds); FD_SET(m->isock, &rfds);
    int maxfd = m->isock;
    if (m->tsock >= 0) { FD_SET(m->tsock, &rfds); if (m->tsock > maxfd) maxfd = m->tsock; }
    struct timeval tv = { 0, tick_us };
    if (select(maxfd + 1, &rfds, NULL, NULL, &tv) <= 0) return -1;

    char buf[1024]; struct sockaddr_in kaynak; socklen_t kl;
    if (FD_ISSET(m->isock, &rfds)) {                        /* router, firewall ya da echo reply */
        kl = sizeof(kaynak);
        int n = recvfrom(m->isock, buf, sizeof(buf), 0, (struct sockaddr *)&kaynak, &kl);
        if (n > 0 && paket_coz(buf, n, &kaynak, m, tag_out, ip_out, reached_out, flag_out)) return 1;
    }
    if (m->tsock >= 0 && FD_ISSET(m->tsock, &rfds)) {       /* hedefin kendisi */
        kl = sizeof(kaynak);
        int n = recvfrom(m->tsock, buf, sizeof(buf), 0, (struct sockaddr *)&kaynak, &kl);
        if (n > 0 && tcp_coz(buf, n, &kaynak, m, tag_out, ip_out, reached_out, flag_out)) return 1;
    }
    return 0;
}

/* Gelen etiket beklenenle ayni probe mu? Etiketin tasindigi alan protokole
 * gore daraliyor: ICMP / TCP 16 bit, UDP blok ici ofset. Ping'de seq buyudukce
 * sarar, karsilastirma ayni daralmayla yapilmali. */
static int ayni_tag(const Motor *m, int got, int want) {
    if (m->proto == IPPROTO_UDP) return got == want % PORT_BLOK;
    return got == (want & 0xFFFF);
}

/* Config'e gore motoru kur. Hata varsa ekranda gosterilecek mesaji
 * doner, yoksa NULL. Hata durumunda da motor_kapat cagrilmali.
 * paralel = 1 ise TCP probe basina kaynak port kullanir. */
static const char *motor_ac(Motor *m, struct in_addr hedef_ip, int paralel) {
    static int oturum = 0;                     /* her oturum yeni kaynak port */
    memset(m, 0, sizeof(*m));
    m->isock = m->tsock = -1;
    m->hedef.sin_family = AF_INET;
    m->hedef.sin_addr   = hedef_ip;            /* hedef_coz cozdu, hostname ise DNS ile */

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
        m->port_blok = paralel;
        if (paralel) m->sport = 40000 + ((getpid() + oturum++) % 100) * PORT_BLOK;  /* oturum basina blok */
        else         m->sport = 40000 + ((getpid() + oturum++) % 20000);  /* gec gelen eski SYN-ACK karismasin */
    }
    if (m->proto == IPPROTO_UDP) {
        if (current_cfg.port < 1) return "UDP needs a port between 1 and 65535.";
        m->hedef.sin_port = htons(current_cfg.port);
        m->sport = 40000 + ((getpid() + oturum++) % 100) * PORT_BLOK;  /* oturum basina ayri blok, en fazla 59999 */
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
 *  DNS MOTORU  (elle kurulan sorgular)
 *
 *  dnsq.c'den gelen kanitlanmis kutular. Sorguyu bayt
 *  bayt kuruyoruz, resolv.conf'taki sunucuya duz UDP ile
 *  atiyoruz, cevabi sikistirilmis isimler dahil elle
 *  cozuyoruz.
 *
 *  Bloklamaz: soket tick dongusunde MSG_DONTWAIT ile
 *  yoklaniyor. getaddrinfo gibi UI'yi dondurmuyor
 *  (NXDOMAIN ~1 sn surebiliyor, olculdu).
 *
 *  Kimlik: rastgele 16 bit ID. DNS'te el sikisma yok,
 *  sahte cevabi durduran tek sey ID + kaynak port.
 * ═══════════════════════════════════════════════════ */
#define DNS_PORT        53
#define DNS_TIMEOUT_MS  2000
#define T_A             1
#define T_PTR           12
#define DNS_MAX_ATLAMA  16             /* isim basina takip edilen pointer, otesi dongu sayilir */

static double ms_fark(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1000000.0;
}

/* resolv.conf'taki ilk IPv4 nameserver'a connect edilmis UDP soketi. -1 = yok */
static int dns_ac(void) {
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
    if (connect(s, (struct sockaddr *)&ns, sizeof(ns)) < 0) { close(s); return -1; } /* sadece sunucunun cevabi girer */
    return s;
}

/* Tahmin edilebilir ID = cache poisoning, o yuzden kernel RNG */
static uint16_t rastgele_id(void) {
    uint16_t id = 0; int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, &id, sizeof(id)) != sizeof(id))
        id = (uint16_t)(getpid() ^ time(NULL));
    if (fd >= 0) close(fd);
    return id;
}

/* "www.google.com" -> 3www6google3com0. -1 = bos / uzun etiket ya da isim */
static int isim_yaz(const char *name, unsigned char *out, int cap) {
    int n = 0; const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len == 0 || len > 63) return -1;                       /* cift nokta ya da 6 bit siniri */
        if (n + 1 + len + 1 > cap || n + 1 + len + 1 > 255) return -1;
        out[n++] = (unsigned char)len;                             /* uzunluk bayti, sonra etiket */
        memcpy(out + n, p, len); n += len;
        p += len; if (*p == '.') p++;
    }
    if (n + 1 > cap) return -1;
    out[n++] = 0;                                                  /* root etiketi, isim biter */
    return n;
}

/* Tek sorgu kur ve at. Header struct'siz, bayt bayt: endian / padding derdi yok.
 * id_out'a eslestirme icin ID yazar. 0 = isim bozuk ya da send patladi */
static int dns_sor(int s, const char *qname, uint16_t qtype, uint16_t *id_out) {
    unsigned char q[300]; uint16_t id = rastgele_id();
    memset(q, 0, 12);
    q[0] = id >> 8; q[1] = id & 0xFF;          /* ID, cevap ayni ID'yi tasimali */
    q[2] = 0x01;                               /* RD=1, ozyinelemeyi resolver yapsin */
    q[5] = 1;                                  /* QDCOUNT = 1 */
    int n = isim_yaz(qname, q + 12, sizeof(q) - 12 - 4);
    if (n < 0) return 0;
    int off = 12 + n;
    q[off++] = qtype >> 8; q[off++] = qtype & 0xFF;     /* QTYPE */
    q[off++] = 0;          q[off++] = 1;                /* QCLASS = IN */
    if (send(s, q, off, 0) != off) return 0;
    *id_out = id;
    return 1;
}

/* 8.8.4.4 -> 4.4.8.8.in-addr.arpa, agac agdan asagi yurunsun diye ters */
static void ptr_isim(struct in_addr a, char *out, int cap) {
    unsigned char *b = (unsigned char *)&a.s_addr;
    snprintf(out, cap, "%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1], b[0]);
}

/* Sikistirilmis olabilen ismi off'tan oku. Donen: ismin kayittaki sonu
 * (pointer'in ziplattigi yer degil), bozuksa -1. Pointer'lar geri gostermeli
 * ve sayisi sinirli, yoksa ileri yururken ayni pointer'a donup dongu kurulabilir.
 * Basilamayan karakter '?' olur, PTR icinde escape kodu ekrani bozmasin. */
static int isim_oku(const unsigned char *msg, int len, int off, char *out, int cap) {
    int pos = off, end = -1, w = 0, jumps = 0;
    if (cap < 1) return -1;
    while (1) {
        if (pos >= len) return -1;
        unsigned char c = msg[pos];
        if (c == 0) { pos++; break; }                           /* root, isim bitti */
        if ((c & 0xC0) == 0xC0) {                               /* 11xxxxxx = 14 bit pointer */
            if (pos + 1 >= len) return -1;
            int target = ((c & 0x3F) << 8) | msg[pos + 1];
            if (end < 0) end = pos + 2;
            if (target >= pos || ++jumps > DNS_MAX_ATLAMA) return -1;
            pos = target; continue;
        }
        if (c & 0xC0) return -1;                                /* 01 ve 10 onekleri rezerve */
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

/* Cevabi coz (ID'yi cagiran eslestirdi). qtype'tan ilk kaydi out'a yazar:
 * A ise IP metni, PTR ise isim. 1 = bulundu, 0 = yok / NXDOMAIN / bozuk.
 * CNAME zinciri atlanir, resolver A kaydini zincirin sonuna koyuyor. */
static int dns_coz(const unsigned char *msg, int len, uint16_t qtype, char *out, int cap) {
    if (len < 12) return 0;
    int flags = (msg[2] << 8) | msg[3];
    if (!(flags & 0x8000) || (flags & 0x0F)) return 0;      /* cevap degil ya da rcode != NOERROR */
    int qd = (msg[4] << 8) | msg[5], an = (msg[6] << 8) | msg[7];
    int off = 12; char isim[256];
    for (int i = 0; i < qd; i++) {                          /* geri yansitilan soruyu atla */
        off = isim_oku(msg, len, off, isim, sizeof(isim));
        if (off < 0 || off + 4 > len) return 0;
        off += 4;
    }
    for (int i = 0; i < an; i++) {
        off = isim_oku(msg, len, off, isim, sizeof(isim));
        if (off < 0 || off + 10 > len) return 0;            /* type, class, ttl, rdlength */
        int type  = (msg[off] << 8) | msg[off + 1];
        int rdlen = (msg[off + 8] << 8) | msg[off + 9];
        off += 10;
        if (off + rdlen > len) return 0;                    /* RDATA paketten uzun */
        if (type == qtype && qtype == T_A && rdlen == 4) {
            inet_ntop(AF_INET, msg + off, out, cap);
            return 1;
        }
        if (type == qtype && qtype == T_PTR) {
            if (isim_oku(msg, len, off, isim, sizeof(isim)) < 0) return 0;
            snprintf(out, cap, "%s", isim);
            return 1;
        }
        off += rdlen;
    }
    return 0;
}

/* Hedefi IP'ye cevir. IPv4 ise aninda. Hostname ise A sorgusu atar, tick tick
 * bekler (UI donmaz, ESC iptal eder). 1 = out dolu, 0 = iptal ya da hata
 * (hata mesaji gosterildi). */
static int hedef_coz(const char *host, struct in_addr *out) {
    if (inet_pton(AF_INET, host, out) == 1) return 1;          /* zaten IP, DNS gerekmez */
    if (!ayar.dns) { motor_hata("Target is a hostname but Resolve DNS is OFF (see Settings)."); return 0; }

    int s = dns_ac();
    if (s < 0) { motor_hata("No usable nameserver in /etc/resolv.conf."); return 0; }
    uint16_t id;
    if (!dns_sor(s, host, T_A, &id)) { close(s); motor_hata("Could not send the DNS query."); return 0; }

    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    const char *hata = NULL; int sonuc = 0;
    nodelay(stdscr, TRUE);
    while (1) {
        int k = getch();
        if (k == 27 || k == 'q' || k == 'Q') break;            /* kullanici vazgecti, mesaj yok */

        erase();
        mvprintw(2, 4, "Resolving %s ...", host);
        mvprintw(4, 4, "[ ESC ] cancel");
        refresh();

        fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
        struct timeval tv = { 0, 60000 };                      /* 60 ms tick, ayni ritim */
        if (select(s + 1, &rf, NULL, NULL, &tv) > 0) {
            unsigned char buf[1500];
            int n = recv(s, buf, sizeof(buf), 0);
            if (n >= 2 && ((buf[0] << 8) | buf[1]) == id) {    /* benim sorgumun cevabi */
                char ip[INET_ADDRSTRLEN];
                if (dns_coz(buf, n, T_A, ip, sizeof(ip)) && inet_pton(AF_INET, ip, out) == 1) sonuc = 1;
                else hata = "Host not found (no A record).";
                break;
            }
        }
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        if (ms_fark(t0, now) > DNS_TIMEOUT_MS) { hata = "DNS timeout, the resolver did not answer."; break; }
    }
    nodelay(stdscr, FALSE);
    close(s);
    if (hata) motor_hata(hata);
    return sonuc;
}

/* Ust satirdaki hedef yazisi: "8.8.8.8" ya da "dns.google -> 8.8.8.8" */
static void hedef_yazisi(const char *host, struct in_addr ip, char *out, int cap) {
    char ipbuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &ip, ipbuf, sizeof(ipbuf));
    if (strcmp(host, ipbuf) == 0) snprintf(out, cap, "%s", ipbuf);
    else                          snprintf(out, cap, "%s -> %s", host, ipbuf);
}

/* Hop basina PTR isi: 0 sorulmadi, 1 bekliyor, 2 bitti (bulundu ya da vazgecildi) */
typedef struct {
    int             durum;
    uint16_t        id;
    struct timespec t;
    char            ip[INET_ADDRSTRLEN];   /* hangi IP icin soruldu, hop IP'si degisirse yeniden */
} PtrIs;

/* Her tick: IP'si yeni belli olan hop'lara PTR at, gelen cevaplari ID ile
 * hop'lara dagit, 2 sn'de cevapsiz kalanlardan vazgec. Hic bloklamaz. */
static void ptr_tick(int s, HopResult *hops, int count, PtrIs *p) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    for (int i = 0; i < count; i++) {
        if (hops[i].ip[0] == '\0') continue;
        if (p[i].durum != 0 && strcmp(p[i].ip, hops[i].ip) != 0) {   /* ECMP: hop IP'si degisti */
            p[i].durum = 0; hops[i].name[0] = '\0';
        }
        if (p[i].durum == 0) {
            struct in_addr a; char q[64];
            inet_pton(AF_INET, hops[i].ip, &a); ptr_isim(a, q, sizeof(q));
            if (dns_sor(s, q, T_PTR, &p[i].id)) { p[i].durum = 1; p[i].t = now; }
            else p[i].durum = 2;
            snprintf(p[i].ip, sizeof(p[i].ip), "%s", hops[i].ip);
        } else if (p[i].durum == 1 && ms_fark(p[i].t, now) > DNS_TIMEOUT_MS) {
            p[i].durum = 2;                                          /* cevap yok, isimsiz kalsin */
        }
    }

    unsigned char buf[1500]; int n;
    while ((n = recv(s, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {      /* birikenleri bosalt, beklemeden */
        if (n < 2) continue;
        uint16_t id = (buf[0] << 8) | buf[1];
        for (int i = 0; i < count; i++) {
            if (p[i].durum != 1 || p[i].id != id) continue;
            char name[256];
            if (dns_coz(buf, n, T_PTR, name, sizeof(name)) && strcmp(name, p[i].ip) != 0)
                snprintf(hops[i].name, sizeof(hops[i].name), "%.*s",       /* isim = IP ise gosterme (WSL) */
                         (int)sizeof(hops[i].name) - 1, name);              /* uzun isim bilerek kirpilir */
            p[i].durum = 2;
            break;
        }
    }
}

/* ═══════════════════════════════════════════════════
 *  TRACK SIGNAL — PARALEL FSM
 *
 *  Bloklamayan tick dongusu. Probe'lar slot'larda:
 *  pd[hop][p] = 0 atilmadi, 1 yolda, 2 bitti. Etiket
 *  ttl*probes+p benzersiz, cevap etiketinden dogrudan
 *  kendi slot'una gider. Her tick:
 *
 *    1. klavye
 *    2. pencere dolana kadar siradaki probe'lari at
 *    3. gelen cevaplari bosalt (tick basina en fazla 64)
 *    4. suresi dolanlari timeout say
 *    5. stop_ttl'e kadar her sey bittiyse DONE
 *
 *  Durma: bir probe hedefe varinca stop_ttl o hop'a
 *  cekilir, otesine probe atilmaz, yoldakiler birakilir.
 *  Pencere 1 = eski sirali davranis (at, bekle, siradaki).
 * ═══════════════════════════════════════════════════ */
enum { ST_SEND, ST_WAIT, ST_DONE };               /* send_signal hala kullaniyor */
#define MAX_TICK_PAKET 64                         /* raw TCP soketi hosttaki her TCP'yi goruyor, dongu kilitlenmesin */

void track_signal(void) {
    /* Hedefi coz (hostname ise DNS), protokolu config'den al, soketleri ac */
    struct in_addr hedef_ip;
    if (!hedef_coz(current_cfg.ip, &hedef_ip)) return;
    Motor m;
    const char *hata = motor_ac(&m, hedef_ip, ayar.paralel > 1);   /* paralelde TCP probe basina port */
    if (hata) { motor_kapat(&m); motor_hata(hata); return; }   /* raw socket root ister */
    char etiket[16]; motor_etiket(&m, etiket, sizeof(etiket));
    char hedef_y[96]; hedef_yazisi(current_cfg.ip, hedef_ip, hedef_y, sizeof(hedef_y));

    int dsock = ayar.dns ? dns_ac() : -1;      /* hop isimleri icin, acilamazsa isimsiz devam */
    PtrIs ptr[MAX_HOPS]; memset(ptr, 0, sizeof(ptr));

    int limit = current_cfg.ttl;               /* config'deki TTL = max hop */
    if (limit > MAX_HOPS) limit = MAX_HOPS;
    if (limit < 1) limit = 1;

    int probes = ayar.probes;                  /* oturum basinda dondur, yarida degismesin */
    if (probes < 1) probes = 1;
    if (probes > MAX_PROBES) probes = MAX_PROBES;
    double timeout_ms = ayar.timeout_ms;
    int pencere = ayar.paralel;                /* ayni anda yolda en fazla bu kadar probe */
    if (pencere < 1) pencere = 1;
    if (pencere > MAX_PARALEL) pencere = MAX_PARALEL;

    HopResult hops[MAX_HOPS]; memset(hops, 0, sizeof(hops));
    int pd[MAX_HOPS][MAX_PROBES]; memset(pd, 0, sizeof(pd));       /* slot durumu: 0 / 1 yolda / 2 bitti */
    struct timespec pt[MAX_HOPS][MAX_PROBES];                     /* slot'un gonderim ani */

    int next_ttl = 1, next_p = 0;              /* siradaki atilacak probe */
    int stop_ttl = limit;                      /* hedefe varilinca kuculur */
    int yolda = 0, count = 0, running = 1;
    int scroll_off = 0, takip = 1;             /* tablo penceresi, baslangicta en alti takip et */

    nodelay(stdscr, TRUE);                     /* getch bloklamasin, dongu donsun */

    while (1) {
        /* ── 1. Klavye ──────────────────────────────── */
        int k = getch();
        if (k == 27 || k == 'q' || k == 'Q') break;   /* ESC -> menuye don */
        if (k == KEY_UP)   { scroll_off--; takip = 0; }  /* yukari bakan takibi birakir */
        if (k == KEY_DOWN) { scroll_off++; }             /* dibe varinca draw_track takibi geri acar */

        if (running) {
            /* ── 2. Pencere dolana kadar siradakileri at ── */
            while (yolda < pencere && next_ttl <= stop_ttl) {
                int t = next_ttl - 1;
                if (next_p == 0) {             /* yeni hop: satiri sifirla */
                    hops[t].hop = next_ttl;
                    for (int p = 0; p < MAX_PROBES; p++) hops[t].rtt[p] = -1.0;
                    hops[t].ip[0] = '\0';
                    hops[t].reached = 0;
                    hops[t].flag = 0;
                    hops[t].name[0] = '\0';
                    if (next_ttl > count) count = next_ttl;
                }
                pt[t][next_p] = probe_at(&m, next_ttl, next_ttl * probes + next_p);  /* etiket probe basina benzersiz */
                pd[t][next_p] = 1; yolda++;
                if (++next_p >= probes) { next_p = 0; next_ttl++; }
            }

            /* ── 3. Gelen cevaplari bosalt, etiketten slot'a dagit ── */
            int tick_us = 60000;                /* ilk bekleme 60 ms, UI donmaz */
            for (int i = 0; i < MAX_TICK_PAKET; i++) {
                char ip[INET_ADDRSTRLEN]; int reached = 0, tag = -1; char flag = 0;
                int r = cevap_oku(&m, tick_us, &tag, ip, &reached, &flag);
                if (r < 0) break;               /* okunacak bir sey kalmadi */
                tick_us = 0;                    /* ilkinden sonra sadece birikenleri al */
                if (r == 0) continue;           /* yabanci paket */

                int t = tag / probes - 1, p = tag % probes;          /* etiket -> slot */
                if (tag < probes || t >= limit || pd[t][p] != 1) continue;   /* gec kalan ya da birakilmis */
                pd[t][p] = 2; yolda--;

                struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
                hops[t].rtt[p] = ms_fark(pt[t][p], now);
                strcpy(hops[t].ip, ip);
                if (flag_guc(flag) > flag_guc(hops[t].flag)) hops[t].flag = flag;   /* zayif karar gucluyu ezmesin */
                if (reached) {
                    hops[t].reached = 1;
                    if (t + 1 < stop_ttl) {                          /* daha yakinda hedef bulundu */
                        stop_ttl = t + 1;
                        for (int tt = stop_ttl; tt < limit; tt++)    /* otesindeki yoldakileri birak */
                            for (int pp = 0; pp < probes; pp++)
                                if (pd[tt][pp] == 1) { pd[tt][pp] = 2; yolda--; }
                        if (count > stop_ttl) count = stop_ttl;      /* tabloda hedefin otesi gorunmesin */
                    }
                }
            }

            /* ── 4. Suresi dolanlar timeout, rtt -1 kalir ── */
            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
            for (int t = 0; t < count; t++)
                for (int p = 0; p < probes; p++)
                    if (pd[t][p] == 1 && ms_fark(pt[t][p], now) >= timeout_ms) { pd[t][p] = 2; yolda--; }

            /* ── 5. stop_ttl'e kadar hepsi bittiyse DONE ── */
            if (next_ttl > stop_ttl) {
                int acik = 0;
                for (int t = 0; t < stop_ttl; t++)
                    for (int p = 0; p < probes; p++)
                        if (pd[t][p] == 1) acik = 1;
                if (!acik) running = 0;
            }
        } else {
            napms(30);                          /* DONE: bosa donmesin, DNS isimleri gelmeye devam eder */
        }

        /* ── 2b. DNS: yeni IP'lere PTR, gelen isimler ── */
        if (dsock >= 0) ptr_tick(dsock, hops, count, ptr);   /* DONE'dan sonra da isimler dolmaya devam eder */

        /* ── 3. Ciz ─────────────────────────────────── */
        draw_track(hops, count, running, etiket, probes, &scroll_off, &takip, dsock >= 0, hedef_y);
    }

    if (dsock >= 0) close(dsock);
    motor_kapat(&m);
    nodelay(stdscr, FALSE);                     /* menuye normal bloklayan getch ile don */
}

/* ═══════════════════════════════════════════════════
 *  SEND SIGNAL — PING TABLOSU CIZIMI
 * ═══════════════════════════════════════════════════ */
static void draw_ping(const char *hedef_ip, const char *hedef_y, const char *etiket, PingSat *ring, int ring_count,
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
    mvprintw(y - 1, x, "Target: %s", hedef_y);
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
    struct in_addr hedef_ip;
    if (!hedef_coz(current_cfg.ip, &hedef_ip)) return;
    Motor m;
    const char *hata = motor_ac(&m, hedef_ip, 0);              /* ping tek tek gider, sabit port yeter */
    if (hata) { motor_kapat(&m); motor_hata(hata); return; }
    char etiket[16]; motor_etiket(&m, etiket, sizeof(etiket));
    char hedef_y[96]; hedef_yazisi(current_cfg.ip, hedef_ip, hedef_y, sizeof(hedef_y));
    char ipbuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &hedef_ip, ipbuf, sizeof(ipbuf));

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
            int tag = -1;
            int geldi = (cevap_oku(&m, 60000, &tag, ip, &reached, &flag) == 1 &&  /* her turda yokla, bos donmesin */
                         ayni_tag(&m, tag, seq));                                /* onceki ping'in gec cevabi sayilmaz */
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

        draw_ping(ipbuf, hedef_y, etiket, ring, ring_count, sent, recv, rmin, rmax, rsum, 1);
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
