#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include "third_party/mbedtls/ssl.h"
#include "third_party/mbedtls/net_sockets.h"
#include "third_party/mbedtls/entropy.h"
#include "third_party/mbedtls/ctr_drbg.h"

struct sb {
    char * data;
    size_t count;
    size_t capacity;
};

struct cfg {
    char h[256], p[1024], t[16], m[16], o[1024];
    char * d;
    char * hs[32];
    int hc;
    bool s, L, v, i, N, p301, p302;
};

static void sb_init(struct sb * b) {
    b->count = 0;
    b->capacity = 256;
    b->data = malloc(b->capacity);
    if (b->data) {
        b->data[0] = '\0';
    }
}

static void sb_put(struct sb * b, const char * d, int bytes) {
    if (b->data && b->count + (size_t) bytes + 1 > b->capacity) {
        b->capacity = (b->capacity + (size_t) bytes + 1) * 2;
        b->data = realloc(b->data, b->capacity);
    }
    if (b->data) {
        memcpy(b->data + b->count, d, (size_t) bytes);
        b->count += (size_t) bytes;
        b->data[b->count] = '\0';
    }
}

static void sb_puts(struct sb * b, const char * s) {
    sb_put(b, s, (int) strlen(s));
}

static void sb_free(struct sb * b) {
    free(b->data);
    b->data = NULL;
    b->count = 0;
    b->capacity = 0;
}

static void help() {
    printf("usage: curly [options] <url>\n"
           "  -L, --location      follow redirects\n"
           "  -v, --verbose       show handshake and headers\n"
           "  -i, --include       show response headers\n"
           "  -o, --output <file> write body to file\n"
           "  -X, --request <cmd> set method (GET, POST, etc.)\n"
           "  -H, --header <hdr>  add custom header\n"
           "  -d, --data <data>   send POST data\n"
           "  --post301/302       keep method on redirect\n");
}

static void render_body(char * d, FILE * f) {
    char * b = strstr(d, "\r\n\r\n");
    if (b) {
        b += 4;
        if (strcasestr(d, "Transfer-Encoding: chunked")) {
            char * p = b;
            long z = 1;
            while (z > 0) {
                z = strtol(p, & p, 16);
                if (z > 0) {
                    while (* p == '\r' || * p == '\n') { p++; }
                    fwrite(p, 1, (size_t) z, f);
                    p += z;
                    while (* p == '\r' || * p == '\n') { p++; }
                }
            }
        } else {
            fwrite(b, 1, strlen(b), f);
        }
    }
}

static void parse_url(char * u, struct cfg * c) {
    if (strncmp(u, "https://", 8) == 0) {
        u += 8; c->s = true; strcpy(c->t, "443");
    } else if (strncmp(u, "http://", 7) == 0) {
        u += 7; c->s = false; strcpy(c->t, "80");
    }
    char * f = strchr(u, '/'), * k = strchr(u, ':');
    if (k && (! f || k < f)) {
        snprintf(c->h, 256, "%.*s", (int)(k - u), u);
        snprintf(c->t, 16, "%.*s", (int)(f ? f - k - 1 : strlen(k + 1)), k + 1);
        if (f) { strcpy(c->p, f); } else { strcpy(c->p, "/"); }
    } else if (f) {
        snprintf(c->h, 256, "%.*s", (int)(f - u), u);
        strcpy(c->p, f);
    } else {
        strcpy(c->h, u);
        strcpy(c->p, "/");
    }
}

static void progress(size_t cur, size_t total, time_t start) {
    time_t now = time(NULL);
    double el = difftime(now, start);
    double mbs = (el > 0) ? (cur / 1024.0 / 1024.0) / el : 0;
    if (total > 0) {
        int pct = (int)((cur * 100) / total);
        int eta = (mbs > 0) ? (int)((total - cur) / 1024.0 / 1024.0 / mbs) : 0;
        fprintf(stderr, "%3d%% %6.2f MB/s ETA %ds\r", pct, mbs, eta);
    } else {
        fprintf(stderr, "%6.2f MB %6.2f MB/s\r", cur / 1024.0 / 1024.0, mbs);
    }
}

static char * fetch(struct cfg * c) {
    struct sb b; sb_init(& b);
    int ok = 1;
    mbedtls_net_context fd; mbedtls_entropy_context nt;
    mbedtls_ctr_drbg_context rg; mbedtls_ssl_context sl;
    mbedtls_ssl_config cf;
    mbedtls_net_init(& fd); mbedtls_ssl_init(& sl);
    mbedtls_ssl_config_init(& cf); mbedtls_entropy_init(& nt);
    mbedtls_ctr_drbg_init(& rg);
    mbedtls_ctr_drbg_seed(& rg, mbedtls_entropy_func, & nt,
                          (const unsigned char *) "curly", 5);
    if (mbedtls_net_connect(& fd, c->h, c->t, MBEDTLS_NET_PROTO_TCP) != 0) {
        ok = 0;
    }
    if (ok && c->s) {
        mbedtls_ssl_config_defaults(& cf, MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        mbedtls_ssl_conf_authmode(& cf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(& cf, mbedtls_ctr_drbg_random, & rg);
        mbedtls_ssl_setup(& sl, & cf);
        mbedtls_ssl_set_hostname(& sl, c->h);
        mbedtls_ssl_set_bio(& sl, & fd, mbedtls_net_send,
                            mbedtls_net_recv, NULL);
        if (mbedtls_ssl_handshake(& sl) != 0) { ok = 0; }
    }
    if (ok) {
        struct sb q; sb_init(& q);
        char hdr[8192];
        int l = snprintf(hdr, sizeof(hdr), "%s %s HTTP/1.1\r\nHost: %s\r\n"
                         "User-Agent: curly/1.0\r\n", c->m, c->p, c->h);
        sb_put(& q, hdr, l);
        for (int i = 0; i < c->hc; i++) {
            sb_puts(& q, c->hs[i]); sb_puts(& q, "\r\n");
        }
        if (c->d) {
            char cl[64];
            l = snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n",
                         strlen(c->d));
            sb_put(& q, cl, l);
        }
        sb_puts(& q, "Connection: close\r\n\r\n");
        if (c->d) { sb_puts(& q, c->d); }
        if (c->v) { fprintf(stderr, "> %s", q.data); }
        if (c->s) { mbedtls_ssl_write(& sl, (unsigned char *) q.data,
                                     (int) q.count); }
        else { mbedtls_net_send(& fd, (unsigned char *) q.data,
                                (int) q.count); }
        sb_free(& q);
        char tmp[16384];
        int n, rd = 1;
        size_t ts = 0;
        time_t start = time(NULL);
        while (rd) {
            if (c->s) { n = mbedtls_ssl_read(& sl, (unsigned char *) tmp,
                                            sizeof(tmp)); }
            else { n = mbedtls_net_recv(& fd, (unsigned char *) tmp,
                                         sizeof(tmp)); }
            if (n <= 0) { rd = 0; }
            else {
                sb_put(& b, tmp, n);
                if (ts == 0) {
                    char * cl = strcasestr(b.data, "Content-Length: ");
                    if (cl) { ts = atol(cl + 16); }
                }
                progress(b.count, ts, start);
            }
        }
        if (b.count > 0) { fprintf(stderr, "\n"); }
    }
    mbedtls_net_free(& fd); mbedtls_ssl_free(& sl);
    mbedtls_ssl_config_free(& cf);
    return b.data;
}

int main(int argc, char ** argv) {
    struct cfg c = { .m = "GET", .hc = 0, .s = true };
    int r = 0, cnt = 0, ok = 1;
    memset(c.h, 0, 256); memset(c.p, 0, 1024); memset(c.t, 0, 16);
    memset(c.o, 0, 1024);
    for (int i = 1; i < argc && ok; i++) {
        if ((strcmp(argv[i], "-X") == 0) && i + 1 < argc) {
            strcpy(c.m, argv[++i]);
        } else if ((strcmp(argv[i], "-H") == 0) && i + 1 < argc) {
            if (c.hc < 32) { c.hs[c.hc++] = argv[++i]; }
        } else if ((strcmp(argv[i], "-d") == 0) && i + 1 < argc) {
            c.d = argv[++i];
            if (strcmp(c.m, "GET") == 0) { strcpy(c.m, "POST"); }
        } else if (strcmp(argv[i], "-L") == 0) {
            c.L = true;
        } else if (strcmp(argv[i], "-v") == 0) {
            c.v = true;
        } else if (strcmp(argv[i], "-i") == 0) {
            c.i = true;
        } else if ((strcmp(argv[i], "-o") == 0) && i + 1 < argc) {
            strcpy(c.o, argv[++i]);
        } else if (strcmp(argv[i], "--post301") == 0) {
            c.p301 = true;
        } else if (strcmp(argv[i], "--post302") == 0) {
            c.p302 = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            help(); ok = 0;
        } else if (argv[i][0] != '-') {
            parse_url(argv[i], & c);
        }
    }
    if (ok && c.h[0] == 0) { help(); ok = 0; r = 1; }
    while (ok && cnt < 10) {
        char * b = fetch(& c);
        bool redir = false;
        if (b) {
            if (c.v) {
                char * end = strstr(b, "\r\n\r\n");
                if (end) { fprintf(stderr, "< %.*s\n", (int)(end - b), b); }
            }
            if (c.L && (strncmp(b, "HTTP/1.1 3", 10) == 0 ||
                        strncmp(b, "HTTP/1.0 3", 10) == 0)) {
                char * l = strcasestr(b, "Location: ");
                if (l) {
                    l += 10; char * e = strstr(l, "\r\n");
                    if (e) {
                        * e = '\0';
                        if (strncmp(b + 9, "301", 3) == 0 && ! c.p301) {
                            strcpy(c.m, "GET");
                        }
                        if (strncmp(b + 9, "302", 3) == 0 && ! c.p302) {
                            strcpy(c.m, "GET");
                        }
                        if (strncmp(l, "http", 4) == 0) { parse_url(l, & c); }
                        else { strcpy(c.p, l); }
                        redir = true; cnt++;
                    }
                }
            }
            if (! redir) {
                if (c.i) {
                    char * end = strstr(b, "\r\n\r\n");
                    if (end) { printf("%.*s\n\n", (int)(end - b), b); }
                }
                FILE * f = stdout;
                if (c.o[0]) {
                    if (c.o[strlen(c.o) - 1] == '/') {
                        char * fn = strrchr(c.p, '/');
                        if (fn) { strcat(c.o, fn + 1); }
                    }
                    f = fopen(c.o, "wb");
                }
                render_body(b, f);
                if (f != stdout) { fclose(f); }
                ok = 0;
            }
            free(b);
        } else { ok = 0; r = 1; }
    }
    return r;
}
