#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include "third_party/mbedtls/ssl.h"
#include "third_party/mbedtls/net_sockets.h"
#include "third_party/mbedtls/entropy.h"
#include "third_party/mbedtls/ctr_drbg.h"

struct cfg {
    char h[256]; // host
    char p[1024]; // path
    char t[16]; // port
    char m[16]; // method
    char * d; // data
    char * hs[32]; // headers
    int hc; // header count
    bool s; // ssl
};

static void render_chunks(char * p) {
    long z = 1;
    while (z > 0) {
        z = strtol(p, & p, 16);
        if (z > 0) {
            while (* p == '\r' || * p == '\n') {
                p++;
            }
            printf("%.*s", (int) z, p);
            p += z;
            while (* p == '\r' || * p == '\n') {
                p++;
            }
        }
    }
}

static void emit_body(char * d) {
    char * b = strstr(d, "\r\n\r\n");
    if (b) {
        b += 4;
        if (strcasestr(d, "Transfer-Encoding: chunked")) {
            render_chunks(b);
        } else {
            printf("%s", b);
        }
    }
}

static void parse_url(char * u, struct cfg * c) {
    if (strncmp(u, "https://", 8) == 0) {
        u += 8;
        c->s = true;
        strcpy(c->t, "443");
    } else if (strncmp(u, "http://", 7) == 0) {
        u += 7;
        c->s = false;
        strcpy(c->t, "80");
    }
    char * f = strchr(u, '/'), * k = strchr(u, ':');
    if (k && (! f || k < f)) {
        snprintf(c->h, 256, "%.*s", (int)(k - u), u);
        snprintf(c->t, 16, "%.*s", (int)(f ? f - k - 1 : strlen(k + 1)), k + 1);
        if (f) {
            strcpy(c->p, f);
        } else {
            strcpy(c->p, "/");
        }
    } else if (f) {
        snprintf(c->h, 256, "%.*s", (int)(f - u), u);
        strcpy(c->p, f);
    } else {
        strcpy(c->h, u);
        strcpy(c->p, "/");
    }
}

static char * fetch(struct cfg * c) {
    char * b = NULL;
    int ok = 1, total = 0;
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
        if (mbedtls_ssl_handshake(& sl) != 0) {
            ok = 0;
        }
    }
    if (ok) {
        char q[8192];
        int l = snprintf(q, sizeof(q), "%s %s HTTP/1.1\r\nHost: %s\r\n"
                         "User-Agent: curly/1.0\r\n", c->m, c->p, c->h);
        for (int i = 0; i < c->hc; i++) {
            l += snprintf(q + l, sizeof(q) - l, "%s\r\n", c->hs[i]);
        }
        if (c->d) {
            l += snprintf(q + l, sizeof(q) - l, "Content-Length: %zu\r\n",
                          strlen(c->d));
        }
        l += snprintf(q + l, sizeof(q) - l, "Connection: close\r\n\r\n");
        if (c->d) {
            l += snprintf(q + l, sizeof(q) - l, "%s", c->d);
        }
        if (c->s) {
            mbedtls_ssl_write(& sl, (unsigned char *) q, l);
        } else {
            mbedtls_net_send(& fd, (unsigned char *) q, l);
        }
        size_t bytes = 65536;
        b = calloc(1, bytes);
        int n, rd = 1;
        while (rd) {
            if (c->s) {
                n = mbedtls_ssl_read(& sl, (unsigned char *) b + total,
                                     bytes - total - 1);
            } else {
                n = mbedtls_net_recv(& fd, (unsigned char *) b + total,
                                     bytes - total - 1);
            }
            if (n <= 0) {
                rd = 0;
            } else {
                total += n;
                if (total >= (int) bytes - 1) {
                    bytes *= 2;
                    b = realloc(b, bytes);
                    memset(b + total, 0, bytes - total);
                }
            }
        }
    }
    mbedtls_net_free(& fd); mbedtls_ssl_free(& sl);
    mbedtls_ssl_config_free(& cf);
    return b;
}

int main(int argc, char ** argv) {
    struct cfg c = { .m = "GET", .hc = 0, .s = true, .d = NULL };
    int r = 0, cnt = 0, ok = 1;
    memset(c.h, 0, 256);
    memset(c.p, 0, 1024);
    memset(c.t, 0, 16);
    for (int i = 1; i < argc && ok; i++) {
        if (strcmp(argv[i], "-X") == 0 && i + 1 < argc) {
            strcpy(c.m, argv[++i]);
        } else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
            if (c.hc < 32) {
                c.hs[c.hc++] = argv[++i];
            }
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            c.d = argv[++i];
            if (strcmp(c.m, "GET") == 0) {
                strcpy(c.m, "POST");
            }
        } else if (strcmp(argv[i], "-s") == 0) {
            // ignore silent for now
        } else if (argv[i][0] != '-') {
            parse_url(argv[i], & c);
        }
    }
    if (ok && c.h[0] == 0) {
        ok = 0;
        r = 1;
    }
    while (ok && cnt < 5) {
        char * b = fetch(& c);
        if (b && (strncmp(b, "HTTP/1.1 3", 10) == 0 ||
                  strncmp(b, "HTTP/1.0 3", 10) == 0)) {
            char * l = strcasestr(b, "Location: ");
            if (l) {
                l += 10;
                char * e = strstr(l, "\r\n");
                if (e) {
                    * e = '\0';
                    if (strncmp(l, "http", 4) == 0) {
                        parse_url(l, & c);
                    } else {
                        strcpy(c.p, l);
                    }
                    cnt++;
                } else {
                    emit_body(b);
                    ok = 0;
                }
            } else {
                emit_body(b);
                ok = 0;
            }
        } else if (b) {
            emit_body(b);
            ok = 0;
        } else {
            ok = 0;
            r = 1;
        }
        free(b);
    }
    return r;
}
