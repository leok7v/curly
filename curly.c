#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include "third_party/mbedtls/ssl.h"
#include "third_party/mbedtls/net_sockets.h"
#include "third_party/mbedtls/entropy.h"
#include "third_party/mbedtls/ctr_drbg.h"

static void render_chunks(char * p) {
    long z = 1;
    while (z > 0) {
        z = strtol(p, & p, 16);
        if (z > 0) {
            while (* p == '\r' || * p == '\n') { p++; }
            printf("%.*s", (int) z, p);
            p += z;
            while (* p == '\r' || * p == '\n') { p++; }
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

static void parse(char * u, char * h, char * p, char * t, bool * s) {
    if (strncmp(u, "https://", 8) == 0) {
        u += 8; * s = true; strcpy(t, "443");
    } else if (strncmp(u, "http://", 7) == 0) {
        u += 7; * s = false; strcpy(t, "80");
    }
    char * f = strchr(u, '/'), * k = strchr(u, ':');
    if (k && (! f || k < f)) {
        snprintf(h, 256, "%.*s", (int)(k - u), u);
        snprintf(t, 16, "%.*s", (int)(f ? f - k - 1 : strlen(k + 1)), k + 1);
        if (f) {
            strcpy(p, f);
        } else {
            strcpy(p, "/");
        }
    } else if (f) {
        snprintf(h, 256, "%.*s", (int)(f - u), u);
        strcpy(p, f);
    } else {
        strcpy(h, u);
        strcpy(p, "/");
    }
}

static char * fetch(char * h, char * p, char * t, bool s) {
    char * b = NULL;
    int ok = 1, tt = 0;
    mbedtls_net_context fd; mbedtls_entropy_context nt;
    mbedtls_ctr_drbg_context rg; mbedtls_ssl_context sl;
    mbedtls_ssl_config cf;
    mbedtls_net_init(& fd); mbedtls_ssl_init(& sl);
    mbedtls_ssl_config_init(& cf); mbedtls_entropy_init(& nt);
    mbedtls_ctr_drbg_init(& rg);
    mbedtls_ctr_drbg_seed(& rg, mbedtls_entropy_func, & nt,
                          (const unsigned char *) "curly", 5);
    if (mbedtls_net_connect(& fd, h, t, MBEDTLS_NET_PROTO_TCP) != 0) {
        ok = 0;
    }
    if (ok && s) {
        mbedtls_ssl_config_defaults(& cf, MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        mbedtls_ssl_conf_authmode(& cf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(& cf, mbedtls_ctr_drbg_random, & rg);
        mbedtls_ssl_setup(& sl, & cf);
        mbedtls_ssl_set_hostname(& sl, h);
        mbedtls_ssl_set_bio(& sl, & fd, mbedtls_net_send,
                            mbedtls_net_recv, NULL);
        if (mbedtls_ssl_handshake(& sl) != 0) {
            ok = 0;
        }
    }
    if (ok) {
        char q[2048];
        snprintf(q, sizeof(q), "GET %s HTTP/1.1\r\nHost: %s\r\n"
                 "User-Agent: curly/1.0\r\nConnection: close\r\n\r\n", p, h);
        if (s) {
            mbedtls_ssl_write(& sl, (unsigned char *) q, strlen(q));
        } else {
            mbedtls_net_send(& fd, (unsigned char *) q, strlen(q));
        }
        size_t bytes = 65536;
        b = calloc(1, bytes);
        int n, rd = 1;
        while (rd) {
            if (s) {
                n = mbedtls_ssl_read(& sl, (unsigned char *) b + tt,
                                     bytes - tt - 1);
            } else {
                n = mbedtls_net_recv(& fd, (unsigned char *) b + tt,
                                     bytes - tt - 1);
            }
            if (n <= 0) {
                rd = 0;
            } else {
                tt += n;
                if (tt >= (int) bytes - 1) {
                    bytes *= 2;
                    b = realloc(b, bytes);
                    memset(b + tt, 0, bytes - tt);
                }
            }
        }
    }
    mbedtls_net_free(& fd); mbedtls_ssl_free(& sl);
    mbedtls_ssl_config_free(& cf);
    return b;
}

int main(int argc, char ** argv) {
    char h[256] = "models.github.ai", p[1024] = "/catalog/models", t[16] = "443";
    bool s = true;
    int r = 0, c = 0, ok = 1;
    if (argc > 1) { parse(argv[1], h, p, t, & s); }
    while (c < 5 && ok) {
        char * b = fetch(h, p, t, s);
        if (b && (strncmp(b, "HTTP/1.1 3", 10) == 0 ||
                  strncmp(b, "HTTP/1.0 3", 10) == 0)) {
            char * l = strcasestr(b, "Location: ");
            if (l) {
                l += 10;
                char * e = strstr(l, "\r\n");
                if (e) {
                    * e = '\0';
                    if (strncmp(l, "http", 4) == 0) {
                        parse(l, h, p, t, & s);
                    } else {
                        strcpy(p, l);
                    }
                    c++;
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
