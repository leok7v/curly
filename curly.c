#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include "third_party/mbedtls/ssl.h"
#include "third_party/mbedtls/net_sockets.h"
#include "third_party/mbedtls/entropy.h"
#include "third_party/mbedtls/ctr_drbg.h"

struct sb {
    char * data;
    size_t count;
    size_t capacity;
};

struct state {
    struct sb host;
    struct sb path;
    struct sb port;
    struct sb method;
    struct sb output;
    char * data;
    char * headers[32];
    int header_count;
    bool ssl; // enable https
    bool location; // follow redirects
    bool verbose; // show details
    bool include; // show response headers
    bool post301; // maintain post on 301
    bool post302; // maintain post on 302
};

static void sb_init(struct sb * b) {
    b->count = 0;
    b->capacity = 256;
    b->data = malloc(b->capacity);
    if (b->data) { b->data[0] = '\0'; }
}

static void sb_put(struct sb * b, const char * d, int bytes) {
    if (b->data && b->count + (size_t)bytes + 1 > b->capacity) {
        b->capacity = (b->capacity + (size_t)bytes + 1) * 2;
        b->data = realloc(b->data, b->capacity);
    }
    if (b->data) {
        memcpy(b->data + b->count, d, (size_t)bytes);
        b->count += (size_t)bytes;
        b->data[b->count] = '\0';
    }
}

static void sb_puts(struct sb * b, const char * s) {
    sb_put(b, s, (int)strlen(s));
}

static void sb_printf(struct sb * b, const char * f, ...) {
    va_list ap;
    va_start(ap, f);
    int n = vsnprintf(NULL, 0, f, ap);
    va_end(ap);
    if (n > 0) {
        if (b->data && b->count + (size_t)n + 1 > b->capacity) {
            b->capacity = (b->capacity + (size_t)n + 1) * 2;
            b->data = realloc(b->data, b->capacity);
        }
        if (b->data) {
            va_start(ap, f);
            vsnprintf(b->data + b->count, (size_t)n + 1, f, ap);
            va_end(ap);
            b->count += (size_t)n;
        }
    }
}

static void sb_free(struct sb * b) {
    free(b->data);
    b->data = NULL;
    b->count = 0;
    b->capacity = 0;
}

static void help(void) {
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

static char * skip_crlf(char * p) {
    while (*p == '\r' || *p == '\n') { p++; }
    return p;
}

static void render_body(char * data, FILE * file) {
    char * body = strstr(data, "\r\n\r\n");
    if (body) {
        body += 4;
        if (strcasestr(data, "Transfer-Encoding: chunked")) {
            char * p = body;
            long size = 1;
            while (size > 0) {
                size = strtol(p, &p, 16);
                if (size > 0) {
                    p = skip_crlf(p);
                    fwrite(p, 1, (size_t)size, file);
                    p += size;
                    p = skip_crlf(p);
                }
            }
        } else {
            fwrite(body, 1, strlen(body), file);
        }
    }
}

static void parse_url(char * url, struct state * state) {
    state->host.count = 0;
    state->path.count = 0;
    state->port.count = 0;
    if (strncmp(url, "https://", 8) == 0) {
        url += 8;
        state->ssl = true;
        sb_puts(&state->port, "443");
    } else if (strncmp(url, "http://", 7) == 0) {
        url += 7;
        state->ssl = false;
        sb_puts(&state->port, "80");
    } else {
        sb_puts(&state->port, state->ssl ? "443" : "80");
    }
    char * slash = strchr(url, '/');
    char * colon = strchr(url, ':');
    if (colon && (!slash || colon < slash)) {
        sb_put(&state->host, url, (int)(colon - url));
        sb_put(&state->port, colon + 1,
               (int)(slash ? slash - colon - 1 : strlen(colon + 1)));
        if (slash) {
            sb_puts(&state->path, slash);
        } else {
            sb_puts(&state->path, "/");
        }
    } else if (slash) {
        sb_put(&state->host, url, (int)(slash - url));
        sb_puts(&state->path, slash);
    } else {
        sb_puts(&state->host, url);
        sb_puts(&state->path, "/");
    }
}

static void progress(size_t current, size_t total, time_t start) {
    time_t now = time(NULL);
    double elapsed = difftime(now, start);
    double mbs = (elapsed > 0) ? (current / 1024.0 / 1024.0) / elapsed : 0;
    if (total > 0) {
        int percentage = (int)((current * 100) / total);
        int eta = (mbs > 0) ?
            (int)((total - current) / 1024.0 / 1024.0 / mbs) : 0;
        if (eta > 3600) { eta = 3600; }
        fprintf(stderr, "%3d%% %6.2f MB/s ETA %ds\033[K\r",
                percentage, mbs, eta);
    } else {
        fprintf(stderr, "%6.2f MB %6.2f MB/s\033[K\r",
                current / 1024.0 / 1024.0, mbs);
    }
}

static char * fetch(struct state * state, bool * ok) {
    struct sb response;
    sb_init(&response);
    mbedtls_net_context fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_net_init(&fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)"curly", 5);
    if (mbedtls_net_connect(&fd, state->host.data, state->port.data,
                            MBEDTLS_NET_PROTO_TCP) != 0) { *ok = false; }
    if (*ok && state->ssl) {
        mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &drbg);
        mbedtls_ssl_setup(&ssl, &config);
        mbedtls_ssl_set_hostname(&ssl, state->host.data);
        mbedtls_ssl_set_bio(&ssl, &fd, mbedtls_net_send,
                            mbedtls_net_recv, NULL);
        if (mbedtls_ssl_handshake(&ssl) != 0) { *ok = false; }
    }
    if (*ok) {
        struct sb request;
        sb_init(&request);
        sb_printf(&request, "%s %s HTTP/1.1\r\nHost: %s\r\n"
                  "User-Agent: curly/1.0\r\n", state->method.data,
                  state->path.data, state->host.data);
        for (int i = 0; i < state->header_count; i++) {
            sb_printf(&request, "%s\r\n", state->headers[i]);
        }
        if (state->data) {
            sb_printf(&request, "Content-Length: %zu\r\n",
                      strlen(state->data));
        }
        sb_puts(&request, "Connection: close\r\n\r\n");
        if (state->data) { sb_puts(&request, state->data); }
        if (state->verbose) { fprintf(stderr, "> %s", request.data); }
        if (state->ssl) {
            mbedtls_ssl_write(&ssl, (unsigned char *)request.data,
                              (int)request.count);
        } else {
            mbedtls_net_send(&fd, (unsigned char *)request.data,
                             (int)request.count);
        }
        sb_free(&request);
        char buffer[16 * 1024];
        int n;
        int reading = 1;
        size_t total_size = 0;
        time_t start = time(NULL);
        while (reading) {
            if (state->ssl) {
                n = mbedtls_ssl_read(&ssl, (unsigned char *)buffer,
                                     sizeof(buffer));
            } else {
                n = mbedtls_net_recv(&fd, (unsigned char *)buffer,
                                     sizeof(buffer));
            }
            if (n <= 0) {
                reading = 0;
            } else {
                sb_put(&response, buffer, n);
                if (total_size == 0) {
                    char * cl = strcasestr(response.data, "Content-Length: ");
                    if (cl) { total_size = atol(cl + 16); }
                }
                progress(response.count, total_size, start);
            }
        }
        if (response.count > 0) { fprintf(stderr, "\n"); }
    }
    mbedtls_net_free(&fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
    return response.data;
}

int main(int argc, char ** argv) {
    struct state state = { .header_count = 0, .ssl = true };
    int count = 0;
    bool ok = true;
    sb_init(&state.host);
    sb_init(&state.path);
    sb_init(&state.port);
    sb_init(&state.method);
    sb_init(&state.output);
    sb_puts(&state.method, "GET");
    for (int i = 1; i < argc && ok; i++) {
        if ((strcmp(argv[i], "-X") == 0) && i + 1 < argc) {
            state.method.count = 0;
            sb_puts(&state.method, argv[++i]);
        } else if ((strcmp(argv[i], "-H") == 0) && i + 1 < argc) {
            if (state.header_count < 32) {
                state.headers[state.header_count++] = argv[++i];
            }
        } else if ((strcmp(argv[i], "-d") == 0) && i + 1 < argc) {
            state.data = argv[++i];
            if (strcmp(state.method.data, "GET") == 0) {
                state.method.count = 0;
                sb_puts(&state.method, "POST");
            }
        } else if (strcmp(argv[i], "-L") == 0) {
            state.location = true;
        } else if (strcmp(argv[i], "-v") == 0) {
            state.verbose = true;
        } else if (strcmp(argv[i], "-i") == 0) {
            state.include = true;
        } else if ((strcmp(argv[i], "-o") == 0) && i + 1 < argc) {
            sb_puts(&state.output, argv[++i]);
        } else if (strcmp(argv[i], "--post301") == 0) {
            state.post301 = true;
        } else if (strcmp(argv[i], "--post302") == 0) {
            state.post302 = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            help();
            ok = false;
        } else if (argv[i][0] != '-') {
            parse_url(argv[i], &state);
        }
    }
    if (ok && state.host.count == 0) {
        help();
        ok = false;
    }
    while (ok && count < 10) {
        char * data = fetch(&state, &ok);
        bool redirected = false;
        if (ok && data) {
            if (state.verbose) {
                char * end = strstr(data, "\r\n\r\n");
                if (end) {
                    fprintf(stderr, "< %.*s\n", (int)(end - data), data);
                }
            }
            if (state.location && (strncmp(data, "HTTP/1.1 3", 10) == 0 ||
                                   strncmp(data, "HTTP/1.0 3", 10) == 0)) {
                char * loc = strcasestr(data, "Location: ");
                if (loc) {
                    loc += 10;
                    char * end = strstr(loc, "\r\n");
                    if (end) {
                        *end = '\0';
                        if (strncmp(data + 9, "301", 3) == 0 &&
                            !state.post301) {
                            state.method.count = 0;
                            sb_puts(&state.method, "GET");
                        }
                        if (strncmp(data + 9, "302", 3) == 0 &&
                            !state.post302) {
                            state.method.count = 0;
                            sb_puts(&state.method, "GET");
                        }
                        if (strncmp(loc, "http", 4) == 0) {
                            parse_url(loc, &state);
                        } else {
                            state.path.count = 0;
                            sb_puts(&state.path, loc);
                        }
                        redirected = true;
                        count++;
                    }
                }
            }
            if (!redirected) {
                if (state.include) {
                    char * end = strstr(data, "\r\n\r\n");
                    if (end) {
                        printf("%.*s\n\n", (int)(end - data), data);
                    }
                }
                FILE * file = stdout;
                if (state.output.count > 0) {
                    if (state.output.data[state.output.count - 1] == '/') {
                        char * fn = strrchr(state.path.data, '/');
                        if (fn) { sb_puts(&state.output, fn + 1); }
                    }
                    file = fopen(state.output.data, "wb");
                }
                render_body(data, file);
                if (file != stdout) { fclose(file); }
                ok = false;
            }
            free(data);
        } else {
            ok = false;
        }
    }
    sb_free(&state.host);
    sb_free(&state.path);
    sb_free(&state.port);
    sb_free(&state.method);
    sb_free(&state.output);
    return !ok ? 0 : 1;
}
