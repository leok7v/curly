#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include "third_party/mbedtls/ssl.h"
#include "third_party/mbedtls/net_sockets.h"
#include "third_party/mbedtls/entropy.h"
#include "third_party/mbedtls/ctr_drbg.h"
void handle_response(char *data) {
    char *body = strstr(data, "\r\n\r\n");
    if (!body) return;
    body += 4;
    if (strcasestr(data, "Transfer-Encoding: chunked")) {
        char *p = body;
        while (1) {
            long sz = strtol(p, &p, 16);
            if (sz <= 0) break;
            while (*p == '\r' || *p == '\n') p++;
            printf("%.*s", (int)sz, p);
            p += sz;
            while (*p == '\r' || *p == '\n') p++;
        }
    } else { printf("%s", body); }
}
int main(int argc, char **argv) {
    char host[256] = "models.github.ai", path[1024] = "/catalog/models", port[16] = "443";
    bool https = true;
    if (argc > 1) {
        char *url = argv[1];
        if (strncmp(url, "https://", 8) == 0) { url += 8; https = true; strcpy(port, "443"); }
        else if (strncmp(url, "http://", 7) == 0) { url += 7; https = false; strcpy(port, "80"); }
        char *slash = strchr(url, '/'), *colon = strchr(url, ':');
        if (colon && (!slash || colon < slash)) {
            snprintf(host, sizeof(host), "%.*s", (int)(colon - url), url);
            snprintf(port, sizeof(port), "%.*s", (int)(slash ? slash - colon - 1 : strlen(colon + 1)), colon + 1);
            if (slash) strcpy(path, slash); else strcpy(path, "/");
        } else if (slash) {
            snprintf(host, sizeof(host), "%.*s", (int)(slash - url), url);
            strcpy(path, slash);
        } else { strcpy(host, url); strcpy(path, "/"); }
    }
    for (int redirect = 0; redirect < 5; redirect++) {
        mbedtls_net_context fd; mbedtls_entropy_context ent; mbedtls_ctr_drbg_context drbg;
        mbedtls_ssl_context ssl; mbedtls_ssl_config conf;
        mbedtls_net_init(&fd); mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf);
        mbedtls_entropy_init(&ent); mbedtls_ctr_drbg_init(&drbg);
        mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const unsigned char *)"curly", 5);
        if (mbedtls_net_connect(&fd, host, port, MBEDTLS_NET_PROTO_TCP) != 0) return 1;
        if (https) {
            mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
            mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
            mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
            mbedtls_ssl_setup(&ssl, &conf);
            mbedtls_ssl_set_hostname(&ssl, host);
            mbedtls_ssl_set_bio(&ssl, &fd, mbedtls_net_send, mbedtls_net_recv, NULL);
            if (mbedtls_ssl_handshake(&ssl) != 0) return 1;
        }
        char req[2048];
        snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curly/1.0\r\nConnection: close\r\n\r\n", path, host);
        if (https) mbedtls_ssl_write(&ssl, (unsigned char *)req, strlen(req));
        else mbedtls_net_send(&fd, (unsigned char *)req, strlen(req));
        size_t buf_size = 65536; char *buf = calloc(1, buf_size); int ret, total = 0;
        while (1) {
            if (https) ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf + total, buf_size - total - 1);
            else ret = mbedtls_net_recv(&fd, (unsigned char *)buf + total, buf_size - total - 1);
            if (ret <= 0) break;
            total += ret;
            if (total >= buf_size - 1) {
                buf_size *= 2; buf = realloc(buf, buf_size);
                memset(buf + total, 0, buf_size - total);
            }
        }
        if (total > 0) {
            if (strncmp(buf, "HTTP/1.1 3", 10) == 0 || strncmp(buf, "HTTP/1.0 3", 10) == 0) {
                char *loc = strcasestr(buf, "Location: ");
                if (loc) {
                    loc += 10; char *end = strstr(loc, "\r\n");
                    if (end) {
                        *end = '\0';
                        if (strncmp(loc, "https://", 8) == 0) {
                            loc += 8; https = true; strcpy(port, "443");
                            char *s = strchr(loc, '/');
                            if (s) { snprintf(host, sizeof(host), "%.*s", (int)(s - loc), loc); strcpy(path, s); }
                            else { strcpy(host, loc); strcpy(path, "/"); }
                        } else if (strncmp(loc, "http://", 7) == 0) {
                            loc += 7; https = false; strcpy(port, "80");
                            char *s = strchr(loc, '/');
                            if (s) { snprintf(host, sizeof(host), "%.*s", (int)(s - loc), loc); strcpy(path, s); }
                            else { strcpy(host, loc); strcpy(path, "/"); }
                        } else strcpy(path, loc);
                        free(buf); mbedtls_net_free(&fd); mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf);
                        continue;
                    }
                }
            }
            handle_response(buf);
        }
        free(buf); mbedtls_net_free(&fd); mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf);
        break;
    }
    return 0;
}
