#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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
            p += 2; printf("%.*s", (int)sz, p);
            p += sz + 2;
        }
    } else { printf("%s", body); }
}
int main(int argc, char **argv) {
    const char *host = "models.github.ai";
    const char *port = "443";
    const char *path = "/catalog/models";
    mbedtls_net_context fd; mbedtls_entropy_context ent; mbedtls_ctr_drbg_context drbg; mbedtls_ssl_context ssl; mbedtls_ssl_config conf;
    mbedtls_net_init(&fd); mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf); mbedtls_entropy_init(&ent); mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const unsigned char *)"micro", 5);
    if (mbedtls_net_connect(&fd, host, port, MBEDTLS_NET_PROTO_TCP) != 0) return 1;
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_hostname(&ssl, host); // CRITICAL: Adds SNI support
    mbedtls_ssl_set_bio(&ssl, &fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    if (mbedtls_ssl_handshake(&ssl) != 0) return 1;
    char req[1024];
    int len = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: cosmo/1.0\r\nConnection: close\r\n\r\n", path, host);
    mbedtls_ssl_write(&ssl, (unsigned char *)req, len);
    char buf[16384] = {0}; int ret, total = 0;
    while ((ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf + total, sizeof(buf) - total - 1)) > 0) { total += ret; }
    handle_response(buf);
    mbedtls_net_free(&fd); mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf); return 0;
}
