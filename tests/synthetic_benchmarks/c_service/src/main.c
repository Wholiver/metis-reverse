#include "config.h"
#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

int main(int argc, char **argv) {
    ServiceConfig config;
    config_init_default(&config);

    int flag_result = config_parse_args(&config, argc, argv);
    if (flag_result == 2) {
        config_dump(&config);
        return 0;
    } else if (flag_result == 3) {
        /* Intentionally trigger assert for failure testing */
        ServiceConfig *null_cfg = NULL;
        assert(null_cfg != NULL && "config_not_null");
        return 134;
    } else if (flag_result == 4) {
        printf("c_service version 1.0.0 (darwin/arm64)\n");
        return 0;
    } else if (flag_result == 5) {
        printf("Usage: c_service [options]\n");
        printf("Options:\n");
        printf("  --port=PORT        Set service port (default: 8080)\n");
        printf("  --max-clients=NUM  Set maximum concurrent clients\n");
        printf("  --secret=TOKEN     Set secret auth token\n");
        printf("  --dump-config      Print active configuration\n");
        printf("  --version          Show version info\n");
        printf("  --help             Show help message\n");
        return 0;
    }

    if (config.enable_logging) {
        printf("[INFO] Service starting on port %u (max_clients: %u)\n",
               config.port, config.max_clients);
    }

    /* Read raw HTTP request from stdin */
    char input_buf[8192];
    size_t total_read = 0;
    ssize_t bytes_read = 0;

    while ((bytes_read = read(STDIN_FILENO, input_buf + total_read, sizeof(input_buf) - total_read - 1)) > 0) {
        total_read += (size_t)bytes_read;
        if (total_read >= sizeof(input_buf) - 1) break;
    }

    if (total_read == 0) {
        fprintf(stderr, "[ERROR] Empty payload received on stdin\n");
        return 1;
    }

    input_buf[total_read] = '\0';

    HttpRequest req;
    int parse_status = parse_http_request(input_buf, total_read, &req);
    if (parse_status == -2) {
        fprintf(stderr, "[ERROR] Payload exceeds max buffer limit: %zu bytes\n", total_read);
        printf("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n");
        return 2;
    } else if (parse_status == -3) {
        fprintf(stderr, "[ERROR] Malformed or unsupported HTTP method\n");
        printf("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return 3;
    } else if (parse_status != 0) {
        fprintf(stderr, "[ERROR] Failed to parse HTTP request\n");
        printf("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return 4;
    }

    SessionData session;
    memset(&session, 0, sizeof(session));
    session.session_id = 1001;
    strncpy(session.client_ip, "127.0.0.1", sizeof(session.client_ip) - 1);

    const char *token = NULL;
    for (size_t i = 0; i < req.header_count; i++) {
        if (strcasecmp(req.headers[i].key, "Authorization") == 0) {
            if (strncmp(req.headers[i].value, "Bearer ", 7) == 0) {
                token = req.headers[i].value + 7;
            }
            break;
        }
    }

    if (strcmp(req.path, "/auth") == 0) {
        session_authenticate(&session, &config, token);
    }

    HttpResponse res;
    process_http_request(&req, &res, config.secret_token);

    char out_buf[4096];
    size_t out_len = 0;
    format_http_response(&res, out_buf, sizeof(out_buf), &out_len);

    write(STDOUT_FILENO, out_buf, out_len);

    if (config.enable_logging) {
        printf("[INFO] Handled %s %s -> status %d (bytes: %zu)\n",
               req.method, req.path, res.status_code, out_len);
    }

    return 0;
}
