/* Reconstructed C Service - Ground Truth Reference Implementation */
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>

#define CONFIG_MAGIC 0x53455256
#define HTTP_REQ_MAGIC 0x48545450
#define MAX_TOKEN_LEN 64
#define MAX_IP_LEN 32
#define MAX_PATH_LEN 256
#define MAX_METHOD_LEN 16
#define MAX_HEADERS 16
#define MAX_HEADER_KEY 64
#define MAX_HEADER_VAL 128

typedef struct ServiceConfig {
    uint32_t magic;
    uint32_t port;
    uint32_t max_clients;
    char secret_token[MAX_TOKEN_LEN];
    int enable_logging;
    uint32_t timeout_ms;
} ServiceConfig;

typedef struct SessionData {
    uint32_t session_id;
    char client_ip[MAX_IP_LEN];
    char auth_token[MAX_TOKEN_LEN];
    int is_authenticated;
    size_t request_count;
    uint32_t last_active_ts;
} SessionData;

typedef struct HttpHeader {
    char key[MAX_HEADER_KEY];
    char value[MAX_HEADER_VAL];
} HttpHeader;

typedef struct HttpRequest {
    uint32_t magic;
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    HttpHeader headers[MAX_HEADERS];
    size_t header_count;
    char body[1024];
    size_t body_len;
} HttpRequest;

typedef struct HttpResponse {
    int status_code;
    const char *status_text;
    char response_body[2048];
    size_t body_len;
} HttpResponse;

void config_init_default(ServiceConfig *cfg) {
    assert(cfg != NULL && "config_not_null");
    cfg->magic = CONFIG_MAGIC;
    cfg->port = 8080;
    cfg->max_clients = 128;
    strncpy(cfg->secret_token, "metis_default_secret_token_2026", sizeof(cfg->secret_token) - 1);
    cfg->secret_token[sizeof(cfg->secret_token) - 1] = '\0';
    cfg->enable_logging = 1;
    cfg->timeout_ms = 5000;
}

int config_parse_args(ServiceConfig *cfg, int argc, char **argv) {
    assert(cfg != NULL && "config_not_null");
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--port=", 7) == 0) {
            cfg->port = (uint32_t)atoi(argv[i] + 7);
        } else if (strncmp(argv[i], "--max-clients=", 14) == 0) {
            cfg->max_clients = (uint32_t)atoi(argv[i] + 14);
        } else if (strncmp(argv[i], "--secret=", 9) == 0) {
            strncpy(cfg->secret_token, argv[i] + 9, sizeof(cfg->secret_token) - 1);
            cfg->secret_token[sizeof(cfg->secret_token) - 1] = '\0';
        } else if (strcmp(argv[i], "--quiet") == 0) {
            cfg->enable_logging = 0;
        } else if (strcmp(argv[i], "--dump-config") == 0) {
            return 2;
        } else if (strcmp(argv[i], "--debug-force-null") == 0) {
            return 3;
        } else if (strcmp(argv[i], "--version") == 0) {
            return 4;
        } else if (strcmp(argv[i], "--help") == 0) {
            return 5;
        }
    }
    return 0;
}

void config_dump(const ServiceConfig *cfg) {
    assert(cfg != NULL && "config_not_null");
    printf("[CONFIG] magic=0x%08X port=%u max_clients=%u secret=%s logging=%d timeout=%u\n",
           cfg->magic, cfg->port, cfg->max_clients, cfg->secret_token, cfg->enable_logging, cfg->timeout_ms);
}

int session_authenticate(SessionData *session, const ServiceConfig *cfg, const char *token) {
    assert(session != NULL && "session_not_null");
    assert(cfg != NULL && "config_not_null");
    if (token == NULL || strlen(token) == 0) {
        session->is_authenticated = 0;
        return 0;
    }
    if (strcmp(token, cfg->secret_token) == 0) {
        session->is_authenticated = 1;
        strncpy(session->auth_token, token, sizeof(session->auth_token) - 1);
        session->auth_token[sizeof(session->auth_token) - 1] = '\0';
        if (cfg->enable_logging) {
            printf("[DEBUG] Session %u authenticated for client %s\n",
                   session->session_id, session->client_ip);
        }
        return 1;
    } else {
        session->is_authenticated = 0;
        if (cfg->enable_logging) {
            fprintf(stderr, "[ERROR] Auth failed for client %s (id: %u)\n",
                    session->client_ip, session->session_id);
        }
        return 0;
    }
}

int parse_http_request(const char *raw_data, size_t len, HttpRequest *req) {
    assert(raw_data != NULL && "raw_data_not_null");
    assert(req != NULL && "req_not_null");
    assert(len > 0 && "len_check");

    memset(req, 0, sizeof(HttpRequest));
    req->magic = HTTP_REQ_MAGIC;

    if (len > 4096) return -2;

    char buf[4096];
    size_t copy_len = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
    memcpy(buf, raw_data, copy_len);
    buf[copy_len] = '\0';

    char *line = strtok(buf, "\r\n");
    if (line == NULL) return -1;

    char method[MAX_METHOD_LEN] = {0};
    char path[MAX_PATH_LEN] = {0};
    char version[16] = {0};

    int items = sscanf(line, "%15s %255s %15s", method, path, version);
    if (items < 2) return -1;

    if (strcmp(method, "GET") != 0 &&
        strcmp(method, "POST") != 0 &&
        strcmp(method, "PUT") != 0 &&
        strcmp(method, "DELETE") != 0 &&
        strcmp(method, "HEAD") != 0) {
        return -3;
    }

    strncpy(req->method, method, sizeof(req->method) - 1);
    strncpy(req->path, path, sizeof(req->path) - 1);

    while ((line = strtok(NULL, "\r\n")) != NULL) {
        if (strlen(line) == 0) break;
        if (req->header_count < MAX_HEADERS) {
            char *colon = strchr(line, ':');
            if (colon != NULL) {
                *colon = '\0';
                char *key = line;
                char *val = colon + 1;
                while (*val == ' ' || *val == '\t') val++;
                strncpy(req->headers[req->header_count].key, key, MAX_HEADER_KEY - 1);
                strncpy(req->headers[req->header_count].value, val, MAX_HEADER_VAL - 1);
                req->header_count++;
            }
        }
    }
    return 0;
}

void process_http_request(const HttpRequest *req, HttpResponse *res, const char *secret_token) {
    assert(req != NULL && "req_not_null");
    assert(req->magic == HTTP_REQ_MAGIC && "http_magic_check");
    assert(res != NULL && "res_not_null");

    memset(res, 0, sizeof(HttpResponse));

    if (strcmp(req->path, "/health") == 0) {
        res->status_code = 200;
        res->status_text = "OK";
        snprintf(res->response_body, sizeof(res->response_body), "{\"status\":\"healthy\",\"uptime\":3600}\n");
        res->body_len = strlen(res->response_body);
        return;
    }

    if (strcmp(req->path, "/auth") == 0) {
        const char *auth_header = NULL;
        for (size_t i = 0; i < req->header_count; i++) {
            if (strcasecmp(req->headers[i].key, "Authorization") == 0) {
                auth_header = req->headers[i].value;
                break;
            }
        }

        if (auth_header != NULL && strncmp(auth_header, "Bearer ", 7) == 0) {
            const char *token = auth_header + 7;
            if (secret_token != NULL && strcmp(token, secret_token) == 0) {
                res->status_code = 200;
                res->status_text = "OK";
                snprintf(res->response_body, sizeof(res->response_body), "{\"authenticated\":true,\"user\":\"admin\"}\n");
                res->body_len = strlen(res->response_body);
                return;
            }
        }

        res->status_code = 401;
        res->status_text = "Unauthorized";
        snprintf(res->response_body, sizeof(res->response_body), "{\"error\":\"invalid_credentials\"}\n");
        res->body_len = strlen(res->response_body);
        return;
    }

    if (strncmp(req->path, "/api/echo", 9) == 0) {
        res->status_code = 200;
        res->status_text = "OK";
        snprintf(res->response_body, sizeof(res->response_body), "{\"method\":\"%s\",\"path\":\"%s\",\"headers_count\":%zu}\n",
                 req->method, req->path, req->header_count);
        res->body_len = strlen(res->response_body);
        return;
    }

    res->status_code = 404;
    res->status_text = "Not Found";
    snprintf(res->response_body, sizeof(res->response_body), "{\"error\":\"not_found\",\"path\":\"%s\"}\n", req->path);
    res->body_len = strlen(res->response_body);
}

void format_http_response(const HttpResponse *res, char *out_buf, size_t out_max, size_t *out_len) {
    assert(res != NULL && "res_not_null");
    assert(out_buf != NULL && "out_buf_not_null");

    int written = snprintf(out_buf, out_max,
        "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s",
        res->status_code, res->status_text, res->body_len, res->response_body);
    
    if (written > 0 && out_len != NULL) {
        *out_len = (size_t)written;
    }
}

int main(int argc, char **argv) {
    ServiceConfig config;
    config_init_default(&config);

    int flag_result = config_parse_args(&config, argc, argv);
    if (flag_result == 2) {
        config_dump(&config);
        return 0;
    } else if (flag_result == 3) {
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
