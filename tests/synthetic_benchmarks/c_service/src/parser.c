#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

int parse_http_request(const char *raw_data, size_t len, HttpRequest *req) {
    assert(raw_data != NULL && "raw_data_not_null");
    assert(req != NULL && "req_not_null");
    assert(len > 0 && "len_check");

    memset(req, 0, sizeof(HttpRequest));
    req->magic = HTTP_REQ_MAGIC;

    if (len > 4096) {
        return -2; /* Payload too large */
    }

    /* Make copy to tokenize safely */
    char buf[4096];
    size_t copy_len = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
    memcpy(buf, raw_data, copy_len);
    buf[copy_len] = '\0';

    char *line = strtok(buf, "\r\n");
    if (line == NULL) {
        return -1;
    }

    /* Parse request line: METHOD /path HTTP/1.x */
    char method[MAX_METHOD_LEN] = {0};
    char path[MAX_PATH_LEN] = {0};
    char version[16] = {0};

    int items = sscanf(line, "%15s %255s %15s", method, path, version);
    if (items < 2) {
        return -1;
    }

    /* Validate method */
    if (strcmp(method, "GET") != 0 &&
        strcmp(method, "POST") != 0 &&
        strcmp(method, "PUT") != 0 &&
        strcmp(method, "DELETE") != 0 &&
        strcmp(method, "HEAD") != 0) {
        return -3; /* Unknown/Malformed method */
    }

    strncpy(req->method, method, sizeof(req->method) - 1);
    strncpy(req->path, path, sizeof(req->path) - 1);

    /* Parse headers */
    while ((line = strtok(NULL, "\r\n")) != NULL) {
        if (strlen(line) == 0) {
            break; /* Empty line before body */
        }
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

    /* Route: /health */
    if (strcmp(req->path, "/health") == 0) {
        res->status_code = 200;
        res->status_text = "OK";
        snprintf(res->response_body, sizeof(res->response_body), "{\"status\":\"healthy\",\"uptime\":3600}\n");
        res->body_len = strlen(res->response_body);
        return;
    }

    /* Route: /auth */
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

    /* Route: /api/echo */
    if (strncmp(req->path, "/api/echo", 9) == 0) {
        res->status_code = 200;
        res->status_text = "OK";
        snprintf(res->response_body, sizeof(res->response_body), "{\"method\":\"%s\",\"path\":\"%s\",\"headers_count\":%zu}\n",
                 req->method, req->path, req->header_count);
        res->body_len = strlen(res->response_body);
        return;
    }

    /* Default 404 */
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
