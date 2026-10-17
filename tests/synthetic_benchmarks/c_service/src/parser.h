#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stddef.h>

#define HTTP_REQ_MAGIC 0x48545450 /* 'HTTP' */
#define MAX_PATH_LEN 256
#define MAX_METHOD_LEN 16
#define MAX_HEADERS 16
#define MAX_HEADER_KEY 64
#define MAX_HEADER_VAL 128

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

int parse_http_request(const char *raw_data, size_t len, HttpRequest *req);
void process_http_request(const HttpRequest *req, HttpResponse *res, const char *secret_token);
void format_http_response(const HttpResponse *res, char *out_buf, size_t out_max, size_t *out_len);

#endif /* PARSER_H */
