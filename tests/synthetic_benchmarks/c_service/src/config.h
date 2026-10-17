#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CONFIG_MAGIC 0x53455256 /* 'SERV' */
#define MAX_TOKEN_LEN 64
#define MAX_IP_LEN 32

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

void config_init_default(ServiceConfig *cfg);
int config_parse_args(ServiceConfig *cfg, int argc, char **argv);
void config_dump(const ServiceConfig *cfg);
int session_authenticate(SessionData *session, const ServiceConfig *cfg, const char *token);

#endif /* CONFIG_H */
