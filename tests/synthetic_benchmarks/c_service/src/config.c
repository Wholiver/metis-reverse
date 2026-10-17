#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

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
            return 2; /* Special code for dumping config */
        } else if (strcmp(argv[i], "--debug-force-null") == 0) {
            return 3; /* Special code to trigger assert */
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
