#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define MAX_CACHE_ENTRIES 32
#define KEY_BUFFER_SIZE   32
#define VAL_BUFFER_SIZE   64

#define FLAG_ACTIVE    0x0001
#define FLAG_READONLY  0x0002
#define FLAG_EPHEMERAL 0x0004

typedef struct {
    uint32_t record_id;
    char key[KEY_BUFFER_SIZE];
    char value[VAL_BUFFER_SIZE];
    uint32_t hash;
    int32_t ttl_seconds;
    uint32_t access_count;
    uint16_t flags;
} CacheRecord;

typedef struct {
    uint32_t magic;          /* 0x4B565354 = "KVST" */
    uint16_t version;        /* 1 */
    uint16_t capacity;       /* MAX_CACHE_ENTRIES */
    uint32_t active_count;
    uint32_t total_lookups;
    uint32_t total_hits;
    CacheRecord records[MAX_CACHE_ENTRIES];
} CacheStore;

/* 32-bit FNV-1a hash algorithm */
static uint32_t calc_fnv1a_hash(const char *key) {
    assert(key != NULL && "null_key_in_hash");
    uint32_t hash = 2166136261u;
    for (size_t i = 0; key[i] != '\0'; i++) {
        hash ^= (uint8_t)key[i];
        hash *= 16777619u;
    }
    return hash;
}

static void cache_init(CacheStore *store, uint16_t capacity) {
    assert(store != NULL && "null_store_pointer");
    assert(capacity > 0 && capacity <= MAX_CACHE_ENTRIES && "invalid_store_capacity");
    memset(store, 0, sizeof(*store));
    store->magic = 0x4B565354;
    store->version = 1;
    store->capacity = capacity;
    store->active_count = 0;
    store->total_lookups = 0;
    store->total_hits = 0;
}

static CacheRecord* cache_lookup(CacheStore *store, const char *key) {
    assert(store != NULL && "null_store_pointer");
    assert(key != NULL && "null_key_pointer");
    size_t key_len = strlen(key);
    assert(key_len > 0 && key_len < KEY_BUFFER_SIZE && "key_length_out_of_range");

    store->total_lookups++;
    uint32_t h = calc_fnv1a_hash(key);
    for (uint16_t i = 0; i < store->capacity; i++) {
        CacheRecord *rec = &store->records[i];
        if ((rec->flags & FLAG_ACTIVE) && rec->hash == h && strcmp(rec->key, key) == 0) {
            rec->access_count++;
            store->total_hits++;
            return rec;
        }
    }
    return NULL;
}

static int cache_set(CacheStore *store, const char *key, const char *val, int32_t ttl, uint16_t flags) {
    assert(store != NULL && "null_store_pointer");
    assert(key != NULL && val != NULL && "null_key_or_val");
    size_t key_len = strlen(key);
    size_t val_len = strlen(val);
    assert(key_len > 0 && key_len < KEY_BUFFER_SIZE && "key_length_out_of_range");
    assert(val_len < VAL_BUFFER_SIZE && "val_length_exceeds_max");

    CacheRecord *existing = cache_lookup(store, key);
    if (existing) {
        if (existing->flags & FLAG_READONLY) {
            fprintf(stderr, "[ERROR] Cannot update read-only entry for key '%s'\n", key);
            return -1;
        }
        strncpy(existing->value, val, VAL_BUFFER_SIZE - 1);
        existing->value[VAL_BUFFER_SIZE - 1] = '\0';
        existing->ttl_seconds = ttl;
        existing->flags = flags | FLAG_ACTIVE;
        printf("[CACHE_UPDATE] key='%s' updated val_len=%zu\n", key, val_len);
        return 0;
    }

    for (uint16_t i = 0; i < store->capacity; i++) {
        CacheRecord *rec = &store->records[i];
        if (!(rec->flags & FLAG_ACTIVE)) {
            rec->record_id = (uint32_t)(i + 1);
            strncpy(rec->key, key, KEY_BUFFER_SIZE - 1);
            rec->key[KEY_BUFFER_SIZE - 1] = '\0';
            strncpy(rec->value, val, VAL_BUFFER_SIZE - 1);
            rec->value[VAL_BUFFER_SIZE - 1] = '\0';
            rec->hash = calc_fnv1a_hash(key);
            rec->ttl_seconds = ttl;
            rec->access_count = 0;
            rec->flags = flags | FLAG_ACTIVE;
            store->active_count++;
            printf("[CACHE_INSERT] id=%u key='%s' val='%s' hash=0x%08X (ttl=%ds, flags=0x%04X)\n",
                   rec->record_id, rec->key, rec->value, rec->hash, rec->ttl_seconds, rec->flags);
            return 0;
        }
    }

    fprintf(stderr, "[ERROR] Cache store is full (capacity=%u)\n", store->capacity);
    return -2;
}

static int cache_delete(CacheStore *store, const char *key) {
    assert(store != NULL && "null_store_pointer");
    assert(key != NULL && "null_key_pointer");
    CacheRecord *rec = cache_lookup(store, key);
    if (!rec) {
        fprintf(stderr, "[WARN] Key '%s' not found for deletion\n", key);
        return -1;
    }
    if (rec->flags & FLAG_READONLY) {
        fprintf(stderr, "[ERROR] Cannot delete read-only entry for key '%s'\n", key);
        return -2;
    }
    printf("[CACHE_DEL] Evicted record id=%u key='%s'\n", rec->record_id, rec->key);
    memset(rec, 0, sizeof(*rec));
    store->active_count--;
    return 0;
}

static void cache_print_stats(const CacheStore *store) {
    assert(store != NULL && "null_store_pointer");
    float hit_rate = 0.0f;
    if (store->total_lookups > 0) {
        hit_rate = ((float)store->total_hits / (float)store->total_lookups) * 100.0f;
    }
    uint32_t misses = (store->total_lookups >= store->total_hits) ?
                      (store->total_lookups - store->total_hits) : 0;
    printf("[CACHE_STATS] magic=0x%08X version=%u entries=%u/%u lookups=%u hits=%u misses=%u (hit_ratio=%.2f%%)\n",
           store->magic, store->version, store->active_count, store->capacity,
           store->total_lookups, store->total_hits, misses, hit_rate);
}

static void cache_dump_table(const CacheStore *store) {
    assert(store != NULL && "null_store_pointer");
    printf("--- Cache Table Dump (%u active records) ---\n", store->active_count);
    for (uint16_t i = 0; i < store->capacity; i++) {
        const CacheRecord *rec = &store->records[i];
        if (rec->flags & FLAG_ACTIVE) {
            printf("  [Slot %02u] id=%u key='%s' val='%s' hash=0x%08X access=%u ttl=%ds flags=0x%04X\n",
                   i, rec->record_id, rec->key, rec->value, rec->hash,
                   rec->access_count, rec->ttl_seconds, rec->flags);
        }
    }
    printf("-------------------------------------------\n");
}

static int run_benchmark_workload(CacheStore *store) {
    printf("[BENCHMARK] Executing standard cache workload...\n");
    cache_set(store, "server.host", "127.0.0.1", 0, FLAG_READONLY);
    cache_set(store, "server.port", "8080", 0, FLAG_READONLY);
    cache_set(store, "session.timeout", "3600", 3600, 0);
    cache_set(store, "app.env", "production", 0, FLAG_READONLY);
    cache_set(store, "temp.worker_token", "tok_99bf21a", 300, FLAG_EPHEMERAL);

    printf("[BENCHMARK] Querying keys...\n");
    CacheRecord *r1 = cache_lookup(store, "server.port");
    if (r1) printf("[QUERY_HIT] key='%s' -> val='%s' (access=%u)\n", r1->key, r1->value, r1->access_count);

    CacheRecord *r2 = cache_lookup(store, "session.timeout");
    if (r2) printf("[QUERY_HIT] key='%s' -> val='%s' (access=%u)\n", r2->key, r2->value, r2->access_count);

    CacheRecord *r3 = cache_lookup(store, "missing.key");
    if (!r3) printf("[QUERY_MISS] key='missing.key' not found\n");

    CacheRecord *r4 = cache_lookup(store, "server.host");
    if (r4) printf("[QUERY_HIT] key='%s' -> val='%s' (access=%u)\n", r4->key, r4->value, r4->access_count);

    printf("[BENCHMARK] Evicting ephemeral key...\n");
    cache_delete(store, "temp.worker_token");

    cache_dump_table(store);
    cache_print_stats(store);
    return 0;
}

int main(int argc, char **argv) {
    CacheStore store;
    cache_init(&store, 16);

    if (argc < 2) {
        fprintf(stderr, "Usage: demo_target [OPTIONS]\n"
                        "Try 'demo_target --help' for more options.\n");
        return 1;
    }

    int32_t cli_ttl = 0;
    uint16_t cli_flags = 0;
    const char *set_pair = NULL;
    const char *get_key = NULL;
    const char *del_key = NULL;
    int run_bench = 0;
    int show_stats = 0;
    int show_dump = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: demo_target [OPTIONS]\n\n"
                   "In-Memory Key-Value Cache Engine Target\n\n"
                   "Options:\n"
                   "  --benchmark              Run built-in cache benchmark workload\n"
                   "  --set=<key>=<val>        Insert or update a key-value record\n"
                   "  --set <key>=<val>        Alternative syntax for --set\n"
                   "  --get=<key>              Lookup key in cache\n"
                   "  --get <key>              Alternative syntax for --get\n"
                   "  --del=<key>              Delete key from cache\n"
                   "  --del <key>              Alternative syntax for --del\n"
                   "  --ttl=<sec>              Specify TTL for inserted entry (default: 0)\n"
                   "  --readonly               Mark inserted entry as read-only\n"
                   "  --stats                  Print cache statistics\n"
                   "  --dump                   Dump active cache entries\n"
                   "  --help                   Display this help message\n");
            return 0;
        } else if (strcmp(argv[i], "--benchmark") == 0) {
            run_bench = 1;
        } else if (strcmp(argv[i], "--readonly") == 0) {
            cli_flags |= FLAG_READONLY;
        } else if (strcmp(argv[i], "--stats") == 0) {
            show_stats = 1;
        } else if (strcmp(argv[i], "--dump") == 0) {
            show_dump = 1;
        } else if (strncmp(argv[i], "--ttl=", 6) == 0) {
            cli_ttl = (int32_t)atoi(argv[i] + 6);
        } else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) {
            cli_ttl = (int32_t)atoi(argv[++i]);
        } else if (strncmp(argv[i], "--set=", 6) == 0) {
            set_pair = argv[i] + 6;
        } else if (strcmp(argv[i], "--set") == 0 && i + 1 < argc) {
            set_pair = argv[++i];
        } else if (strncmp(argv[i], "--get=", 6) == 0) {
            get_key = argv[i] + 6;
        } else if (strcmp(argv[i], "--get") == 0 && i + 1 < argc) {
            get_key = argv[++i];
        } else if (strncmp(argv[i], "--del=", 6) == 0) {
            del_key = argv[i] + 6;
        } else if (strcmp(argv[i], "--del") == 0 && i + 1 < argc) {
            del_key = argv[++i];
        } else {
            fprintf(stderr, "[ERROR] Unknown option '%s'. Try '--help'.\n", argv[i]);
            return 1;
        }
    }

    if (run_bench) {
        return run_benchmark_workload(&store);
    }

    /* Seed default records if performing standalone queries/updates */
    cache_set(&store, "sys.version", "2.4.0", 0, FLAG_READONLY);
    cache_set(&store, "cluster.node", "node-alpha-1", 0, 0);

    if (set_pair) {
        char buf[128];
        strncpy(buf, set_pair, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *eq = strchr(buf, '=');
        if (!eq) {
            fprintf(stderr, "[ERROR] Invalid format for --set. Expected <key>=<val>\n");
            return 1;
        }
        *eq = '\0';
        const char *k = buf;
        const char *v = eq + 1;
        int rc = cache_set(&store, k, v, cli_ttl, cli_flags);
        if (rc != 0) return 2;
    }

    if (get_key) {
        CacheRecord *rec = cache_lookup(&store, get_key);
        if (rec) {
            printf("[GET_HIT] key='%s' value='%s' hash=0x%08X access=%u\n",
                   rec->key, rec->value, rec->hash, rec->access_count);
        } else {
            printf("[GET_MISS] key='%s' not found in cache\n", get_key);
            return 3;
        }
    }

    if (del_key) {
        int rc = cache_delete(&store, del_key);
        if (rc != 0) return 4;
    }

    if (show_dump) {
        cache_dump_table(&store);
    }

    if (show_stats) {
        cache_print_stats(&store);
    }

    return 0;
}
