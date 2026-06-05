#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <event2/event.h>

#include "lsquic.h"
#include "lsquic_hash.h"
#include "test_common.h"
#include "prog.h"
#include "test_cert.h"

#define APPLICATION_PROTOCOL "perf"
#define DEFAULT_MAX_RUN_REQUESTS 4096ULL
#define TRANSFER_CONNECTION_WINDOW (32U * 1024U * 1024U)
#define TRANSFER_STREAM_WINDOW (16U * 1024U * 1024U)
#define WRITE_CHUNK_SIZE 32768U

static int debug_enabled(void) {
    static int initialized = 0;
    static int enabled = 0;
    if (!initialized) {
        enabled = getenv("LSQUIC_PERF_DEBUG") != NULL;
        initialized = 1;
    }
    return enabled;
}

static FILE *open_json_output(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        return NULL;
    }
    FILE *out = fdopen(fd, "w");
    if (out == NULL) {
        close(fd);
    }
    return out;
}

#define DEBUG_LOG(...)                                                                             \
    do {                                                                                           \
        if (debug_enabled()) {                                                                     \
            fprintf(stderr, __VA_ARGS__);                                                          \
        }                                                                                          \
    } while (0)

typedef struct {
    uint64_t value;
    int set;
} optional_u64_t;

typedef struct {
    char role[16];
    char host[256];
    uint16_t port;
    char server_name[256];
    int verify_peer;
    char io_backend[32];
    char congestion_control[32];
    char certificate_chain[512];
    char private_key[512];
    int disable_pmtud;
    char mode[16];
    char direction[16];
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t streams;
    uint64_t connections;
    uint64_t requests_in_flight;
    optional_u64_t requests;
    optional_u64_t total_bytes;
    uint64_t warmup_us;
    uint64_t duration_us;
    char json_out[512];
} config_t;

typedef struct {
    uint64_t *values;
    size_t len;
    size_t cap;
} latency_vec_t;

typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t requests_completed;
    uint64_t skipped_setup_errors;
    latency_vec_t latencies;
} counters_t;

typedef struct {
    uint64_t min_us;
    uint64_t avg_us;
    uint64_t p50_us;
    uint64_t p90_us;
    uint64_t p99_us;
    uint64_t max_us;
} latency_summary_t;

typedef struct client_state client_state_t;

struct lsquic_conn_ctx {
    client_state_t *state;
    lsquic_conn_t *conn;
    uint64_t active_streams;
    int ready;
    int closing;
    struct lsquic_conn_ctx *next;
};

struct lsquic_stream_ctx {
    client_state_t *state;
    struct lsquic_conn_ctx *conn_ctx;
    uint8_t header[8];
    size_t header_sent;
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t request_sent;
    uint64_t response_read;
    uint64_t started_at;
    int counts_latency;
    int completed;
    union {
        uint64_t response_left;
        uint8_t header_buf[8];
    } server;
    size_t server_header_read;
};

struct client_state {
    config_t cfg;
    struct prog prog;
    struct sport_head sports;
    struct event *deadline_timer;
    struct lsquic_conn_ctx *conns;
    counters_t counters;
    uint64_t target_requests;
    uint64_t started_requests;
    uint64_t active_streams;
    uint64_t pending_streams;
    uint64_t active_conns;
    uint64_t pending_conns;
    uint64_t measure_start_us;
    uint64_t deadline_us;
    int bounded;
    int stop_starting;
    int failed;
    char failure_reason[256];
};

typedef struct {
    const char *status;
    const char *failure_reason;
    const config_t *cfg;
    int64_t elapsed_ms;
    counters_t counters;
    latency_summary_t latency;
    double throughput_mib_per_s;
    double throughput_gbit_per_s;
    double requests_per_s;
} run_summary_t;

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static uint64_t duration_millis(uint64_t usec) {
    return usec / 1000ULL;
}

static uint64_t parse_u64(const char *text, const char *name) {
    char *end = NULL;
    errno = 0;
    uint64_t value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != 0) {
        fprintf(stderr, "invalid %s: %s\n", name, text);
        exit(2);
    }
    return value;
}

static uint64_t parse_duration_us(const char *text) {
    size_t len = strlen(text);
    char tmp[64];
    if (len > 2 && strcmp(text + len - 2, "ms") == 0) {
        if (len - 2 >= sizeof(tmp)) {
            fprintf(stderr, "invalid duration: %s\n", text);
            exit(2);
        }
        memcpy(tmp, text, len - 2);
        tmp[len - 2] = 0;
        return parse_u64(tmp, "duration") * 1000ULL;
    }
    if (len > 1 && text[len - 1] == 's') {
        if (len - 1 >= sizeof(tmp)) {
            fprintf(stderr, "invalid duration: %s\n", text);
            exit(2);
        }
        memcpy(tmp, text, len - 1);
        tmp[len - 1] = 0;
        return parse_u64(tmp, "duration") * 1000000ULL;
    }
    fprintf(stderr, "invalid duration: %s\n", text);
    exit(2);
}

static const char *take_value(int argc, char **argv, int *index, const char *arg) {
    if (*index >= argc) {
        fprintf(stderr, "missing value for %s\n", arg);
        exit(2);
    }
    const char *value = argv[*index];
    *index += 1;
    return value;
}

static void copy_arg(char *dst, size_t dst_len, const char *value, const char *name) {
    if (strlen(value) >= dst_len) {
        fprintf(stderr, "%s is too long\n", name);
        exit(2);
    }
    snprintf(dst, dst_len, "%s", value);
}

static void init_config(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->host, sizeof(cfg->host), "127.0.0.1");
    cfg->port = 4433;
    snprintf(cfg->server_name, sizeof(cfg->server_name), "localhost");
    snprintf(cfg->io_backend, sizeof(cfg->io_backend), "socket");
    snprintf(cfg->congestion_control, sizeof(cfg->congestion_control), "default");
    snprintf(cfg->certificate_chain, sizeof(cfg->certificate_chain),
             "tests/fixtures/quic-server-cert.pem");
    snprintf(cfg->private_key, sizeof(cfg->private_key), "tests/fixtures/quic-server-key.pem");
    cfg->disable_pmtud = 1;
    snprintf(cfg->mode, sizeof(cfg->mode), "bulk");
    snprintf(cfg->direction, sizeof(cfg->direction), "download");
    cfg->request_bytes = 64;
    cfg->response_bytes = 64;
    cfg->streams = 1;
    cfg->connections = 1;
    cfg->requests_in_flight = 1;
    cfg->duration_us = 5000000ULL;
}

static int is_mode(const config_t *cfg, const char *mode) {
    return strcmp(cfg->mode, mode) == 0;
}

static int is_direction(const config_t *cfg, const char *direction) {
    return strcmp(cfg->direction, direction) == 0;
}

static void validate_config(const config_t *cfg) {
    if (!is_mode(cfg, "bulk") && !is_mode(cfg, "rr") && !is_mode(cfg, "crr")) {
        fprintf(stderr, "unsupported mode: %s\n", cfg->mode);
        exit(2);
    }
    if (strcmp(cfg->io_backend, "socket") != 0) {
        fprintf(stderr, "lsquic-perf only supports the socket backend\n");
        exit(2);
    }
    if (strcmp(cfg->congestion_control, "default") != 0 &&
        strcmp(cfg->congestion_control, "newreno") != 0 &&
        strcmp(cfg->congestion_control, "reno") != 0 &&
        strcmp(cfg->congestion_control, "cubic") != 0 &&
        strcmp(cfg->congestion_control, "bbr") != 0 &&
        strcmp(cfg->congestion_control, "copa") != 0) {
        fprintf(stderr, "unsupported congestion-control label: %s\n", cfg->congestion_control);
        exit(2);
    }
    if (strcmp(cfg->congestion_control, "copa") == 0) {
        fprintf(stderr,
                "lsquic-perf does not provide Copa; use PERF_CONGESTION_CONTROLS=default\n");
        exit(2);
    }
    if (!is_direction(cfg, "upload") && !is_direction(cfg, "download") &&
        !is_direction(cfg, "stay")) {
        fprintf(stderr, "unsupported direction: %s\n", cfg->direction);
        exit(2);
    }
    if (cfg->streams == 0 || cfg->connections == 0 || cfg->requests_in_flight == 0) {
        fprintf(stderr, "streams, connections, and requests-in-flight must be greater than zero\n");
        exit(2);
    }
}

static config_t parse_args(int argc, char **argv) {
    config_t cfg;
    init_config(&cfg);
    if (argc < 2 || (strcmp(argv[1], "client") != 0 && strcmp(argv[1], "server") != 0)) {
        fprintf(stderr, "usage: lsquic-perf [client|server] [options]\n");
        exit(2);
    }
    copy_arg(cfg.role, sizeof(cfg.role), argv[1], "role");
    int i = 2;
    while (i < argc) {
        const char *arg = argv[i++];
        if (strcmp(arg, "--host") == 0) {
            copy_arg(cfg.host, sizeof(cfg.host), take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--port") == 0) {
            uint64_t port = parse_u64(take_value(argc, argv, &i, arg), "port");
            if (port > 65535) {
                fprintf(stderr, "invalid port: %" PRIu64 "\n", port);
                exit(2);
            }
            cfg.port = (uint16_t)port;
        } else if (strcmp(arg, "--server-name") == 0) {
            copy_arg(cfg.server_name, sizeof(cfg.server_name), take_value(argc, argv, &i, arg),
                     arg);
        } else if (strcmp(arg, "--verify-peer") == 0) {
            cfg.verify_peer = 1;
        } else if (strcmp(arg, "--io-backend") == 0) {
            copy_arg(cfg.io_backend, sizeof(cfg.io_backend), take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--congestion-control") == 0) {
            copy_arg(cfg.congestion_control, sizeof(cfg.congestion_control),
                     take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--certificate-chain") == 0) {
            copy_arg(cfg.certificate_chain, sizeof(cfg.certificate_chain),
                     take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--private-key") == 0) {
            copy_arg(cfg.private_key, sizeof(cfg.private_key), take_value(argc, argv, &i, arg),
                     arg);
        } else if (strcmp(arg, "--disable-pmtud") == 0) {
            cfg.disable_pmtud = 1;
        } else if (strcmp(arg, "--mode") == 0) {
            copy_arg(cfg.mode, sizeof(cfg.mode), take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--direction") == 0) {
            copy_arg(cfg.direction, sizeof(cfg.direction), take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--request-bytes") == 0) {
            cfg.request_bytes = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--response-bytes") == 0) {
            cfg.response_bytes = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--streams") == 0) {
            cfg.streams = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--connections") == 0) {
            cfg.connections = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--requests-in-flight") == 0) {
            cfg.requests_in_flight = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--requests") == 0) {
            cfg.requests.value = parse_u64(take_value(argc, argv, &i, arg), arg);
            cfg.requests.set = 1;
        } else if (strcmp(arg, "--total-bytes") == 0) {
            cfg.total_bytes.value = parse_u64(take_value(argc, argv, &i, arg), arg);
            cfg.total_bytes.set = 1;
        } else if (strcmp(arg, "--warmup") == 0) {
            cfg.warmup_us = parse_duration_us(take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--duration") == 0) {
            cfg.duration_us = parse_duration_us(take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--json-out") == 0) {
            copy_arg(cfg.json_out, sizeof(cfg.json_out), take_value(argc, argv, &i, arg), arg);
        } else {
            fprintf(stderr, "unknown argument: %s\n", arg);
            exit(2);
        }
    }
    validate_config(&cfg);
    return cfg;
}

static uint64_t encode_be64(uint64_t value) {
    uint64_t high = htonl((uint32_t)(value >> 32));
    uint64_t low = htonl((uint32_t)(value & 0xffffffffu));
    return (low << 32) | high;
}

static uint64_t decode_be64(const uint8_t bytes[8]) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

static void latency_push(latency_vec_t *vec, uint64_t value) {
    if (vec->len == vec->cap) {
        size_t new_cap = vec->cap ? vec->cap * 2 : 256;
        uint64_t *new_values = realloc(vec->values, new_cap * sizeof(vec->values[0]));
        if (!new_values) {
            perror("realloc");
            exit(1);
        }
        vec->values = new_values;
        vec->cap = new_cap;
    }
    vec->values[vec->len++] = value;
}

static int compare_u64(const void *a, const void *b) {
    uint64_t lhs = *(const uint64_t *)a;
    uint64_t rhs = *(const uint64_t *)b;
    return (lhs > rhs) - (lhs < rhs);
}

static uint64_t percentile(const uint64_t *values, size_t len, double pct) {
    size_t rank = (size_t)ceil((pct / 100.0) * (double)len);
    if (rank == 0) {
        rank = 1;
    }
    if (rank > len) {
        rank = len;
    }
    return values[rank - 1];
}

static latency_summary_t summarize_latency(const latency_vec_t *latencies) {
    latency_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    if (latencies->len == 0) {
        return summary;
    }
    uint64_t *values = malloc(latencies->len * sizeof(values[0]));
    if (!values) {
        perror("malloc");
        exit(1);
    }
    memcpy(values, latencies->values, latencies->len * sizeof(values[0]));
    qsort(values, latencies->len, sizeof(values[0]), compare_u64);
    uint64_t sum = 0;
    for (size_t i = 0; i < latencies->len; ++i) {
        sum += values[i];
    }
    summary.min_us = values[0];
    summary.avg_us = sum / latencies->len;
    summary.p50_us = percentile(values, latencies->len, 50.0);
    summary.p90_us = percentile(values, latencies->len, 90.0);
    summary.p99_us = percentile(values, latencies->len, 99.0);
    summary.max_us = values[latencies->len - 1];
    free(values);
    return summary;
}

static uint64_t ceil_div(uint64_t numerator, uint64_t denominator) {
    if (denominator == 0) {
        denominator = 1;
    }
    return numerator / denominator + (numerator % denominator != 0);
}

static void apply_lsquic_settings(struct prog *prog, const config_t *cfg) {
    prog->prog_settings.es_init_max_data = TRANSFER_CONNECTION_WINDOW;
    prog->prog_settings.es_init_max_stream_data_bidi_local = TRANSFER_STREAM_WINDOW;
    prog->prog_settings.es_init_max_stream_data_bidi_remote = TRANSFER_STREAM_WINDOW;
    prog->prog_settings.es_init_max_streams_bidi =
        (unsigned)(cfg->streams > 100 ? cfg->streams : 100);
    prog->prog_settings.es_max_streams_in = (unsigned)(cfg->streams > 100 ? cfg->streams : 100);
    if (cfg->disable_pmtud) {
        prog->prog_settings.es_dplpmtud = 0;
    }
    if (strcmp(cfg->congestion_control, "cubic") == 0) {
        prog->prog_settings.es_cc_algo = 1;
    } else if (strcmp(cfg->congestion_control, "bbr") == 0) {
        prog->prog_settings.es_cc_algo = 2;
    }
}

static void set_failure(client_state_t *state, const char *message) {
    if (!state->failed) {
        state->failed = 1;
        snprintf(state->failure_reason, sizeof(state->failure_reason), "%s", message);
    }
}

static uint64_t scenario_request_bytes(const config_t *cfg) {
    if (is_mode(cfg, "bulk") && is_direction(cfg, "upload")) {
        return cfg->request_bytes > cfg->response_bytes ? cfg->request_bytes : cfg->response_bytes;
    }
    return cfg->request_bytes;
}

static uint64_t scenario_response_bytes(const config_t *cfg) {
    if (is_mode(cfg, "bulk") && is_direction(cfg, "upload")) {
        return 0;
    }
    return cfg->response_bytes;
}

static uint64_t inflight_limit(const config_t *cfg) {
    uint64_t connections = cfg->connections ? cfg->connections : 1;
    if (is_mode(cfg, "bulk")) {
        return (cfg->streams ? cfg->streams : 1) * connections;
    }
    if (is_mode(cfg, "crr")) {
        return connections;
    }
    return (cfg->requests_in_flight ? cfg->requests_in_flight : 1) * connections;
}

static uint64_t per_conn_stream_limit(const config_t *cfg) {
    if (is_mode(cfg, "bulk")) {
        return cfg->streams ? cfg->streams : 1;
    }
    if (is_mode(cfg, "crr")) {
        return 1;
    }
    return cfg->requests_in_flight ? cfg->requests_in_flight : 1;
}

static int should_start_request(const client_state_t *state) {
    if (state->stop_starting) {
        return 0;
    }
    if (state->bounded) {
        return state->started_requests + state->pending_streams < state->target_requests;
    }
    return now_us() < state->deadline_us;
}

static void close_all_connections(client_state_t *state) {
    struct lsquic_conn_ctx *conn_ctx = state->conns;
    while (conn_ctx) {
        struct lsquic_conn_ctx *next = conn_ctx->next;
        if (!conn_ctx->closing) {
            conn_ctx->closing = 1;
            lsquic_conn_close(conn_ctx->conn);
        }
        conn_ctx = next;
    }
}

static void maybe_finish_client(client_state_t *state);

static void try_open_streams_on_conn(client_state_t *state, struct lsquic_conn_ctx *conn_ctx) {
    const uint64_t global_limit = inflight_limit(&state->cfg);
    const uint64_t conn_limit = per_conn_stream_limit(&state->cfg);
    while (conn_ctx->ready && !conn_ctx->closing && should_start_request(state) &&
           state->active_streams + state->pending_streams < global_limit &&
           conn_ctx->active_streams < conn_limit &&
           lsquic_conn_n_avail_streams(conn_ctx->conn) > 0) {
        ++state->pending_streams;
        lsquic_conn_make_stream(conn_ctx->conn);
    }
}

static void try_open_streams(client_state_t *state) {
    struct lsquic_conn_ctx *conn_ctx = state->conns;
    while (conn_ctx) {
        try_open_streams_on_conn(state, conn_ctx);
        conn_ctx = conn_ctx->next;
    }
}

static int start_client_connection(client_state_t *state) {
    ++state->pending_conns;
    DEBUG_LOG("start connection pending=%" PRIu64 " active=%" PRIu64 "\n", state->pending_conns,
              state->active_conns);
    if (prog_connect(&state->prog, NULL, 0) != 0) {
        --state->pending_conns;
        set_failure(state, "could not connect");
        return -1;
    }
    return 0;
}

static void ensure_crr_connections(client_state_t *state) {
    while (should_start_request(state) &&
           state->active_conns + state->pending_conns < state->cfg.connections) {
        if (start_client_connection(state) != 0) {
            break;
        }
    }
}

static void maybe_finish_client(client_state_t *state) {
    if (state->failed) {
        state->stop_starting = 1;
        close_all_connections(state);
        if (state->active_conns == 0) {
            prog_stop(&state->prog);
        }
        return;
    }
    if (is_mode(&state->cfg, "crr")) {
        ensure_crr_connections(state);
    } else {
        try_open_streams(state);
    }
    if (!should_start_request(state) && state->active_streams + state->pending_streams == 0) {
        state->stop_starting = 1;
        close_all_connections(state);
        if (state->active_conns == 0) {
            prog_stop(&state->prog);
        }
    }
}

static lsquic_conn_ctx_t *client_on_new_conn(void *stream_if_ctx, lsquic_conn_t *conn) {
    client_state_t *state = stream_if_ctx;
    DEBUG_LOG("client new conn pending=%" PRIu64 " active=%" PRIu64 "\n", state->pending_conns,
              state->active_conns);
    struct lsquic_conn_ctx *conn_ctx = calloc(1, sizeof(*conn_ctx));
    if (!conn_ctx) {
        perror("calloc");
        exit(1);
    }
    if (state->pending_conns > 0) {
        --state->pending_conns;
    }
    conn_ctx->state = state;
    conn_ctx->conn = conn;
    conn_ctx->next = state->conns;
    state->conns = conn_ctx;
    ++state->active_conns;
    return conn_ctx;
}

static void client_on_conn_closed(lsquic_conn_t *conn) {
    struct lsquic_conn_ctx *conn_ctx = lsquic_conn_get_ctx(conn);
    DEBUG_LOG("client conn closed ctx=%p\n", (void *)conn_ctx);
    if (!conn_ctx) {
        return;
    }
    client_state_t *state = conn_ctx->state;
    struct lsquic_conn_ctx **link = &state->conns;
    while (*link && *link != conn_ctx) {
        link = &(*link)->next;
    }
    if (*link == conn_ctx) {
        *link = conn_ctx->next;
    }
    if (state->active_conns > 0) {
        --state->active_conns;
    }
    lsquic_conn_set_ctx(conn, NULL);
    free(conn_ctx);
    maybe_finish_client(state);
}

static lsquic_stream_ctx_t *client_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream) {
    client_state_t *state = stream_if_ctx;
    DEBUG_LOG(
        "client new stream stream=%p pending=%" PRIu64 " started=%" PRIu64 " target=%" PRIu64 "\n",
        (void *)stream, state->pending_streams, state->started_requests, state->target_requests);
    if (state->pending_streams > 0) {
        --state->pending_streams;
    }
    if (!stream || !should_start_request(state)) {
        if (stream) {
            lsquic_stream_close(stream);
        }
        maybe_finish_client(state);
        return NULL;
    }
    struct lsquic_conn_ctx *conn_ctx = lsquic_conn_get_ctx(lsquic_stream_conn(stream));
    struct lsquic_stream_ctx *stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (!stream_ctx) {
        perror("calloc");
        exit(1);
    }
    stream_ctx->state = state;
    stream_ctx->conn_ctx = conn_ctx;
    stream_ctx->request_bytes = scenario_request_bytes(&state->cfg);
    stream_ctx->response_bytes = scenario_response_bytes(&state->cfg);
    stream_ctx->counts_latency = !is_mode(&state->cfg, "bulk");
    stream_ctx->started_at = now_us();
    uint64_t be_response = encode_be64(stream_ctx->response_bytes);
    memcpy(stream_ctx->header, &be_response, sizeof(stream_ctx->header));
    ++state->started_requests;
    ++state->active_streams;
    if (conn_ctx) {
        ++conn_ctx->active_streams;
    }
    lsquic_stream_wantwrite(stream, 1);
    return stream_ctx;
}

static void client_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *stream_ctx = h;
    DEBUG_LOG("client write stream=%" PRIu64 " header=%zu request=%" PRIu64 "/%" PRIu64 "\n",
              (uint64_t)lsquic_stream_id(stream), stream_ctx->header_sent, stream_ctx->request_sent,
              stream_ctx->request_bytes);
    static const uint8_t zeros[WRITE_CHUNK_SIZE] = {0};
    while (stream_ctx->header_sent < sizeof(stream_ctx->header)) {
        ssize_t nw = lsquic_stream_write(stream, stream_ctx->header + stream_ctx->header_sent,
                                         sizeof(stream_ctx->header) - stream_ctx->header_sent);
        if (nw > 0) {
            stream_ctx->header_sent += (size_t)nw;
        } else if (nw < 0 && errno != EWOULDBLOCK) {
            set_failure(stream_ctx->state, strerror(errno));
            lsquic_stream_close(stream);
            return;
        } else {
            return;
        }
    }
    while (stream_ctx->request_sent < stream_ctx->request_bytes) {
        uint64_t left = stream_ctx->request_bytes - stream_ctx->request_sent;
        size_t chunk = left > sizeof(zeros) ? sizeof(zeros) : (size_t)left;
        ssize_t nw = lsquic_stream_write(stream, zeros, chunk);
        if (nw > 0) {
            stream_ctx->request_sent += (uint64_t)nw;
        } else if (nw < 0 && errno != EWOULDBLOCK) {
            set_failure(stream_ctx->state, strerror(errno));
            lsquic_stream_close(stream);
            return;
        } else {
            return;
        }
    }
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_shutdown(stream, 1);
    lsquic_stream_wantread(stream, 1);
}

static void client_on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *stream_ctx = h;
    DEBUG_LOG("client read stream=%" PRIu64 " response=%" PRIu64 "/%" PRIu64 "\n",
              (uint64_t)lsquic_stream_id(stream), stream_ctx->response_read,
              stream_ctx->response_bytes);
    uint8_t buf[8192];
    for (;;) {
        ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
        if (nr > 0) {
            stream_ctx->response_read += (uint64_t)nr;
        } else if (nr == 0) {
            stream_ctx->completed = 1;
            lsquic_stream_wantread(stream, 0);
            lsquic_stream_shutdown(stream, 0);
            return;
        } else if (errno == EWOULDBLOCK) {
            return;
        } else {
            set_failure(stream_ctx->state, strerror(errno));
            lsquic_stream_close(stream);
            return;
        }
    }
}

static void client_on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    (void)stream;
    struct lsquic_stream_ctx *stream_ctx = h;
    DEBUG_LOG("client close completed=%d response=%" PRIu64 "/%" PRIu64 "\n", stream_ctx->completed,
              stream_ctx->response_read, stream_ctx->response_bytes);
    client_state_t *state = stream_ctx->state;
    if (stream_ctx->completed) {
        state->counters.bytes_sent += stream_ctx->request_bytes;
        state->counters.bytes_received += stream_ctx->response_bytes;
        ++state->counters.requests_completed;
        if (stream_ctx->counts_latency) {
            latency_push(&state->counters.latencies, now_us() - stream_ctx->started_at);
        }
    }
    if (state->active_streams > 0) {
        --state->active_streams;
    }
    if (stream_ctx->conn_ctx && stream_ctx->conn_ctx->active_streams > 0) {
        --stream_ctx->conn_ctx->active_streams;
    }
    if (is_mode(&state->cfg, "crr") && stream_ctx->conn_ctx && !stream_ctx->conn_ctx->closing) {
        stream_ctx->conn_ctx->closing = 1;
        lsquic_conn_close(stream_ctx->conn_ctx->conn);
    }
    free(stream_ctx);
    maybe_finish_client(state);
}

static void client_on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status) {
    struct lsquic_conn_ctx *conn_ctx = lsquic_conn_get_ctx(conn);
    DEBUG_LOG("client handshake done status=%d ctx=%p\n", (int)status, (void *)conn_ctx);
    if (!conn_ctx) {
        return;
    }
    conn_ctx->ready = status == LSQ_HSK_OK || status == LSQ_HSK_RESUMED_OK;
    if (!conn_ctx->ready) {
        set_failure(conn_ctx->state, "lsquic handshake failed");
        lsquic_conn_close(conn);
        return;
    }
    try_open_streams_on_conn(conn_ctx->state, conn_ctx);
}

const struct lsquic_stream_if client_stream_if = {
    .on_new_conn = client_on_new_conn,
    .on_conn_closed = client_on_conn_closed,
    .on_new_stream = client_on_new_stream,
    .on_read = client_on_read,
    .on_write = client_on_write,
    .on_close = client_on_close,
    .on_hsk_done = client_on_hsk_done,
};

static lsquic_conn_ctx_t *server_on_new_conn(void *stream_if_ctx, lsquic_conn_t *conn) {
    (void)stream_if_ctx;
    (void)conn;
    return NULL;
}

static void server_on_conn_closed(lsquic_conn_t *conn) {
    (void)conn;
}

static lsquic_stream_ctx_t *server_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream) {
    (void)stream_if_ctx;
    DEBUG_LOG("server new stream=%" PRIu64 "\n", (uint64_t)lsquic_stream_id(stream));
    struct lsquic_stream_ctx *stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (!stream_ctx) {
        perror("calloc");
        exit(1);
    }
    lsquic_stream_wantread(stream, 1);
    return stream_ctx;
}

static size_t discard_readf(void *user_data, const unsigned char *buf, size_t count, int fin) {
    (void)user_data;
    (void)buf;
    (void)fin;
    return count;
}

static void server_on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *stream_ctx = h;
    DEBUG_LOG("server read stream=%" PRIu64 " header=%zu left=%" PRIu64 "\n",
              (uint64_t)lsquic_stream_id(stream), stream_ctx->server_header_read,
              stream_ctx->server.response_left);
    while (stream_ctx->server_header_read < sizeof(stream_ctx->server.header_buf)) {
        size_t need = sizeof(stream_ctx->server.header_buf) - stream_ctx->server_header_read;
        ssize_t nr = lsquic_stream_read(
            stream, stream_ctx->server.header_buf + stream_ctx->server_header_read, need);
        if (nr > 0) {
            stream_ctx->server_header_read += (size_t)nr;
            if (stream_ctx->server_header_read == sizeof(stream_ctx->server.header_buf)) {
                stream_ctx->server.response_left = decode_be64(stream_ctx->server.header_buf);
            }
        } else if (nr == 0) {
            lsquic_conn_abort(lsquic_stream_conn(stream));
            return;
        } else if (errno == EWOULDBLOCK) {
            return;
        } else {
            lsquic_stream_close(stream);
            return;
        }
    }

    ssize_t nr = lsquic_stream_readf(stream, discard_readf, NULL);
    if (nr == 0) {
        lsquic_stream_wantread(stream, 0);
        lsquic_stream_shutdown(stream, 0);
        lsquic_stream_wantwrite(stream, 1);
    } else if (nr < 0 && errno != EWOULDBLOCK) {
        lsquic_stream_close(stream);
    }
}

static void server_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *stream_ctx = h;
    DEBUG_LOG("server write stream=%" PRIu64 " left=%" PRIu64 "\n",
              (uint64_t)lsquic_stream_id(stream), stream_ctx->server.response_left);
    static const uint8_t zeros[WRITE_CHUNK_SIZE] = {0};
    while (stream_ctx->server.response_left > 0) {
        size_t chunk = stream_ctx->server.response_left > sizeof(zeros)
                           ? sizeof(zeros)
                           : (size_t)stream_ctx->server.response_left;
        ssize_t nw = lsquic_stream_write(stream, zeros, chunk);
        if (nw > 0) {
            stream_ctx->server.response_left -= (uint64_t)nw;
        } else if (nw < 0 && errno != EWOULDBLOCK) {
            lsquic_stream_close(stream);
            return;
        } else {
            return;
        }
    }
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_shutdown(stream, 1);
}

static void server_on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    DEBUG_LOG("server close stream=%" PRIu64 "\n", (uint64_t)lsquic_stream_id(stream));
    free(h);
}

const struct lsquic_stream_if server_stream_if = {
    .on_new_conn = server_on_new_conn,
    .on_conn_closed = server_on_conn_closed,
    .on_new_stream = server_on_new_stream,
    .on_read = server_on_read,
    .on_write = server_on_write,
    .on_close = server_on_close,
};

static void client_deadline_cb(evutil_socket_t fd, short what, void *arg) {
    (void)fd;
    (void)what;
    client_state_t *state = arg;
    state->stop_starting = 1;
    close_all_connections(state);
    if (state->active_conns == 0) {
        prog_stop(&state->prog);
    } else {
        prog_process_conns(&state->prog);
    }
}

static int run_server(const config_t *cfg) {
    struct prog prog;
    struct sport_head sports;
    TAILQ_INIT(&sports);
    if (prog_init(&prog, LSENG_SERVER, &sports, &server_stream_if, NULL) != 0) {
        return 1;
    }
    apply_lsquic_settings(&prog, cfg);
    char service[320];
    snprintf(service, sizeof(service), "%s:%u", cfg->host, cfg->port);
    char certspec[1400];
    snprintf(certspec, sizeof(certspec), "%s,%s,%s", cfg->server_name, cfg->certificate_chain,
             cfg->private_key);
    if (prog_set_opt(&prog, 's', service) != 0 || prog_set_opt(&prog, 'c', certspec) != 0 ||
        add_alpn(APPLICATION_PROTOCOL) != 0 || prog_prep(&prog) != 0) {
        prog_cleanup(&prog);
        return 1;
    }
    int status = prog_run(&prog);
    prog_cleanup(&prog);
    return status == 0 ? 0 : 1;
}

static run_summary_t make_summary(const config_t *cfg, const counters_t *counters,
                                  int64_t elapsed_ms, const char *status,
                                  const char *failure_reason) {
    run_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    summary.status = status;
    summary.failure_reason = failure_reason;
    summary.cfg = cfg;
    summary.elapsed_ms = elapsed_ms;
    summary.counters = *counters;
    summary.latency = summarize_latency(&counters->latencies);
    double seconds = elapsed_ms > 0 ? (double)elapsed_ms / 1000.0 : 0.001;
    double total_bytes = (double)counters->bytes_sent + (double)counters->bytes_received;
    summary.throughput_mib_per_s = total_bytes / (1024.0 * 1024.0) / seconds;
    summary.throughput_gbit_per_s = (total_bytes * 8.0) / 1000000000.0 / seconds;
    summary.requests_per_s = (double)counters->requests_completed / seconds;
    return summary;
}

static void json_string(FILE *out, const char *value) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        switch (*p) {
        case '"':
            fputs("\\\"", out);
            break;
        case '\\':
            fputs("\\\\", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (*p < 0x20) {
                fprintf(out, "\\u%04x", *p);
            } else {
                fputc(*p, out);
            }
            break;
        }
    }
    fputc('"', out);
}

static void write_summary_json(FILE *out, const run_summary_t *summary) {
    const config_t *cfg = summary->cfg;
    fprintf(out, "{\n");
    fprintf(out, "  \"schema_version\": 1,\n");
    fprintf(out, "  \"status\": ");
    json_string(out, summary->status);
    fprintf(out, ",\n");
    fprintf(out, "  \"mode\": ");
    json_string(out, cfg->mode);
    fprintf(out, ",\n");
    fprintf(out, "  \"direction\": ");
    json_string(out, cfg->direction);
    fprintf(out, ",\n");
    fprintf(out, "  \"backend\": ");
    json_string(out, cfg->io_backend);
    fprintf(out, ",\n");
    fprintf(out, "  \"congestion_control\": ");
    json_string(out, cfg->congestion_control);
    fprintf(out, ",\n");
    fprintf(out, "  \"remote_host\": ");
    json_string(out, cfg->host);
    fprintf(out, ",\n");
    fprintf(out, "  \"remote_port\": %u,\n", cfg->port);
    fprintf(out, "  \"alpn\": ");
    json_string(out, APPLICATION_PROTOCOL);
    fprintf(out, ",\n");
    fprintf(out, "  \"elapsed_ms\": %" PRId64 ",\n", summary->elapsed_ms);
    fprintf(out, "  \"warmup_ms\": %" PRIu64 ",\n", duration_millis(cfg->warmup_us));
    fprintf(out, "  \"bytes_sent\": %" PRIu64 ",\n", summary->counters.bytes_sent);
    fprintf(out, "  \"bytes_received\": %" PRIu64 ",\n", summary->counters.bytes_received);
    fprintf(out, "  \"server_counters\": {\n");
    fprintf(out, "    \"bytes_sent\": %" PRIu64 ",\n", summary->counters.bytes_received);
    fprintf(out, "    \"bytes_received\": %" PRIu64 ",\n", summary->counters.bytes_sent);
    fprintf(out, "    \"requests_completed\": %" PRIu64 "\n", summary->counters.requests_completed);
    fprintf(out, "  },\n");
    fprintf(out, "  \"requests_completed\": %" PRIu64 ",\n", summary->counters.requests_completed);
    fprintf(out, "  \"streams\": %" PRIu64 ",\n", cfg->streams);
    fprintf(out, "  \"connections\": %" PRIu64 ",\n", cfg->connections);
    fprintf(out, "  \"requests_in_flight\": %" PRIu64 ",\n", cfg->requests_in_flight);
    fprintf(out, "  \"request_bytes\": %" PRIu64 ",\n", cfg->request_bytes);
    fprintf(out, "  \"response_bytes\": %" PRIu64 ",\n", cfg->response_bytes);
    fprintf(out, "  \"throughput_mib_per_s\": %.6f,\n", summary->throughput_mib_per_s);
    fprintf(out, "  \"throughput_gbit_per_s\": %.6f,\n", summary->throughput_gbit_per_s);
    fprintf(out, "  \"requests_per_s\": %.6f,\n", summary->requests_per_s);
    fprintf(out, "  \"latency\": {\n");
    fprintf(out, "    \"min_us\": %" PRIu64 ",\n", summary->latency.min_us);
    fprintf(out, "    \"avg_us\": %" PRIu64 ",\n", summary->latency.avg_us);
    fprintf(out, "    \"p50_us\": %" PRIu64 ",\n", summary->latency.p50_us);
    fprintf(out, "    \"p90_us\": %" PRIu64 ",\n", summary->latency.p90_us);
    fprintf(out, "    \"p99_us\": %" PRIu64 ",\n", summary->latency.p99_us);
    fprintf(out, "    \"max_us\": %" PRIu64 "\n", summary->latency.max_us);
    fprintf(out, "  }");
    if (summary->counters.skipped_setup_errors != 0) {
        fprintf(out, ",\n  \"skipped_setup_errors\": %" PRIu64,
                summary->counters.skipped_setup_errors);
    }
    if (summary->failure_reason && summary->failure_reason[0]) {
        fprintf(out, ",\n  \"failure_reason\": ");
        json_string(out, summary->failure_reason);
    }
    fprintf(out, "\n}\n");
}

static int emit_summary(const run_summary_t *summary) {
    printf("status=%s mode=%s cc=%s direction=%s throughput_mib/s=%.3f "
           "throughput_gbit/s=%.3f requests/s=%.3f\n",
           summary->status, summary->cfg->mode, summary->cfg->congestion_control,
           summary->cfg->direction, summary->throughput_mib_per_s, summary->throughput_gbit_per_s,
           summary->requests_per_s);
    if (summary->cfg->json_out[0]) {
        FILE *out = open_json_output(summary->cfg->json_out);
        if (!out) {
            perror("fopen");
            return -1;
        }
        write_summary_json(out, summary);
        fclose(out);
    }
    return 0;
}

static run_summary_t run_client(const config_t *cfg) {
    client_state_t state;
    memset(&state, 0, sizeof(state));
    state.cfg = *cfg;
    TAILQ_INIT(&state.sports);

    uint64_t request_bytes = scenario_request_bytes(cfg);
    uint64_t response_bytes = scenario_response_bytes(cfg);
    if (cfg->requests.set) {
        state.target_requests = cfg->requests.value;
        state.bounded = 1;
    } else if (cfg->total_bytes.set) {
        uint64_t unit = is_direction(cfg, "upload") ? request_bytes : response_bytes;
        state.target_requests = ceil_div(cfg->total_bytes.value, unit ? unit : 1);
        state.bounded = 1;
    } else {
        state.target_requests = 0;
        state.bounded = 0;
        if (cfg->warmup_us > 0) {
            usleep((useconds_t)cfg->warmup_us);
        }
    }

    if (prog_init(&state.prog, 0, &state.sports, &client_stream_if, &state) != 0) {
        set_failure(&state, "could not initialize lsquic");
        counters_t counters;
        memset(&counters, 0, sizeof(counters));
        return make_summary(cfg, &counters, 0, "failed", state.failure_reason);
    }
    state.prog.prog_api.ea_alpn = APPLICATION_PROTOCOL;
    state.prog.prog_settings.es_delay_onclose = 1;
    apply_lsquic_settings(&state.prog, cfg);

    char service[320];
    snprintf(service, sizeof(service), "%s:%u", cfg->host, cfg->port);
    if (prog_set_opt(&state.prog, 'H', cfg->server_name) != 0 ||
        prog_set_opt(&state.prog, 's', service) != 0 || prog_prep(&state.prog) != 0) {
        set_failure(&state, "could not prepare lsquic client");
        prog_cleanup(&state.prog);
        return make_summary(cfg, &state.counters, 0, "failed", state.failure_reason);
    }

    state.measure_start_us = now_us();
    state.deadline_us = state.measure_start_us + cfg->duration_us;
    if (!state.bounded) {
        state.deadline_timer = evtimer_new(prog_eb(&state.prog), client_deadline_cb, &state);
        if (state.deadline_timer) {
            struct timeval timeout;
            timeout.tv_sec = (time_t)(cfg->duration_us / 1000000ULL);
            timeout.tv_usec = (suseconds_t)(cfg->duration_us % 1000000ULL);
            evtimer_add(state.deadline_timer, &timeout);
        }
    }

    uint64_t initial_connections = is_mode(cfg, "crr") ? cfg->connections : cfg->connections;
    for (uint64_t i = 0; i < initial_connections && should_start_request(&state); ++i) {
        if (start_client_connection(&state) != 0) {
            break;
        }
    }
    if (!state.failed) {
        prog_run(&state.prog);
    }
    uint64_t elapsed_us = now_us() - state.measure_start_us;
    if (state.deadline_timer) {
        event_del(state.deadline_timer);
        event_free(state.deadline_timer);
    }
    prog_cleanup(&state.prog);
    const char *status = state.failed ? "failed" : "ok";
    run_summary_t summary = make_summary(cfg, &state.counters, (int64_t)duration_millis(elapsed_us),
                                         status, state.failed ? state.failure_reason : NULL);
    free(state.counters.latencies.values);
    return summary;
}

int main(int argc, char **argv) {
    config_t cfg = parse_args(argc, argv);
    if (strcmp(cfg.role, "server") == 0) {
        return run_server(&cfg);
    }
    run_summary_t summary = run_client(&cfg);
    if (emit_summary(&summary) != 0) {
        return 1;
    }
    return strcmp(summary.status, "ok") == 0 ? 0 : 1;
}
