#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
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

#define APPLICATION_PROTOCOL "coquic-perf/1"
#define PERF_PROTOCOL_VERSION 3U
#define CONTROL_STREAM_ID 0ULL
#define MESSAGE_SESSION_START 1U
#define MESSAGE_SESSION_READY 2U
#define MESSAGE_SESSION_ERROR 3U
#define MODE_CODE_BULK 0U
#define MODE_CODE_RR 1U
#define MODE_CODE_CRR 2U
#define MODE_CODE_PERSISTENT_RR 3U
#define DIRECTION_CODE_UPLOAD 0U
#define DIRECTION_CODE_DOWNLOAD 1U
#define DEFAULT_MAX_RUN_REQUESTS 4096ULL
#define TRANSFER_CONNECTION_WINDOW (32U * 1024U * 1024U)
#define TRANSFER_STREAM_WINDOW (16U * 1024U * 1024U)
#define TRANSFER_MAX_STREAMS 10000000U
#define DRAIN_TIMEOUT_US 2000000ULL
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
struct lsquic_stream_ctx;

typedef struct {
    int started;
    uint8_t mode;
    uint8_t direction;
    uint64_t request_bytes;
    uint64_t response_bytes;
    optional_u64_t total_bytes;
    optional_u64_t requests;
    uint64_t warmup_us;
    uint64_t duration_us;
    uint64_t streams;
    uint64_t connections;
    uint64_t requests_in_flight;
} perf_session_start_t;

struct lsquic_conn_ctx {
    client_state_t *state;
    lsquic_conn_t *conn;
    struct service_port *sport;
    struct lsquic_stream_ctx *persistent_stream;
    uint64_t active_streams;
    uint64_t started_requests;
    uint64_t request_limit;
    int ready;
    int control_opened;
    int persistent_stream_pending;
    int session_ready;
    int closing;
    int closed;
    uint64_t stream_refs;
    perf_session_start_t session_start;
    struct lsquic_conn_ctx *next;
};

struct lsquic_stream_ctx {
    client_state_t *state;
    struct lsquic_conn_ctx *conn_ctx;
    lsquic_stream_t *stream;
    int is_control;
    int persistent_rr;
    int request_fin;
    uint8_t *control_out;
    uint8_t *control_in;
    size_t control_len;
    size_t control_sent;
    size_t control_in_len;
    size_t control_in_cap;
    int control_fin;
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t request_sent;
    uint64_t response_read;
    uint64_t response_pending;
    uint64_t started_at;
    uint64_t *latency_starts;
    size_t latency_head;
    size_t latency_len;
    size_t latency_cap;
    int counts_latency;
    int completed;
    struct {
        uint64_t request_bytes;
        uint64_t response_bytes;
        uint64_t request_read;
        uint64_t response_left;
        int request_fin;
        int ready_to_send;
        int shape_set;
    } server;
};

struct client_state {
    config_t cfg;
    struct prog prog;
    struct sport_head sports;
    struct event *deadline_timer;
    struct event *drain_timer;
    struct service_port **client_sports;
    int *client_sport_busy;
    uint64_t client_sport_count;
    struct lsquic_conn_ctx *conns;
    counters_t counters;
    uint64_t target_requests;
    uint64_t started_requests;
    uint64_t active_streams;
    uint64_t pending_streams;
    uint64_t pending_control_streams;
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

static uint64_t scenario_request_bytes(const config_t *cfg);
static uint64_t scenario_response_bytes(const config_t *cfg);

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

static int is_rr_like_mode(const config_t *cfg) {
    return is_mode(cfg, "rr") || is_mode(cfg, "persistent-rr");
}

static int is_direction(const config_t *cfg, const char *direction) {
    return strcmp(cfg->direction, direction) == 0;
}

static void validate_config(const config_t *cfg) {
    if (!is_mode(cfg, "bulk") && !is_mode(cfg, "rr") && !is_mode(cfg, "crr") &&
        !is_mode(cfg, "persistent-rr")) {
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
    if (is_mode(cfg, "persistent-rr") && (cfg->request_bytes == 0 || cfg->response_bytes == 0)) {
        fprintf(stderr, "persistent-rr request and response bytes must be greater than zero\n");
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

static void encode_be32(uint8_t out[4], uint32_t value) {
    out[0] = (uint8_t)((value >> 24) & 0xffU);
    out[1] = (uint8_t)((value >> 16) & 0xffU);
    out[2] = (uint8_t)((value >> 8) & 0xffU);
    out[3] = (uint8_t)(value & 0xffU);
}

static uint32_t decode_be32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static void encode_bytes_be64(uint8_t out[8], uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)(value & 0xffU);
        value >>= 8;
    }
}

static uint64_t decode_be64(const uint8_t bytes[8]) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

static uint8_t mode_code(const char *mode) {
    if (strcmp(mode, "rr") == 0) {
        return MODE_CODE_RR;
    }
    if (strcmp(mode, "crr") == 0) {
        return MODE_CODE_CRR;
    }
    if (strcmp(mode, "persistent-rr") == 0) {
        return MODE_CODE_PERSISTENT_RR;
    }
    return MODE_CODE_BULK;
}

static uint8_t direction_code(const char *direction) {
    return strcmp(direction, "upload") == 0 ? DIRECTION_CODE_UPLOAD : DIRECTION_CODE_DOWNLOAD;
}

static uint8_t *frame_control_message(uint8_t type, const uint8_t *payload, uint32_t payload_len,
                                      size_t *out_len) {
    uint8_t *out = malloc((size_t)payload_len + 5);
    if (out == NULL) {
        return NULL;
    }
    out[0] = type;
    encode_be32(out + 1, payload_len);
    if (payload_len != 0) {
        memcpy(out + 5, payload, payload_len);
    }
    *out_len = (size_t)payload_len + 5;
    return out;
}

static uint8_t *encode_session_start_message(const config_t *cfg, size_t *out_len) {
    uint8_t payload[79];
    encode_be32(payload, PERF_PROTOCOL_VERSION);
    payload[4] = mode_code(cfg->mode);
    payload[5] = direction_code(cfg->direction);
    encode_bytes_be64(payload + 6, scenario_request_bytes(cfg));
    encode_bytes_be64(payload + 14, scenario_response_bytes(cfg));
    payload[22] = (cfg->total_bytes.set ? 0x01 : 0) | (cfg->requests.set ? 0x02 : 0);
    encode_bytes_be64(payload + 23, cfg->total_bytes.value);
    encode_bytes_be64(payload + 31, cfg->requests.value);
    encode_bytes_be64(payload + 39, cfg->warmup_us);
    encode_bytes_be64(payload + 47, cfg->duration_us);
    encode_bytes_be64(payload + 55, cfg->streams);
    encode_bytes_be64(payload + 63, cfg->connections);
    encode_bytes_be64(payload + 71, cfg->requests_in_flight);
    return frame_control_message(MESSAGE_SESSION_START, payload, sizeof(payload), out_len);
}

static uint8_t *encode_session_ready_message(size_t *out_len) {
    uint8_t payload[4];
    encode_be32(payload, PERF_PROTOCOL_VERSION);
    return frame_control_message(MESSAGE_SESSION_READY, payload, sizeof(payload), out_len);
}

static uint8_t *encode_session_error_message(const char *reason, size_t *out_len) {
    size_t reason_len = strlen(reason);
    uint8_t *payload = malloc(reason_len + 4);
    if (payload == NULL) {
        return NULL;
    }
    encode_be32(payload, (uint32_t)reason_len);
    memcpy(payload + 4, reason, reason_len);
    uint8_t *out =
        frame_control_message(MESSAGE_SESSION_ERROR, payload, (uint32_t)(reason_len + 4), out_len);
    free(payload);
    return out;
}

static int decode_session_start_payload(const uint8_t *payload, size_t len,
                                        perf_session_start_t *start) {
    if (len != 79 || decode_be32(payload) != PERF_PROTOCOL_VERSION) {
        return -1;
    }
    memset(start, 0, sizeof(*start));
    start->started = 1;
    start->mode = payload[4];
    start->direction = payload[5];
    start->request_bytes = decode_be64(payload + 6);
    start->response_bytes = decode_be64(payload + 14);
    uint8_t flags = payload[22];
    start->total_bytes.value = decode_be64(payload + 23);
    start->total_bytes.set = (flags & 0x01) != 0;
    start->requests.value = decode_be64(payload + 31);
    start->requests.set = (flags & 0x02) != 0;
    start->warmup_us = decode_be64(payload + 39);
    start->duration_us = decode_be64(payload + 47);
    start->streams = decode_be64(payload + 55);
    start->connections = decode_be64(payload + 63);
    start->requests_in_flight = decode_be64(payload + 71);
    if ((start->mode != MODE_CODE_BULK && start->mode != MODE_CODE_RR &&
         start->mode != MODE_CODE_CRR && start->mode != MODE_CODE_PERSISTENT_RR) ||
        (start->direction != DIRECTION_CODE_UPLOAD &&
         start->direction != DIRECTION_CODE_DOWNLOAD) ||
        start->streams == 0 || start->connections == 0 || start->requests_in_flight == 0) {
        return -1;
    }
    if (start->mode == MODE_CODE_PERSISTENT_RR &&
        (start->request_bytes == 0 || start->response_bytes == 0)) {
        return -1;
    }
    return 0;
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

static uint64_t inflight_limit(const config_t *cfg);
static void apply_lsquic_settings(struct prog *prog, const config_t *cfg) {
    prog->prog_settings.es_init_max_data = TRANSFER_CONNECTION_WINDOW;
    prog->prog_settings.es_init_max_stream_data_bidi_local = TRANSFER_STREAM_WINDOW;
    prog->prog_settings.es_init_max_stream_data_bidi_remote = TRANSFER_STREAM_WINDOW;
    uint64_t stream_limit = inflight_limit(cfg);
    if (stream_limit < 100) {
        stream_limit = 100;
    }
    if (stream_limit > UINT_MAX) {
        stream_limit = UINT_MAX;
    }
    prog->prog_settings.es_init_max_streams_bidi =
        stream_limit > TRANSFER_MAX_STREAMS ? (unsigned)stream_limit : TRANSFER_MAX_STREAMS;
    prog->prog_settings.es_max_streams_in =
        stream_limit > TRANSFER_MAX_STREAMS ? (unsigned)stream_limit : TRANSFER_MAX_STREAMS;
    if (cfg->disable_pmtud) {
        prog->prog_settings.es_dplpmtud = 0;
    }
    prog->prog_settings.es_rw_once = 1;
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

static int is_client_shutdown_io_error(const struct lsquic_stream_ctx *stream_ctx) {
    return errno == EBADF && stream_ctx->state && stream_ctx->state->stop_starting &&
           (!stream_ctx->conn_ctx || stream_ctx->conn_ctx->closing);
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

static uint64_t rr_connection_target(const config_t *cfg) {
    if (is_rr_like_mode(cfg) && cfg->requests.set) {
        return cfg->connections < cfg->requests.value ? cfg->connections : cfg->requests.value;
    }
    return cfg->connections;
}

static uint64_t rr_request_limit_for_connection(const config_t *cfg, uint64_t connection_index) {
    uint64_t connections = rr_connection_target(cfg);
    if (connections == 0) {
        return 0;
    }
    uint64_t base = cfg->requests.value / connections;
    uint64_t remainder = cfg->requests.value % connections;
    return base + (connection_index < remainder ? 1 : 0);
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

static int persistent_latency_push(struct lsquic_stream_ctx *stream_ctx, uint64_t value) {
    if (stream_ctx->latency_len == stream_ctx->latency_cap) {
        size_t new_cap = stream_ctx->latency_cap ? stream_ctx->latency_cap * 2 : 16;
        uint64_t *new_values = malloc(new_cap * sizeof(new_values[0]));
        if (!new_values) {
            return -1;
        }
        for (size_t i = 0; i < stream_ctx->latency_len; ++i) {
            new_values[i] =
                stream_ctx
                    ->latency_starts[(stream_ctx->latency_head + i) % stream_ctx->latency_cap];
        }
        free(stream_ctx->latency_starts);
        stream_ctx->latency_starts = new_values;
        stream_ctx->latency_head = 0;
        stream_ctx->latency_cap = new_cap;
    }
    size_t index = (stream_ctx->latency_head + stream_ctx->latency_len) % stream_ctx->latency_cap;
    stream_ctx->latency_starts[index] = value;
    ++stream_ctx->latency_len;
    return 0;
}

static int persistent_latency_pop(struct lsquic_stream_ctx *stream_ctx, uint64_t *value) {
    if (stream_ctx->latency_len == 0) {
        return 0;
    }
    *value = stream_ctx->latency_starts[stream_ctx->latency_head];
    stream_ctx->latency_head = (stream_ctx->latency_head + 1) % stream_ctx->latency_cap;
    --stream_ctx->latency_len;
    if (stream_ctx->latency_len == 0) {
        stream_ctx->latency_head = 0;
    }
    return 1;
}

static int can_start_persistent_request(client_state_t *state, struct lsquic_conn_ctx *conn_ctx) {
    if (!conn_ctx || !conn_ctx->ready || !conn_ctx->session_ready || conn_ctx->closing ||
        !should_start_request(state)) {
        return 0;
    }
    if (state->active_streams >= inflight_limit(&state->cfg) ||
        conn_ctx->active_streams >= per_conn_stream_limit(&state->cfg)) {
        return 0;
    }
    if (state->cfg.requests.set && conn_ctx->started_requests >= conn_ctx->request_limit) {
        return 0;
    }
    return 1;
}

static int start_persistent_request(client_state_t *state, struct lsquic_conn_ctx *conn_ctx,
                                    struct lsquic_stream_ctx *stream_ctx) {
    if (!can_start_persistent_request(state, conn_ctx)) {
        return 0;
    }
    uint64_t request_bytes = scenario_request_bytes(&state->cfg);
    uint64_t response_bytes = scenario_response_bytes(&state->cfg);
    if (request_bytes == 0 || response_bytes == 0) {
        set_failure(state, "persistent-rr request and response bytes must be nonzero");
        return -1;
    }
    if (UINT64_MAX - stream_ctx->request_bytes < request_bytes) {
        set_failure(state, "persistent-rr request byte counter overflow");
        return -1;
    }
    if (persistent_latency_push(stream_ctx, now_us()) != 0) {
        set_failure(state, "out of memory queuing persistent-rr request");
        return -1;
    }
    stream_ctx->response_bytes = response_bytes;
    stream_ctx->request_bytes += request_bytes;
    stream_ctx->counts_latency = 1;
    ++state->started_requests;
    ++state->active_streams;
    ++conn_ctx->started_requests;
    ++conn_ctx->active_streams;
    lsquic_stream_wantwrite(stream_ctx->stream, 1);
    return 1;
}

static void close_all_connections(client_state_t *state) {
    struct lsquic_conn_ctx *conn_ctx = state->conns;
    while (conn_ctx) {
        struct lsquic_conn_ctx *next = conn_ctx->next;
        if (!conn_ctx->closing) {
            conn_ctx->closing = 1;
            if (conn_ctx->persistent_stream && !conn_ctx->persistent_stream->request_fin) {
                conn_ctx->persistent_stream->request_fin = 1;
                lsquic_stream_wantwrite(conn_ctx->persistent_stream->stream, 1);
            }
            lsquic_conn_close(conn_ctx->conn);
        }
        conn_ctx = next;
    }
}

static void maybe_finish_client(client_state_t *state);

static void maybe_free_client_conn_ctx(struct lsquic_conn_ctx *conn_ctx) {
    if (conn_ctx && conn_ctx->closed && conn_ctx->stream_refs == 0) {
        free(conn_ctx);
    }
}

static void retain_client_conn_ctx(struct lsquic_conn_ctx *conn_ctx) {
    if (conn_ctx) {
        ++conn_ctx->stream_refs;
    }
}

static void release_client_conn_ctx(struct lsquic_stream_ctx *stream_ctx) {
    struct lsquic_conn_ctx *conn_ctx = stream_ctx->conn_ctx;
    if (!conn_ctx) {
        return;
    }
    stream_ctx->conn_ctx = NULL;
    if (conn_ctx->stream_refs > 0) {
        --conn_ctx->stream_refs;
    }
    maybe_free_client_conn_ctx(conn_ctx);
}

static void free_client_stream_ctx(struct lsquic_stream_ctx *stream_ctx) {
    if (!stream_ctx) {
        return;
    }
    if (stream_ctx->persistent_rr && stream_ctx->conn_ctx &&
        stream_ctx->conn_ctx->persistent_stream == stream_ctx) {
        stream_ctx->conn_ctx->persistent_stream = NULL;
    }
    free(stream_ctx->latency_starts);
    free(stream_ctx->control_out);
    free(stream_ctx->control_in);
    release_client_conn_ctx(stream_ctx);
    free(stream_ctx);
}

static void try_open_streams_on_conn(client_state_t *state, struct lsquic_conn_ctx *conn_ctx) {
    const uint64_t global_limit = inflight_limit(&state->cfg);
    const uint64_t conn_limit = per_conn_stream_limit(&state->cfg);
    if (!conn_ctx) {
        return;
    }
    if (is_mode(&state->cfg, "persistent-rr")) {
        if (!conn_ctx->ready || !conn_ctx->session_ready || conn_ctx->closing) {
            return;
        }
        if (!conn_ctx->persistent_stream && !conn_ctx->persistent_stream_pending &&
            should_start_request(state) &&
            state->active_streams + state->pending_streams < global_limit &&
            conn_ctx->active_streams < conn_limit &&
            (!state->cfg.requests.set || conn_ctx->started_requests < conn_ctx->request_limit) &&
            lsquic_conn_n_avail_streams(conn_ctx->conn) > 0) {
            ++state->pending_streams;
            conn_ctx->persistent_stream_pending = 1;
            lsquic_conn_make_stream(conn_ctx->conn);
        }
        while (conn_ctx->persistent_stream) {
            int started = start_persistent_request(state, conn_ctx, conn_ctx->persistent_stream);
            if (started <= 0) {
                break;
            }
        }
        return;
    }
    while (conn_ctx->ready && conn_ctx->session_ready && !conn_ctx->closing &&
           should_start_request(state) &&
           state->active_streams + state->pending_streams < global_limit &&
           conn_ctx->active_streams < conn_limit &&
           (!is_rr_like_mode(&state->cfg) || !state->cfg.requests.set ||
            conn_ctx->started_requests < conn_ctx->request_limit) &&
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

static int open_client_control_stream(client_state_t *state, struct lsquic_conn_ctx *conn_ctx) {
    if (conn_ctx->control_opened || conn_ctx->closing || !conn_ctx->ready) {
        return 0;
    }
    if (lsquic_conn_n_avail_streams(conn_ctx->conn) <= 0) {
        return 0;
    }
    ++state->pending_control_streams;
    conn_ctx->control_opened = 1;
    lsquic_conn_make_stream(conn_ctx->conn);
    return 0;
}

static int add_client_sport(client_state_t *state, uint64_t index, const char *service) {
    struct service_port *sport;
    if (index == 0) {
        sport = TAILQ_FIRST(&state->sports);
    } else {
        sport = sport_new(service, &state->prog);
        if (!sport) {
            return -1;
        }
        sport->sp_flags = state->prog.prog_dummy_sport.sp_flags;
        sport->sp_sndbuf = state->prog.prog_dummy_sport.sp_sndbuf;
        sport->sp_rcvbuf = state->prog.prog_dummy_sport.sp_rcvbuf;
        TAILQ_INSERT_TAIL(&state->sports, sport, next_sport);
        if (sport_init_client(sport, state->prog.prog_engine, prog_eb(&state->prog)) != 0) {
            TAILQ_REMOVE(&state->sports, sport, next_sport);
            sport_destroy(sport);
            return -1;
        }
    }
    if (!sport) {
        return -1;
    }
    state->client_sports[index] = sport;
    return 0;
}

static int init_client_sports(client_state_t *state, const char *service) {
    state->client_sport_count = state->cfg.connections ? state->cfg.connections : 1;
    state->client_sports = calloc((size_t)state->client_sport_count, sizeof(*state->client_sports));
    state->client_sport_busy =
        calloc((size_t)state->client_sport_count, sizeof(*state->client_sport_busy));
    if (!state->client_sports || !state->client_sport_busy) {
        return -1;
    }
    for (uint64_t i = 0; i < state->client_sport_count; ++i) {
        if (add_client_sport(state, i, service) != 0) {
            return -1;
        }
    }
    return 0;
}

static void cleanup_client_sports(client_state_t *state) {
    free(state->client_sports);
    free(state->client_sport_busy);
    state->client_sports = NULL;
    state->client_sport_busy = NULL;
    state->client_sport_count = 0;
}

static uint64_t client_sport_index(const client_state_t *state, const struct service_port *sport) {
    for (uint64_t i = 0; i < state->client_sport_count; ++i) {
        if (state->client_sports[i] == sport) {
            return i;
        }
    }
    return state->client_sport_count;
}

static struct service_port *next_available_client_sport(client_state_t *state) {
    for (uint64_t i = 0; i < state->client_sport_count; ++i) {
        if (!state->client_sport_busy[i]) {
            state->client_sport_busy[i] = 1;
            return state->client_sports[i];
        }
    }
    return NULL;
}

static void release_client_sport(client_state_t *state, const struct service_port *sport) {
    uint64_t index = client_sport_index(state, sport);
    if (index < state->client_sport_count) {
        state->client_sport_busy[index] = 0;
    }
}

static int start_client_connection(client_state_t *state) {
    struct service_port *sport = next_available_client_sport(state);
    if (!sport) {
        set_failure(state, "no available lsquic client port");
        return -1;
    }
    DEBUG_LOG("start connection pending=%" PRIu64 " active=%" PRIu64 "\n", state->pending_conns,
              state->active_conns);
    ++state->pending_conns;
    if (lsquic_engine_connect(state->prog.prog_engine, N_LSQVER,
                              (struct sockaddr *)&sport->sp_local_addr,
                              (struct sockaddr *)&sport->sas, sport, NULL,
                              state->prog.prog_hostname ? state->prog.prog_hostname : NULL,
                              state->prog.prog_max_packet_size, NULL, 0, sport->sp_token_buf,
                              sport->sp_token_sz) == NULL) {
        if (state->pending_conns > 0) {
            --state->pending_conns;
        }
        release_client_sport(state, sport);
        set_failure(state, "could not connect");
        return -1;
    }
    prog_process_conns(&state->prog);
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
    conn_ctx->sport = lsquic_conn_get_peer_ctx(conn, NULL);
    conn_ctx->request_limit = rr_request_limit_for_connection(&state->cfg, state->active_conns);
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
    release_client_sport(state, conn_ctx->sport);
    conn_ctx->closed = 1;
    conn_ctx->closing = 1;
    lsquic_conn_set_ctx(conn, NULL);
    maybe_free_client_conn_ctx(conn_ctx);
    maybe_finish_client(state);
}

static lsquic_stream_ctx_t *client_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream) {
    client_state_t *state = stream_if_ctx;
    DEBUG_LOG(
        "client new stream stream=%p pending=%" PRIu64 " started=%" PRIu64 " target=%" PRIu64 "\n",
        (void *)stream, state->pending_streams, state->started_requests, state->target_requests);
    struct lsquic_conn_ctx *conn_ctx =
        stream ? lsquic_conn_get_ctx(lsquic_stream_conn(stream)) : NULL;
    if ((uint64_t)lsquic_stream_id(stream) == CONTROL_STREAM_ID &&
        state->pending_control_streams > 0) {
        --state->pending_control_streams;
    } else if (state->pending_streams > 0) {
        --state->pending_streams;
        if (is_mode(&state->cfg, "persistent-rr") && conn_ctx) {
            conn_ctx->persistent_stream_pending = 0;
        }
    }
    if (!stream || !should_start_request(state)) {
        if (stream) {
            lsquic_stream_close(stream);
        }
        maybe_finish_client(state);
        return NULL;
    }
    struct lsquic_stream_ctx *stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (!stream_ctx) {
        perror("calloc");
        exit(1);
    }
    stream_ctx->state = state;
    stream_ctx->conn_ctx = conn_ctx;
    retain_client_conn_ctx(conn_ctx);
    stream_ctx->stream = stream;
    if ((uint64_t)lsquic_stream_id(stream) == CONTROL_STREAM_ID) {
        stream_ctx->is_control = 1;
        stream_ctx->control_fin = 1;
        config_t connection_cfg = state->cfg;
        if (is_rr_like_mode(&state->cfg) && state->cfg.requests.set && conn_ctx) {
            connection_cfg.requests.value = conn_ctx->request_limit;
            connection_cfg.requests.set = 1;
        }
        stream_ctx->control_out =
            encode_session_start_message(&connection_cfg, &stream_ctx->control_len);
        if (stream_ctx->control_out == NULL) {
            set_failure(state, "could not encode lsquic session_start");
            lsquic_stream_close(stream);
            free_client_stream_ctx(stream_ctx);
            maybe_finish_client(state);
            return NULL;
        }
        lsquic_stream_wantwrite(stream, 1);
        return stream_ctx;
    }
    if (conn_ctx && !conn_ctx->session_ready) {
        lsquic_stream_close(stream);
        free_client_stream_ctx(stream_ctx);
        maybe_finish_client(state);
        return NULL;
    }
    if (is_mode(&state->cfg, "persistent-rr")) {
        stream_ctx->persistent_rr = 1;
        if (conn_ctx) {
            conn_ctx->persistent_stream = stream_ctx;
        }
        int started = start_persistent_request(state, conn_ctx, stream_ctx);
        if (started <= 0) {
            if (started == 0) {
                set_failure(state, "could not start persistent-rr request");
            }
            lsquic_stream_close(stream);
            free_client_stream_ctx(stream_ctx);
            maybe_finish_client(state);
            return NULL;
        }
        try_open_streams_on_conn(state, conn_ctx);
        lsquic_stream_wantread(stream, 1);
        return stream_ctx;
    }
    stream_ctx->request_bytes = scenario_request_bytes(&state->cfg);
    stream_ctx->response_bytes = scenario_response_bytes(&state->cfg);
    stream_ctx->counts_latency = !is_mode(&state->cfg, "bulk");
    stream_ctx->started_at = now_us();
    ++state->started_requests;
    ++state->active_streams;
    if (conn_ctx) {
        ++conn_ctx->active_streams;
        ++conn_ctx->started_requests;
    }
    lsquic_stream_wantwrite(stream, 1);
    return stream_ctx;
}

static void client_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *stream_ctx = h;
    DEBUG_LOG("client write stream=%" PRIu64 " request=%" PRIu64 "/%" PRIu64 "\n",
              (uint64_t)lsquic_stream_id(stream), stream_ctx->request_sent,
              stream_ctx->request_bytes);
    static const uint8_t zeros[WRITE_CHUNK_SIZE] = {0};
    if (stream_ctx->is_control) {
        while (stream_ctx->control_sent < stream_ctx->control_len) {
            ssize_t nw =
                lsquic_stream_write(stream, stream_ctx->control_out + stream_ctx->control_sent,
                                    stream_ctx->control_len - stream_ctx->control_sent);
            if (nw > 0) {
                stream_ctx->control_sent += (size_t)nw;
            } else if (nw < 0 && errno != EWOULDBLOCK) {
                if (is_client_shutdown_io_error(stream_ctx)) {
                    return;
                }
                set_failure(stream_ctx->state, strerror(errno));
                lsquic_stream_close(stream);
                return;
            } else {
                return;
            }
        }
        lsquic_stream_wantwrite(stream, 0);
        (void)lsquic_stream_flush(stream);
        if (stream_ctx->control_fin) {
            lsquic_stream_shutdown(stream, 1);
        }
        lsquic_stream_wantread(stream, 1);
        return;
    }
    while (stream_ctx->request_sent < stream_ctx->request_bytes) {
        uint64_t left = stream_ctx->request_bytes - stream_ctx->request_sent;
        size_t chunk = left > sizeof(zeros) ? sizeof(zeros) : (size_t)left;
        ssize_t nw = lsquic_stream_write(stream, zeros, chunk);
        if (nw > 0) {
            stream_ctx->request_sent += (uint64_t)nw;
        } else if (nw < 0 && errno != EWOULDBLOCK) {
            if (is_client_shutdown_io_error(stream_ctx)) {
                return;
            }
            set_failure(stream_ctx->state, strerror(errno));
            lsquic_stream_close(stream);
            return;
        } else {
            return;
        }
    }
    lsquic_stream_wantwrite(stream, 0);
    if (stream_ctx->persistent_rr) {
        (void)lsquic_stream_flush(stream);
        if (stream_ctx->request_fin) {
            lsquic_stream_shutdown(stream, 1);
        }
    } else {
        lsquic_stream_shutdown(stream, 1);
    }
    lsquic_stream_wantread(stream, 1);
}

static int count_persistent_client_responses(struct lsquic_stream_ctx *stream_ctx) {
    client_state_t *state = stream_ctx->state;
    while (stream_ctx->response_pending >= stream_ctx->response_bytes &&
           stream_ctx->latency_len > 0) {
        uint64_t started_at = 0;
        (void)persistent_latency_pop(stream_ctx, &started_at);
        stream_ctx->response_pending -= stream_ctx->response_bytes;
        state->counters.bytes_sent += scenario_request_bytes(&state->cfg);
        state->counters.bytes_received += stream_ctx->response_bytes;
        ++state->counters.requests_completed;
        latency_push(&state->counters.latencies, now_us() - started_at);
        if (state->active_streams > 0) {
            --state->active_streams;
        }
        if (stream_ctx->conn_ctx && stream_ctx->conn_ctx->active_streams > 0) {
            --stream_ctx->conn_ctx->active_streams;
        }
    }
    if (stream_ctx->response_pending >= stream_ctx->response_bytes &&
        stream_ctx->latency_len == 0) {
        set_failure(state, "persistent-rr received too many response bytes");
        lsquic_stream_close(stream_ctx->stream);
        return -1;
    }
    try_open_streams_on_conn(state, stream_ctx->conn_ctx);
    maybe_finish_client(state);
    return 0;
}

static void client_on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *stream_ctx = h;
    if (stream_ctx->is_control) {
        uint8_t buf[1024];
        for (;;) {
            ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
            if (nr > 0) {
                if (stream_ctx->control_in_len + (size_t)nr > stream_ctx->control_in_cap) {
                    size_t next = stream_ctx->control_in_cap ? stream_ctx->control_in_cap * 2 : 128;
                    while (next < stream_ctx->control_in_len + (size_t)nr) {
                        next *= 2;
                    }
                    uint8_t *new_bytes = realloc(stream_ctx->control_in, next);
                    if (!new_bytes) {
                        set_failure(stream_ctx->state,
                                    "out of memory reading lsquic control stream");
                        lsquic_stream_close(stream);
                        return;
                    }
                    stream_ctx->control_in = new_bytes;
                    stream_ctx->control_in_cap = next;
                }
                memcpy(stream_ctx->control_in + stream_ctx->control_in_len, buf, (size_t)nr);
                stream_ctx->control_in_len += (size_t)nr;
            } else if (nr == 0) {
                lsquic_stream_wantread(stream, 0);
                return;
            } else if (errno == EWOULDBLOCK) {
                break;
            } else {
                if (is_client_shutdown_io_error(stream_ctx)) {
                    return;
                }
                set_failure(stream_ctx->state, strerror(errno));
                lsquic_stream_close(stream);
                return;
            }
        }
        if (stream_ctx->control_in_len >= 5) {
            uint32_t payload_len = decode_be32(stream_ctx->control_in + 1);
            if (stream_ctx->control_in_len >= (size_t)payload_len + 5) {
                if (stream_ctx->control_in[0] == MESSAGE_SESSION_READY && payload_len == 4 &&
                    decode_be32(stream_ctx->control_in + 5) == PERF_PROTOCOL_VERSION) {
                    if (stream_ctx->conn_ctx) {
                        stream_ctx->conn_ctx->session_ready = 1;
                        try_open_streams_on_conn(stream_ctx->state, stream_ctx->conn_ctx);
                    }
                } else if (stream_ctx->control_in[0] == MESSAGE_SESSION_ERROR) {
                    set_failure(stream_ctx->state, "lsquic server reported session_error");
                } else {
                    set_failure(stream_ctx->state, "unexpected lsquic control message");
                }
            }
        }
        return;
    }
    DEBUG_LOG("client read stream=%" PRIu64 " response=%" PRIu64 "/%" PRIu64 "\n",
              (uint64_t)lsquic_stream_id(stream), stream_ctx->response_read,
              stream_ctx->response_bytes);
    uint8_t buf[8192];
    for (;;) {
        ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
        if (nr > 0) {
            stream_ctx->response_read += (uint64_t)nr;
            if (stream_ctx->persistent_rr) {
                stream_ctx->response_pending += (uint64_t)nr;
                if (count_persistent_client_responses(stream_ctx) != 0) {
                    return;
                }
            }
        } else if (nr == 0) {
            if (stream_ctx->persistent_rr && stream_ctx->latency_len != 0) {
                set_failure(stream_ctx->state, "persistent-rr stream closed with pending requests");
                lsquic_stream_close(stream);
                return;
            }
            stream_ctx->completed = 1;
            lsquic_stream_wantread(stream, 0);
            lsquic_stream_shutdown(stream, 0);
            return;
        } else if (errno == EWOULDBLOCK) {
            return;
        } else {
            if (is_client_shutdown_io_error(stream_ctx)) {
                return;
            }
            set_failure(stream_ctx->state, strerror(errno));
            lsquic_stream_close(stream);
            return;
        }
    }
}

static void client_on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    (void)stream;
    struct lsquic_stream_ctx *stream_ctx = h;
    if (!stream_ctx) {
        return;
    }
    DEBUG_LOG("client close completed=%d response=%" PRIu64 "/%" PRIu64 "\n", stream_ctx->completed,
              stream_ctx->response_read, stream_ctx->response_bytes);
    client_state_t *state = stream_ctx->state;
    if (stream_ctx->is_control) {
        free_client_stream_ctx(stream_ctx);
        maybe_finish_client(state);
        return;
    }
    if (stream_ctx->persistent_rr) {
        free_client_stream_ctx(stream_ctx);
        maybe_finish_client(state);
        return;
    }
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
    struct lsquic_conn_ctx *conn_ctx = stream_ctx->conn_ctx;
    if (is_mode(&state->cfg, "crr") && conn_ctx && !conn_ctx->closing && !conn_ctx->closed) {
        conn_ctx->closing = 1;
        lsquic_conn_close(conn_ctx->conn);
    }
    free_client_stream_ctx(stream_ctx);
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
    open_client_control_stream(conn_ctx->state, conn_ctx);
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
    struct lsquic_conn_ctx *conn_ctx = calloc(1, sizeof(*conn_ctx));
    if (!conn_ctx) {
        perror("calloc");
        exit(1);
    }
    conn_ctx->conn = conn;
    return conn_ctx;
}

static void server_on_conn_closed(lsquic_conn_t *conn) {
    struct lsquic_conn_ctx *conn_ctx = lsquic_conn_get_ctx(conn);
    free(conn_ctx);
}

static lsquic_stream_ctx_t *server_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream) {
    (void)stream_if_ctx;
    DEBUG_LOG("server new stream=%" PRIu64 "\n", (uint64_t)lsquic_stream_id(stream));
    struct lsquic_stream_ctx *stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (!stream_ctx) {
        perror("calloc");
        exit(1);
    }
    stream_ctx->conn_ctx = lsquic_conn_get_ctx(lsquic_stream_conn(stream));
    stream_ctx->is_control = (uint64_t)lsquic_stream_id(stream) == CONTROL_STREAM_ID;
    lsquic_stream_wantread(stream, 1);
    return stream_ctx;
}

static void server_on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *stream_ctx = h;
    if (stream_ctx->is_control) {
        uint8_t buf[1024];
        for (;;) {
            ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
            if (nr > 0) {
                if (stream_ctx->control_in_len + (size_t)nr > stream_ctx->control_in_cap) {
                    size_t next = stream_ctx->control_in_cap ? stream_ctx->control_in_cap * 2 : 128;
                    while (next < stream_ctx->control_in_len + (size_t)nr) {
                        next *= 2;
                    }
                    uint8_t *new_bytes = realloc(stream_ctx->control_in, next);
                    if (!new_bytes) {
                        lsquic_stream_close(stream);
                        return;
                    }
                    stream_ctx->control_in = new_bytes;
                    stream_ctx->control_in_cap = next;
                }
                memcpy(stream_ctx->control_in + stream_ctx->control_in_len, buf, (size_t)nr);
                stream_ctx->control_in_len += (size_t)nr;
            } else if (nr == 0) {
                break;
            } else if (errno == EWOULDBLOCK) {
                break;
            } else {
                lsquic_stream_close(stream);
                return;
            }
        }
        if (stream_ctx->control_in_len >= 5) {
            uint32_t payload_len = decode_be32(stream_ctx->control_in + 1);
            if (stream_ctx->control_in_len >= (size_t)payload_len + 5) {
                size_t msg_len = 0;
                if (stream_ctx->control_in[0] == MESSAGE_SESSION_START && stream_ctx->conn_ctx &&
                    decode_session_start_payload(stream_ctx->control_in + 5, payload_len,
                                                 &stream_ctx->conn_ctx->session_start) == 0) {
                    stream_ctx->conn_ctx->session_ready = 1;
                    stream_ctx->control_out = encode_session_ready_message(&msg_len);
                    stream_ctx->control_fin = 0;
                } else {
                    stream_ctx->control_out =
                        encode_session_error_message("invalid session_start", &msg_len);
                    stream_ctx->control_fin = 1;
                }
                stream_ctx->control_len = msg_len;
                if (stream_ctx->control_out == NULL) {
                    lsquic_stream_close(stream);
                    return;
                }
                lsquic_stream_wantwrite(stream, 1);
            }
        }
        return;
    }
    DEBUG_LOG("server read stream=%" PRIu64 " left=%" PRIu64 "\n",
              (uint64_t)lsquic_stream_id(stream), stream_ctx->server.response_left);
    if (!stream_ctx->conn_ctx || !stream_ctx->conn_ctx->session_start.started) {
        lsquic_conn_abort(lsquic_stream_conn(stream));
        return;
    }
    if (!stream_ctx->server.shape_set) {
        stream_ctx->server.request_bytes = stream_ctx->conn_ctx->session_start.request_bytes;
        stream_ctx->server.response_bytes = stream_ctx->conn_ctx->session_start.response_bytes;
        stream_ctx->persistent_rr =
            stream_ctx->conn_ctx->session_start.mode == MODE_CODE_PERSISTENT_RR;
        stream_ctx->server.response_left =
            stream_ctx->persistent_rr ? 0 : stream_ctx->server.response_bytes;
        stream_ctx->server.shape_set = 1;
    }
    for (;;) {
        uint8_t buf[8192];
        ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
        if (nr > 0) {
            stream_ctx->server.request_read += (uint64_t)nr;
        } else if (nr == 0) {
            stream_ctx->server.request_fin = 1;
            break;
        } else if (errno == EWOULDBLOCK) {
            break;
        } else {
            lsquic_stream_close(stream);
            return;
        }
    }

    if (stream_ctx->persistent_rr) {
        if (stream_ctx->server.request_fin &&
            stream_ctx->server.request_read % stream_ctx->server.request_bytes != 0) {
            lsquic_stream_close(stream);
            return;
        }
        while (stream_ctx->server.request_read >= stream_ctx->server.request_bytes) {
            stream_ctx->server.request_read -= stream_ctx->server.request_bytes;
            if (UINT64_MAX - stream_ctx->server.response_left < stream_ctx->server.response_bytes) {
                lsquic_stream_close(stream);
                return;
            }
            stream_ctx->server.response_left += stream_ctx->server.response_bytes;
            stream_ctx->server.ready_to_send = 1;
        }
    } else if (stream_ctx->server.request_read >= stream_ctx->server.request_bytes) {
        stream_ctx->server.ready_to_send = 1;
    }
    if (stream_ctx->server.ready_to_send) {
        if (stream_ctx->server.request_fin) {
            lsquic_stream_wantread(stream, 0);
        }
        lsquic_stream_wantwrite(stream, 1);
    }
}

static void server_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *stream_ctx = h;
    if (stream_ctx->is_control) {
        while (stream_ctx->control_sent < stream_ctx->control_len) {
            ssize_t nw =
                lsquic_stream_write(stream, stream_ctx->control_out + stream_ctx->control_sent,
                                    stream_ctx->control_len - stream_ctx->control_sent);
            if (nw > 0) {
                stream_ctx->control_sent += (size_t)nw;
            } else if (nw < 0 && errno != EWOULDBLOCK) {
                lsquic_stream_close(stream);
                return;
            } else {
                return;
            }
        }
        lsquic_stream_wantwrite(stream, 0);
        (void)lsquic_stream_flush(stream);
        if (stream_ctx->control_fin) {
            lsquic_stream_shutdown(stream, 1);
        }
        return;
    }
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
    (void)lsquic_stream_flush(stream);
    if (!stream_ctx->persistent_rr || stream_ctx->server.request_fin) {
        lsquic_stream_shutdown(stream, 1);
    }
}

static void server_on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *h) {
    DEBUG_LOG("server close stream=%" PRIu64 "\n", (uint64_t)lsquic_stream_id(stream));
    struct lsquic_stream_ctx *stream_ctx = h;
    if (stream_ctx) {
        free(stream_ctx->control_out);
        free(stream_ctx->control_in);
        free(stream_ctx->latency_starts);
    }
    free(stream_ctx);
}

const struct lsquic_stream_if server_stream_if = {
    .on_new_conn = server_on_new_conn,
    .on_conn_closed = server_on_conn_closed,
    .on_new_stream = server_on_new_stream,
    .on_read = server_on_read,
    .on_write = server_on_write,
    .on_close = server_on_close,
};

static void client_drain_cb(evutil_socket_t fd, short what, void *arg) {
    (void)fd;
    (void)what;
    client_state_t *state = arg;
    prog_stop(&state->prog);
}

static void client_deadline_cb(evutil_socket_t fd, short what, void *arg) {
    (void)fd;
    (void)what;
    client_state_t *state = arg;
    state->stop_starting = 1;
    close_all_connections(state);
    if (state->active_conns == 0) {
        prog_stop(&state->prog);
    } else {
        if (state->drain_timer) {
            struct timeval timeout;
            timeout.tv_sec = (time_t)(DRAIN_TIMEOUT_US / 1000000ULL);
            timeout.tv_usec = (suseconds_t)(DRAIN_TIMEOUT_US % 1000000ULL);
            evtimer_add(state->drain_timer, &timeout);
        } else {
            prog_stop(&state->prog);
            return;
        }
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
    if (init_client_sports(&state, service) != 0) {
        set_failure(&state, "could not prepare lsquic client ports");
        prog_stop(&state.prog);
        prog_cleanup(&state.prog);
        cleanup_client_sports(&state);
        return make_summary(cfg, &state.counters, 0, "failed", state.failure_reason);
    }

    state.measure_start_us = now_us();
    state.deadline_us = state.measure_start_us + cfg->duration_us;
    if (!state.bounded) {
        state.deadline_timer = evtimer_new(prog_eb(&state.prog), client_deadline_cb, &state);
        state.drain_timer = evtimer_new(prog_eb(&state.prog), client_drain_cb, &state);
        if (state.deadline_timer) {
            struct timeval timeout;
            timeout.tv_sec = (time_t)(cfg->duration_us / 1000000ULL);
            timeout.tv_usec = (suseconds_t)(cfg->duration_us % 1000000ULL);
            evtimer_add(state.deadline_timer, &timeout);
        }
    }

    uint64_t initial_connections =
        is_mode(cfg, "rr") ? rr_connection_target(cfg) : cfg->connections;
    for (uint64_t i = 0; i < initial_connections && should_start_request(&state); ++i) {
        if (start_client_connection(&state) != 0) {
            break;
        }
    }
    if (!state.failed) {
        prog_run(&state.prog);
    }
    if (!state.failed && !state.bounded && !is_mode(cfg, "bulk") &&
        state.counters.requests_completed == 0) {
        set_failure(&state, "timed request-response run completed zero requests");
    }
    uint64_t elapsed_us = now_us() - state.measure_start_us;
    if (!state.bounded && !state.failed) {
        elapsed_us = cfg->duration_us;
    }
    if (state.deadline_timer) {
        event_del(state.deadline_timer);
        event_free(state.deadline_timer);
    }
    if (state.drain_timer) {
        event_del(state.drain_timer);
        event_free(state.drain_timer);
    }
    prog_cleanup(&state.prog);
    cleanup_client_sports(&state);
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
