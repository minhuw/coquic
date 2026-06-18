#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_utils.h"
#include "picosocks.h"

#define APPLICATION_PROTOCOL "coquic-perf/1"
#define PERF_PROTOCOL_VERSION 3U
#define CONTROL_STREAM_ID 0ULL
#define FIRST_DATA_STREAM_ID 4ULL
#define MESSAGE_SESSION_START 1U
#define MESSAGE_SESSION_READY 2U
#define MESSAGE_SESSION_ERROR 3U
#define MESSAGE_SESSION_COMPLETE 4U
#define MODE_CODE_BULK 0U
#define MODE_CODE_RR 1U
#define MODE_CODE_CRR 2U
#define MODE_CODE_PERSISTENT_RR 3U
#define DIRECTION_CODE_UPLOAD 0U
#define DIRECTION_CODE_DOWNLOAD 1U
#define TRANSFER_CONNECTION_WINDOW (32ULL * 1024ULL * 1024ULL)
#define TRANSFER_STREAM_WINDOW (16ULL * 1024ULL * 1024ULL)
#define WRITE_CHUNK_SIZE 32768U
#define READ_CHUNK_SIZE 65536U
#define DEFAULT_PORT 4433
#define DRAIN_TIMEOUT_US 2000000ULL
#define SERVER_SHUTDOWN_DELAY_US 500000ULL
#define HANDSHAKE_TIMEOUT_US 10000000ULL
#define CRR_WORKER_LIMIT 8ULL

typedef struct optional_u64_t {
    uint64_t value;
    int set;
} optional_u64_t;

static FILE *open_json_output(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        return NULL;
    }
    FILE *f = fdopen(fd, "w");
    if (f == NULL) {
        close(fd);
    }
    return f;
}

typedef struct config_t {
    const char *host;
    uint16_t port;
    const char *server_name;
    int verify_peer;
    const char *io_backend;
    const char *congestion_control;
    const char *certificate_chain;
    const char *private_key;
    int disable_pmtud;
    const char *mode;
    const char *direction;
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t streams;
    uint64_t connections;
    uint64_t requests_in_flight;
    optional_u64_t requests;
    optional_u64_t total_bytes;
    uint64_t warmup_us;
    uint64_t duration_us;
    const char *json_out;
} config_t;

typedef struct latency_vec_t {
    uint64_t *values;
    size_t len;
    size_t cap;
} latency_vec_t;

typedef struct counters_t {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t requests_completed;
    uint64_t skipped_setup_errors;
    latency_vec_t latencies;
} counters_t;

typedef struct latency_summary_t {
    uint64_t min_us;
    uint64_t avg_us;
    uint64_t p50_us;
    uint64_t p90_us;
    uint64_t p99_us;
    uint64_t max_us;
} latency_summary_t;

typedef struct stream_ctx_t {
    struct stream_ctx_t *next;
    picoquic_cnx_t *cnx;
    uint64_t stream_id;
    int is_server;
    int counts;
    int request_fin;
    int response_fin;
    int closed;
    uint8_t *control_out;
    uint8_t *control_in;
    size_t control_len;
    size_t control_in_len;
    size_t control_in_cap;
    size_t control_sent;
    int control_fin;
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t request_received;
    uint64_t request_sent;
    uint64_t response_received;
    uint64_t response_sent;
    uint64_t started_at;
    int persistent_rr;
    uint64_t response_pending;
    uint64_t *persistent_started_at;
    uint8_t *persistent_counts;
    size_t persistent_head;
    size_t persistent_len;
    size_t persistent_cap;
} stream_ctx_t;

typedef struct perf_session_start_t {
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

typedef struct app_ctx_t {
    config_t cfg;
    int is_client;
    int finished;
    int failed;
    int initial_opened;
    char error[256];
    picoquic_cnx_t *cnx;
    picoquic_cnx_t **connections;
    uint8_t *connection_ready;
    uint8_t *connection_control_opened;
    uint64_t *connection_request_limit;
    uint64_t *connection_requests_started;
    uint64_t connection_count;
    uint64_t ready_connections;
    uint64_t next_connection;
    stream_ctx_t *streams;
    uint64_t active_streams;
    uint64_t started_requests;
    uint64_t next_stream_rr;
    uint64_t measure_start;
    uint64_t measure_deadline;
    perf_session_start_t session_start;
    uint64_t server_bytes_sent;
    uint64_t server_bytes_received;
    uint64_t server_requests_completed;
    int server_complete_sent;
    counters_t counters;
} app_ctx_t;

typedef struct run_summary_t {
    const char *status;
    const char *failure_reason;
    const char *mode;
    const char *direction;
    const char *backend;
    const char *congestion_control;
    const char *remote_host;
    uint16_t remote_port;
    const char *alpn;
    int64_t elapsed_ms;
    int64_t warmup_ms;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t server_bytes_sent;
    uint64_t server_bytes_received;
    uint64_t server_requests_completed;
    uint64_t requests_completed;
    uint64_t streams;
    uint64_t connections;
    uint64_t requests_in_flight;
    uint64_t request_bytes;
    uint64_t response_bytes;
    double throughput_mib_per_s;
    double throughput_gbit_per_s;
    double requests_per_s;
    latency_summary_t latency;
    uint64_t skipped_setup_errors;
} run_summary_t;

typedef struct crr_worker_state_t {
    config_t cfg;
    uint64_t measure_start;
    uint64_t measure_deadline;
    uint64_t started;
    int failed;
    char failure_reason[256];
    counters_t counters;
    pthread_mutex_t mutex;
} crr_worker_state_t;

static volatile sig_atomic_t stop_requested = 0;

static int app_callback(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes, size_t length,
                        picoquic_call_back_event_t event, void *callback_ctx, void *v_stream_ctx);

static void handle_signal(int signum) {
    (void)signum;
    stop_requested = 1;
}

static void set_error(app_ctx_t *app, const char *message) {
    if (app->error[0] == 0) {
        snprintf(app->error, sizeof(app->error), "%s", message);
    }
    app->failed = 1;
}

static int is_mode(const config_t *cfg, const char *mode) {
    return strcmp(cfg->mode, mode) == 0;
}

static int is_direction(const config_t *cfg, const char *direction) {
    return strcmp(cfg->direction, direction) == 0;
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
    if (len > 2 && strcmp(text + len - 2, "ms") == 0) {
        char tmp[64];
        if (len - 2 >= sizeof(tmp)) {
            fprintf(stderr, "invalid duration: %s\n", text);
            exit(2);
        }
        memcpy(tmp, text, len - 2);
        tmp[len - 2] = 0;
        return parse_u64(tmp, "duration") * 1000ULL;
    }
    if (len > 1 && text[len - 1] == 's') {
        char tmp[64];
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

static config_t default_config(void) {
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = "127.0.0.1";
    cfg.port = DEFAULT_PORT;
    cfg.server_name = "localhost";
    cfg.io_backend = "socket";
    cfg.congestion_control = "default";
    cfg.certificate_chain = "tests/fixtures/quic-server-cert.pem";
    cfg.private_key = "tests/fixtures/quic-server-key.pem";
    cfg.disable_pmtud = 1;
    cfg.mode = "bulk";
    cfg.direction = "download";
    cfg.request_bytes = 64;
    cfg.response_bytes = 64;
    cfg.streams = 1;
    cfg.connections = 1;
    cfg.requests_in_flight = 1;
    cfg.duration_us = 5000000ULL;
    return cfg;
}

static config_t parse_args(int argc, char **argv) {
    config_t cfg = default_config();
    for (int i = 0; i < argc;) {
        const char *arg = argv[i++];
        if (strcmp(arg, "--verify-peer") == 0) {
            cfg.verify_peer = 1;
        } else if (strcmp(arg, "--disable-pmtud") == 0) {
            cfg.disable_pmtud = 1;
        } else if (strcmp(arg, "--host") == 0) {
            cfg.host = take_value(argc, argv, &i, arg);
        } else if (strcmp(arg, "--port") == 0) {
            cfg.port = (uint16_t)parse_u64(take_value(argc, argv, &i, arg), "port");
        } else if (strcmp(arg, "--server-name") == 0) {
            cfg.server_name = take_value(argc, argv, &i, arg);
        } else if (strcmp(arg, "--io-backend") == 0) {
            cfg.io_backend = take_value(argc, argv, &i, arg);
        } else if (strcmp(arg, "--congestion-control") == 0) {
            cfg.congestion_control = take_value(argc, argv, &i, arg);
        } else if (strcmp(arg, "--certificate-chain") == 0) {
            cfg.certificate_chain = take_value(argc, argv, &i, arg);
        } else if (strcmp(arg, "--private-key") == 0) {
            cfg.private_key = take_value(argc, argv, &i, arg);
        } else if (strcmp(arg, "--mode") == 0) {
            cfg.mode = take_value(argc, argv, &i, arg);
        } else if (strcmp(arg, "--direction") == 0) {
            cfg.direction = take_value(argc, argv, &i, arg);
        } else if (strcmp(arg, "--request-bytes") == 0) {
            cfg.request_bytes = parse_u64(take_value(argc, argv, &i, arg), "request-bytes");
        } else if (strcmp(arg, "--response-bytes") == 0) {
            cfg.response_bytes = parse_u64(take_value(argc, argv, &i, arg), "response-bytes");
        } else if (strcmp(arg, "--streams") == 0) {
            cfg.streams = parse_u64(take_value(argc, argv, &i, arg), "streams");
        } else if (strcmp(arg, "--connections") == 0) {
            cfg.connections = parse_u64(take_value(argc, argv, &i, arg), "connections");
        } else if (strcmp(arg, "--requests-in-flight") == 0) {
            cfg.requests_in_flight =
                parse_u64(take_value(argc, argv, &i, arg), "requests-in-flight");
        } else if (strcmp(arg, "--requests") == 0) {
            cfg.requests.value = parse_u64(take_value(argc, argv, &i, arg), "requests");
            cfg.requests.set = 1;
        } else if (strcmp(arg, "--total-bytes") == 0) {
            cfg.total_bytes.value = parse_u64(take_value(argc, argv, &i, arg), "total-bytes");
            cfg.total_bytes.set = 1;
        } else if (strcmp(arg, "--warmup") == 0) {
            cfg.warmup_us = parse_duration_us(take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--duration") == 0) {
            cfg.duration_us = parse_duration_us(take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--json-out") == 0) {
            cfg.json_out = take_value(argc, argv, &i, arg);
        } else {
            fprintf(stderr, "unknown argument: %s\n", arg);
            exit(2);
        }
    }
    if (!is_mode(&cfg, "bulk") && !is_mode(&cfg, "rr") && !is_mode(&cfg, "crr") &&
        !is_mode(&cfg, "persistent-rr")) {
        fprintf(stderr, "unsupported mode: %s\n", cfg.mode);
        exit(2);
    }
    if (strcmp(cfg.io_backend, "socket") != 0 && strcmp(cfg.io_backend, "io_uring") != 0) {
        fprintf(stderr, "unsupported io-backend label: %s\n", cfg.io_backend);
        exit(2);
    }
    if (strcmp(cfg.io_backend, "socket") != 0) {
        fprintf(stderr, "picoquic-perf only supports the socket backend\n");
        exit(2);
    }
    if (strcmp(cfg.congestion_control, "default") != 0 &&
        strcmp(cfg.congestion_control, "newreno") != 0 &&
        strcmp(cfg.congestion_control, "cubic") != 0 &&
        strcmp(cfg.congestion_control, "bbr") != 0 && strcmp(cfg.congestion_control, "copa") != 0) {
        fprintf(stderr, "unsupported congestion-control label: %s\n", cfg.congestion_control);
        exit(2);
    }
    if (strcmp(cfg.congestion_control, "copa") == 0) {
        fprintf(stderr, "picoquic-perf does not provide Copa; use PERF_CONGESTION_CONTROLS=default "
                        "for paired picoquic baselines\n");
        exit(2);
    }
    if (!is_direction(&cfg, "upload") && !is_direction(&cfg, "download") &&
        !is_direction(&cfg, "stay")) {
        fprintf(stderr, "unsupported direction: %s\n", cfg.direction);
        exit(2);
    }
    if (cfg.streams == 0 || cfg.connections == 0 || cfg.requests_in_flight == 0) {
        fprintf(stderr, "streams, connections, and requests-in-flight must be greater than zero\n");
        exit(2);
    }
    if (is_mode(&cfg, "persistent-rr") && (cfg.request_bytes == 0 || cfg.response_bytes == 0)) {
        fprintf(stderr, "persistent-rr requires nonzero request and response bytes\n");
        exit(2);
    }
    return cfg;
}

static void configure_quic(picoquic_quic_t *quic, const config_t *cfg) {
    picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_data, TRANSFER_CONNECTION_WINDOW);
    picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_stream_data_bidi_local,
                                  TRANSFER_STREAM_WINDOW);
    picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_stream_data_bidi_remote,
                                  TRANSFER_STREAM_WINDOW);
    picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_stream_data_uni,
                                  TRANSFER_STREAM_WINDOW);
    picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_streams_bidi, 4096);
    picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_streams_uni, 0);
    picoquic_set_default_idle_timeout(quic, 30000);
    if (cfg->disable_pmtud) {
        picoquic_set_default_pmtud_policy(quic, picoquic_pmtud_blocked);
    }
    if (strcmp(cfg->congestion_control, "default") != 0) {
        const char *cc =
            strcmp(cfg->congestion_control, "newreno") == 0 ? "newreno" : cfg->congestion_control;
        picoquic_set_default_congestion_algorithm_by_name(quic, cc);
    }
}

static picoquic_quic_t *create_quic_context(const config_t *cfg, int server, app_ctx_t *app) {
    picoquic_quic_t *quic = picoquic_create(
        server ? 4096U : (uint32_t)(cfg->connections + 8), server ? cfg->certificate_chain : NULL,
        server ? cfg->private_key : NULL, NULL, APPLICATION_PROTOCOL, server ? app_callback : NULL,
        server ? app : NULL, NULL, NULL, NULL, picoquic_current_time(), NULL, NULL, NULL, 0);
    if (quic == NULL) {
        return NULL;
    }
    configure_quic(quic, cfg);
    if (!server && !cfg->verify_peer) {
        picoquic_set_null_verifier(quic);
    }
    return quic;
}

static int latency_push(latency_vec_t *vec, uint64_t value) {
    if (vec->len == vec->cap) {
        size_t next_cap = vec->cap == 0 ? 1024 : vec->cap * 2;
        uint64_t *next = (uint64_t *)realloc(vec->values, next_cap * sizeof(uint64_t));
        if (next == NULL) {
            return -1;
        }
        vec->values = next;
        vec->cap = next_cap;
    }
    vec->values[vec->len++] = value;
    return 0;
}

static int compare_u64(const void *a, const void *b) {
    uint64_t av = *(const uint64_t *)a;
    uint64_t bv = *(const uint64_t *)b;
    return (av > bv) - (av < bv);
}

static uint64_t percentile_value(const uint64_t *sorted, size_t len, double pct) {
    size_t rank = (size_t)((pct / 100.0) * (double)len + 0.999999);
    if (rank == 0) {
        rank = 1;
    }
    if (rank > len) {
        rank = len;
    }
    return sorted[rank - 1];
}

static latency_summary_t summarize_latency(latency_vec_t *vec) {
    latency_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    if (vec->len == 0) {
        return summary;
    }
    qsort(vec->values, vec->len, sizeof(uint64_t), compare_u64);
    uint64_t total = 0;
    for (size_t i = 0; i < vec->len; ++i) {
        total += vec->values[i];
    }
    summary.min_us = vec->values[0];
    summary.avg_us = total / (uint64_t)vec->len;
    summary.p50_us = percentile_value(vec->values, vec->len, 50.0);
    summary.p90_us = percentile_value(vec->values, vec->len, 90.0);
    summary.p99_us = percentile_value(vec->values, vec->len, 99.0);
    summary.max_us = vec->values[vec->len - 1];
    return summary;
}

static stream_ctx_t *alloc_stream(app_ctx_t *app, uint64_t stream_id, int is_server) {
    stream_ctx_t *s = (stream_ctx_t *)calloc(1, sizeof(stream_ctx_t));
    if (s == NULL) {
        set_error(app, "out of memory allocating stream context");
        return NULL;
    }
    s->stream_id = stream_id;
    s->is_server = is_server;
    s->next = app->streams;
    app->streams = s;
    return s;
}

static void remove_stream(app_ctx_t *app, stream_ctx_t *stream) {
    stream_ctx_t **pp = &app->streams;
    while (*pp != NULL) {
        if (*pp == stream) {
            *pp = stream->next;
            free(stream->control_out);
            free(stream->control_in);
            free(stream->persistent_started_at);
            free(stream->persistent_counts);
            free(stream);
            return;
        }
        pp = &(*pp)->next;
    }
}

static void free_streams(app_ctx_t *app) {
    while (app->streams != NULL) {
        stream_ctx_t *next = app->streams->next;
        free(app->streams->control_out);
        free(app->streams->control_in);
        free(app->streams->persistent_started_at);
        free(app->streams->persistent_counts);
        free(app->streams);
        app->streams = next;
    }
}

static int persistent_queue_push(stream_ctx_t *stream, uint64_t started_at, int counts) {
    if (stream->persistent_len == stream->persistent_cap) {
        size_t new_cap = stream->persistent_cap ? stream->persistent_cap * 2 : 8;
        uint64_t *new_started = (uint64_t *)malloc(new_cap * sizeof(new_started[0]));
        uint8_t *new_counts = (uint8_t *)malloc(new_cap * sizeof(new_counts[0]));
        if (new_started == NULL || new_counts == NULL) {
            free(new_started);
            free(new_counts);
            return -1;
        }
        for (size_t i = 0; i < stream->persistent_len; ++i) {
            size_t old = (stream->persistent_head + i) % stream->persistent_cap;
            new_started[i] = stream->persistent_started_at[old];
            new_counts[i] = stream->persistent_counts[old];
        }
        free(stream->persistent_started_at);
        free(stream->persistent_counts);
        stream->persistent_started_at = new_started;
        stream->persistent_counts = new_counts;
        stream->persistent_cap = new_cap;
        stream->persistent_head = 0;
    }
    size_t index = (stream->persistent_head + stream->persistent_len) % stream->persistent_cap;
    stream->persistent_started_at[index] = started_at;
    stream->persistent_counts[index] = counts ? 1 : 0;
    ++stream->persistent_len;
    return 0;
}

static int persistent_queue_pop(stream_ctx_t *stream, uint64_t *started_at, int *counts) {
    if (stream->persistent_len == 0) {
        return -1;
    }
    *started_at = stream->persistent_started_at[stream->persistent_head];
    *counts = stream->persistent_counts[stream->persistent_head] != 0;
    stream->persistent_head = (stream->persistent_head + 1) % stream->persistent_cap;
    --stream->persistent_len;
    return 0;
}

static void encode_be32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)((value >> 24) & 0xffU);
    out[1] = (uint8_t)((value >> 16) & 0xffU);
    out[2] = (uint8_t)((value >> 8) & 0xffU);
    out[3] = (uint8_t)(value & 0xffU);
}

static uint32_t decode_be32(const uint8_t *in) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static void encode_be64(uint8_t *out, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)(value & 0xffU);
        value >>= 8;
    }
}

static uint64_t decode_be64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
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
    uint8_t *out = (uint8_t *)malloc((size_t)payload_len + 5);
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

static uint64_t rr_connection_target(const config_t *cfg) {
    if ((is_mode(cfg, "rr") || is_mode(cfg, "persistent-rr")) && cfg->requests.set) {
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

static uint8_t *encode_session_start_message(const config_t *cfg, uint64_t request_limit,
                                             size_t *out_len) {
    uint8_t payload[79];
    encode_be32(payload, PERF_PROTOCOL_VERSION);
    payload[4] = mode_code(cfg->mode);
    payload[5] = direction_code(cfg->direction);
    encode_be64(payload + 6, cfg->request_bytes);
    encode_be64(payload + 14, cfg->response_bytes);
    payload[22] = (cfg->total_bytes.set ? 0x01 : 0) | (cfg->requests.set ? 0x02 : 0);
    encode_be64(payload + 23, cfg->total_bytes.value);
    encode_be64(payload + 31, cfg->requests.set ? request_limit : cfg->requests.value);
    encode_be64(payload + 39, cfg->warmup_us);
    encode_be64(payload + 47, cfg->duration_us);
    encode_be64(payload + 55, cfg->streams);
    encode_be64(payload + 63, cfg->connections);
    encode_be64(payload + 71, cfg->requests_in_flight);
    return frame_control_message(MESSAGE_SESSION_START, payload, sizeof(payload), out_len);
}

static uint8_t *encode_session_ready_message(size_t *out_len) {
    uint8_t payload[4];
    encode_be32(payload, PERF_PROTOCOL_VERSION);
    return frame_control_message(MESSAGE_SESSION_READY, payload, sizeof(payload), out_len);
}

static uint8_t *encode_session_error_message(const char *reason, size_t *out_len) {
    size_t reason_len = strlen(reason);
    uint8_t *payload = (uint8_t *)malloc(reason_len + 4);
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

static uint8_t *encode_session_complete_message(uint64_t bytes_sent, uint64_t bytes_received,
                                                uint64_t requests_completed, size_t *out_len) {
    uint8_t payload[24];
    encode_be64(payload, bytes_sent);
    encode_be64(payload + 8, bytes_received);
    encode_be64(payload + 16, requests_completed);
    return frame_control_message(MESSAGE_SESSION_COMPLETE, payload, sizeof(payload), out_len);
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
        start->streams == 0 || start->connections == 0 || start->requests_in_flight == 0 ||
        (start->mode == MODE_CODE_PERSISTENT_RR &&
         (start->request_bytes == 0 || start->response_bytes == 0))) {
        return -1;
    }
    return 0;
}

static int mark_connection_ready(app_ctx_t *app, picoquic_cnx_t *cnx) {
    for (uint64_t i = 0; i < app->connection_count; ++i) {
        if (app->connections[i] == cnx) {
            if (!app->connection_ready[i]) {
                app->connection_ready[i] = 1;
                app->ready_connections++;
            }
            return 0;
        }
    }
    return -1;
}

static picoquic_cnx_t *pick_connection(app_ctx_t *app) {
    if (app->connection_count == 0) {
        return NULL;
    }
    picoquic_cnx_t *cnx = app->connections[app->next_connection % app->connection_count];
    app->next_connection++;
    return cnx;
}

static uint64_t active_streams_on_connection(app_ctx_t *app, picoquic_cnx_t *cnx) {
    uint64_t active = 0;
    for (stream_ctx_t *stream = app->streams; stream != NULL; stream = stream->next) {
        if (!stream->is_server && stream->stream_id != CONTROL_STREAM_ID && stream->cnx == cnx) {
            active += stream->persistent_rr ? stream->persistent_len : 1;
        }
    }
    return active;
}

static stream_ctx_t *persistent_stream_on_connection(app_ctx_t *app, picoquic_cnx_t *cnx) {
    for (stream_ctx_t *stream = app->streams; stream != NULL; stream = stream->next) {
        if (!stream->is_server && stream->persistent_rr && stream->cnx == cnx) {
            return stream;
        }
    }
    return NULL;
}

static uint64_t connection_index_for(app_ctx_t *app, picoquic_cnx_t *cnx) {
    for (uint64_t i = 0; i < app->connection_count; ++i) {
        if (app->connections[i] == cnx) {
            return i;
        }
    }
    return app->connection_count;
}

static int open_request_stream(app_ctx_t *app, uint64_t request_bytes, uint64_t response_bytes,
                               int counts) {
    picoquic_cnx_t *cnx = pick_connection(app);
    if (cnx == NULL) {
        set_error(app, "no picoquic connection available");
        return -1;
    }
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    stream_ctx_t *stream = alloc_stream(app, stream_id, 0);
    if (stream == NULL) {
        return -1;
    }
    stream->counts = counts;
    stream->cnx = cnx;
    stream->request_bytes = request_bytes;
    stream->response_bytes = response_bytes;
    stream->started_at = picoquic_current_time();
    if (picoquic_mark_active_stream(cnx, stream_id, 1, stream) != 0) {
        remove_stream(app, stream);
        set_error(app, "picoquic_mark_active_stream failed");
        return -1;
    }
    app->active_streams++;
    app->started_requests++;
    uint64_t index = connection_index_for(app, cnx);
    if (index < app->connection_count) {
        app->connection_requests_started[index]++;
    }
    return 0;
}

static int send_persistent_rr_request(app_ctx_t *app, picoquic_cnx_t *cnx, int counts) {
    stream_ctx_t *stream = persistent_stream_on_connection(app, cnx);
    if (stream == NULL) {
        uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, 0);
        stream = alloc_stream(app, stream_id, 0);
        if (stream == NULL) {
            return -1;
        }
        stream->counts = counts;
        stream->cnx = cnx;
        stream->request_bytes = 0;
        stream->response_bytes = app->cfg.response_bytes;
        stream->persistent_rr = 1;
    }
    if (persistent_queue_push(stream, picoquic_current_time(), counts) != 0) {
        set_error(app, "out of memory queuing persistent-rr request");
        return -1;
    }
    stream->request_bytes += app->cfg.request_bytes;
    if (picoquic_mark_active_stream(cnx, stream->stream_id, 1, stream) != 0) {
        set_error(app, "picoquic_mark_active_stream failed");
        return -1;
    }
    app->active_streams++;
    app->started_requests++;
    uint64_t index = connection_index_for(app, cnx);
    if (index < app->connection_count) {
        app->connection_requests_started[index]++;
    }
    return 0;
}

static int open_control_stream(app_ctx_t *app, picoquic_cnx_t *cnx) {
    stream_ctx_t *stream = alloc_stream(app, CONTROL_STREAM_ID, 0);
    if (stream == NULL) {
        return -1;
    }
    uint64_t index = connection_index_for(app, cnx);
    uint64_t request_limit = index < app->connection_count ? app->connection_request_limit[index]
                                                           : app->cfg.requests.value;
    stream->control_out =
        encode_session_start_message(&app->cfg, request_limit, &stream->control_len);
    stream->cnx = cnx;
    stream->control_fin = 1;
    if (stream->control_out == NULL ||
        picoquic_add_to_stream_with_ctx(cnx, CONTROL_STREAM_ID, stream->control_out,
                                        stream->control_len, 1, stream) != 0) {
        remove_stream(app, stream);
        set_error(app, "picoquic control stream open failed");
        return -1;
    }
    return 0;
}

static int open_bulk_streams(app_ctx_t *app) {
    if (app->cfg.total_bytes.set) {
        uint64_t per_stream = app->cfg.total_bytes.value / app->cfg.streams;
        uint64_t remainder = app->cfg.total_bytes.value % app->cfg.streams;
        for (uint64_t i = 0; i < app->cfg.streams; ++i) {
            uint64_t target = per_stream + (i < remainder ? 1 : 0);
            uint64_t request = is_direction(&app->cfg, "upload") ? target : 0;
            uint64_t response = is_direction(&app->cfg, "upload") ? 0 : target;
            if (open_request_stream(app, request, response, 1) != 0) {
                return -1;
            }
        }
        return 0;
    }
    for (uint64_t i = 0; i < app->connection_count; ++i) {
        picoquic_cnx_t *cnx = app->connections[i];
        while (active_streams_on_connection(app, cnx) < app->cfg.streams) {
            uint64_t now = picoquic_current_time();
            if (now >= app->measure_deadline) {
                break;
            }
            app->next_connection = i;
            if (open_request_stream(app, 0, app->cfg.response_bytes, now >= app->measure_start) !=
                0) {
                return -1;
            }
        }
    }
    return 0;
}

static int open_rr_streams(app_ctx_t *app) {
    for (uint64_t i = 0; i < app->connection_count; ++i) {
        picoquic_cnx_t *cnx = app->connections[i];
        while (active_streams_on_connection(app, cnx) < app->cfg.requests_in_flight) {
            uint64_t now = picoquic_current_time();
            if (app->cfg.requests.set) {
                if (app->started_requests >= app->cfg.requests.value) {
                    return 0;
                }
                if (app->connection_requests_started[i] >= app->connection_request_limit[i]) {
                    break;
                }
            }
            if (!app->cfg.requests.set && now >= app->measure_deadline) {
                return 0;
            }
            int counts = now >= app->measure_start;
            app->next_connection = i;
            if (is_mode(&app->cfg, "persistent-rr")) {
                if (send_persistent_rr_request(app, cnx, counts) != 0) {
                    return -1;
                }
            } else if (open_request_stream(app, app->cfg.request_bytes, app->cfg.response_bytes,
                                           counts) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

static void maybe_finish_client(app_ctx_t *app) {
    uint64_t now = picoquic_current_time();
    if (app->failed) {
        app->finished = 1;
        return;
    }
    if (!app->initial_opened) {
        return;
    }
    if (is_mode(&app->cfg, "bulk")) {
        if (app->cfg.total_bytes.set) {
            if (app->active_streams == 0 && app->started_requests >= app->cfg.streams) {
                app->finished = 1;
            }
            return;
        }
        if (now >= app->measure_deadline) {
            app->finished = 1;
        } else {
            (void)open_bulk_streams(app);
        }
        return;
    }
    if (is_mode(&app->cfg, "rr") || is_mode(&app->cfg, "persistent-rr")) {
        if (app->cfg.requests.set) {
            if (app->started_requests >= app->cfg.requests.value && app->active_streams == 0) {
                app->finished = 1;
            }
        } else if (now >= app->measure_deadline) {
            app->finished = 1;
        }
        if (!app->finished) {
            (void)open_rr_streams(app);
        }
    }
}

static int provide_client_data(stream_ctx_t *stream, uint8_t *context, size_t length) {
    if (stream->stream_id == CONTROL_STREAM_ID) {
        size_t remaining = stream->control_len > stream->control_sent
                               ? stream->control_len - stream->control_sent
                               : 0;
        size_t to_send = remaining < length ? remaining : length;
        int is_fin = to_send == remaining && stream->control_fin;
        uint8_t *buffer = picoquic_provide_stream_data_buffer(context, to_send, is_fin, !is_fin);
        if (buffer == NULL && to_send > 0) {
            return -1;
        }
        if (to_send > 0) {
            memcpy(buffer, stream->control_out + stream->control_sent, to_send);
        }
        stream->control_sent += to_send;
        return 0;
    }
    uint64_t total = stream->request_bytes;
    uint64_t sent = stream->request_sent;
    uint64_t remaining = total > sent ? total - sent : 0;
    size_t to_send = remaining < (uint64_t)length ? (size_t)remaining : length;
    int is_fin = (uint64_t)to_send == remaining && (!stream->persistent_rr || stream->request_fin);
    if (to_send == 0 && !is_fin) {
        (void)picoquic_provide_stream_data_buffer(context, 0, 0, 0);
        return 0;
    }
    uint8_t *buffer = picoquic_provide_stream_data_buffer(context, to_send, is_fin, !is_fin);
    if (buffer == NULL && to_send > 0) {
        return -1;
    }
    if (to_send > 0) {
        memset(buffer, 0x5a, to_send);
    }
    stream->request_sent += to_send;
    return 0;
}

static int provide_server_data(stream_ctx_t *stream, uint8_t *context, size_t length) {
    if (stream->stream_id == CONTROL_STREAM_ID) {
        size_t remaining = stream->control_len > stream->control_sent
                               ? stream->control_len - stream->control_sent
                               : 0;
        size_t to_send = remaining < length ? remaining : length;
        int is_fin = to_send == remaining && stream->control_fin;
        uint8_t *buffer = picoquic_provide_stream_data_buffer(context, to_send, is_fin, !is_fin);
        if (buffer == NULL && to_send > 0) {
            return -1;
        }
        if (to_send > 0) {
            memcpy(buffer, stream->control_out + stream->control_sent, to_send);
        }
        stream->control_sent += to_send;
        if (is_fin) {
            stream->response_fin = 1;
        }
        return 0;
    }
    uint64_t remaining = stream->response_bytes > stream->response_sent
                             ? stream->response_bytes - stream->response_sent
                             : 0;
    size_t to_send = remaining < (uint64_t)length ? (size_t)remaining : length;
    int is_fin = (uint64_t)to_send == remaining && (!stream->persistent_rr || stream->request_fin);
    if (to_send == 0 && !is_fin) {
        (void)picoquic_provide_stream_data_buffer(context, 0, 0, 0);
        return 0;
    }
    uint8_t *buffer = picoquic_provide_stream_data_buffer(context, to_send, is_fin, !is_fin);
    if (buffer == NULL && to_send > 0) {
        return -1;
    }
    if (to_send > 0) {
        memset(buffer, 0x5a, to_send);
    }
    stream->response_sent += to_send;
    if (is_fin) {
        stream->response_fin = 1;
        if (stream->stream_id != CONTROL_STREAM_ID && stream->is_server) {
            /* Count once when the response body reaches FIN. */
            stream->closed = 1;
        }
    }
    return 0;
}

static uint64_t server_response_bytes(const app_ctx_t *app, uint64_t requests_completed) {
    const perf_session_start_t *start = &app->session_start;
    if (start->mode == MODE_CODE_BULK && start->direction == DIRECTION_CODE_DOWNLOAD &&
        start->total_bytes.set) {
        uint64_t stream_index = requests_completed ? requests_completed - 1 : 0;
        uint64_t per_stream = start->total_bytes.value / start->streams;
        uint64_t remainder = start->total_bytes.value % start->streams;
        return per_stream + (stream_index < remainder ? 1 : 0);
    }
    if (start->mode == MODE_CODE_BULK && start->direction == DIRECTION_CODE_DOWNLOAD) {
        return start->response_bytes;
    }
    if (start->mode == MODE_CODE_RR || start->mode == MODE_CODE_CRR ||
        start->mode == MODE_CODE_PERSISTENT_RR) {
        return start->response_bytes;
    }
    return 0;
}

static int should_send_complete(const app_ctx_t *app) {
    const perf_session_start_t *start = &app->session_start;
    if (!start->started || app->server_complete_sent) {
        return 0;
    }
    return (start->mode == MODE_CODE_BULK && start->total_bytes.set &&
            app->server_requests_completed >= start->streams) ||
           (start->mode == MODE_CODE_BULK && start->total_bytes.set &&
            start->direction == DIRECTION_CODE_UPLOAD &&
            app->server_requests_completed >= start->streams) ||
           ((start->mode == MODE_CODE_RR || start->mode == MODE_CODE_PERSISTENT_RR) &&
            start->requests.set && app->server_requests_completed >= start->requests.value);
}

static int receive_server_stream(app_ctx_t *app, picoquic_cnx_t *cnx, uint64_t stream_id,
                                 uint8_t *bytes, size_t length, int fin, stream_ctx_t *stream) {
    if (stream == NULL) {
        stream = alloc_stream(app, stream_id, 1);
        if (stream == NULL) {
            return -1;
        }
        stream->cnx = cnx;
        picoquic_set_app_stream_ctx(cnx, stream_id, stream);
    }
    if (stream_id == CONTROL_STREAM_ID) {
        if (length != 0) {
            if (stream->control_in_len + length > stream->control_in_cap) {
                size_t new_cap = stream->control_in_cap ? stream->control_in_cap * 2 : 128;
                while (new_cap < stream->control_in_len + length) {
                    new_cap *= 2;
                }
                uint8_t *new_bytes = (uint8_t *)realloc(stream->control_in, new_cap);
                if (new_bytes == NULL) {
                    set_error(app, "out of memory reading control stream");
                    return -1;
                }
                stream->control_in = new_bytes;
                stream->control_in_cap = new_cap;
            }
            memcpy(stream->control_in + stream->control_in_len, bytes, length);
            stream->control_in_len += length;
        }
        if (fin) {
            stream->request_fin = 1;
            size_t msg_len = 0;
            if (stream->control_in_len < 5 || stream->control_in[0] != MESSAGE_SESSION_START ||
                stream->control_in_len != (size_t)decode_be32(stream->control_in + 1) + 5 ||
                decode_session_start_payload(stream->control_in + 5, stream->control_in_len - 5,
                                             &app->session_start) != 0) {
                stream->control_out =
                    encode_session_error_message("invalid session_start", &msg_len);
                stream->control_fin = 1;
            } else {
                stream->control_out = encode_session_ready_message(&msg_len);
            }
            stream->control_len = msg_len;
            if (stream->control_out == NULL ||
                picoquic_add_to_stream_with_ctx(cnx, stream_id, stream->control_out,
                                                stream->control_len, stream->control_fin,
                                                stream) != 0) {
                set_error(app, "server failed to write control response");
                return -1;
            }
        }
        return 0;
    }
    if (!app->session_start.started) {
        return 0;
    }
    stream->request_bytes = app->session_start.request_bytes;
    stream->persistent_rr = app->session_start.mode == MODE_CODE_PERSISTENT_RR;
    stream->request_received += length;
    app->server_bytes_received += length;
    if (stream->persistent_rr) {
        while (stream->request_received >= stream->request_bytes) {
            stream->request_received -= stream->request_bytes;
            app->server_requests_completed++;
            stream->response_bytes += app->session_start.response_bytes;
            if (picoquic_mark_active_stream(cnx, stream_id, 1, stream) != 0) {
                set_error(app, "server failed to mark response stream active");
                return -1;
            }
        }
        if (fin) {
            if (stream->request_received != 0) {
                set_error(app, "picoquic-perf request byte count mismatch");
                return -1;
            }
            stream->request_fin = 1;
            if (picoquic_mark_active_stream(cnx, stream_id, 1, stream) != 0) {
                set_error(app, "server failed to mark response stream active");
                return -1;
            }
        }
    } else if (fin) {
        if (stream->request_received != stream->request_bytes) {
            set_error(app, "picoquic-perf request byte count mismatch");
            return -1;
        }
        app->server_requests_completed++;
        stream->response_bytes = server_response_bytes(app, app->server_requests_completed);
        stream->request_fin = 1;
        if (picoquic_mark_active_stream(cnx, stream_id, 1, stream) != 0) {
            set_error(app, "server failed to mark response stream active");
            return -1;
        }
    }
    return 0;
}

static int complete_client_stream(app_ctx_t *app, picoquic_cnx_t *cnx, stream_ctx_t *stream) {
    if (stream->response_received != stream->response_bytes) {
        char message[256];
        snprintf(message, sizeof(message),
                 "stream %" PRIu64 " received %" PRIu64 " bytes, expected %" PRIu64,
                 stream->stream_id, stream->response_received, stream->response_bytes);
        set_error(app, message);
        return -1;
    }
    if (stream->counts && picoquic_current_time() >= app->measure_start) {
        app->counters.bytes_sent += stream->request_bytes;
        app->counters.bytes_received += stream->response_received;
        if (!is_mode(&app->cfg, "bulk")) {
            app->counters.requests_completed++;
            if (latency_push(&app->counters.latencies,
                             picoquic_current_time() - stream->started_at) != 0) {
                set_error(app, "out of memory recording latency");
                return -1;
            }
        }
    }
    if (app->active_streams > 0) {
        app->active_streams--;
    }
    picoquic_unlink_app_stream_ctx(cnx, stream->stream_id);
    remove_stream(app, stream);
    maybe_finish_client(app);
    return 0;
}

static int complete_persistent_client_responses(app_ctx_t *app, stream_ctx_t *stream) {
    while (stream->response_pending >= app->cfg.response_bytes) {
        uint64_t started_at = 0;
        int counts = 0;
        if (persistent_queue_pop(stream, &started_at, &counts) != 0) {
            set_error(app, "persistent-rr response without pending request");
            return -1;
        }
        stream->response_pending -= app->cfg.response_bytes;
        if (counts && picoquic_current_time() >= app->measure_start) {
            app->counters.bytes_sent += app->cfg.request_bytes;
            app->counters.bytes_received += app->cfg.response_bytes;
            app->counters.requests_completed++;
            if (latency_push(&app->counters.latencies, picoquic_current_time() - started_at) != 0) {
                set_error(app, "out of memory recording latency");
                return -1;
            }
        }
        if (app->active_streams > 0) {
            app->active_streams--;
        }
    }
    maybe_finish_client(app);
    return 0;
}

static int handle_client_control(app_ctx_t *app, picoquic_cnx_t *cnx, stream_ctx_t *stream,
                                 uint8_t *bytes, size_t length, int fin) {
    if (length != 0) {
        if (stream->control_in_len + length > stream->control_in_cap) {
            size_t new_cap = stream->control_in_cap ? stream->control_in_cap * 2 : 128;
            while (new_cap < stream->control_in_len + length) {
                new_cap *= 2;
            }
            uint8_t *new_bytes = (uint8_t *)realloc(stream->control_in, new_cap);
            if (new_bytes == NULL) {
                set_error(app, "out of memory reading client control");
                return -1;
            }
            stream->control_in = new_bytes;
            stream->control_in_cap = new_cap;
        }
        memcpy(stream->control_in + stream->control_in_len, bytes, length);
        stream->control_in_len += length;
    }
    if (stream->control_in_len >= 5) {
        uint32_t payload_len = decode_be32(stream->control_in + 1);
        if (stream->control_in_len >= (size_t)payload_len + 5) {
            if (stream->control_in[0] == MESSAGE_SESSION_READY && payload_len == 4 &&
                decode_be32(stream->control_in + 5) == PERF_PROTOCOL_VERSION) {
                if (mark_connection_ready(app, cnx) != 0) {
                    set_error(app, "session_ready for unknown picoquic connection");
                    return -1;
                }
                if (app->ready_connections == app->connection_count && !app->initial_opened) {
                    if (app->measure_start == 0) {
                        app->measure_start = picoquic_current_time() + app->cfg.warmup_us;
                        app->measure_deadline = app->measure_start + app->cfg.duration_us;
                    }
                    app->initial_opened = 1;
                    if (is_mode(&app->cfg, "bulk")) {
                        return open_bulk_streams(app);
                    }
                    if (is_mode(&app->cfg, "rr") || is_mode(&app->cfg, "persistent-rr")) {
                        return open_rr_streams(app);
                    }
                }
            } else if (stream->control_in[0] == MESSAGE_SESSION_ERROR) {
                set_error(app, "server returned session_error");
                return -1;
            } else if (stream->control_in[0] == MESSAGE_SESSION_COMPLETE) {
                return 0;
            } else {
                set_error(app, "unexpected picoquic control message");
                return -1;
            }
        }
    }
    (void)fin;
    return 0;
}

static int app_callback(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes, size_t length,
                        picoquic_call_back_event_t event, void *callback_ctx, void *v_stream_ctx) {
    app_ctx_t *app = (app_ctx_t *)callback_ctx;
    stream_ctx_t *stream = (stream_ctx_t *)v_stream_ctx;
    /* Drive connection setup, per-stream accounting, and control/data stream IO from one callback.
     */
    if (app == NULL) {
        return -1;
    }
    if (app->cnx == NULL) {
        app->cnx = cnx;
    }
    if (event == picoquic_callback_almost_ready || event == picoquic_callback_ready) {
        if (app->is_client && !app->initial_opened) {
            int known = 0;
            for (uint64_t i = 0; i < app->connection_count; ++i) {
                if (app->connections[i] == cnx) {
                    known = 1;
                    if (!app->connection_control_opened[i]) {
                        app->connection_control_opened[i] = 1;
                        if (open_control_stream(app, cnx) != 0) {
                            return -1;
                        }
                    }
                    break;
                }
            }
            if (!known) {
                set_error(app, "ready callback for unknown picoquic connection");
                return -1;
            }
        }
        return 0;
    }

    if (event == picoquic_callback_stream_data || event == picoquic_callback_stream_fin) {
        /* Client streams count responses; server streams accumulate requests before scheduling
         * replies. */
        if (app->is_client) {
            if (stream == NULL) {
                set_error(app, "client received stream data without context");
                return -1;
            }
            if (stream_id == CONTROL_STREAM_ID) {
                return handle_client_control(app, cnx, stream, bytes, length,
                                             event == picoquic_callback_stream_fin);
            }
            stream->response_received += length;
            if (stream->persistent_rr) {
                stream->response_pending += length;
                if (complete_persistent_client_responses(app, stream) != 0) {
                    return -1;
                }
                if (event == picoquic_callback_stream_fin) {
                    if (stream->response_pending != 0 || stream->persistent_len != 0) {
                        set_error(app, "persistent-rr stream closed with pending responses");
                        return -1;
                    }
                    picoquic_unlink_app_stream_ctx(cnx, stream->stream_id);
                    remove_stream(app, stream);
                }
                return 0;
            }
            if (event == picoquic_callback_stream_fin) {
                return complete_client_stream(app, cnx, stream);
            }
        } else {
            return receive_server_stream(app, cnx, stream_id, bytes, length,
                                         event == picoquic_callback_stream_fin, stream);
        }
        return 0;
    }

    if (event == picoquic_callback_prepare_to_send) {
        /* prepare_to_send is the only callback path that writes application payload bytes. */
        if (stream == NULL) {
            set_error(app, "prepare_to_send without stream context");
            return -1;
        }
        if (stream->is_server) {
            if (stream->stream_id != CONTROL_STREAM_ID && !stream->request_fin &&
                (!stream->persistent_rr || stream->response_sent >= stream->response_bytes)) {
                (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
                return 0;
            }
            if (provide_server_data(stream, bytes, length) != 0) {
                set_error(app, "server failed to provide stream data");
                return -1;
            }
            if (stream->response_fin) {
                if (stream->stream_id != CONTROL_STREAM_ID) {
                    app->server_bytes_sent += stream->response_bytes;
                    if (should_send_complete(app)) {
                        stream_ctx_t *control = alloc_stream(app, CONTROL_STREAM_ID, 1);
                        if (control == NULL) {
                            return -1;
                        }
                        control->cnx = cnx;
                        control->control_out = encode_session_complete_message(
                            app->server_bytes_sent, app->server_bytes_received,
                            app->server_requests_completed, &control->control_len);
                        control->control_fin = 1;
                        app->server_complete_sent = 1;
                        if (control->control_out == NULL ||
                            picoquic_add_to_stream_with_ctx(
                                cnx, CONTROL_STREAM_ID, control->control_out, control->control_len,
                                1, control) != 0) {
                            set_error(app, "server failed to send session_complete");
                            return -1;
                        }
                    }
                }
                picoquic_unlink_app_stream_ctx(cnx, stream_id);
                remove_stream(app, stream);
            }
        } else {
            if (provide_client_data(stream, bytes, length) != 0) {
                set_error(app, "client failed to provide stream data");
                return -1;
            }
        }
        return 0;
    }

    if (event == picoquic_callback_stream_reset || event == picoquic_callback_stop_sending) {
        if (stream != NULL) {
            if (app->is_client && app->active_streams > 0) {
                app->active_streams--;
            }
            remove_stream(app, stream);
        }
        set_error(app, "stream reset or stop_sending received");
        return -1;
    }

    if (event == picoquic_callback_close || event == picoquic_callback_application_close ||
        event == picoquic_callback_stateless_reset) {
        app->finished = 1;
        return 0;
    }

    return 0;
}

static int loop_callback(picoquic_quic_t *quic, picoquic_packet_loop_cb_enum mode,
                         void *callback_ctx, void *callback_arg) {
    app_ctx_t *app = (app_ctx_t *)callback_ctx;
    if (app == NULL) {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    if (stop_requested) {
        return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
    }
    if (mode == picoquic_packet_loop_ready) {
        picoquic_packet_loop_options_t *options = (picoquic_packet_loop_options_t *)callback_arg;
        options->do_time_check = 1;
        return 0;
    }
    if (mode == picoquic_packet_loop_after_receive || mode == picoquic_packet_loop_after_send) {
        if (app->is_client) {
            maybe_finish_client(app);
            if (app->finished) {
                return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
        }
        return 0;
    }
    if (mode == picoquic_packet_loop_time_check) {
        packet_loop_time_check_arg_t *time_check = (packet_loop_time_check_arg_t *)callback_arg;
        if (app->is_client) {
            maybe_finish_client(app);
            if (app->finished) {
                return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            if (app->measure_deadline != 0 &&
                time_check->current_time > app->measure_deadline + DRAIN_TIMEOUT_US) {
                return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            if (time_check->delta_t > 1000) {
                time_check->delta_t = 1000;
            }
        } else {
            if (time_check->delta_t > 1000000) {
                time_check->delta_t = 1000000;
            }
        }
        return 0;
    }
    if (mode == picoquic_packet_loop_port_update || mode == picoquic_packet_loop_wake_up ||
        mode == picoquic_packet_loop_alt_port ||
        mode == picoquic_packet_loop_system_call_duration) {
        return 0;
    }
    return PICOQUIC_ERROR_UNEXPECTED_ERROR;
}

static int run_server(const config_t *cfg) {
    app_ctx_t app;
    memset(&app, 0, sizeof(app));
    app.cfg = *cfg;
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    picoquic_register_all_congestion_control_algorithms();
    picoquic_quic_t *quic = create_quic_context(cfg, 1, &app);
    if (quic == NULL) {
        fprintf(stderr, "could not create picoquic server context\n");
        return 1;
    }
    picoquic_set_default_callback(quic, app_callback, &app);
    picoquic_packet_loop_param_t param;
    memset(&param, 0, sizeof(param));
    param.local_port = cfg->port;
    param.socket_buffer_size = 0;
    param.do_not_use_gso = 0;
    int ret = picoquic_packet_loop_v2(quic, &param, loop_callback, &app);
    picoquic_free(quic);
    free_streams(&app);
    if (ret != 0) {
        fprintf(stderr, "picoquic server packet loop failed: %d\n", ret);
        return 1;
    }
    return 0;
}

static int connect_one_client(app_ctx_t *app, picoquic_quic_t *quic, uint64_t index) {
    struct sockaddr_storage server_address;
    int is_name = 0;
    if (picoquic_get_server_address(app->cfg.host, app->cfg.port, &server_address, &is_name) != 0) {
        set_error(app, "unable to resolve server address");
        return -1;
    }
    const char *sni = is_name ? app->cfg.host : app->cfg.server_name;
    app->connections[index] =
        picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
                            (struct sockaddr *)&server_address, picoquic_current_time(), 0, sni,
                            APPLICATION_PROTOCOL, 1);
    if (app->connections[index] == NULL) {
        set_error(app, "could not create picoquic client connection");
        return -1;
    }
    picoquic_set_callback(app->connections[index], app_callback, app);
    if (picoquic_start_client_cnx(app->connections[index]) != 0) {
        set_error(app, "could not start picoquic client connection");
        return -1;
    }
    return 0;
}

static int connect_clients(app_ctx_t *app, picoquic_quic_t *quic) {
    app->connection_count = rr_connection_target(&app->cfg);
    app->connections =
        (picoquic_cnx_t **)calloc((size_t)app->connection_count, sizeof(picoquic_cnx_t *));
    app->connection_ready = (uint8_t *)calloc((size_t)app->connection_count, sizeof(uint8_t));
    app->connection_control_opened =
        (uint8_t *)calloc((size_t)app->connection_count, sizeof(uint8_t));
    app->connection_request_limit =
        (uint64_t *)calloc((size_t)app->connection_count, sizeof(uint64_t));
    app->connection_requests_started =
        (uint64_t *)calloc((size_t)app->connection_count, sizeof(uint64_t));
    if (app->connections == NULL || app->connection_ready == NULL ||
        app->connection_control_opened == NULL || app->connection_request_limit == NULL ||
        app->connection_requests_started == NULL) {
        set_error(app, "out of memory allocating connection table");
        return -1;
    }
    if (app->connection_count == 0) {
        set_error(app, "no picoquic connections requested");
        return -1;
    }
    for (uint64_t i = 0; i < app->connection_count; ++i) {
        app->connection_request_limit[i] = rr_request_limit_for_connection(&app->cfg, i);
        if (connect_one_client(app, quic, i) != 0) {
            return -1;
        }
    }
    app->cnx = app->connections[0];
    return 0;
}

static void close_client_connections(app_ctx_t *app) {
    for (stream_ctx_t *stream = app->streams; stream != NULL; stream = stream->next) {
        if (!stream->is_server && stream->persistent_rr && !stream->request_fin &&
            stream->cnx != NULL) {
            stream->request_fin = 1;
            (void)picoquic_mark_active_stream(stream->cnx, stream->stream_id, 1, stream);
        }
    }
    for (uint64_t i = 0; i < app->connection_count; ++i) {
        picoquic_cnx_t *cnx = app->connections == NULL ? NULL : app->connections[i];
        if (cnx != NULL && picoquic_get_cnx_state(cnx) < picoquic_state_disconnecting) {
            (void)picoquic_close(cnx, 0);
        }
    }
}

static int run_client_session(app_ctx_t *app) {
    picoquic_register_all_congestion_control_algorithms();
    picoquic_quic_t *quic = create_quic_context(&app->cfg, 0, app);
    if (quic == NULL) {
        set_error(app, "could not create picoquic client context");
        return -1;
    }
    if (connect_clients(app, quic) != 0) {
        picoquic_free(quic);
        return -1;
    }
    picoquic_packet_loop_param_t param;
    memset(&param, 0, sizeof(param));
    param.local_port = 0;
    param.socket_buffer_size = 0;
    param.do_not_use_gso = 0;
    int ret = picoquic_packet_loop_v2(quic, &param, loop_callback, app);
    if (ret != 0) {
        char message[256];
        snprintf(message, sizeof(message), "picoquic client packet loop failed: %d", ret);
        set_error(app, message);
    }
    close_client_connections(app);
    picoquic_free(quic);
    free_streams(app);
    free(app->connections);
    free(app->connection_ready);
    free(app->connection_control_opened);
    free(app->connection_request_limit);
    free(app->connection_requests_started);
    app->connections = NULL;
    app->connection_ready = NULL;
    app->connection_control_opened = NULL;
    app->connection_request_limit = NULL;
    app->connection_requests_started = NULL;
    return app->failed ? -1 : 0;
}

static int merge_counters(counters_t *dst, const counters_t *src) {
    dst->bytes_sent += src->bytes_sent;
    dst->bytes_received += src->bytes_received;
    dst->requests_completed += src->requests_completed;
    dst->skipped_setup_errors += src->skipped_setup_errors;
    for (size_t i = 0; i < src->latencies.len; ++i) {
        if (latency_push(&dst->latencies, src->latencies.values[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int next_crr_task(crr_worker_state_t *state, int *counts) {
    int should_start = 0;
    pthread_mutex_lock(&state->mutex);
    if (!state->failed) {
        uint64_t now = picoquic_current_time();
        if (state->cfg.requests.set) {
            if (state->started < state->cfg.requests.value) {
                state->started++;
                *counts = 1;
                should_start = 1;
            }
        } else if (now < state->measure_deadline) {
            state->started++;
            *counts = now >= state->measure_start;
            should_start = 1;
        }
    }
    pthread_mutex_unlock(&state->mutex);
    return should_start;
}

static void *crr_worker_main(void *arg) {
    crr_worker_state_t *state = (crr_worker_state_t *)arg;
    int counts = 0;
    while (next_crr_task(state, &counts)) {
        app_ctx_t app;
        memset(&app, 0, sizeof(app));
        app.cfg = state->cfg;
        app.cfg.mode = "rr";
        app.cfg.requests.set = 1;
        app.cfg.requests.value = 1;
        app.cfg.requests_in_flight = 1;
        app.cfg.connections = 1;
        app.cfg.warmup_us = 0;
        app.is_client = 1;
        app.measure_start = counts ? 0 : state->measure_start;
        app.measure_deadline = state->measure_deadline;

        int ret = run_client_session(&app);

        pthread_mutex_lock(&state->mutex);
        if (ret != 0 || app.failed) {
            if (state->cfg.requests.set && !state->failed) {
                state->failed = 1;
                snprintf(state->failure_reason, sizeof(state->failure_reason), "%s",
                         app.error[0] == 0 ? "picoquic CRR client failed" : app.error);
            } else if (!state->cfg.requests.set) {
                state->counters.skipped_setup_errors++;
            }
        } else if (merge_counters(&state->counters, &app.counters) != 0 && !state->failed) {
            state->failed = 1;
            snprintf(state->failure_reason, sizeof(state->failure_reason),
                     "out of memory recording CRR latency");
        }
        pthread_mutex_unlock(&state->mutex);
        free(app.counters.latencies.values);
    }
    return NULL;
}

static int run_crr(const config_t *cfg, counters_t *counters) {
    crr_worker_state_t state;
    memset(&state, 0, sizeof(state));
    state.cfg = *cfg;
    state.measure_start = picoquic_current_time() + cfg->warmup_us;
    state.measure_deadline = state.measure_start + cfg->duration_us;
    if (pthread_mutex_init(&state.mutex, NULL) != 0) {
        return -1;
    }

    uint64_t worker_count =
        cfg->connections < CRR_WORKER_LIMIT ? cfg->connections : CRR_WORKER_LIMIT;
    pthread_t *threads = (pthread_t *)calloc((size_t)worker_count, sizeof(*threads));
    if (threads == NULL) {
        pthread_mutex_destroy(&state.mutex);
        return -1;
    }

    uint64_t created = 0;
    for (; created < worker_count; ++created) {
        if (pthread_create(&threads[created], NULL, crr_worker_main, &state) != 0) {
            pthread_mutex_lock(&state.mutex);
            state.failed = 1;
            snprintf(state.failure_reason, sizeof(state.failure_reason),
                     "picoquic CRR worker creation failed");
            pthread_mutex_unlock(&state.mutex);
            break;
        }
    }

    for (uint64_t i = 0; i < created; ++i) {
        pthread_join(threads[i], NULL);
    }
    free(threads);

    int failed = state.failed;
    if (failed) {
        fprintf(stderr, "%s\n",
                state.failure_reason[0] == 0 ? "picoquic CRR failed" : state.failure_reason);
        free(state.counters.latencies.values);
    } else {
        *counters = state.counters;
    }
    pthread_mutex_destroy(&state.mutex);
    return failed ? -1 : 0;
}

static run_summary_t new_summary(const config_t *cfg) {
    run_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    summary.status = "ok";
    summary.mode = cfg->mode;
    summary.direction = strcmp(cfg->direction, "stay") == 0 ? "download" : cfg->direction;
    summary.backend = cfg->io_backend;
    summary.congestion_control = cfg->congestion_control;
    summary.remote_host = cfg->host;
    summary.remote_port = cfg->port;
    summary.alpn = APPLICATION_PROTOCOL;
    summary.warmup_ms = (int64_t)duration_millis(cfg->warmup_us);
    summary.streams = cfg->streams;
    summary.connections = cfg->connections;
    summary.requests_in_flight = cfg->requests_in_flight;
    summary.request_bytes = cfg->request_bytes;
    summary.response_bytes = cfg->response_bytes;
    return summary;
}

static void finalize_summary(run_summary_t *summary) {
    if (summary->elapsed_ms == 0) {
        summary->elapsed_ms = summary->warmup_ms;
    }
    double seconds = (double)summary->elapsed_ms / 1000.0;
    if (seconds < 0.001) {
        seconds = 0.001;
    }
    uint64_t total_bytes = summary->bytes_sent + summary->bytes_received;
    summary->throughput_mib_per_s = (double)total_bytes / (1024.0 * 1024.0) / seconds;
    summary->throughput_gbit_per_s = ((double)total_bytes * 8.0) / 1000000000.0 / seconds;
    summary->requests_per_s = (double)summary->requests_completed / seconds;
}

static int emit_summary(const run_summary_t *summary, const char *json_out) {
    printf("status=%s mode=%s cc=%s direction=%s throughput_mib/s=%.3f throughput_gbit/s=%.3f "
           "requests/s=%.3f\n",
           summary->status, summary->mode, summary->congestion_control, summary->direction,
           summary->throughput_mib_per_s, summary->throughput_gbit_per_s, summary->requests_per_s);
    if (json_out == NULL) {
        return 0;
    }
    FILE *f = open_json_output(json_out);
    if (f == NULL) {
        fprintf(stderr, "failed to open JSON output %s\n", json_out);
        return -1;
    }
    fprintf(f,
            "{\n"
            "  \"schema_version\": 1,\n"
            "  \"status\": \"%s\",\n"
            "  \"mode\": \"%s\",\n"
            "  \"direction\": \"%s\",\n"
            "  \"backend\": \"%s\",\n"
            "  \"congestion_control\": \"%s\",\n"
            "  \"remote_host\": \"%s\",\n"
            "  \"remote_port\": %u,\n"
            "  \"alpn\": \"%s\",\n"
            "  \"elapsed_ms\": %" PRId64 ",\n"
            "  \"warmup_ms\": %" PRId64 ",\n"
            "  \"bytes_sent\": %" PRIu64 ",\n"
            "  \"bytes_received\": %" PRIu64 ",\n"
            "  \"server_counters\": {\"bytes_sent\": %" PRIu64 ", \"bytes_received\": %" PRIu64
            ", \"requests_completed\": %" PRIu64 "},\n"
            "  \"requests_completed\": %" PRIu64 ",\n"
            "  \"streams\": %" PRIu64 ",\n"
            "  \"connections\": %" PRIu64 ",\n"
            "  \"requests_in_flight\": %" PRIu64 ",\n"
            "  \"request_bytes\": %" PRIu64 ",\n"
            "  \"response_bytes\": %" PRIu64 ",\n"
            "  \"throughput_mib_per_s\": %.6f,\n"
            "  \"throughput_gbit_per_s\": %.6f,\n"
            "  \"requests_per_s\": %.6f,\n"
            "  \"latency\": {\"min_us\": %" PRIu64 ", \"avg_us\": %" PRIu64 ", \"p50_us\": %" PRIu64
            ", \"p90_us\": %" PRIu64 ", \"p99_us\": %" PRIu64 ", \"max_us\": %" PRIu64 "}",
            summary->status, summary->mode, summary->direction, summary->backend,
            summary->congestion_control, summary->remote_host, summary->remote_port, summary->alpn,
            summary->elapsed_ms, summary->warmup_ms, summary->bytes_sent, summary->bytes_received,
            summary->server_bytes_sent, summary->server_bytes_received,
            summary->server_requests_completed, summary->requests_completed, summary->streams,
            summary->connections, summary->requests_in_flight, summary->request_bytes,
            summary->response_bytes, summary->throughput_mib_per_s, summary->throughput_gbit_per_s,
            summary->requests_per_s, summary->latency.min_us, summary->latency.avg_us,
            summary->latency.p50_us, summary->latency.p90_us, summary->latency.p99_us,
            summary->latency.max_us);
    if (summary->failure_reason != NULL && summary->failure_reason[0] != 0) {
        fprintf(f, ",\n  \"failure_reason\": \"%s\"", summary->failure_reason);
    }
    if (summary->skipped_setup_errors != 0) {
        fprintf(f, ",\n  \"skipped_setup_errors\": %" PRIu64, summary->skipped_setup_errors);
    }
    fprintf(f, "\n}\n");
    fclose(f);
    return 0;
}

static int run_client(const config_t *cfg) {
    run_summary_t summary = new_summary(cfg);
    uint64_t start = picoquic_current_time();
    app_ctx_t app;
    memset(&app, 0, sizeof(app));
    app.cfg = *cfg;
    app.is_client = 1;
    int ret = 0;

    if (is_mode(cfg, "crr")) {
        ret = run_crr(cfg, &app.counters);
        summary.elapsed_ms = cfg->requests.set
                                 ? (int64_t)duration_millis(picoquic_current_time() - start)
                                 : (int64_t)duration_millis(cfg->duration_us);
    } else {
        ret = run_client_session(&app);
        if (cfg->total_bytes.set || cfg->requests.set) {
            summary.elapsed_ms = (int64_t)duration_millis(picoquic_current_time() - start);
        } else {
            summary.elapsed_ms = (int64_t)duration_millis(cfg->duration_us);
        }
    }

    if (ret != 0 || app.failed) {
        summary.status = "failed";
        summary.failure_reason = app.error[0] == 0 ? "picoquic client failed" : app.error;
        if (summary.elapsed_ms == 0) {
            summary.elapsed_ms = (int64_t)duration_millis(picoquic_current_time() - start);
        }
    }
    summary.bytes_sent = app.counters.bytes_sent;
    summary.bytes_received = app.counters.bytes_received;
    summary.requests_completed = app.counters.requests_completed;
    summary.server_bytes_sent = app.counters.bytes_received;
    summary.server_bytes_received = app.counters.bytes_sent;
    summary.server_requests_completed = app.counters.requests_completed;
    summary.skipped_setup_errors = app.counters.skipped_setup_errors;
    summary.latency = summarize_latency(&app.counters.latencies);
    finalize_summary(&summary);
    int emit_ret = emit_summary(&summary, cfg->json_out);
    free(app.counters.latencies.values);
    return emit_ret != 0 || strcmp(summary.status, "ok") != 0 ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "client") != 0 && strcmp(argv[1], "server") != 0)) {
        fprintf(stderr, "usage: picoquic-perf [client|server] [options]\n");
        return 2;
    }
    config_t cfg = parse_args(argc - 2, argv + 2);
    if (strcmp(argv[1], "server") == 0) {
        return run_server(&cfg);
    }
    return run_client(&cfg);
}
