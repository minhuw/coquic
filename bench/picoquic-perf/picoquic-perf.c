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
#define TRANSFER_CONNECTION_WINDOW (32ULL * 1024ULL * 1024ULL)
#define TRANSFER_STREAM_WINDOW (16ULL * 1024ULL * 1024ULL)
#define WRITE_CHUNK_SIZE 32768U
#define READ_CHUNK_SIZE 65536U
#define DEFAULT_PORT 4433
#define DRAIN_TIMEOUT_US 2000000ULL
#define SERVER_SHUTDOWN_DELAY_US 500000ULL
#define HANDSHAKE_TIMEOUT_US 10000000ULL

typedef struct optional_u64_t {
    uint64_t value;
    int set;
} optional_u64_t;

static FILE *open_json_output(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
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
    uint64_t stream_id;
    int is_server;
    int counts;
    int request_fin;
    int response_fin;
    int closed;
    uint8_t header[16];
    size_t header_len;
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t request_received;
    uint64_t request_sent;
    uint64_t response_received;
    uint64_t response_sent;
    uint64_t started_at;
} stream_ctx_t;

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
    uint64_t connection_count;
    uint64_t ready_connections;
    uint64_t next_connection;
    stream_ctx_t *streams;
    uint64_t active_streams;
    uint64_t started_requests;
    uint64_t next_stream_rr;
    uint64_t measure_start;
    uint64_t measure_deadline;
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
    if (!is_mode(&cfg, "bulk") && !is_mode(&cfg, "rr") && !is_mode(&cfg, "crr")) {
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
            free(stream);
            return;
        }
        pp = &(*pp)->next;
    }
}

static void free_streams(app_ctx_t *app) {
    while (app->streams != NULL) {
        stream_ctx_t *next = app->streams->next;
        free(app->streams);
        app->streams = next;
    }
}

static void store_header(stream_ctx_t *s) {
    for (int i = 0; i < 8; ++i) {
        s->header[i] = (uint8_t)(s->request_bytes >> (56 - i * 8));
        s->header[8 + i] = (uint8_t)(s->response_bytes >> (56 - i * 8));
    }
    s->header_len = 16;
}

static uint64_t load_be64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | bytes[i];
    }
    return value;
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
    stream->request_bytes = request_bytes;
    stream->response_bytes = response_bytes;
    stream->started_at = picoquic_current_time();
    store_header(stream);
    if (picoquic_mark_active_stream(cnx, stream_id, 1, stream) != 0) {
        remove_stream(app, stream);
        set_error(app, "picoquic_mark_active_stream failed");
        return -1;
    }
    app->active_streams++;
    app->started_requests++;
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
    uint64_t target_active = app->cfg.streams * app->connection_count;
    while (app->active_streams < target_active) {
        uint64_t now = picoquic_current_time();
        if (now >= app->measure_deadline) {
            break;
        }
        if (open_request_stream(app, 0, app->cfg.response_bytes, now >= app->measure_start) != 0) {
            return -1;
        }
    }
    return 0;
}

static int open_rr_streams(app_ctx_t *app) {
    uint64_t target_active = app->cfg.requests_in_flight * app->connection_count;
    while (app->active_streams < target_active) {
        uint64_t now = picoquic_current_time();
        if (app->cfg.requests.set && app->started_requests >= app->cfg.requests.value) {
            break;
        }
        if (!app->cfg.requests.set && now >= app->measure_deadline) {
            break;
        }
        int counts = now >= app->measure_start;
        if (open_request_stream(app, app->cfg.request_bytes, app->cfg.response_bytes, counts) !=
            0) {
            return -1;
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
    if (is_mode(&app->cfg, "rr")) {
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
    uint64_t total = 16ULL + stream->request_bytes;
    uint64_t sent = stream->request_sent;
    uint64_t remaining = total > sent ? total - sent : 0;
    size_t to_send = remaining < (uint64_t)length ? (size_t)remaining : length;
    int is_fin = (uint64_t)to_send == remaining;
    uint8_t *buffer = picoquic_provide_stream_data_buffer(context, to_send, is_fin, !is_fin);
    if (buffer == NULL && to_send > 0) {
        return -1;
    }
    size_t offset = 0;
    while (offset < to_send) {
        uint64_t absolute = sent + offset;
        if (absolute < 16ULL) {
            size_t header_offset = (size_t)absolute;
            size_t take = 16U - header_offset;
            if (take > to_send - offset) {
                take = to_send - offset;
            }
            memcpy(buffer + offset, stream->header + header_offset, take);
            offset += take;
        } else {
            size_t take = to_send - offset;
            memset(buffer + offset, 0x5a, take);
            offset += take;
        }
    }
    stream->request_sent += to_send;
    return 0;
}

static int provide_server_data(stream_ctx_t *stream, uint8_t *context, size_t length) {
    uint64_t remaining = stream->response_bytes > stream->response_sent
                             ? stream->response_bytes - stream->response_sent
                             : 0;
    size_t to_send = remaining < (uint64_t)length ? (size_t)remaining : length;
    int is_fin = (uint64_t)to_send == remaining;
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
    }
    return 0;
}

static int receive_server_stream(app_ctx_t *app, picoquic_cnx_t *cnx, uint64_t stream_id,
                                 uint8_t *bytes, size_t length, int fin, stream_ctx_t *stream) {
    if (stream == NULL) {
        stream = alloc_stream(app, stream_id, 1);
        if (stream == NULL) {
            return -1;
        }
        picoquic_set_app_stream_ctx(cnx, stream_id, stream);
    }
    size_t offset = 0;
    if (stream->header_len < sizeof(stream->header)) {
        size_t take = sizeof(stream->header) - stream->header_len;
        if (take > length) {
            take = length;
        }
        memcpy(stream->header + stream->header_len, bytes, take);
        stream->header_len += take;
        offset += take;
        if (stream->header_len == sizeof(stream->header)) {
            stream->request_bytes = load_be64(stream->header);
            stream->response_bytes = load_be64(stream->header + 8);
        }
    }
    stream->request_received += length - offset;
    if (fin) {
        if (stream->header_len != sizeof(stream->header)) {
            set_error(app, "picoquic-perf malformed stream request header");
            return -1;
        }
        if (stream->request_received != stream->request_bytes) {
            set_error(app, "picoquic-perf request byte count mismatch");
            return -1;
        }
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

static int app_callback(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes, size_t length,
                        picoquic_call_back_event_t event, void *callback_ctx, void *v_stream_ctx) {
    app_ctx_t *app = (app_ctx_t *)callback_ctx;
    stream_ctx_t *stream = (stream_ctx_t *)v_stream_ctx;
    if (app == NULL) {
        return -1;
    }
    if (app->cnx == NULL) {
        app->cnx = cnx;
    }
    switch (event) {
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        if (app->is_client && !app->initial_opened) {
            if (mark_connection_ready(app, cnx) != 0) {
                set_error(app, "ready callback for unknown picoquic connection");
                return -1;
            }
            if (app->ready_connections < app->connection_count) {
                break;
            }
            if (app->measure_start == 0) {
                app->measure_start = picoquic_current_time() + app->cfg.warmup_us;
                app->measure_deadline = app->measure_start + app->cfg.duration_us;
            }
            app->initial_opened = 1;
            if (is_mode(&app->cfg, "bulk")) {
                if (open_bulk_streams(app) != 0) {
                    return -1;
                }
            } else if (is_mode(&app->cfg, "rr")) {
                if (open_rr_streams(app) != 0) {
                    return -1;
                }
            }
        }
        return 0;
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (app->is_client) {
            if (stream == NULL) {
                set_error(app, "client received stream data without context");
                return -1;
            }
            stream->response_received += length;
            if (event == picoquic_callback_stream_fin) {
                return complete_client_stream(app, cnx, stream);
            }
        } else {
            return receive_server_stream(app, cnx, stream_id, bytes, length,
                                         event == picoquic_callback_stream_fin, stream);
        }
        return 0;
    case picoquic_callback_prepare_to_send:
        if (stream == NULL) {
            set_error(app, "prepare_to_send without stream context");
            return -1;
        }
        if (stream->is_server) {
            if (!stream->request_fin) {
                return 0;
            }
            if (provide_server_data(stream, bytes, length) != 0) {
                set_error(app, "server failed to provide stream data");
                return -1;
            }
            if (stream->response_fin) {
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
    case picoquic_callback_stream_reset:
    case picoquic_callback_stop_sending:
        if (stream != NULL) {
            if (app->is_client && app->active_streams > 0) {
                app->active_streams--;
            }
            remove_stream(app, stream);
        }
        set_error(app, "stream reset or stop_sending received");
        return -1;
    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stateless_reset:
        app->finished = 1;
        return 0;
    default:
        return 0;
    }
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
    switch (mode) {
    case picoquic_packet_loop_ready: {
        picoquic_packet_loop_options_t *options = (picoquic_packet_loop_options_t *)callback_arg;
        options->do_time_check = 1;
        break;
    }
    case picoquic_packet_loop_after_receive:
    case picoquic_packet_loop_after_send:
        if (app->is_client) {
            maybe_finish_client(app);
            if (app->finished) {
                return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
        }
        break;
    case picoquic_packet_loop_time_check: {
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
        break;
    }
    case picoquic_packet_loop_port_update:
    case picoquic_packet_loop_wake_up:
    case picoquic_packet_loop_alt_port:
    case picoquic_packet_loop_system_call_duration:
        break;
    default:
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    return 0;
}

static int run_server(config_t cfg) {
    app_ctx_t app;
    memset(&app, 0, sizeof(app));
    app.cfg = cfg;
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    picoquic_register_all_congestion_control_algorithms();
    picoquic_quic_t *quic = create_quic_context(&cfg, 1, &app);
    if (quic == NULL) {
        fprintf(stderr, "could not create picoquic server context\n");
        return 1;
    }
    picoquic_set_default_callback(quic, app_callback, &app);
    picoquic_packet_loop_param_t param;
    memset(&param, 0, sizeof(param));
    param.local_port = cfg.port;
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
    app->connection_count = app->cfg.connections;
    app->connections =
        (picoquic_cnx_t **)calloc((size_t)app->connection_count, sizeof(picoquic_cnx_t *));
    app->connection_ready = (uint8_t *)calloc((size_t)app->connection_count, sizeof(uint8_t));
    if (app->connections == NULL || app->connection_ready == NULL) {
        set_error(app, "out of memory allocating connection table");
        return -1;
    }
    for (uint64_t i = 0; i < app->connection_count; ++i) {
        if (connect_one_client(app, quic, i) != 0) {
            return -1;
        }
    }
    app->cnx = app->connections[0];
    return 0;
}

static void close_client_connections(app_ctx_t *app) {
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
    app->connections = NULL;
    app->connection_ready = NULL;
    return app->failed ? -1 : 0;
}

static int run_crr(config_t cfg, counters_t *counters) {
    uint64_t measure_start = picoquic_current_time() + cfg.warmup_us;
    uint64_t measure_deadline = measure_start + cfg.duration_us;
    uint64_t started = 0;
    while ((cfg.requests.set && started < cfg.requests.value) ||
           (!cfg.requests.set && picoquic_current_time() < measure_deadline)) {
        app_ctx_t app;
        memset(&app, 0, sizeof(app));
        app.cfg = cfg;
        app.cfg.mode = "rr";
        app.cfg.requests.set = 1;
        app.cfg.requests.value = 1;
        app.cfg.requests_in_flight = 1;
        app.cfg.connections = 1;
        app.cfg.warmup_us = 0;
        app.is_client = 1;
        app.measure_start = measure_start;
        app.measure_deadline = measure_deadline;
        if (run_client_session(&app) != 0) {
            if (!cfg.requests.set) {
                counters->skipped_setup_errors++;
                continue;
            }
            free(app.counters.latencies.values);
            return -1;
        }
        counters->bytes_sent += app.counters.bytes_sent;
        counters->bytes_received += app.counters.bytes_received;
        counters->requests_completed += app.counters.requests_completed;
        counters->skipped_setup_errors += app.counters.skipped_setup_errors;
        for (size_t i = 0; i < app.counters.latencies.len; ++i) {
            if (latency_push(&counters->latencies, app.counters.latencies.values[i]) != 0) {
                free(app.counters.latencies.values);
                return -1;
            }
        }
        free(app.counters.latencies.values);
        started++;
    }
    return 0;
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

static int run_client(config_t cfg) {
    run_summary_t summary = new_summary(&cfg);
    uint64_t start = picoquic_current_time();
    app_ctx_t app;
    memset(&app, 0, sizeof(app));
    app.cfg = cfg;
    app.is_client = 1;
    int ret = 0;

    if (is_mode(&cfg, "crr")) {
        ret = run_crr(cfg, &app.counters);
        summary.elapsed_ms = cfg.requests.set
                                 ? (int64_t)duration_millis(picoquic_current_time() - start)
                                 : (int64_t)duration_millis(cfg.duration_us);
    } else {
        ret = run_client_session(&app);
        if (cfg.total_bytes.set || cfg.requests.set) {
            summary.elapsed_ms = (int64_t)duration_millis(picoquic_current_time() - start);
        } else {
            summary.elapsed_ms = (int64_t)duration_millis(cfg.duration_us);
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
    int emit_ret = emit_summary(&summary, cfg.json_out);
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
        return run_server(cfg);
    }
    return run_client(cfg);
}
