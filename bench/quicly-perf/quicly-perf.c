#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <openssl/pem.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

#define APPLICATION_PROTOCOL "coquic-perf/1"
#define PROTOCOL_VERSION 3U
#define CONTROL_STREAM_ID 0
#define FIRST_DATA_STREAM_ID 4
#define MESSAGE_SESSION_START 1
#define MESSAGE_SESSION_READY 2
#define MESSAGE_SESSION_ERROR 3
#define MESSAGE_SESSION_COMPLETE 4
#define MODE_CODE_BULK 0
#define MODE_CODE_RR 1
#define MODE_CODE_CRR 2
#define MODE_CODE_PERSISTENT_RR 3
#define DIRECTION_CODE_UPLOAD 0
#define DIRECTION_CODE_DOWNLOAD 1
#define DEFAULT_MAX_RUN_REQUESTS 4096ULL
#define MAX_BURST_PACKETS 10
#define TRANSFER_CONNECTION_WINDOW (32U * 1024U * 1024U)
#define TRANSFER_STREAM_WINDOW (16U * 1024U * 1024U)
#define DRAIN_TIMEOUT_US 2000000ULL
#define SESSION_READY_TIMEOUT_US 30000000ULL
#define WRITE_CHUNK_SIZE 32768U

typedef struct {
    uint64_t value;
    int set;
} optional_u64_t;

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

typedef struct {
    counters_t counters;
    uint64_t expected_requests;
    uint64_t completed_requests;
    uint64_t active_requests;
    uint64_t started_requests;
    uint64_t request_bytes;
    uint64_t response_bytes;
    int counts_latency;
    int persistent_rr;
    uint64_t response_pending;
    quicly_stream_t *persistent_stream;
    uint64_t *persistent_started_at;
    uint8_t *persistent_counts;
    size_t persistent_head;
    size_t persistent_len;
    size_t persistent_cap;
    int failed;
    int session_ready;
    uint8_t control_bytes[64];
    size_t control_len;
    char failure_reason[256];
} client_batch_t;

typedef struct {
    int fd;
    quicly_conn_t *conn;
    client_batch_t *batch;
} client_conn_t;

typedef struct {
    int started;
    uint8_t mode;
    uint8_t direction;
    uint64_t request_bytes;
    uint64_t response_bytes;
    optional_u64_t requests;
    optional_u64_t total_bytes;
    uint64_t warmup_us;
    uint64_t duration_us;
    uint64_t streams;
    uint64_t connections;
    uint64_t requests_in_flight;
} perf_session_start_t;

typedef struct {
    quicly_streambuf_t streambuf;
    uint8_t *control_bytes;
    size_t control_len;
    size_t control_cap;
    perf_session_start_t start;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t requests_completed;
    int ready_sent;
    int complete_sent;
} server_conn_data_t;

typedef struct {
    quicly_streambuf_t streambuf;
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t request_read;
    uint64_t response_sent;
    int ready_to_send;
    int persistent_rr;
    int request_fin;
    int send_closed;
} server_stream_data_t;

typedef struct {
    quicly_streambuf_t streambuf;
    client_batch_t *batch;
    uint64_t response_bytes;
    uint64_t response_read;
    uint64_t started_at;
    int counts_latency;
    int persistent_rr;
    int completed;
    int counted;
} client_stream_data_t;

static ptls_key_exchange_algorithm_t *key_exchanges[4];
static ptls_cipher_suite_t *cipher_suites[8];
static int is_server_role;

static int on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                              ptls_on_client_hello_parameters_t *params);
static void server_conn_data_destroy(server_conn_data_t *data);
static quicly_error_t flatten_sized_text(quicly_sendbuf_vec_t *vec, void *dst, size_t off,
                                         size_t len);
static void on_stop_sending(quicly_stream_t *stream, quicly_error_t err);
static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err);
static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void client_on_destroy(quicly_stream_t *stream, quicly_error_t err);
static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
static quicly_error_t drive_client_once(int fd, quicly_conn_t *conn, int64_t max_wait_ms);
static int write_request_body(quicly_stream_t *stream, client_batch_t *batch);

static void *checked_calloc(size_t count, size_t size) {
    void *ptr = calloc(count, size);
    if (ptr == NULL) {
        perror("calloc");
        exit(1);
    }
    return ptr;
}

static quicly_context_t *quic_context(void) {
    static quicly_context_t *context;
    if (context == NULL) {
        context = checked_calloc(1, sizeof(*context));
    }
    return context;
}

static quicly_cid_plaintext_t *next_connection_id(void) {
    static quicly_cid_plaintext_t *cid;
    if (cid == NULL) {
        cid = checked_calloc(1, sizeof(*cid));
    }
    return cid;
}

static ptls_on_client_hello_t *client_hello_callback(void) {
    static ptls_on_client_hello_t *on_client_hello;
    if (on_client_hello == NULL) {
        on_client_hello = checked_calloc(1, sizeof(*on_client_hello));
        on_client_hello->cb = on_client_hello_cb;
    }
    return on_client_hello;
}

static ptls_context_t *tls_context(void) {
    static ptls_context_t *tlsctx;
    if (tlsctx == NULL) {
        tlsctx = checked_calloc(1, sizeof(*tlsctx));
        tlsctx->random_bytes = ptls_openssl_random_bytes;
        tlsctx->get_time = &ptls_get_time;
        tlsctx->key_exchanges = key_exchanges;
        tlsctx->cipher_suites = cipher_suites;
        tlsctx->require_dhe_on_psk = 1;
    }
    tlsctx->on_client_hello = client_hello_callback();
    return tlsctx;
}

static ptls_openssl_sign_certificate_t *certificate_signer(void) {
    static ptls_openssl_sign_certificate_t *signer;
    if (signer == NULL) {
        signer = checked_calloc(1, sizeof(*signer));
    }
    return signer;
}

static ptls_openssl_verify_certificate_t *certificate_verifier(void) {
    static ptls_openssl_verify_certificate_t *verifier;
    if (verifier == NULL) {
        verifier = checked_calloc(1, sizeof(*verifier));
    }
    return verifier;
}

static ptls_iovec_t *negotiated_protocol_list(void) {
    static ptls_iovec_t *protocols;
    if (protocols == NULL) {
        protocols = checked_calloc(1, sizeof(*protocols));
    }
    return protocols;
}

static quicly_stream_open_t *stream_open_callback(void) {
    static quicly_stream_open_t *stream_open;
    if (stream_open == NULL) {
        stream_open = checked_calloc(1, sizeof(*stream_open));
        stream_open->cb = on_stream_open;
    }
    return stream_open;
}

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static uint64_t duration_millis(uint64_t usec) {
    return usec / 1000ULL;
}

static long timeout_delta_ms(int64_t timeout_at, int64_t now_ms, long max_wait_ms) {
    if (timeout_at == INT64_MAX) {
        return max_wait_ms;
    }
    if (timeout_at <= now_ms) {
        return 0;
    }
    const uint64_t delta = (uint64_t)(timeout_at - now_ms);
    return delta > (uint64_t)max_wait_ms ? max_wait_ms : (long)delta;
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
    if (!is_mode(cfg, "bulk") && !is_mode(cfg, "rr") && !is_mode(cfg, "crr") &&
        !is_mode(cfg, "persistent-rr")) {
        fprintf(stderr, "unsupported mode: %s\n", cfg->mode);
        exit(2);
    }
    if (strcmp(cfg->io_backend, "socket") != 0) {
        fprintf(stderr, "quicly-perf only supports the socket backend\n");
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
    if (strcmp(cfg->congestion_control, "bbr") == 0 ||
        strcmp(cfg->congestion_control, "copa") == 0) {
        fprintf(stderr,
                "quicly-perf does not provide BBR or Copa; use PERF_CONGESTION_CONTROLS=default\n");
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
        fprintf(stderr, "persistent-rr requires nonzero request and response bytes\n");
        exit(2);
    }
}

static config_t parse_args(int argc, char **argv) {
    config_t cfg;
    init_config(&cfg);
    if (argc < 2 || (strcmp(argv[1], "client") != 0 && strcmp(argv[1], "server") != 0)) {
        fprintf(stderr, "usage: quicly-perf [client|server] [options]\n");
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

static void counters_merge(counters_t *dst, counters_t *src) {
    dst->bytes_sent += src->bytes_sent;
    dst->bytes_received += src->bytes_received;
    dst->requests_completed += src->requests_completed;
    dst->skipped_setup_errors += src->skipped_setup_errors;
    for (size_t i = 0; i != src->latencies.len; ++i) {
        latency_push(&dst->latencies, src->latencies.values[i]);
    }
    free(src->latencies.values);
    memset(src, 0, sizeof(*src));
}

static void free_batch(client_batch_t *batch) {
    if (batch == NULL) {
        return;
    }
    free(batch->counters.latencies.values);
    free(batch->persistent_started_at);
    free(batch->persistent_counts);
    free(batch);
}

static void finish_batch(client_batch_t *batch, counters_t *counters) {
    if (batch == NULL) {
        return;
    }
    counters_merge(counters, &batch->counters);
    free_batch(batch);
}

static int persistent_queue_push(client_batch_t *batch, uint64_t started_at, int counts_latency) {
    if (batch->persistent_len == batch->persistent_cap) {
        size_t new_cap = batch->persistent_cap ? batch->persistent_cap * 2 : 8;
        uint64_t *new_started = malloc(new_cap * sizeof(new_started[0]));
        uint8_t *new_counts = malloc(new_cap * sizeof(new_counts[0]));
        if (new_started == NULL || new_counts == NULL) {
            free(new_started);
            free(new_counts);
            return -1;
        }
        for (size_t i = 0; i != batch->persistent_len; ++i) {
            size_t old = (batch->persistent_head + i) % batch->persistent_cap;
            new_started[i] = batch->persistent_started_at[old];
            new_counts[i] = batch->persistent_counts[old];
        }
        free(batch->persistent_started_at);
        free(batch->persistent_counts);
        batch->persistent_started_at = new_started;
        batch->persistent_counts = new_counts;
        batch->persistent_cap = new_cap;
        batch->persistent_head = 0;
    }
    size_t index = (batch->persistent_head + batch->persistent_len) % batch->persistent_cap;
    batch->persistent_started_at[index] = started_at;
    batch->persistent_counts[index] = counts_latency ? 1 : 0;
    ++batch->persistent_len;
    return 0;
}

static int persistent_queue_pop(client_batch_t *batch, uint64_t *started_at, int *counts_latency) {
    if (batch->persistent_len == 0) {
        return -1;
    }
    *started_at = batch->persistent_started_at[batch->persistent_head];
    *counts_latency = batch->persistent_counts[batch->persistent_head] != 0;
    batch->persistent_head = (batch->persistent_head + 1) % batch->persistent_cap;
    --batch->persistent_len;
    return 0;
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

static void encode_be64(uint8_t out[8], uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)(value & 0xffU);
        value >>= 8;
    }
}

static uint64_t decode_be64(const uint8_t in[8]) {
    uint64_t value = 0;
    for (int i = 0; i != 8; ++i) {
        value = (value << 8) | in[i];
    }
    return value;
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

static int valid_session_start(const perf_session_start_t *start) {
    return start->started &&
           (start->mode == MODE_CODE_BULK || start->mode == MODE_CODE_RR ||
            start->mode == MODE_CODE_CRR || start->mode == MODE_CODE_PERSISTENT_RR) &&
           (start->direction == DIRECTION_CODE_UPLOAD ||
            start->direction == DIRECTION_CODE_DOWNLOAD) &&
           start->streams != 0 && start->connections != 0 && start->requests_in_flight != 0 &&
           (start->mode != MODE_CODE_PERSISTENT_RR ||
            (start->request_bytes != 0 && start->response_bytes != 0));
}

static int decode_session_start_payload(const uint8_t *payload, size_t len,
                                        perf_session_start_t *start) {
    if (len != 79 || decode_be32(payload) != PROTOCOL_VERSION) {
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
    return valid_session_start(start) ? 0 : -1;
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

static uint8_t *encode_session_start_message(const config_t *cfg, uint64_t request_bytes,
                                             uint64_t response_bytes, size_t *out_len) {
    uint8_t payload[79];
    encode_be32(payload, PROTOCOL_VERSION);
    payload[4] = mode_code(cfg->mode);
    payload[5] = direction_code(cfg->direction);
    encode_be64(payload + 6, request_bytes);
    encode_be64(payload + 14, response_bytes);
    payload[22] = (cfg->total_bytes.set ? 0x01 : 0) | (cfg->requests.set ? 0x02 : 0);
    encode_be64(payload + 23, cfg->total_bytes.value);
    encode_be64(payload + 31, cfg->requests.value);
    encode_be64(payload + 39, cfg->warmup_us);
    encode_be64(payload + 47, cfg->duration_us);
    encode_be64(payload + 55, cfg->streams);
    encode_be64(payload + 63, cfg->connections);
    encode_be64(payload + 71, cfg->requests_in_flight);
    return frame_control_message(MESSAGE_SESSION_START, payload, sizeof(payload), out_len);
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

static uint8_t *encode_session_ready_message(size_t *out_len) {
    uint8_t payload[4];
    encode_be32(payload, PROTOCOL_VERSION);
    return frame_control_message(MESSAGE_SESSION_READY, payload, sizeof(payload), out_len);
}

static uint8_t *encode_session_error_message(const char *reason, size_t *out_len) {
    size_t reason_len = strlen(reason);
    if (reason_len > UINT32_MAX - 4) {
        reason_len = UINT32_MAX - 4;
    }
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

static uint8_t *encode_session_complete_message(uint64_t bytes_sent, uint64_t bytes_received,
                                                uint64_t requests_completed, size_t *out_len) {
    uint8_t payload[24];
    encode_be64(payload, bytes_sent);
    encode_be64(payload + 8, bytes_received);
    encode_be64(payload + 16, requests_completed);
    return frame_control_message(MESSAGE_SESSION_COMPLETE, payload, sizeof(payload), out_len);
}

static int decode_ready_message(const uint8_t *data, size_t len, char *failure_reason,
                                size_t failure_reason_len) {
    if (len < 5) {
        snprintf(failure_reason, failure_reason_len, "short control message");
        return -1;
    }
    uint8_t type = data[0];
    uint32_t payload_len = decode_be32(data + 1);
    if ((size_t)payload_len + 5 != len) {
        snprintf(failure_reason, failure_reason_len, "malformed control message length");
        return -1;
    }
    const uint8_t *payload = data + 5;
    if (type == MESSAGE_SESSION_READY) {
        if (payload_len != 4 || decode_be32(payload) != PROTOCOL_VERSION) {
            snprintf(failure_reason, failure_reason_len, "malformed session_ready");
            return -1;
        }
        return 0;
    }
    if (type == MESSAGE_SESSION_ERROR) {
        if (payload_len < 4) {
            snprintf(failure_reason, failure_reason_len, "malformed session_error");
            return -1;
        }
        uint32_t reason_len = decode_be32(payload);
        if (reason_len + 4 != payload_len) {
            snprintf(failure_reason, failure_reason_len, "malformed session_error length");
            return -1;
        }
        size_t copy_len = reason_len < failure_reason_len - 1 ? reason_len : failure_reason_len - 1;
        memcpy(failure_reason, payload + 4, copy_len);
        failure_reason[copy_len] = 0;
        return -1;
    }
    snprintf(failure_reason, failure_reason_len, "unexpected control message type %u", type);
    return -1;
}

static void set_batch_failure(client_batch_t *batch, const char *message) {
    if (!batch->failed) {
        batch->failed = 1;
        snprintf(batch->failure_reason, sizeof(batch->failure_reason), "%s", message);
    }
}

static void server_conn_data_destroy(server_conn_data_t *data) {
    if (data == NULL) {
        return;
    }
    free(data->control_bytes);
    free(data);
}

static server_conn_data_t *server_conn_data(quicly_conn_t *conn) {
    return (server_conn_data_t *)*quicly_get_data(conn);
}

static uint64_t server_response_bytes(const perf_session_start_t *start,
                                      uint64_t requests_completed) {
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

static int should_send_complete(server_conn_data_t *conn_data) {
    if (conn_data == NULL || conn_data->complete_sent || !conn_data->start.started) {
        return 0;
    }
    const perf_session_start_t *start = &conn_data->start;
    return (start->mode == MODE_CODE_BULK && start->total_bytes.set &&
            conn_data->requests_completed >= start->streams) ||
           (start->mode == MODE_CODE_BULK && start->total_bytes.set &&
            start->direction == DIRECTION_CODE_UPLOAD &&
            conn_data->requests_completed >= start->streams) ||
           ((start->mode == MODE_CODE_RR || start->mode == MODE_CODE_PERSISTENT_RR) &&
            start->requests.set && conn_data->requests_completed >= start->requests.value);
}

static int send_control_on_stream(quicly_stream_t *stream, uint8_t *message, size_t len,
                                  int close_send) {
    if (message == NULL) {
        return -1;
    }
    int rc = quicly_streambuf_egress_write(stream, message, len);
    free(message);
    if (rc != 0) {
        return -1;
    }
    if (close_send) {
        quicly_streambuf_egress_shutdown(stream);
    }
    return 0;
}

static void maybe_send_server_complete(quicly_stream_t *stream, server_conn_data_t *conn_data) {
    if (!should_send_complete(conn_data)) {
        return;
    }
    size_t len = 0;
    uint8_t *message = encode_session_complete_message(
        conn_data->bytes_sent, conn_data->bytes_received, conn_data->requests_completed, &len);
    if (send_control_on_stream(stream, message, len, 1) == 0) {
        conn_data->complete_sent = 1;
    }
}

static int resolve_address(struct sockaddr_storage *sa, socklen_t *salen, const char *host,
                           uint16_t port, int passive) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char service[16];
    snprintf(service, sizeof(service), "%u", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | (passive ? AI_PASSIVE : 0);
    int err = getaddrinfo(host, service, &hints, &res);
    if (err != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, service,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }
    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static void load_certificate_chain(ptls_context_t *tls, const char *path) {
    if (ptls_load_certificates(tls, (char *)path) != 0) {
        fprintf(stderr, "failed to load certificate:%s:%s\n", path, strerror(errno));
        exit(1);
    }
}

static void load_private_key(ptls_context_t *tls, const char *path) {
    ptls_openssl_sign_certificate_t *signer = certificate_signer();
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "failed to open private key:%s:%s\n", path, strerror(errno));
        exit(1);
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "failed to read private key:%s\n", path);
        exit(1);
    }
    ptls_openssl_init_sign_certificate(signer, pkey);
    EVP_PKEY_free(pkey);
    tls->sign_certificate = &signer->super;
}

static void setup_verify_certificate(ptls_context_t *tls) {
    ptls_openssl_verify_certificate_t *verifier = certificate_verifier();
    ptls_openssl_init_verify_certificate(verifier, NULL);
    tls->verify_certificate = &verifier->super;
}

static int on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                              ptls_on_client_hello_parameters_t *params) {
    (void)self;
    ptls_iovec_t want = ptls_iovec_init(APPLICATION_PROTOCOL, strlen(APPLICATION_PROTOCOL));
    for (size_t i = 0; i != params->negotiated_protocols.count; ++i) {
        ptls_iovec_t got = params->negotiated_protocols.list[i];
        if (got.len == want.len && memcmp(got.base, want.base, want.len) == 0) {
            return ptls_set_negotiated_protocol(tls, (const char *)want.base, want.len);
        }
    }
    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

static const char *quicly_cc_name(const char *label) {
    if (strcmp(label, "default") == 0 || strcmp(label, "newreno") == 0 ||
        strcmp(label, "reno") == 0) {
        return "reno";
    }
    return label;
}

static void configure_context(const config_t *cfg, int server) {
    quicly_context_t *context = quic_context();
    ptls_context_t *tls = tls_context();
    ptls_iovec_t *protocols = negotiated_protocol_list();
    is_server_role = server;
    key_exchanges[0] = &ptls_openssl_secp256r1;
    key_exchanges[1] = NULL;
    for (size_t i = 0; ptls_openssl_cipher_suites[i] != NULL &&
                       i < sizeof(cipher_suites) / sizeof(cipher_suites[0]) - 1;
         ++i) {
        cipher_suites[i] = ptls_openssl_cipher_suites[i];
        cipher_suites[i + 1] = NULL;
    }
    protocols[0] = ptls_iovec_init(APPLICATION_PROTOCOL, strlen(APPLICATION_PROTOCOL));

    *context = quicly_spec_context;
    context->tls = tls;
    context->stream_open = NULL;
    context->transport_params.max_data = TRANSFER_CONNECTION_WINDOW;
    context->transport_params.max_stream_data.bidi_local = TRANSFER_STREAM_WINDOW;
    context->transport_params.max_stream_data.bidi_remote = TRANSFER_STREAM_WINDOW;
    context->transport_params.max_stream_data.uni = TRANSFER_STREAM_WINDOW;
    uint64_t max_streams_bidi = (is_mode(cfg, "rr") || is_mode(cfg, "persistent-rr"))
                                    ? cfg->requests_in_flight * cfg->connections
                                    : cfg->streams * cfg->connections;
    if (max_streams_bidi < 100) {
        max_streams_bidi = 100;
    }
    context->transport_params.max_streams_bidi = max_streams_bidi;
    context->transport_params.max_udp_payload_size = 1500;

    const char *cc_name = quicly_cc_name(cfg->congestion_control);
    for (quicly_cc_type_t **cc = quicly_cc_all_types; *cc != NULL; ++cc) {
        if (strcmp((*cc)->name, cc_name) == 0) {
            context->init_cc = (*cc)->cc_init;
            break;
        }
    }

    quicly_amend_ptls_context(context->tls);
    if (server) {
        load_certificate_chain(context->tls, cfg->certificate_chain);
        load_private_key(context->tls, cfg->private_key);
    } else if (cfg->verify_peer) {
        setup_verify_certificate(context->tls);
    }
}

static quicly_error_t flatten_sized_text(quicly_sendbuf_vec_t *vec, void *dst, size_t off,
                                         size_t len) {
    (void)vec;
    static const char pattern[] = "hello world\nhello world\nhello world\nhello world\nhello "
                                  "world\nhello world\nhello world\n";
    while (len != 0) {
        size_t pattern_off = off % (sizeof(pattern) - 1);
        size_t chunk = sizeof(pattern) - 1 - pattern_off;
        if (chunk > len) {
            chunk = len;
        }
        memcpy(dst, pattern + pattern_off, chunk);
        off += chunk;
        dst = (char *)dst + chunk;
        len -= chunk;
    }
    return 0;
}

static const quicly_streambuf_sendvec_callbacks_t *sized_text_callbacks(void) {
    static quicly_streambuf_sendvec_callbacks_t *callbacks;
    if (callbacks == NULL) {
        callbacks = checked_calloc(1, sizeof(*callbacks));
        callbacks->flatten_vec = flatten_sized_text;
    }
    return callbacks;
}

static void on_stop_sending(quicly_stream_t *stream, quicly_error_t err) {
    (void)stream;
    (void)err;
}

static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err) {
    (void)stream;
    (void)err;
}

static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {
    server_stream_data_t *data = stream->data;
    server_conn_data_t *conn_data = server_conn_data(stream->conn);
    /* Parse control stream requests separately from payload streams that need response bytes. */
    if (!quicly_sendstate_is_open(&stream->sendstate)) {
        return;
    }
    if (!data || data->send_closed) {
        return;
    }

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0) {
        return;
    }

    if (stream->stream_id == CONTROL_STREAM_ID) {
        for (;;) {
            ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
            if (input.len == 0) {
                break;
            }
            if (conn_data == NULL) {
                quicly_streambuf_ingress_shift(stream, input.len);
                break;
            }
            if (conn_data->control_len + input.len > conn_data->control_cap) {
                size_t new_cap = conn_data->control_cap ? conn_data->control_cap * 2 : 128;
                while (new_cap < conn_data->control_len + input.len) {
                    new_cap *= 2;
                }
                uint8_t *new_bytes = realloc(conn_data->control_bytes, new_cap);
                if (new_bytes == NULL) {
                    quicly_streambuf_ingress_shift(stream, input.len);
                    return;
                }
                conn_data->control_bytes = new_bytes;
                conn_data->control_cap = new_cap;
            }
            memcpy(conn_data->control_bytes + conn_data->control_len, input.base, input.len);
            conn_data->control_len += input.len;
            quicly_streambuf_ingress_shift(stream, input.len);
        }
        if (!quicly_recvstate_transfer_complete(&stream->recvstate) || conn_data == NULL ||
            conn_data->ready_sent) {
            return;
        }
        if (conn_data->control_len < 5 ||
            conn_data->control_len != (size_t)decode_be32(conn_data->control_bytes + 1) + 5 ||
            conn_data->control_bytes[0] != MESSAGE_SESSION_START ||
            decode_session_start_payload(conn_data->control_bytes + 5, conn_data->control_len - 5,
                                         &conn_data->start) != 0) {
            size_t msg_len = 0;
            uint8_t *msg = encode_session_error_message("invalid session_start", &msg_len);
            (void)send_control_on_stream(stream, msg, msg_len, 1);
            data->send_closed = 1;
            return;
        }
        size_t msg_len = 0;
        uint8_t *msg = encode_session_ready_message(&msg_len);
        if (send_control_on_stream(stream, msg, msg_len, 0) == 0) {
            conn_data->ready_sent = 1;
        }
        return;
    }

    if (conn_data == NULL || !conn_data->start.started) {
        return;
    }
    data->persistent_rr = conn_data->start.mode == MODE_CODE_PERSISTENT_RR;

    for (;;) {
        ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
        if (input.len == 0) {
            break;
        }
        data->request_read += input.len;
        conn_data->bytes_received += input.len;
        quicly_streambuf_ingress_shift(stream, input.len);
    }

    if (data->persistent_rr) {
        while (data->request_read >= conn_data->start.request_bytes) {
            data->request_read -= conn_data->start.request_bytes;
            ++conn_data->requests_completed;
            data->response_bytes += conn_data->start.response_bytes;
            data->ready_to_send = 1;
        }
        if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
            if (data->request_read != 0) {
                quicly_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1));
                return;
            }
            data->request_fin = 1;
            data->ready_to_send = 1;
        }
    } else if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        data->request_bytes = conn_data->start.request_bytes;
        if (data->request_read != data->request_bytes) {
            quicly_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1));
            return;
        }
        ++conn_data->requests_completed;
        data->response_bytes =
            server_response_bytes(&conn_data->start, conn_data->requests_completed);
        data->ready_to_send = 1;
    }
    if (!data->ready_to_send) {
        return;
    }

    const quicly_streambuf_sendvec_callbacks_t *callbacks = sized_text_callbacks();
    uint64_t pending = data->response_bytes - data->response_sent;
    if (pending != 0) {
        quicly_sendbuf_vec_t vec = {callbacks, pending, NULL};
        quicly_streambuf_egress_write_vec(stream, &vec);
        data->response_sent += pending;
        conn_data->bytes_sent += pending;
    }
    if ((!data->persistent_rr || data->request_fin) &&
        data->response_sent >= data->response_bytes) {
        quicly_streambuf_egress_shutdown(stream);
        data->send_closed = 1;
    }
    data->ready_to_send = 0;
    quicly_stream_t *control = quicly_get_stream(stream->conn, CONTROL_STREAM_ID);
    if (control != NULL) {
        maybe_send_server_complete(control, conn_data);
    }
}

static void client_count_stream(client_stream_data_t *data) {
    client_batch_t *batch = data->batch;
    if (!batch || data->counted || !data->completed) {
        return;
    }
    data->counted = 1;
    if (data->response_read != data->response_bytes) {
        char message[160];
        snprintf(message, sizeof(message),
                 "quicly-perf response byte count mismatch: got %" PRIu64 ", expected %" PRIu64,
                 data->response_read, data->response_bytes);
        set_batch_failure(batch, message);
    }
    batch->counters.bytes_sent += batch->request_bytes;
    batch->counters.bytes_received += data->response_bytes;
    ++batch->counters.requests_completed;
    ++batch->completed_requests;
    if (batch->active_requests > 0) {
        --batch->active_requests;
    }
    if (data->counts_latency) {
        latency_push(&batch->counters.latencies, now_us() - data->started_at);
    }
}

static void client_count_persistent_responses(client_stream_data_t *data) {
    client_batch_t *batch = data->batch;
    if (batch == NULL || batch->response_bytes == 0) {
        return;
    }
    while (batch->response_pending >= batch->response_bytes) {
        uint64_t started_at = 0;
        int counts_latency = 0;
        if (persistent_queue_pop(batch, &started_at, &counts_latency) != 0) {
            set_batch_failure(batch, "persistent-rr response without pending request");
            return;
        }
        batch->response_pending -= batch->response_bytes;
        batch->counters.bytes_sent += batch->request_bytes;
        batch->counters.bytes_received += batch->response_bytes;
        ++batch->counters.requests_completed;
        ++batch->completed_requests;
        if (batch->active_requests > 0) {
            --batch->active_requests;
        }
        if (counts_latency) {
            latency_push(&batch->counters.latencies, now_us() - started_at);
        }
    }
}

static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {
    client_stream_data_t *data = stream->data;
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0) {
        return;
    }
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (stream->stream_id == CONTROL_STREAM_ID) {
        client_batch_t *batch = data->batch;
        if (batch == NULL) {
            return;
        }
        if (input.len != 0) {
            size_t available = sizeof(batch->control_bytes) - batch->control_len;
            size_t take = input.len < available ? input.len : available;
            memcpy(batch->control_bytes + batch->control_len, input.base, take);
            batch->control_len += take;
            quicly_streambuf_ingress_shift(stream, input.len);
        }
        if (!batch->session_ready && batch->control_len >= 5) {
            uint32_t payload_len = decode_be32(batch->control_bytes + 1);
            if ((size_t)payload_len + 5 <= batch->control_len) {
                char message[256] = "";
                if (decode_ready_message(batch->control_bytes, (size_t)payload_len + 5, message,
                                         sizeof(message)) == 0) {
                    batch->session_ready = 1;
                } else {
                    set_batch_failure(batch, message[0] ? message : "invalid session_ready");
                }
            }
        }
        return;
    }
    if (input.len != 0) {
        data->response_read += input.len;
        if (data->persistent_rr && data->batch != NULL) {
            data->batch->response_pending += input.len;
        }
        quicly_streambuf_ingress_shift(stream, input.len);
        if (data->persistent_rr) {
            client_count_persistent_responses(data);
        }
    }
    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        if (data->persistent_rr) {
            if (data->batch != NULL &&
                (data->batch->response_pending != 0 || data->batch->persistent_len != 0)) {
                set_batch_failure(data->batch,
                                  "persistent-rr stream closed with pending responses");
            }
            return;
        }
        data->completed = 1;
        client_count_stream(data);
    }
}

static void client_on_destroy(quicly_stream_t *stream, quicly_error_t err) {
    (void)err;
    client_stream_data_t *data = stream->data;
    if (stream->stream_id != CONTROL_STREAM_ID && !data->persistent_rr) {
        client_count_stream(data);
    }
    quicly_streambuf_destroy(stream, err);
}

static const quicly_stream_callbacks_t *server_stream_callback_table(void) {
    static quicly_stream_callbacks_t *callbacks;
    if (callbacks == NULL) {
        callbacks = checked_calloc(1, sizeof(*callbacks));
        callbacks->on_destroy = quicly_streambuf_destroy;
        callbacks->on_send_shift = quicly_streambuf_egress_shift;
        callbacks->on_send_emit = quicly_streambuf_egress_emit;
        callbacks->on_send_stop = on_stop_sending;
        callbacks->on_receive = server_on_receive;
        callbacks->on_receive_reset = on_receive_reset;
    }
    return callbacks;
}

static const quicly_stream_callbacks_t *client_stream_callback_table(void) {
    static quicly_stream_callbacks_t *callbacks;
    if (callbacks == NULL) {
        callbacks = checked_calloc(1, sizeof(*callbacks));
        callbacks->on_destroy = client_on_destroy;
        callbacks->on_send_shift = quicly_streambuf_egress_shift;
        callbacks->on_send_emit = quicly_streambuf_egress_emit;
        callbacks->on_send_stop = on_stop_sending;
        callbacks->on_receive = client_on_receive;
        callbacks->on_receive_reset = on_receive_reset;
    }
    return callbacks;
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream) {
    (void)self;
    int ret;
    if ((ret = quicly_streambuf_create(stream, is_server_role ? sizeof(server_stream_data_t)
                                                              : sizeof(client_stream_data_t))) !=
        0) {
        return ret;
    }
    stream->callbacks =
        is_server_role ? server_stream_callback_table() : client_stream_callback_table();
    return 0;
}

static ssize_t receive_datagram(int fd, void *buf, quicly_address_t *dest, quicly_address_t *src,
                                uint8_t *ecn) {
    const quicly_context_t *context = quic_context();
    struct iovec vec = {.iov_base = buf, .iov_len = context->transport_params.max_udp_payload_size};
    char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(1)] = {};
    struct msghdr msg = {
        .msg_name = &src->sa,
        .msg_namelen = sizeof(*src),
        .msg_iov = &vec,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };
    quicly_address_t localaddr = {};
    socklen_t localaddrlen = sizeof(localaddr);
    if (getsockname(fd, &localaddr.sa, &localaddrlen) != 0) {
        perror("getsockname failed");
    }
    ssize_t rret;
    while ((rret = recvmsg(fd, &msg, 0)) == -1 && errno == EINTR) {
    }
    if (rret >= 0) {
        dest->sa.sa_family = AF_UNSPEC;
        *ecn = 0;
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#ifdef IP_PKTINFO
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                dest->sin.sin_family = AF_INET;
                memcpy(&dest->sin.sin_addr, CMSG_DATA(cmsg) + offsetof(struct in_pktinfo, ipi_addr),
                       sizeof(dest->sin.sin_addr));
                dest->sin.sin_port = localaddr.sin.sin_port;
            }
#endif
#ifdef IP_RECVDSTADDR
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR) {
                dest->sin.sin_family = AF_INET;
                memcpy(&dest->sin.sin_addr, CMSG_DATA(cmsg), sizeof(dest->sin.sin_addr));
                dest->sin.sin_port = localaddr.sin.sin_port;
            }
#endif
#ifdef IP_RECVTOS
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) {
                *ecn = *(uint8_t *)CMSG_DATA(cmsg) & IPTOS_ECN_MASK;
            }
#endif
        }
    }
    return rret;
}

static void set_srcaddr(struct msghdr *msg, quicly_address_t *addr) {
    if (addr == NULL || addr->sa.sa_family == AF_UNSPEC) {
        return;
    }
#ifdef IP_PKTINFO
    if (addr->sa.sa_family == AF_INET) {
        struct cmsghdr *cmsg = (struct cmsghdr *)((char *)msg->msg_control + msg->msg_controllen);
        struct in_pktinfo info = {.ipi_spec_dst = addr->sin.sin_addr};
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(info));
        memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
        msg->msg_controllen += CMSG_SPACE(sizeof(info));
    }
#endif
}

static void set_ecn(struct msghdr *msg, uint8_t ecn) {
    if (ecn == 0) {
        return;
    }
    struct cmsghdr *cmsg = (struct cmsghdr *)((char *)msg->msg_control + msg->msg_controllen);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_TOS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(ecn));
    memcpy(CMSG_DATA(cmsg), &ecn, sizeof(ecn));
    msg->msg_controllen += CMSG_SPACE(sizeof(ecn));
}

static void send_packets(int fd, quicly_address_t *dest, quicly_address_t *src,
                         struct iovec *packets, size_t num_packets, uint8_t ecn) {
    for (size_t i = 0; i != num_packets; ++i) {
        char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))] = {};
        struct msghdr msg = {
            .msg_name = dest,
            .msg_namelen = quicly_get_socklen(&dest->sa),
            .msg_iov = &packets[i],
            .msg_iovlen = 1,
            .msg_control = cmsgbuf,
        };
        set_srcaddr(&msg, src);
        set_ecn(&msg, ecn);
        if (msg.msg_controllen == 0) {
            msg.msg_control = NULL;
        }
        int ret;
        while ((ret = (int)sendmsg(fd, &msg, 0)) == -1 && errno == EINTR) {
        }
        if (ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("sendmsg failed");
        }
    }
}

static void send_one_packet(int fd, quicly_address_t *dest, quicly_address_t *src,
                            const void *payload, size_t payload_len) {
    struct iovec vec = {.iov_base = (void *)payload, .iov_len = payload_len};
    send_packets(fd, dest, src, &vec, 1, 0);
}

static quicly_error_t send_pending(int fd, quicly_conn_t *conn) {
    quicly_address_t dest;
    quicly_address_t src;
    struct iovec packets[MAX_BURST_PACKETS];
    uint8_t buf[MAX_BURST_PACKETS * 1500];
    size_t num_packets = MAX_BURST_PACKETS;
    quicly_error_t ret = quicly_send(conn, &dest, &src, packets, &num_packets, buf, sizeof(buf));
    if (ret == 0 && num_packets != 0) {
        send_packets(fd, &dest, &src, packets, num_packets, quicly_send_get_ecn_bits(conn));
    }
    return ret;
}

static int prep_socket(int fd) {
    if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
        perror("fcntl(O_NONBLOCK) failed");
        return -1;
    }
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }
#ifdef IP_PKTINFO
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) != 0) {
        perror("setsockopt(IP_PKTINFO) failed");
        return -1;
    }
#endif
#ifdef IP_RECVTOS
    if (setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on)) != 0) {
        perror("Warning: setsockopt(IP_RECVTOS) failed");
    }
#endif
    return 0;
}

static int open_request_stream(quicly_conn_t *conn, client_batch_t *batch, int counts) {
    quicly_stream_t *stream = NULL;
    quicly_error_t ret = quicly_open_stream(conn, &stream, 0);
    if (ret != 0) {
        set_batch_failure(batch, "quicly_open_stream failed");
        return -1;
    }
    client_stream_data_t *data = stream->data;
    data->batch = batch;
    data->response_bytes = batch->response_bytes;
    data->started_at = now_us();
    data->counts_latency = counts && batch->counts_latency;

    if (write_request_body(stream, batch) != 0) {
        return -1;
    }
    if (quicly_streambuf_egress_shutdown(stream) != 0) {
        set_batch_failure(batch, "could not close request stream send side");
        return -1;
    }
    ++batch->active_requests;
    return 0;
}

static int write_request_body(quicly_stream_t *stream, client_batch_t *batch) {
    static const uint8_t zeros[WRITE_CHUNK_SIZE] = {0};
    uint64_t sent = 0;
    while (sent < batch->request_bytes) {
        uint64_t left = batch->request_bytes - sent;
        size_t chunk = left > sizeof(zeros) ? sizeof(zeros) : (size_t)left;
        if (quicly_streambuf_egress_write(stream, zeros, chunk) != 0) {
            set_batch_failure(batch, "could not write request stream body");
            return -1;
        }
        sent += chunk;
    }
    return 0;
}

static int open_persistent_rr_stream(quicly_conn_t *conn, client_batch_t *batch) {
    if (batch->persistent_stream != NULL) {
        return 0;
    }
    quicly_stream_t *stream = NULL;
    quicly_error_t ret = quicly_open_stream(conn, &stream, 0);
    if (ret != 0) {
        set_batch_failure(batch, "quicly_open_stream persistent-rr failed");
        return -1;
    }
    client_stream_data_t *data = stream->data;
    data->batch = batch;
    data->response_bytes = batch->response_bytes;
    data->persistent_rr = 1;
    batch->persistent_stream = stream;
    return 0;
}

static int send_persistent_rr_request(quicly_conn_t *conn, client_batch_t *batch,
                                      int counts_latency) {
    if (open_persistent_rr_stream(conn, batch) != 0) {
        return -1;
    }
    if (write_request_body(batch->persistent_stream, batch) != 0) {
        return -1;
    }
    if (persistent_queue_push(batch, now_us(), counts_latency && batch->counts_latency) != 0) {
        set_batch_failure(batch, "out of memory");
        return -1;
    }
    ++batch->active_requests;
    ++batch->started_requests;
    return 0;
}

static void close_persistent_rr_stream(client_batch_t *batch) {
    if (batch == NULL || batch->persistent_stream == NULL) {
        return;
    }
    (void)quicly_streambuf_egress_shutdown(batch->persistent_stream);
    batch->persistent_stream = NULL;
}

static int open_control_stream(quicly_conn_t *conn, const config_t *cfg, client_batch_t *batch,
                               uint64_t request_bytes, uint64_t response_bytes) {
    quicly_stream_t *stream = NULL;
    quicly_error_t ret = quicly_open_stream(conn, &stream, 0);
    if (ret != 0 || stream == NULL) {
        set_batch_failure(batch, "quicly_open_stream control failed");
        return -1;
    }
    if (stream->stream_id != CONTROL_STREAM_ID) {
        set_batch_failure(batch, "unexpected quicly control stream id");
        return -1;
    }
    client_stream_data_t *data = stream->data;
    data->batch = batch;
    size_t message_len = 0;
    uint8_t *message =
        encode_session_start_message(cfg, request_bytes, response_bytes, &message_len);
    if (message == NULL) {
        set_batch_failure(batch, "could not encode session_start");
        return -1;
    }
    int rc = quicly_streambuf_egress_write(stream, message, message_len);
    free(message);
    if (rc != 0 || quicly_streambuf_egress_shutdown(stream) != 0) {
        set_batch_failure(batch, "could not write session_start");
        return -1;
    }
    return 0;
}

static int wait_for_session_ready(int fd, quicly_conn_t *conn, client_batch_t *batch,
                                  uint64_t deadline_us, char *failure_reason,
                                  size_t failure_reason_len) {
    while (!batch->session_ready && !batch->failed && now_us() < deadline_us) {
        quicly_error_t ret = drive_client_once(fd, conn, 100);
        if (ret != 0 && ret != QUICLY_ERROR_FREE_CONNECTION) {
            snprintf(failure_reason, failure_reason_len, "quicly_send returned %" PRId64,
                     (int64_t)ret);
            return -1;
        }
    }
    if (batch->failed) {
        snprintf(failure_reason, failure_reason_len, "%s", batch->failure_reason);
        return -1;
    }
    if (!batch->session_ready) {
        snprintf(failure_reason, failure_reason_len, "session_ready timed out");
        return -1;
    }
    return 0;
}

static int open_refill_streams(quicly_conn_t *conn, client_batch_t *batch, uint64_t target_active,
                               int counts_latency) {
    while (batch->active_requests < target_active) {
        if (open_request_stream(conn, batch, counts_latency) != 0) {
            return -1;
        }
    }
    return 0;
}

static uint64_t client_total_completed(client_conn_t *clients, size_t count) {
    uint64_t completed = 0;
    for (size_t i = 0; i != count; ++i) {
        if (clients[i].batch != NULL) {
            completed += clients[i].batch->completed_requests;
        }
    }
    return completed;
}

static uint64_t client_total_active(client_conn_t *clients, size_t count) {
    uint64_t active = 0;
    for (size_t i = 0; i != count; ++i) {
        if (clients[i].batch != NULL) {
            active += clients[i].batch->active_requests;
        }
    }
    return active;
}

static int refill_rr_clients(client_conn_t *clients, size_t count, const config_t *cfg,
                             uint64_t *started, uint64_t limit, uint64_t deadline_us,
                             int counts_latency, char *failure_reason, size_t failure_reason_len) {
    for (size_t i = 0; i != count; ++i) {
        client_batch_t *batch = clients[i].batch;
        while (batch != NULL && batch->active_requests < cfg->requests_in_flight) {
            if (limit != UINT64_MAX) {
                if (*started >= limit) {
                    return 0;
                }
                if (batch->started_requests >= rr_request_limit_for_connection(cfg, (uint64_t)i)) {
                    break;
                }
            }
            if (deadline_us != 0 && now_us() >= deadline_us) {
                return 0;
            }
            if (batch->persistent_rr) {
                if (send_persistent_rr_request(clients[i].conn, batch, counts_latency) != 0) {
                    snprintf(failure_reason, failure_reason_len, "%s", batch->failure_reason);
                    return -1;
                }
            } else {
                if (open_request_stream(clients[i].conn, batch, counts_latency) != 0) {
                    snprintf(failure_reason, failure_reason_len, "%s", batch->failure_reason);
                    return -1;
                }
                ++batch->started_requests;
            }
            ++*started;
        }
    }
    return 0;
}

static int drive_client_sessions_once(client_conn_t *clients, size_t count, int64_t max_wait_ms,
                                      char *failure_reason, size_t failure_reason_len) {
    for (size_t i = 0; i != count; ++i) {
        if (clients[i].conn == NULL) {
            continue;
        }
        quicly_error_t ret = drive_client_once(clients[i].fd, clients[i].conn, max_wait_ms);
        if (ret != 0) {
            quicly_free(clients[i].conn);
            clients[i].conn = NULL;
            if (ret != QUICLY_ERROR_FREE_CONNECTION) {
                snprintf(failure_reason, failure_reason_len, "quicly_send returned %" PRId64,
                         (int64_t)ret);
                return -1;
            }
        }
        if (clients[i].batch != NULL && clients[i].batch->failed) {
            snprintf(failure_reason, failure_reason_len, "%s", clients[i].batch->failure_reason);
            return -1;
        }
    }
    return 0;
}

static int prepare_client_socket(const config_t *cfg, int *fd, struct sockaddr_storage *sa,
                                 socklen_t *salen, char *failure_reason,
                                 size_t failure_reason_len) {
    if (resolve_address(sa, salen, cfg->host, cfg->port, 0) != 0) {
        snprintf(failure_reason, failure_reason_len, "could not resolve server");
        return -1;
    }
    *fd = socket(sa->ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (*fd == -1) {
        snprintf(failure_reason, failure_reason_len, "socket failed: %s", strerror(errno));
        return -1;
    }
    if (prep_socket(*fd) != 0) {
        close(*fd);
        *fd = -1;
        snprintf(failure_reason, failure_reason_len, "could not prepare socket");
        return -1;
    }
    quicly_address_t local;
    memset(&local, 0, sizeof(local));
    local.sa.sa_family = sa->ss_family;
    if (bind(*fd, &local.sa,
             local.sa.sa_family == AF_INET ? sizeof(local.sin) : sizeof(local.sin6)) != 0) {
        close(*fd);
        *fd = -1;
        snprintf(failure_reason, failure_reason_len, "bind failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void close_client_session(client_conn_t *client) {
    if (client == NULL) {
        return;
    }
    if (client->conn != NULL) {
        if (client->batch != NULL && client->batch->persistent_rr) {
            close_persistent_rr_stream(client->batch);
            if (client->fd >= 0) {
                (void)send_pending(client->fd, client->conn);
            }
        }
        quicly_free(client->conn);
        client->conn = NULL;
    }
    if (client->fd >= 0) {
        close(client->fd);
        client->fd = -1;
    }
}

static void close_client_sessions(client_conn_t *clients, size_t count, counters_t *counters) {
    if (clients == NULL) {
        return;
    }
    for (size_t i = 0; i != count; ++i) {
        close_client_session(&clients[i]);
        if (clients[i].batch != NULL) {
            if (counters != NULL) {
                finish_batch(clients[i].batch, counters);
            } else {
                free_batch(clients[i].batch);
            }
            clients[i].batch = NULL;
        }
    }
    free(clients);
}

static quicly_conn_t *connect_client(const config_t *cfg, const struct sockaddr_storage *sa,
                                     char *failure_reason, size_t failure_reason_len) {
    quicly_context_t *context = quic_context();
    quicly_cid_plaintext_t *next_cid = next_connection_id();
    ptls_iovec_t *protocols = negotiated_protocol_list();
    ptls_handshake_properties_t hs_properties;
    memset(&hs_properties, 0, sizeof(hs_properties));
    hs_properties.client.negotiated_protocols.list = protocols;
    hs_properties.client.negotiated_protocols.count = 1;

    quicly_conn_t *conn = NULL;
    quicly_error_t ret =
        quicly_connect(&conn, context, cfg->server_name, (struct sockaddr *)sa, NULL, next_cid,
                       ptls_iovec_init(NULL, 0), &hs_properties, NULL, NULL);
    if (ret != 0 || conn == NULL) {
        snprintf(failure_reason, failure_reason_len, "quicly_connect failed");
        return NULL;
    }
    ++next_cid->master_id;
    return conn;
}

static int init_client_session(const config_t *cfg, client_conn_t *client,
                               uint64_t expected_requests, uint64_t request_bytes,
                               uint64_t response_bytes, int counts_latency, char *failure_reason,
                               size_t failure_reason_len) {
    memset(client, 0, sizeof(*client));
    client->fd = -1;
    struct sockaddr_storage sa;
    socklen_t salen;
    if (prepare_client_socket(cfg, &client->fd, &sa, &salen, failure_reason, failure_reason_len) !=
        0) {
        return -1;
    }
    (void)salen;
    client->batch = calloc(1, sizeof(*client->batch));
    if (client->batch == NULL) {
        close_client_session(client);
        snprintf(failure_reason, failure_reason_len, "out of memory");
        return -1;
    }
    client->batch->expected_requests = expected_requests;
    client->batch->request_bytes = request_bytes;
    client->batch->response_bytes = response_bytes;
    client->batch->counts_latency = counts_latency;
    client->batch->persistent_rr = is_mode(cfg, "persistent-rr");
    client->conn = connect_client(cfg, &sa, failure_reason, failure_reason_len);
    if (client->conn == NULL) {
        free_batch(client->batch);
        client->batch = NULL;
        close_client_session(client);
        return -1;
    }
    if (open_control_stream(client->conn, cfg, client->batch, request_bytes, response_bytes) != 0 ||
        send_pending(client->fd, client->conn) != 0 ||
        wait_for_session_ready(client->fd, client->conn, client->batch,
                               now_us() + SESSION_READY_TIMEOUT_US, failure_reason,
                               failure_reason_len) != 0) {
        if (failure_reason[0] == '\0') {
            snprintf(failure_reason, failure_reason_len, "%s", client->batch->failure_reason);
        }
        free_batch(client->batch);
        client->batch = NULL;
        close_client_session(client);
        return -1;
    }
    return 0;
}

static client_conn_t *open_client_sessions(const config_t *cfg, size_t count,
                                           uint64_t expected_requests, uint64_t request_bytes,
                                           uint64_t response_bytes, int counts_latency,
                                           char *failure_reason, size_t failure_reason_len,
                                           size_t *opened_count) {
    *opened_count = 0;
    client_conn_t *clients = calloc(count, sizeof(*clients));
    if (clients == NULL) {
        snprintf(failure_reason, failure_reason_len, "out of memory");
        return NULL;
    }
    for (size_t i = 0; i != count; ++i) {
        clients[i].fd = -1;
        config_t connection_cfg = *cfg;
        uint64_t connection_expected_requests = expected_requests;
        if ((is_mode(cfg, "rr") || is_mode(cfg, "persistent-rr")) && cfg->requests.set) {
            connection_expected_requests = rr_request_limit_for_connection(cfg, (uint64_t)i);
            connection_cfg.requests.value = connection_expected_requests;
            connection_cfg.requests.set = 1;
        }
        if (init_client_session(&connection_cfg, &clients[i], connection_expected_requests,
                                request_bytes, response_bytes, counts_latency, failure_reason,
                                failure_reason_len) != 0) {
            close_client_sessions(clients, i + 1, NULL);
            return NULL;
        }
        *opened_count = i + 1;
    }
    return clients;
}

static client_conn_t *open_timed_client_sessions(const config_t *cfg, size_t count,
                                                 uint64_t request_bytes, uint64_t response_bytes,
                                                 int counts_latency, counters_t *counters,
                                                 char *failure_reason, size_t failure_reason_len,
                                                 size_t *opened_count) {
    *opened_count = 0;
    client_conn_t *clients = calloc(count, sizeof(*clients));
    if (clients == NULL) {
        snprintf(failure_reason, failure_reason_len, "out of memory");
        return NULL;
    }
    for (size_t i = 0; i != count; ++i) {
        clients[i].fd = -1;
    }

    char last_failure_reason[256] = "";
    for (size_t i = 0; i != count; ++i) {
        char setup_failure_reason[256] = "";
        client_conn_t *client = &clients[*opened_count];
        if (init_client_session(cfg, client, 0, request_bytes, response_bytes, counts_latency,
                                setup_failure_reason, sizeof(setup_failure_reason)) != 0) {
            if (counters != NULL) {
                counters->skipped_setup_errors += 1;
            }
            if (setup_failure_reason[0] != '\0') {
                snprintf(last_failure_reason, sizeof(last_failure_reason), "%s",
                         setup_failure_reason);
            }
            close_client_session(client);
            free_batch(client->batch);
            memset(client, 0, sizeof(*client));
            client->fd = -1;
            continue;
        }
        *opened_count += 1;
    }

    if (*opened_count == 0) {
        if (last_failure_reason[0] != '\0') {
            snprintf(failure_reason, failure_reason_len, "all client sessions failed setup: %s",
                     last_failure_reason);
        } else {
            snprintf(failure_reason, failure_reason_len, "all client sessions failed setup");
        }
        close_client_sessions(clients, count, NULL);
        return NULL;
    }
    return clients;
}

static quicly_error_t drive_client_once(int fd, quicly_conn_t *conn, int64_t max_wait_ms) {
    quicly_context_t *context = quic_context();
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    struct timeval tv;
    int64_t timeout_at = quicly_get_first_timeout(conn);
    int64_t now_ms = context->now->cb(context->now);
    long delta = timeout_delta_ms(timeout_at, now_ms, max_wait_ms);
    tv.tv_sec = delta / 1000;
    tv.tv_usec = (delta % 1000) * 1000;
    int sret;
    do {
        sret = select(fd + 1, &readfds, NULL, NULL, &tv);
    } while (sret == -1 && errno == EINTR);

    if (sret > 0 && FD_ISSET(fd, &readfds)) {
        for (;;) {
            uint8_t buf[1500];
            uint8_t ecn;
            quicly_address_t dest;
            quicly_address_t src;
            ssize_t rret = receive_datagram(fd, buf, &dest, &src, &ecn);
            if (rret <= 0) {
                break;
            }
            size_t off = 0;
            while (off != (size_t)rret) {
                quicly_decoded_packet_t packet;
                if (quicly_decode_packet(context, &packet, buf, (size_t)rret, &off) == SIZE_MAX) {
                    break;
                }
                packet.ecn = ecn;
                quicly_receive(conn, &dest.sa, &src.sa, &packet);
            }
        }
    }
    return send_pending(fd, conn);
}

static int run_fixed_bulk(const config_t *cfg, uint64_t response_bytes, uint64_t request_bytes,
                          counters_t *counters, char *failure_reason, size_t failure_reason_len) {
    if (!cfg->total_bytes.set) {
        snprintf(failure_reason, failure_reason_len, "fixed bulk requires --total-bytes");
        return -1;
    }
    size_t opened = 0;
    client_conn_t *clients =
        open_client_sessions(cfg, (size_t)cfg->connections, 0, request_bytes, response_bytes, 0,
                             failure_reason, failure_reason_len, &opened);
    if (clients == NULL) {
        return -1;
    }
    uint64_t per_stream = cfg->total_bytes.value / cfg->streams;
    uint64_t remainder = cfg->total_bytes.value % cfg->streams;
    for (uint64_t i = 0; i != cfg->streams; ++i) {
        client_conn_t *client = &clients[i % opened];
        client->batch->request_bytes =
            is_direction(cfg, "upload") ? per_stream + (i < remainder ? 1 : 0) : request_bytes;
        client->batch->response_bytes =
            is_direction(cfg, "upload") ? response_bytes : per_stream + (i < remainder ? 1 : 0);
        if (open_request_stream(client->conn, client->batch, 0) != 0) {
            snprintf(failure_reason, failure_reason_len, "%s", client->batch->failure_reason);
            close_client_sessions(clients, opened, counters);
            return -1;
        }
    }
    for (size_t i = 0; i != opened; ++i) {
        (void)send_pending(clients[i].fd, clients[i].conn);
    }
    uint64_t hard_deadline = now_us() + 120000000ULL;
    while (client_total_active(clients, opened) != 0) {
        if (now_us() > hard_deadline) {
            snprintf(failure_reason, failure_reason_len, "quicly-perf fixed bulk timed out");
            close_client_sessions(clients, opened, counters);
            return -1;
        }
        if (drive_client_sessions_once(clients, opened, 1, failure_reason, failure_reason_len) !=
            0) {
            close_client_sessions(clients, opened, counters);
            return -1;
        }
    }
    close_client_sessions(clients, opened, counters);
    return 0;
}

static int run_timed_bulk_download(const config_t *cfg, uint64_t response_bytes,
                                   uint64_t request_bytes, counters_t *counters,
                                   char *failure_reason, size_t failure_reason_len) {
    size_t opened = 0;
    client_conn_t *clients =
        open_client_sessions(cfg, (size_t)cfg->connections, 0, request_bytes, response_bytes, 1,
                             failure_reason, failure_reason_len, &opened);
    if (clients == NULL) {
        return -1;
    }

    uint64_t deadline = now_us() + cfg->duration_us;
    uint64_t drain_deadline = deadline + DRAIN_TIMEOUT_US;
    for (size_t i = 0; i != opened; ++i) {
        if (open_refill_streams(clients[i].conn, clients[i].batch, cfg->streams, 1) != 0) {
            snprintf(failure_reason, failure_reason_len, "%s", clients[i].batch->failure_reason);
            close_client_sessions(clients, opened, counters);
            return -1;
        }
        (void)send_pending(clients[i].fd, clients[i].conn);
    }

    while (now_us() <= drain_deadline) {
        uint64_t now = now_us();
        if (now < deadline) {
            for (size_t i = 0; i != opened; ++i) {
                if (clients[i].conn != NULL &&
                    open_refill_streams(clients[i].conn, clients[i].batch, cfg->streams, 1) != 0) {
                    snprintf(failure_reason, failure_reason_len, "%s",
                             clients[i].batch->failure_reason);
                    close_client_sessions(clients, opened, counters);
                    return -1;
                }
            }
        } else if (client_total_active(clients, opened) == 0) {
            break;
        }
        if (drive_client_sessions_once(clients, opened, 1, failure_reason, failure_reason_len) !=
            0) {
            close_client_sessions(clients, opened, counters);
            return -1;
        }
    }

    close_client_sessions(clients, opened, counters);
    return 0;
}

static int run_rr_requests(const config_t *cfg, uint64_t request_limit, counters_t *counters,
                           char *failure_reason, size_t failure_reason_len) {
    uint64_t capped_limit =
        request_limit > DEFAULT_MAX_RUN_REQUESTS ? DEFAULT_MAX_RUN_REQUESTS : request_limit;
    config_t request_cfg = *cfg;
    request_cfg.connections = rr_connection_target(cfg);
    size_t opened = 0;
    client_conn_t *clients = open_client_sessions(
        &request_cfg, (size_t)request_cfg.connections, capped_limit, cfg->request_bytes,
        cfg->response_bytes, 1, failure_reason, failure_reason_len, &opened);
    if (clients == NULL) {
        return -1;
    }
    uint64_t started = 0;
    if (refill_rr_clients(clients, opened, cfg, &started, capped_limit, 0, 1, failure_reason,
                          failure_reason_len) != 0) {
        close_client_sessions(clients, opened, counters);
        return -1;
    }
    uint64_t hard_deadline = now_us() + 120000000ULL;
    while (client_total_completed(clients, opened) < capped_limit ||
           client_total_active(clients, opened) != 0) {
        if (now_us() > hard_deadline) {
            snprintf(failure_reason, failure_reason_len, "quicly-perf rr batch timed out");
            close_client_sessions(clients, opened, counters);
            return -1;
        }
        if (drive_client_sessions_once(clients, opened, 1, failure_reason, failure_reason_len) !=
            0) {
            close_client_sessions(clients, opened, counters);
            return -1;
        }
        if (refill_rr_clients(clients, opened, cfg, &started, capped_limit, 0, 1, failure_reason,
                              failure_reason_len) != 0) {
            close_client_sessions(clients, opened, counters);
            return -1;
        }
    }
    close_client_sessions(clients, opened, counters);
    return 0;
}

static int run_timed_rr(const config_t *cfg, counters_t *counters, char *failure_reason,
                        size_t failure_reason_len) {
    size_t opened = 0;
    client_conn_t *clients = open_timed_client_sessions(
        cfg, (size_t)cfg->connections, cfg->request_bytes, cfg->response_bytes, 1, counters,
        failure_reason, failure_reason_len, &opened);
    if (clients == NULL) {
        return -1;
    }
    uint64_t started = 0;
    uint64_t deadline = now_us() + cfg->duration_us;
    uint64_t drain_deadline = deadline + DRAIN_TIMEOUT_US;
    if (refill_rr_clients(clients, opened, cfg, &started, UINT64_MAX, deadline, 1, failure_reason,
                          failure_reason_len) != 0) {
        close_client_sessions(clients, opened, counters);
        return -1;
    }
    while (now_us() <= drain_deadline) {
        uint64_t now = now_us();
        if (now < deadline) {
            if (refill_rr_clients(clients, opened, cfg, &started, UINT64_MAX, deadline, 1,
                                  failure_reason, failure_reason_len) != 0) {
                close_client_sessions(clients, opened, counters);
                return -1;
            }
        } else if (client_total_active(clients, opened) == 0) {
            break;
        }
        if (drive_client_sessions_once(clients, opened, 1, failure_reason, failure_reason_len) !=
            0) {
            close_client_sessions(clients, opened, counters);
            return -1;
        }
    }
    close_client_sessions(clients, opened, counters);
    return 0;
}

static int run_crr(const config_t *cfg, counters_t *counters, char *failure_reason,
                   size_t failure_reason_len) {
    client_conn_t *clients = calloc((size_t)cfg->connections, sizeof(*clients));
    if (clients == NULL) {
        snprintf(failure_reason, failure_reason_len, "out of memory");
        return -1;
    }
    for (uint64_t i = 0; i != cfg->connections; ++i) {
        clients[i].fd = -1;
    }

    uint64_t started = 0;
    uint64_t deadline = now_us() + cfg->duration_us;
    uint64_t drain_deadline = deadline + DRAIN_TIMEOUT_US;
    while ((cfg->requests.set && started < cfg->requests.value) ||
           (!cfg->requests.set && now_us() < deadline) ||
           client_total_active(clients, cfg->connections) != 0) {
        for (uint64_t i = 0; i != cfg->connections; ++i) {
            client_conn_t *client = &clients[i];
            if (client->conn == NULL && client->batch != NULL &&
                client->batch->completed_requests >= 1) {
                finish_batch(client->batch, counters);
                client->batch = NULL;
                close_client_session(client);
            }
            if (client->conn == NULL && client->batch == NULL) {
                if (cfg->requests.set && started >= cfg->requests.value) {
                    continue;
                }
                if (!cfg->requests.set && now_us() >= deadline) {
                    continue;
                }
                int counts = cfg->requests.set || now_us() < deadline;
                if (init_client_session(cfg, client, 1, cfg->request_bytes, cfg->response_bytes,
                                        counts, failure_reason, failure_reason_len) != 0) {
                    if (!cfg->requests.set) {
                        counters->skipped_setup_errors += 1;
                        close_client_session(client);
                        free_batch(client->batch);
                        client->batch = NULL;
                        continue;
                    }
                    close_client_sessions(clients, (size_t)cfg->connections, counters);
                    return -1;
                }
                if (open_request_stream(client->conn, client->batch, counts) != 0) {
                    snprintf(failure_reason, failure_reason_len, "%s",
                             client->batch->failure_reason);
                    close_client_sessions(clients, (size_t)cfg->connections, counters);
                    return -1;
                }
                ++started;
            }
        }

        if (!cfg->requests.set && now_us() > drain_deadline) {
            break;
        }
        if (drive_client_sessions_once(clients, (size_t)cfg->connections, 1, failure_reason,
                                       failure_reason_len) != 0) {
            close_client_sessions(clients, (size_t)cfg->connections, counters);
            return -1;
        }
    }
    close_client_sessions(clients, (size_t)cfg->connections, counters);
    return 0;
}

static int run_bulk(const config_t *cfg, counters_t *counters, char *failure_reason,
                    size_t failure_reason_len) {
    uint64_t request_bytes;
    uint64_t response_bytes;
    if (is_direction(cfg, "upload")) {
        request_bytes =
            cfg->request_bytes > cfg->response_bytes ? cfg->request_bytes : cfg->response_bytes;
        response_bytes = 0;
    } else {
        request_bytes = cfg->request_bytes;
        response_bytes = cfg->response_bytes;
    }

    if (cfg->total_bytes.set) {
        return run_fixed_bulk(cfg, response_bytes, request_bytes, counters, failure_reason,
                              failure_reason_len);
    }

    return run_timed_bulk_download(cfg, response_bytes, request_bytes, counters, failure_reason,
                                   failure_reason_len);
}

static int run_rr(const config_t *cfg, counters_t *counters, char *failure_reason,
                  size_t failure_reason_len) {
    if (cfg->requests.set) {
        return run_rr_requests(cfg, cfg->requests.value, counters, failure_reason,
                               failure_reason_len);
    }
    return run_timed_rr(cfg, counters, failure_reason, failure_reason_len);
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

static run_summary_t run_client(const config_t *cfg) {
    counters_t counters;
    memset(&counters, 0, sizeof(counters));
    char failure_reason[256] = "";
    uint64_t start = now_us();
    if (cfg->warmup_us > 0 && !cfg->requests.set && !cfg->total_bytes.set) {
        usleep((useconds_t)cfg->warmup_us);
    }
    uint64_t measure_start = now_us();
    int rc;
    if (is_mode(cfg, "bulk")) {
        rc = run_bulk(cfg, &counters, failure_reason, sizeof(failure_reason));
    } else if (is_mode(cfg, "rr") || is_mode(cfg, "persistent-rr")) {
        rc = run_rr(cfg, &counters, failure_reason, sizeof(failure_reason));
    } else {
        rc = run_crr(cfg, &counters, failure_reason, sizeof(failure_reason));
    }
    uint64_t end = now_us();
    uint64_t elapsed = (!cfg->requests.set && !cfg->total_bytes.set && rc == 0)
                           ? cfg->duration_us
                           : end - (cfg->requests.set ? start : measure_start);
    run_summary_t summary =
        make_summary(cfg, &counters, (int64_t)duration_millis(elapsed), rc == 0 ? "ok" : "failed",
                     rc == 0 ? NULL : failure_reason);
    free(counters.latencies.values);
    return summary;
}

static quicly_conn_t **server_conns;
static size_t num_server_conns;
static volatile sig_atomic_t server_stop;

static void on_server_signal(int signo) {
    (void)signo;
    server_stop = 1;
}

static void remove_server_conn(size_t index) {
    server_conn_data_destroy(server_conn_data(server_conns[index]));
    quicly_free(server_conns[index]);
    memmove(server_conns + index, server_conns + index + 1,
            (num_server_conns - index - 1) * sizeof(server_conns[0]));
    --num_server_conns;
}

static int run_server(const config_t *cfg) {
    quicly_context_t *context = quic_context();
    quicly_cid_plaintext_t *next_cid = next_connection_id();

    /* Bind the UDP listener and install signal handlers for benchmark shutdown. */
    struct sockaddr_storage sa;
    socklen_t salen;
    if (resolve_address(&sa, &salen, cfg->host, cfg->port, 1) != 0) {
        return 1;
    }
    int fd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        perror("socket failed");
        return 1;
    }
    if (prep_socket(fd) != 0) {
        close(fd);
        return 1;
    }
    if (bind(fd, (struct sockaddr *)&sa, salen) != 0) {
        perror("bind failed");
        close(fd);
        return 1;
    }
    signal(SIGTERM, on_server_signal);
    signal(SIGINT, on_server_signal);

    while (!server_stop) {
        /* Wait for either network input or the earliest quicly connection timer. */
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        int64_t timeout_at = INT64_MAX;
        for (size_t i = 0; i != num_server_conns; ++i) {
            int64_t conn_timeout = quicly_get_first_timeout(server_conns[i]);
            if (conn_timeout < timeout_at) {
                timeout_at = conn_timeout;
            }
        }
        struct timeval tv;
        long delta = timeout_delta_ms(timeout_at, context->now->cb(context->now), 100);
        tv.tv_sec = delta / 1000;
        tv.tv_usec = (delta % 1000) * 1000;
        int sret;
        do {
            sret = select(fd + 1, &readfds, NULL, NULL, &tv);
        } while (sret == -1 && errno == EINTR && !server_stop);

        if (sret > 0 && FD_ISSET(fd, &readfds)) {
            for (;;) {
                uint8_t buf[1500];
                uint8_t ecn;
                quicly_address_t local;
                quicly_address_t remote;
                ssize_t rret = receive_datagram(fd, buf, &local, &remote, &ecn);
                if (rret <= 0) {
                    break;
                }
                size_t off = 0;
                while (off != (size_t)rret) {
                    quicly_decoded_packet_t packet;
                    if (quicly_decode_packet(context, &packet, buf, (size_t)rret, &off) ==
                        SIZE_MAX) {
                        break;
                    }
                    packet.ecn = ecn;
                    quicly_conn_t *conn = NULL;
                    for (size_t i = 0; i != num_server_conns; ++i) {
                        if (quicly_is_destination(server_conns[i], &local.sa, &remote.sa,
                                                  &packet)) {
                            conn = server_conns[i];
                            break;
                        }
                    }
                    if (conn != NULL) {
                        quicly_receive(conn, &local.sa, &remote.sa, &packet);
                    } else if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0]) &&
                               packet.version != 0 &&
                               !quicly_is_supported_version(packet.version)) {
                        /* Unknown-version Initials need a stateless version negotiation response.
                         */
                        uint8_t payload[1500];
                        size_t payload_len = quicly_send_version_negotiation(
                            context, packet.cid.src, packet.cid.dest.encrypted,
                            quicly_supported_versions, payload);
                        if (payload_len != SIZE_MAX) {
                            send_one_packet(fd, &remote, &local, payload, payload_len);
                        }
                    } else if (QUICLY_PACKET_IS_INITIAL(packet.octets.base[0])) {
                        quicly_error_t ret = quicly_accept(&conn, context, &local.sa, &remote.sa,
                                                           &packet, NULL, next_cid, NULL, NULL);
                        if (ret == 0 && conn != NULL) {
                            server_conn_data_t *conn_data = calloc(1, sizeof(*conn_data));
                            if (conn_data == NULL) {
                                perror("calloc");
                                quicly_free(conn);
                                continue;
                            }
                            *quicly_get_data(conn) = conn_data;
                            ++next_cid->master_id;
                            quicly_conn_t **new_conns = realloc(
                                server_conns, (num_server_conns + 1) * sizeof(server_conns[0]));
                            if (!new_conns) {
                                perror("realloc");
                                server_conn_data_destroy(conn_data);
                                quicly_free(conn);
                                continue;
                            }
                            server_conns = new_conns;
                            server_conns[num_server_conns++] = conn;
                        }
                    }
                }
            }
        }

        for (size_t i = 0; i < num_server_conns;) {
            quicly_error_t ret = send_pending(fd, server_conns[i]);
            if (ret != 0) {
                remove_server_conn(i);
                continue;
            }
            ++i;
        }
    }

    for (size_t i = 0; i != num_server_conns; ++i) {
        server_conn_data_destroy(server_conn_data(server_conns[i]));
        quicly_free(server_conns[i]);
    }
    free(server_conns);
    close(fd);
    return 0;
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

int main(int argc, char **argv) {
    config_t cfg = parse_args(argc, argv);
    configure_context(&cfg, strcmp(cfg.role, "server") == 0);
    quic_context()->stream_open = stream_open_callback();
    if (strcmp(cfg.role, "server") == 0) {
        return run_server(&cfg);
    }
    run_summary_t summary = run_client(&cfg);
    if (emit_summary(&summary) != 0) {
        return 1;
    }
    return strcmp(summary.status, "ok") == 0 ? 0 : 1;
}
