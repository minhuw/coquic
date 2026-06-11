#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#define APPLICATION_PROTOCOL "coquic-perf/1"
#define APPLICATION_PROTOCOL_WIRE "\x0d" APPLICATION_PROTOCOL
#define PERF_PROTOCOL_VERSION 3U
#define CONTROL_STREAM_ID 0LL
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
#define DEFAULT_MAX_RUN_REQUESTS 4096ULL
#define TRANSFER_CONNECTION_WINDOW (32ULL * 1024ULL * 1024ULL)
#define TRANSFER_STREAM_WINDOW (16ULL * 1024ULL * 1024ULL)
#define TRANSFER_MAX_STREAMS 1000000ULL
#define WRITE_CHUNK_SIZE 1024U
#define READ_BUF_SIZE 65536U
#define UDP_PAYLOAD_SIZE 1452U
#define SERVER_CID_LEN 18U
#define HANDSHAKE_TIMEOUT_US 10000000ULL
#define BATCH_TIMEOUT_US 120000000ULL
#define DRAIN_TIMEOUT_US 2000000ULL

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

typedef struct perf_conn perf_conn_t;

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

typedef struct stream_ctx {
    struct stream_ctx *next;
    int64_t stream_id;
    perf_conn_t *conn;
    int is_control;
    uint8_t *control_out;
    size_t control_len;
    size_t control_sent;
    int control_fin;
    uint8_t *control_in;
    size_t control_in_len;
    size_t control_in_cap;
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t request_sent;
    uint64_t request_received;
    uint64_t response_sent;
    uint64_t response_received;
    uint64_t started_at;
    int request_fin;
    int response_fin;
    int counted;
    int counts_latency;
    int server_shape_set;
    int write_fin_sent;
    int server_ready_to_send;
    int persistent_rr;
    uint64_t response_pending;
    uint64_t *persistent_started_at;
    uint8_t *persistent_counts;
    size_t persistent_head;
    size_t persistent_len;
    size_t persistent_cap;
} stream_ctx_t;

static int persistent_queue_push(stream_ctx_t *stream, uint64_t started_at, int counts_latency);
static int persistent_queue_pop(stream_ctx_t *stream, uint64_t *started_at, int *counts_latency);

struct perf_conn {
    config_t cfg;
    int fd;
    int owns_fd;
    int is_server;
    int closed;
    int failed;
    char failure_reason[256];
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ssl_native_ctx;
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_ccerr last_error;
    stream_ctx_t *streams;
    uint64_t expected_requests;
    uint64_t started_requests;
    uint64_t completed_requests;
    uint64_t started_at;
    counters_t *counters;
    perf_session_start_t session_start;
    int session_ready;
    uint64_t server_bytes_sent;
    uint64_t server_bytes_received;
    uint64_t server_requests_completed;
    int server_complete_sent;
};

typedef struct server_state {
    config_t cfg;
    int fd;
    SSL_CTX *ssl_ctx;
    perf_conn_t **conns;
    size_t num_conns;
    size_t cap_conns;
} server_state_t;

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signum) {
    (void)signum;
    stop_requested = 1;
}

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static ngtcp2_tstamp ngtcp2_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

static uint64_t duration_millis(uint64_t usec) {
    return usec / 1000ULL;
}

static int is_mode(const config_t *cfg, const char *mode) {
    return strcmp(cfg->mode, mode) == 0;
}

static int is_direction(const config_t *cfg, const char *direction) {
    return strcmp(cfg->direction, direction) == 0;
}

static uint64_t ceil_div(uint64_t n, uint64_t d) {
    return d == 0 ? 0 : (n + d - 1) / d;
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

static void config_defaults(config_t *cfg) {
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

static void parse_args(config_t *cfg, int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "client") != 0 && strcmp(argv[1], "server") != 0)) {
        fprintf(stderr, "usage: ngtcp2-perf [client|server] [options]\n");
        exit(2);
    }
    config_defaults(cfg);
    snprintf(cfg->role, sizeof(cfg->role), "%s", argv[1]);

    for (int i = 2; i < argc;) {
        const char *arg = argv[i++];
        if (strcmp(arg, "--verify-peer") == 0) {
            cfg->verify_peer = 1;
        } else if (strcmp(arg, "--disable-pmtud") == 0) {
            cfg->disable_pmtud = 1;
        } else if (strcmp(arg, "--host") == 0) {
            snprintf(cfg->host, sizeof(cfg->host), "%s", take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--port") == 0) {
            cfg->port = (uint16_t)parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--server-name") == 0) {
            snprintf(cfg->server_name, sizeof(cfg->server_name), "%s",
                     take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--io-backend") == 0) {
            snprintf(cfg->io_backend, sizeof(cfg->io_backend), "%s",
                     take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--congestion-control") == 0) {
            snprintf(cfg->congestion_control, sizeof(cfg->congestion_control), "%s",
                     take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--certificate-chain") == 0) {
            snprintf(cfg->certificate_chain, sizeof(cfg->certificate_chain), "%s",
                     take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--private-key") == 0) {
            snprintf(cfg->private_key, sizeof(cfg->private_key), "%s",
                     take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--mode") == 0) {
            snprintf(cfg->mode, sizeof(cfg->mode), "%s", take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--direction") == 0) {
            snprintf(cfg->direction, sizeof(cfg->direction), "%s", take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--request-bytes") == 0) {
            cfg->request_bytes = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--response-bytes") == 0) {
            cfg->response_bytes = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--streams") == 0) {
            cfg->streams = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--connections") == 0) {
            cfg->connections = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--requests-in-flight") == 0) {
            cfg->requests_in_flight = parse_u64(take_value(argc, argv, &i, arg), arg);
        } else if (strcmp(arg, "--requests") == 0) {
            cfg->requests.value = parse_u64(take_value(argc, argv, &i, arg), arg);
            cfg->requests.set = 1;
        } else if (strcmp(arg, "--total-bytes") == 0) {
            cfg->total_bytes.value = parse_u64(take_value(argc, argv, &i, arg), arg);
            cfg->total_bytes.set = 1;
        } else if (strcmp(arg, "--warmup") == 0) {
            cfg->warmup_us = parse_duration_us(take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--duration") == 0) {
            cfg->duration_us = parse_duration_us(take_value(argc, argv, &i, arg));
        } else if (strcmp(arg, "--json-out") == 0) {
            snprintf(cfg->json_out, sizeof(cfg->json_out), "%s", take_value(argc, argv, &i, arg));
        } else {
            fprintf(stderr, "unknown argument: %s\n", arg);
            exit(2);
        }
    }
}

static ngtcp2_cc_algo ngtcp2_cc(const char *label) {
    if (strcmp(label, "default") == 0 || strcmp(label, "cubic") == 0) {
        return NGTCP2_CC_ALGO_CUBIC;
    }
    if (strcmp(label, "newreno") == 0 || strcmp(label, "reno") == 0) {
        return NGTCP2_CC_ALGO_RENO;
    }
    if (strcmp(label, "bbr") == 0) {
        return NGTCP2_CC_ALGO_BBR;
    }
    return NGTCP2_CC_ALGO_CUBIC;
}

static void validate_config(const config_t *cfg) {
    if (!is_mode(cfg, "bulk") && !is_mode(cfg, "rr") && !is_mode(cfg, "crr") &&
        !is_mode(cfg, "persistent-rr")) {
        fprintf(stderr, "unsupported mode: %s\n", cfg->mode);
        exit(2);
    }
    if (strcmp(cfg->io_backend, "socket") != 0) {
        fprintf(stderr, "ngtcp2-perf only supports the socket backend\n");
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
                "ngtcp2-perf does not provide Copa; use PERF_CONGESTION_CONTROLS=default\n");
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

static int latency_push(latency_vec_t *vec, uint64_t value) {
    if (vec->len == vec->cap) {
        size_t next = vec->cap ? vec->cap * 2 : 128;
        uint64_t *values = realloc(vec->values, next * sizeof(values[0]));
        if (!values) {
            return -1;
        }
        vec->values = values;
        vec->cap = next;
    }
    vec->values[vec->len++] = value;
    return 0;
}

static int compare_u64(const void *a, const void *b) {
    uint64_t av = *(const uint64_t *)a;
    uint64_t bv = *(const uint64_t *)b;
    return (av > bv) - (av < bv);
}

static uint64_t percentile_u64(const uint64_t *values, size_t len, double pct) {
    if (len == 0) {
        return 0;
    }
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
        return summary;
    }
    memcpy(values, latencies->values, latencies->len * sizeof(values[0]));
    qsort(values, latencies->len, sizeof(values[0]), compare_u64);

    uint64_t sum = 0;
    for (size_t i = 0; i < latencies->len; ++i) {
        sum += values[i];
    }
    summary.min_us = values[0];
    summary.avg_us = sum / latencies->len;
    summary.p50_us = percentile_u64(values, latencies->len, 50.0);
    summary.p90_us = percentile_u64(values, latencies->len, 90.0);
    summary.p99_us = percentile_u64(values, latencies->len, 99.0);
    summary.max_us = values[latencies->len - 1];
    free(values);
    return summary;
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

static uint64_t decode_be64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

static void encode_be64(uint8_t *bytes, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        bytes[i] = (uint8_t)(value & 0xff);
        value >>= 8;
    }
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

static uint8_t *frame_control_message(uint8_t type, const uint8_t *payload, uint32_t payload_len,
                                      size_t *out_len) {
    uint8_t *out = malloc((size_t)payload_len + 5);
    if (!out) {
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
    encode_be32(payload, PERF_PROTOCOL_VERSION);
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

static uint8_t *encode_session_ready_message(size_t *out_len) {
    uint8_t payload[4];
    encode_be32(payload, PERF_PROTOCOL_VERSION);
    return frame_control_message(MESSAGE_SESSION_READY, payload, sizeof(payload), out_len);
}

static uint8_t *encode_session_error_message(const char *reason, size_t *out_len) {
    size_t reason_len = strlen(reason);
    uint8_t *payload = malloc(reason_len + 4);
    if (!payload) {
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

static void set_failure(perf_conn_t *pc, const char *message) {
    if (!pc->failed) {
        snprintf(pc->failure_reason, sizeof(pc->failure_reason), "%s", message);
    }
    pc->failed = 1;
}

static void set_failure_liberr(perf_conn_t *pc, const char *context, int rv) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s: %s", context, ngtcp2_strerror(rv));
    set_failure(pc, buf);
}

static int is_terminal_conn_error(int rv) {
    return rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING || rv == NGTCP2_ERR_IDLE_CLOSE;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int resolve_address(struct sockaddr_storage *addr, socklen_t *addrlen, const char *host,
                           uint16_t port, int passive) {
    char service[32];
    snprintf(service, sizeof(service), "%u", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = passive ? AI_PASSIVE : 0;

    struct addrinfo *res = NULL;
    int rv =
        getaddrinfo((passive && strcmp(host, "0.0.0.0") == 0) ? NULL : host, service, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        if (rp->ai_addrlen <= sizeof(*addr)) {
            memcpy(addr, rp->ai_addr, rp->ai_addrlen);
            *addrlen = rp->ai_addrlen;
            freeaddrinfo(res);
            return 0;
        }
    }
    freeaddrinfo(res);
    return -1;
}

static int create_client_socket(perf_conn_t *pc) {
    if (resolve_address(&pc->remote_addr, &pc->remote_addrlen, pc->cfg.host, pc->cfg.port, 0) !=
        0) {
        set_failure(pc, "could not resolve server");
        return -1;
    }

    pc->fd = socket(pc->remote_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (pc->fd == -1) {
        set_failure(pc, strerror(errno));
        return -1;
    }
    if (connect(pc->fd, (struct sockaddr *)&pc->remote_addr, pc->remote_addrlen) != 0) {
        set_failure(pc, strerror(errno));
        return -1;
    }
    pc->local_addrlen = sizeof(pc->local_addr);
    if (getsockname(pc->fd, (struct sockaddr *)&pc->local_addr, &pc->local_addrlen) != 0) {
        set_failure(pc, strerror(errno));
        return -1;
    }
    if (set_nonblocking(pc->fd) != 0) {
        set_failure(pc, strerror(errno));
        return -1;
    }
    pc->owns_fd = 1;
    return 0;
}

static int create_server_socket(const config_t *cfg, struct sockaddr_storage *local_addr,
                                socklen_t *local_addrlen) {
    if (resolve_address(local_addr, local_addrlen, cfg->host, cfg->port, 1) != 0) {
        return -1;
    }
    int fd = socket(local_addr->ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        perror("socket");
        return -1;
    }
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, (socklen_t)sizeof(val));
    if (bind(fd, (struct sockaddr *)local_addr, *local_addrlen) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (set_nonblocking(fd) != 0) {
        perror("fcntl");
        close(fd);
        return -1;
    }
    socklen_t len = *local_addrlen;
    if (getsockname(fd, (struct sockaddr *)local_addr, &len) == 0) {
        *local_addrlen = len;
    }
    return fd;
}

static int numeric_host_family(const char *hostname, int family) {
    uint8_t dst[sizeof(struct in6_addr)];
    return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char *hostname) {
    return numeric_host_family(hostname, AF_INET) || numeric_host_family(hostname, AF_INET6);
}

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    const unsigned char proto[] = APPLICATION_PROTOCOL_WIRE;
    size_t proto_len = sizeof(proto) - 1;
    for (const unsigned char *p = in; p < in + inlen;) {
        if (p + 1 > in + inlen || p + 1 + *p > in + inlen) {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        if ((size_t)(*p + 1) == proto_len && memcmp(p, proto, proto_len) == 0) {
            *out = p + 1;
            *outlen = *p;
            return SSL_TLSEXT_ERR_OK;
        }
        p += *p + 1;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static SSL_CTX *make_client_ssl_ctx(const config_t *cfg) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        return NULL;
    }
    if (cfg->verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_load_verify_locations(ctx, cfg->certificate_chain, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    return ctx;
}

static SSL_CTX *make_server_ssl_ctx(const config_t *cfg) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, cfg->private_key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_certificate_chain_file(ctx, cfg->certificate_chain) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    return ctx;
}

static ngtcp2_conn *get_conn_from_ref(ngtcp2_crypto_conn_ref *conn_ref) {
    perf_conn_t *pc = conn_ref->user_data;
    return pc->conn;
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    if (RAND_bytes(dest, (int)destlen) != 1) {
        abort();
    }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                                    size_t cidlen, void *user_data) {
    (void)conn;
    (void)user_data;
    if (RAND_bytes(cid->data, (int)cidlen) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;
    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    (void)user_data;
    return 0;
}

static stream_ctx_t *conn_find_stream(perf_conn_t *pc, int64_t stream_id);
static void conn_remove_stream(perf_conn_t *pc, stream_ctx_t *stream);

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                           uint64_t app_error_code, void *user_data, void *stream_user_data) {
    (void)conn;
    (void)flags;
    (void)app_error_code;
    perf_conn_t *pc = user_data;
    stream_ctx_t *stream = stream_user_data;
    if (!stream) {
        stream = conn_find_stream(pc, stream_id);
    }
    if (stream) {
        if (pc->is_server) {
            ngtcp2_conn_extend_max_streams_bidi(conn, 1);
        }
        conn_remove_stream(pc, stream);
    }
    return 0;
}

static void conn_add_stream(perf_conn_t *pc, stream_ctx_t *stream) {
    stream->next = pc->streams;
    pc->streams = stream;
}

static void conn_remove_stream(perf_conn_t *pc, stream_ctx_t *stream) {
    stream_ctx_t **link = &pc->streams;
    while (*link) {
        if (*link == stream) {
            *link = stream->next;
            stream->next = NULL;
            free(stream->control_out);
            free(stream->control_in);
            free(stream->persistent_started_at);
            free(stream->persistent_counts);
            free(stream);
            return;
        }
        link = &(*link)->next;
    }
}

static stream_ctx_t *conn_find_stream(perf_conn_t *pc, int64_t stream_id) {
    for (stream_ctx_t *stream = pc->streams; stream; stream = stream->next) {
        if (stream->stream_id == stream_id) {
            return stream;
        }
    }
    return NULL;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    perf_conn_t *pc = user_data;
    if (!pc->is_server) {
        return 0;
    }
    stream_ctx_t *stream = calloc(1, sizeof(*stream));
    if (!stream) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    stream->conn = pc;
    stream->stream_id = stream_id;
    stream->is_control = stream_id == CONTROL_STREAM_ID;
    conn_add_stream(pc, stream);
    if (ngtcp2_conn_set_stream_user_data(conn, stream_id, stream) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static void maybe_count_client_stream(perf_conn_t *pc, stream_ctx_t *stream) {
    if (pc->is_server || stream->is_control || stream->counted || !stream->response_fin) {
        return;
    }
    if (stream->response_received != stream->response_bytes) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "ngtcp2-perf response byte count mismatch: got %" PRIu64 ", expected %" PRIu64,
                 stream->response_received, stream->response_bytes);
        set_failure(pc, buf);
        return;
    }
    stream->counted = 1;
    pc->counters->bytes_sent += stream->request_bytes;
    pc->counters->bytes_received += stream->response_bytes;
    ++pc->counters->requests_completed;
    ++pc->completed_requests;
    if (stream->counts_latency) {
        latency_push(&pc->counters->latencies, now_us() - stream->started_at);
    }
}

static int maybe_count_persistent_client_responses(perf_conn_t *pc, stream_ctx_t *stream) {
    while (stream->response_pending >= pc->cfg.response_bytes) {
        uint64_t started_at = 0;
        int counts_latency = 0;
        if (persistent_queue_pop(stream, &started_at, &counts_latency) != 0) {
            set_failure(pc, "ngtcp2 persistent-rr response without pending request");
            return -1;
        }
        stream->response_pending -= pc->cfg.response_bytes;
        pc->counters->bytes_sent += pc->cfg.request_bytes;
        pc->counters->bytes_received += pc->cfg.response_bytes;
        ++pc->counters->requests_completed;
        ++pc->completed_requests;
        if (counts_latency) {
            latency_push(&pc->counters->latencies, now_us() - started_at);
        }
    }
    return 0;
}

static int append_control_bytes(perf_conn_t *pc, stream_ctx_t *stream, const uint8_t *data,
                                size_t datalen) {
    if (datalen == 0) {
        return 0;
    }
    if (stream->control_in_len + datalen > stream->control_in_cap) {
        size_t next = stream->control_in_cap ? stream->control_in_cap * 2 : 128;
        while (next < stream->control_in_len + datalen) {
            next *= 2;
        }
        uint8_t *bytes = realloc(stream->control_in, next);
        if (!bytes) {
            set_failure(pc, "out of memory reading control stream");
            return -1;
        }
        stream->control_in = bytes;
        stream->control_in_cap = next;
    }
    memcpy(stream->control_in + stream->control_in_len, data, datalen);
    stream->control_in_len += datalen;
    return 0;
}

static void replace_control_output(perf_conn_t *pc, stream_ctx_t *stream, uint8_t *message,
                                   size_t len, int fin) {
    (void)pc;
    free(stream->control_out);
    stream->control_out = message;
    stream->control_len = len;
    stream->control_sent = 0;
    stream->control_fin = fin;
    stream->write_fin_sent = 0;
}

static int handle_server_control(perf_conn_t *pc, stream_ctx_t *stream, const uint8_t *data,
                                 size_t datalen) {
    if (append_control_bytes(pc, stream, data, datalen) != 0) {
        return -1;
    }
    if (stream->control_in_len < 5) {
        return 0;
    }
    uint32_t payload_len = decode_be32(stream->control_in + 1);
    if (stream->control_in_len < (size_t)payload_len + 5) {
        return 0;
    }

    size_t msg_len = 0;
    uint8_t *msg = NULL;
    if (stream->control_in[0] != MESSAGE_SESSION_START ||
        decode_session_start_payload(stream->control_in + 5, payload_len, &pc->session_start) !=
            0) {
        msg = encode_session_error_message("invalid session_start", &msg_len);
        replace_control_output(pc, stream, msg, msg_len, 1);
        if (!msg) {
            set_failure(pc, "could not encode session_error");
            return -1;
        }
        return 0;
    }

    msg = encode_session_ready_message(&msg_len);
    replace_control_output(pc, stream, msg, msg_len, 0);
    if (!msg) {
        set_failure(pc, "could not encode session_ready");
        return -1;
    }
    pc->session_ready = 1;
    return 0;
}

static int handle_client_control(perf_conn_t *pc, stream_ctx_t *stream, const uint8_t *data,
                                 size_t datalen) {
    if (append_control_bytes(pc, stream, data, datalen) != 0) {
        return -1;
    }
    if (stream->control_in_len < 5) {
        return 0;
    }
    uint32_t payload_len = decode_be32(stream->control_in + 1);
    if (stream->control_in_len < (size_t)payload_len + 5) {
        return 0;
    }
    uint8_t type = stream->control_in[0];
    const uint8_t *payload = stream->control_in + 5;
    if (type == MESSAGE_SESSION_READY && payload_len == 4 &&
        decode_be32(payload) == PERF_PROTOCOL_VERSION) {
        pc->session_ready = 1;
        return 0;
    }
    if (type == MESSAGE_SESSION_ERROR && payload_len >= 4) {
        uint32_t reason_len = decode_be32(payload);
        char reason[256];
        size_t copy = reason_len < sizeof(reason) - 1 ? reason_len : sizeof(reason) - 1;
        if (copy > payload_len - 4) {
            copy = payload_len - 4;
        }
        memcpy(reason, payload + 4, copy);
        reason[copy] = 0;
        set_failure(pc, reason[0] ? reason : "ngtcp2 server reported session_error");
        return -1;
    }
    if (type == MESSAGE_SESSION_COMPLETE) {
        return 0;
    }
    set_failure(pc, "unexpected ngtcp2 control message");
    return -1;
}

static void maybe_send_server_complete(perf_conn_t *pc) {
    if (!pc->is_server || pc->server_complete_sent) {
        return;
    }
    stream_ctx_t *control = conn_find_stream(pc, CONTROL_STREAM_ID);
    if (!control || control->write_fin_sent) {
        return;
    }
    size_t msg_len = 0;
    uint8_t *msg = encode_session_complete_message(pc->server_bytes_sent, pc->server_bytes_received,
                                                   pc->server_requests_completed, &msg_len);
    if (!msg) {
        set_failure(pc, "could not encode session_complete");
        return;
    }
    replace_control_output(pc, control, msg, msg_len, 1);
    pc->server_complete_sent = 1;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t offset, const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data) {
    (void)offset;
    perf_conn_t *pc = user_data;
    stream_ctx_t *stream = stream_user_data;
    if (!stream) {
        stream = conn_find_stream(pc, stream_id);
    }
    if (!stream) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (stream->is_control) {
        int rv = pc->is_server ? handle_server_control(pc, stream, data, datalen)
                               : handle_client_control(pc, stream, data, datalen);
        if (rv != 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
        ngtcp2_conn_extend_max_offset(conn, datalen);
        return 0;
    }

    if (pc->is_server) {
        if (!pc->session_start.started) {
            set_failure(pc, "data stream opened before session_start");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (!stream->server_shape_set) {
            stream->request_bytes = pc->session_start.request_bytes;
            stream->persistent_rr = pc->session_start.mode == MODE_CODE_PERSISTENT_RR;
            stream->response_bytes = stream->persistent_rr ? 0 : pc->session_start.response_bytes;
            stream->server_shape_set = 1;
        }
        stream->request_received += datalen;
        pc->server_bytes_received += datalen;
        if (stream->persistent_rr) {
            while (stream->request_received >= stream->request_bytes) {
                stream->request_received -= stream->request_bytes;
                ++pc->server_requests_completed;
                stream->response_bytes += pc->session_start.response_bytes;
                stream->server_ready_to_send = 1;
            }
            if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
                if (stream->request_received != 0) {
                    set_failure(pc, "ngtcp2 persistent-rr request byte count mismatch");
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
                stream->request_fin = 1;
                stream->server_ready_to_send = 1;
            }
        } else {
            if (stream->request_received >= stream->request_bytes) {
                stream->server_ready_to_send = 1;
            }
            if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
                stream->request_fin = 1;
                if (stream->request_received >= stream->request_bytes) {
                    stream->server_ready_to_send = 1;
                }
            }
        }
    } else {
        stream->response_received += datalen;
        if (stream->persistent_rr) {
            stream->response_pending += datalen;
            if (maybe_count_persistent_client_responses(pc, stream) != 0) {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
                if (stream->response_pending != 0 || stream->persistent_len != 0) {
                    set_failure(pc, "ngtcp2 persistent-rr stream closed with pending responses");
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
            }
            ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
            ngtcp2_conn_extend_max_offset(conn, datalen);
            return 0;
        }
        if (stream->response_received > stream->response_bytes) {
            set_failure(pc, "ngtcp2-perf received too many response bytes");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
            stream->response_fin = 1;
            maybe_count_client_stream(pc, stream);
        }
    }

    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn, datalen);
    return 0;
}

static ngtcp2_callbacks make_callbacks(int is_server) {
    ngtcp2_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.client_initial = is_server ? NULL : ngtcp2_crypto_client_initial_cb;
    callbacks.recv_client_initial = is_server ? ngtcp2_crypto_recv_client_initial_cb : NULL;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.handshake_completed = handshake_completed_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_stream_data = recv_stream_data_cb;
    callbacks.stream_open = stream_open_cb;
    callbacks.stream_close = stream_close_cb;
    callbacks.recv_retry = is_server ? NULL : ngtcp2_crypto_recv_retry_cb;
    callbacks.rand = rand_cb;
    callbacks.get_new_connection_id = get_new_connection_id_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.extend_max_stream_data = NULL;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    return callbacks;
}

static void configure_settings(ngtcp2_settings *settings, const config_t *cfg) {
    ngtcp2_settings_default(settings);
    settings->initial_ts = ngtcp2_now();
    settings->cc_algo = ngtcp2_cc(cfg->congestion_control);
    settings->max_window = TRANSFER_CONNECTION_WINDOW;
    settings->max_stream_window = TRANSFER_STREAM_WINDOW;
    settings->handshake_timeout = 10 * NGTCP2_SECONDS;
    settings->no_pmtud = cfg->disable_pmtud ? 1 : 0;
}

static void configure_transport_params(ngtcp2_transport_params *params) {
    ngtcp2_transport_params_default(params);
    params->initial_max_stream_data_bidi_local = TRANSFER_STREAM_WINDOW;
    params->initial_max_stream_data_bidi_remote = TRANSFER_STREAM_WINDOW;
    params->initial_max_stream_data_uni = TRANSFER_STREAM_WINDOW;
    params->initial_max_data = TRANSFER_CONNECTION_WINDOW;
    params->initial_max_streams_bidi = TRANSFER_MAX_STREAMS;
    params->initial_max_streams_uni = 0;
    params->max_idle_timeout = 30 * NGTCP2_SECONDS;
    params->max_udp_payload_size = 65527;
    params->active_connection_id_limit = 7;
}

static int init_client_quic(perf_conn_t *pc) {
    pc->ssl_ctx = make_client_ssl_ctx(&pc->cfg);
    if (!pc->ssl_ctx) {
        set_failure(pc, "could not initialize client TLS context");
        return -1;
    }
    pc->ssl = SSL_new(pc->ssl_ctx);
    if (!pc->ssl) {
        set_failure(pc, "SSL_new failed");
        return -1;
    }
    pc->conn_ref.get_conn = get_conn_from_ref;
    pc->conn_ref.user_data = pc;
    SSL_set_app_data(pc->ssl, &pc->conn_ref);
    if (ngtcp2_crypto_ossl_ctx_new(&pc->ssl_native_ctx, pc->ssl) != 0) {
        set_failure(pc, "ngtcp2_crypto_ossl_ctx_new failed");
        return -1;
    }
    if (ngtcp2_crypto_ossl_configure_client_session(pc->ssl) != 0) {
        set_failure(pc, "ngtcp2_crypto_ossl_configure_client_session failed");
        return -1;
    }
    SSL_set_connect_state(pc->ssl);
    SSL_set_alpn_protos(pc->ssl, (const unsigned char *)APPLICATION_PROTOCOL_WIRE,
                        sizeof(APPLICATION_PROTOCOL_WIRE) - 1);
    if (!numeric_host(pc->cfg.server_name)) {
        SSL_set_tlsext_host_name(pc->ssl, pc->cfg.server_name);
    }

    ngtcp2_cid dcid;
    ngtcp2_cid scid;
    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    scid.datalen = SERVER_CID_LEN;
    if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1 ||
        RAND_bytes(scid.data, (int)scid.datalen) != 1) {
        set_failure(pc, "RAND_bytes failed");
        return -1;
    }

    ngtcp2_path path;
    memset(&path, 0, sizeof(path));
    path.local.addr = (struct sockaddr *)&pc->local_addr;
    path.local.addrlen = pc->local_addrlen;
    path.remote.addr = (struct sockaddr *)&pc->remote_addr;
    path.remote.addrlen = pc->remote_addrlen;

    ngtcp2_callbacks callbacks = make_callbacks(0);
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    configure_settings(&settings, &pc->cfg);
    configure_transport_params(&params);

    int rv = ngtcp2_conn_client_new(&pc->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &callbacks,
                                    &settings, &params, NULL, pc);
    if (rv != 0) {
        set_failure_liberr(pc, "ngtcp2_conn_client_new", rv);
        return -1;
    }
    ngtcp2_conn_set_tls_native_handle(pc->conn, pc->ssl_native_ctx);
    return 0;
}

static int init_server_conn(perf_conn_t *pc, SSL_CTX *ssl_ctx, const ngtcp2_pkt_hd *hd,
                            const struct sockaddr *local_addr, socklen_t local_addrlen,
                            const struct sockaddr *remote_addr, socklen_t remote_addrlen,
                            uint32_t version) {
    pc->is_server = 1;
    pc->ssl_ctx = ssl_ctx;
    pc->ssl = SSL_new(ssl_ctx);
    if (!pc->ssl) {
        set_failure(pc, "SSL_new failed");
        return -1;
    }
    pc->conn_ref.get_conn = get_conn_from_ref;
    pc->conn_ref.user_data = pc;
    SSL_set_app_data(pc->ssl, &pc->conn_ref);
    if (ngtcp2_crypto_ossl_ctx_new(&pc->ssl_native_ctx, pc->ssl) != 0) {
        set_failure(pc, "ngtcp2_crypto_ossl_ctx_new failed");
        return -1;
    }
    if (ngtcp2_crypto_ossl_configure_server_session(pc->ssl) != 0) {
        set_failure(pc, "ngtcp2_crypto_ossl_configure_server_session failed");
        return -1;
    }
    SSL_set_accept_state(pc->ssl);

    memcpy(&pc->local_addr, local_addr, local_addrlen);
    pc->local_addrlen = local_addrlen;
    memcpy(&pc->remote_addr, remote_addr, remote_addrlen);
    pc->remote_addrlen = remote_addrlen;

    ngtcp2_cid scid;
    scid.datalen = SERVER_CID_LEN;
    if (RAND_bytes(scid.data, (int)scid.datalen) != 1) {
        set_failure(pc, "RAND_bytes failed");
        return -1;
    }

    ngtcp2_path path;
    memset(&path, 0, sizeof(path));
    path.local.addr = (struct sockaddr *)&pc->local_addr;
    path.local.addrlen = pc->local_addrlen;
    path.remote.addr = (struct sockaddr *)&pc->remote_addr;
    path.remote.addrlen = pc->remote_addrlen;

    ngtcp2_callbacks callbacks = make_callbacks(1);
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    configure_settings(&settings, &pc->cfg);
    configure_transport_params(&params);
    params.original_dcid = hd->dcid;
    params.original_dcid_present = 1;
    params.stateless_reset_token_present = 1;
    if (RAND_bytes(params.stateless_reset_token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        set_failure(pc, "RAND_bytes failed");
        return -1;
    }

    int rv = ngtcp2_conn_server_new(&pc->conn, &hd->scid, &scid, &path, version, &callbacks,
                                    &settings, &params, NULL, pc);
    if (rv != 0) {
        set_failure_liberr(pc, "ngtcp2_conn_server_new", rv);
        return -1;
    }
    ngtcp2_conn_set_tls_native_handle(pc->conn, pc->ssl_native_ctx);
    return 0;
}

static void free_streams(stream_ctx_t *stream) {
    while (stream) {
        stream_ctx_t *next = stream->next;
        free(stream->control_out);
        free(stream->control_in);
        free(stream->persistent_started_at);
        free(stream->persistent_counts);
        free(stream);
        stream = next;
    }
}

static int persistent_queue_push(stream_ctx_t *stream, uint64_t started_at, int counts_latency) {
    if (stream->persistent_len == stream->persistent_cap) {
        size_t new_cap = stream->persistent_cap ? stream->persistent_cap * 2 : 8;
        uint64_t *new_started = malloc(new_cap * sizeof(new_started[0]));
        uint8_t *new_counts = malloc(new_cap * sizeof(new_counts[0]));
        if (!new_started || !new_counts) {
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
    stream->persistent_counts[index] = counts_latency ? 1 : 0;
    ++stream->persistent_len;
    return 0;
}

static int persistent_queue_pop(stream_ctx_t *stream, uint64_t *started_at, int *counts_latency) {
    if (stream->persistent_len == 0) {
        return -1;
    }
    *started_at = stream->persistent_started_at[stream->persistent_head];
    *counts_latency = stream->persistent_counts[stream->persistent_head] != 0;
    stream->persistent_head = (stream->persistent_head + 1) % stream->persistent_cap;
    --stream->persistent_len;
    return 0;
}

static void free_conn(perf_conn_t *pc, int free_ssl_ctx) {
    if (!pc) {
        return;
    }
    if (pc->conn) {
        ngtcp2_conn_del(pc->conn);
    }
    if (pc->ssl) {
        SSL_set_app_data(pc->ssl, NULL);
        SSL_free(pc->ssl);
    }
    if (pc->ssl_native_ctx) {
        ngtcp2_crypto_ossl_ctx_del(pc->ssl_native_ctx);
    }
    if (free_ssl_ctx && pc->ssl_ctx) {
        SSL_CTX_free(pc->ssl_ctx);
    }
    if (pc->owns_fd && pc->fd != -1) {
        close(pc->fd);
    }
    free_streams(pc->streams);
    free(pc);
}

static int send_packet_fd(int fd, const struct sockaddr *remote, socklen_t remote_len,
                          const uint8_t *data, size_t datalen) {
    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (uint8_t *)data;
    iov.iov_len = datalen;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (remote) {
        msg.msg_name = (struct sockaddr *)remote;
        msg.msg_namelen = remote_len;
    }
    ssize_t nwrite;
    do {
        nwrite = sendmsg(fd, &msg, 0);
    } while (nwrite == -1 && errno == EINTR);
    return nwrite == (ssize_t)datalen ? 0 : -1;
}

static int select_writable_stream(perf_conn_t *pc, int64_t *stream_id, ngtcp2_vec *datav,
                                  uint32_t *flags) {
    static uint8_t zeros[WRITE_CHUNK_SIZE];
    *stream_id = -1;
    datav->base = NULL;
    datav->len = 0;
    *flags = NGTCP2_WRITE_STREAM_FLAG_NONE;

    for (stream_ctx_t *stream = pc->streams; stream; stream = stream->next) {
        if (stream->is_control) {
            if (stream->write_fin_sent) {
                continue;
            }
            if (stream->control_sent >= stream->control_len && !stream->control_fin) {
                continue;
            }
            *stream_id = stream->stream_id;
            if (stream->control_sent < stream->control_len) {
                uint64_t left = stream->control_len - stream->control_sent;
                size_t chunk = left > sizeof(zeros) ? sizeof(zeros) : (size_t)left;
                datav->base = stream->control_out + stream->control_sent;
                datav->len = chunk;
                if (chunk == left && stream->control_fin) {
                    *flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                }
                return 1;
            }
            if (stream->control_fin) {
                *flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                return 1;
            }
            continue;
        }
        if (pc->is_server) {
            if (!stream->server_ready_to_send || stream->write_fin_sent) {
                continue;
            }
            if (stream->persistent_rr && stream->response_sent >= stream->response_bytes &&
                !stream->request_fin) {
                continue;
            }
            *stream_id = stream->stream_id;
            if (stream->response_sent < stream->response_bytes) {
                uint64_t left = stream->response_bytes - stream->response_sent;
                size_t chunk = left > sizeof(zeros) ? sizeof(zeros) : (size_t)left;
                datav->base = zeros;
                datav->len = chunk;
                if (chunk == left && (!stream->persistent_rr || stream->request_fin)) {
                    *flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                }
                return 1;
            }
            if (stream->persistent_rr && !stream->request_fin) {
                continue;
            }
            *flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            return 1;
        }

        if (stream->write_fin_sent) {
            continue;
        }
        if (stream->persistent_rr && stream->request_sent >= stream->request_bytes &&
            !stream->request_fin) {
            continue;
        }
        *stream_id = stream->stream_id;
        if (stream->request_sent < stream->request_bytes) {
            uint64_t left = stream->request_bytes - stream->request_sent;
            size_t chunk = left > sizeof(zeros) ? sizeof(zeros) : (size_t)left;
            datav->base = zeros;
            datav->len = chunk;
            if (chunk == left && (!stream->persistent_rr || stream->request_fin)) {
                *flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            }
            return 1;
        }
        if (stream->persistent_rr && !stream->request_fin) {
            continue;
        }
        *flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        return 1;
    }
    return 0;
}

static void note_stream_write(perf_conn_t *pc, int64_t stream_id, ngtcp2_ssize wdatalen,
                              size_t datalen, uint32_t flags) {
    if (stream_id < 0) {
        return;
    }
    stream_ctx_t *stream = conn_find_stream(pc, stream_id);
    if (!stream) {
        return;
    }
    uint64_t written = wdatalen > 0 ? (uint64_t)wdatalen : 0;
    if (stream->is_control) {
        stream->control_sent += (size_t)written;
    } else if (pc->is_server) {
        stream->response_sent += written;
        pc->server_bytes_sent += written;
    } else {
        stream->request_sent += written;
    }
    if ((flags & NGTCP2_WRITE_STREAM_FLAG_FIN) && (datalen == 0 || written >= datalen)) {
        if (pc->is_server && !stream->is_control && !stream->persistent_rr &&
            !stream->write_fin_sent) {
            ++pc->server_requests_completed;
        }
        stream->write_fin_sent = 1;
    }
}

static int conn_write(perf_conn_t *pc) {
    uint8_t buf[UDP_PAYLOAD_SIZE];
    ngtcp2_tstamp ts = ngtcp2_now();

    for (;;) {
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi;
        memset(&pi, 0, sizeof(pi));
        ngtcp2_vec datav;
        int64_t stream_id;
        uint32_t flags;
        int has_data = select_writable_stream(pc, &stream_id, &datav, &flags);
        ngtcp2_ssize wdatalen = 0;
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            pc->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen, flags, stream_id,
            has_data && datav.base ? &datav : NULL, has_data && datav.base ? 1 : 0, ts);
        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
                nwrite == NGTCP2_ERR_STREAM_ID_BLOCKED) {
                return 0;
            }
            set_failure_liberr(pc, "ngtcp2_conn_writev_stream", (int)nwrite);
            return -1;
        }
        if (nwrite == 0) {
            return 0;
        }
        note_stream_write(pc, stream_id, wdatalen, has_data && datav.base ? datav.len : 0, flags);

        const struct sockaddr *remote = NULL;
        socklen_t remote_len = 0;
        if (pc->is_server) {
            remote =
                ps.path.remote.addr ? ps.path.remote.addr : (struct sockaddr *)&pc->remote_addr;
            remote_len = ps.path.remote.addr ? ps.path.remote.addrlen : pc->remote_addrlen;
        }
        if (send_packet_fd(pc->fd, remote, remote_len, buf, (size_t)nwrite) != 0) {
            set_failure(pc, strerror(errno));
            return -1;
        }
    }
}

static int conn_read_client(perf_conn_t *pc) {
    uint8_t buf[READ_BUF_SIZE];
    for (;;) {
        ssize_t nread = recv(pc->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (nread == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            set_failure(pc, strerror(errno));
            return -1;
        }
        ngtcp2_path path;
        memset(&path, 0, sizeof(path));
        path.local.addr = (struct sockaddr *)&pc->local_addr;
        path.local.addrlen = pc->local_addrlen;
        path.remote.addr = (struct sockaddr *)&pc->remote_addr;
        path.remote.addrlen = pc->remote_addrlen;
        ngtcp2_pkt_info pi;
        memset(&pi, 0, sizeof(pi));
        int rv = ngtcp2_conn_read_pkt(pc->conn, &path, &pi, buf, (size_t)nread, ngtcp2_now());
        if (rv != 0) {
            if (is_terminal_conn_error(rv)) {
                pc->closed = 1;
                return 0;
            }
            set_failure_liberr(pc, "ngtcp2_conn_read_pkt", rv);
            return -1;
        }
    }
}

static int open_request_stream(perf_conn_t *pc, uint64_t request_bytes, uint64_t response_bytes,
                               int counts_latency) {
    stream_ctx_t *stream = calloc(1, sizeof(*stream));
    if (!stream) {
        set_failure(pc, "out of memory");
        return -1;
    }
    stream->conn = pc;
    stream->request_bytes = request_bytes;
    stream->response_bytes = response_bytes;
    stream->started_at = now_us();
    stream->counts_latency = counts_latency;
    int rv = ngtcp2_conn_open_bidi_stream(pc->conn, &stream->stream_id, stream);
    if (rv != 0) {
        free(stream);
        set_failure_liberr(pc, "ngtcp2_conn_open_bidi_stream", rv);
        return -1;
    }
    conn_add_stream(pc, stream);
    ++pc->started_requests;
    return 0;
}

static stream_ctx_t *find_persistent_rr_stream(perf_conn_t *pc) {
    for (stream_ctx_t *stream = pc->streams; stream; stream = stream->next) {
        if (!stream->is_control && stream->persistent_rr) {
            return stream;
        }
    }
    return NULL;
}

static int send_persistent_rr_request(perf_conn_t *pc, int counts_latency) {
    stream_ctx_t *stream = find_persistent_rr_stream(pc);
    if (!stream) {
        stream = calloc(1, sizeof(*stream));
        if (!stream) {
            set_failure(pc, "out of memory");
            return -1;
        }
        stream->conn = pc;
        stream->response_bytes = pc->cfg.response_bytes;
        stream->persistent_rr = 1;
        int rv = ngtcp2_conn_open_bidi_stream(pc->conn, &stream->stream_id, stream);
        if (rv != 0) {
            free(stream);
            set_failure_liberr(pc, "ngtcp2_conn_open_bidi_stream persistent-rr", rv);
            return -1;
        }
        conn_add_stream(pc, stream);
    }
    if (persistent_queue_push(stream, now_us(), counts_latency) != 0) {
        set_failure(pc, "out of memory");
        return -1;
    }
    stream->request_bytes += pc->cfg.request_bytes;
    stream->write_fin_sent = 0;
    ++pc->started_requests;
    return 0;
}

static int open_control_stream(perf_conn_t *pc, uint64_t request_bytes, uint64_t response_bytes) {
    stream_ctx_t *stream = calloc(1, sizeof(*stream));
    if (!stream) {
        set_failure(pc, "out of memory");
        return -1;
    }
    stream->conn = pc;
    stream->is_control = 1;
    stream->control_fin = 1;
    stream->control_out =
        encode_session_start_message(&pc->cfg, request_bytes, response_bytes, &stream->control_len);
    if (!stream->control_out) {
        free(stream);
        set_failure(pc, "could not encode session_start");
        return -1;
    }
    int rv = ngtcp2_conn_open_bidi_stream(pc->conn, &stream->stream_id, stream);
    if (rv != 0) {
        free(stream->control_out);
        free(stream);
        set_failure_liberr(pc, "ngtcp2_conn_open_bidi_stream control", rv);
        return -1;
    }
    if (stream->stream_id != CONTROL_STREAM_ID) {
        free(stream->control_out);
        free(stream);
        set_failure(pc, "unexpected ngtcp2 control stream id");
        return -1;
    }
    conn_add_stream(pc, stream);
    return 0;
}

static int ensure_session_ready(perf_conn_t *pc, uint64_t request_bytes, uint64_t response_bytes,
                                uint64_t started_at) {
    if (pc->session_ready) {
        return 0;
    }
    if (ngtcp2_conn_get_handshake_completed(pc->conn) && !conn_find_stream(pc, CONTROL_STREAM_ID)) {
        if (open_control_stream(pc, request_bytes, response_bytes) != 0) {
            return -1;
        }
    }
    if (now_us() - started_at > HANDSHAKE_TIMEOUT_US) {
        set_failure(pc, "ngtcp2 session_ready timed out");
        return -1;
    }
    return 0;
}

static uint64_t active_requests(const perf_conn_t *pc) {
    return pc->started_requests - pc->completed_requests;
}

static int init_client_conn(const config_t *cfg, counters_t *counters, perf_conn_t **out,
                            char *failure_reason, size_t failure_reason_len) {
    perf_conn_t *pc = calloc(1, sizeof(*pc));
    if (!pc) {
        snprintf(failure_reason, failure_reason_len, "out of memory");
        return -1;
    }
    pc->fd = -1;
    pc->cfg = *cfg;
    pc->counters = counters;
    pc->started_at = now_us();
    ngtcp2_ccerr_default(&pc->last_error);
    if (create_client_socket(pc) != 0 || init_client_quic(pc) != 0) {
        snprintf(failure_reason, failure_reason_len, "%s", pc->failure_reason);
        free_conn(pc, 1);
        return -1;
    }
    *out = pc;
    return 0;
}

static int open_streams_to_active(perf_conn_t *pc, uint64_t target_active, uint64_t request_bytes,
                                  uint64_t response_bytes, int counts_latency, uint64_t *started,
                                  uint64_t limit) {
    while (active_requests(pc) < target_active) {
        if (started && limit != UINT64_MAX && *started >= limit) {
            break;
        }
        if (open_request_stream(pc, request_bytes, response_bytes, counts_latency) != 0) {
            return -1;
        }
        if (started) {
            ++*started;
        }
    }
    return 0;
}

static int wait_client_connections(perf_conn_t **conns, size_t count, uint64_t max_wait_us,
                                   char *failure_reason, size_t failure_reason_len) {
    fd_set readfds;
    FD_ZERO(&readfds);
    int maxfd = -1;
    uint64_t timeout_us = max_wait_us;
    uint64_t now = ngtcp2_now();
    for (size_t i = 0; i < count; ++i) {
        perf_conn_t *pc = conns[i];
        if (!pc || pc->closed) {
            continue;
        }
        if (pc->fd >= FD_SETSIZE) {
            snprintf(failure_reason, failure_reason_len,
                     "ngtcp2 connection fd exceeds select limit");
            return -1;
        }
        FD_SET(pc->fd, &readfds);
        if (pc->fd > maxfd) {
            maxfd = pc->fd;
        }
        ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(pc->conn);
        if (expiry <= now) {
            timeout_us = 0;
        } else {
            uint64_t delta = (uint64_t)((expiry - now) / 1000);
            if (delta < timeout_us) {
                timeout_us = delta;
            }
        }
    }
    if (maxfd < 0) {
        return 0;
    }
    struct timeval tv;
    tv.tv_sec = (time_t)(timeout_us / 1000000ULL);
    tv.tv_usec = (suseconds_t)(timeout_us % 1000000ULL);
    int sret;
    do {
        sret = select(maxfd + 1, &readfds, NULL, NULL, &tv);
    } while (sret == -1 && errno == EINTR);
    if (sret < 0) {
        snprintf(failure_reason, failure_reason_len, "%s", strerror(errno));
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        perf_conn_t *pc = conns[i];
        if (pc && FD_ISSET(pc->fd, &readfds) && conn_read_client(pc) != 0) {
            snprintf(failure_reason, failure_reason_len, "%s", pc->failure_reason);
            return -1;
        }
    }
    return 0;
}

static int drive_client_connections_once(perf_conn_t **conns, size_t count, uint64_t max_wait_us,
                                         char *failure_reason, size_t failure_reason_len) {
    for (size_t i = 0; i < count; ++i) {
        perf_conn_t *pc = conns[i];
        if (!pc || pc->closed) {
            continue;
        }
        if (conn_write(pc) != 0) {
            snprintf(failure_reason, failure_reason_len, "%s", pc->failure_reason);
            return -1;
        }
        uint64_t now = ngtcp2_now();
        if (ngtcp2_conn_get_expiry(pc->conn) <= now) {
            int rv = ngtcp2_conn_handle_expiry(pc->conn, now);
            if (rv != 0) {
                if (is_terminal_conn_error(rv)) {
                    pc->closed = 1;
                    continue;
                }
                set_failure_liberr(pc, "ngtcp2_conn_handle_expiry", rv);
                snprintf(failure_reason, failure_reason_len, "%s", pc->failure_reason);
                return -1;
            }
        }
    }
    return wait_client_connections(conns, count, max_wait_us, failure_reason, failure_reason_len);
}

static void free_client_connections(perf_conn_t **conns, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (conns[i]) {
            free_conn(conns[i], 1);
            conns[i] = NULL;
        }
    }
}

static int refill_rr_connections(perf_conn_t **conns, size_t count, const config_t *cfg,
                                 uint64_t *started, uint64_t limit, uint64_t deadline,
                                 char *failure_reason, size_t failure_reason_len) {
    for (size_t i = 0; i < count; ++i) {
        perf_conn_t *pc = conns[i];
        if (!pc || !pc->session_ready) {
            continue;
        }
        while (active_requests(pc) < cfg->requests_in_flight) {
            if (limit != UINT64_MAX) {
                if (*started >= limit) {
                    return 0;
                }
                if (pc->started_requests >= rr_request_limit_for_connection(cfg, (uint64_t)i)) {
                    break;
                }
            }
            if (deadline != 0 && now_us() >= deadline) {
                return 0;
            }
            if (is_mode(cfg, "persistent-rr")) {
                if (send_persistent_rr_request(pc, 1) != 0) {
                    snprintf(failure_reason, failure_reason_len, "%s", pc->failure_reason);
                    return -1;
                }
            } else if (open_request_stream(pc, cfg->request_bytes, cfg->response_bytes, 1) != 0) {
                snprintf(failure_reason, failure_reason_len, "%s", pc->failure_reason);
                return -1;
            }
            ++*started;
        }
    }
    return 0;
}

static int all_connections_ready(perf_conn_t **conns, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (!conns[i] || !conns[i]->session_ready) {
            return 0;
        }
    }
    return 1;
}

static uint64_t total_active_requests(perf_conn_t **conns, size_t count) {
    uint64_t active = 0;
    for (size_t i = 0; i < count; ++i) {
        if (conns[i]) {
            active += active_requests(conns[i]);
        }
    }
    return active;
}

static uint64_t total_completed_requests(perf_conn_t **conns, size_t count) {
    uint64_t completed = 0;
    for (size_t i = 0; i < count; ++i) {
        if (conns[i]) {
            completed += conns[i]->completed_requests;
        }
    }
    return completed;
}

static perf_conn_t **open_client_connections(const config_t *cfg, counters_t *counters,
                                             uint64_t request_bytes, uint64_t response_bytes,
                                             size_t *count, char *failure_reason,
                                             size_t failure_reason_len) {
    *count = (size_t)cfg->connections;
    perf_conn_t **conns = calloc(*count, sizeof(conns[0]));
    if (!conns) {
        snprintf(failure_reason, failure_reason_len, "out of memory");
        return NULL;
    }
    for (size_t i = 0; i < *count; ++i) {
        config_t connection_cfg = *cfg;
        if ((is_mode(cfg, "rr") || is_mode(cfg, "persistent-rr")) && cfg->requests.set) {
            connection_cfg.requests.value = rr_request_limit_for_connection(cfg, (uint64_t)i);
            connection_cfg.requests.set = 1;
        }
        if (init_client_conn(&connection_cfg, counters, &conns[i], failure_reason,
                             failure_reason_len) != 0) {
            free_client_connections(conns, *count);
            free(conns);
            return NULL;
        }
    }
    uint64_t started_at = now_us();
    while (!all_connections_ready(conns, *count)) {
        for (size_t i = 0; i < *count; ++i) {
            if (ensure_session_ready(conns[i], request_bytes, response_bytes, started_at) != 0) {
                snprintf(failure_reason, failure_reason_len, "%s", conns[i]->failure_reason);
                free_client_connections(conns, *count);
                free(conns);
                return NULL;
            }
        }
        if (drive_client_connections_once(conns, *count, 100000, failure_reason,
                                          failure_reason_len) != 0) {
            free_client_connections(conns, *count);
            free(conns);
            return NULL;
        }
    }
    return conns;
}

static int open_batch_distributed(perf_conn_t **conns, size_t count, uint64_t request_count,
                                  uint64_t request_bytes, uint64_t response_bytes,
                                  int counts_latency, char *failure_reason,
                                  size_t failure_reason_len) {
    for (uint64_t i = 0; i < request_count; ++i) {
        perf_conn_t *pc = conns[i % count];
        if (open_request_stream(pc, request_bytes, response_bytes, counts_latency) != 0) {
            snprintf(failure_reason, failure_reason_len, "%s", pc->failure_reason);
            return -1;
        }
    }
    return 0;
}

static void send_connection_close(perf_conn_t *pc) {
    if (!pc->is_server) {
        for (stream_ctx_t *stream = pc->streams; stream; stream = stream->next) {
            if (!stream->is_control && stream->persistent_rr && !stream->request_fin) {
                stream->request_fin = 1;
                stream->write_fin_sent = 0;
            }
        }
        (void)conn_write(pc);
    }
    if (pc->is_server) {
        maybe_send_server_complete(pc);
        (void)conn_write(pc);
    }
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi;
    memset(&pi, 0, sizeof(pi));
    uint8_t buf[UDP_PAYLOAD_SIZE];
    ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
        pc->conn, &ps.path, &pi, buf, sizeof(buf), &pc->last_error, ngtcp2_now());
    if (nwrite > 0) {
        send_packet_fd(pc->fd, NULL, 0, buf, (size_t)nwrite);
    }
}

static int crr_can_start_connection(const config_t *cfg, uint64_t started, uint64_t deadline) {
    if (cfg->requests.set) {
        return started < cfg->requests.value;
    }
    return now_us() < deadline;
}

static size_t active_crr_connection_count(perf_conn_t **slots, size_t count) {
    size_t active = 0;
    for (size_t i = 0; i < count; ++i) {
        if (slots[i]) {
            ++active;
        }
    }
    return active;
}

static int run_request_batch(const config_t *cfg, uint64_t count, uint64_t request_bytes,
                             uint64_t response_bytes, counters_t *counters, int counts_latency,
                             char *failure_reason, size_t failure_reason_len) {
    if (count == 0) {
        return 0;
    }
    if (count > DEFAULT_MAX_RUN_REQUESTS) {
        count = DEFAULT_MAX_RUN_REQUESTS;
    }

    size_t conn_count = 0;
    perf_conn_t **conns = open_client_connections(cfg, counters, request_bytes, response_bytes,
                                                  &conn_count, failure_reason, failure_reason_len);
    if (!conns) {
        return -1;
    }
    if (open_batch_distributed(conns, conn_count, count, request_bytes, response_bytes,
                               counts_latency, failure_reason, failure_reason_len) != 0) {
        free_client_connections(conns, conn_count);
        free(conns);
        return -1;
    }
    uint64_t hard_deadline = now_us() + BATCH_TIMEOUT_US;
    while (total_completed_requests(conns, conn_count) < count) {
        if (now_us() >= hard_deadline) {
            snprintf(failure_reason, failure_reason_len,
                     "ngtcp2-perf completed %" PRIu64 " of %" PRIu64 " requests",
                     total_completed_requests(conns, conn_count), count);
            free_client_connections(conns, conn_count);
            free(conns);
            return -1;
        }
        if (drive_client_connections_once(conns, conn_count, 100000, failure_reason,
                                          failure_reason_len) != 0) {
            break;
        }
    }
    int rc = total_completed_requests(conns, conn_count) == count ? 0 : -1;
    if (rc == 0) {
        for (size_t i = 0; i < conn_count; ++i) {
            send_connection_close(conns[i]);
        }
    }
    free_client_connections(conns, conn_count);
    free(conns);
    return rc;
}

static int run_timed_bulk(const config_t *cfg, uint64_t request_bytes, uint64_t response_bytes,
                          counters_t *counters, char *failure_reason, size_t failure_reason_len) {
    size_t conn_count = 0;
    perf_conn_t **conns = open_client_connections(cfg, counters, request_bytes, response_bytes,
                                                  &conn_count, failure_reason, failure_reason_len);
    if (!conns) {
        return -1;
    }
    uint64_t started_at = now_us();
    uint64_t deadline = started_at + cfg->duration_us;
    uint64_t drain_deadline = deadline + DRAIN_TIMEOUT_US;
    while (now_us() <= drain_deadline) {
        uint64_t now = now_us();
        if (now < deadline) {
            for (size_t i = 0; i < conn_count; ++i) {
                if (open_streams_to_active(conns[i], cfg->streams, request_bytes, response_bytes, 0,
                                           NULL, UINT64_MAX) != 0) {
                    snprintf(failure_reason, failure_reason_len, "%s", conns[i]->failure_reason);
                    free_client_connections(conns, conn_count);
                    free(conns);
                    return -1;
                }
            }
        } else if (total_active_requests(conns, conn_count) == 0) {
            break;
        }
        if (drive_client_connections_once(conns, conn_count, 100000, failure_reason,
                                          failure_reason_len) != 0) {
            free_client_connections(conns, conn_count);
            free(conns);
            return -1;
        }
    }
    for (size_t i = 0; i < conn_count; ++i) {
        send_connection_close(conns[i]);
    }
    free_client_connections(conns, conn_count);
    free(conns);
    return 0;
}

static int run_bulk(const config_t *cfg, counters_t *counters, char *failure_reason,
                    size_t failure_reason_len) {
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t unit;
    if (is_direction(cfg, "upload")) {
        request_bytes =
            cfg->request_bytes > cfg->response_bytes ? cfg->request_bytes : cfg->response_bytes;
        response_bytes = 0;
        unit = request_bytes ? request_bytes : 1;
    } else {
        request_bytes = cfg->request_bytes;
        response_bytes = cfg->response_bytes;
        unit = response_bytes ? response_bytes : 1;
    }

    if (cfg->total_bytes.set) {
        uint64_t count = ceil_div(cfg->total_bytes.value, unit);
        if (count == 0) {
            count = 1;
        }
        return run_request_batch(cfg, count, request_bytes, response_bytes, counters, 0,
                                 failure_reason, failure_reason_len);
    }

    return run_timed_bulk(cfg, request_bytes, response_bytes, counters, failure_reason,
                          failure_reason_len);
}

static int run_rr(const config_t *cfg, counters_t *counters, char *failure_reason,
                  size_t failure_reason_len) {
    if (cfg->requests.set) {
        config_t request_cfg = *cfg;
        request_cfg.connections = rr_connection_target(cfg);
        size_t conn_count = 0;
        perf_conn_t **conns =
            open_client_connections(&request_cfg, counters, cfg->request_bytes, cfg->response_bytes,
                                    &conn_count, failure_reason, failure_reason_len);
        if (!conns) {
            return -1;
        }
        uint64_t started = 0;
        if (refill_rr_connections(conns, conn_count, cfg, &started, cfg->requests.value, 0,
                                  failure_reason, failure_reason_len) != 0) {
            free_client_connections(conns, conn_count);
            free(conns);
            return -1;
        }
        uint64_t hard_deadline = now_us() + BATCH_TIMEOUT_US;
        while (total_completed_requests(conns, conn_count) < cfg->requests.value ||
               total_active_requests(conns, conn_count) != 0) {
            if (now_us() >= hard_deadline) {
                snprintf(failure_reason, failure_reason_len,
                         "ngtcp2-perf completed %" PRIu64 " of %" PRIu64 " requests",
                         total_completed_requests(conns, conn_count), cfg->requests.value);
                free_client_connections(conns, conn_count);
                free(conns);
                return -1;
            }
            if (drive_client_connections_once(conns, conn_count, 100000, failure_reason,
                                              failure_reason_len) != 0 ||
                refill_rr_connections(conns, conn_count, cfg, &started, cfg->requests.value, 0,
                                      failure_reason, failure_reason_len) != 0) {
                free_client_connections(conns, conn_count);
                free(conns);
                return -1;
            }
        }
        for (size_t i = 0; i < conn_count; ++i) {
            send_connection_close(conns[i]);
        }
        free_client_connections(conns, conn_count);
        free(conns);
        return 0;
    }

    size_t conn_count = 0;
    perf_conn_t **conns =
        open_client_connections(cfg, counters, cfg->request_bytes, cfg->response_bytes, &conn_count,
                                failure_reason, failure_reason_len);
    if (!conns) {
        return -1;
    }
    uint64_t started = 0;
    uint64_t deadline = now_us() + cfg->duration_us;
    uint64_t drain_deadline = deadline + DRAIN_TIMEOUT_US;
    if (refill_rr_connections(conns, conn_count, cfg, &started, UINT64_MAX, deadline,
                              failure_reason, failure_reason_len) != 0) {
        free_client_connections(conns, conn_count);
        free(conns);
        return -1;
    }
    while (now_us() <= drain_deadline) {
        uint64_t now = now_us();
        if (now < deadline) {
            if (refill_rr_connections(conns, conn_count, cfg, &started, UINT64_MAX, deadline,
                                      failure_reason, failure_reason_len) != 0) {
                free_client_connections(conns, conn_count);
                free(conns);
                return -1;
            }
        } else if (total_active_requests(conns, conn_count) == 0) {
            break;
        }
        if (drive_client_connections_once(conns, conn_count, 100000, failure_reason,
                                          failure_reason_len) != 0) {
            free_client_connections(conns, conn_count);
            free(conns);
            return -1;
        }
    }
    for (size_t i = 0; i < conn_count; ++i) {
        send_connection_close(conns[i]);
    }
    free_client_connections(conns, conn_count);
    free(conns);
    return 0;
}

static int run_crr(const config_t *cfg, counters_t *counters, char *failure_reason,
                   size_t failure_reason_len) {
    size_t slot_count = (size_t)cfg->connections;
    perf_conn_t **slots = calloc(slot_count, sizeof(slots[0]));
    if (!slots) {
        snprintf(failure_reason, failure_reason_len, "out of memory");
        return -1;
    }

    uint64_t started = 0;
    uint64_t deadline = now_us() + cfg->duration_us;
    for (;;) {
        for (size_t i = 0; i < slot_count; ++i) {
            if (slots[i] || !crr_can_start_connection(cfg, started, deadline)) {
                continue;
            }
            if (init_client_conn(cfg, counters, &slots[i], failure_reason, failure_reason_len) !=
                0) {
                free_client_connections(slots, slot_count);
                free(slots);
                return -1;
            }
            slots[i]->expected_requests = 1;
            ++started;
        }

        if (active_crr_connection_count(slots, slot_count) == 0) {
            break;
        }

        for (size_t i = 0; i < slot_count; ++i) {
            perf_conn_t *pc = slots[i];
            if (!pc) {
                continue;
            }
            if (ensure_session_ready(pc, cfg->request_bytes, cfg->response_bytes, pc->started_at) !=
                0) {
                snprintf(failure_reason, failure_reason_len, "%s", pc->failure_reason);
                free_client_connections(slots, slot_count);
                free(slots);
                return -1;
            }
            if (pc->session_ready && pc->started_requests == 0 &&
                open_request_stream(pc, cfg->request_bytes, cfg->response_bytes, 1) != 0) {
                snprintf(failure_reason, failure_reason_len, "%s", pc->failure_reason);
                free_client_connections(slots, slot_count);
                free(slots);
                return -1;
            }
            if (pc->completed_requests >= pc->expected_requests) {
                send_connection_close(pc);
                free_conn(pc, 1);
                slots[i] = NULL;
            }
        }

        if (active_crr_connection_count(slots, slot_count) == 0 &&
            !crr_can_start_connection(cfg, started, deadline)) {
            break;
        }
        if (drive_client_connections_once(slots, slot_count, 100000, failure_reason,
                                          failure_reason_len) != 0) {
            free_client_connections(slots, slot_count);
            free(slots);
            return -1;
        }
    }

    free(slots);
    return 0;
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
    counters_t *counters = calloc(1, sizeof(*counters));
    if (!counters) {
        run_summary_t summary;
        memset(&summary, 0, sizeof(summary));
        summary.status = "failed";
        summary.failure_reason = "out of memory";
        summary.cfg = cfg;
        return summary;
    }
    char failure_reason[256] = "";
    uint64_t start = now_us();
    if (cfg->warmup_us > 0 && !cfg->requests.set && !cfg->total_bytes.set) {
        usleep((useconds_t)cfg->warmup_us);
    }
    uint64_t measure_start = now_us();
    int rc;
    if (is_mode(cfg, "bulk")) {
        rc = run_bulk(cfg, counters, failure_reason, sizeof(failure_reason));
    } else if (is_mode(cfg, "rr") || is_mode(cfg, "persistent-rr")) {
        rc = run_rr(cfg, counters, failure_reason, sizeof(failure_reason));
    } else {
        rc = run_crr(cfg, counters, failure_reason, sizeof(failure_reason));
    }
    uint64_t end = now_us();
    uint64_t elapsed = (!cfg->requests.set && !cfg->total_bytes.set && rc == 0)
                           ? cfg->duration_us
                           : end - (cfg->requests.set ? start : measure_start);
    run_summary_t summary =
        make_summary(cfg, counters, (int64_t)duration_millis(elapsed), rc == 0 ? "ok" : "failed",
                     rc == 0 ? NULL : failure_reason);
    free(counters->latencies.values);
    free(counters);
    return summary;
}

static perf_conn_t *server_find_conn(server_state_t *state, const uint8_t *dcid, size_t dcidlen) {
    for (size_t i = 0; i < state->num_conns; ++i) {
        ngtcp2_cid scids[8];
        size_t n = ngtcp2_conn_get_scid(state->conns[i]->conn, scids);
        if (n > 8) {
            n = 8;
        }
        for (size_t j = 0; j < n; ++j) {
            if (scids[j].datalen == dcidlen && memcmp(scids[j].data, dcid, dcidlen) == 0) {
                return state->conns[i];
            }
        }
    }
    return NULL;
}

static int server_add_conn(server_state_t *state, perf_conn_t *pc) {
    if (state->num_conns == state->cap_conns) {
        size_t next = state->cap_conns ? state->cap_conns * 2 : 16;
        perf_conn_t **conns = realloc(state->conns, next * sizeof(conns[0]));
        if (!conns) {
            return -1;
        }
        state->conns = conns;
        state->cap_conns = next;
    }
    state->conns[state->num_conns++] = pc;
    return 0;
}

static void server_remove_conn(server_state_t *state, size_t index) {
    free_conn(state->conns[index], 0);
    memmove(state->conns + index, state->conns + index + 1,
            (state->num_conns - index - 1) * sizeof(state->conns[0]));
    --state->num_conns;
}

static int server_read_datagrams(server_state_t *state, struct sockaddr_storage *local_addr,
                                 socklen_t local_addrlen) {
    for (;;) {
        uint8_t buf[READ_BUF_SIZE];
        struct sockaddr_storage remote_addr;
        socklen_t remote_addrlen = sizeof(remote_addr);
        ssize_t nread = recvfrom(state->fd, buf, sizeof(buf), MSG_DONTWAIT,
                                 (struct sockaddr *)&remote_addr, &remote_addrlen);
        if (nread == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            perror("recvfrom");
            return -1;
        }

        ngtcp2_version_cid vc;
        int rv = ngtcp2_pkt_decode_version_cid(&vc, buf, (size_t)nread, SERVER_CID_LEN);
        if (rv != 0) {
            continue;
        }
        perf_conn_t *pc = server_find_conn(state, vc.dcid, vc.dcidlen);
        if (!pc) {
            ngtcp2_pkt_hd hd;
            rv = ngtcp2_accept(&hd, buf, (size_t)nread);
            if (rv != 0) {
                continue;
            }
            pc = calloc(1, sizeof(*pc));
            if (!pc) {
                return -1;
            }
            pc->fd = state->fd;
            pc->cfg = state->cfg;
            ngtcp2_ccerr_default(&pc->last_error);
            if (init_server_conn(pc, state->ssl_ctx, &hd, (struct sockaddr *)local_addr,
                                 local_addrlen, (struct sockaddr *)&remote_addr, remote_addrlen,
                                 hd.version) != 0) {
                free_conn(pc, 0);
                continue;
            }
            if (server_add_conn(state, pc) != 0) {
                free_conn(pc, 0);
                return -1;
            }
        }

        ngtcp2_path path;
        memset(&path, 0, sizeof(path));
        path.local.addr = (struct sockaddr *)local_addr;
        path.local.addrlen = local_addrlen;
        path.remote.addr = (struct sockaddr *)&remote_addr;
        path.remote.addrlen = remote_addrlen;
        ngtcp2_pkt_info pi;
        memset(&pi, 0, sizeof(pi));
        rv = ngtcp2_conn_read_pkt(pc->conn, &path, &pi, buf, (size_t)nread, ngtcp2_now());
        if (rv != 0) {
            if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING ||
                rv == NGTCP2_ERR_IDLE_CLOSE) {
                pc->closed = 1;
            } else {
                set_failure_liberr(pc, "ngtcp2_conn_read_pkt", rv);
                pc->closed = 1;
            }
        } else {
            memcpy(&pc->remote_addr, &remote_addr, remote_addrlen);
            pc->remote_addrlen = remote_addrlen;
        }
    }
}

static int run_server(const config_t *cfg) {
    server_state_t state;
    memset(&state, 0, sizeof(state));
    state.cfg = *cfg;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);
    state.fd = create_server_socket(cfg, &local_addr, &local_addrlen);
    if (state.fd == -1) {
        return 1;
    }
    state.ssl_ctx = make_server_ssl_ctx(cfg);
    if (!state.ssl_ctx) {
        close(state.fd);
        return 1;
    }

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    while (!stop_requested) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(state.fd, &readfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000;
        int sret;
        do {
            sret = select(state.fd + 1, &readfds, NULL, NULL, &tv);
        } while (sret == -1 && errno == EINTR && !stop_requested);
        if (sret > 0 && FD_ISSET(state.fd, &readfds)) {
            server_read_datagrams(&state, &local_addr, local_addrlen);
        }

        ngtcp2_tstamp now = ngtcp2_now();
        for (size_t i = 0; i < state.num_conns;) {
            perf_conn_t *pc = state.conns[i];
            if (!pc->closed && ngtcp2_conn_get_expiry(pc->conn) <= now) {
                int rv = ngtcp2_conn_handle_expiry(pc->conn, now);
                if (rv != 0) {
                    pc->closed = 1;
                }
            }
            if (!pc->closed) {
                conn_write(pc);
            }
            if (pc->closed || pc->failed) {
                server_remove_conn(&state, i);
                continue;
            }
            ++i;
        }
    }

    while (state.num_conns > 0) {
        server_remove_conn(&state, state.num_conns - 1);
    }
    free(state.conns);
    SSL_CTX_free(state.ssl_ctx);
    close(state.fd);
    return 0;
}

static void write_summary_json(FILE *out, const run_summary_t *summary) {
    const config_t *cfg = summary->cfg;
    fprintf(out, "{\n");
    fprintf(out, "  \"schema_version\": 1,\n");
    fprintf(out, "  \"status\": \"%s\",\n", summary->status);
    if (summary->failure_reason) {
        fprintf(out, "  \"failure_reason\": \"%s\",\n", summary->failure_reason);
    }
    fprintf(out, "  \"mode\": \"%s\",\n", cfg->mode);
    fprintf(out, "  \"direction\": \"%s\",\n", cfg->direction);
    fprintf(out, "  \"backend\": \"%s\",\n", cfg->io_backend);
    fprintf(out, "  \"congestion_control\": \"%s\",\n", cfg->congestion_control);
    fprintf(out, "  \"remote_host\": \"%s\",\n", cfg->host);
    fprintf(out, "  \"remote_port\": %u,\n", cfg->port);
    fprintf(out, "  \"alpn\": \"%s\",\n", APPLICATION_PROTOCOL);
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
    fprintf(out, "  }\n");
    fprintf(out, "}\n");
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
    config_t cfg;
    parse_args(&cfg, argc, argv);
    validate_config(&cfg);

    if (ngtcp2_crypto_ossl_init() != 0) {
        fprintf(stderr, "ngtcp2_crypto_ossl_init failed\n");
        return 1;
    }

    if (strcmp(cfg.role, "server") == 0) {
        return run_server(&cfg);
    }

    run_summary_t summary = run_client(&cfg);
    if (emit_summary(&summary) != 0) {
        return 1;
    }
    return strcmp(summary.status, "ok") == 0 ? 0 : 1;
}
