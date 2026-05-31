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

#define APPLICATION_PROTOCOL "hq-interop"
#define DEFAULT_MAX_RUN_REQUESTS 4096ULL
#define MAX_BURST_PACKETS 10
#define TRANSFER_CONNECTION_WINDOW (32U * 1024U * 1024U)
#define TRANSFER_STREAM_WINDOW (16U * 1024U * 1024U)

typedef struct {
    uint64_t value;
    int set;
} optional_u64_t;

static FILE *open_json_output(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
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
    const config_t *cfg;
    counters_t *counters;
    uint64_t expected_requests;
    uint64_t completed_requests;
    uint64_t request_bytes;
    uint64_t response_bytes;
    int counts_latency;
    int failed;
    char failure_reason[256];
} client_batch_t;

typedef struct {
    quicly_streambuf_t streambuf;
    client_batch_t *batch;
    uint64_t response_bytes;
    uint64_t response_read;
    uint64_t started_at;
    int counts_latency;
    int completed;
    int counted;
} client_stream_data_t;

static quicly_context_t ctx;
static ptls_key_exchange_algorithm_t *key_exchanges[4];
static ptls_cipher_suite_t *cipher_suites[8];
static int is_server_role;
static quicly_cid_plaintext_t next_cid;

static int on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                              ptls_on_client_hello_parameters_t *params);
static ptls_on_client_hello_t on_client_hello = {on_client_hello_cb};
static ptls_context_t tlsctx = {
    .random_bytes = ptls_openssl_random_bytes,
    .get_time = &ptls_get_time,
    .key_exchanges = key_exchanges,
    .cipher_suites = cipher_suites,
    .require_dhe_on_psk = 1,
    .on_client_hello = &on_client_hello,
};
static ptls_iovec_t negotiated_protocols[1];

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

static void set_batch_failure(client_batch_t *batch, const char *message) {
    if (!batch->failed) {
        batch->failed = 1;
        snprintf(batch->failure_reason, sizeof(batch->failure_reason), "%s", message);
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
    static ptls_openssl_sign_certificate_t signer;
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
    ptls_openssl_init_sign_certificate(&signer, pkey);
    EVP_PKEY_free(pkey);
    tls->sign_certificate = &signer.super;
}

static void setup_verify_certificate(ptls_context_t *tls) {
    static ptls_openssl_verify_certificate_t verifier;
    ptls_openssl_init_verify_certificate(&verifier, NULL);
    tls->verify_certificate = &verifier.super;
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
    is_server_role = server;
    key_exchanges[0] = &ptls_openssl_secp256r1;
    key_exchanges[1] = NULL;
    for (size_t i = 0; ptls_openssl_cipher_suites[i] != NULL &&
                       i < sizeof(cipher_suites) / sizeof(cipher_suites[0]) - 1;
         ++i) {
        cipher_suites[i] = ptls_openssl_cipher_suites[i];
        cipher_suites[i + 1] = NULL;
    }
    negotiated_protocols[0] = ptls_iovec_init(APPLICATION_PROTOCOL, strlen(APPLICATION_PROTOCOL));

    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    ctx.stream_open = NULL;
    ctx.transport_params.max_data = TRANSFER_CONNECTION_WINDOW;
    ctx.transport_params.max_stream_data.bidi_local = TRANSFER_STREAM_WINDOW;
    ctx.transport_params.max_stream_data.bidi_remote = TRANSFER_STREAM_WINDOW;
    ctx.transport_params.max_stream_data.uni = TRANSFER_STREAM_WINDOW;
    ctx.transport_params.max_streams_bidi = cfg->streams > 100 ? cfg->streams : 100;
    ctx.transport_params.max_udp_payload_size = 1500;

    const char *cc_name = quicly_cc_name(cfg->congestion_control);
    for (quicly_cc_type_t **cc = quicly_cc_all_types; *cc != NULL; ++cc) {
        if (strcmp((*cc)->name, cc_name) == 0) {
            ctx.init_cc = (*cc)->cc_init;
            break;
        }
    }

    quicly_amend_ptls_context(ctx.tls);
    if (server) {
        load_certificate_chain(ctx.tls, cfg->certificate_chain);
        load_private_key(ctx.tls, cfg->private_key);
    } else if (cfg->verify_peer) {
        setup_verify_certificate(ctx.tls);
    }
}

static int parse_request(ptls_iovec_t input, char **path, int *is_http1) {
    size_t off = 0;
    size_t path_start;
    for (off = 0; off != input.len; ++off) {
        if (input.base[off] == ' ') {
            goto end_of_method;
        }
    }
    return 0;

end_of_method:
    ++off;
    path_start = off;
    for (; off != input.len; ++off) {
        if (input.base[off] == ' ' || input.base[off] == '\r' || input.base[off] == '\n') {
            goto end_of_path;
        }
    }
    return 0;

end_of_path:
    *path = (char *)(input.base + path_start);
    *is_http1 = input.base[off] == ' ';
    input.base[off] = '\0';
    return 1;
}

static void send_str(quicly_stream_t *stream, const char *text) {
    quicly_streambuf_egress_write(stream, text, strlen(text));
}

static void send_header(quicly_stream_t *stream, int is_http1, int status, const char *mime_type) {
    char buf[256];
    if (!is_http1) {
        return;
    }
    snprintf(buf, sizeof(buf), "HTTP/1.1 %03d OK\r\nConnection: close\r\nContent-Type: %s\r\n\r\n",
             status, mime_type);
    send_str(stream, buf);
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

static int send_sized_text(quicly_stream_t *stream, const char *path, int is_http1) {
    size_t size;
    int lastpos;
    if (sscanf(path, "/%zu%n", &size, &lastpos) != 1 || lastpos != (int)strlen(path)) {
        return 0;
    }
    send_header(stream, is_http1, 200, "text/plain; charset=utf-8");
    static const quicly_streambuf_sendvec_callbacks_t callbacks = {flatten_sized_text, NULL};
    quicly_sendbuf_vec_t vec = {&callbacks, size, NULL};
    quicly_streambuf_egress_write_vec(stream, &vec);
    return 1;
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
    char *path;
    int is_http1;
    if (!quicly_sendstate_is_open(&stream->sendstate)) {
        return;
    }
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0) {
        return;
    }
    if (!parse_request(quicly_streambuf_ingress_get(stream), &path, &is_http1)) {
        if (!quicly_recvstate_transfer_complete(&stream->recvstate)) {
            return;
        }
        send_header(stream, 1, 500, "text/plain; charset=utf-8");
        send_str(stream, "failed to parse HTTP request\n");
        goto sent;
    }
    if (!quicly_recvstate_transfer_complete(&stream->recvstate)) {
        quicly_request_stop(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
    }
    if (!send_sized_text(stream, path, is_http1)) {
        send_header(stream, is_http1, 404, "text/plain; charset=utf-8");
        send_str(stream, "not found\n");
    }

sent:
    quicly_streambuf_egress_shutdown(stream);
    quicly_streambuf_ingress_shift(stream, quicly_streambuf_ingress_get(stream).len);
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
    batch->counters->bytes_sent += batch->request_bytes;
    batch->counters->bytes_received += data->response_bytes;
    ++batch->counters->requests_completed;
    ++batch->completed_requests;
    if (data->counts_latency) {
        latency_push(&batch->counters->latencies, now_us() - data->started_at);
    }
}

static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {
    client_stream_data_t *data = stream->data;
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0) {
        return;
    }
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len != 0) {
        data->response_read += input.len;
        quicly_streambuf_ingress_shift(stream, input.len);
    }
    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        data->completed = 1;
        client_count_stream(data);
    }
}

static void client_on_destroy(quicly_stream_t *stream, quicly_error_t err) {
    (void)err;
    client_stream_data_t *data = stream->data;
    client_count_stream(data);
    quicly_streambuf_destroy(stream, err);
}

static const quicly_stream_callbacks_t server_stream_callbacks = {
    quicly_streambuf_destroy,
    quicly_streambuf_egress_shift,
    quicly_streambuf_egress_emit,
    on_stop_sending,
    server_on_receive,
    on_receive_reset,
};

static const quicly_stream_callbacks_t client_stream_callbacks = {
    client_on_destroy,
    quicly_streambuf_egress_shift,
    quicly_streambuf_egress_emit,
    on_stop_sending,
    client_on_receive,
    on_receive_reset,
};

static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream) {
    (void)self;
    int ret;
    if ((ret = quicly_streambuf_create(stream, is_server_role ? sizeof(quicly_streambuf_t)
                                                              : sizeof(client_stream_data_t))) !=
        0) {
        return ret;
    }
    stream->callbacks = is_server_role ? &server_stream_callbacks : &client_stream_callbacks;
    return 0;
}

static quicly_stream_open_t stream_open = {on_stream_open};

static ssize_t receive_datagram(int fd, void *buf, quicly_address_t *dest, quicly_address_t *src,
                                uint8_t *ecn) {
    struct iovec vec = {.iov_base = buf, .iov_len = ctx.transport_params.max_udp_payload_size};
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

static int enqueue_requests(quicly_conn_t *conn, client_batch_t *batch, uint64_t count) {
    for (uint64_t i = 0; i != count; ++i) {
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
        data->counts_latency = batch->counts_latency;

        char req[128];
        int req_len = snprintf(req, sizeof(req), "GET /%" PRIu64 "\r\n", batch->response_bytes);
        if (req_len < 0 || (size_t)req_len >= sizeof(req) ||
            quicly_streambuf_egress_write(stream, req, (size_t)req_len) != 0 ||
            quicly_streambuf_egress_shutdown(stream) != 0) {
            set_batch_failure(batch, "could not write request stream");
            return -1;
        }
    }
    return 0;
}

static int run_request_batch(const config_t *cfg, uint64_t count, uint64_t response_bytes,
                             uint64_t request_bytes, counters_t *counters, int counts_latency,
                             char *failure_reason, size_t failure_reason_len) {
    if (count == 0) {
        return 0;
    }
    if (count > DEFAULT_MAX_RUN_REQUESTS) {
        count = DEFAULT_MAX_RUN_REQUESTS;
    }

    struct sockaddr_storage sa;
    socklen_t salen;
    if (resolve_address(&sa, &salen, cfg->host, cfg->port, 0) != 0) {
        snprintf(failure_reason, failure_reason_len, "could not resolve server");
        return -1;
    }
    int fd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        snprintf(failure_reason, failure_reason_len, "socket failed: %s", strerror(errno));
        return -1;
    }
    if (prep_socket(fd) != 0) {
        close(fd);
        snprintf(failure_reason, failure_reason_len, "could not prepare socket");
        return -1;
    }
    quicly_address_t local;
    memset(&local, 0, sizeof(local));
    local.sa.sa_family = sa.ss_family;
    if (bind(fd, &local.sa,
             local.sa.sa_family == AF_INET ? sizeof(local.sin) : sizeof(local.sin6)) != 0) {
        close(fd);
        snprintf(failure_reason, failure_reason_len, "bind failed: %s", strerror(errno));
        return -1;
    }

    ptls_handshake_properties_t hs_properties;
    memset(&hs_properties, 0, sizeof(hs_properties));
    hs_properties.client.negotiated_protocols.list = negotiated_protocols;
    hs_properties.client.negotiated_protocols.count = 1;

    client_batch_t batch;
    memset(&batch, 0, sizeof(batch));
    batch.cfg = cfg;
    batch.counters = counters;
    batch.expected_requests = count;
    batch.request_bytes = request_bytes;
    batch.response_bytes = response_bytes;
    batch.counts_latency = counts_latency;

    quicly_conn_t *conn = NULL;
    quicly_error_t ret =
        quicly_connect(&conn, &ctx, cfg->server_name, (struct sockaddr *)&sa, NULL, &next_cid,
                       ptls_iovec_init(NULL, 0), &hs_properties, NULL, NULL);
    if (ret != 0 || conn == NULL) {
        close(fd);
        snprintf(failure_reason, failure_reason_len, "quicly_connect failed");
        return -1;
    }
    ++next_cid.master_id;
    if (enqueue_requests(conn, &batch, count) != 0) {
        snprintf(failure_reason, failure_reason_len, "%s", batch.failure_reason);
        quicly_free(conn);
        close(fd);
        return -1;
    }
    send_pending(fd, conn);

    int close_called = 0;
    uint64_t hard_deadline = now_us() + 120000000ULL;
    while (conn != NULL) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        struct timeval tv;
        int64_t timeout_at = quicly_get_first_timeout(conn);
        int64_t now_ms = ctx.now->cb(ctx.now);
        int64_t delta = timeout_at == INT64_MAX ? 100 : timeout_at - now_ms;
        if (delta < 0) {
            delta = 0;
        }
        if (delta > 100) {
            delta = 100;
        }
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
                    if (quicly_decode_packet(&ctx, &packet, buf, (size_t)rret, &off) == SIZE_MAX) {
                        break;
                    }
                    packet.ecn = ecn;
                    quicly_receive(conn, &dest.sa, &src.sa, &packet);
                }
            }
        }

        if (!close_called && batch.completed_requests >= batch.expected_requests &&
            quicly_num_streams(conn) == 0) {
            quicly_close(conn, 0, "");
            close_called = 1;
        }

        ret = send_pending(fd, conn);
        if (ret != 0) {
            quicly_free(conn);
            conn = NULL;
            if (ret != QUICLY_ERROR_FREE_CONNECTION) {
                snprintf(failure_reason, failure_reason_len, "quicly_send returned %" PRId64,
                         (int64_t)ret);
                close(fd);
                return -1;
            }
        }
        if (batch.failed) {
            snprintf(failure_reason, failure_reason_len, "%s", batch.failure_reason);
            if (conn != NULL) {
                quicly_close(conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1), "perf failure");
            }
            close(fd);
            return -1;
        }
        if (now_us() > hard_deadline) {
            snprintf(failure_reason, failure_reason_len, "quicly-perf request batch timed out");
            if (conn != NULL) {
                quicly_free(conn);
            }
            close(fd);
            return -1;
        }
    }
    close(fd);
    if (batch.completed_requests != batch.expected_requests) {
        snprintf(failure_reason, failure_reason_len,
                 "quicly-perf completed %" PRIu64 " of %" PRIu64 " requests",
                 batch.completed_requests, batch.expected_requests);
        return -1;
    }
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
        unit = request_bytes;
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
        return run_request_batch(cfg, count, response_bytes, request_bytes, counters, 0,
                                 failure_reason, failure_reason_len);
    }

    uint64_t deadline = now_us() + cfg->duration_us;
    while (now_us() < deadline) {
        uint64_t count = cfg->streams * cfg->connections;
        if (count == 0) {
            count = 1;
        }
        uint64_t before = now_us();
        if (run_request_batch(cfg, count, response_bytes, request_bytes, counters, 0,
                              failure_reason, failure_reason_len) != 0) {
            return -1;
        }
        if (now_us() - before > cfg->duration_us * 2) {
            break;
        }
    }
    return 0;
}

static int run_rr(const config_t *cfg, counters_t *counters, char *failure_reason,
                  size_t failure_reason_len) {
    if (cfg->requests.set) {
        return run_request_batch(cfg, cfg->requests.value, cfg->response_bytes, cfg->request_bytes,
                                 counters, 1, failure_reason, failure_reason_len);
    }
    uint64_t deadline = now_us() + cfg->duration_us;
    while (now_us() < deadline) {
        uint64_t count = cfg->requests_in_flight;
        if (count > DEFAULT_MAX_RUN_REQUESTS) {
            count = DEFAULT_MAX_RUN_REQUESTS;
        }
        if (count == 0) {
            count = 1;
        }
        if (run_request_batch(cfg, count, cfg->response_bytes, cfg->request_bytes, counters, 1,
                              failure_reason, failure_reason_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int run_crr(const config_t *cfg, counters_t *counters, char *failure_reason,
                   size_t failure_reason_len) {
    if (cfg->requests.set) {
        uint64_t remaining = cfg->requests.value;
        while (remaining > 0) {
            uint64_t batch = remaining < cfg->connections ? remaining : cfg->connections;
            if (run_request_batch(cfg, batch, cfg->response_bytes, cfg->request_bytes, counters, 1,
                                  failure_reason, failure_reason_len) != 0) {
                return -1;
            }
            remaining -= batch;
        }
        return 0;
    }
    uint64_t deadline = now_us() + cfg->duration_us;
    while (now_us() < deadline) {
        uint64_t batch = cfg->connections ? cfg->connections : 1;
        if (run_request_batch(cfg, batch, cfg->response_bytes, cfg->request_bytes, counters, 1,
                              failure_reason, failure_reason_len) != 0) {
            return -1;
        }
    }
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
    } else if (is_mode(cfg, "rr")) {
        rc = run_rr(cfg, &counters, failure_reason, sizeof(failure_reason));
    } else {
        rc = run_crr(cfg, &counters, failure_reason, sizeof(failure_reason));
    }
    uint64_t end = now_us();
    uint64_t elapsed = end - (cfg->requests.set ? start : measure_start);
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
    quicly_free(server_conns[index]);
    memmove(server_conns + index, server_conns + index + 1,
            (num_server_conns - index - 1) * sizeof(server_conns[0]));
    --num_server_conns;
}

static int run_server(const config_t *cfg) {
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
        int64_t delta = timeout_at == INT64_MAX ? 100 : timeout_at - ctx.now->cb(ctx.now);
        if (delta < 0) {
            delta = 0;
        }
        if (delta > 100) {
            delta = 100;
        }
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
                    if (quicly_decode_packet(&ctx, &packet, buf, (size_t)rret, &off) == SIZE_MAX) {
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
                        uint8_t payload[1500];
                        size_t payload_len = quicly_send_version_negotiation(
                            &ctx, packet.cid.src, packet.cid.dest.encrypted,
                            quicly_supported_versions, payload);
                        if (payload_len != SIZE_MAX) {
                            send_one_packet(fd, &remote, &local, payload, payload_len);
                        }
                    } else if (QUICLY_PACKET_IS_INITIAL(packet.octets.base[0])) {
                        quicly_error_t ret = quicly_accept(&conn, &ctx, &local.sa, &remote.sa,
                                                           &packet, NULL, &next_cid, NULL, NULL);
                        if (ret == 0 && conn != NULL) {
                            ++next_cid.master_id;
                            quicly_conn_t **new_conns = realloc(
                                server_conns, (num_server_conns + 1) * sizeof(server_conns[0]));
                            if (!new_conns) {
                                perror("realloc");
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

        for (size_t i = 0; i != num_server_conns; ++i) {
            quicly_error_t ret = send_pending(fd, server_conns[i]);
            if (ret != 0) {
                remove_server_conn(i);
                --i;
            }
        }
    }

    for (size_t i = 0; i != num_server_conns; ++i) {
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
    ctx.stream_open = &stream_open;
    if (strcmp(cfg.role, "server") == 0) {
        return run_server(&cfg);
    }
    run_summary_t summary = run_client(&cfg);
    if (emit_summary(&summary) != 0) {
        return 1;
    }
    return strcmp(summary.status, "ok") == 0 ? 0 : 1;
}
