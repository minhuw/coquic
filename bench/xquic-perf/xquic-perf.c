#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <xquic/xquic.h>

#define APPLICATION_PROTOCOL "coquic-perf/1"
#define PERF_PROTOCOL_VERSION 3U
#define MESSAGE_SESSION_START 1U
#define MESSAGE_SESSION_READY 2U
#define MESSAGE_SESSION_ERROR 3U
#define MESSAGE_SESSION_COMPLETE 4U
#define MODE_CODE_BULK 0U
#define MODE_CODE_RR 1U
#define MODE_CODE_CRR 2U
#define DIRECTION_CODE_UPLOAD 0U
#define DIRECTION_CODE_DOWNLOAD 1U
#define MAX_DATAGRAM_SIZE 1350
#define READ_CHUNK_SIZE 65536
#define WRITE_CHUNK_SIZE 32768
#define DRAIN_TIMEOUT_US 2000000ULL
#define TIMED_BULK_RESPONSE_BYTES (1ULL << 62)
#define TRANSFER_CONNECTION_WINDOW (32U * 1024U * 1024U)
#define TRANSFER_STREAM_WINDOW (16U * 1024U * 1024U)
#define TRANSFER_MAX_STREAMS 1048576ULL
#define PERF_CTX_MAGIC 0x63706678U
#define CONN_CTX_MAGIC 0x636e6678U

static int debug_enabled(void) {
    static int initialized = 0;
    static int enabled = 0;
    if (!initialized) {
        enabled = getenv("XQUIC_PERF_DEBUG") != NULL;
        initialized = 1;
    }
    return enabled;
}

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
    uint64_t min_us;
    uint64_t avg_us;
    uint64_t p50_us;
    uint64_t p90_us;
    uint64_t p99_us;
    uint64_t max_us;
} latency_summary_t;

typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t requests_completed;
    uint64_t skipped_setup_errors;
    uint64_t *latencies;
    size_t latency_len;
    size_t latency_cap;
} counters_t;

typedef struct perf_ctx_s perf_ctx_t;
typedef struct conn_ctx_s conn_ctx_t;
typedef struct stream_ctx_s stream_ctx_t;

typedef struct {
    int counts;
    uint64_t request_bytes;
    uint64_t received;
    uint64_t latency_us;
} completed_stream_t;

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

struct stream_ctx_s {
    conn_ctx_t *conn;
    xqc_stream_t *stream;
    int is_control;
    uint8_t *control_in;
    size_t control_in_len;
    size_t control_in_cap;
    int send_fin_on_complete;
    uint64_t request_bytes;
    uint64_t response_bytes;
    uint64_t request_received;
    uint64_t response_sent;
    uint64_t received;
    uint8_t *send_buf;
    size_t send_len;
    size_t sent;
    int counts;
    int request_fin;
    int response_fin;
    int fin_sent;
    uint64_t started_at;
    stream_ctx_t *next;
};

struct conn_ctx_s {
    uint32_t magic;
    perf_ctx_t *ctx;
    xqc_connection_t *conn;
    xqc_cid_t cid;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    int ready;
    int session_ready;
    int session_started;
    int server_control_seen;
    int server_complete_sent;
    perf_session_start_t session_start;
    stream_ctx_t *control_stream;
    uint64_t server_bytes_sent;
    uint64_t server_bytes_received;
    uint64_t server_requests_completed;
    uint64_t request_limit;
    uint64_t started_requests;
    int closed;
    stream_ctx_t *streams;
    conn_ctx_t *next;
};

struct perf_ctx_s {
    uint32_t magic;
    config_t cfg;
    xqc_engine_t *engine;
    int fd;
    int is_server;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
    uint64_t next_wake_us;
    int error;
    char error_message[256];
    conn_ctx_t *conns;
    completed_stream_t *completed;
    size_t completed_len;
    size_t completed_cap;
    uint64_t live_bytes_received;
    uint64_t measure_start_us;
    int count_stream_bytes;
};

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static uint64_t wall_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

static uint64_t parse_duration_us(const char *value) {
    size_t len = strlen(value);
    if (len >= 2 && strcmp(value + len - 2, "ms") == 0) {
        char tmp[64];
        memcpy(tmp, value, len - 2);
        tmp[len - 2] = 0;
        return strtoull(tmp, NULL, 10) * 1000ULL;
    }
    if (len >= 1 && value[len - 1] == 's') {
        char tmp[64];
        memcpy(tmp, value, len - 1);
        tmp[len - 1] = 0;
        return strtoull(tmp, NULL, 10) * 1000000ULL;
    }
    fprintf(stderr, "invalid duration: %s\n", value);
    exit(2);
}

static uint64_t htonll_local(uint64_t value) {
    uint32_t high = htonl((uint32_t)(value >> 32));
    uint32_t low = htonl((uint32_t)(value & 0xffffffffu));
    return ((uint64_t)low << 32) | high;
}

static uint64_t ntohll_local(uint64_t value) {
    return htonll_local(value);
}

static void set_error(perf_ctx_t *ctx, const char *message) {
    if (!ctx->error) {
        ctx->error = 1;
        snprintf(ctx->error_message, sizeof(ctx->error_message), "%s", message);
    }
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
    if (strcmp(cfg->mode, "rr") == 0 && cfg->requests.set) {
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
         start->mode != MODE_CODE_CRR) ||
        (start->direction != DIRECTION_CODE_UPLOAD &&
         start->direction != DIRECTION_CODE_DOWNLOAD) ||
        start->streams == 0 || start->connections == 0 || start->requests_in_flight == 0) {
        return -1;
    }
    return 0;
}

static uint64_t server_response_bytes(const perf_session_start_t *start,
                                      uint64_t requests_completed) {
    if (start->mode == MODE_CODE_BULK && start->direction == DIRECTION_CODE_DOWNLOAD &&
        start->total_bytes.set) {
        uint64_t stream_index = requests_completed > 0 ? requests_completed - 1 : 0;
        uint64_t per_stream = start->total_bytes.value / start->streams;
        uint64_t remainder = start->total_bytes.value % start->streams;
        return per_stream + (stream_index < remainder ? 1 : 0);
    }
    if (start->mode == MODE_CODE_BULK && start->direction == DIRECTION_CODE_DOWNLOAD) {
        return start->response_bytes;
    }
    if (start->mode == MODE_CODE_RR || start->mode == MODE_CODE_CRR) {
        return start->response_bytes;
    }
    return 0;
}

static int should_send_complete(conn_ctx_t *conn) {
    const perf_session_start_t *start = &conn->session_start;
    if (conn->server_complete_sent || !start->started) {
        return 0;
    }
    return (start->mode == MODE_CODE_BULK && start->total_bytes.set &&
            conn->server_requests_completed >= start->streams) ||
           (start->mode == MODE_CODE_BULK && start->direction == DIRECTION_CODE_UPLOAD &&
            conn->server_requests_completed >= start->streams) ||
           (start->mode == MODE_CODE_RR && start->requests.set &&
            conn->server_requests_completed >= start->requests.value);
}

static void set_stream_send_buffer(stream_ctx_t *s, uint8_t *buf, size_t len, int fin) {
    free(s->send_buf);
    s->send_buf = buf;
    s->send_len = len;
    s->sent = 0;
    s->send_fin_on_complete = fin;
    s->fin_sent = 0;
}

static stream_ctx_t *open_control_stream(perf_ctx_t *ctx, conn_ctx_t *conn);

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

static const char *take_value(int argc, char **argv, int *index, const char *arg) {
    if (*index >= argc) {
        fprintf(stderr, "missing value for %s\n", arg);
        exit(2);
    }
    return argv[(*index)++];
}

static void parse_args(config_t *cfg, int argc, char **argv) {
    init_config(cfg);
    int index = 0;
    while (index < argc) {
        const char *arg = argv[index++];
        if (strcmp(arg, "--verify-peer") == 0) {
            cfg->verify_peer = 1;
        } else if (strcmp(arg, "--disable-pmtud") == 0) {
            cfg->disable_pmtud = 1;
        } else if (strcmp(arg, "--host") == 0) {
            snprintf(cfg->host, sizeof(cfg->host), "%s", take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--port") == 0) {
            cfg->port = (uint16_t)strtoul(take_value(argc, argv, &index, arg), NULL, 10);
        } else if (strcmp(arg, "--server-name") == 0) {
            snprintf(cfg->server_name, sizeof(cfg->server_name), "%s",
                     take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--io-backend") == 0) {
            snprintf(cfg->io_backend, sizeof(cfg->io_backend), "%s",
                     take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--congestion-control") == 0) {
            snprintf(cfg->congestion_control, sizeof(cfg->congestion_control), "%s",
                     take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--certificate-chain") == 0) {
            snprintf(cfg->certificate_chain, sizeof(cfg->certificate_chain), "%s",
                     take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--private-key") == 0) {
            snprintf(cfg->private_key, sizeof(cfg->private_key), "%s",
                     take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--mode") == 0) {
            snprintf(cfg->mode, sizeof(cfg->mode), "%s", take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--direction") == 0) {
            snprintf(cfg->direction, sizeof(cfg->direction), "%s",
                     take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--request-bytes") == 0) {
            cfg->request_bytes = strtoull(take_value(argc, argv, &index, arg), NULL, 10);
        } else if (strcmp(arg, "--response-bytes") == 0) {
            cfg->response_bytes = strtoull(take_value(argc, argv, &index, arg), NULL, 10);
        } else if (strcmp(arg, "--streams") == 0) {
            cfg->streams = strtoull(take_value(argc, argv, &index, arg), NULL, 10);
        } else if (strcmp(arg, "--connections") == 0) {
            cfg->connections = strtoull(take_value(argc, argv, &index, arg), NULL, 10);
        } else if (strcmp(arg, "--requests-in-flight") == 0) {
            cfg->requests_in_flight = strtoull(take_value(argc, argv, &index, arg), NULL, 10);
        } else if (strcmp(arg, "--requests") == 0) {
            cfg->requests.value = strtoull(take_value(argc, argv, &index, arg), NULL, 10);
            cfg->requests.set = 1;
        } else if (strcmp(arg, "--total-bytes") == 0) {
            cfg->total_bytes.value = strtoull(take_value(argc, argv, &index, arg), NULL, 10);
            cfg->total_bytes.set = 1;
        } else if (strcmp(arg, "--warmup") == 0) {
            cfg->warmup_us = parse_duration_us(take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--duration") == 0) {
            cfg->duration_us = parse_duration_us(take_value(argc, argv, &index, arg));
        } else if (strcmp(arg, "--json-out") == 0) {
            snprintf(cfg->json_out, sizeof(cfg->json_out), "%s",
                     take_value(argc, argv, &index, arg));
        } else {
            fprintf(stderr, "unknown argument: %s\n", arg);
            exit(2);
        }
    }
    if (strcmp(cfg->io_backend, "socket") != 0) {
        fprintf(stderr, "xquic-perf only supports the socket backend\n");
        exit(2);
    }
    if (cfg->streams == 0 || cfg->connections == 0 || cfg->requests_in_flight == 0) {
        fprintf(stderr, "streams, connections, and requests-in-flight must be greater than zero\n");
        exit(2);
    }
}

static int resolve_addr(const char *host, uint16_t port, struct sockaddr_storage *out,
                        socklen_t *out_len) {
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%u", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    int ret = getaddrinfo(host, port_text, &hints, &res);
    if (ret != 0 || res == NULL) {
        return -1;
    }
    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static int make_socket(struct sockaddr_storage *addr, socklen_t addrlen) {
    int fd = socket(addr->ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    int value = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
    int size = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)addr, addrlen) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void timer_cb(xqc_usec_t wake_after, void *user_data) {
    perf_ctx_t *ctx = (perf_ctx_t *)user_data;
    ctx->next_wake_us = now_us() + wake_after;
}

static void xquic_log_cb(xqc_log_level_t lvl, const void *buf, size_t size,
                         void *engine_user_data) {
    (void)lvl;
    (void)engine_user_data;
    if (debug_enabled()) {
        fwrite(buf, 1, size, stderr);
        fputc('\n', stderr);
    }
}

static ssize_t write_socket_cb(const unsigned char *buf, size_t size,
                               const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                               void *conn_user_data) {
    perf_ctx_t *ctx = NULL;
    if (conn_user_data != NULL) {
        uint32_t magic = *(uint32_t *)conn_user_data;
        if (magic == CONN_CTX_MAGIC) {
            ctx = ((conn_ctx_t *)conn_user_data)->ctx;
        } else if (magic == PERF_CTX_MAGIC) {
            ctx = (perf_ctx_t *)conn_user_data;
        }
    }
    if (ctx == NULL) {
        DEBUG_LOG("xquic write no ctx conn_user_data=%p\n", conn_user_data);
        return XQC_SOCKET_ERROR;
    }
    ssize_t ret;
    do {
        ret = sendto(ctx->fd, buf, size, 0, peer_addr, peer_addrlen);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        DEBUG_LOG("xquic %s send eagain size=%zu\n", ctx->is_server ? "server" : "client", size);
        return XQC_SOCKET_EAGAIN;
    }
    DEBUG_LOG("xquic %s send size=%zu ret=%zd errno=%d\n", ctx->is_server ? "server" : "client",
              size, ret, errno);
    return ret < 0 ? XQC_SOCKET_ERROR : ret;
}

static ssize_t write_socket_ex_cb(uint64_t path_id, const unsigned char *buf, size_t size,
                                  const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                                  void *conn_user_data) {
    (void)path_id;
    return write_socket_cb(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

static int cert_verify_cb(const unsigned char *certs[], const size_t cert_len[], size_t certs_len,
                          void *conn_user_data) {
    (void)certs;
    (void)cert_len;
    (void)certs_len;
    (void)conn_user_data;
    return XQC_OK;
}

static void save_token_cb(const unsigned char *token, uint32_t token_len, void *conn_user_data) {
    (void)token;
    (void)token_len;
    (void)conn_user_data;
}

static void save_string_cb(const char *data, size_t data_len, void *conn_user_data) {
    (void)data;
    (void)data_len;
    (void)conn_user_data;
}

static conn_ctx_t *add_conn(perf_ctx_t *ctx) {
    conn_ctx_t *conn = (conn_ctx_t *)calloc(1, sizeof(conn_ctx_t));
    if (conn == NULL) {
        return NULL;
    }
    conn->magic = CONN_CTX_MAGIC;
    conn->ctx = ctx;
    conn->next = ctx->conns;
    ctx->conns = conn;
    return conn;
}

static stream_ctx_t *add_stream(conn_ctx_t *conn) {
    stream_ctx_t *stream = (stream_ctx_t *)calloc(1, sizeof(stream_ctx_t));
    if (stream == NULL) {
        return NULL;
    }
    stream->conn = conn;
    stream->next = conn->streams;
    conn->streams = stream;
    return stream;
}

static void remove_stream(conn_ctx_t *conn, stream_ctx_t *stream) {
    stream_ctx_t **slot = &conn->streams;
    while (*slot != NULL) {
        if (*slot == stream) {
            *slot = stream->next;
            free(stream->send_buf);
            free(stream->control_in);
            free(stream);
            return;
        }
        slot = &(*slot)->next;
    }
}

static void cleanup_ctx(perf_ctx_t *ctx) {
    if (ctx->engine != NULL) {
        xqc_engine_destroy(ctx->engine);
        ctx->engine = NULL;
    }
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    conn_ctx_t *conn = ctx->conns;
    while (conn != NULL) {
        conn_ctx_t *next_conn = conn->next;
        stream_ctx_t *stream = conn->streams;
        while (stream != NULL) {
            stream_ctx_t *next_stream = stream->next;
            free(stream->send_buf);
            free(stream->control_in);
            free(stream);
            stream = next_stream;
        }
        free(conn);
        conn = next_conn;
    }
    ctx->conns = NULL;
    free(ctx->completed);
    ctx->completed = NULL;
    ctx->completed_len = 0;
    ctx->completed_cap = 0;
}

static void push_completed(perf_ctx_t *ctx, completed_stream_t item) {
    if (ctx->completed_len == ctx->completed_cap) {
        size_t next_cap = ctx->completed_cap == 0 ? 16 : ctx->completed_cap * 2;
        completed_stream_t *next =
            (completed_stream_t *)realloc(ctx->completed, next_cap * sizeof(completed_stream_t));
        if (next == NULL) {
            set_error(ctx, "xquic completed queue allocation failed");
            return;
        }
        ctx->completed = next;
        ctx->completed_cap = next_cap;
    }
    ctx->completed[ctx->completed_len++] = item;
}

static void try_stream_send(stream_ctx_t *stream) {
    while (!stream->fin_sent) {
        perf_ctx_t *ctx = stream->conn->ctx;
        if (stream->is_control) {
            size_t remaining = stream->send_len - stream->sent;
            if (remaining == 0 && !stream->send_fin_on_complete) {
                stream->fin_sent = 1;
                return;
            }
            size_t chunk = remaining < WRITE_CHUNK_SIZE ? remaining : WRITE_CHUNK_SIZE;
            uint8_t fin = stream->send_fin_on_complete && chunk == remaining;
            uint8_t *base = stream->send_buf != NULL ? stream->send_buf + stream->sent : NULL;
            ssize_t ret = xqc_stream_send(stream->stream, base, chunk, fin);
            if (ret == -XQC_EAGAIN) {
                return;
            }
            if (ret < 0) {
                set_error(ctx, "xqc_stream_send failed");
                return;
            }
            stream->sent += (size_t)ret;
            if (fin && (size_t)ret == chunk) {
                stream->fin_sent = 1;
                return;
            }
            if (ret == 0) {
                return;
            }
            continue;
        }

        if (stream->conn->ctx->is_server) {
            uint64_t response_remaining = stream->response_bytes - stream->response_sent;
            size_t chunk = (size_t)(response_remaining < WRITE_CHUNK_SIZE ? response_remaining
                                                                          : WRITE_CHUNK_SIZE);
            uint8_t fin = response_remaining == chunk;
            uint8_t *base = stream->send_buf != NULL ? stream->send_buf : NULL;
            ssize_t ret = xqc_stream_send(stream->stream, base, chunk, fin);
            if (ret == -XQC_EAGAIN) {
                return;
            }
            if (ret < 0) {
                set_error(ctx, "xqc_stream_send failed");
                return;
            }
            if (chunk == 0 && fin && ret == 0) {
                stream->fin_sent = 1;
                return;
            }
            stream->response_sent += (uint64_t)ret;
            if (fin && (size_t)ret == chunk) {
                stream->fin_sent = 1;
                return;
            }
            if (ret == 0) {
                return;
            }
            continue;
        }

        size_t remaining = stream->send_len - stream->sent;
        size_t chunk = remaining < WRITE_CHUNK_SIZE ? remaining : WRITE_CHUNK_SIZE;
        uint8_t fin = chunk == remaining;
        ssize_t ret = xqc_stream_send(stream->stream, stream->send_buf + stream->sent, chunk, fin);
        if (ret == -XQC_EAGAIN) {
            return;
        }
        if (ret < 0) {
            set_error(ctx, "xqc_stream_send failed");
            return;
        }
        if (chunk == 0 && fin && ret == 0) {
            stream->fin_sent = 1;
            return;
        }
        stream->sent += (size_t)ret;
        if (fin && (size_t)ret == chunk) {
            stream->fin_sent = 1;
            return;
        }
        if (ret == 0) {
            return;
        }
    }
}

static xqc_int_t stream_write_notify(xqc_stream_t *stream, void *strm_user_data) {
    (void)stream;
    stream_ctx_t *s = (stream_ctx_t *)strm_user_data;
    if (s != NULL) {
        try_stream_send(s);
    }
    return XQC_OK;
}

static xqc_int_t stream_read_notify(xqc_stream_t *stream, void *strm_user_data) {
    stream_ctx_t *s = (stream_ctx_t *)strm_user_data;
    if (s == NULL) {
        return XQC_OK;
    }
    perf_ctx_t *ctx = s->conn->ctx;
    unsigned char buf[READ_CHUNK_SIZE];
    uint8_t fin = 0;
    for (;;) {
        ssize_t ret = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
        if (ret == -XQC_EAGAIN) {
            break;
        }
        if (ret < 0) {
            set_error(ctx, "xqc_stream_recv failed");
            return XQC_ERROR;
        }

        if (s->is_control) {
            if ((size_t)ret > 0) {
                if (s->control_in_len + (size_t)ret > s->control_in_cap) {
                    size_t next_cap = s->control_in_cap == 0 ? 128 : s->control_in_cap * 2;
                    while (next_cap < s->control_in_len + (size_t)ret) {
                        next_cap *= 2;
                    }
                    uint8_t *next = (uint8_t *)realloc(s->control_in, next_cap);
                    if (next == NULL) {
                        set_error(ctx, "xquic control allocation failed");
                        return XQC_ERROR;
                    }
                    s->control_in = next;
                    s->control_in_cap = next_cap;
                }
                memcpy(s->control_in + s->control_in_len, buf, (size_t)ret);
                s->control_in_len += (size_t)ret;
            }
            if (ctx->is_server) {
                if (!fin) {
                    continue;
                }
                size_t msg_len = 0;
                if (s->control_in_len < 5 || s->control_in[0] != MESSAGE_SESSION_START ||
                    s->control_in_len != (size_t)decode_be32(s->control_in + 1) + 5 ||
                    decode_session_start_payload(s->control_in + 5, s->control_in_len - 5,
                                                 &s->conn->session_start) != 0) {
                    uint8_t *msg = encode_session_error_message("invalid session_start", &msg_len);
                    if (msg == NULL) {
                        set_error(ctx, "xquic session_error allocation failed");
                        return XQC_ERROR;
                    }
                    set_stream_send_buffer(s, msg, msg_len, 1);
                    try_stream_send(s);
                    return XQC_OK;
                }
                s->conn->session_started = 1;
                s->conn->control_stream = s;
                uint8_t *msg = encode_session_ready_message(&msg_len);
                if (msg == NULL) {
                    set_error(ctx, "xquic session_ready allocation failed");
                    return XQC_ERROR;
                }
                set_stream_send_buffer(s, msg, msg_len, 0);
                try_stream_send(s);
            } else {
                if (s->control_in_len < 5) {
                    continue;
                }
                uint32_t payload_len = decode_be32(s->control_in + 1);
                if (s->control_in_len < (size_t)payload_len + 5) {
                    continue;
                }
                if (s->control_in_len < 5) {
                    set_error(ctx, "xquic short control message");
                    return XQC_ERROR;
                }
                uint8_t type = s->control_in[0];
                if (type == MESSAGE_SESSION_READY && payload_len == 4 &&
                    decode_be32(s->control_in + 5) == PERF_PROTOCOL_VERSION) {
                    s->conn->session_ready = 1;
                } else if (type == MESSAGE_SESSION_ERROR) {
                    set_error(ctx, "xquic server session_error");
                    return XQC_ERROR;
                } else if (type == MESSAGE_SESSION_COMPLETE) {
                    s->conn->session_ready = 1;
                } else {
                    set_error(ctx, "xquic unexpected control message");
                    return XQC_ERROR;
                }
                size_t frame_len = (size_t)payload_len + 5;
                memmove(s->control_in, s->control_in + frame_len, s->control_in_len - frame_len);
                s->control_in_len -= frame_len;
            }
            return XQC_OK;
        }

        if (ctx->is_server) {
            if (!s->conn->session_started) {
                continue;
            }
            s->request_bytes = s->conn->session_start.request_bytes;
            s->request_received += (uint64_t)ret;
            if (fin) {
                if (s->request_fin) {
                    return XQC_OK;
                }
                s->request_fin = 1;
                if (s->request_received != s->request_bytes) {
                    set_error(ctx, "xquic server received unexpected request byte count");
                    return XQC_ERROR;
                }
                s->conn->server_bytes_received += s->request_received;
                s->conn->server_requests_completed++;
                s->response_bytes = server_response_bytes(&s->conn->session_start,
                                                          s->conn->server_requests_completed);
                s->send_len = (size_t)(s->response_bytes < WRITE_CHUNK_SIZE ? s->response_bytes
                                                                            : WRITE_CHUNK_SIZE);
                if (s->response_bytes > 0) {
                    s->send_buf = (uint8_t *)malloc(s->send_len);
                    if (s->send_buf == NULL) {
                        set_error(ctx, "xquic response allocation failed");
                        return XQC_ERROR;
                    }
                    memset(s->send_buf, 0x5a, s->send_len);
                } else {
                    s->send_buf = (uint8_t *)calloc(1, 1);
                }
                s->sent = 0;
                try_stream_send(s);
                s->conn->server_bytes_sent += s->response_bytes;
                if (should_send_complete(s->conn) && s->conn->control_stream != NULL) {
                    size_t msg_len = 0;
                    uint8_t *msg = encode_session_complete_message(
                        s->conn->server_bytes_sent, s->conn->server_bytes_received,
                        s->conn->server_requests_completed, &msg_len);
                    if (msg == NULL) {
                        set_error(ctx, "xquic session_complete allocation failed");
                        return XQC_ERROR;
                    }
                    set_stream_send_buffer(s->conn->control_stream, msg, msg_len, 1);
                    s->conn->server_complete_sent = 1;
                    try_stream_send(s->conn->control_stream);
                }
                return XQC_OK;
            }
        } else {
            uint64_t received = (uint64_t)ret;
            s->received += received;
            if (ctx->count_stream_bytes && s->counts && now_us() >= ctx->measure_start_us) {
                ctx->live_bytes_received += received;
            }
            if (fin) {
                completed_stream_t done;
                memset(&done, 0, sizeof(done));
                done.counts = s->counts;
                done.request_bytes = s->request_bytes;
                done.received = s->received;
                done.latency_us = now_us() - s->started_at;
                push_completed(ctx, done);
                xqc_stream_set_user_data(stream, NULL);
                remove_stream(s->conn, s);
                return XQC_OK;
            }
        }
        if (ret == 0 && !fin) {
            break;
        }
    }
    return XQC_OK;
}

static xqc_int_t stream_create_notify(xqc_stream_t *stream, void *strm_user_data) {
    conn_ctx_t *conn = (conn_ctx_t *)xqc_get_conn_alp_user_data_by_stream(stream);
    if (conn == NULL) {
        return XQC_ERROR;
    }
    stream_ctx_t *s = (stream_ctx_t *)strm_user_data;
    if (s == NULL) {
        s = add_stream(conn);
        if (s == NULL) {
            return XQC_ERROR;
        }
        if (conn->ctx->is_server && !conn->server_control_seen && !conn->session_started) {
            s->is_control = 1;
            conn->server_control_seen = 1;
            conn->control_stream = s;
        }
    }
    s->conn = conn;
    s->stream = stream;
    xqc_stream_set_user_data(stream, s);
    return XQC_OK;
}

static xqc_int_t stream_close_notify(xqc_stream_t *stream, void *strm_user_data) {
    (void)stream;
    stream_ctx_t *s = (stream_ctx_t *)strm_user_data;
    if (s != NULL) {
        remove_stream(s->conn, s);
    }
    return XQC_OK;
}

static int conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
                              void *conn_proto_data) {
    (void)conn_proto_data;
    conn_ctx_t *c = (conn_ctx_t *)user_data;
    if (c == NULL) {
        return XQC_ERROR;
    }
    c->conn = conn;
    memcpy(&c->cid, cid, sizeof(*cid));
    xqc_conn_set_transport_user_data(conn, c);
    xqc_conn_set_alp_user_data(conn, c);
    return XQC_OK;
}

static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
                             void *conn_proto_data) {
    (void)conn;
    (void)cid;
    (void)conn_proto_data;
    conn_ctx_t *c = (conn_ctx_t *)user_data;
    if (c != NULL) {
        c->closed = 1;
    }
    return XQC_OK;
}

static void conn_handshake_finished(xqc_connection_t *conn, void *conn_user_data,
                                    void *conn_proto_data) {
    (void)conn;
    (void)conn_proto_data;
    conn_ctx_t *c = (conn_ctx_t *)conn_user_data;
    if (c != NULL) {
        c->ready = 1;
        DEBUG_LOG("xquic handshake_finished conn=%p user_data=%p\n", conn, conn_user_data);
    }
}

static int server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
                         void *user_data) {
    (void)engine;
    perf_ctx_t *ctx = (perf_ctx_t *)user_data;
    DEBUG_LOG("xquic server_accept conn=%p user_data=%p\n", conn, user_data);
    conn_ctx_t *c = add_conn(ctx);
    if (c == NULL) {
        return XQC_ERROR;
    }
    c->conn = conn;
    memcpy(&c->cid, cid, sizeof(*cid));
    c->local_addrlen = sizeof(c->local_addr);
    c->peer_addrlen = sizeof(c->peer_addr);
    xqc_conn_get_local_addr(conn, (struct sockaddr *)&c->local_addr, sizeof(c->local_addr),
                            &c->local_addrlen);
    xqc_conn_get_peer_addr(conn, (struct sockaddr *)&c->peer_addr, sizeof(c->peer_addr),
                           &c->peer_addrlen);
    xqc_conn_set_transport_user_data(conn, c);
    xqc_conn_set_alp_user_data(conn, c);
    return XQC_OK;
}

static int create_engine(perf_ctx_t *ctx, int server) {
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, server ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT) !=
        XQC_OK) {
        return -1;
    }
    if (debug_enabled()) {
        config.cfg_log_level = XQC_LOG_DEBUG;
        config.cfg_log_event = 1;
        config.cfg_log_timestamp = 1;
        config.cfg_log_level_name = 1;
    }
    config.sendmmsg_on = 0;
    xqc_engine_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    ssl_cfg.private_key_file = server ? ctx->cfg.private_key : NULL;
    ssl_cfg.cert_file = server ? ctx->cfg.certificate_chain : NULL;
    ssl_cfg.ciphers = XQC_TLS_CIPHERS;
    ssl_cfg.groups = XQC_TLS_GROUPS;
    xqc_engine_callback_t callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.set_event_timer = timer_cb;
    callbacks.log_callbacks.xqc_log_write_err = xquic_log_cb;
    callbacks.log_callbacks.xqc_log_write_stat = xquic_log_cb;
    xqc_transport_callbacks_t transport;
    memset(&transport, 0, sizeof(transport));
    transport.write_socket = write_socket_cb;
    transport.write_socket_ex = write_socket_ex_cb;
    transport.server_accept = server ? server_accept : NULL;
    transport.conn_send_packet_before_accept = server ? write_socket_cb : NULL;
    transport.cert_verify_cb = cert_verify_cb;
    transport.save_token = save_token_cb;
    transport.save_session_cb = save_string_cb;
    transport.save_tp_cb = save_string_cb;
    ctx->engine = xqc_engine_create(server ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT, &config,
                                    &ssl_cfg, &callbacks, &transport, ctx);
    if (ctx->engine == NULL) {
        return -1;
    }
    xqc_app_proto_callbacks_t app;
    memset(&app, 0, sizeof(app));
    app.conn_cbs.conn_create_notify = conn_create_notify;
    app.conn_cbs.conn_close_notify = conn_close_notify;
    app.conn_cbs.conn_handshake_finished = conn_handshake_finished;
    app.stream_cbs.stream_read_notify = stream_read_notify;
    app.stream_cbs.stream_write_notify = stream_write_notify;
    app.stream_cbs.stream_create_notify = stream_create_notify;
    app.stream_cbs.stream_close_notify = stream_close_notify;
    if (xqc_engine_register_alpn(ctx->engine, APPLICATION_PROTOCOL, strlen(APPLICATION_PROTOCOL),
                                 &app, NULL) != XQC_OK) {
        return -1;
    }
    xqc_conn_settings_t settings = xqc_conn_get_conn_settings_template(XQC_CONN_SETTINGS_DEFAULT);
    settings.init_recv_window = TRANSFER_STREAM_WINDOW;
    settings.max_streams_bidi = TRANSFER_MAX_STREAMS;
    settings.max_streams_uni = 0;
    settings.idle_time_out = 30000;
    settings.init_idle_time_out = 30000;
    settings.max_udp_payload_size = MAX_DATAGRAM_SIZE;
    settings.enable_pmtud = ctx->cfg.disable_pmtud ? 0 : 3;
    if (strcmp(ctx->cfg.congestion_control, "newreno") == 0) {
#ifdef XQC_ENABLE_RENO
        settings.cong_ctrl_callback = xqc_reno_cb;
#else
        set_error(ctx, "xquic built without Reno");
#endif
    } else if (strcmp(ctx->cfg.congestion_control, "bbr") == 0) {
        settings.cong_ctrl_callback = xqc_bbr_cb;
    } else if (strcmp(ctx->cfg.congestion_control, "copa") == 0) {
#ifdef XQC_ENABLE_COPA
        settings.cong_ctrl_callback = xqc_copa_cb;
#else
        set_error(ctx, "xquic built without Copa");
#endif
    } else if (strcmp(ctx->cfg.congestion_control, "default") != 0 &&
               strcmp(ctx->cfg.congestion_control, "cubic") != 0) {
        set_error(ctx, "unsupported xquic congestion-control label");
    } else {
        settings.cong_ctrl_callback = xqc_cubic_cb;
    }
    if (server) {
        xqc_server_set_conn_settings(ctx->engine, &settings);
    }
    return ctx->error ? -1 : 0;
}

static int init_ctx(perf_ctx_t *ctx, const config_t *cfg, int server) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->fd = -1;
    ctx->magic = PERF_CTX_MAGIC;
    ctx->cfg = *cfg;
    ctx->is_server = server;
    if (server) {
        if (resolve_addr(cfg->host, cfg->port, &ctx->local_addr, &ctx->local_addrlen) != 0) {
            return -1;
        }
    } else {
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = 0;
        memcpy(&ctx->local_addr, &local, sizeof(local));
        ctx->local_addrlen = sizeof(local);
        if (resolve_addr(cfg->host, cfg->port, &ctx->peer_addr, &ctx->peer_addrlen) != 0) {
            return -1;
        }
    }
    ctx->fd = make_socket(&ctx->local_addr, ctx->local_addrlen);
    if (ctx->fd < 0) {
        return -1;
    }
    ctx->local_addrlen = sizeof(ctx->local_addr);
    getsockname(ctx->fd, (struct sockaddr *)&ctx->local_addr, &ctx->local_addrlen);
    if (create_engine(ctx, server) != 0) {
        cleanup_ctx(ctx);
        return -1;
    }
    return 0;
}

static perf_ctx_t *alloc_ctx(const config_t *cfg, int server) {
    perf_ctx_t *ctx = (perf_ctx_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->fd = -1;
    if (init_ctx(ctx, cfg, server) != 0) {
        cleanup_ctx(ctx);
        free(ctx);
        return NULL;
    }
    return ctx;
}

static void free_ctx(perf_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    cleanup_ctx(ctx);
    free(ctx);
}

static void drive_once(perf_ctx_t *ctx, uint64_t deadline_us) {
    int timeout_ms = 10;
    uint64_t now = now_us();
    if (ctx->next_wake_us > now) {
        uint64_t wake_ms = (ctx->next_wake_us - now + 999) / 1000;
        if (wake_ms < (uint64_t)timeout_ms) {
            timeout_ms = (int)wake_ms;
        }
    } else if (ctx->next_wake_us != 0) {
        timeout_ms = 0;
    } else if (deadline_us <= now) {
        timeout_ms = 0;
    }
    if (deadline_us > now) {
        uint64_t deadline_ms = (deadline_us - now + 999) / 1000;
        if (deadline_ms < (uint64_t)timeout_ms) {
            timeout_ms = (int)deadline_ms;
        }
    }
    struct pollfd pfd = {.fd = ctx->fd, .events = POLLIN, .revents = 0};
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret > 0 && (pfd.revents & POLLIN)) {
        for (;;) {
            unsigned char packet[65535];
            struct sockaddr_storage peer;
            socklen_t peer_len = sizeof(peer);
            ssize_t n =
                recvfrom(ctx->fd, packet, sizeof(packet), 0, (struct sockaddr *)&peer, &peer_len);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
            if (n < 0) {
                set_error(ctx, "xquic recvfrom failed");
                break;
            }
            DEBUG_LOG("xquic %s recv size=%zd\n", ctx->is_server ? "server" : "client", n);
            xqc_int_t process_ret = xqc_engine_packet_process(
                ctx->engine, packet, (size_t)n, (struct sockaddr *)&ctx->local_addr,
                ctx->local_addrlen, (struct sockaddr *)&peer, peer_len, wall_time_us(),
                ctx->is_server ? (void *)ctx : (void *)ctx->conns);
            DEBUG_LOG("xquic %s packet_process ret=%d\n", ctx->is_server ? "server" : "client",
                      process_ret);
        }
        xqc_engine_finish_recv(ctx->engine);
        DEBUG_LOG("xquic %s finish_recv\n", ctx->is_server ? "server" : "client");
    }
    if (ctx->next_wake_us != 0 && now_us() >= ctx->next_wake_us) {
        ctx->next_wake_us = 0;
        xqc_engine_main_logic(ctx->engine);
        DEBUG_LOG("xquic %s main_logic\n", ctx->is_server ? "server" : "client");
    }
}

static void run_server(const config_t *cfg) {
    perf_ctx_t *ctx = alloc_ctx(cfg, 1);
    if (ctx == NULL) {
        fprintf(stderr, "could not initialize xquic server\n");
        exit(1);
    }
    for (;;) {
        drive_once(ctx, now_us() + 1000000ULL);
    }
}

static conn_ctx_t *connect_one(perf_ctx_t *ctx) {
    conn_ctx_t *conn = add_conn(ctx);
    if (conn == NULL) {
        set_error(ctx, "xquic connection allocation failed");
        return NULL;
    }
    conn->peer_addr = ctx->peer_addr;
    conn->peer_addrlen = ctx->peer_addrlen;
    conn->local_addr = ctx->local_addr;
    conn->local_addrlen = ctx->local_addrlen;
    xqc_conn_settings_t settings = xqc_conn_get_conn_settings_template(XQC_CONN_SETTINGS_DEFAULT);
    settings.init_recv_window = TRANSFER_STREAM_WINDOW;
    settings.max_streams_bidi = TRANSFER_MAX_STREAMS;
    settings.max_streams_uni = 0;
    settings.idle_time_out = 30000;
    settings.init_idle_time_out = 30000;
    settings.max_udp_payload_size = MAX_DATAGRAM_SIZE;
    settings.enable_pmtud = ctx->cfg.disable_pmtud ? 0 : 3;
    if (strcmp(ctx->cfg.congestion_control, "newreno") == 0) {
#ifdef XQC_ENABLE_RENO
        settings.cong_ctrl_callback = xqc_reno_cb;
#else
        set_error(ctx, "xquic built without Reno");
#endif
    } else if (strcmp(ctx->cfg.congestion_control, "bbr") == 0) {
        settings.cong_ctrl_callback = xqc_bbr_cb;
    } else if (strcmp(ctx->cfg.congestion_control, "copa") == 0) {
#ifdef XQC_ENABLE_COPA
        settings.cong_ctrl_callback = xqc_copa_cb;
#else
        set_error(ctx, "xquic built without Copa");
#endif
    } else if (strcmp(ctx->cfg.congestion_control, "default") != 0 &&
               strcmp(ctx->cfg.congestion_control, "cubic") != 0) {
        set_error(ctx, "unsupported xquic congestion-control label");
    } else {
        settings.cong_ctrl_callback = xqc_cubic_cb;
    }
    if (ctx->error) {
        return NULL;
    }
    xqc_conn_ssl_config_t ssl;
    memset(&ssl, 0, sizeof(ssl));
    ssl.cert_verify_flag = XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
    const xqc_cid_t *cid = xqc_connect(ctx->engine, &settings, NULL, 0, ctx->cfg.server_name, 0,
                                       &ssl, (struct sockaddr *)&ctx->peer_addr, ctx->peer_addrlen,
                                       APPLICATION_PROTOCOL, conn);
    if (cid == NULL) {
        set_error(ctx, "xqc_connect failed");
        return NULL;
    }
    memcpy(&conn->cid, cid, sizeof(*cid));
    DEBUG_LOG("xquic client connect cid=%p conn_ctx=%p\n", (const void *)cid, (void *)conn);
    xqc_engine_main_logic(ctx->engine);
    DEBUG_LOG("xquic client initial main_logic\n");
    uint64_t deadline = now_us() + 10000000ULL;
    while (!conn->ready && !ctx->error && now_us() < deadline) {
        drive_once(ctx, deadline);
    }
    if (!conn->ready && !ctx->error) {
        set_error(ctx, "xquic handshake timed out");
    }
    return conn;
}

static int open_connections(perf_ctx_t *ctx, uint64_t count) {
    for (uint64_t i = 0; i < count; ++i) {
        conn_ctx_t *conn = connect_one(ctx);
        if (ctx->error || conn == NULL) {
            return -1;
        }
        conn->request_limit = rr_request_limit_for_connection(&ctx->cfg, i);
        if (open_control_stream(ctx, conn) == NULL) {
            return -1;
        }
        uint64_t deadline = now_us() + 10000000ULL;
        while (!conn->session_ready && !ctx->error && now_us() < deadline) {
            drive_once(ctx, deadline);
        }
        if (!conn->session_ready && !ctx->error) {
            set_error(ctx, "xquic session_ready timed out");
            return -1;
        }
    }
    return 0;
}

static conn_ctx_t *connection_at(perf_ctx_t *ctx, uint64_t index) {
    uint64_t current = 0;
    for (conn_ctx_t *conn = ctx->conns; conn != NULL; conn = conn->next) {
        if (current == index) {
            return conn;
        }
        current++;
    }
    return NULL;
}

static stream_ctx_t *open_control_stream(perf_ctx_t *ctx, conn_ctx_t *conn) {
    stream_ctx_t *s = add_stream(conn);
    if (s == NULL) {
        set_error(ctx, "xquic control stream allocation failed");
        return NULL;
    }
    s->is_control = 1;
    s->send_fin_on_complete = 1;
    size_t msg_len = 0;
    uint8_t *msg = encode_session_start_message(&ctx->cfg, conn->request_limit, &msg_len);
    if (msg == NULL) {
        remove_stream(conn, s);
        set_error(ctx, "xquic session_start allocation failed");
        return NULL;
    }
    set_stream_send_buffer(s, msg, msg_len, 1);
    s->stream = xqc_stream_create(ctx->engine, &conn->cid, NULL, s);
    if (s->stream == NULL) {
        remove_stream(conn, s);
        set_error(ctx, "xqc_stream_create control failed");
        return NULL;
    }
    conn->control_stream = s;
    try_stream_send(s);
    xqc_engine_main_logic(ctx->engine);
    return s;
}

static stream_ctx_t *open_request(perf_ctx_t *ctx, conn_ctx_t *conn, int counts,
                                  uint64_t request_bytes, uint64_t response_bytes) {
    if (conn == NULL) {
        set_error(ctx, "xquic connection missing");
        return NULL;
    }
    stream_ctx_t *s = add_stream(conn);
    if (s == NULL) {
        set_error(ctx, "xquic stream allocation failed");
        return NULL;
    }
    s->request_bytes = request_bytes;
    s->response_bytes = response_bytes;
    s->counts = counts;
    s->started_at = now_us();
    s->send_len = (size_t)request_bytes;
    s->send_buf = (uint8_t *)malloc(s->send_len == 0 ? 1 : s->send_len);
    if (s->send_buf == NULL) {
        set_error(ctx, "xquic request allocation failed");
        return NULL;
    }
    memset(s->send_buf, 0x5a, (size_t)request_bytes);
    s->stream = xqc_stream_create(ctx->engine, &conn->cid, NULL, s);
    if (s->stream == NULL) {
        set_error(ctx, "xqc_stream_create failed");
        remove_stream(conn, s);
        return NULL;
    }
    try_stream_send(s);
    xqc_engine_main_logic(ctx->engine);
    return s;
}

static size_t active_streams(perf_ctx_t *ctx) {
    size_t count = 0;
    for (conn_ctx_t *c = ctx->conns; c != NULL; c = c->next) {
        for (stream_ctx_t *s = c->streams; s != NULL; s = s->next) {
            if (!s->is_control) {
                count++;
            }
        }
    }
    return count;
}

static size_t active_streams_for_conn(conn_ctx_t *conn) {
    size_t count = 0;
    for (stream_ctx_t *s = conn->streams; s != NULL; s = s->next) {
        if (!s->is_control) {
            count++;
        }
    }
    return count;
}

static void open_rr_refill(config_t *cfg, perf_ctx_t *ctx, uint64_t *started,
                           uint64_t measure_start, uint64_t deadline) {
    uint64_t connections = rr_connection_target(cfg);
    for (uint64_t i = 0; !ctx->error && i < connections; ++i) {
        conn_ctx_t *conn = connection_at(ctx, i);
        while (conn != NULL && active_streams_for_conn(conn) < cfg->requests_in_flight) {
            if (cfg->requests.set) {
                if (*started >= cfg->requests.value) {
                    return;
                }
                if (conn->started_requests >= conn->request_limit) {
                    break;
                }
            }
            if (!cfg->requests.set && now_us() >= deadline) {
                return;
            }
            open_request(ctx, conn, cfg->requests.set || now_us() >= measure_start,
                         cfg->request_bytes, cfg->response_bytes);
            conn->started_requests++;
            (*started)++;
        }
    }
}

static void append_latency(counters_t *c, uint64_t latency) {
    if (c->latency_len == c->latency_cap) {
        size_t next_cap = c->latency_cap == 0 ? 1024 : c->latency_cap * 2;
        uint64_t *next = (uint64_t *)realloc(c->latencies, next_cap * sizeof(uint64_t));
        if (next == NULL) {
            return;
        }
        c->latencies = next;
        c->latency_cap = next_cap;
    }
    c->latencies[c->latency_len++] = latency;
}

static void consume_completed(perf_ctx_t *ctx, counters_t *c, uint64_t measure_start,
                              int count_bulk) {
    for (size_t i = 0; i < ctx->completed_len; ++i) {
        completed_stream_t *done = &ctx->completed[i];
        if (done->counts && now_us() >= measure_start) {
            c->bytes_sent += done->request_bytes;
            c->bytes_received += done->received;
            if (!count_bulk) {
                c->requests_completed++;
                append_latency(c, done->latency_us);
            }
        }
    }
    ctx->completed_len = 0;
}

static void consume_completed_bulk(perf_ctx_t *ctx, counters_t *c, uint64_t measure_start) {
    for (size_t i = 0; i < ctx->completed_len; ++i) {
        completed_stream_t *done = &ctx->completed[i];
        if (done->counts && now_us() >= measure_start) {
            c->bytes_received += done->received;
        }
    }
    ctx->completed_len = 0;
}

static void run_timed_bulk_download(config_t *cfg, counters_t *c) {
    perf_ctx_t *ctx = alloc_ctx(cfg, 0);
    if (ctx == NULL) {
        fprintf(stderr, "could not initialize xquic client\n");
        exit(1);
    }
    uint64_t connections = rr_connection_target(cfg);
    if (!ctx->error && open_connections(ctx, connections) != 0) {
        set_error(ctx, "could not connect xquic client");
    }
    uint64_t measure_start = now_us() + cfg->warmup_us;
    uint64_t deadline = measure_start + cfg->duration_us;
    ctx->measure_start_us = measure_start;
    ctx->count_stream_bytes = 1;
    for (uint64_t i = 0; !ctx->error && i < cfg->connections; ++i) {
        conn_ctx_t *conn = connection_at(ctx, i);
        for (uint64_t j = 0; j < cfg->streams; ++j) {
            open_request(ctx, conn, 1, 0, TIMED_BULK_RESPONSE_BYTES);
        }
    }
    while (!ctx->error && now_us() < deadline) {
        drive_once(ctx, deadline);
        ctx->completed_len = 0;
    }
    if (ctx->error) {
        fprintf(stderr, "%s\n", ctx->error_message);
        free_ctx(ctx);
        exit(1);
    }
    c->bytes_received += ctx->live_bytes_received;
    free_ctx(ctx);
}

static void run_fixed_bulk(config_t *cfg, counters_t *c) {
    if (!cfg->total_bytes.set) {
        fprintf(stderr, "fixed bulk requires --total-bytes for xquic client\n");
        exit(1);
    }
    perf_ctx_t *ctx = alloc_ctx(cfg, 0);
    if (ctx == NULL) {
        fprintf(stderr, "could not initialize xquic client\n");
        exit(1);
    }
    if (!ctx->error && open_connections(ctx, cfg->connections) != 0) {
        set_error(ctx, "could not connect xquic client");
    }
    uint64_t per_stream = cfg->total_bytes.value / cfg->streams;
    uint64_t remainder = cfg->total_bytes.value % cfg->streams;
    for (uint64_t i = 0; i < cfg->streams; ++i) {
        uint64_t target = per_stream + (i < remainder ? 1 : 0);
        conn_ctx_t *conn = connection_at(ctx, i % cfg->connections);
        if (strcmp(cfg->direction, "upload") == 0) {
            open_request(ctx, conn, 1, target, 0);
        } else {
            open_request(ctx, conn, 1, 0, target);
        }
    }
    while (!ctx->error && active_streams(ctx) > 0) {
        drive_once(ctx, now_us() + 10000000ULL);
        consume_completed(ctx, c, 0, 1);
    }
    if (ctx->error) {
        fprintf(stderr, "%s\n", ctx->error_message);
        free_ctx(ctx);
        exit(1);
    }
    free_ctx(ctx);
}

static void run_rr(config_t *cfg, counters_t *c) {
    perf_ctx_t *ctx = alloc_ctx(cfg, 0);
    if (ctx == NULL) {
        fprintf(stderr, "could not initialize xquic client\n");
        exit(1);
    }
    if (!ctx->error && open_connections(ctx, cfg->connections) != 0) {
        set_error(ctx, "could not connect xquic client");
    }
    uint64_t measure_start = now_us() + cfg->warmup_us;
    uint64_t deadline = measure_start + cfg->duration_us;
    uint64_t started = 0;
    open_rr_refill(cfg, ctx, &started, measure_start, deadline);
    while (!ctx->error) {
        if (!cfg->requests.set && now_us() >= deadline) {
            break;
        }
        if (cfg->requests.set && started >= cfg->requests.value && active_streams(ctx) == 0) {
            break;
        }
        drive_once(ctx, deadline);
        consume_completed(ctx, c, measure_start, 0);
        open_rr_refill(cfg, ctx, &started, measure_start, deadline);
    }
    if (ctx->error) {
        fprintf(stderr, "%s\n", ctx->error_message);
        free_ctx(ctx);
        exit(1);
    }
    free_ctx(ctx);
}

static int start_one_crr(config_t *cfg, counters_t *c, uint64_t measure_start, uint64_t *started,
                         perf_ctx_t *ctx) {
    if (cfg->requests.set && *started >= cfg->requests.value) {
        return 0;
    }
    if (init_ctx(ctx, cfg, 0) != 0) {
        if (cfg->requests.set) {
            set_error(ctx, "could not initialize xquic client");
        } else {
            c->skipped_setup_errors++;
        }
        return 0;
    }
    conn_ctx_t *conn = connect_one(ctx);
    if (ctx->error || conn == NULL) {
        if (!cfg->requests.set) {
            c->skipped_setup_errors++;
            cleanup_ctx(ctx);
            memset(ctx, 0, sizeof(*ctx));
            ctx->fd = -1;
        }
        return 0;
    }
    open_request(ctx, conn, cfg->requests.set || now_us() >= measure_start, cfg->request_bytes,
                 cfg->response_bytes);
    if (ctx->error || active_streams(ctx) == 0) {
        if (!cfg->requests.set) {
            c->skipped_setup_errors++;
            cleanup_ctx(ctx);
            memset(ctx, 0, sizeof(*ctx));
            ctx->fd = -1;
        }
        return 0;
    }
    (*started)++;
    return 1;
}

static void run_crr(config_t *cfg, counters_t *c) {
    uint64_t measure_start = now_us() + cfg->warmup_us;
    uint64_t deadline = measure_start + cfg->duration_us;
    uint64_t started = 0;
    size_t ctx_count = (size_t)cfg->connections;
    perf_ctx_t *contexts = (perf_ctx_t *)calloc(ctx_count, sizeof(perf_ctx_t));
    if (contexts == NULL) {
        fprintf(stderr, "xquic CRR context allocation failed\n");
        exit(1);
    }
    for (size_t i = 0; i < ctx_count; ++i) {
        contexts[i].fd = -1;
    }
    while (1) {
        for (size_t i = 0; i < ctx_count; ++i) {
            if (contexts[i].engine != NULL) {
                continue;
            }
            if (cfg->requests.set) {
                if (started >= cfg->requests.value) {
                    continue;
                }
            } else if (now_us() >= deadline) {
                continue;
            }
            start_one_crr(cfg, c, measure_start, &started, &contexts[i]);
        }

        size_t active = 0;
        for (size_t i = 0; i < ctx_count; ++i) {
            perf_ctx_t *ctx = &contexts[i];
            if (ctx->engine == NULL) {
                continue;
            }
            if (ctx->error) {
                if (cfg->requests.set) {
                    fprintf(stderr, "%s\n", ctx->error_message);
                    for (size_t j = 0; j < ctx_count; ++j) {
                        cleanup_ctx(&contexts[j]);
                    }
                    free(contexts);
                    exit(1);
                }
                c->skipped_setup_errors++;
                cleanup_ctx(ctx);
                memset(ctx, 0, sizeof(*ctx));
                ctx->fd = -1;
                continue;
            }
            if (active_streams(ctx) > 0) {
                drive_once(ctx, now_us() + 1000ULL);
                consume_completed(ctx, c, measure_start, 0);
            }
            if (ctx->engine != NULL && active_streams(ctx) == 0) {
                cleanup_ctx(ctx);
                memset(ctx, 0, sizeof(*ctx));
                ctx->fd = -1;
            } else if (ctx->engine != NULL) {
                active++;
            }
        }
        if (cfg->requests.set && c->requests_completed >= cfg->requests.value) {
            break;
        }
        if (!cfg->requests.set && now_us() >= deadline && active == 0) {
            break;
        }
        if (cfg->requests.set && started >= cfg->requests.value && active == 0) {
            break;
        }
    }
    for (size_t i = 0; i < ctx_count; ++i) {
        cleanup_ctx(&contexts[i]);
    }
    free(contexts);
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t av = *(const uint64_t *)a;
    uint64_t bv = *(const uint64_t *)b;
    return (av > bv) - (av < bv);
}

static latency_summary_t summarize_latency(counters_t *c) {
    latency_summary_t out;
    memset(&out, 0, sizeof(out));
    if (c->latency_len == 0) {
        return out;
    }
    qsort(c->latencies, c->latency_len, sizeof(uint64_t), cmp_u64);
    uint64_t total = 0;
    for (size_t i = 0; i < c->latency_len; ++i) {
        total += c->latencies[i];
    }
    out.min_us = c->latencies[0];
    out.avg_us = total / c->latency_len;
    out.p50_us = c->latencies[(c->latency_len * 50 + 99) / 100 - 1];
    out.p90_us = c->latencies[(c->latency_len * 90 + 99) / 100 - 1];
    out.p99_us = c->latencies[(c->latency_len * 99 + 99) / 100 - 1];
    out.max_us = c->latencies[c->latency_len - 1];
    return out;
}

static void emit_summary(config_t *cfg, counters_t *c, uint64_t elapsed_us, const char *failure) {
    double seconds = (double)elapsed_us / 1000000.0;
    if (seconds < 0.001) {
        seconds = 0.001;
    }
    uint64_t total_bytes = c->bytes_sent + c->bytes_received;
    double mib = (double)total_bytes / (1024.0 * 1024.0) / seconds;
    double gbit = (double)total_bytes * 8.0 / 1000000000.0 / seconds;
    double rps = (double)c->requests_completed / seconds;
    latency_summary_t latency = summarize_latency(c);
    printf("status=%s mode=%s cc=%s direction=%s throughput_mib/s=%.3f throughput_gbit/s=%.3f "
           "requests/s=%.3f\n",
           failure == NULL ? "ok" : "failed", cfg->mode, cfg->congestion_control, cfg->direction,
           mib, gbit, rps);
    if (cfg->json_out[0] == 0) {
        return;
    }
    FILE *f = open_json_output(cfg->json_out);
    if (f == NULL) {
        return;
    }
    fprintf(f, "{\n");
    fprintf(f, "  \"schema_version\": 1,\n");
    fprintf(f, "  \"status\": \"%s\",\n", failure == NULL ? "ok" : "failed");
    fprintf(f, "  \"mode\": \"%s\",\n", cfg->mode);
    fprintf(f, "  \"direction\": \"%s\",\n", cfg->direction);
    fprintf(f, "  \"backend\": \"xquic\",\n");
    fprintf(f, "  \"congestion_control\": \"%s\",\n", cfg->congestion_control);
    fprintf(f, "  \"remote_host\": \"%s\",\n", cfg->host);
    fprintf(f, "  \"remote_port\": %u,\n", cfg->port);
    fprintf(f, "  \"alpn\": \"%s\",\n", APPLICATION_PROTOCOL);
    fprintf(f, "  \"elapsed_ms\": %" PRIu64 ",\n", elapsed_us / 1000);
    fprintf(f, "  \"warmup_ms\": %" PRIu64 ",\n", cfg->warmup_us / 1000);
    fprintf(f, "  \"bytes_sent\": %" PRIu64 ",\n", c->bytes_sent);
    fprintf(f, "  \"bytes_received\": %" PRIu64 ",\n", c->bytes_received);
    fprintf(f,
            "  \"server_counters\": {\"bytes_sent\": %" PRIu64 ", \"bytes_received\": %" PRIu64
            ", \"requests_completed\": %" PRIu64 "},\n",
            c->bytes_received, c->bytes_sent, c->requests_completed);
    fprintf(f, "  \"requests_completed\": %" PRIu64 ",\n", c->requests_completed);
    fprintf(f, "  \"streams\": %" PRIu64 ",\n", cfg->streams);
    fprintf(f, "  \"connections\": %" PRIu64 ",\n", cfg->connections);
    fprintf(f, "  \"requests_in_flight\": %" PRIu64 ",\n", cfg->requests_in_flight);
    fprintf(f, "  \"request_bytes\": %" PRIu64 ",\n", cfg->request_bytes);
    fprintf(f, "  \"response_bytes\": %" PRIu64 ",\n", cfg->response_bytes);
    fprintf(f, "  \"throughput_mib_per_s\": %.3f,\n", mib);
    fprintf(f, "  \"throughput_gbit_per_s\": %.3f,\n", gbit);
    fprintf(f, "  \"requests_per_s\": %.3f,\n", rps);
    fprintf(f,
            "  \"latency\": {\"min_us\": %" PRIu64 ", \"avg_us\": %" PRIu64 ", \"p50_us\": %" PRIu64
            ", \"p90_us\": %" PRIu64 ", \"p99_us\": %" PRIu64 ", \"max_us\": %" PRIu64 "}",
            latency.min_us, latency.avg_us, latency.p50_us, latency.p90_us, latency.p99_us,
            latency.max_us);
    if (failure != NULL) {
        fprintf(f, ",\n  \"failure_reason\": \"%s\"", failure);
    }
    if (c->skipped_setup_errors != 0) {
        fprintf(f, ",\n  \"skipped_setup_errors\": %" PRIu64, c->skipped_setup_errors);
    }
    fprintf(f, "\n}\n");
    fclose(f);
}

static void run_client(config_t *cfg) {
    counters_t counters;
    memset(&counters, 0, sizeof(counters));
    uint64_t start = now_us();
    if (strcmp(cfg->mode, "bulk") == 0) {
        if (strcmp(cfg->direction, "download") == 0 && !cfg->total_bytes.set) {
            run_timed_bulk_download(cfg, &counters);
            emit_summary(cfg, &counters, cfg->duration_us, NULL);
        } else {
            run_fixed_bulk(cfg, &counters);
            emit_summary(cfg, &counters, now_us() - start, NULL);
        }
    } else if (strcmp(cfg->mode, "rr") == 0) {
        run_rr(cfg, &counters);
        emit_summary(cfg, &counters, cfg->requests.set ? now_us() - start : cfg->duration_us, NULL);
    } else if (strcmp(cfg->mode, "crr") == 0) {
        run_crr(cfg, &counters);
        emit_summary(cfg, &counters, cfg->requests.set ? now_us() - start : cfg->duration_us, NULL);
    } else {
        emit_summary(cfg, &counters, 1, "unsupported mode");
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "client") != 0 && strcmp(argv[1], "server") != 0)) {
        fprintf(stderr, "usage: xquic-perf [client|server] [options]\n");
        return 2;
    }
    config_t cfg;
    parse_args(&cfg, argc - 2, argv + 2);
    if (strcmp(argv[1], "server") == 0) {
        run_server(&cfg);
    } else {
        run_client(&cfg);
    }
    return 0;
}
