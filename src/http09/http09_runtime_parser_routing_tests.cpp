#include "src/http09/http09_runtime_test_support.h"

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_profile_instrument_function)), apply_to = function)
#endif

namespace coquic::http09 {

namespace test {

bool runtime_parser_and_utility_coverage_for_tests() {
    bool ok = true;
    struct RuntimeParserUtilityCheck {
        bool &ok;
        bool operator()(std::string_view label, bool condition) const {
            if (!condition) {
                std::cerr << "runtime_parser_and_utility_coverage_for_tests failed: " << label
                          << '\n';
                ok = false;
            }
            return condition;
        }
    } check{ok};

    apply_runtime_ops_override(runtime_ops());
    check("parse_io_backend_kind accepts socket",
          parse_io_backend_kind("socket") == io::QuicIoBackendKind::socket);

    sockaddr_storage trace_address{};
    auto &trace_ipv4 = *reinterpret_cast<sockaddr_in *>(&trace_address);
    trace_ipv4.sin_family = AF_INET;
    trace_ipv4.sin_port = htons(443);
    trace_ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check("format_sockaddr_for_trace prints numeric host and port",
          format_sockaddr_for_trace(trace_address, sizeof(sockaddr_in)) == "127.0.0.1:443");

    ResolvedUdpAddress bind_address{};
    auto &bind_ipv4 = *reinterpret_cast<sockaddr_in *>(&bind_address.address);
    bind_ipv4.sin_family = AF_INET;
    bind_ipv4.sin_port = htons(0);
    bind_ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_address.address_len = sizeof(sockaddr_in);
    bind_address.family = AF_INET;

    {
        const int socket_fd = open_and_bind_udp_socket(bind_address, "client");
        check("open_and_bind_udp_socket succeeds for loopback ephemeral binds", socket_fd >= 0);
        if (socket_fd >= 0) {
            ::close(socket_fd);
        }
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .socket_fn = [](int, int, int) -> int {
                    errno = EMFILE;
                    return -1;
                },
            },
        };
        check("open_and_bind_udp_socket reports socket creation failures",
              open_and_bind_udp_socket(bind_address, "client") < 0);
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .socket_fn = &::socket,
                .bind_fn = [](int, const sockaddr *, socklen_t) -> int {
                    errno = EADDRINUSE;
                    return -1;
                },
            },
        };
        check("open_and_bind_udp_socket reports bind failures",
              open_and_bind_udp_socket(bind_address, "client") < 0);
    }

    check("v1 initial header type recognized", is_initial_long_header_type(kQuicVersion1, 0x00u));
    check("v2 initial header type recognized", is_initial_long_header_type(kQuicVersion2, 0x01u));
    check("big-endian u32 reader decodes version words", read_u32_be_at(
                                                             std::array{
                                                                 std::byte{0x01},
                                                                 std::byte{0x23},
                                                                 std::byte{0x45},
                                                                 std::byte{0x67},
                                                             },
                                                             0) == 0x01234567u);

    struct LongHeaderSpec {
        std::uint8_t first_byte = 0;
        std::uint32_t version = 0;
        std::span<const std::byte> destination_connection_id;
        std::span<const std::byte> source_connection_id;
        std::span<const std::byte> tail = {};
    };
    const auto make_long_header = [](const LongHeaderSpec &spec) {
        std::vector<std::byte> bytes;
        bytes.push_back(static_cast<std::byte>(spec.first_byte));
        bytes.push_back(static_cast<std::byte>((spec.version >> 24) & 0xffu));
        bytes.push_back(static_cast<std::byte>((spec.version >> 16) & 0xffu));
        bytes.push_back(static_cast<std::byte>((spec.version >> 8) & 0xffu));
        bytes.push_back(static_cast<std::byte>(spec.version & 0xffu));
        bytes.push_back(static_cast<std::byte>(spec.destination_connection_id.size()));
        bytes.insert(bytes.end(), spec.destination_connection_id.begin(),
                     spec.destination_connection_id.end());
        bytes.push_back(static_cast<std::byte>(spec.source_connection_id.size()));
        bytes.insert(bytes.end(), spec.source_connection_id.begin(),
                     spec.source_connection_id.end());
        bytes.insert(bytes.end(), spec.tail.begin(), spec.tail.end());
        return bytes;
    };

    const auto destination_connection_id = make_runtime_connection_id(std::byte{0x41}, 1);
    const auto source_connection_id = make_runtime_connection_id(std::byte{0x42}, 2);

    check("empty datagram does not parse", !parse_server_datagram_for_routing({}).has_value());
    check("short header without fixed bit is rejected",
          !parse_server_datagram_for_routing(std::vector<std::byte>{std::byte{0x00}}).has_value());
    check("short header shorter than runtime cid length is rejected",
          !parse_server_datagram_for_routing(
               std::vector<std::byte>{std::byte{0x40}, std::byte{0x01}, std::byte{0x02}})
               .has_value());
    {
        std::vector<std::byte> short_header{std::byte{0x40}};
        short_header.insert(short_header.end(), destination_connection_id.begin(),
                            destination_connection_id.end());
        const auto parsed = parse_server_datagram_for_routing(short_header);
        check("valid short header parses", parsed.has_value());
        check("short header kind is reported",
              parsed.has_value() && parsed->kind == ParsedServerDatagram::Kind::short_header);
    }

    check("long header missing fixed bit is rejected",
          !parse_server_datagram_for_routing(
               std::vector<std::byte>{std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                                      std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                      std::byte{0x00}})
               .has_value());
    check("fixed-bit long headers shorter than the minimum prefix are rejected",
          !parse_server_datagram_for_routing(
               std::vector<std::byte>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                      std::byte{0x00}, std::byte{0x01}, std::byte{0x00}})
               .has_value());
    check("version negotiation packets are ignored",
          !parse_server_datagram_for_routing(
               make_long_header(LongHeaderSpec{
                   .first_byte = 0xc0u,
                   .version = kVersionNegotiationVersion,
                   .destination_connection_id = destination_connection_id,
                   .source_connection_id = source_connection_id,
               }))
               .has_value());
    check("destination connection id length overflow is rejected",
          !parse_server_datagram_for_routing(
               std::vector<std::byte>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                      std::byte{0x00}, std::byte{0x01}, std::byte{0x08},
                                      std::byte{0x01}})
               .has_value());
    check("source connection id length overflow is rejected",
          !parse_server_datagram_for_routing(
               std::vector<std::byte>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                      std::byte{0x00}, std::byte{0x01}, std::byte{0x01},
                                      std::byte{0x01}, std::byte{0x08}, std::byte{0x02}})
               .has_value());

    {
        constexpr std::uint32_t kUnsupportedVersion = 0xfaceb00cu;
        const auto parsed = parse_server_datagram_for_routing(make_long_header(LongHeaderSpec{
            .first_byte = 0xc0u,
            .version = kUnsupportedVersion,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = source_connection_id,
        }));
        check("unsupported versions parse as probes", parsed.has_value());
        check("unsupported versions are classified as unsupported long headers",
              parsed.has_value() &&
                  parsed->kind == ParsedServerDatagram::Kind::unsupported_version_long_header);
    }

    {
        const auto parsed = parse_server_datagram_for_routing(make_long_header(LongHeaderSpec{
            .first_byte = 0xc0u,
            .version = kQuicVersion1,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = source_connection_id,
        }));
        check("initial headers with truncated token varints are rejected", !parsed.has_value());
    }

    {
        const auto oversized_token_length = encode_varint(2).value();
        const auto parsed = parse_server_datagram_for_routing(make_long_header(LongHeaderSpec{
            .first_byte = 0xc0u,
            .version = kQuicVersion1,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = source_connection_id,
            .tail = oversized_token_length,
        }));
        check("initial headers with oversized tokens are rejected", !parsed.has_value());
    }

    {
        const auto zero_token_length = encode_varint(0).value();
        const auto parsed = parse_server_datagram_for_routing(make_long_header(LongHeaderSpec{
            .first_byte = 0xe0u,
            .version = kQuicVersion1,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = source_connection_id,
            .tail = zero_token_length,
        }));
        check("supported non-initial long headers parse", parsed.has_value());
        check("supported non-initial long headers keep empty retry tokens",
              parsed.has_value() && parsed->token.empty() &&
                  parsed->kind == ParsedServerDatagram::Kind::supported_long_header);
    }

    {
        auto token = encode_varint(1).value();
        token.push_back(std::byte{0xaa});
        const auto parsed = parse_server_datagram_for_routing(make_long_header(LongHeaderSpec{
            .first_byte = 0xc0u,
            .version = kQuicVersion1,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = source_connection_id,
            .tail = token,
        }));
        check("supported initial long headers parse", parsed.has_value());
        check("supported initial long headers preserve retry tokens",
              parsed.has_value() && parsed->kind == ParsedServerDatagram::Kind::supported_initial &&
                  parsed->token == std::vector<std::byte>{std::byte{0xaa}});
    }

    {
        const auto zero_token_length = encode_varint(0).value();
        const auto parsed = parse_server_datagram_for_routing(make_long_header(LongHeaderSpec{
            .first_byte = 0xd0u,
            .version = kQuicVersion2,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = source_connection_id,
            .tail = zero_token_length,
        }));
        check("v2 initial long headers parse", parsed.has_value());
        check("v2 initial long headers use the v2 initial type mapping",
              parsed.has_value() && parsed->kind == ParsedServerDatagram::Kind::supported_initial);
    }

    return ok;
}

bool runtime_retry_and_probe_coverage_for_tests() {
    bool ok = true;
    struct RuntimeRetryProbeCheck {
        bool &ok;
        bool operator()(std::string_view label, bool condition) const {
            if (!condition) {
                std::cerr << "runtime_retry_and_probe_coverage_for_tests failed: " << label << '\n';
                ok = false;
            }
            return condition;
        }
    } check{ok};

    sockaddr_storage peer{};
    auto &peer_ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    peer_ipv4.sin_family = AF_INET;
    peer_ipv4.sin_port = htons(4443);
    peer_ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    const auto destination_connection_id = make_runtime_connection_id(std::byte{0x51}, 1);
    const auto source_connection_id = make_runtime_connection_id(std::byte{0x61}, 2);
    const ParsedServerDatagram supported_initial{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .version = kQuicVersion1,
        .destination_connection_id = destination_connection_id,
        .source_connection_id = source_connection_id,
        .token = {},
    };

    const auto retry_token = make_runtime_retry_token(0x0102030405060708ull);
    check("retry token encodes the runtime prefix",
          retry_token.size() == 16 && retry_token[0] == std::byte{0x72} &&
              retry_token[1] == std::byte{0x74} && retry_token[2] == std::byte{0x72} &&
              retry_token[3] == std::byte{0x79});

    PendingRetryToken pending_retry{
        .original_destination_connection_id = destination_connection_id,
        .retry_source_connection_id = make_runtime_connection_id(std::byte{0x71}, 3),
        .original_version = kQuicVersion1,
        .peer = peer,
        .peer_len = sizeof(sockaddr_in),
    };
    check("retry peer matching accepts the original peer",
          peer_matches_pending_retry(pending_retry, peer, sizeof(sockaddr_in)));

    sockaddr_storage other_peer = peer;
    auto &other_ipv4 = *reinterpret_cast<sockaddr_in *>(&other_peer);
    other_ipv4.sin_port = htons(4444);
    check("retry peer matching rejects mismatched peers",
          !peer_matches_pending_retry(pending_retry, other_peer, sizeof(sockaddr_in)));

    {
        RetryTokenStore retry_tokens;
        check("missing retry token lookup returns nullopt",
              !lookup_retry_context(supported_initial, peer, sizeof(sockaddr_in), retry_tokens)
                   .has_value());
    }

    {
        ParsedServerDatagram parsed = supported_initial;
        parsed.token = retry_token;
        parsed.destination_connection_id = pending_retry.retry_source_connection_id;
        RetryTokenStore retry_tokens{
            {connection_id_key(retry_token), pending_retry},
        };
        check("retry lookup rejects peer mismatches",
              !lookup_retry_context(parsed, other_peer, sizeof(sockaddr_in), retry_tokens)
                   .has_value());
        check("retry lookup keeps stored tokens on mismatch",
              retry_tokens.contains(connection_id_key(retry_token)));
    }

    {
        ParsedServerDatagram parsed = supported_initial;
        parsed.token = retry_token;
        parsed.destination_connection_id = make_runtime_connection_id(std::byte{0x72}, 4);
        RetryTokenStore retry_tokens{
            {connection_id_key(retry_token), pending_retry},
        };
        check("retry lookup rejects destination connection id mismatches",
              !lookup_retry_context(parsed, peer, sizeof(sockaddr_in), retry_tokens).has_value());
    }

    {
        ParsedServerDatagram parsed = supported_initial;
        parsed.token = retry_token;
        parsed.destination_connection_id = pending_retry.retry_source_connection_id;
        parsed.version = kQuicVersion2;
        RetryTokenStore retry_tokens{
            {connection_id_key(retry_token), pending_retry},
        };
        check("retry lookup rejects version mismatches",
              !lookup_retry_context(parsed, peer, sizeof(sockaddr_in), retry_tokens).has_value());
    }

    {
        ParsedServerDatagram parsed = supported_initial;
        parsed.token = retry_token;
        parsed.destination_connection_id = pending_retry.retry_source_connection_id;
        RetryTokenStore retry_tokens{
            {connection_id_key(retry_token), pending_retry},
        };
        const auto context = lookup_retry_context(parsed, peer, sizeof(sockaddr_in), retry_tokens);
        check("retry lookup accepts matching retry contexts", context.has_value());
        check("successful retry lookup erases consumed tokens", retry_tokens.empty());
    }

    {
        ParsedServerDatagram missing_source = supported_initial;
        missing_source.source_connection_id.reset();
        RetryTokenStore retry_tokens;
        check("retry send rejects missing source connection ids",
              !send_retry_for_initial(/*fd=*/17, missing_source, peer, sizeof(sockaddr_in),
                                      retry_tokens, /*connection_index=*/1));
    }

    {
        g_recorded_sendto_for_tests = {};
        RetryTokenStore retry_tokens;
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = record_sendto_for_tests,
            },
        };
        check("retry send emits a retry datagram",
              send_retry_for_initial(/*fd=*/21, supported_initial, peer, sizeof(sockaddr_in),
                                     retry_tokens,
                                     /*connection_index=*/5));
        check("retry send records exactly one sendto call", g_recorded_sendto_for_tests.calls == 1);
        check("retry send stores one pending retry token", retry_tokens.size() == 1);
    }

    {
        RetryTokenStore retry_tokens;
        std::uint64_t next_connection_index = 9;
        check("retry helper returns nullopt when retry is disabled",
              !maybe_send_retry_for_supported_initial(
                   /*retry_enabled=*/false, /*socket_fd=*/17, supported_initial, peer,
                   sizeof(sockaddr_in), retry_tokens, next_connection_index)
                   .has_value());
        ParsedServerDatagram tokenized = supported_initial;
        tokenized.token = retry_token;
        check("retry helper returns nullopt when the client already presented a token",
              !maybe_send_retry_for_supported_initial(
                   /*retry_enabled=*/true, /*socket_fd=*/17, tokenized, peer, sizeof(sockaddr_in),
                   retry_tokens, next_connection_index)
                   .has_value());
    }

    {
        g_recorded_sendto_for_tests = {};
        RetryTokenStore retry_tokens;
        std::uint64_t next_connection_index = 12;
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = record_sendto_for_tests,
            },
        };
        const auto retry_result = maybe_send_retry_for_supported_initial(
            /*retry_enabled=*/true, /*socket_fd=*/22, supported_initial, peer, sizeof(sockaddr_in),
            retry_tokens, next_connection_index);
        check("retry helper returns an immediate result for tokenless initials",
              retry_result.has_value() && retry_result.value());
        check("retry helper increments the next connection index", next_connection_index == 13);
    }

    {
        std::optional<PendingRetryToken> retry_context;
        RetryTokenStore retry_tokens;
        check("populate retry context succeeds when retry is disabled",
              populate_retry_context_if_required(/*retry_enabled=*/false, supported_initial, peer,
                                                 sizeof(sockaddr_in), retry_tokens, retry_context));
        check("populate retry context leaves retry context empty when disabled",
              !retry_context.has_value());
    }

    {
        std::optional<PendingRetryToken> retry_context;
        RetryTokenStore retry_tokens{
            {connection_id_key(retry_token), pending_retry},
        };
        ParsedServerDatagram parsed = supported_initial;
        parsed.token = retry_token;
        parsed.destination_connection_id = pending_retry.retry_source_connection_id;
        check("populate retry context returns the matched context",
              populate_retry_context_if_required(/*retry_enabled=*/true, parsed, peer,
                                                 sizeof(sockaddr_in), retry_tokens, retry_context));
        check("populate retry context fills the optional context", retry_context.has_value());
    }

    {
        std::optional<PendingRetryToken> retry_context;
        RetryTokenStore retry_tokens;
        ParsedServerDatagram parsed = supported_initial;
        parsed.token = retry_token;
        parsed.destination_connection_id = pending_retry.retry_source_connection_id;
        check("populate retry context rejects invalid retry tokens",
              !populate_retry_context_if_required(/*retry_enabled=*/true, parsed, peer,
                                                  sizeof(sockaddr_in), retry_tokens,
                                                  retry_context));
    }

    {
        g_recorded_sendto_for_tests = {};
        RetryTokenStore retry_tokens;
        std::uint64_t next_connection_index = 40;
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = record_sendto_for_tests,
            },
        };
        const auto preparation = prepare_supported_initial_retry_handling(
            /*retry_enabled=*/true, /*socket_fd=*/33, supported_initial, peer, sizeof(sockaddr_in),
            retry_tokens, next_connection_index);
        check("retry preparation returns an immediate result when it emits a retry",
              preparation.immediate_result.has_value() && preparation.immediate_result.value());
    }

    {
        RetryTokenStore retry_tokens{
            {connection_id_key(retry_token), pending_retry},
        };
        std::uint64_t next_connection_index = 41;
        ParsedServerDatagram parsed = supported_initial;
        parsed.token = retry_token;
        parsed.destination_connection_id = pending_retry.retry_source_connection_id;
        const auto preparation = prepare_supported_initial_retry_handling(
            /*retry_enabled=*/true, /*socket_fd=*/34, parsed, peer, sizeof(sockaddr_in),
            retry_tokens, next_connection_index);
        check("retry preparation returns a retry context when the token matches",
              !preparation.immediate_result.has_value() && preparation.retry_context.has_value());
    }

    {
        RetryTokenStore retry_tokens;
        std::uint64_t next_connection_index = 42;
        ParsedServerDatagram parsed = supported_initial;
        parsed.token = retry_token;
        parsed.destination_connection_id = pending_retry.retry_source_connection_id;
        const auto preparation = prepare_supported_initial_retry_handling(
            /*retry_enabled=*/true, /*socket_fd=*/35, parsed, peer, sizeof(sockaddr_in),
            retry_tokens, next_connection_index);
        check("retry preparation turns invalid retry tokens into immediate no-op results",
              preparation.immediate_result.has_value() && preparation.immediate_result.value());
    }

    check("version negotiation probes under the minimum size are ignored",
          send_version_negotiation_for_probe(
              /*fd=*/36,
              std::vector<std::byte>(kMinimumClientInitialDatagramBytes - 1, std::byte{0x00}),
              supported_initial, peer, sizeof(sockaddr_in)));

    {
        ParsedServerDatagram missing_source = supported_initial;
        missing_source.source_connection_id.reset();
        check("version negotiation send rejects missing source connection ids",
              !send_version_negotiation_for_probe(
                  /*fd=*/37,
                  std::vector<std::byte>(kMinimumClientInitialDatagramBytes, std::byte{0x00}),
                  missing_source, peer, sizeof(sockaddr_in)));
    }

    {
        g_recorded_sendto_for_tests = {};
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = record_sendto_for_tests,
            },
        };
        check("version negotiation sends a probe response for oversized unsupported initials",
              send_version_negotiation_for_probe(
                  /*fd=*/38,
                  std::vector<std::byte>(kMinimumClientInitialDatagramBytes, std::byte{0x00}),
                  supported_initial, peer, sizeof(sockaddr_in)));
        check("version negotiation send records a datagram",
              g_recorded_sendto_for_tests.calls == 1);
    }

    return ok;
}

bool runtime_routing_and_driver_coverage_for_tests() {
    struct ScopedEnvVar {
        std::string name;
        std::optional<std::string> previous;

        ScopedEnvVar(std::string variable, std::optional<std::string> value)
            : name(std::move(variable)) {
            if (const char *existing = std::getenv(name.c_str()); existing != nullptr) {
                previous = std::string(existing);
            }
            if (value.has_value()) {
                ::setenv(name.c_str(), value->c_str(), 1);
            } else {
                ::unsetenv(name.c_str());
            }
        }

        ~ScopedEnvVar() {
            if (previous.has_value()) {
                ::setenv(name.c_str(), previous->c_str(), 1);
            } else {
                ::unsetenv(name.c_str());
            }
        }
    };

    class FailingSendBackendForTests final : public QuicIoBackend {
      public:
        std::vector<QuicIoTxDatagram> sent_datagrams;

        std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &) override {
            return std::nullopt;
        }

        std::optional<QuicIoEvent> wait(std::optional<QuicCoreTimePoint>) override {
            return std::nullopt;
        }

        bool send(const QuicIoTxDatagram &datagram) override {
            sent_datagrams.push_back(owning_tx_datagram_for_tests(datagram));
            return false;
        }
    };

    bool ok = true;
    struct RuntimeRoutingDriverCheck {
        bool &ok;
        bool operator()(std::string_view label, bool condition) const {
            if (!condition) {
                std::cerr << "runtime_routing_and_driver_coverage_for_tests failed: " << label
                          << '\n';
                ok = false;
            }
            return condition;
        }
    } check{ok};
    const auto make_loopback_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return peer;
    };

    {
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 11,
                    .family = AF_INET,
                },
            .secondary =
                ClientSocketDescriptor{
                    .fd = 12,
                    .family = AF_INET6,
                },
        };
        check("active_client_socket_fds includes secondary sockets when present",
              active_client_socket_fds(sockets) == std::array<int, 2>{11, 12});
        check("active_client_socket_count includes secondary sockets when present",
              active_client_socket_count(sockets) == 2u);
    }

    const auto make_server_session =
        [&](std::span<const std::byte> local_connection_id,
            std::span<const std::byte> initial_destination_connection_id,
            std::optional<QuicCoreTimePoint> next_wakeup, bool has_pending_work) {
            return std::make_unique<ServerSession>(ServerSession{
                .core = make_failing_server_core_for_tests(),
                .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                    .document_root = std::filesystem::path("."),
                }),
                .state =
                    EndpointDriveState{
                        .next_wakeup = next_wakeup,
                        .endpoint_has_pending_work = has_pending_work,
                    },
                .socket_fd = 71,
                .peer = make_loopback_peer(7443),
                .peer_len = sizeof(sockaddr_in),
                .local_connection_id_key = connection_id_key(local_connection_id),
                .initial_destination_connection_id_key =
                    connection_id_key(initial_destination_connection_id),
            });
        };

    {
        EndpointDriveState state;
        RuntimeWaitStep missing_input_step{
            .socket_fd = 41,
            .source = make_loopback_peer(9443),
            .source_len = sizeof(sockaddr_in),
            .has_source = true,
        };
        check("assign_runtime_path_for_inbound_step ignores steps without inputs",
              !assign_runtime_path_for_inbound_step(state, missing_input_step).has_value());

        RuntimeWaitStep timer_step = missing_input_step;
        timer_step.input = QuicCoreTimerExpired{};
        check("assign_runtime_path_for_inbound_step ignores timer inputs",
              !assign_runtime_path_for_inbound_step(state, timer_step).has_value());

        RuntimeWaitStep inbound_step{
            .input =
                QuicCoreInboundDatagram{
                    .bytes =
                        {
                            std::byte{0xaa},
                            std::byte{0xbb},
                        },
                },
            .input_time = now(),
            .socket_fd = 41,
            .source = make_loopback_peer(9443),
            .source_len = sizeof(sockaddr_in),
            .has_source = true,
        };
        const auto path_id = assign_runtime_path_for_inbound_step(state, inbound_step);
        const auto *inbound = inbound_step.input.has_value()
                                  ? std::get_if<QuicCoreInboundDatagram>(&*inbound_step.input)
                                  : nullptr;
        check("assign_runtime_path_for_inbound_step assigns stable path and route handles",
              path_id.has_value() && path_id.value() == 1 && inbound != nullptr &&
                  inbound->route_handle.has_value() && inbound->route_handle.value() == 1 &&
                  state.path_routes.contains(1) && state.route_routes.contains(1));

        RuntimeWaitStep identified_inbound_step = inbound_step;
        identified_inbound_step.input = QuicCoreInboundDatagram{
            .bytes =
                {
                    std::byte{0xcc},
                },
            .address_validation_identity =
                {
                    std::byte{0x04},
                    std::byte{127},
                    std::byte{0},
                    std::byte{0},
                    std::byte{1},
                    std::byte{0x1f},
                    std::byte{0x90},
                },
        };
        const auto identified_path_id =
            assign_runtime_path_for_inbound_step(state, identified_inbound_step);
        const auto *identified_inbound =
            identified_inbound_step.input.has_value()
                ? std::get_if<QuicCoreInboundDatagram>(&*identified_inbound_step.input)
                : nullptr;
        check("assign_runtime_path_for_inbound_step preserves supplied identities",
              identified_path_id.has_value() && identified_inbound != nullptr &&
                  identified_inbound->address_validation_identity.size() == 7);

        const auto translated = make_inbound_datagram_from_io_event(QuicIoRxDatagram{
            .route_handle = 7,
            .bytes =
                {
                    std::byte{0x10},
                    std::byte{0x20},
                },
            .ecn = QuicEcnCodepoint::ect1,
        });
        check("make_inbound_datagram_from_io_event preserves route handles and ecn",
              translated.route_handle == 7 && translated.bytes.size() == 2 &&
                  translated.ecn == QuicEcnCodepoint::ect1);
    }

    {
        QuicCoreResult result;
        result.effects.emplace_back(QuicCoreSendDatagram{
            .bytes =
                {
                    std::byte{0x31},
                },
            .ecn = QuicEcnCodepoint::ect0,
        });
        check("handle_core_effects rejects missing fallback routes",
              !handle_core_effects(/*fallback_socket_fd=*/-1, result, nullptr, 0, {}, "client"));
        check("handle_core_effects rejects missing peers even with valid fallback sockets",
              !handle_core_effects(/*fallback_socket_fd=*/17, result, nullptr, 0, {}, "client"));
    }

    {
        QuicCoreResult result;
        result.effects.emplace_back(QuicCoreSendDatagram{
            .bytes =
                {
                    std::byte{0x32},
                },
            .ecn = QuicEcnCodepoint::ect1,
        });
        const auto peer = make_loopback_peer(9555);
        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = [](int, const void *, size_t, int, const sockaddr *,
                                socklen_t) -> ssize_t {
                    errno = EIO;
                    return -1;
                },
            },
        };
        check("handle_core_effects propagates sendto failures",
              !handle_core_effects(/*fallback_socket_fd=*/17, result, &peer, sizeof(sockaddr_in),
                                   {}, "client"));
    }

    {
        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        check("handle_core_effects traces route-handle sends when a routed send succeeds",
              runtime_server_send_effect_uses_route_handle_for_tests());
    }

    {
        QuicCoreResult result;
        result.effects.emplace_back(QuicCoreSendDatagram{
            .bytes =
                {
                    std::byte{0x33},
                },
            .ecn = QuicEcnCodepoint::ect1,
        });
        ScriptedIoBackendForTests backend;
        check("handle_core_effects_with_backend rejects missing fallback route handles",
              !handle_core_effects_with_backend(std::nullopt, backend, result, "client"));
    }

    {
        QuicCoreResult result;
        result.effects.emplace_back(QuicCoreSendDatagram{
            .bytes =
                {
                    std::byte{0x34},
                },
            .ecn = QuicEcnCodepoint::ce,
        });
        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        FailingSendBackendForTests backend;
        check("handle_core_effects_with_backend propagates backend send failures",
              !handle_core_effects_with_backend(9, backend, result, "client"));
        check("handle_core_effects_with_backend passes the fallback route handle to the "
              "backend",
              backend.sent_datagrams.size() == 1 &&
                  backend.sent_datagrams.front().route_handle == 9 &&
                  backend.sent_datagrams.front().ecn == QuicEcnCodepoint::ce);
    }

    QuicCoreResult preferred_address_result;
    preferred_address_result.effects.emplace_back(QuicCoreStateEvent{
        .connection = 1,
        .change = QuicCoreStateChange::handshake_ready,
    });
    preferred_address_result.effects.emplace_back(QuicCoreStateEvent{
        .connection = 1,
        .change = QuicCoreStateChange::handshake_confirmed,
    });
    preferred_address_result.effects.emplace_back(
        make_ipv4_preferred_address_effect_for_tests(9777));

    {
        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 21,
                    .family = AF_INET,
                },
        };
        check("observe_client_runtime_policy_effects tracks preferred-address routes without "
              "opening sockets",
              observe_client_runtime_policy_effects(preferred_address_result, state, policy,
                                                    sockets, "client"));
        check("observe_client_runtime_policy_effects records handshake and routing state",
              policy.handshake_ready_seen && policy.handshake_confirmed_seen &&
                  policy.preferred_address_route_handle.has_value() &&
                  state.path_routes.size() == 1 && state.route_routes.size() == 1);
    }

    {
        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientIoContext io_context;
        check("observe_client_runtime_policy_effects_with_backend rejects missing backends",
              !observe_client_runtime_policy_effects_with_backend(preferred_address_result, state,
                                                                  policy, io_context, "client"));
        check("missing backend still records handshake state before failing",
              policy.handshake_ready_seen && policy.handshake_confirmed_seen);
    }

    {
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientIoContext io_context;
        auto backend = std::make_unique<ScriptedIoBackendForTests>();
        backend->ensure_route_results.push_back(std::nullopt);
        io_context.backend = std::move(backend);
        check("observe_client_runtime_policy_effects_with_backend rejects "
              "preferred-address route "
              "failures",
              !observe_client_runtime_policy_effects_with_backend(preferred_address_result, state,
                                                                  policy, io_context, "client"));
    }

    {
        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientIoContext io_context;
        auto backend = std::make_unique<ScriptedIoBackendForTests>();
        auto *backend_ptr = backend.get();
        backend->ensure_route_results.push_back(77);
        io_context.backend = std::move(backend);
        check("observe_client_runtime_policy_effects_with_backend records successful "
              "preferred-address routes",
              observe_client_runtime_policy_effects_with_backend(preferred_address_result, state,
                                                                 policy, io_context, "client"));
        check("preferred-address route creation stores the chosen route handle",
              io_context.preferred_route_handle == std::optional<QuicRouteHandle>(77) &&
                  policy.preferred_address_route_handle == std::optional<QuicRouteHandle>(77) &&
                  backend_ptr->ensure_route_calls.size() == 1 &&
                  peer_port_for_remote_for_tests(backend_ptr->ensure_route_calls.front()) == 9777);
    }

    {
        const auto direct_connection_id = make_runtime_connection_id(std::byte{0x91}, 1);
        const auto routed_connection_id = make_runtime_connection_id(std::byte{0x92}, 2);
        const auto initial_destination_connection_id =
            make_runtime_connection_id(std::byte{0x93}, 3);
        const auto session_key = connection_id_key(direct_connection_id);

        ServerSessionMap sessions;
        sessions.emplace(session_key, make_server_session(direct_connection_id,
                                                          initial_destination_connection_id,
                                                          std::nullopt, false));
        ServerConnectionIdRouteMap connection_id_routes{
            {connection_id_key(routed_connection_id), session_key},
        };
        std::unordered_map<std::string, std::string> initial_destination_routes{
            {connection_id_key(initial_destination_connection_id), session_key},
        };

        const ParsedServerDatagram direct_parsed{
            .kind = ParsedServerDatagram::Kind::short_header,
            .destination_connection_id = direct_connection_id,
        };
        const ParsedServerDatagram routed_parsed{
            .kind = ParsedServerDatagram::Kind::short_header,
            .destination_connection_id = routed_connection_id,
        };
        const ParsedServerDatagram initial_parsed{
            .kind = ParsedServerDatagram::Kind::supported_initial,
            .version = kQuicVersion1,
            .destination_connection_id = initial_destination_connection_id,
        };
        const ParsedServerDatagram supported_long_header_parsed{
            .kind = ParsedServerDatagram::Kind::supported_long_header,
            .version = kQuicVersion1,
            .destination_connection_id = initial_destination_connection_id,
        };
        const ParsedServerDatagram missing_initial_route{
            .kind = ParsedServerDatagram::Kind::supported_initial,
            .version = kQuicVersion1,
            .destination_connection_id = make_runtime_connection_id(std::byte{0x94}, 4),
        };
        const ParsedServerDatagram short_header_without_route{
            .kind = ParsedServerDatagram::Kind::short_header,
            .destination_connection_id = make_runtime_connection_id(std::byte{0x95}, 5),
        };

        check("find_server_session_for_datagram matches direct destination connection ids",
              find_server_session_for_datagram(sessions, connection_id_routes,
                                               initial_destination_routes,
                                               direct_parsed) != sessions.end());
        check("find_server_session_for_datagram matches routed destination connection ids",
              find_server_session_for_datagram(sessions, connection_id_routes,
                                               initial_destination_routes,
                                               routed_parsed) != sessions.end());
        check("find_server_session_for_datagram falls back to initial destination routes for "
              "initials",
              find_server_session_for_datagram(sessions, connection_id_routes,
                                               initial_destination_routes,
                                               initial_parsed) != sessions.end());
        check("find_server_session_for_datagram falls back to initial destination routes "
              "for long "
              "headers",
              find_server_session_for_datagram(sessions, connection_id_routes,
                                               initial_destination_routes,
                                               supported_long_header_parsed) != sessions.end());
        check("find_server_session_for_datagram returns end when initial routes miss",
              find_server_session_for_datagram(sessions, connection_id_routes,
                                               initial_destination_routes,
                                               missing_initial_route) == sessions.end());
        check("find_server_session_for_datagram returns end for unrouted short headers",
              find_server_session_for_datagram(sessions, connection_id_routes,
                                               initial_destination_routes,
                                               short_header_without_route) == sessions.end());
        check("datagram_routes_via_initial_destination only accepts supported long-header "
              "client "
              "opens",
              datagram_routes_via_initial_destination(initial_parsed) &&
                  datagram_routes_via_initial_destination(supported_long_header_parsed) &&
                  !datagram_routes_via_initial_destination(short_header_without_route));
    }

    {
        const auto runtime_server_core = make_runtime_server_core_config(
            Http09RuntimeConfig{
                .mode = Http09RuntimeMode::server,
            },
            TlsIdentity{
                .certificate_pem = "cert",
                .private_key_pem = "key",
            },
            19);
        check("make_runtime_server_core_config assigns runtime source connection ids",
              runtime_server_core.source_connection_id ==
                  make_runtime_connection_id(std::byte{0x53}, 19));

        const auto wakeup_a = now() + std::chrono::milliseconds(20);
        const auto wakeup_b = now() + std::chrono::milliseconds(10);
        ServerSessionMap sessions;
        sessions.emplace(connection_id_key(make_runtime_connection_id(std::byte{0xa1}, 1)),
                         make_server_session(make_runtime_connection_id(std::byte{0xa1}, 1),
                                             make_runtime_connection_id(std::byte{0xb1}, 1),
                                             wakeup_a, false));
        sessions.emplace(connection_id_key(make_runtime_connection_id(std::byte{0xa2}, 2)),
                         make_server_session(make_runtime_connection_id(std::byte{0xa2}, 2),
                                             make_runtime_connection_id(std::byte{0xb2}, 2),
                                             wakeup_b, false));
        sessions.emplace(connection_id_key(make_runtime_connection_id(std::byte{0xa3}, 3)),
                         make_server_session(make_runtime_connection_id(std::byte{0xa3}, 3),
                                             make_runtime_connection_id(std::byte{0xb3}, 3),
                                             std::nullopt, false));
        check("earliest_server_session_wakeup picks the minimum wakeup",
              earliest_server_session_wakeup(sessions) ==
                  std::optional<QuicCoreTimePoint>(wakeup_b));
    }

    {
        g_recorded_sendto_for_tests = {};
        const auto peer = make_loopback_peer(9666);
        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = record_sendto_for_tests,
            },
        };
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        QuicCoreResult initial_result;
        initial_result.effects.emplace_back(QuicCoreSendDatagram{
            .bytes =
                {
                    std::byte{0x41},
                },
        });
        EndpointDriveState state;
        bool observed_send_effects = false;
        check("drive_endpoint_until_blocked records send effects before terminal success",
              drive_endpoint_until_blocked(make_endpoint_driver(endpoint), core, 33, &peer,
                                           sizeof(sockaddr_in), initial_result, state, "client",
                                           nullptr, nullptr, nullptr, &observed_send_effects));
        check("drive_endpoint_until_blocked marks terminal success and observed sends",
              state.terminal_success && observed_send_effects &&
                  g_recorded_sendto_for_tests.calls == 1);
    }

    {
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        Http09RuntimeConfig config{
            .mode = Http09RuntimeMode::client,
        };
        ScriptedIoBackendForTests backend;
        check("drive_endpoint_until_blocked_with_backend rejects missing client io context "
              "when "
              "policy observation is requested",
              !drive_endpoint_until_blocked_with_backend(make_endpoint_driver(endpoint), core, 5,
                                                         backend, QuicCoreResult{}, state, "client",
                                                         &config, &policy, nullptr));
        check("missing client io context marks terminal failure", state.terminal_failure);
    }

    {
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        Http09RuntimeConfig config{
            .mode = Http09RuntimeMode::client,
        };
        ScriptedIoBackendForTests backend;
        ClientIoContext io_context;
        check("drive_endpoint_until_blocked_with_backend propagates preferred-address "
              "observation "
              "failures from client io state",
              !drive_endpoint_until_blocked_with_backend(make_endpoint_driver(endpoint), core, 5,
                                                         backend, preferred_address_result, state,
                                                         "client", &config, &policy, &io_context));
        check("preferred-address observation failures mark terminal failure",
              state.terminal_failure);
    }

    {
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        EndpointDriveState state;
        ScriptedIoBackendForTests backend;
        QuicCoreResult local_error_result;
        local_error_result.local_error = QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        check("drive_endpoint_until_blocked_with_backend treats unhandled local errors as "
              "terminal "
              "failures",
              !drive_endpoint_until_blocked_with_backend(make_endpoint_driver(endpoint), core, 6,
                                                         backend, local_error_result, state,
                                                         "client"));
        check("unhandled local errors mark terminal failure", state.terminal_failure);
    }

    {
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .handled_local_error = true,
        });
        EndpointDriveState state;
        bool observed_send_effects = true;
        ScriptedIoBackendForTests backend;
        QuicCoreResult local_error_result;
        local_error_result.local_error = QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        check("drive_endpoint_until_blocked_with_backend keeps handled local errors "
              "non-terminal",
              drive_endpoint_until_blocked_with_backend(
                  make_endpoint_driver(endpoint), core, 6, backend, local_error_result, state,
                  "client", nullptr, nullptr, nullptr, &observed_send_effects));
        check("handled local errors do not record send effects or terminal failures",
              !state.terminal_failure && !observed_send_effects);
    }

    {
        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        EndpointDriveState state;
        bool observed_send_effects = false;
        ScriptedIoBackendForTests backend;
        QuicCoreResult initial_result;
        initial_result.effects.emplace_back(QuicCoreSendDatagram{
            .bytes =
                {
                    std::byte{0x42},
                },
            .ecn = QuicEcnCodepoint::ect0,
        });
        check("drive_endpoint_until_blocked_with_backend records sends before terminal "
              "success",
              drive_endpoint_until_blocked_with_backend(
                  make_endpoint_driver(endpoint), core, 7, backend, initial_result, state, "client",
                  nullptr, nullptr, nullptr, &observed_send_effects));
        check("backend drive path marks terminal success and records the sent datagram",
              state.terminal_success && observed_send_effects &&
                  backend.sent_datagrams.size() == 1 &&
                  backend.sent_datagrams.front().route_handle == 7);
    }

    {
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientIoContext io_context;
        check("run_http09_client_connection_backend_loop rejects missing backend bootstrap "
              "state",
              run_http09_client_connection_backend_loop(
                  Http09RuntimeConfig{
                      .mode = Http09RuntimeMode::client,
                  },
                  make_endpoint_driver(endpoint), core, io_context, state, policy,
                  QuicCoreResult{}) == 1);
    }

    {
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientIoContext io_context;
        io_context.backend = std::make_unique<ScriptedIoBackendForTests>();
        check("run_http09_client_connection_backend_loop rejects missing primary route "
              "handles even "
              "when a backend exists",
              run_http09_client_connection_backend_loop(
                  Http09RuntimeConfig{
                      .mode = Http09RuntimeMode::client,
                  },
                  make_endpoint_driver(endpoint), core, io_context, state, policy,
                  QuicCoreResult{}) == 1);
    }

    {
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 61,
                    .family = AF_INET,
                },
        };
        ScriptedClientLoopIoForTests io_script;
        QuicCoreResult start_result;
        start_result.local_error = QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        check("run_http09_client_connection_loop exits when the initial drive fails",
              run_http09_client_connection_loop(
                  Http09RuntimeConfig{
                      .mode = Http09RuntimeMode::client,
                  },
                  make_endpoint_driver(endpoint), core, sockets, 5, make_loopback_peer(9888),
                  sizeof(sockaddr_in), state, policy,
                  make_scripted_client_loop_io_for_tests(io_script), start_result) == 1);
    }

    {
        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        QuicCore core = make_local_error_client_core_for_tests();
        ScriptedEndpointForTests endpoint;
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_failure = true,
        });
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 62,
                    .family = AF_INET,
                },
        };
        ScriptedClientLoopIoForTests io_script;
        check("run_http09_client_connection_loop traces pending endpoint polls before "
              "terminal "
              "failures",
              run_http09_client_connection_loop(
                  Http09RuntimeConfig{
                      .mode = Http09RuntimeMode::client,
                  },
                  make_endpoint_driver(endpoint), core, sockets, 5, make_loopback_peer(9999),
                  sizeof(sockaddr_in), state, policy,
                  make_scripted_client_loop_io_for_tests(io_script), QuicCoreResult{}) == 1);
        check("pending endpoint poll failures mark terminal failure", state.terminal_failure);
    }

    {
        bool processed_any = true;
        std::vector<std::string> erased_keys;
        ServerSessionMap sessions;
        sessions.emplace(connection_id_key(make_runtime_connection_id(std::byte{0xc1}, 1)),
                         make_server_session(make_runtime_connection_id(std::byte{0xc1}, 1),
                                             make_runtime_connection_id(std::byte{0xd1}, 1),
                                             now() + std::chrono::milliseconds(50), false));
        sessions.emplace(connection_id_key(make_runtime_connection_id(std::byte{0xc3}, 3)),
                         make_server_session(make_runtime_connection_id(std::byte{0xc3}, 3),
                                             make_runtime_connection_id(std::byte{0xd3}, 3),
                                             std::nullopt, false));
        ServerConnectionIdRouteMap connection_id_routes;
        process_expired_server_sessions(
            sessions, now(), connection_id_routes,
            [&](const std::string &local_connection_id_key) {
                erased_keys.push_back(local_connection_id_key);
            },
            processed_any);
        check("process_expired_server_sessions skips sessions whose wakeup is still in the "
              "future",
              !processed_any && erased_keys.empty());
    }

    {
        std::vector<std::string> erased_keys;
        ServerSessionMap sessions;
        sessions.emplace(connection_id_key(make_runtime_connection_id(std::byte{0xc2}, 2)),
                         make_server_session(make_runtime_connection_id(std::byte{0xc2}, 2),
                                             make_runtime_connection_id(std::byte{0xd2}, 2),
                                             std::nullopt, false));
        ServerConnectionIdRouteMap connection_id_routes;
        check("pump_server_pending_endpoint_work skips sessions without pending endpoint "
              "work",
              !pump_server_pending_endpoint_work(sessions, connection_id_routes,
                                                 [&](const std::string &local_connection_id_key) {
                                                     erased_keys.push_back(local_connection_id_key);
                                                 }));
        check("has_pending_server_endpoint_work reports false when no session is pending",
              !has_pending_server_endpoint_work(sessions));
        sessions.begin()->second->state.endpoint_has_pending_work = true;
        check("has_pending_server_endpoint_work reports true when a session is pending",
              has_pending_server_endpoint_work(sessions));
    }

    {
        ServerConnectionEndpointMap endpoints;
        endpoints.emplace(7, ServerConnectionEndpointState{
                                 .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                     .document_root = std::filesystem::path("."),
                                 }),
                                 .has_pending_work = true,
                             });
        QuicCoreResult closed_result;
        closed_result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
            .connection = 7,
            .event = QuicCoreConnectionLifecycle::closed,
        });
        erase_closed_server_connection_endpoints(endpoints, closed_result);
        check("erase_closed_server_connection_endpoints removes closed endpoints",
              endpoints.empty());
    }

    {
        check("to_connection_command_input preserves supported stream commands",
              to_connection_command_input(QuicCoreSendStreamData{
                                              .stream_id = 3,
                                              .bytes =
                                                  {
                                                      std::byte{0x51},
                                                  },
                                          })
                  .has_value());
        check("to_connection_command_input rejects unsupported endpoint-level inputs",
              !to_connection_command_input(QuicCoreStart{}).has_value());
    }

    return ok;
}

} // namespace test

#if defined(__clang__)
#pragma clang attribute pop
#endif

} // namespace coquic::http09
