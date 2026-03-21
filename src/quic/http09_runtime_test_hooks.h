#pragma once

#include <initializer_list>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

#include "src/quic/http09_runtime.h"

namespace coquic::quic::test {

struct RuntimePollOutcome {
    int result = 0;
    short revents = 0;
    int error = 0;
};

struct RuntimeRecvfromOutcome {
    ssize_t result = 0;
    std::vector<std::byte> bytes;
    sockaddr_storage source{};
    socklen_t source_len = 0;
    int error = 0;
};

struct RuntimeWaitOutcome {
    std::optional<QuicCoreInput> input;
    QuicCoreTimePoint input_time{};
    sockaddr_storage source{};
    socklen_t source_len = 0;
    bool has_source = false;
    bool idle_timeout = false;
};

struct RuntimeFaultConfig {
    std::vector<std::optional<RuntimeWaitOutcome>> wait_outcomes;
    std::vector<RuntimePollOutcome> poll_outcomes;
    std::vector<RuntimeRecvfromOutcome> recvfrom_outcomes;
    std::optional<std::size_t> open_udp_socket_failure_occurrence;
    std::optional<std::size_t> send_datagram_failure_occurrence;
    std::optional<std::size_t> drive_endpoint_failure_occurrence;
    std::optional<bool> project_name_empty;
    std::optional<bool> openssl_available;
    std::optional<bool> logging_ready;
};

struct RuntimeWaitObservation {
    bool has_value = false;
    std::optional<QuicCoreInput> input;
    QuicCoreTimePoint input_time{};
    sockaddr_storage source{};
    socklen_t source_len = 0;
    bool has_source = false;
    bool idle_timeout = false;
};

struct RuntimeDriveObservation {
    bool returned = false;
    std::optional<QuicCoreTimePoint> next_wakeup;
    bool terminal_success = false;
    bool terminal_failure = false;
};

class ScopedRuntimeFaultInjector {
  public:
    explicit ScopedRuntimeFaultInjector(RuntimeFaultConfig config);
    ~ScopedRuntimeFaultInjector();

    ScopedRuntimeFaultInjector(const ScopedRuntimeFaultInjector &) = delete;
    ScopedRuntimeFaultInjector &operator=(const ScopedRuntimeFaultInjector &) = delete;

  private:
    RuntimeFaultConfig previous_config_;
    std::size_t previous_open_udp_socket_calls_ = 0;
    std::size_t previous_send_datagram_calls_ = 0;
    std::size_t previous_drive_endpoint_calls_ = 0;
};

class Http09RuntimeTestPeer {
  public:
    static bool call_resolve_udp_peer_ipv4(std::string_view host, std::uint16_t port,
                                           sockaddr_in &address);
    static bool call_send_datagram(int fd, std::span<const std::byte> datagram,
                                   const sockaddr_storage &peer, socklen_t peer_len,
                                   std::string_view role_name);
    static ssize_t call_runtime_recvfrom(int socket_fd, void *buffer, std::size_t buffer_size,
                                         int flags, sockaddr *source, socklen_t *source_len);
    static RuntimeWaitObservation
    call_wait_for_socket_or_deadline(int socket_fd, int idle_timeout_ms, std::string_view role_name,
                                     const std::optional<QuicCoreTimePoint> &next_wakeup);
    static bool call_handle_core_effects(int fd, const QuicCoreResult &result,
                                         const sockaddr_storage *peer, socklen_t peer_len,
                                         std::string_view role_name);
    static QuicCoreResult call_advance_core_with_inputs(QuicCore &core,
                                                        std::span<const QuicCoreInput> inputs,
                                                        QuicCoreTimePoint step_time);
    static RuntimeDriveObservation call_drive_scripted_endpoint_until_blocked(
        QuicCore &core, int fd, const sockaddr_storage *peer, socklen_t peer_len,
        const QuicCoreResult &initial_result,
        std::initializer_list<QuicHttp09EndpointUpdate> scripted_updates,
        std::string_view role_name);
};

} // namespace coquic::quic::test
