#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "coquic/core.h"

namespace coquic::quic {

using ConnectionHandle = core::ConnectionHandle;
using RouteHandle = core::RouteHandle;
using StreamId = core::StreamId;
using TimePoint = core::TimePoint;

struct ConnectResult;
class Endpoint;
class Connection;
class Stream;

struct EndpointConfig {
    core::EndpointConfig core;
};

struct ClientConfig {
    core::ClientConnectionConfig core;
    RouteHandle initial_route_handle = 0;
    std::vector<std::byte> address_validation_identity;
};

class Endpoint {
  public:
    explicit Endpoint(const EndpointConfig &config = {});
    ~Endpoint();

    Endpoint(const Endpoint &) = delete;
    Endpoint &operator=(const Endpoint &) = delete;
    Endpoint(Endpoint &&) noexcept;
    Endpoint &operator=(Endpoint &&) noexcept;

    ConnectResult connect(ClientConfig config, TimePoint now);
    Connection connection(ConnectionHandle handle);

    core::Result receive_datagram(core::InboundDatagram datagram, TimePoint now);
    core::Result update_path_mtu(core::PathMtuUpdate update, TimePoint now);
    core::Result timer_expired(TimePoint now);
    core::Result advance(core::EndpointInput input, TimePoint now);

    std::optional<TimePoint> next_wakeup() const;
    std::size_t connection_count() const;
    std::vector<core::ConnectionDiagnostics> connection_diagnostics() const;

  private:
    friend class Connection;
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class Connection {
  public:
    Connection() = default;

    ConnectionHandle handle() const;
    explicit operator bool() const;

    Stream stream(StreamId stream_id) const;
    core::Result advance(core::ConnectionInput input, TimePoint now) const;
    core::Result send_stream(StreamId stream_id, std::span<const std::byte> bytes, bool fin,
                             TimePoint now) const;
    core::Result send_datagram(std::span<const std::byte> bytes, TimePoint now) const;
    core::Result reset_stream(StreamId stream_id, std::uint64_t application_error_code,
                              TimePoint now) const;
    core::Result stop_sending(StreamId stream_id, std::uint64_t application_error_code,
                              TimePoint now) const;
    core::Result close(std::uint64_t application_error_code, std::string reason_phrase,
                       TimePoint now) const;
    core::Result request_key_update(TimePoint now) const;

  private:
    friend class Endpoint;
    Connection(Endpoint *endpoint, ConnectionHandle handle);

    Endpoint *endpoint_ = nullptr;
    ConnectionHandle handle_ = 0;
};

struct ConnectResult {
    Connection connection;
    core::Result result;
};

class Stream {
  public:
    Stream() = default;

    StreamId id() const;
    explicit operator bool() const;

    core::Result send(std::span<const std::byte> bytes, bool fin, TimePoint now) const;
    core::Result finish(TimePoint now) const;
    core::Result reset(std::uint64_t application_error_code, TimePoint now) const;
    core::Result stop_sending(std::uint64_t application_error_code, TimePoint now) const;

  private:
    friend class Connection;
    Stream(Connection connection, StreamId stream_id);

    Connection connection_;
    StreamId stream_id_ = 0;
};

} // namespace coquic::quic
