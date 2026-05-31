#include "coquic/quic.h"

#include <string>
#include <utility>

namespace coquic::quic {

struct ConnectResult;

class Endpoint::Impl {
  public:
    explicit Impl(const EndpointConfig &config) : core(config.core) {
    }

    core::Endpoint core;
};

Endpoint::Endpoint(const EndpointConfig &config) : impl_(std::make_unique<Impl>(config)) {
}

Endpoint::~Endpoint() = default;

Endpoint::Endpoint(Endpoint &&) noexcept = default;

Endpoint &Endpoint::operator=(Endpoint &&) noexcept = default;

ConnectResult Endpoint::connect(ClientConfig config, TimePoint now) {
    core::OpenConnection open{
        .connection = std::move(config.core),
        .initial_route_handle = config.initial_route_handle,
        .address_validation_identity = std::move(config.address_validation_identity),
    };
    auto result = impl_->core.open_connection(std::move(open), now);

    ConnectionHandle handle = 0;
    for (const auto &event : core::lifecycle_events(result)) {
        if (event.event == core::Lifecycle::created) {
            handle = event.connection;
            break;
        }
    }
    return ConnectResult{
        .connection = connection(handle),
        .result = std::move(result),
    };
}

Connection Endpoint::connection(ConnectionHandle handle) {
    return Connection(this, handle);
}

core::Result Endpoint::receive_datagram(core::InboundDatagram datagram, TimePoint now) {
    return impl_->core.input_datagram(std::move(datagram), now);
}

core::Result Endpoint::update_path_mtu(core::PathMtuUpdate update, TimePoint now) {
    return impl_->core.update_path_mtu(update, now);
}

core::Result Endpoint::timer_expired(TimePoint now) {
    return impl_->core.timer_expired(now);
}

core::Result Endpoint::advance(core::EndpointInput input, TimePoint now) {
    return impl_->core.advance(std::move(input), now);
}

std::optional<TimePoint> Endpoint::next_wakeup() const {
    return impl_->core.next_wakeup();
}

std::size_t Endpoint::connection_count() const {
    return impl_->core.connection_count();
}

std::vector<core::ConnectionDiagnostics> Endpoint::connection_diagnostics() const {
    return impl_->core.connection_diagnostics();
}

Connection::Connection(Endpoint *endpoint, ConnectionHandle handle)
    : endpoint_(endpoint), handle_(handle) {
}

ConnectionHandle Connection::handle() const {
    return handle_;
}

Connection::operator bool() const {
    return endpoint_ != nullptr && handle_ != 0;
}

Stream Connection::stream(StreamId stream_id) const {
    return Stream(*this, stream_id);
}

core::Result Connection::advance(core::ConnectionInput input, TimePoint now) const {
    if (endpoint_ == nullptr) {
        core::Result result;
        result.local_error = core::LocalError{
            .connection = std::nullopt,
            .code = core::LocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        return result;
    }
    return endpoint_->impl_->core.advance_connection(
        core::ConnectionCommand{
            .connection = handle_,
            .input = std::move(input),
        },
        now);
}

core::Result Connection::send_stream(StreamId stream_id, std::span<const std::byte> bytes, bool fin,
                                     TimePoint now) const {
    return advance(
        core::SendStreamData{
            .stream_id = stream_id,
            .bytes = std::vector<std::byte>(bytes.begin(), bytes.end()),
            .fin = fin,
        },
        now);
}

core::Result Connection::send_datagram(std::span<const std::byte> bytes, TimePoint now) const {
    return advance(
        core::SendDatagramData{
            .bytes = std::vector<std::byte>(bytes.begin(), bytes.end()),
        },
        now);
}

core::Result Connection::reset_stream(StreamId stream_id, std::uint64_t application_error_code,
                                      TimePoint now) const {
    return advance(
        core::ResetStream{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        },
        now);
}

core::Result Connection::stop_sending(StreamId stream_id, std::uint64_t application_error_code,
                                      TimePoint now) const {
    return advance(
        core::StopSending{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        },
        now);
}

core::Result Connection::close(std::uint64_t application_error_code, std::string reason_phrase,
                               TimePoint now) const {
    return advance(
        core::CloseConnection{
            .application_error_code = application_error_code,
            .reason_phrase = std::move(reason_phrase),
        },
        now);
}

core::Result Connection::request_key_update(TimePoint now) const {
    return advance(core::RequestKeyUpdate{}, now);
}

Stream::Stream(Connection connection, StreamId stream_id)
    : connection_(connection), stream_id_(stream_id) {
}

StreamId Stream::id() const {
    return stream_id_;
}

Stream::operator bool() const {
    return static_cast<bool>(connection_);
}

core::Result Stream::send(std::span<const std::byte> bytes, bool fin, TimePoint now) const {
    return connection_.send_stream(stream_id_, bytes, fin, now);
}

core::Result Stream::finish(TimePoint now) const {
    return send({}, true, now);
}

core::Result Stream::reset(std::uint64_t application_error_code, TimePoint now) const {
    return connection_.reset_stream(stream_id_, application_error_code, now);
}

core::Result Stream::stop_sending(std::uint64_t application_error_code, TimePoint now) const {
    return connection_.stop_sending(stream_id_, application_error_code, now);
}

} // namespace coquic::quic
