#include "src/quic/core.h"

#include <utility>

#include "src/quic/connection.h"

namespace coquic::quic {

QuicCore::QuicCore(QuicCoreConfig config)
    : connection_(std::make_unique<QuicConnection>(std::move(config))) {
}

QuicCore::~QuicCore() = default;

QuicCore::QuicCore(QuicCore &&) noexcept = default;

QuicCore &QuicCore::operator=(QuicCore &&) noexcept = default;

std::vector<std::byte> QuicCore::receive(std::vector<std::byte> bytes) {
    return connection_->receive(bytes);
}

void QuicCore::queue_application_data(std::vector<std::byte> bytes) {
    connection_->queue_application_data(bytes);
}

std::vector<std::byte> QuicCore::take_received_application_data() {
    return connection_->take_received_application_data();
}

bool QuicCore::is_handshake_complete() const {
    return connection_->is_handshake_complete();
}

bool QuicCore::has_failed() const {
    return connection_->has_failed();
}

} // namespace coquic::quic
