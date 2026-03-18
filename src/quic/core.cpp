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

bool QuicCore::is_handshake_complete() const {
    return connection_->is_handshake_complete();
}

} // namespace coquic::quic
