#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace coquic::quic::test {

enum class PacketCryptoFaultPoint : std::uint8_t {
    hkdf_extract_context_new,
    hkdf_extract_setup,
    hkdf_expand_context_new,
    hkdf_expand_setup,
    seal_length_guard,
    seal_context_new,
    seal_init,
    seal_aad_update,
    seal_payload_update,
    seal_final,
    seal_get_tag,
    open_length_guard,
    open_context_new,
    open_init,
    open_aad_update,
    open_payload_update,
    open_set_tag,
    header_protection_context_new,
    header_protection_chacha_init,
    header_protection_chacha_final,
    header_protection_chacha_bad_length,
    header_protection_aes_init,
    header_protection_aes_final,
    header_protection_aes_bad_length,
};

class ScopedPacketCryptoFaultInjector {
  public:
    explicit ScopedPacketCryptoFaultInjector(PacketCryptoFaultPoint fault_point,
                                             std::size_t occurrence = 1);
    ~ScopedPacketCryptoFaultInjector();

    ScopedPacketCryptoFaultInjector(const ScopedPacketCryptoFaultInjector &) = delete;
    ScopedPacketCryptoFaultInjector &operator=(const ScopedPacketCryptoFaultInjector &) = delete;

  private:
    std::optional<PacketCryptoFaultPoint> previous_fault_point_;
    std::size_t previous_occurrence_ = 0;
};

} // namespace coquic::quic::test
