#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include "src/quic/packet_crypto.h"
#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/version.h"

namespace coquic::quic::detail {

using test::PacketCryptoFaultPoint;

constexpr std::array<std::byte, 20> quic_v1_initial_salt{
    std::byte{0x38}, std::byte{0x76}, std::byte{0x2c}, std::byte{0xf7}, std::byte{0xf5},
    std::byte{0x59}, std::byte{0x34}, std::byte{0xb3}, std::byte{0x4d}, std::byte{0x17},
    std::byte{0x9a}, std::byte{0xe6}, std::byte{0xa4}, std::byte{0xc8}, std::byte{0x0c},
    std::byte{0xad}, std::byte{0xcc}, std::byte{0xbb}, std::byte{0x7f}, std::byte{0x0a},
};

constexpr std::array<std::byte, 20> quic_v2_initial_salt{
    std::byte{0x0d}, std::byte{0xed}, std::byte{0xe3}, std::byte{0xde}, std::byte{0xf7},
    std::byte{0x00}, std::byte{0xa6}, std::byte{0xdb}, std::byte{0x81}, std::byte{0x93},
    std::byte{0x81}, std::byte{0xbe}, std::byte{0x6e}, std::byte{0x26}, std::byte{0x9d},
    std::byte{0xcb}, std::byte{0xf9}, std::byte{0xbd}, std::byte{0x2e}, std::byte{0xd9},
};

constexpr std::string_view tls13_label_prefix = "tls13 ";
constexpr std::size_t aead_tag_length = 16;
constexpr std::size_t header_protection_sample_length = 16;
constexpr std::size_t header_protection_mask_length = 5;

struct CipherSuiteParameters {
    const EVP_MD *(*digest)();
    std::size_t key_length;
    std::size_t iv_length;
    std::size_t hp_key_length;
};

struct PacketProtectionLabels {
    std::string_view key;
    std::string_view iv;
    std::string_view hp;
    std::string_view ku;
};

struct PacketCryptoFaultState {
    std::optional<PacketCryptoFaultPoint> fault_point;
    std::size_t occurrence = 0;
};

inline PacketCryptoFaultState &packet_crypto_fault_state() {
    static thread_local PacketCryptoFaultState state;
    return state;
}

inline void set_packet_crypto_fault_state(std::optional<PacketCryptoFaultPoint> fault_point,
                                          std::size_t occurrence) {
    packet_crypto_fault_state() = PacketCryptoFaultState{
        .fault_point = fault_point,
        .occurrence = occurrence,
    };
}

inline bool consume_packet_crypto_fault(PacketCryptoFaultPoint fault_point) {
    auto &state = packet_crypto_fault_state();
    if (!state.fault_point.has_value() || state.fault_point.value() != fault_point) {
        return false;
    }

    if (state.occurrence > 1) {
        --state.occurrence;
        return false;
    }

    state.fault_point.reset();
    state.occurrence = 0;
    return true;
}

inline CodecResult<std::vector<std::byte>> crypto_failure(CodecErrorCode code) {
    return CodecResult<std::vector<std::byte>>::failure(code, 0);
}

inline CodecResult<PacketProtectionKeys> packet_key_failure(CodecErrorCode code) {
    return CodecResult<PacketProtectionKeys>::failure(code, 0);
}

inline CodecResult<std::span<const std::byte>> initial_salt_for_version(std::uint32_t version) {
    if (version == kQuicVersion1) {
        return CodecResult<std::span<const std::byte>>::success(
            std::span<const std::byte>(quic_v1_initial_salt));
    }
    if (version == kQuicVersion2) {
        return CodecResult<std::span<const std::byte>>::success(
            std::span<const std::byte>(quic_v2_initial_salt));
    }

    return CodecResult<std::span<const std::byte>>::failure(CodecErrorCode::unsupported_packet_type,
                                                            0);
}

inline CodecResult<PacketProtectionLabels>
packet_protection_labels_for_version(std::uint32_t version) {
    if (version == kQuicVersion1) {
        return CodecResult<PacketProtectionLabels>::success(PacketProtectionLabels{
            .key = "quic key",
            .iv = "quic iv",
            .hp = "quic hp",
            .ku = "quic ku",
        });
    }
    if (version == kQuicVersion2) {
        return CodecResult<PacketProtectionLabels>::success(PacketProtectionLabels{
            .key = "quicv2 key",
            .iv = "quicv2 iv",
            .hp = "quicv2 hp",
            .ku = "quicv2 ku",
        });
    }

    return CodecResult<PacketProtectionLabels>::failure(CodecErrorCode::unsupported_packet_type, 0);
}

inline const unsigned char *openssl_data(std::span<const std::byte> bytes) {
    static constexpr unsigned char empty = 0;
    if (bytes.empty()) {
        return &empty;
    }

    return reinterpret_cast<const unsigned char *>(bytes.data());
}

inline unsigned char *openssl_data(std::span<std::byte> bytes) {
    static unsigned char empty = 0;
    if (bytes.empty()) {
        return &empty;
    }

    return reinterpret_cast<unsigned char *>(bytes.data());
}

inline CodecResult<CipherSuiteParameters> cipher_suite_parameters(CipherSuite cipher_suite) {
    switch (cipher_suite) {
    case CipherSuite::tls_aes_128_gcm_sha256:
        return CodecResult<CipherSuiteParameters>::success(CipherSuiteParameters{
            .digest = &EVP_sha256,
            .key_length = 16,
            .iv_length = 12,
            .hp_key_length = 16,
        });
    case CipherSuite::tls_aes_256_gcm_sha384:
        return CodecResult<CipherSuiteParameters>::success(CipherSuiteParameters{
            .digest = &EVP_sha384,
            .key_length = 32,
            .iv_length = 12,
            .hp_key_length = 32,
        });
    case CipherSuite::tls_chacha20_poly1305_sha256:
        return CodecResult<CipherSuiteParameters>::success(CipherSuiteParameters{
            .digest = &EVP_sha256,
            .key_length = 32,
            .iv_length = 12,
            .hp_key_length = 32,
        });
    }

    return CodecResult<CipherSuiteParameters>::failure(CodecErrorCode::unsupported_cipher_suite, 0);
}

} // namespace coquic::quic::detail
