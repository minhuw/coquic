#include "src/quic/packet_crypto.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace {

using coquic::quic::CipherSuite;
using coquic::quic::CodecErrorCode;
using coquic::quic::CodecResult;
using coquic::quic::EndpointRole;
using coquic::quic::PacketProtectionKeys;
using coquic::quic::TrafficSecret;

constexpr std::array<std::byte, 20> quic_v1_initial_salt{
    std::byte{0x38}, std::byte{0x76}, std::byte{0x2c}, std::byte{0xf7}, std::byte{0xf5},
    std::byte{0x59}, std::byte{0x34}, std::byte{0xb3}, std::byte{0x4d}, std::byte{0x17},
    std::byte{0x9a}, std::byte{0xe6}, std::byte{0xa4}, std::byte{0xc8}, std::byte{0x0c},
    std::byte{0xad}, std::byte{0xcc}, std::byte{0xbb}, std::byte{0x7f}, std::byte{0x0a},
};

constexpr std::string_view tls13_label_prefix = "tls13 ";

struct CipherSuiteParameters {
    const EVP_MD *(*digest)();
    std::size_t key_length;
    std::size_t iv_length;
    std::size_t hp_key_length;
};

CodecResult<std::vector<std::byte>> crypto_failure(CodecErrorCode code) {
    return CodecResult<std::vector<std::byte>>::failure(code, 0);
}

CodecResult<PacketProtectionKeys> packet_key_failure(CodecErrorCode code) {
    return CodecResult<PacketProtectionKeys>::failure(code, 0);
}

const unsigned char *openssl_data(std::span<const std::byte> bytes) {
    static constexpr unsigned char empty = 0;
    if (bytes.empty()) {
        return &empty;
    }

    return reinterpret_cast<const unsigned char *>(bytes.data());
}

unsigned char *openssl_data(std::span<std::byte> bytes) {
    static unsigned char empty = 0;
    if (bytes.empty()) {
        return &empty;
    }

    return reinterpret_cast<unsigned char *>(bytes.data());
}

CodecResult<CipherSuiteParameters> cipher_suite_parameters(CipherSuite cipher_suite) {
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

CodecResult<std::vector<std::byte>> hkdf_extract(const EVP_MD *digest,
                                                 std::span<const std::byte> salt,
                                                 std::span<const std::byte> input_key_material) {
    const auto digest_length = EVP_MD_get_size(digest);
    if (digest_length <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::vector<std::byte> pseudorandom_key(static_cast<std::size_t>(digest_length));
    std::size_t output_length = pseudorandom_key.size();
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), &EVP_PKEY_CTX_free);
    if (context == nullptr) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    if (EVP_PKEY_derive_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_mode(context.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(context.get(), digest) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(context.get(), openssl_data(salt),
                                    static_cast<int>(salt.size())) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(context.get(), openssl_data(input_key_material),
                                   static_cast<int>(input_key_material.size())) <= 0 ||
        EVP_PKEY_derive(context.get(), openssl_data(std::span{pseudorandom_key}), &output_length) <=
            0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    pseudorandom_key.resize(output_length);
    return CodecResult<std::vector<std::byte>>::success(std::move(pseudorandom_key));
}

CodecResult<std::vector<std::byte>> hkdf_expand(const EVP_MD *digest,
                                                std::span<const std::byte> secret,
                                                std::span<const std::byte> info,
                                                std::size_t output_length) {
    std::vector<std::byte> output(output_length);
    std::size_t derived_length = output.size();
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), &EVP_PKEY_CTX_free);
    if (context == nullptr) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    if (EVP_PKEY_derive_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_mode(context.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(context.get(), digest) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(context.get(), openssl_data(secret),
                                   static_cast<int>(secret.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(context.get(), openssl_data(info),
                                    static_cast<int>(info.size())) <= 0 ||
        EVP_PKEY_derive(context.get(), openssl_data(std::span{output}), &derived_length) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    output.resize(derived_length);
    return CodecResult<std::vector<std::byte>>::success(std::move(output));
}

CodecResult<std::vector<std::byte>> hkdf_expand_label(const EVP_MD *digest,
                                                      std::span<const std::byte> secret,
                                                      std::string_view label,
                                                      std::size_t output_length) {
    if (output_length > std::numeric_limits<std::uint16_t>::max()) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    const auto full_label_length = tls13_label_prefix.size() + label.size();
    if (full_label_length > std::numeric_limits<std::uint8_t>::max()) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::vector<std::byte> info;
    info.reserve(2 + 1 + full_label_length + 1);

    info.push_back(static_cast<std::byte>((output_length >> 8) & 0xff));
    info.push_back(static_cast<std::byte>(output_length & 0xff));
    info.push_back(static_cast<std::byte>(full_label_length));

    for (const auto ch : tls13_label_prefix) {
        info.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    for (const auto ch : label) {
        info.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }

    info.push_back(std::byte{0x00});

    return hkdf_expand(digest, secret, info, output_length);
}

CodecResult<PacketProtectionKeys> expand_secret(CipherSuite cipher_suite,
                                                std::span<const std::byte> secret) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value()) {
        return packet_key_failure(parameters.error().code);
    }

    const auto digest = parameters.value().digest();
    const auto key = hkdf_expand_label(digest, secret, "quic key", parameters.value().key_length);
    if (!key.has_value()) {
        return packet_key_failure(key.error().code);
    }

    const auto iv = hkdf_expand_label(digest, secret, "quic iv", parameters.value().iv_length);
    if (!iv.has_value()) {
        return packet_key_failure(iv.error().code);
    }

    const auto hp_key =
        hkdf_expand_label(digest, secret, "quic hp", parameters.value().hp_key_length);
    if (!hp_key.has_value()) {
        return packet_key_failure(hp_key.error().code);
    }

    return CodecResult<PacketProtectionKeys>::success(PacketProtectionKeys{
        .key = key.value(),
        .iv = iv.value(),
        .hp_key = hp_key.value(),
    });
}

} // namespace

namespace coquic::quic {

CodecResult<PacketProtectionKeys>
derive_initial_packet_keys(EndpointRole local_role, bool for_local_send,
                           const ConnectionId &client_initial_destination_connection_id) {
    const auto initial_secret =
        hkdf_extract(EVP_sha256(), quic_v1_initial_salt, client_initial_destination_connection_id);
    if (!initial_secret.has_value()) {
        return CodecResult<PacketProtectionKeys>::failure(initial_secret.error().code, 0);
    }

    const auto use_client_initial_secret = (local_role == EndpointRole::client) == for_local_send;
    const auto directional_secret =
        hkdf_expand_label(EVP_sha256(), initial_secret.value(),
                          use_client_initial_secret ? "client in" : "server in", 32);
    if (!directional_secret.has_value()) {
        return CodecResult<PacketProtectionKeys>::failure(directional_secret.error().code, 0);
    }

    return expand_secret(CipherSuite::tls_aes_128_gcm_sha256, directional_secret.value());
}

CodecResult<PacketProtectionKeys> expand_traffic_secret(const TrafficSecret &secret) {
    return expand_secret(secret.cipher_suite, secret.secret);
}

} // namespace coquic::quic
