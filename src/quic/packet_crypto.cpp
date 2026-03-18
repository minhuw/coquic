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
constexpr std::size_t aead_tag_length = 16;
constexpr std::size_t header_protection_sample_length = 16;
constexpr std::size_t header_protection_mask_length = 5;

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

bool fits_openssl_int(std::size_t size) {
    return size <= static_cast<std::size_t>(std::numeric_limits<int>::max());
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

const EVP_CIPHER *aead_cipher(CipherSuite cipher_suite) {
    switch (cipher_suite) {
    case CipherSuite::tls_aes_128_gcm_sha256:
        return EVP_aes_128_gcm();
    case CipherSuite::tls_aes_256_gcm_sha384:
        return EVP_aes_256_gcm();
    case CipherSuite::tls_chacha20_poly1305_sha256:
        return EVP_chacha20_poly1305();
    }

    return nullptr;
}

const EVP_CIPHER *aes_header_protection_cipher(CipherSuite cipher_suite) {
    switch (cipher_suite) {
    case CipherSuite::tls_aes_128_gcm_sha256:
        return EVP_aes_128_ecb();
    case CipherSuite::tls_aes_256_gcm_sha384:
        return EVP_aes_256_ecb();
    case CipherSuite::tls_chacha20_poly1305_sha256:
        return nullptr;
    }

    return nullptr;
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

CodecResult<std::vector<std::byte>> seal_aead(const EVP_CIPHER *cipher,
                                              std::span<const std::byte> key,
                                              std::span<const std::byte> nonce,
                                              std::span<const std::byte> associated_data,
                                              std::span<const std::byte> plaintext) {
    if (!fits_openssl_int(nonce.size()) || !fits_openssl_int(associated_data.size()) ||
        !fits_openssl_int(plaintext.size())) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(),
                                                                            &EVP_CIPHER_CTX_free);
    if (context == nullptr) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    if (EVP_EncryptInit_ex(context.get(), cipher, nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                            nullptr) <= 0 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, openssl_data(key),
                           openssl_data(nonce)) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    int output_length = 0;
    if (!associated_data.empty() &&
        EVP_EncryptUpdate(context.get(), nullptr, &output_length, openssl_data(associated_data),
                          static_cast<int>(associated_data.size())) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::vector<std::byte> ciphertext(plaintext.size() + aead_tag_length);
    int produced_length = 0;
    if (EVP_EncryptUpdate(context.get(), openssl_data(std::span{ciphertext}), &produced_length,
                          openssl_data(plaintext), static_cast<int>(plaintext.size())) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    int final_length = 0;
    if (EVP_EncryptFinal_ex(
            context.get(),
            openssl_data(std::span{ciphertext}.subspan(static_cast<std::size_t>(produced_length))),
            &final_length) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::array<std::byte, aead_tag_length> tag{};
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tag.size()),
                            openssl_data(std::span<std::byte>{tag})) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    const auto total_ciphertext_length =
        static_cast<std::size_t>(produced_length) + static_cast<std::size_t>(final_length);
    ciphertext.resize(total_ciphertext_length);
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return CodecResult<std::vector<std::byte>>::success(std::move(ciphertext));
}

CodecResult<std::vector<std::byte>> open_aead(const EVP_CIPHER *cipher,
                                              std::span<const std::byte> key,
                                              std::span<const std::byte> nonce,
                                              std::span<const std::byte> associated_data,
                                              std::span<const std::byte> ciphertext) {
    if (ciphertext.size() < aead_tag_length) {
        return crypto_failure(CodecErrorCode::packet_decryption_failed);
    }
    if (!fits_openssl_int(nonce.size()) || !fits_openssl_int(associated_data.size()) ||
        !fits_openssl_int(ciphertext.size() - aead_tag_length)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    const auto ciphertext_without_tag = ciphertext.first(ciphertext.size() - aead_tag_length);
    const auto tag = ciphertext.last(aead_tag_length);
    std::vector<std::byte> mutable_tag(tag.begin(), tag.end());

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(),
                                                                            &EVP_CIPHER_CTX_free);
    if (context == nullptr) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    if (EVP_DecryptInit_ex(context.get(), cipher, nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                            nullptr) <= 0 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, openssl_data(key),
                           openssl_data(nonce)) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    int output_length = 0;
    if (!associated_data.empty() &&
        EVP_DecryptUpdate(context.get(), nullptr, &output_length, openssl_data(associated_data),
                          static_cast<int>(associated_data.size())) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::vector<std::byte> plaintext(ciphertext_without_tag.size());
    int produced_length = 0;
    if (EVP_DecryptUpdate(context.get(), openssl_data(std::span{plaintext}), &produced_length,
                          openssl_data(ciphertext_without_tag),
                          static_cast<int>(ciphertext_without_tag.size())) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG,
                            static_cast<int>(mutable_tag.size()),
                            openssl_data(std::span{mutable_tag})) <= 0) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    int final_length = 0;
    if (EVP_DecryptFinal_ex(
            context.get(),
            openssl_data(std::span{plaintext}.subspan(static_cast<std::size_t>(produced_length))),
            &final_length) <= 0) {
        return crypto_failure(CodecErrorCode::packet_decryption_failed);
    }

    plaintext.resize(static_cast<std::size_t>(produced_length) +
                     static_cast<std::size_t>(final_length));
    return CodecResult<std::vector<std::byte>>::success(std::move(plaintext));
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

CodecResult<std::vector<std::byte>> make_packet_protection_nonce(std::span<const std::byte> iv,
                                                                 std::uint64_t packet_number) {
    auto nonce = std::vector<std::byte>(iv.begin(), iv.end());
    auto packet_number_value = packet_number;

    for (std::size_t index = 0; index < sizeof(packet_number) && index < nonce.size(); ++index) {
        const auto nonce_index = nonce.size() - 1 - index;
        nonce[nonce_index] ^= static_cast<std::byte>(packet_number_value & 0xff);
        packet_number_value >>= 8;
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(nonce));
}

CodecResult<std::vector<std::byte>> seal_payload(CipherSuite cipher_suite,
                                                 std::span<const std::byte> key,
                                                 std::span<const std::byte> nonce,
                                                 std::span<const std::byte> associated_data,
                                                 std::span<const std::byte> plaintext) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value()) {
        return crypto_failure(parameters.error().code);
    }
    if (key.size() != parameters.value().key_length ||
        nonce.size() != parameters.value().iv_length) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    const auto *cipher = aead_cipher(cipher_suite);
    if (cipher == nullptr) {
        return crypto_failure(CodecErrorCode::unsupported_cipher_suite);
    }

    return seal_aead(cipher, key, nonce, associated_data, plaintext);
}

CodecResult<std::vector<std::byte>> open_payload(CipherSuite cipher_suite,
                                                 std::span<const std::byte> key,
                                                 std::span<const std::byte> nonce,
                                                 std::span<const std::byte> associated_data,
                                                 std::span<const std::byte> ciphertext) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value()) {
        return crypto_failure(parameters.error().code);
    }
    if (key.size() != parameters.value().key_length ||
        nonce.size() != parameters.value().iv_length) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    const auto *cipher = aead_cipher(cipher_suite);
    if (cipher == nullptr) {
        return crypto_failure(CodecErrorCode::unsupported_cipher_suite);
    }

    return open_aead(cipher, key, nonce, associated_data, ciphertext);
}

CodecResult<std::vector<std::byte>> make_header_protection_mask(CipherSuite cipher_suite,
                                                                std::span<const std::byte> hp_key,
                                                                std::span<const std::byte> sample) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value()) {
        return crypto_failure(parameters.error().code);
    }
    if (hp_key.size() != parameters.value().hp_key_length) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }
    if (sample.size() < header_protection_sample_length) {
        return crypto_failure(CodecErrorCode::header_protection_sample_too_short);
    }
    const auto sample_prefix = sample.first(header_protection_sample_length);

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(),
                                                                            &EVP_CIPHER_CTX_free);
    if (context == nullptr) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    if (cipher_suite == CipherSuite::tls_chacha20_poly1305_sha256) {
        std::array<std::byte, header_protection_mask_length> zeros{};
        std::vector<std::byte> mask(header_protection_mask_length);
        int produced_length = 0;
        if (EVP_EncryptInit_ex(context.get(), EVP_chacha20(), nullptr, openssl_data(hp_key),
                               openssl_data(sample_prefix)) <= 0 ||
            EVP_EncryptUpdate(context.get(), openssl_data(std::span{mask}), &produced_length,
                              openssl_data(std::span<const std::byte>{zeros}),
                              static_cast<int>(zeros.size())) <= 0) {
            return crypto_failure(CodecErrorCode::header_protection_failed);
        }

        int final_length = 0;
        if (EVP_EncryptFinal_ex(
                context.get(),
                openssl_data(std::span{mask}.subspan(static_cast<std::size_t>(produced_length))),
                &final_length) <= 0) {
            return crypto_failure(CodecErrorCode::header_protection_failed);
        }

        const auto mask_length =
            static_cast<std::size_t>(produced_length) + static_cast<std::size_t>(final_length);
        if (mask_length != header_protection_mask_length) {
            return crypto_failure(CodecErrorCode::header_protection_failed);
        }
        mask.resize(mask_length);
        return CodecResult<std::vector<std::byte>>::success(std::move(mask));
    }

    const auto *cipher = aes_header_protection_cipher(cipher_suite);
    if (cipher == nullptr) {
        return crypto_failure(CodecErrorCode::unsupported_cipher_suite);
    }

    std::vector<std::byte> block(header_protection_sample_length);
    int produced_length = 0;
    if (EVP_EncryptInit_ex(context.get(), cipher, nullptr, openssl_data(hp_key), nullptr) <= 0 ||
        EVP_CIPHER_CTX_set_padding(context.get(), 0) <= 0 ||
        EVP_EncryptUpdate(context.get(), openssl_data(std::span{block}), &produced_length,
                          openssl_data(sample_prefix),
                          static_cast<int>(sample_prefix.size())) <= 0) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    int final_length = 0;
    if (EVP_EncryptFinal_ex(
            context.get(),
            openssl_data(std::span{block}.subspan(static_cast<std::size_t>(produced_length))),
            &final_length) <= 0) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    const auto block_length =
        static_cast<std::size_t>(produced_length) + static_cast<std::size_t>(final_length);
    if (block_length != header_protection_sample_length) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }
    block.resize(block_length);
    block.resize(header_protection_mask_length);
    return CodecResult<std::vector<std::byte>>::success(std::move(block));
}

} // namespace coquic::quic
