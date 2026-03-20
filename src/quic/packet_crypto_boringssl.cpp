#include "src/quic/packet_crypto_internal.h"

#include <array>
#include <memory>

#include <openssl/aead.h>
#include <openssl/chacha.h>
#include <openssl/hkdf.h>

namespace {

using namespace coquic::quic;
using namespace coquic::quic::detail;

int hkdf_extract_call(unsigned char *out_key, std::size_t *out_len, const EVP_MD *digest,
                      std::span<const std::byte> input_key_material,
                      std::span<const std::byte> salt) {
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::hkdf_extract_setup)) {
        return 0;
    }

    return HKDF_extract(out_key, out_len, digest, openssl_data(input_key_material),
                        input_key_material.size(), openssl_data(salt), salt.size());
}

int hkdf_expand_call(unsigned char *out_key, std::size_t out_len, const EVP_MD *digest,
                     std::span<const std::byte> secret, std::span<const std::byte> info) {
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::hkdf_expand_setup)) {
        return 0;
    }

    return HKDF_expand(out_key, out_len, digest, openssl_data(secret), secret.size(),
                       openssl_data(info), info.size());
}

int aead_ctx_seal(EVP_AEAD_CTX *context, std::span<std::byte> ciphertext,
                  std::size_t *output_length, std::span<const std::byte> nonce,
                  std::span<const std::byte> plaintext,
                  std::span<const std::byte> associated_data) {
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_native_seal)) {
        return 0;
    }

    return EVP_AEAD_CTX_seal(context, openssl_data(ciphertext), output_length, ciphertext.size(),
                             openssl_data(nonce), nonce.size(), openssl_data(plaintext),
                             plaintext.size(), openssl_data(associated_data),
                             associated_data.size());
}

EVP_CIPHER_CTX *new_header_protection_cipher_ctx() {
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_context_new)) {
        return nullptr;
    }

    return EVP_CIPHER_CTX_new();
}

int header_protection_aes_init(EVP_CIPHER_CTX *context, const EVP_CIPHER *cipher,
                               std::span<const std::byte> hp_key) {
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_init)) {
        return 0;
    }

    return EVP_EncryptInit_ex(context, cipher, nullptr, openssl_data(hp_key), nullptr);
}

int header_protection_aes_set_padding(EVP_CIPHER_CTX *context) {
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_set_padding)) {
        return 0;
    }

    return EVP_CIPHER_CTX_set_padding(context, 0);
}

int header_protection_aes_update(EVP_CIPHER_CTX *context, std::span<std::byte> block,
                                 int *produced_length, std::span<const std::byte> sample_prefix) {
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_update)) {
        return 0;
    }

    return EVP_EncryptUpdate(context, openssl_data(block), produced_length,
                             openssl_data(sample_prefix), static_cast<int>(sample_prefix.size()));
}

int header_protection_aes_final(EVP_CIPHER_CTX *context, std::span<std::byte> block_tail,
                                int *final_length) {
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_final)) {
        return 0;
    }

    return EVP_EncryptFinal_ex(context, openssl_data(block_tail), final_length);
}

CodecResult<std::vector<std::byte>> hkdf_extract(const EVP_MD *digest,
                                                 std::span<const std::byte> salt,
                                                 std::span<const std::byte> input_key_material) {
    std::vector<std::byte> pseudorandom_key(static_cast<std::size_t>(EVP_MD_size(digest)));
    std::size_t output_length = pseudorandom_key.size();

    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::hkdf_extract_context_new)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    const auto failed = hkdf_extract_call(openssl_data(std::span{pseudorandom_key}), &output_length,
                                          digest, input_key_material, salt) != 1;
    if (failed) {
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

    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::hkdf_expand_context_new)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    const auto failed =
        hkdf_expand_call(openssl_data(std::span{output}), output.size(), digest, secret, info) != 1;
    if (failed) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(output));
}

CodecResult<std::vector<std::byte>> hkdf_expand_label(const EVP_MD *digest,
                                                      std::span<const std::byte> secret,
                                                      std::string_view label,
                                                      std::size_t output_length) {
    const auto full_label_length = tls13_label_prefix.size() + label.size();

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

struct SealAeadRequest {
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const std::byte> plaintext;
};

struct OpenAeadRequest {
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const std::byte> ciphertext;
};

CodecResult<std::vector<std::byte>> seal_aead(const EVP_AEAD *aead,
                                              const SealAeadRequest &request) {
    const auto invalid_lengths =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_length_guard);
    if (invalid_lengths) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_init)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::unique_ptr<EVP_AEAD_CTX, decltype(&EVP_AEAD_CTX_free)> context(
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_context_new)
            ? nullptr
            : EVP_AEAD_CTX_new(aead, openssl_data(request.key), request.key.size(),
                               aead_tag_length),
        &EVP_AEAD_CTX_free);
    if (context == nullptr) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    if (!request.associated_data.empty() &&
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_aad_update)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_payload_update)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::vector<std::byte> ciphertext(request.plaintext.size() + aead_tag_length);
    std::size_t output_length = 0;
    if (aead_ctx_seal(context.get(), std::span{ciphertext}, &output_length, request.nonce,
                      request.plaintext, request.associated_data) != 1) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_final) ||
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_get_tag)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    ciphertext.resize(output_length);
    return CodecResult<std::vector<std::byte>>::success(std::move(ciphertext));
}

CodecResult<std::vector<std::byte>> open_aead(const EVP_AEAD *aead,
                                              const OpenAeadRequest &request) {
    if (request.ciphertext.size() < aead_tag_length) {
        return crypto_failure(CodecErrorCode::packet_decryption_failed);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::open_length_guard)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::open_init)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::unique_ptr<EVP_AEAD_CTX, decltype(&EVP_AEAD_CTX_free)> context(
        consume_packet_crypto_fault(PacketCryptoFaultPoint::open_context_new)
            ? nullptr
            : EVP_AEAD_CTX_new(aead, openssl_data(request.key), request.key.size(),
                               aead_tag_length),
        &EVP_AEAD_CTX_free);
    if (context == nullptr) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    if (!request.associated_data.empty() &&
        consume_packet_crypto_fault(PacketCryptoFaultPoint::open_aad_update)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::open_payload_update) ||
        consume_packet_crypto_fault(PacketCryptoFaultPoint::open_set_tag)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::vector<std::byte> plaintext(request.ciphertext.size() - aead_tag_length);
    std::size_t output_length = 0;
    if (EVP_AEAD_CTX_open(context.get(), openssl_data(std::span{plaintext}), &output_length,
                          plaintext.size(), openssl_data(request.nonce), request.nonce.size(),
                          openssl_data(request.ciphertext), request.ciphertext.size(),
                          openssl_data(request.associated_data),
                          request.associated_data.size()) != 1) {
        return crypto_failure(CodecErrorCode::packet_decryption_failed);
    }

    plaintext.resize(output_length);
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

    static constexpr std::array<const EVP_AEAD *(*)(), 3> kAeadCiphers{
        &EVP_aead_aes_128_gcm,
        &EVP_aead_aes_256_gcm,
        &EVP_aead_chacha20_poly1305,
    };
    const auto aead = kAeadCiphers[static_cast<std::size_t>(cipher_suite)]();

    return seal_aead(aead, SealAeadRequest{
                               .key = key,
                               .nonce = nonce,
                               .associated_data = associated_data,
                               .plaintext = plaintext,
                           });
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

    static constexpr std::array<const EVP_AEAD *(*)(), 3> kAeadCiphers{
        &EVP_aead_aes_128_gcm,
        &EVP_aead_aes_256_gcm,
        &EVP_aead_chacha20_poly1305,
    };
    const auto aead = kAeadCiphers[static_cast<std::size_t>(cipher_suite)]();

    return open_aead(aead, OpenAeadRequest{
                               .key = key,
                               .nonce = nonce,
                               .associated_data = associated_data,
                               .ciphertext = ciphertext,
                           });
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
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_context_new)) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    const auto sample_prefix = sample.first(header_protection_sample_length);

    if (cipher_suite == CipherSuite::tls_chacha20_poly1305_sha256) {
        if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_chacha_init)) {
            return crypto_failure(CodecErrorCode::header_protection_failed);
        }

        std::array<std::byte, header_protection_mask_length> zeros{};
        std::vector<std::byte> mask(header_protection_mask_length);
        const std::uint32_t counter = std::to_integer<std::uint8_t>(sample_prefix[0]) |
                                      (std::to_integer<std::uint8_t>(sample_prefix[1]) << 8) |
                                      (std::to_integer<std::uint8_t>(sample_prefix[2]) << 16) |
                                      (std::to_integer<std::uint8_t>(sample_prefix[3]) << 24);
        const auto nonce = sample_prefix.subspan(4, 12);

        CRYPTO_chacha_20(openssl_data(std::span{mask}),
                         openssl_data(std::span<const std::byte>{zeros}), mask.size(),
                         openssl_data(hp_key), openssl_data(nonce), counter);

        if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_chacha_final)) {
            return crypto_failure(CodecErrorCode::header_protection_failed);
        }
        if (consume_packet_crypto_fault(
                PacketCryptoFaultPoint::header_protection_chacha_bad_length)) {
            mask.clear();
        }
        if (mask.size() != header_protection_mask_length) {
            return crypto_failure(CodecErrorCode::header_protection_failed);
        }

        return CodecResult<std::vector<std::byte>>::success(std::move(mask));
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        new_header_protection_cipher_ctx(), &EVP_CIPHER_CTX_free);
    if (context == nullptr) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    static constexpr std::array<const EVP_CIPHER *(*)(), 2> kHeaderProtectionAesCiphers{
        &EVP_aes_128_ecb,
        &EVP_aes_256_ecb,
    };
    const auto cipher = kHeaderProtectionAesCiphers[static_cast<std::size_t>(cipher_suite)]();

    std::vector<std::byte> block(header_protection_sample_length);
    int produced_length = 0;
    const auto init_failed = header_protection_aes_init(context.get(), cipher, hp_key) <= 0 ||
                             header_protection_aes_set_padding(context.get()) <= 0 ||
                             header_protection_aes_update(context.get(), std::span{block},
                                                          &produced_length, sample_prefix) <= 0;
    if (init_failed) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    int final_length = 0;
    const auto final_failed =
        header_protection_aes_final(
            context.get(), std::span{block}.subspan(static_cast<std::size_t>(produced_length)),
            &final_length) <= 0;
    if (final_failed) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_bad_length)) {
        produced_length = 0;
        final_length = 0;
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

namespace coquic::quic::test {

ScopedPacketCryptoFaultInjector::ScopedPacketCryptoFaultInjector(PacketCryptoFaultPoint fault_point,
                                                                 std::size_t occurrence)
    : previous_fault_point_(detail::packet_crypto_fault_state().fault_point),
      previous_occurrence_(detail::packet_crypto_fault_state().occurrence) {
    detail::set_packet_crypto_fault_state(fault_point, occurrence);
}

ScopedPacketCryptoFaultInjector::~ScopedPacketCryptoFaultInjector() {
    detail::set_packet_crypto_fault_state(previous_fault_point_, previous_occurrence_);
}

} // namespace coquic::quic::test
