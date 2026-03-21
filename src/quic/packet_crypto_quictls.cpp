#include "src/quic/packet_crypto_internal.h"

#include <array>
#include <limits>
#include <memory>

#include <openssl/kdf.h>

namespace {

using namespace coquic::quic;
using namespace coquic::quic::detail;

bool fits_openssl_int(std::size_t size) {
    return size <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

CodecResult<std::vector<std::byte>> hkdf_extract(const EVP_MD *digest,
                                                 std::span<const std::byte> salt,
                                                 std::span<const std::byte> input_key_material) {
    const auto digest_length = static_cast<std::size_t>(EVP_MD_get_size(digest));

    std::vector<std::byte> pseudorandom_key(digest_length);
    std::size_t output_length = pseudorandom_key.size();
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        consume_packet_crypto_fault(PacketCryptoFaultPoint::hkdf_extract_context_new)
            ? nullptr
            : EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr),
        &EVP_PKEY_CTX_free);
    if (context == nullptr)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);

    bool setup_failed = consume_packet_crypto_fault(PacketCryptoFaultPoint::hkdf_extract_setup);
    setup_failed |= EVP_PKEY_derive_init(context.get()) <= 0;
    setup_failed |=
        EVP_PKEY_CTX_set_hkdf_mode(context.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0;
    setup_failed |= EVP_PKEY_CTX_set_hkdf_md(context.get(), digest) <= 0;
    setup_failed |= EVP_PKEY_CTX_set1_hkdf_salt(context.get(), openssl_data(salt),
                                                static_cast<int>(salt.size())) <= 0;
    setup_failed |= EVP_PKEY_CTX_set1_hkdf_key(context.get(), openssl_data(input_key_material),
                                               static_cast<int>(input_key_material.size())) <= 0;
    setup_failed |= EVP_PKEY_derive(context.get(), openssl_data(std::span{pseudorandom_key}),
                                    &output_length) <= 0;
    if (setup_failed) {
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
        consume_packet_crypto_fault(PacketCryptoFaultPoint::hkdf_expand_context_new)
            ? nullptr
            : EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr),
        &EVP_PKEY_CTX_free);
    if (context == nullptr)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);

    bool setup_failed = consume_packet_crypto_fault(PacketCryptoFaultPoint::hkdf_expand_setup);
    setup_failed |= EVP_PKEY_derive_init(context.get()) <= 0;
    setup_failed |= EVP_PKEY_CTX_set_hkdf_mode(context.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0;
    setup_failed |= EVP_PKEY_CTX_set_hkdf_md(context.get(), digest) <= 0;
    setup_failed |= EVP_PKEY_CTX_set1_hkdf_key(context.get(), openssl_data(secret),
                                               static_cast<int>(secret.size())) <= 0;
    setup_failed |= EVP_PKEY_CTX_add1_hkdf_info(context.get(), openssl_data(info),
                                                static_cast<int>(info.size())) <= 0;
    setup_failed |=
        EVP_PKEY_derive(context.get(), openssl_data(std::span{output}), &derived_length) <= 0;
    if (setup_failed) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    output.resize(derived_length);
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
    if (!parameters.has_value())
        return packet_key_failure(parameters.error().code);

    const auto digest = parameters.value().digest();
    const auto key = hkdf_expand_label(digest, secret, "quic key", parameters.value().key_length);
    if (!key.has_value())
        return packet_key_failure(key.error().code);

    const auto iv = hkdf_expand_label(digest, secret, "quic iv", parameters.value().iv_length);
    if (!iv.has_value())
        return packet_key_failure(iv.error().code);

    const auto hp_key =
        hkdf_expand_label(digest, secret, "quic hp", parameters.value().hp_key_length);
    if (!hp_key.has_value())
        return packet_key_failure(hp_key.error().code);

    return CodecResult<PacketProtectionKeys>::success(PacketProtectionKeys{
        .key = key.value(),
        .iv = iv.value(),
        .hp_key = hp_key.value(),
    });
}

CodecResult<std::vector<std::byte>> derive_header_protection_key(const TrafficSecret &secret) {
    if (secret.header_protection_key.has_value()) {
        return CodecResult<std::vector<std::byte>>::success(secret.header_protection_key.value());
    }

    const auto parameters = cipher_suite_parameters(secret.cipher_suite);
    if (!parameters.has_value()) {
        return crypto_failure(parameters.error().code);
    }

    auto hp_key = hkdf_expand_label(parameters.value().digest(), secret.secret, "quic hp",
                                    parameters.value().hp_key_length);
    if (!hp_key.has_value()) {
        return crypto_failure(hp_key.error().code);
    }

    return hp_key;
}

CodecResult<std::vector<std::byte>> seal_aead(const EVP_CIPHER *cipher,
                                              std::span<const std::byte> key,
                                              std::span<const std::byte> nonce,
                                              std::span<const std::byte> associated_data,
                                              std::span<const std::byte> plaintext) {
    const auto invalid_lengths =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_length_guard) |
        !fits_openssl_int(nonce.size()) | !fits_openssl_int(associated_data.size()) |
        !fits_openssl_int(plaintext.size());
    if (invalid_lengths)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_context_new)
            ? nullptr
            : EVP_CIPHER_CTX_new(),
        &EVP_CIPHER_CTX_free);
    if (context == nullptr)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);

    bool init_failed = consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_init);
    init_failed |= EVP_EncryptInit_ex(context.get(), cipher, nullptr, nullptr, nullptr) <= 0;
    init_failed |= EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN,
                                       static_cast<int>(nonce.size()), nullptr) <= 0;
    init_failed |= EVP_EncryptInit_ex(context.get(), nullptr, nullptr, openssl_data(key),
                                      openssl_data(nonce)) <= 0;
    if (init_failed) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    int output_length = 0;
    if (!associated_data.empty()) {
        const auto aad_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_aad_update) |
            (EVP_EncryptUpdate(context.get(), nullptr, &output_length,
                               openssl_data(associated_data),
                               static_cast<int>(associated_data.size())) <= 0);
        if (aad_failed) {
            return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
        }
    }

    std::vector<std::byte> ciphertext(plaintext.size() + aead_tag_length);
    int produced_length = 0;
    const auto payload_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_payload_update) |
        (EVP_EncryptUpdate(context.get(), openssl_data(std::span{ciphertext}), &produced_length,
                           openssl_data(plaintext), static_cast<int>(plaintext.size())) <= 0);
    if (payload_failed) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_native_seal)) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    int final_length = 0;
    const auto final_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_final) |
        (EVP_EncryptFinal_ex(
             context.get(),
             openssl_data(std::span{ciphertext}.subspan(static_cast<std::size_t>(produced_length))),
             &final_length) <= 0);
    if (final_failed) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    std::array<std::byte, aead_tag_length> tag{};
    const auto get_tag_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_get_tag) |
        (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tag.size()),
                             openssl_data(std::span<std::byte>{tag})) <= 0);
    if (get_tag_failed) {
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
    if (ciphertext.size() < aead_tag_length)
        return crypto_failure(CodecErrorCode::packet_decryption_failed);
    const auto invalid_lengths =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::open_length_guard) |
        !fits_openssl_int(nonce.size()) | !fits_openssl_int(associated_data.size()) |
        !fits_openssl_int(ciphertext.size() - aead_tag_length);
    if (invalid_lengths)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);

    const auto ciphertext_without_tag = ciphertext.first(ciphertext.size() - aead_tag_length);
    const auto tag = ciphertext.last(aead_tag_length);
    std::vector<std::byte> mutable_tag(tag.begin(), tag.end());

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        consume_packet_crypto_fault(PacketCryptoFaultPoint::open_context_new)
            ? nullptr
            : EVP_CIPHER_CTX_new(),
        &EVP_CIPHER_CTX_free);
    if (context == nullptr)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);

    bool init_failed = consume_packet_crypto_fault(PacketCryptoFaultPoint::open_init);
    init_failed |= EVP_DecryptInit_ex(context.get(), cipher, nullptr, nullptr, nullptr) <= 0;
    init_failed |= EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN,
                                       static_cast<int>(nonce.size()), nullptr) <= 0;
    init_failed |= EVP_DecryptInit_ex(context.get(), nullptr, nullptr, openssl_data(key),
                                      openssl_data(nonce)) <= 0;
    if (init_failed) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    int output_length = 0;
    if (!associated_data.empty()) {
        const auto aad_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::open_aad_update) |
            (EVP_DecryptUpdate(context.get(), nullptr, &output_length,
                               openssl_data(associated_data),
                               static_cast<int>(associated_data.size())) <= 0);
        if (aad_failed) {
            return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
        }
    }

    std::vector<std::byte> plaintext(ciphertext_without_tag.size());
    int produced_length = 0;
    const auto payload_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::open_payload_update) |
        (EVP_DecryptUpdate(context.get(), openssl_data(std::span{plaintext}), &produced_length,
                           openssl_data(ciphertext_without_tag),
                           static_cast<int>(ciphertext_without_tag.size())) <= 0);
    if (payload_failed) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    const auto set_tag_failed = consume_packet_crypto_fault(PacketCryptoFaultPoint::open_set_tag) |
                                (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG,
                                                     static_cast<int>(mutable_tag.size()),
                                                     openssl_data(std::span{mutable_tag})) <= 0);
    if (set_tag_failed) {
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
    auto keys = expand_secret(secret.cipher_suite, secret.secret);
    if (!keys.has_value()) {
        return keys;
    }

    const auto hp_key = derive_header_protection_key(secret);
    if (!hp_key.has_value()) {
        return CodecResult<PacketProtectionKeys>::failure(hp_key.error().code,
                                                          hp_key.error().offset);
    }

    auto expanded = keys.value();
    expanded.hp_key = hp_key.value();
    return CodecResult<PacketProtectionKeys>::success(std::move(expanded));
}

CodecResult<TrafficSecret> derive_next_traffic_secret(const TrafficSecret &secret) {
    const auto parameters = cipher_suite_parameters(secret.cipher_suite);
    if (!parameters.has_value()) {
        return CodecResult<TrafficSecret>::failure(parameters.error().code,
                                                   parameters.error().offset);
    }

    const auto digest = parameters.value().digest();
    const auto secret_length = static_cast<std::size_t>(EVP_MD_get_size(digest));
    const auto next_secret = hkdf_expand_label(digest, secret.secret, "quic ku", secret_length);
    if (!next_secret.has_value()) {
        return CodecResult<TrafficSecret>::failure(next_secret.error().code,
                                                   next_secret.error().offset);
    }

    const auto hp_key = derive_header_protection_key(secret);
    if (!hp_key.has_value()) {
        return CodecResult<TrafficSecret>::failure(hp_key.error().code, hp_key.error().offset);
    }

    return CodecResult<TrafficSecret>::success(TrafficSecret{
        .cipher_suite = secret.cipher_suite,
        .secret = next_secret.value(),
        .header_protection_key = hp_key.value(),
    });
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
    if (!parameters.has_value())
        return crypto_failure(parameters.error().code);
    if (key.size() != parameters.value().key_length || nonce.size() != parameters.value().iv_length)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);

    static constexpr std::array<const EVP_CIPHER *(*)(), 3> kAeadCiphers{
        &EVP_aes_128_gcm,
        &EVP_aes_256_gcm,
        &EVP_chacha20_poly1305,
    };
    const auto cipher = kAeadCiphers[static_cast<std::size_t>(cipher_suite)]();

    return seal_aead(cipher, key, nonce, associated_data, plaintext);
}

CodecResult<std::vector<std::byte>> open_payload(CipherSuite cipher_suite,
                                                 std::span<const std::byte> key,
                                                 std::span<const std::byte> nonce,
                                                 std::span<const std::byte> associated_data,
                                                 std::span<const std::byte> ciphertext) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value())
        return crypto_failure(parameters.error().code);
    if (key.size() != parameters.value().key_length || nonce.size() != parameters.value().iv_length)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);

    static constexpr std::array<const EVP_CIPHER *(*)(), 3> kAeadCiphers{
        &EVP_aes_128_gcm,
        &EVP_aes_256_gcm,
        &EVP_chacha20_poly1305,
    };
    const auto cipher = kAeadCiphers[static_cast<std::size_t>(cipher_suite)]();

    return open_aead(cipher, key, nonce, associated_data, ciphertext);
}

CodecResult<std::vector<std::byte>> make_header_protection_mask(CipherSuite cipher_suite,
                                                                std::span<const std::byte> hp_key,
                                                                std::span<const std::byte> sample) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value())
        return crypto_failure(parameters.error().code);
    if (hp_key.size() != parameters.value().hp_key_length)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    if (sample.size() < header_protection_sample_length)
        return crypto_failure(CodecErrorCode::header_protection_sample_too_short);
    const auto sample_prefix = sample.first(header_protection_sample_length);

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_context_new) ||
                consume_packet_crypto_fault(
                    PacketCryptoFaultPoint::header_protection_aes_context_new)
            ? nullptr
            : EVP_CIPHER_CTX_new(),
        &EVP_CIPHER_CTX_free);
    if (context == nullptr)
        return crypto_failure(CodecErrorCode::header_protection_failed);

    if (cipher_suite == CipherSuite::tls_chacha20_poly1305_sha256) {
        std::array<std::byte, header_protection_mask_length> zeros{};
        std::vector<std::byte> mask(header_protection_mask_length);
        int produced_length = 0;
        const auto init_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_chacha_init) |
            (EVP_EncryptInit_ex(context.get(), EVP_chacha20(), nullptr, openssl_data(hp_key),
                                openssl_data(sample_prefix)) <= 0) |
            (EVP_EncryptUpdate(context.get(), openssl_data(std::span{mask}), &produced_length,
                               openssl_data(std::span<const std::byte>{zeros}),
                               static_cast<int>(zeros.size())) <= 0);
        if (init_failed) {
            return crypto_failure(CodecErrorCode::header_protection_failed);
        }

        int final_length = 0;
        const auto final_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_chacha_final) |
            (EVP_EncryptFinal_ex(
                 context.get(),
                 openssl_data(std::span{mask}.subspan(static_cast<std::size_t>(produced_length))),
                 &final_length) <= 0);
        if (final_failed) {
            return crypto_failure(CodecErrorCode::header_protection_failed);
        }

        if (consume_packet_crypto_fault(
                PacketCryptoFaultPoint::header_protection_chacha_bad_length)) {
            produced_length = 0;
            final_length = 0;
        }
        const auto mask_length =
            static_cast<std::size_t>(produced_length) + static_cast<std::size_t>(final_length);
        if (mask_length != header_protection_mask_length)
            return crypto_failure(CodecErrorCode::header_protection_failed);
        mask.resize(mask_length);
        return CodecResult<std::vector<std::byte>>::success(std::move(mask));
    }

    static constexpr std::array<const EVP_CIPHER *(*)(), 2> kHeaderProtectionAesCiphers{
        &EVP_aes_128_ecb,
        &EVP_aes_256_ecb,
    };
    const auto cipher = kHeaderProtectionAesCiphers[static_cast<std::size_t>(cipher_suite)]();

    std::vector<std::byte> block(header_protection_sample_length);
    int produced_length = 0;
    const auto init_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_init) |
        (EVP_EncryptInit_ex(context.get(), cipher, nullptr, openssl_data(hp_key), nullptr) <= 0) |
        consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_set_padding) |
        (EVP_CIPHER_CTX_set_padding(context.get(), 0) <= 0) |
        consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_update) |
        (EVP_EncryptUpdate(context.get(), openssl_data(std::span{block}), &produced_length,
                           openssl_data(sample_prefix),
                           static_cast<int>(sample_prefix.size())) <= 0);
    if (init_failed) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    int final_length = 0;
    const auto final_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_final) |
        (EVP_EncryptFinal_ex(
             context.get(),
             openssl_data(std::span{block}.subspan(static_cast<std::size_t>(produced_length))),
             &final_length) <= 0);
    if (final_failed) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_bad_length)) {
        produced_length = 0;
        final_length = 0;
    }
    const auto block_length =
        static_cast<std::size_t>(produced_length) + static_cast<std::size_t>(final_length);
    if (block_length != header_protection_sample_length)
        return crypto_failure(CodecErrorCode::header_protection_failed);
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

CodecResult<std::vector<std::byte>>
derive_header_protection_key_for_test(const TrafficSecret &secret) {
    return derive_header_protection_key(secret);
}

} // namespace coquic::quic::test
