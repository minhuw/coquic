#include "src/quic/packet_crypto_internal.h"

#include <algorithm>
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

struct ReusableCipherContext {
    EVP_CIPHER_CTX *context = nullptr;
    std::size_t new_calls = 0;

    ~ReusableCipherContext() {
        EVP_CIPHER_CTX_free(context);
    }

    void reset() {
        EVP_CIPHER_CTX_free(context);
        context = nullptr;
        new_calls = 0;
    }
};

struct ReusableAeadCipherContext {
    EVP_CIPHER_CTX *context = nullptr;
    const EVP_CIPHER *cipher = nullptr;
    std::vector<std::byte> key;
    std::size_t iv_length = 0;
    std::size_t new_calls = 0;
    std::size_t key_setup_calls = 0;

    ~ReusableAeadCipherContext() {
        EVP_CIPHER_CTX_free(context);
    }

    void clear_cached_configuration() {
        cipher = nullptr;
        key.clear();
        iv_length = 0;
    }

    void reset() {
        EVP_CIPHER_CTX_free(context);
        context = nullptr;
        clear_cached_configuration();
        new_calls = 0;
        key_setup_calls = 0;
    }
};

ReusableAeadCipherContext &seal_context_cache() {
    static thread_local ReusableAeadCipherContext cache;
    return cache;
}

ReusableAeadCipherContext &open_context_cache() {
    static thread_local ReusableAeadCipherContext cache;
    return cache;
}

ReusableCipherContext &header_protection_context_cache() {
    static thread_local ReusableCipherContext cache;
    return cache;
}

EVP_CIPHER_CTX *acquire_cipher_context(ReusableAeadCipherContext &cache,
                                       PacketCryptoFaultPoint fault_point) {
    if (cache.context == nullptr) {
        if (consume_packet_crypto_fault(fault_point)) {
            return nullptr;
        }

        cache.context = EVP_CIPHER_CTX_new();
        if (cache.context == nullptr) {
            return nullptr;
        }
        ++cache.new_calls;
        return cache.context;
    }

    return cache.context;
}

EVP_CIPHER_CTX *
acquire_cipher_context(ReusableCipherContext &cache, PacketCryptoFaultPoint fault_point,
                       std::optional<PacketCryptoFaultPoint> alternate_fault_point = std::nullopt) {
    if (cache.context == nullptr) {
        if (consume_packet_crypto_fault(fault_point) ||
            (alternate_fault_point.has_value() &&
             consume_packet_crypto_fault(*alternate_fault_point))) {
            return nullptr;
        }

        cache.context = EVP_CIPHER_CTX_new();
        if (cache.context == nullptr) {
            return nullptr;
        }
        ++cache.new_calls;
        return cache.context;
    }

    if (EVP_CIPHER_CTX_reset(cache.context) <= 0) {
        EVP_CIPHER_CTX_free(cache.context);
        cache.context = nullptr;
        return nullptr;
    }
    return cache.context;
}

bool cached_cipher_configuration_matches(const ReusableAeadCipherContext &cache,
                                         const EVP_CIPHER *cipher, std::span<const std::byte> key,
                                         std::size_t iv_length) {
    return cache.cipher == cipher && cache.iv_length == iv_length &&
           cache.key.size() == key.size() &&
           std::equal(cache.key.begin(), cache.key.end(), key.begin(), key.end());
}

bool reset_cipher_context(ReusableAeadCipherContext &cache) {
    cache.clear_cached_configuration();
    if (cache.context == nullptr) {
        return true;
    }

    if (EVP_CIPHER_CTX_reset(cache.context) <= 0) {
        EVP_CIPHER_CTX_free(cache.context);
        cache.context = nullptr;
        return false;
    }
    return true;
}

void cache_cipher_configuration(ReusableAeadCipherContext &cache, const EVP_CIPHER *cipher,
                                std::span<const std::byte> key, std::size_t iv_length) {
    cache.cipher = cipher;
    cache.key.assign(key.begin(), key.end());
    cache.iv_length = iv_length;
    ++cache.key_setup_calls;
}

EVP_CIPHER_CTX *prepare_seal_cipher_context(ReusableAeadCipherContext &cache,
                                            const EVP_CIPHER *cipher,
                                            std::span<const std::byte> key,
                                            std::span<const std::byte> nonce) {
    auto *context = acquire_cipher_context(cache, PacketCryptoFaultPoint::seal_context_new);
    if (context == nullptr) {
        return nullptr;
    }

    if (!cached_cipher_configuration_matches(cache, cipher, key, nonce.size())) {
        if (cache.cipher != nullptr && !reset_cipher_context(cache)) {
            context = acquire_cipher_context(cache, PacketCryptoFaultPoint::seal_context_new);
            if (context == nullptr) {
                return nullptr;
            }
        }

        bool init_failed = consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_init);
        init_failed |= EVP_EncryptInit_ex(context, cipher, nullptr, nullptr, nullptr) <= 0;
        init_failed |= EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
                                           static_cast<int>(nonce.size()), nullptr) <= 0;
        init_failed |= EVP_EncryptInit_ex(context, nullptr, nullptr, openssl_data(key),
                                          openssl_data(nonce)) <= 0;
        if (init_failed) {
            reset_cipher_context(cache);
            return nullptr;
        }

        cache_cipher_configuration(cache, cipher, key, nonce.size());
        return context;
    }

    const bool init_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_init) |
        (EVP_EncryptInit_ex(context, nullptr, nullptr, nullptr, openssl_data(nonce)) <= 0);
    if (init_failed) {
        reset_cipher_context(cache);
        return nullptr;
    }

    return context;
}

EVP_CIPHER_CTX *prepare_open_cipher_context(ReusableAeadCipherContext &cache,
                                            const EVP_CIPHER *cipher,
                                            std::span<const std::byte> key,
                                            std::span<const std::byte> nonce) {
    auto *context = acquire_cipher_context(cache, PacketCryptoFaultPoint::open_context_new);
    if (context == nullptr) {
        return nullptr;
    }

    if (!cached_cipher_configuration_matches(cache, cipher, key, nonce.size())) {
        if (cache.cipher != nullptr && !reset_cipher_context(cache)) {
            context = acquire_cipher_context(cache, PacketCryptoFaultPoint::open_context_new);
            if (context == nullptr) {
                return nullptr;
            }
        }

        bool init_failed = consume_packet_crypto_fault(PacketCryptoFaultPoint::open_init);
        init_failed |= EVP_DecryptInit_ex(context, cipher, nullptr, nullptr, nullptr) <= 0;
        init_failed |= EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
                                           static_cast<int>(nonce.size()), nullptr) <= 0;
        init_failed |= EVP_DecryptInit_ex(context, nullptr, nullptr, openssl_data(key),
                                          openssl_data(nonce)) <= 0;
        if (init_failed) {
            reset_cipher_context(cache);
            return nullptr;
        }

        cache_cipher_configuration(cache, cipher, key, nonce.size());
        return context;
    }

    const bool init_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::open_init) |
        (EVP_DecryptInit_ex(context, nullptr, nullptr, nullptr, openssl_data(nonce)) <= 0);
    if (init_failed) {
        reset_cipher_context(cache);
        return nullptr;
    }

    return context;
}

coquic::quic::test::PacketCryptoRuntimeCacheStats runtime_cache_stats_for_tests_impl() {
    return coquic::quic::test::PacketCryptoRuntimeCacheStats{
        .seal_context_new_calls = seal_context_cache().new_calls,
        .open_context_new_calls = open_context_cache().new_calls,
        .header_protection_context_new_calls = header_protection_context_cache().new_calls,
        .seal_key_setup_calls = seal_context_cache().key_setup_calls,
        .open_key_setup_calls = open_context_cache().key_setup_calls,
    };
}

void reset_runtime_caches_for_tests_impl() {
    seal_context_cache().reset();
    open_context_cache().reset();
    header_protection_context_cache().reset();
}

CodecResult<std::size_t> total_plaintext_length(std::span<const PlaintextChunk> plaintext_chunks) {
    const auto max_openssl_size = static_cast<std::size_t>(std::numeric_limits<int>::max());
    std::size_t total = 0;
    for (const auto &chunk : plaintext_chunks) {
        if (!fits_openssl_int(chunk.bytes.size())) {
            return CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
        }
        if (chunk.bytes.size() > max_openssl_size - total) {
            return CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
        }
        total += chunk.bytes.size();
    }

    return CodecResult<std::size_t>::success(total);
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
                                                std::span<const std::byte> secret,
                                                std::uint32_t quic_version) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value())
        return packet_key_failure(parameters.error().code);
    const auto labels = packet_protection_labels_for_version(quic_version);
    if (!labels.has_value())
        return packet_key_failure(labels.error().code);

    const auto digest = parameters.value().digest();
    const auto key =
        hkdf_expand_label(digest, secret, labels.value().key, parameters.value().key_length);
    if (!key.has_value())
        return packet_key_failure(key.error().code);

    const auto iv =
        hkdf_expand_label(digest, secret, labels.value().iv, parameters.value().iv_length);
    if (!iv.has_value())
        return packet_key_failure(iv.error().code);

    const auto hp_key =
        hkdf_expand_label(digest, secret, labels.value().hp, parameters.value().hp_key_length);
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

    const auto parameters = cipher_suite_parameters(secret.cipher_suite).value();
    const auto labels = packet_protection_labels_for_version(secret.quic_version).value();

    auto hp_key =
        hkdf_expand_label(parameters.digest(), secret.secret, labels.hp, parameters.hp_key_length);
    if (!hp_key.has_value()) {
        return crypto_failure(hp_key.error().code);
    }

    return hp_key;
}

struct SealAeadRequest {
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const std::byte> plaintext;
    std::span<std::byte> ciphertext;
};

CodecResult<std::vector<std::byte>>
serialize_retry_pseudo_packet(const RetryPacket &packet,
                              const ConnectionId &original_destination_connection_id) {
    if (original_destination_connection_id.size() >
        static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max())) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto encoded_retry_packet = serialize_packet(Packet{packet});
    if (!encoded_retry_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(encoded_retry_packet.error().code,
                                                            encoded_retry_packet.error().offset);
    }

    std::vector<std::byte> pseudo_packet;
    pseudo_packet.reserve(1 + original_destination_connection_id.size() +
                          encoded_retry_packet.value().size() - aead_tag_length);
    pseudo_packet.push_back(
        static_cast<std::byte>(original_destination_connection_id.size() & 0xff));
    pseudo_packet.insert(pseudo_packet.end(), original_destination_connection_id.begin(),
                         original_destination_connection_id.end());
    pseudo_packet.insert(pseudo_packet.end(), encoded_retry_packet.value().begin(),
                         encoded_retry_packet.value().end() - aead_tag_length);
    return CodecResult<std::vector<std::byte>>::success(std::move(pseudo_packet));
}

CodecResult<std::size_t> seal_aead_chunks_into(const EVP_CIPHER *cipher,
                                               std::span<const std::byte> key,
                                               std::span<const std::byte> nonce,
                                               std::span<const std::byte> associated_data,
                                               std::span<const PlaintextChunk> plaintext_chunks,
                                               std::span<std::byte> ciphertext) {
    const auto plaintext_length = total_plaintext_length(plaintext_chunks);
    if (!plaintext_length.has_value()) {
        return plaintext_length;
    }
    const auto invalid_lengths =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_length_guard) |
        !fits_openssl_int(nonce.size()) | !fits_openssl_int(associated_data.size());
    if (invalid_lengths)
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    if (ciphertext.size() < plaintext_length.value() + aead_tag_length)
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);

    auto &cache = seal_context_cache();
    auto *context = prepare_seal_cipher_context(cache, cipher, key, nonce);
    if (context == nullptr) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    int output_length = 0;
    if (!associated_data.empty()) {
        const auto aad_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_aad_update) |
            (EVP_EncryptUpdate(context, nullptr, &output_length, openssl_data(associated_data),
                               static_cast<int>(associated_data.size())) <= 0);
        if (aad_failed) {
            reset_cipher_context(cache);
            return CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
        }
    }

    auto payload_output = ciphertext.first(ciphertext.size() - aead_tag_length);
    std::size_t produced_total = 0;
    for (const auto &chunk : plaintext_chunks) {
        if (chunk.bytes.empty()) {
            continue;
        }

        int produced_length = 0;
        const auto payload_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_payload_update) |
            (EVP_EncryptUpdate(context, openssl_data(payload_output.subspan(produced_total)),
                               &produced_length, openssl_data(chunk.bytes),
                               static_cast<int>(chunk.bytes.size())) <= 0);
        if (payload_failed) {
            reset_cipher_context(cache);
            return CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
        }
        produced_total += static_cast<std::size_t>(produced_length);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_native_seal)) {
        reset_cipher_context(cache);
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    int final_length = 0;
    const auto final_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_final) |
        (EVP_EncryptFinal_ex(context, openssl_data(payload_output.subspan(produced_total)),
                             &final_length) <= 0);
    if (final_failed) {
        reset_cipher_context(cache);
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    const auto total_ciphertext_length = produced_total + static_cast<std::size_t>(final_length);

    std::array<std::byte, aead_tag_length> tag{};
    const auto get_tag_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_get_tag) |
        (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tag.size()),
                             openssl_data(std::span<std::byte>{tag})) <= 0);
    if (get_tag_failed) {
        reset_cipher_context(cache);
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    const auto tag_output = ciphertext.subspan(total_ciphertext_length, tag.size());
    std::copy(tag.begin(), tag.end(), tag_output.begin());
    return CodecResult<std::size_t>::success(total_ciphertext_length + tag.size());
}

CodecResult<std::size_t> seal_aead_into(const EVP_CIPHER *cipher, const SealAeadRequest &request) {
    const std::array chunks{
        PlaintextChunk{
            .bytes = request.plaintext,
        },
    };
    return seal_aead_chunks_into(cipher, request.key, request.nonce, request.associated_data,
                                 chunks, request.ciphertext);
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

    auto &cache = open_context_cache();
    auto *context = prepare_open_cipher_context(cache, cipher, key, nonce);
    if (context == nullptr) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    int output_length = 0;
    if (!associated_data.empty()) {
        const auto aad_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::open_aad_update) |
            (EVP_DecryptUpdate(context, nullptr, &output_length, openssl_data(associated_data),
                               static_cast<int>(associated_data.size())) <= 0);
        if (aad_failed) {
            reset_cipher_context(cache);
            return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
        }
    }

    std::vector<std::byte> plaintext(ciphertext_without_tag.size());
    int produced_length = 0;
    const auto payload_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::open_payload_update) |
        (EVP_DecryptUpdate(context, openssl_data(std::span{plaintext}), &produced_length,
                           openssl_data(ciphertext_without_tag),
                           static_cast<int>(ciphertext_without_tag.size())) <= 0);
    if (payload_failed) {
        reset_cipher_context(cache);
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    const auto set_tag_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::open_set_tag) |
        (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(mutable_tag.size()),
                             openssl_data(std::span{mutable_tag})) <= 0);
    if (set_tag_failed) {
        reset_cipher_context(cache);
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    int final_length = 0;
    if (EVP_DecryptFinal_ex(
            context,
            openssl_data(std::span{plaintext}.subspan(static_cast<std::size_t>(produced_length))),
            &final_length) <= 0) {
        reset_cipher_context(cache);
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
                           const ConnectionId &client_initial_destination_connection_id,
                           std::uint32_t version) {
    const auto salt = initial_salt_for_version(version);
    if (!salt.has_value()) {
        return CodecResult<PacketProtectionKeys>::failure(salt.error().code, salt.error().offset);
    }

    const auto initial_secret =
        hkdf_extract(EVP_sha256(), salt.value(), client_initial_destination_connection_id);
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

    return expand_secret(CipherSuite::tls_aes_128_gcm_sha256, directional_secret.value(), version);
}

CodecResult<std::reference_wrapper<const PacketProtectionKeys>>
expand_traffic_secret_cached(const TrafficSecret &secret) {
    if (secret.cached_packet_protection_keys.has_value() &&
        secret.cached_packet_protection_inputs.has_value()) {
        const auto &cached_inputs = secret.cached_packet_protection_inputs.value();
        if (cached_inputs.secret == secret.secret &&
            cached_inputs.header_protection_key == secret.header_protection_key &&
            cached_inputs.quic_version == secret.quic_version) {
            return CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::success(
                std::cref(secret.cached_packet_protection_keys.value()));
        }
    }

    auto keys = expand_secret(secret.cipher_suite, secret.secret, secret.quic_version);
    if (!keys.has_value()) {
        return CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::failure(
            keys.error().code, keys.error().offset);
    }

    const auto hp_key = derive_header_protection_key(secret);
    if (!hp_key.has_value()) {
        return CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::failure(
            hp_key.error().code, hp_key.error().offset);
    }

    auto expanded = keys.value();
    expanded.hp_key = hp_key.value();
    secret.cached_packet_protection_keys = expanded;
    secret.cached_packet_protection_inputs = TrafficSecretCacheInputs{
        .secret = secret.secret,
        .header_protection_key = secret.header_protection_key,
        .quic_version = secret.quic_version,
    };
    return CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::success(
        std::cref(secret.cached_packet_protection_keys.value()));
}

CodecResult<PacketProtectionKeys> expand_traffic_secret(const TrafficSecret &secret) {
    const auto cached = expand_traffic_secret_cached(secret);
    if (!cached.has_value()) {
        return CodecResult<PacketProtectionKeys>::failure(cached.error().code,
                                                          cached.error().offset);
    }

    return CodecResult<PacketProtectionKeys>::success(cached.value().get());
}

CodecResult<TrafficSecret> derive_next_traffic_secret(const TrafficSecret &secret) {
    const auto parameters = cipher_suite_parameters(secret.cipher_suite);
    if (!parameters.has_value()) {
        return CodecResult<TrafficSecret>::failure(parameters.error().code,
                                                   parameters.error().offset);
    }
    const auto labels = packet_protection_labels_for_version(secret.quic_version);
    if (!labels.has_value()) {
        return CodecResult<TrafficSecret>::failure(labels.error().code, labels.error().offset);
    }

    const auto digest = parameters.value().digest();
    const auto secret_length = static_cast<std::size_t>(EVP_MD_get_size(digest));
    const auto next_secret =
        hkdf_expand_label(digest, secret.secret, labels.value().ku, secret_length);
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
        .quic_version = secret.quic_version,
    });
}

CodecResult<std::size_t> make_packet_protection_nonce_into(PacketProtectionNonceInput input,
                                                           std::span<std::byte> nonce) {
    if (nonce.size() < input.iv.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    auto nonce_output = nonce.first(input.iv.size());
    std::copy(input.iv.begin(), input.iv.end(), nonce_output.begin());
    auto packet_number_value = input.packet_number;

    for (std::size_t index = 0; index < sizeof(input.packet_number) && index < nonce_output.size();
         ++index) {
        const auto nonce_index = nonce_output.size() - 1 - index;
        nonce_output[nonce_index] ^= static_cast<std::byte>(packet_number_value & 0xff);
        packet_number_value >>= 8;
    }

    return CodecResult<std::size_t>::success(nonce_output.size());
}

CodecResult<std::vector<std::byte>> make_packet_protection_nonce(PacketProtectionNonceInput input) {
    auto nonce = std::vector<std::byte>(input.iv.size());
    const auto written = make_packet_protection_nonce_into(input, nonce);
    if (!written.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(written.error().code,
                                                            written.error().offset);
    }
    nonce.resize(written.value());
    return CodecResult<std::vector<std::byte>>::success(std::move(nonce));
}

CodecResult<std::array<std::byte, 16>>
compute_retry_integrity_tag(const RetryPacket &packet,
                            const ConnectionId &original_destination_connection_id) {
    const auto retry_material = retry_integrity_material_for_version(packet.version);
    if (!retry_material.has_value()) {
        return CodecResult<std::array<std::byte, 16>>::failure(retry_material.error().code,
                                                               retry_material.error().offset);
    }

    const auto retry_pseudo_packet =
        serialize_retry_pseudo_packet(packet, original_destination_connection_id);
    if (!retry_pseudo_packet.has_value()) {
        return CodecResult<std::array<std::byte, 16>>::failure(retry_pseudo_packet.error().code,
                                                               retry_pseudo_packet.error().offset);
    }

    const auto integrity_tag_ciphertext = seal_payload(SealPayloadInput{
        .cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
        .key = retry_material.value().key,
        .nonce = retry_material.value().nonce,
        .associated_data = retry_pseudo_packet.value(),
        .plaintext = {},
    });
    if (!integrity_tag_ciphertext.has_value()) {
        return CodecResult<std::array<std::byte, 16>>::failure(
            integrity_tag_ciphertext.error().code, integrity_tag_ciphertext.error().offset);
    }

    std::array<std::byte, 16> retry_integrity_tag{};
    for (std::size_t i = 0; i < retry_integrity_tag.size(); ++i) {
        retry_integrity_tag[i] = integrity_tag_ciphertext.value()[i];
    }

    return CodecResult<std::array<std::byte, 16>>::success(retry_integrity_tag);
}

CodecResult<bool>
validate_retry_integrity_tag(const RetryPacket &packet,
                             const ConnectionId &original_destination_connection_id) {
    const auto expected_retry_integrity_tag =
        compute_retry_integrity_tag(packet, original_destination_connection_id);
    if (!expected_retry_integrity_tag.has_value()) {
        return CodecResult<bool>::failure(expected_retry_integrity_tag.error().code,
                                          expected_retry_integrity_tag.error().offset);
    }

    bool valid = true;
    for (std::size_t i = 0; i < expected_retry_integrity_tag.value().size(); ++i) {
        if (expected_retry_integrity_tag.value()[i] != packet.retry_integrity_tag[i]) {
            valid = false;
        }
    }
    return CodecResult<bool>::success(valid);
}

CodecResult<std::size_t> seal_payload_into(const SealPayloadIntoInput &input) {
    const auto parameters = cipher_suite_parameters(input.cipher_suite);
    if (!parameters.has_value())
        return CodecResult<std::size_t>::failure(parameters.error().code, 0);
    if ((input.key.size() != parameters.value().key_length) |
        (input.nonce.size() != parameters.value().iv_length))
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);

    static constexpr std::array<const EVP_CIPHER *(*)(), 3> kAeadCiphers{
        &EVP_aes_128_gcm,
        &EVP_aes_256_gcm,
        &EVP_chacha20_poly1305,
    };
    const auto cipher = kAeadCiphers[static_cast<std::size_t>(input.cipher_suite)]();

    return seal_aead_into(cipher, SealAeadRequest{
                                      .key = input.key,
                                      .nonce = input.nonce,
                                      .associated_data = input.associated_data,
                                      .plaintext = input.plaintext,
                                      .ciphertext = input.ciphertext,
                                  });
}

CodecResult<std::size_t> seal_payload_chunks_into(const SealPayloadChunksIntoInput &input) {
    const auto parameters = cipher_suite_parameters(input.cipher_suite);
    if (!parameters.has_value())
        return CodecResult<std::size_t>::failure(parameters.error().code, 0);
    if (input.key.size() != parameters.value().key_length ||
        input.nonce.size() != parameters.value().iv_length)
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);

    static constexpr std::array<const EVP_CIPHER *(*)(), 3> kAeadCiphers{
        &EVP_aes_128_gcm,
        &EVP_aes_256_gcm,
        &EVP_chacha20_poly1305,
    };
    const auto cipher = kAeadCiphers[static_cast<std::size_t>(input.cipher_suite)]();

    return seal_aead_chunks_into(cipher, input.key, input.nonce, input.associated_data,
                                 input.plaintext_chunks, input.ciphertext);
}

CodecResult<std::vector<std::byte>> seal_payload(const SealPayloadInput &input) {
    const auto parameters = cipher_suite_parameters(input.cipher_suite);
    if (!parameters.has_value())
        return crypto_failure(parameters.error().code);

    std::vector<std::byte> ciphertext(input.plaintext.size() + aead_tag_length);
    const auto written = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = input.cipher_suite,
        .key = input.key,
        .nonce = input.nonce,
        .associated_data = input.associated_data,
        .plaintext = input.plaintext,
        .ciphertext = std::span<std::byte>{ciphertext},
    });
    if (!written.has_value())
        return crypto_failure(written.error().code);

    ciphertext.resize(written.value());
    return CodecResult<std::vector<std::byte>>::success(std::move(ciphertext));
}

CodecResult<std::vector<std::byte>> open_payload(const OpenPayloadInput &input) {
    const auto parameters = cipher_suite_parameters(input.cipher_suite);
    if (!parameters.has_value())
        return crypto_failure(parameters.error().code);
    if (input.key.size() != parameters.value().key_length ||
        input.nonce.size() != parameters.value().iv_length)
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);

    static constexpr std::array<const EVP_CIPHER *(*)(), 3> kAeadCiphers{
        &EVP_aes_128_gcm,
        &EVP_aes_256_gcm,
        &EVP_chacha20_poly1305,
    };
    const auto cipher = kAeadCiphers[static_cast<std::size_t>(input.cipher_suite)]();

    return open_aead(cipher, input.key, input.nonce, input.associated_data, input.ciphertext);
}

CodecResult<std::size_t> make_header_protection_mask_into(CipherSuite cipher_suite,
                                                          HeaderProtectionMaskInput input,
                                                          std::span<std::byte> mask) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value()) {
        return CodecResult<std::size_t>::failure(parameters.error().code, 0);
    }
    if (input.hp_key.size() != parameters.value().hp_key_length) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }
    if (input.sample.size() < header_protection_sample_length) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::header_protection_sample_too_short,
                                                 0);
    }
    if (mask.size() < header_protection_mask_length) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    const auto sample_prefix = input.sample.first(header_protection_sample_length);
    auto mask_output = mask.first(header_protection_mask_length);

    auto *context = acquire_cipher_context(
        header_protection_context_cache(), PacketCryptoFaultPoint::header_protection_context_new,
        PacketCryptoFaultPoint::header_protection_aes_context_new);
    if (context == nullptr) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::header_protection_failed, 0);
    }

    if (cipher_suite == CipherSuite::tls_chacha20_poly1305_sha256) {
        std::array<std::byte, header_protection_mask_length> zeros{};
        int produced_length = 0;
        const auto init_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_chacha_init) |
            (EVP_EncryptInit_ex(context, EVP_chacha20(), nullptr, openssl_data(input.hp_key),
                                openssl_data(sample_prefix)) <= 0) |
            (EVP_EncryptUpdate(context, openssl_data(mask_output), &produced_length,
                               openssl_data(std::span<const std::byte>{zeros}),
                               static_cast<int>(zeros.size())) <= 0);
        if (init_failed) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::header_protection_failed, 0);
        }

        int final_length = 0;
        const auto final_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_chacha_final) |
            (EVP_EncryptFinal_ex(
                 context,
                 openssl_data(mask_output.subspan(static_cast<std::size_t>(produced_length))),
                 &final_length) <= 0);
        if (final_failed) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::header_protection_failed, 0);
        }

        if (consume_packet_crypto_fault(
                PacketCryptoFaultPoint::header_protection_chacha_bad_length)) {
            produced_length = 0;
            final_length = 0;
        }
        const auto mask_length =
            static_cast<std::size_t>(produced_length) + static_cast<std::size_t>(final_length);
        if (mask_length != header_protection_mask_length) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::header_protection_failed, 0);
        }
        return CodecResult<std::size_t>::success(mask_length);
    }

    static constexpr std::array<const EVP_CIPHER *(*)(), 2> kHeaderProtectionAesCiphers{
        &EVP_aes_128_ecb,
        &EVP_aes_256_ecb,
    };
    const auto cipher = kHeaderProtectionAesCiphers[static_cast<std::size_t>(cipher_suite)]();

    std::array<std::byte, header_protection_sample_length> block{};
    int produced_length = 0;
    const auto init_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_init) |
        (EVP_EncryptInit_ex(context, cipher, nullptr, openssl_data(input.hp_key), nullptr) <= 0) |
        consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_set_padding) |
        (EVP_CIPHER_CTX_set_padding(context, 0) <= 0) |
        consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_update) |
        (EVP_EncryptUpdate(context, openssl_data(std::span<std::byte>{block}), &produced_length,
                           openssl_data(sample_prefix),
                           static_cast<int>(sample_prefix.size())) <= 0);
    if (init_failed) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::header_protection_failed, 0);
    }

    int final_length = 0;
    const auto final_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_final) |
        (EVP_EncryptFinal_ex(context,
                             openssl_data(std::span<std::byte>{block}.subspan(
                                 static_cast<std::size_t>(produced_length))),
                             &final_length) <= 0);
    if (final_failed) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::header_protection_failed, 0);
    }

    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_aes_bad_length)) {
        produced_length = 0;
        final_length = 0;
    }
    const auto block_length =
        static_cast<std::size_t>(produced_length) + static_cast<std::size_t>(final_length);
    if (block_length != header_protection_sample_length) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::header_protection_failed, 0);
    }

    std::copy_n(block.begin(), header_protection_mask_length, mask_output.begin());
    return CodecResult<std::size_t>::success(header_protection_mask_length);
}

CodecResult<std::vector<std::byte>> make_header_protection_mask(CipherSuite cipher_suite,
                                                                HeaderProtectionMaskInput input) {
    std::vector<std::byte> mask(header_protection_mask_length);
    const auto written = make_header_protection_mask_into(cipher_suite, input, mask);
    if (!written.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(written.error().code,
                                                            written.error().offset);
    }
    mask.resize(written.value());
    return CodecResult<std::vector<std::byte>>::success(std::move(mask));
}

} // namespace coquic::quic

namespace coquic::quic::test {

PacketCryptoRuntimeCacheStats packet_crypto_runtime_cache_stats_for_tests() {
    return runtime_cache_stats_for_tests_impl();
}

void reset_packet_crypto_runtime_caches_for_tests() {
    reset_runtime_caches_for_tests_impl();
}

ScopedPacketCryptoFaultInjector::ScopedPacketCryptoFaultInjector(PacketCryptoFaultPoint fault_point,
                                                                 std::size_t occurrence)
    : previous_fault_point_(detail::packet_crypto_fault_state().fault_point),
      previous_occurrence_(detail::packet_crypto_fault_state().occurrence) {
    reset_packet_crypto_runtime_caches_for_tests();
    detail::set_packet_crypto_fault_state(fault_point, occurrence);
}

ScopedPacketCryptoFaultInjector::~ScopedPacketCryptoFaultInjector() {
    reset_packet_crypto_runtime_caches_for_tests();
    detail::set_packet_crypto_fault_state(previous_fault_point_, previous_occurrence_);
}

} // namespace coquic::quic::test
