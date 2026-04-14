#include "src/quic/packet_crypto_internal.h"

#include <array>
#include <limits>
#include <memory>

#include <openssl/aead.h>
#include <openssl/chacha.h>
#include <openssl/hkdf.h>

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

struct ReusableAeadContext {
    EVP_AEAD_CTX context{};
    bool initialized = false;
    const EVP_AEAD *aead = nullptr;
    std::vector<std::byte> key;
    std::size_t new_calls = 0;

    ~ReusableAeadContext() {
        if (initialized) {
            EVP_AEAD_CTX_cleanup(&context);
        }
    }

    void reset() {
        if (initialized) {
            EVP_AEAD_CTX_cleanup(&context);
        }
        initialized = false;
        aead = nullptr;
        key.clear();
        new_calls = 0;
    }
};

ReusableCipherContext &seal_cipher_context_cache() {
    static thread_local ReusableCipherContext cache;
    return cache;
}

ReusableAeadContext &seal_aead_context_cache() {
    static thread_local ReusableAeadContext cache;
    return cache;
}

ReusableAeadContext &open_aead_context_cache() {
    static thread_local ReusableAeadContext cache;
    return cache;
}

ReusableCipherContext &header_protection_context_cache() {
    static thread_local ReusableCipherContext cache;
    return cache;
}

EVP_CIPHER_CTX *acquire_cipher_context(ReusableCipherContext &cache,
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

    if (EVP_CIPHER_CTX_reset(cache.context) <= 0) {
        EVP_CIPHER_CTX_free(cache.context);
        cache.context = nullptr;
        return nullptr;
    }
    return cache.context;
}

EVP_AEAD_CTX *acquire_aead_context(ReusableAeadContext &cache, const EVP_AEAD *aead,
                                   std::span<const std::byte> key,
                                   PacketCryptoFaultPoint fault_point) {
    if (!cache.initialized || cache.aead != aead || cache.key != key) {
        if (cache.initialized) {
            EVP_AEAD_CTX_cleanup(&cache.context);
            cache.initialized = false;
        }
        if (consume_packet_crypto_fault(fault_point)) {
            return nullptr;
        }
        if (EVP_AEAD_CTX_init(&cache.context, aead, openssl_data(key), key.size(), aead_tag_length,
                              nullptr) != 1) {
            return nullptr;
        }
        cache.initialized = true;
        cache.aead = aead;
        cache.key.assign(key.begin(), key.end());
        ++cache.new_calls;
    }
    return &cache.context;
}

coquic::quic::test::PacketCryptoRuntimeCacheStats runtime_cache_stats_for_tests_impl() {
    return coquic::quic::test::PacketCryptoRuntimeCacheStats{
        .seal_context_new_calls =
            seal_cipher_context_cache().new_calls + seal_aead_context_cache().new_calls,
        .open_context_new_calls = open_aead_context_cache().new_calls,
        .header_protection_context_new_calls = header_protection_context_cache().new_calls,
    };
}

void reset_runtime_caches_for_tests_impl() {
    seal_cipher_context_cache().reset();
    seal_aead_context_cache().reset();
    open_aead_context_cache().reset();
    header_protection_context_cache().reset();
}

CodecResult<std::size_t> total_plaintext_length(std::span<const PlaintextChunk> plaintext_chunks) {
    std::size_t total = 0;
    for (const auto &chunk : plaintext_chunks) {
        if (!fits_openssl_int(chunk.bytes.size())) {
            return CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
        }
        if (chunk.bytes.size() > std::numeric_limits<std::size_t>::max() - total) {
            return CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
        }
        total += chunk.bytes.size();
    }

    return CodecResult<std::size_t>::success(total);
}

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
                                                std::span<const std::byte> secret,
                                                std::uint32_t quic_version) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value()) {
        return packet_key_failure(parameters.error().code);
    }
    const auto labels = packet_protection_labels_for_version(quic_version);
    if (!labels.has_value()) {
        return packet_key_failure(labels.error().code);
    }

    const auto digest = parameters.value().digest();
    const auto key =
        hkdf_expand_label(digest, secret, labels.value().key, parameters.value().key_length);
    if (!key.has_value()) {
        return packet_key_failure(key.error().code);
    }

    const auto iv =
        hkdf_expand_label(digest, secret, labels.value().iv, parameters.value().iv_length);
    if (!iv.has_value()) {
        return packet_key_failure(iv.error().code);
    }

    const auto hp_key =
        hkdf_expand_label(digest, secret, labels.value().hp, parameters.value().hp_key_length);
    if (!hp_key.has_value()) {
        return packet_key_failure(hp_key.error().code);
    }

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
    const auto labels = packet_protection_labels_for_version(secret.quic_version);
    if (!labels.has_value()) {
        return crypto_failure(labels.error().code);
    }

    auto hp_key = hkdf_expand_label(parameters.value().digest(), secret.secret, labels.value().hp,
                                    parameters.value().hp_key_length);
    if (!hp_key.has_value()) {
        return crypto_failure(hp_key.error().code);
    }

    return hp_key;
}

struct OpenAeadRequest {
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const std::byte> ciphertext;
};

struct SealCipherChunksRequest {
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const PlaintextChunk> plaintext_chunks;
    std::span<std::byte> ciphertext;
};

struct SealCipherRequest {
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const std::byte> plaintext;
    std::span<std::byte> ciphertext;
};

struct SealAeadChunksRequest {
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const PlaintextChunk> plaintext_chunks;
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
    if (encoded_retry_packet.value().size() < aead_tag_length) {
        return CodecResult<std::vector<std::byte>>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);
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

CodecResult<std::size_t> seal_cipher_chunks_into(const EVP_CIPHER *cipher,
                                                 const SealCipherChunksRequest &request) {
    const auto plaintext_length = total_plaintext_length(request.plaintext_chunks);
    if (!plaintext_length.has_value()) {
        return plaintext_length;
    }
    const auto invalid_lengths =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_length_guard) |
        !fits_openssl_int(request.nonce.size()) |
        !fits_openssl_int(request.associated_data.size()) |
        !fits_openssl_int(plaintext_length.value());
    if (invalid_lengths) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }
    if (request.ciphertext.size() < plaintext_length.value() + aead_tag_length) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    auto *context = acquire_cipher_context(seal_cipher_context_cache(),
                                           PacketCryptoFaultPoint::seal_context_new);
    if (context == nullptr) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    bool init_failed = consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_init);
    init_failed |= EVP_EncryptInit_ex(context, cipher, nullptr, nullptr, nullptr) <= 0;
    init_failed |= EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
                                       static_cast<int>(request.nonce.size()), nullptr) <= 0;
    init_failed |= EVP_EncryptInit_ex(context, nullptr, nullptr, openssl_data(request.key),
                                      openssl_data(request.nonce)) <= 0;
    if (init_failed) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    int output_length = 0;
    if (!request.associated_data.empty()) {
        const auto aad_failed =
            consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_aad_update) |
            (EVP_EncryptUpdate(context, nullptr, &output_length,
                               openssl_data(request.associated_data),
                               static_cast<int>(request.associated_data.size())) <= 0);
        if (aad_failed) {
            return CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
        }
    }

    auto payload_output = request.ciphertext.first(request.ciphertext.size() - aead_tag_length);
    std::size_t produced_total = 0;
    for (const auto &chunk : request.plaintext_chunks) {
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
            return CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
        }
        produced_total += static_cast<std::size_t>(produced_length);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_native_seal)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    int final_length = 0;
    const auto final_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_final) |
        (EVP_EncryptFinal_ex(context, openssl_data(payload_output.subspan(produced_total)),
                             &final_length) <= 0);
    if (final_failed) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    const auto total_ciphertext_length = produced_total + static_cast<std::size_t>(final_length);
    if (total_ciphertext_length + aead_tag_length > request.ciphertext.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    std::array<std::byte, aead_tag_length> tag{};
    const auto get_tag_failed =
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_get_tag) |
        (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tag.size()),
                             openssl_data(std::span<std::byte>{tag})) <= 0);
    if (get_tag_failed) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    const auto tag_output = request.ciphertext.subspan(total_ciphertext_length, tag.size());
    std::copy(tag.begin(), tag.end(), tag_output.begin());
    return CodecResult<std::size_t>::success(total_ciphertext_length + tag.size());
}

CodecResult<std::vector<std::byte>>
coalesce_plaintext_chunks(std::span<const PlaintextChunk> plaintext_chunks) {
    const auto plaintext_length = total_plaintext_length(plaintext_chunks);
    if (!plaintext_length.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(plaintext_length.error().code, 0);
    }

    std::vector<std::byte> plaintext(plaintext_length.value());
    auto *cursor = plaintext.data();
    for (const auto &chunk : plaintext_chunks) {
        std::copy(chunk.bytes.begin(), chunk.bytes.end(), cursor);
        cursor += chunk.bytes.size();
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(plaintext));
}

CodecResult<std::size_t> seal_cipher_into(const EVP_CIPHER *cipher,
                                          const SealCipherRequest &request) {
    const std::array chunks{
        PlaintextChunk{
            .bytes = request.plaintext,
        },
    };
    return seal_cipher_chunks_into(cipher, SealCipherChunksRequest{
                                               .key = request.key,
                                               .nonce = request.nonce,
                                               .associated_data = request.associated_data,
                                               .plaintext_chunks = chunks,
                                               .ciphertext = request.ciphertext,
                                           });
}

CodecResult<std::size_t> seal_aead_chunks_into(const EVP_AEAD *aead,
                                               const SealAeadChunksRequest &request) {
    const auto plaintext = coalesce_plaintext_chunks(request.plaintext_chunks);
    if (!plaintext.has_value()) {
        return CodecResult<std::size_t>::failure(plaintext.error().code, 0);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_length_guard)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }
    if (request.ciphertext.size() < plaintext.value().size() + aead_tag_length) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_init)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    auto *context = acquire_aead_context(seal_aead_context_cache(), aead, request.key,
                                         PacketCryptoFaultPoint::seal_context_new);
    if (context == nullptr) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }
    if (!request.associated_data.empty() &&
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_aad_update)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_payload_update) ||
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_native_seal) ||
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_final) ||
        consume_packet_crypto_fault(PacketCryptoFaultPoint::seal_get_tag)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    std::size_t output_length = 0;
    if (EVP_AEAD_CTX_seal(context, openssl_data(request.ciphertext), &output_length,
                          request.ciphertext.size(), openssl_data(request.nonce),
                          request.nonce.size(), openssl_data(std::span{plaintext.value()}),
                          plaintext.value().size(), openssl_data(request.associated_data),
                          request.associated_data.size()) != 1) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    return CodecResult<std::size_t>::success(output_length);
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

    auto *context = acquire_aead_context(open_aead_context_cache(), aead, request.key,
                                         PacketCryptoFaultPoint::open_context_new);
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
    if (EVP_AEAD_CTX_open(context, openssl_data(std::span{plaintext}), &output_length,
                          plaintext.size(), openssl_data(request.nonce), request.nonce.size(),
                          openssl_data(request.ciphertext), request.ciphertext.size(),
                          openssl_data(request.associated_data),
                          request.associated_data.size()) != 1) {
        return crypto_failure(CodecErrorCode::packet_decryption_failed);
    }

    plaintext.resize(output_length);
    return CodecResult<std::vector<std::byte>>::success(std::move(plaintext));
}

const EVP_CIPHER *packet_cipher_for_suite(CipherSuite cipher_suite) {
    switch (cipher_suite) {
    case CipherSuite::tls_aes_128_gcm_sha256:
        return EVP_aes_128_gcm();
    case CipherSuite::tls_aes_256_gcm_sha384:
        return EVP_aes_256_gcm();
    case CipherSuite::tls_chacha20_poly1305_sha256:
        return nullptr;
    }

    return nullptr;
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

CodecResult<PacketProtectionKeys> expand_traffic_secret(const TrafficSecret &secret) {
    if (secret.cached_packet_protection_keys.has_value() &&
        secret.cached_packet_protection_inputs.has_value()) {
        const auto &cached_inputs = secret.cached_packet_protection_inputs.value();
        if (cached_inputs.secret == secret.secret &&
            cached_inputs.header_protection_key == secret.header_protection_key &&
            cached_inputs.quic_version == secret.quic_version) {
            return CodecResult<PacketProtectionKeys>::success(
                secret.cached_packet_protection_keys.value());
        }
    }

    auto keys = expand_secret(secret.cipher_suite, secret.secret, secret.quic_version);
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
    secret.cached_packet_protection_keys = expanded;
    secret.cached_packet_protection_inputs = TrafficSecretCacheInputs{
        .secret = secret.secret,
        .header_protection_key = secret.header_protection_key,
        .quic_version = secret.quic_version,
    };
    return CodecResult<PacketProtectionKeys>::success(secret.cached_packet_protection_keys.value());
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
    const auto secret_length = static_cast<std::size_t>(EVP_MD_size(digest));
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

CodecResult<std::vector<std::byte>> make_packet_protection_nonce(PacketProtectionNonceInput input) {
    auto nonce = std::vector<std::byte>(input.iv.begin(), input.iv.end());
    auto packet_number_value = input.packet_number;

    for (std::size_t index = 0; index < sizeof(input.packet_number) && index < nonce.size();
         ++index) {
        const auto nonce_index = nonce.size() - 1 - index;
        nonce[nonce_index] ^= static_cast<std::byte>(packet_number_value & 0xff);
        packet_number_value >>= 8;
    }

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
    if (integrity_tag_ciphertext.value().size() != aead_tag_length) {
        return CodecResult<std::array<std::byte, 16>>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);
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
    if (!parameters.has_value()) {
        return CodecResult<std::size_t>::failure(parameters.error().code, 0);
    }
    if (input.key.size() != parameters.value().key_length ||
        input.nonce.size() != parameters.value().iv_length) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    if (const auto *cipher = packet_cipher_for_suite(input.cipher_suite); cipher != nullptr) {
        return seal_cipher_into(cipher, SealCipherRequest{
                                            .key = input.key,
                                            .nonce = input.nonce,
                                            .associated_data = input.associated_data,
                                            .plaintext = input.plaintext,
                                            .ciphertext = input.ciphertext,
                                        });
    }

    if (input.cipher_suite == CipherSuite::tls_chacha20_poly1305_sha256) {
        const std::array chunks{
            PlaintextChunk{
                .bytes = input.plaintext,
            },
        };
        return seal_aead_chunks_into(EVP_aead_chacha20_poly1305(),
                                     SealAeadChunksRequest{
                                         .key = input.key,
                                         .nonce = input.nonce,
                                         .associated_data = input.associated_data,
                                         .plaintext_chunks = chunks,
                                         .ciphertext = input.ciphertext,
                                     });
    }

    return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_cipher_suite, 0);
}

CodecResult<std::size_t> seal_payload_chunks_into(const SealPayloadChunksIntoInput &input) {
    const auto parameters = cipher_suite_parameters(input.cipher_suite);
    if (!parameters.has_value()) {
        return CodecResult<std::size_t>::failure(parameters.error().code, 0);
    }
    if (input.key.size() != parameters.value().key_length ||
        input.nonce.size() != parameters.value().iv_length) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);
    }

    if (const auto *cipher = packet_cipher_for_suite(input.cipher_suite); cipher != nullptr) {
        return seal_cipher_chunks_into(cipher, SealCipherChunksRequest{
                                                   .key = input.key,
                                                   .nonce = input.nonce,
                                                   .associated_data = input.associated_data,
                                                   .plaintext_chunks = input.plaintext_chunks,
                                                   .ciphertext = input.ciphertext,
                                               });
    }

    if (input.cipher_suite == CipherSuite::tls_chacha20_poly1305_sha256) {
        return seal_aead_chunks_into(EVP_aead_chacha20_poly1305(),
                                     SealAeadChunksRequest{
                                         .key = input.key,
                                         .nonce = input.nonce,
                                         .associated_data = input.associated_data,
                                         .plaintext_chunks = input.plaintext_chunks,
                                         .ciphertext = input.ciphertext,
                                     });
    }

    return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_cipher_suite, 0);
}

CodecResult<std::vector<std::byte>> seal_payload(const SealPayloadInput &input) {
    std::vector<std::byte> ciphertext(input.plaintext.size() + aead_tag_length);
    const auto written = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = input.cipher_suite,
        .key = input.key,
        .nonce = input.nonce,
        .associated_data = input.associated_data,
        .plaintext = input.plaintext,
        .ciphertext = std::span<std::byte>{ciphertext},
    });
    if (!written.has_value()) {
        return crypto_failure(written.error().code);
    }

    ciphertext.resize(written.value());
    return CodecResult<std::vector<std::byte>>::success(std::move(ciphertext));
}

CodecResult<std::vector<std::byte>> open_payload(const OpenPayloadInput &input) {
    const auto parameters = cipher_suite_parameters(input.cipher_suite);
    if (!parameters.has_value()) {
        return crypto_failure(parameters.error().code);
    }
    if (input.key.size() != parameters.value().key_length ||
        input.nonce.size() != parameters.value().iv_length) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }

    static constexpr std::array<const EVP_AEAD *(*)(), 3> kAeadCiphers{
        &EVP_aead_aes_128_gcm,
        &EVP_aead_aes_256_gcm,
        &EVP_aead_chacha20_poly1305,
    };
    const auto aead = kAeadCiphers[static_cast<std::size_t>(input.cipher_suite)]();

    return open_aead(aead, OpenAeadRequest{
                               .key = input.key,
                               .nonce = input.nonce,
                               .associated_data = input.associated_data,
                               .ciphertext = input.ciphertext,
                           });
}

CodecResult<std::vector<std::byte>> make_header_protection_mask(CipherSuite cipher_suite,
                                                                HeaderProtectionMaskInput input) {
    const auto parameters = cipher_suite_parameters(cipher_suite);
    if (!parameters.has_value()) {
        return crypto_failure(parameters.error().code);
    }
    if (input.hp_key.size() != parameters.value().hp_key_length) {
        return crypto_failure(CodecErrorCode::invalid_packet_protection_state);
    }
    if (input.sample.size() < header_protection_sample_length) {
        return crypto_failure(CodecErrorCode::header_protection_sample_too_short);
    }
    if (consume_packet_crypto_fault(PacketCryptoFaultPoint::header_protection_context_new)) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    const auto sample_prefix = input.sample.first(header_protection_sample_length);

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
                         openssl_data(input.hp_key), openssl_data(nonce), counter);

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

    auto *context =
        acquire_cipher_context(header_protection_context_cache(),
                               PacketCryptoFaultPoint::header_protection_aes_context_new);
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
    const auto init_failed = header_protection_aes_init(context, cipher, input.hp_key) <= 0 ||
                             header_protection_aes_set_padding(context) <= 0 ||
                             header_protection_aes_update(context, std::span{block},
                                                          &produced_length, sample_prefix) <= 0;
    if (init_failed) {
        return crypto_failure(CodecErrorCode::header_protection_failed);
    }

    int final_length = 0;
    const auto final_failed =
        header_protection_aes_final(
            context, std::span{block}.subspan(static_cast<std::size_t>(produced_length)),
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
