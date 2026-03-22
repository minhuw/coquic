#include "src/quic/tls_adapter.h"
#include "src/quic/tls_adapter_quictls_test_hooks.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#if defined(OPENSSL_IS_BORINGSSL) && !defined(OSSL_ENCRYPTION_LEVEL)
using OSSL_ENCRYPTION_LEVEL = ssl_encryption_level_t;
#endif

namespace {

using coquic::quic::AvailableTrafficSecret;
using coquic::quic::CipherSuite;
using coquic::quic::CodecError;
using coquic::quic::CodecErrorCode;
using coquic::quic::CodecResult;
using coquic::quic::EncryptionLevel;
using coquic::quic::EndpointRole;
using coquic::quic::TlsAdapter;
using coquic::quic::TlsAdapterConfig;
using coquic::quic::TrafficSecret;
using coquic::quic::test::TlsAdapterFaultPoint;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

constexpr std::uint16_t tls_aes_128_gcm_sha256_id = 0x1301;
constexpr std::uint16_t tls_aes_256_gcm_sha384_id = 0x1302;
constexpr std::uint16_t tls_chacha20_poly1305_sha256_id = 0x1303;

struct TlsAdapterFaultState {
    std::optional<TlsAdapterFaultPoint> fault_point;
    std::size_t occurrence = 0;
};

TlsAdapterFaultState &tls_adapter_fault_state() {
    static thread_local TlsAdapterFaultState state;
    return state;
}

void set_tls_adapter_fault_state(std::optional<TlsAdapterFaultPoint> fault_point,
                                 std::size_t occurrence) {
    tls_adapter_fault_state() = TlsAdapterFaultState{
        .fault_point = fault_point,
        .occurrence = occurrence,
    };
}

COQUIC_NO_PROFILE bool consume_tls_adapter_fault(TlsAdapterFaultPoint fault_point) {
    auto &state = tls_adapter_fault_state();
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

CodecResult<bool> tls_failure() {
    return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
}

EndpointRole opposite_role(EndpointRole role) {
    return role == EndpointRole::client ? EndpointRole::server : EndpointRole::client;
}

std::size_t level_index(EncryptionLevel level) {
    return static_cast<std::size_t>(level);
}

std::span<const std::byte> as_bytes(const uint8_t *data, std::size_t size) {
    return std::span(reinterpret_cast<const std::byte *>(data), size);
}

const uint8_t *as_tls_bytes(std::span<const std::byte> bytes) {
    static constexpr uint8_t empty = 0;
    if (bytes.empty()) {
        return &empty;
    }

    return reinterpret_cast<const uint8_t *>(bytes.data());
}

std::optional<EncryptionLevel> to_encryption_level_value(int level_value) {
    switch (level_value) {
    case ssl_encryption_initial:
        return EncryptionLevel::initial;
    case ssl_encryption_handshake:
        return EncryptionLevel::handshake;
    case ssl_encryption_application:
        return EncryptionLevel::application;
    default:
        return std::nullopt;
    }
}

std::optional<EncryptionLevel> to_encryption_level(OSSL_ENCRYPTION_LEVEL level) {
    return to_encryption_level_value(static_cast<int>(level));
}

OSSL_ENCRYPTION_LEVEL to_ossl_encryption_level_value(std::uint8_t level_value) {
    switch (level_value) {
    case static_cast<std::uint8_t>(EncryptionLevel::initial):
        return ssl_encryption_initial;
    case static_cast<std::uint8_t>(EncryptionLevel::handshake):
        return ssl_encryption_handshake;
    case static_cast<std::uint8_t>(EncryptionLevel::application):
        return ssl_encryption_application;
    default:
        return ssl_encryption_initial;
    }
}

OSSL_ENCRYPTION_LEVEL to_ossl_encryption_level(EncryptionLevel level) {
    return to_ossl_encryption_level_value(static_cast<std::uint8_t>(level));
}

const SSL_METHOD *tls_method_for_role(EndpointRole role) {
    return role == EndpointRole::client ? TLS_client_method() : TLS_server_method();
}

COQUIC_NO_PROFILE SSL_CTX *new_ssl_ctx(EndpointRole role) {
    if (consume_tls_adapter_fault(TlsAdapterFaultPoint::initialize_ctx_new)) {
        return nullptr;
    }

    return SSL_CTX_new(tls_method_for_role(role));
}

CodecResult<CipherSuite>
cipher_suite_for_protocol_ids(std::optional<std::uint16_t> pending_protocol_id,
                              std::optional<std::uint16_t> current_protocol_id) {
    const auto protocol_id =
        pending_protocol_id.has_value() ? pending_protocol_id : current_protocol_id;
    if (!protocol_id.has_value()) {
        return CodecResult<CipherSuite>::failure(CodecErrorCode::unsupported_cipher_suite, 0);
    }

    switch (protocol_id.value()) {
    case tls_aes_128_gcm_sha256_id:
        return CodecResult<CipherSuite>::success(CipherSuite::tls_aes_128_gcm_sha256);
    case tls_aes_256_gcm_sha384_id:
        return CodecResult<CipherSuite>::success(CipherSuite::tls_aes_256_gcm_sha384);
    case tls_chacha20_poly1305_sha256_id:
        return CodecResult<CipherSuite>::success(CipherSuite::tls_chacha20_poly1305_sha256);
    default:
        return CodecResult<CipherSuite>::failure(CodecErrorCode::unsupported_cipher_suite, 0);
    }
}

COQUIC_NO_PROFILE CodecResult<CipherSuite> cipher_suite_for_ssl(const SSL *ssl) {
    std::optional<std::uint16_t> pending_protocol_id;
    if (const SSL_CIPHER *cipher = SSL_get_pending_cipher(ssl); cipher != nullptr) {
        pending_protocol_id = SSL_CIPHER_get_protocol_id(cipher);
    }

    std::optional<std::uint16_t> current_protocol_id;
    if (const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl); cipher != nullptr) {
        current_protocol_id = SSL_CIPHER_get_protocol_id(cipher);
    }

    return cipher_suite_for_protocol_ids(pending_protocol_id, current_protocol_id);
}

COQUIC_NO_PROFILE CodecResult<CipherSuite> cipher_suite_for_cipher(const SSL_CIPHER *cipher) {
    if (cipher == nullptr) {
        return CodecResult<CipherSuite>::failure(CodecErrorCode::unsupported_cipher_suite, 0);
    }

    return cipher_suite_for_protocol_ids(SSL_CIPHER_get_protocol_id(cipher), std::nullopt);
}

COQUIC_NO_PROFILE bool provide_quic_data_failed(SSL *ssl, EncryptionLevel level,
                                                std::span<const std::byte> bytes) {
    return consume_tls_adapter_fault(TlsAdapterFaultPoint::provide_quic_data) ||
           SSL_provide_quic_data(ssl, to_ossl_encryption_level(level), as_tls_bytes(bytes),
                                 bytes.size()) != 1;
}

COQUIC_NO_PROFILE bool post_handshake_failed(SSL *ssl) {
    return consume_tls_adapter_fault(TlsAdapterFaultPoint::provide_post_handshake) ||
           SSL_process_quic_post_handshake(ssl) != 1;
}

COQUIC_NO_PROFILE bool configure_ctx_failed(SSL_CTX *ctx, const SSL_QUIC_METHOD *quic_method) {
    return consume_tls_adapter_fault(TlsAdapterFaultPoint::initialize_ctx_config) ||
           SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
           SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1 ||
           SSL_CTX_set_quic_method(ctx, quic_method) != 1;
}

COQUIC_NO_PROFILE bool
tls13_cipher_suites_failed(std::span<const CipherSuite> allowed_tls_cipher_suites) {
    return !allowed_tls_cipher_suites.empty();
}

COQUIC_NO_PROFILE bool verify_paths_failed(SSL_CTX *ctx) {
    return consume_tls_adapter_fault(TlsAdapterFaultPoint::initialize_verify_paths) ||
           SSL_CTX_set_default_verify_paths(ctx) != 1;
}

COQUIC_NO_PROFILE bool verify_paths_init_failed(bool verify_peer, SSL_CTX *ctx) {
    return verify_peer && verify_paths_failed(ctx);
}

COQUIC_NO_PROFILE SSL *new_ssl(SSL_CTX *ctx) {
    if (consume_tls_adapter_fault(TlsAdapterFaultPoint::initialize_ssl_new)) {
        return nullptr;
    }

    return SSL_new(ctx);
}

COQUIC_NO_PROFILE bool ssl_quic_method_failed(SSL *ssl, const SSL_QUIC_METHOD *quic_method) {
    static_cast<void>(ssl);
    static_cast<void>(quic_method);
    return consume_tls_adapter_fault(TlsAdapterFaultPoint::initialize_ssl_set_quic_method);
}

COQUIC_NO_PROFILE bool server_name_failed(SSL *ssl, const TlsAdapterConfig &config) {
    return !config.server_name.empty() && config.role == EndpointRole::client &&
           (consume_tls_adapter_fault(TlsAdapterFaultPoint::initialize_server_name) ||
            SSL_set_tlsext_host_name(ssl, config.server_name.c_str()) != 1);
}

COQUIC_NO_PROFILE bool transport_params_failed(SSL *ssl,
                                               std::span<const std::byte> transport_params) {
    return consume_tls_adapter_fault(TlsAdapterFaultPoint::initialize_transport_params) ||
           SSL_set_quic_transport_params(ssl, as_tls_bytes(transport_params),
                                         transport_params.size()) != 1;
}

bool application_protocol_valid(std::string_view application_protocol) {
    return !application_protocol.empty() && application_protocol.size() <= UINT8_MAX;
}

std::vector<uint8_t> encode_application_protocol_list(std::string_view application_protocol) {
    if (!application_protocol_valid(application_protocol)) {
        return {};
    }

    std::vector<uint8_t> encoded;
    encoded.reserve(application_protocol.size() + 1);
    encoded.push_back(static_cast<uint8_t>(application_protocol.size()));
    encoded.insert(encoded.end(), application_protocol.begin(), application_protocol.end());
    return encoded;
}

bool set_alpn_protos_failed(SSL *ssl, const std::vector<uint8_t> &encoded) {
    return consume_tls_adapter_fault(TlsAdapterFaultPoint::initialize_client_alpn) ||
           (consume_tls_adapter_fault(TlsAdapterFaultPoint::initialize_client_alpn_set_protos)
                ? -1
                : SSL_set_alpn_protos(ssl, encoded.data(), encoded.size())) != 0;
}

bool client_alpn_failed(SSL *ssl, std::string_view application_protocol) {
    const auto encoded = encode_application_protocol_list(application_protocol);
    return encoded.empty() || set_alpn_protos_failed(ssl, encoded);
}

bool client_offered_application_protocol(std::span<const uint8_t> offered,
                                         std::string_view application_protocol) {
    std::size_t offset = 0;
    while (offset < offered.size()) {
        const auto protocol_length = offered[offset];
        ++offset;
        if (protocol_length == 0 || offset + protocol_length > offered.size()) {
            return false;
        }

        const auto candidate = std::string_view(
            reinterpret_cast<const char *>(offered.data() + offset), protocol_length);
        if (candidate == application_protocol) {
            return true;
        }

        offset += protocol_length;
    }

    return false;
}

COQUIC_NO_PROFILE bool install_identity_failed(SSL_CTX *ctx, X509 *certificate,
                                               EVP_PKEY *private_key) {
    return consume_tls_adapter_fault(TlsAdapterFaultPoint::load_identity_use_certificate) ||
           SSL_CTX_use_certificate(ctx, certificate) != 1 ||
           SSL_CTX_use_PrivateKey(ctx, private_key) != 1 || SSL_CTX_check_private_key(ctx) != 1;
}

bool should_retry_handshake(bool handshake_fault, int error) {
    return !handshake_fault && (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
}

bool handshake_progressed(bool pending_changed, bool secrets_changed,
                          bool peer_transport_parameters_changed) {
    return pending_changed || secrets_changed || peer_transport_parameters_changed;
}

COQUIC_NO_PROFILE bool should_process_post_handshake(EncryptionLevel level,
                                                     bool handshake_complete) {
    return level == EncryptionLevel::application && handshake_complete;
}

} // namespace

namespace coquic::quic {

class TlsAdapter::Impl {
  public:
    friend class coquic::quic::test::TlsAdapterTestPeer;

    explicit Impl(TlsAdapterConfig config)
        : config_(std::move(config)), ctx_(nullptr, &SSL_CTX_free), ssl_(nullptr, &SSL_free) {
        initialize();
    }

    CodecResult<bool> start() {
        return drive_handshake();
    }

    CodecResult<bool> provide(EncryptionLevel level, std::span<const std::byte> bytes) {
        if (sticky_error_.has_value()) {
            return tls_failure();
        }
        if (ssl_ == nullptr) {
            return tls_failure();
        }

        ERR_clear_error();
        if (provide_quic_data_failed(ssl_.get(), level, bytes)) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return tls_failure();
        }

        if (should_process_post_handshake(level, SSL_is_init_finished(ssl_.get()) == 1)) {
            ERR_clear_error();
            if (post_handshake_failed(ssl_.get())) {
                sticky_error_ = CodecError{
                    .code = CodecErrorCode::invalid_packet_protection_state,
                    .offset = 0,
                };
                return tls_failure();
            }
            capture_peer_transport_parameters();
            return CodecResult<bool>::success(true);
        }

        return drive_handshake();
    }

    void poll() {
        if (sticky_error_.has_value()) {
            return;
        }

        drive_handshake();
    }

    std::vector<std::byte> take_pending(EncryptionLevel level) {
        auto &bytes = pending_[level_index(level)];
        auto result = std::move(bytes);
        bytes.clear();
        return result;
    }

    std::vector<AvailableTrafficSecret> take_available_secrets() {
        auto result = std::move(available_secrets_);
        available_secrets_.clear();
        return result;
    }

    const std::optional<std::vector<std::byte>> &peer_transport_parameters() const {
        return peer_transport_parameters_;
    }

    bool handshake_complete() const {
        if (ssl_ == nullptr) {
            return false;
        }

        return SSL_is_init_finished(ssl_.get()) == 1;
    }

    static int set_read_secret(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, const SSL_CIPHER *cipher,
                               const uint8_t *read_secret, size_t secret_len) {
        auto *impl = static_cast<Impl *>(SSL_get_app_data(ssl));
        if (impl == nullptr) {
            return 0;
        }

        return impl->on_set_secret(level, opposite_role(impl->config_.role), cipher, read_secret,
                                   secret_len);
    }

    static int set_write_secret(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, const SSL_CIPHER *cipher,
                                const uint8_t *write_secret, size_t secret_len) {
        auto *impl = static_cast<Impl *>(SSL_get_app_data(ssl));
        if (impl == nullptr) {
            return 0;
        }

        return impl->on_set_secret(level, impl->config_.role, cipher, write_secret, secret_len);
    }

    static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, const uint8_t *data,
                                  size_t len) {
        auto *impl = static_cast<Impl *>(SSL_get_app_data(ssl));
        if (impl == nullptr) {
            return 0;
        }

        return impl->on_add_handshake_data(level, data, len);
    }

    static int flush_flight(SSL *ssl) {
        auto *impl = static_cast<Impl *>(SSL_get_app_data(ssl));
        if (impl == nullptr) {
            return 0;
        }

        return impl->on_flush_flight();
    }

    static int send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert) {
        auto *impl = static_cast<Impl *>(SSL_get_app_data(ssl));
        if (impl == nullptr) {
            return 0;
        }

        return impl->on_send_alert(level, alert);
    }

    static int select_application_protocol(SSL *, const uint8_t **out, uint8_t *out_len,
                                           const uint8_t *in, unsigned in_len, void *arg) {
        auto *impl = static_cast<Impl *>(arg);
        if (impl == nullptr || out == nullptr || out_len == nullptr ||
            !application_protocol_valid(impl->config_.application_protocol) ||
            !client_offered_application_protocol(std::span(in, in_len),
                                                 impl->config_.application_protocol)) {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        *out = reinterpret_cast<const uint8_t *>(impl->config_.application_protocol.data());
        *out_len = static_cast<uint8_t>(impl->config_.application_protocol.size());
        return SSL_TLSEXT_ERR_OK;
    }

  private:
    void initialize() {
        ERR_clear_error();
        ctx_.reset(new_ssl_ctx(config_.role));
        if (ctx_ == nullptr) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (configure_ctx_failed(ctx_.get(), &kQuicMethod)) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (tls13_cipher_suites_failed(config_.allowed_tls_cipher_suites)) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        SSL_CTX_set_verify(ctx_.get(), config_.verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                           nullptr);
        if (verify_paths_init_failed(config_.verify_peer, ctx_.get())) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (!load_identity()) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (!application_protocol_valid(config_.application_protocol)) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (config_.role == EndpointRole::server) {
            SSL_CTX_set_alpn_select_cb(ctx_.get(), &Impl::select_application_protocol, this);
        }

        ssl_.reset(new_ssl(ctx_.get()));
        if (ssl_ == nullptr) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (config_.role == EndpointRole::client &&
            client_alpn_failed(ssl_.get(), config_.application_protocol)) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        SSL_set_app_data(ssl_.get(), this);
        if (ssl_quic_method_failed(ssl_.get(), &kQuicMethod)) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (server_name_failed(ssl_.get(), config_)) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (transport_params_failed(ssl_.get(), config_.local_transport_parameters)) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (config_.role == EndpointRole::client) {
            SSL_set_connect_state(ssl_.get());
        } else {
            SSL_set_accept_state(ssl_.get());
        }
    }

    bool load_identity() {
        if (config_.role != EndpointRole::server) {
            return true;
        }
        if (!config_.identity.has_value()) {
            return false;
        }

        BioPtr cert_bio(
            consume_tls_adapter_fault(TlsAdapterFaultPoint::load_identity_cert_bio)
                ? nullptr
                : BIO_new_mem_buf(config_.identity->certificate_pem.data(),
                                  static_cast<int>(config_.identity->certificate_pem.size())),
            &BIO_free);
        if (cert_bio == nullptr) {
            return false;
        }

        X509Ptr certificate(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr),
                            &X509_free);
        if (certificate == nullptr) {
            return false;
        }

        BioPtr key_bio(
            consume_tls_adapter_fault(TlsAdapterFaultPoint::load_identity_key_bio)
                ? nullptr
                : BIO_new_mem_buf(config_.identity->private_key_pem.data(),
                                  static_cast<int>(config_.identity->private_key_pem.size())),
            &BIO_free);
        if (key_bio == nullptr) {
            return false;
        }

        EvpPkeyPtr private_key(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr),
                               &EVP_PKEY_free);
        if (private_key == nullptr) {
            return false;
        }

        return !install_identity_failed(ctx_.get(), certificate.get(), private_key.get());
    }

    CodecResult<bool> drive_handshake() {
        if (sticky_error_.has_value()) {
            return tls_failure();
        }
        if (ssl_ == nullptr) {
            return tls_failure();
        }

        while (true) {
            const auto pending_before = total_pending_bytes();
            const auto secrets_before = available_secrets_.size();
            const auto had_peer_transport_parameters = peer_transport_parameters_.has_value();

            ERR_clear_error();
            const int result = SSL_do_handshake(ssl_.get());
            capture_peer_transport_parameters();

            if (result == 1) {
                return CodecResult<bool>::success(true);
            }

            const bool handshake_fault =
                consume_tls_adapter_fault(TlsAdapterFaultPoint::drive_handshake);
            const int error = SSL_get_error(ssl_.get(), result);
            if (should_retry_handshake(handshake_fault, error)) {
                const bool pending_changed = total_pending_bytes() != pending_before;
                const bool secrets_changed = available_secrets_.size() != secrets_before;
                const bool peer_transport_parameters_changed =
                    peer_transport_parameters_.has_value() != had_peer_transport_parameters;
                const bool progressed = handshake_progressed(pending_changed, secrets_changed,
                                                             peer_transport_parameters_changed);
                if (!progressed) {
                    return CodecResult<bool>::success(true);
                }
                continue;
            }

            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return tls_failure();
        }
    }

    int on_set_secret(OSSL_ENCRYPTION_LEVEL level, EndpointRole sender, const SSL_CIPHER *cipher,
                      const uint8_t *secret, size_t secret_len) {
        const auto mapped_level = to_encryption_level(level);
        if (!mapped_level.has_value()) {
            return 1;
        }

        if (secret == nullptr) {
            return 1;
        }

        const auto cipher_suite =
            consume_tls_adapter_fault(
                TlsAdapterFaultPoint::set_encryption_secrets_unsupported_cipher)
                ? CodecResult<CipherSuite>::failure(CodecErrorCode::unsupported_cipher_suite, 0)
                : cipher_suite_for_cipher(cipher);
        if (!cipher_suite.has_value()) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::unsupported_cipher_suite, .offset = 0};
            return 0;
        }

        available_secrets_.push_back(AvailableTrafficSecret{
            .level = mapped_level.value(),
            .sender = sender,
            .secret =
                TrafficSecret{
                    .cipher_suite = cipher_suite.value(),
                    .secret = std::vector(as_bytes(secret, secret_len).begin(),
                                          as_bytes(secret, secret_len).end()),
                },
        });

        return 1;
    }

    int on_add_handshake_data(OSSL_ENCRYPTION_LEVEL level, const uint8_t *data, size_t len) {
        const auto mapped_level = to_encryption_level(level);
        if (!mapped_level.has_value()) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return 0;
        }

        auto &pending = pending_[level_index(mapped_level.value())];
        const auto bytes = as_bytes(data, len);
        pending.insert(pending.end(), bytes.begin(), bytes.end());
        return 1;
    }

    int on_flush_flight() {
        return 1;
    }

    int on_send_alert(OSSL_ENCRYPTION_LEVEL, uint8_t) {
        sticky_error_ =
            CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
        return 0;
    }

    void capture_peer_transport_parameters() {
        if (ssl_ == nullptr || peer_transport_parameters_.has_value()) {
            return;
        }

        const uint8_t *params = nullptr;
        size_t params_len = 0;
        SSL_get_peer_quic_transport_params(ssl_.get(), &params, &params_len);
        if (params == nullptr) {
            return;
        }

        const auto bytes = as_bytes(params, params_len);
        peer_transport_parameters_ = std::vector<std::byte>(bytes.begin(), bytes.end());
    }

    std::size_t total_pending_bytes() const {
        std::size_t total = 0;
        for (const auto &bytes : pending_) {
            total += bytes.size();
        }
        return total;
    }

    const SSL_CIPHER *pending_or_current_cipher() const {
        if (ssl_ == nullptr) {
            return nullptr;
        }

        if (const SSL_CIPHER *cipher = SSL_get_pending_cipher(ssl_.get()); cipher != nullptr) {
            return cipher;
        }

        return SSL_get_current_cipher(ssl_.get());
    }

    static inline const SSL_QUIC_METHOD kQuicMethod{
        &Impl::set_read_secret, &Impl::set_write_secret, &Impl::add_handshake_data,
        &Impl::flush_flight,    &Impl::send_alert,
    };

    TlsAdapterConfig config_;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx_;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl_;
    std::array<std::vector<std::byte>, 3> pending_;
    std::vector<AvailableTrafficSecret> available_secrets_;
    std::optional<std::vector<std::byte>> peer_transport_parameters_;
    std::optional<CodecError> sticky_error_;
};

TlsAdapter::TlsAdapter(TlsAdapterConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {
}

TlsAdapter::~TlsAdapter() = default;

TlsAdapter::TlsAdapter(TlsAdapter &&) noexcept = default;

TlsAdapter &TlsAdapter::operator=(TlsAdapter &&) noexcept = default;

CodecResult<bool> TlsAdapter::start() {
    return impl_->start();
}

CodecResult<bool> TlsAdapter::provide(EncryptionLevel level, std::span<const std::byte> bytes) {
    return impl_->provide(level, bytes);
}

void TlsAdapter::poll() {
    impl_->poll();
}

std::vector<std::byte> TlsAdapter::take_pending(EncryptionLevel level) {
    return impl_->take_pending(level);
}

std::vector<AvailableTrafficSecret> TlsAdapter::take_available_secrets() {
    return impl_->take_available_secrets();
}

const std::optional<std::vector<std::byte>> &TlsAdapter::peer_transport_parameters() const {
    return impl_->peer_transport_parameters();
}

bool TlsAdapter::handshake_complete() const {
    return impl_->handshake_complete();
}

namespace test {

ScopedTlsAdapterFaultInjector::ScopedTlsAdapterFaultInjector(TlsAdapterFaultPoint fault_point,
                                                             std::size_t occurrence)
    : previous_fault_point_(tls_adapter_fault_state().fault_point),
      previous_occurrence_(tls_adapter_fault_state().occurrence) {
    set_tls_adapter_fault_state(fault_point, occurrence);
}

ScopedTlsAdapterFaultInjector::~ScopedTlsAdapterFaultInjector() {
    set_tls_adapter_fault_state(previous_fault_point_, previous_occurrence_);
}

const uint8_t *TlsAdapterTestPeer::as_tls_bytes(std::span<const std::byte> bytes) {
    return ::as_tls_bytes(bytes);
}

std::optional<EncryptionLevel>
TlsAdapterTestPeer::to_encryption_level(OSSL_ENCRYPTION_LEVEL level) {
    return ::to_encryption_level(level);
}

std::optional<EncryptionLevel> TlsAdapterTestPeer::to_encryption_level_value(int level_value) {
    return ::to_encryption_level_value(level_value);
}

OSSL_ENCRYPTION_LEVEL TlsAdapterTestPeer::to_ossl_encryption_level(EncryptionLevel level) {
    return ::to_ossl_encryption_level(level);
}

OSSL_ENCRYPTION_LEVEL TlsAdapterTestPeer::to_ossl_encryption_level_value(std::uint8_t level_value) {
    return ::to_ossl_encryption_level_value(level_value);
}

CodecResult<CipherSuite> TlsAdapterTestPeer::cipher_suite_for_protocol_ids(
    std::optional<std::uint16_t> pending_protocol_id,
    std::optional<std::uint16_t> current_protocol_id) {
    return ::cipher_suite_for_protocol_ids(pending_protocol_id, current_protocol_id);
}

CodecResult<CipherSuite> TlsAdapterTestPeer::cipher_suite_for_ssl(TlsAdapter &adapter) {
    return ::cipher_suite_for_ssl(adapter.impl_->ssl_.get());
}

std::vector<uint8_t>
TlsAdapterTestPeer::encode_application_protocol_list(std::string_view application_protocol) {
    return ::encode_application_protocol_list(application_protocol);
}

bool TlsAdapterTestPeer::client_offered_application_protocol(
    std::span<const uint8_t> offered, std::string_view application_protocol) {
    return ::client_offered_application_protocol(offered, application_protocol);
}

bool TlsAdapterTestPeer::call_client_alpn_failed(TlsAdapter &adapter,
                                                 std::string_view application_protocol) {
    auto *ssl = adapter.impl_->ssl_.get();
    if (ssl == nullptr) {
        return true;
    }

    return ::client_alpn_failed(ssl, application_protocol);
}

void TlsAdapterTestPeer::set_application_protocol(TlsAdapter &adapter,
                                                  std::string_view application_protocol) {
    adapter.impl_->config_.application_protocol = std::string(application_protocol);
}

CodecResult<bool> TlsAdapterTestPeer::drive_handshake(TlsAdapter &adapter) {
    return adapter.impl_->drive_handshake();
}

void TlsAdapterTestPeer::reset_ssl(TlsAdapter &adapter) {
    adapter.impl_->ssl_.reset();
}

void TlsAdapterTestPeer::set_sticky_error(TlsAdapter &adapter, CodecErrorCode code) {
    adapter.impl_->sticky_error_ = CodecError{
        .code = code,
        .offset = 0,
    };
}

void TlsAdapterTestPeer::clear_sticky_error(TlsAdapter &adapter) {
    adapter.impl_->sticky_error_.reset();
}

bool TlsAdapterTestPeer::has_sticky_error(const TlsAdapter &adapter) {
    return adapter.impl_->sticky_error_.has_value();
}

std::optional<CodecErrorCode> TlsAdapterTestPeer::sticky_error_code(const TlsAdapter &adapter) {
    const auto &sticky_error = adapter.impl_->sticky_error_;
    if (!sticky_error.has_value()) {
        return std::nullopt;
    }

    return sticky_error.value().code;
}

bool TlsAdapterTestPeer::should_retry_handshake(bool handshake_fault, int error) {
    return ::should_retry_handshake(handshake_fault, error);
}

bool TlsAdapterTestPeer::handshake_progressed(bool pending_changed, bool secrets_changed,
                                              bool peer_transport_parameters_changed) {
    return ::handshake_progressed(pending_changed, secrets_changed,
                                  peer_transport_parameters_changed);
}

int TlsAdapterTestPeer::call_on_set_encryption_secrets(TlsAdapter &adapter,
                                                       OSSL_ENCRYPTION_LEVEL level,
                                                       const uint8_t *read_secret,
                                                       const uint8_t *write_secret,
                                                       size_t secret_len) {
    const SSL_CIPHER *cipher = adapter.impl_->pending_or_current_cipher();
    if (read_secret != nullptr &&
        adapter.impl_->on_set_secret(level, opposite_role(adapter.impl_->config_.role), cipher,
                                     read_secret, secret_len) == 0) {
        return 0;
    }
    if (write_secret != nullptr &&
        adapter.impl_->on_set_secret(level, adapter.impl_->config_.role, cipher, write_secret,
                                     secret_len) == 0) {
        return 0;
    }
    return 1;
}

int TlsAdapterTestPeer::call_on_set_secret(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                           EndpointRole sender, const uint8_t *secret,
                                           size_t secret_len) {
    return adapter.impl_->on_set_secret(level, sender, adapter.impl_->pending_or_current_cipher(),
                                        secret, secret_len);
}

int TlsAdapterTestPeer::call_on_add_handshake_data(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                                   const uint8_t *data, size_t len) {
    return adapter.impl_->on_add_handshake_data(level, data, len);
}

int TlsAdapterTestPeer::call_on_flush_flight(TlsAdapter &adapter) {
    return adapter.impl_->on_flush_flight();
}

int TlsAdapterTestPeer::call_on_send_alert(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                           uint8_t alert) {
    return adapter.impl_->on_send_alert(level, alert);
}

int TlsAdapterTestPeer::call_static_send_alert(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                               uint8_t alert) {
    auto *ssl = adapter.impl_->ssl_.get();
    if (ssl == nullptr) {
        return 0;
    }

    return TlsAdapter::Impl::send_alert(ssl, level, alert);
}

int TlsAdapterTestPeer::call_static_select_application_protocol(TlsAdapter *adapter,
                                                                const uint8_t **out,
                                                                uint8_t *out_len,
                                                                std::span<const uint8_t> offered) {
    return TlsAdapter::Impl::select_application_protocol(
        nullptr, out, out_len, offered.data(), static_cast<unsigned>(offered.size()),
        adapter == nullptr ? nullptr : adapter->impl_.get());
}

std::optional<std::uint16_t>
TlsAdapterTestPeer::pending_or_current_cipher_protocol_id(TlsAdapter &adapter) {
    const SSL_CIPHER *cipher = adapter.impl_->pending_or_current_cipher();
    if (cipher == nullptr) {
        return std::nullopt;
    }

    return SSL_CIPHER_get_protocol_id(cipher);
}

template <typename Callback>
COQUIC_NO_PROFILE int call_with_null_app_data(SSL *ssl, Callback callback) {
    if (ssl == nullptr) {
        return 0;
    }

    void *previous = SSL_get_app_data(ssl);
    SSL_set_app_data(ssl, nullptr);
    const int result = callback(ssl);
    SSL_set_app_data(ssl, previous);
    return result;
}

int TlsAdapterTestPeer::call_static_set_read_secret_with_null_app_data(TlsAdapter &adapter,
                                                                       OSSL_ENCRYPTION_LEVEL level,
                                                                       const uint8_t *secret,
                                                                       size_t secret_len) {
    return call_with_null_app_data(adapter.impl_->ssl_.get(), [&](SSL *ssl) {
        const SSL_CIPHER *cipher = SSL_get_pending_cipher(ssl);
        if (cipher == nullptr) {
            cipher = SSL_get_current_cipher(ssl);
        }
        if (secret == nullptr) {
            return 0;
        }
        return TlsAdapter::Impl::set_read_secret(ssl, level, cipher, secret, secret_len);
    });
}

int TlsAdapterTestPeer::call_static_set_write_secret_with_null_app_data(TlsAdapter &adapter,
                                                                        OSSL_ENCRYPTION_LEVEL level,
                                                                        const uint8_t *secret,
                                                                        size_t secret_len) {
    return call_with_null_app_data(adapter.impl_->ssl_.get(), [&](SSL *ssl) {
        const SSL_CIPHER *cipher = SSL_get_pending_cipher(ssl);
        if (cipher == nullptr) {
            cipher = SSL_get_current_cipher(ssl);
        }
        if (secret == nullptr) {
            return 0;
        }
        return TlsAdapter::Impl::set_write_secret(ssl, level, cipher, secret, secret_len);
    });
}

int TlsAdapterTestPeer::call_static_add_handshake_data_with_null_app_data(
    TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level, const uint8_t *data, size_t len) {
    return call_with_null_app_data(adapter.impl_->ssl_.get(), [&](SSL *ssl) {
        return TlsAdapter::Impl::add_handshake_data(ssl, level, data, len);
    });
}

int TlsAdapterTestPeer::call_static_flush_flight_with_null_app_data(TlsAdapter &adapter) {
    return call_with_null_app_data(adapter.impl_->ssl_.get(),
                                   [&](SSL *ssl) { return TlsAdapter::Impl::flush_flight(ssl); });
}

int TlsAdapterTestPeer::call_static_send_alert_with_null_app_data(TlsAdapter &adapter,
                                                                  OSSL_ENCRYPTION_LEVEL level,
                                                                  uint8_t alert) {
    return call_with_null_app_data(adapter.impl_->ssl_.get(), [&](SSL *ssl) {
        return TlsAdapter::Impl::send_alert(ssl, level, alert);
    });
}

void TlsAdapterTestPeer::capture_peer_transport_parameters(TlsAdapter &adapter) {
    adapter.impl_->capture_peer_transport_parameters();
}

void TlsAdapterTestPeer::set_peer_transport_parameters(TlsAdapter &adapter,
                                                       std::vector<std::byte> bytes) {
    adapter.impl_->peer_transport_parameters_ = std::move(bytes);
}

void TlsAdapterTestPeer::clear_peer_transport_parameters(TlsAdapter &adapter) {
    adapter.impl_->peer_transport_parameters_.reset();
}

} // namespace test

} // namespace coquic::quic
