#include "src/quic/tls_adapter.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

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
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

constexpr std::uint16_t tls_aes_128_gcm_sha256_id = 0x1301;
constexpr std::uint16_t tls_aes_256_gcm_sha384_id = 0x1302;
constexpr std::uint16_t tls_chacha20_poly1305_sha256_id = 0x1303;

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

std::optional<EncryptionLevel> to_encryption_level(OSSL_ENCRYPTION_LEVEL level) {
    switch (level) {
    case ssl_encryption_initial:
        return EncryptionLevel::initial;
    case ssl_encryption_handshake:
        return EncryptionLevel::handshake;
    case ssl_encryption_application:
        return EncryptionLevel::application;
    case ssl_encryption_early_data:
        return std::nullopt;
    }

    return std::nullopt;
}

OSSL_ENCRYPTION_LEVEL to_ossl_encryption_level(EncryptionLevel level) {
    switch (level) {
    case EncryptionLevel::initial:
        return ssl_encryption_initial;
    case EncryptionLevel::handshake:
        return ssl_encryption_handshake;
    case EncryptionLevel::application:
        return ssl_encryption_application;
    }

    return ssl_encryption_initial;
}

const SSL_METHOD *tls_method_for_role(EndpointRole role) {
    return role == EndpointRole::client ? TLS_client_method() : TLS_server_method();
}

CodecResult<CipherSuite> cipher_suite_for_ssl(const SSL *ssl) {
    const SSL_CIPHER *cipher = SSL_get_pending_cipher(ssl);
    if (cipher == nullptr) {
        cipher = SSL_get_current_cipher(ssl);
    }
    if (cipher == nullptr) {
        return CodecResult<CipherSuite>::failure(CodecErrorCode::unsupported_cipher_suite, 0);
    }

    switch (SSL_CIPHER_get_protocol_id(cipher)) {
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

} // namespace

namespace coquic::quic {

class TlsAdapter::Impl {
  public:
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
        if (SSL_provide_quic_data(ssl_.get(), to_ossl_encryption_level(level), as_tls_bytes(bytes),
                                  bytes.size()) != 1) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return tls_failure();
        }

        if (level == EncryptionLevel::application && SSL_is_init_finished(ssl_.get()) == 1) {
            ERR_clear_error();
            if (SSL_process_quic_post_handshake(ssl_.get()) != 1) {
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
        return ssl_ != nullptr && SSL_is_init_finished(ssl_.get()) == 1;
    }

    static int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                      const uint8_t *read_secret, const uint8_t *write_secret,
                                      size_t secret_len) {
        auto *impl = static_cast<Impl *>(SSL_get_app_data(ssl));
        if (impl == nullptr) {
            return 0;
        }

        return impl->on_set_encryption_secrets(ssl, level, read_secret, write_secret, secret_len);
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

  private:
    void initialize() {
        ERR_clear_error();
        ctx_.reset(SSL_CTX_new(tls_method_for_role(config_.role)));
        if (ctx_ == nullptr) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_3_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(ctx_.get(), TLS1_3_VERSION) != 1 ||
            SSL_CTX_set_quic_method(ctx_.get(), &kQuicMethod) != 1) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        SSL_CTX_set_verify(ctx_.get(), config_.verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                           nullptr);
        if (config_.verify_peer && SSL_CTX_set_default_verify_paths(ctx_.get()) != 1) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (!load_identity()) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        ssl_.reset(SSL_new(ctx_.get()));
        if (ssl_ == nullptr) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        SSL_set_app_data(ssl_.get(), this);
        if (SSL_set_quic_method(ssl_.get(), &kQuicMethod) != 1) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (!config_.server_name.empty() && config_.role == EndpointRole::client &&
            SSL_set_tlsext_host_name(ssl_.get(), config_.server_name.c_str()) != 1) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::invalid_packet_protection_state, .offset = 0};
            return;
        }

        if (SSL_set_quic_transport_params(ssl_.get(),
                                          as_tls_bytes(config_.local_transport_parameters),
                                          config_.local_transport_parameters.size()) != 1) {
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

        BioPtr cert_bio(BIO_new_mem_buf(config_.identity->certificate_pem.data(),
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

        BioPtr key_bio(BIO_new_mem_buf(config_.identity->private_key_pem.data(),
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

        return SSL_CTX_use_certificate(ctx_.get(), certificate.get()) == 1 &&
               SSL_CTX_use_PrivateKey(ctx_.get(), private_key.get()) == 1 &&
               SSL_CTX_check_private_key(ctx_.get()) == 1;
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

            const int error = SSL_get_error(ssl_.get(), result);
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                const bool progressed =
                    total_pending_bytes() != pending_before ||
                    available_secrets_.size() != secrets_before ||
                    peer_transport_parameters_.has_value() != had_peer_transport_parameters;
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

    int on_set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, const uint8_t *read_secret,
                                  const uint8_t *write_secret, size_t secret_len) {
        const auto mapped_level = to_encryption_level(level);
        if (!mapped_level.has_value()) {
            return 1;
        }

        const auto cipher_suite = cipher_suite_for_ssl(ssl);
        if (!cipher_suite.has_value()) {
            sticky_error_ =
                CodecError{.code = CodecErrorCode::unsupported_cipher_suite, .offset = 0};
            return 0;
        }

        if (read_secret != nullptr) {
            available_secrets_.push_back(AvailableTrafficSecret{
                .level = mapped_level.value(),
                .sender = opposite_role(config_.role),
                .secret =
                    TrafficSecret{
                        .cipher_suite = cipher_suite.value(),
                        .secret = std::vector(as_bytes(read_secret, secret_len).begin(),
                                              as_bytes(read_secret, secret_len).end()),
                    },
            });
        }

        if (write_secret != nullptr) {
            available_secrets_.push_back(AvailableTrafficSecret{
                .level = mapped_level.value(),
                .sender = config_.role,
                .secret =
                    TrafficSecret{
                        .cipher_suite = cipher_suite.value(),
                        .secret = std::vector(as_bytes(write_secret, secret_len).begin(),
                                              as_bytes(write_secret, secret_len).end()),
                    },
            });
        }

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

    static inline const SSL_QUIC_METHOD kQuicMethod{
        .set_encryption_secrets = &Impl::set_encryption_secrets,
        .add_handshake_data = &Impl::add_handshake_data,
        .flush_flight = &Impl::flush_flight,
        .send_alert = &Impl::send_alert,
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

} // namespace coquic::quic
