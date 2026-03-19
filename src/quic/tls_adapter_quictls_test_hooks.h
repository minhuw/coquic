#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <openssl/ssl.h>

#include "src/quic/tls_adapter.h"

namespace coquic::quic::test {

enum class TlsAdapterFaultPoint : std::uint8_t {
    initialize_ctx_new,
    initialize_ctx_config,
    initialize_verify_paths,
    load_identity_cert_bio,
    load_identity_key_bio,
    load_identity_use_certificate,
    initialize_ssl_new,
    initialize_ssl_set_quic_method,
    initialize_server_name,
    initialize_transport_params,
    provide_quic_data,
    provide_post_handshake,
    drive_handshake,
    set_encryption_secrets_unsupported_cipher,
};

class ScopedTlsAdapterFaultInjector {
  public:
    explicit ScopedTlsAdapterFaultInjector(TlsAdapterFaultPoint fault_point,
                                           std::size_t occurrence = 1);
    ~ScopedTlsAdapterFaultInjector();

    ScopedTlsAdapterFaultInjector(const ScopedTlsAdapterFaultInjector &) = delete;
    ScopedTlsAdapterFaultInjector &operator=(const ScopedTlsAdapterFaultInjector &) = delete;

  private:
    std::optional<TlsAdapterFaultPoint> previous_fault_point_;
    std::size_t previous_occurrence_ = 0;
};

class TlsAdapterTestPeer {
  public:
    static const uint8_t *as_tls_bytes(std::span<const std::byte> bytes);
    static std::optional<EncryptionLevel> to_encryption_level(OSSL_ENCRYPTION_LEVEL level);
    static std::optional<EncryptionLevel> to_encryption_level_value(int level_value);
    static OSSL_ENCRYPTION_LEVEL to_ossl_encryption_level(EncryptionLevel level);
    static OSSL_ENCRYPTION_LEVEL to_ossl_encryption_level_value(std::uint8_t level_value);
    static CodecResult<CipherSuite>
    cipher_suite_for_protocol_ids(std::optional<std::uint16_t> pending_protocol_id,
                                  std::optional<std::uint16_t> current_protocol_id);
    static CodecResult<CipherSuite> cipher_suite_for_ssl(TlsAdapter &adapter);

    static CodecResult<bool> drive_handshake(TlsAdapter &adapter);
    static void reset_ssl(TlsAdapter &adapter);
    static void set_sticky_error(TlsAdapter &adapter, CodecErrorCode code);
    static void clear_sticky_error(TlsAdapter &adapter);
    static bool has_sticky_error(const TlsAdapter &adapter);
    static std::optional<CodecErrorCode> sticky_error_code(const TlsAdapter &adapter);
    static bool should_retry_handshake(bool handshake_fault, int error);
    static bool handshake_progressed(bool pending_changed, bool secrets_changed,
                                     bool peer_transport_parameters_changed);

    static int call_on_set_encryption_secrets(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                              const uint8_t *read_secret,
                                              const uint8_t *write_secret, size_t secret_len);
    static int call_on_add_handshake_data(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                          const uint8_t *data, size_t len);
    static int call_on_flush_flight(TlsAdapter &adapter);
    static int call_on_send_alert(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level, uint8_t alert);
    static int call_static_send_alert(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                      uint8_t alert);

    static int call_static_set_encryption_secrets_with_null_app_data(TlsAdapter &adapter,
                                                                     OSSL_ENCRYPTION_LEVEL level,
                                                                     const uint8_t *read_secret,
                                                                     const uint8_t *write_secret,
                                                                     size_t secret_len);
    static int call_static_add_handshake_data_with_null_app_data(TlsAdapter &adapter,
                                                                 OSSL_ENCRYPTION_LEVEL level,
                                                                 const uint8_t *data, size_t len);
    static int call_static_flush_flight_with_null_app_data(TlsAdapter &adapter);
    static int call_static_send_alert_with_null_app_data(TlsAdapter &adapter,
                                                         OSSL_ENCRYPTION_LEVEL level,
                                                         uint8_t alert);

    static void capture_peer_transport_parameters(TlsAdapter &adapter);
    static void set_peer_transport_parameters(TlsAdapter &adapter, std::vector<std::byte> bytes);
    static void clear_peer_transport_parameters(TlsAdapter &adapter);
};

} // namespace coquic::quic::test
