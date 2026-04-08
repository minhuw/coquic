#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <openssl/ssl.h>

#include "src/quic/tls_adapter.h"

#if !defined(OSSL_ENCRYPTION_LEVEL)
typedef enum ssl_encryption_level_t OSSL_ENCRYPTION_LEVEL;
#endif

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
    initialize_client_alpn,
    initialize_client_alpn_set_protos,
    initialize_server_name,
    initialize_transport_params,
    initialize_server_resumption_context,
    initialize_set_session,
    provide_quic_data,
    provide_post_handshake,
    drive_handshake,
    set_encryption_secrets_unsupported_cipher,
    serialize_session_bytes,
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
    static std::vector<uint8_t>
    encode_application_protocol_list(std::string_view application_protocol);
    static bool client_offered_application_protocol(std::span<const uint8_t> offered,
                                                    std::string_view application_protocol);
    static bool call_client_alpn_failed(TlsAdapter &adapter, std::string_view application_protocol);
    static void set_application_protocol(TlsAdapter &adapter,
                                         std::string_view application_protocol);

    static CodecResult<bool> drive_handshake(TlsAdapter &adapter);
    static void reset_ssl(TlsAdapter &adapter);
    static void set_sticky_error(TlsAdapter &adapter, CodecErrorCode code);
    static void clear_sticky_error(TlsAdapter &adapter);
    static bool has_sticky_error(const TlsAdapter &adapter);
    static std::optional<CodecErrorCode> sticky_error_code(const TlsAdapter &adapter);
    static bool should_retry_handshake(bool handshake_fault, int error);
    static bool handshake_progressed(bool pending_changed, bool secrets_changed,
                                     bool peer_transport_parameters_changed);
    static std::optional<std::vector<std::byte>>
    serialize_session_bytes(const SSL_SESSION *session);
    static bool deserialize_session_bytes(std::span<const std::byte> bytes);

    static int call_on_set_encryption_secrets(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                              const uint8_t *read_secret,
                                              const uint8_t *write_secret, size_t secret_len);
    static int call_on_set_encryption_secrets_value(TlsAdapter &adapter, int level_value,
                                                    const uint8_t *read_secret,
                                                    const uint8_t *write_secret, size_t secret_len);
    static int call_on_set_secret(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                  EndpointRole sender, const uint8_t *secret, size_t secret_len);
    static int call_on_add_handshake_data(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                          const uint8_t *data, size_t len);
    static int call_on_add_handshake_data_value(TlsAdapter &adapter, int level_value,
                                                const uint8_t *data, size_t len);
    static int call_on_flush_flight(TlsAdapter &adapter);
    static int call_on_send_alert(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level, uint8_t alert);
    static int call_static_send_alert(TlsAdapter &adapter, OSSL_ENCRYPTION_LEVEL level,
                                      uint8_t alert);
    static int call_static_select_application_protocol(TlsAdapter *adapter, const uint8_t **out,
                                                       uint8_t *out_len,
                                                       std::span<const uint8_t> offered);
    static std::optional<std::uint16_t> pending_or_current_cipher_protocol_id(TlsAdapter &adapter);

    static int call_static_set_read_secret_with_null_app_data(TlsAdapter &adapter,
                                                              OSSL_ENCRYPTION_LEVEL level,
                                                              const uint8_t *secret,
                                                              size_t secret_len);
    static int call_static_set_write_secret_with_null_app_data(TlsAdapter &adapter,
                                                               OSSL_ENCRYPTION_LEVEL level,
                                                               const uint8_t *secret,
                                                               size_t secret_len);
    static int call_static_add_handshake_data_with_null_app_data(TlsAdapter &adapter,
                                                                 OSSL_ENCRYPTION_LEVEL level,
                                                                 const uint8_t *data, size_t len);
    static int call_static_flush_flight_with_null_app_data(TlsAdapter &adapter);
    static int call_static_send_alert_with_null_app_data(TlsAdapter &adapter,
                                                         OSSL_ENCRYPTION_LEVEL level,
                                                         uint8_t alert);
    static int call_static_on_new_session_with_null_app_data(TlsAdapter &adapter,
                                                             SSL_SESSION *session);
    static void call_static_on_keylog_line(TlsAdapter &adapter, const char *line);
    static void call_static_on_keylog_line_with_null_app_data(TlsAdapter &adapter,
                                                              const char *line);

    static void capture_peer_transport_parameters(TlsAdapter &adapter);
    static void set_peer_transport_parameters(TlsAdapter &adapter, std::vector<std::byte> bytes);
    static void clear_peer_transport_parameters(TlsAdapter &adapter);
    static void update_runtime_status(TlsAdapter &adapter);
    static void set_early_data_attempted(TlsAdapter &adapter, bool attempted);
    static void apply_early_data_status(TlsAdapter &adapter, int early_data_status,
                                        bool handshake_complete);
};

} // namespace coquic::quic::test
