#include <node_api.h>

#include <coquic/ffi/core.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::uint32_t kExpectedFfiAbiVersion = 1;

struct Bytes {
    std::vector<std::uint8_t> storage;

    coquic_bytes_t view() const {
        return coquic_bytes_t{
            .data = storage.empty() ? nullptr : storage.data(),
            .length = storage.size(),
        };
    }
};

struct EndpointConfigMaterialization {
    std::vector<std::uint32_t> supported_versions;
    Bytes application_protocol;
    Bytes zero_rtt_context;
    Bytes certificate_pem;
    Bytes private_key_pem;
    coquic_tls_identity_t identity{};
    coquic_endpoint_config_t config{};
};

struct ClientConnectionConfigMaterialization {
    Bytes source_connection_id;
    Bytes initial_destination_connection_id;
    Bytes original_destination_connection_id;
    Bytes retry_source_connection_id;
    Bytes retry_token;
    Bytes server_name;
    Bytes resumption_state_bytes;
    Bytes zero_rtt_context;
    coquic_resumption_state_t resumption_state{};
    coquic_client_connection_config_t config{};
};

struct OpenConnectionMaterialization {
    ClientConnectionConfigMaterialization connection;
    Bytes address_validation_identity;
    coquic_open_connection_t open{};
};

class EndpointWrap {
  public:
    explicit EndpointWrap(coquic_endpoint_t *endpoint) : endpoint_(endpoint) {
    }

    ~EndpointWrap() {
        if (endpoint_ != nullptr) {
            coquic_endpoint_destroy(endpoint_);
        }
    }

    EndpointWrap(const EndpointWrap &) = delete;
    EndpointWrap &operator=(const EndpointWrap &) = delete;

    coquic_endpoint_t *get() const {
        return endpoint_;
    }

    void close() {
        if (endpoint_ != nullptr) {
            coquic_endpoint_destroy(endpoint_);
            endpoint_ = nullptr;
        }
    }

  private:
    coquic_endpoint_t *endpoint_ = nullptr;
};

struct EndpointHolder {
    std::unique_ptr<EndpointWrap> endpoint;
};

void throw_error(napi_env env, std::string_view message) {
    napi_throw_error(env, nullptr, std::string(message).c_str());
}

void throw_status(napi_env env, coquic_status_t status) {
    const char *message = "unknown status";
    switch (status) {
    case COQUIC_STATUS_OK:
        message = "ok";
        break;
    case COQUIC_STATUS_INVALID_ARGUMENT:
        message = "invalid argument";
        break;
    case COQUIC_STATUS_OUT_OF_MEMORY:
        message = "out of memory";
        break;
    case COQUIC_STATUS_INTERNAL_ERROR:
        message = "internal error";
        break;
    default:
        break;
    }
    napi_throw_error(env, nullptr, message);
}

bool check(napi_env env, napi_status status, std::string_view message) {
    if (status == napi_ok) {
        return true;
    }
    throw_error(env, message);
    return false;
}

napi_value undefined(napi_env env) {
    napi_value value = nullptr;
    napi_get_undefined(env, &value);
    return value;
}

napi_value null_value(napi_env env) {
    napi_value value = nullptr;
    napi_get_null(env, &value);
    return value;
}

napi_valuetype value_type(napi_env env, napi_value value) {
    napi_valuetype type = napi_undefined;
    napi_typeof(env, value, &type);
    return type;
}

bool is_nullish(napi_env env, napi_value value) {
    if (value == nullptr) {
        return true;
    }
    const auto type = value_type(env, value);
    return type == napi_undefined || type == napi_null;
}

bool require_argument(napi_env env, napi_value value, std::string_view message) {
    if (!is_nullish(env, value)) {
        return true;
    }
    throw_error(env, message);
    return false;
}

bool get_named(napi_env env, napi_value object, const char *name, napi_value *out) {
    bool has_property = false;
    if (!check(env, napi_has_named_property(env, object, name, &has_property),
               "failed to inspect object property")) {
        return false;
    }
    if (!has_property) {
        *out = undefined(env);
        return true;
    }
    return check(env, napi_get_named_property(env, object, name, out),
                 "failed to read object property");
}

std::uint8_t get_u8(napi_env env, napi_value object, const char *name, std::uint8_t fallback) {
    napi_value value = nullptr;
    if (!get_named(env, object, name, &value) || is_nullish(env, value)) {
        return fallback;
    }
    std::uint32_t out = fallback;
    napi_get_value_uint32(env, value, &out);
    return static_cast<std::uint8_t>(out);
}

std::uint32_t get_u32(napi_env env, napi_value object, const char *name, std::uint32_t fallback) {
    napi_value value = nullptr;
    if (!get_named(env, object, name, &value) || is_nullish(env, value)) {
        return fallback;
    }
    std::uint32_t out = fallback;
    napi_get_value_uint32(env, value, &out);
    return out;
}

std::uint64_t number_to_u64(napi_env env, napi_value value, std::uint64_t fallback = 0) {
    if (is_nullish(env, value)) {
        return fallback;
    }
    bool lossless = false;
    std::uint64_t out = fallback;
    if (napi_get_value_bigint_uint64(env, value, &out, &lossless) == napi_ok) {
        return out;
    }
    double number = static_cast<double>(fallback);
    if (napi_get_value_double(env, value, &number) != napi_ok) {
        return fallback;
    }
    if (!std::isfinite(number) || std::signbit(number) ||
        number > static_cast<double>(std::numeric_limits<std::uint64_t>::max())) {
        return fallback;
    }
    return static_cast<std::uint64_t>(number);
}

std::uint64_t get_u64(napi_env env, napi_value object, const char *name, std::uint64_t fallback) {
    napi_value value = nullptr;
    if (!get_named(env, object, name, &value)) {
        return fallback;
    }
    return number_to_u64(env, value, fallback);
}

std::size_t get_size(napi_env env, napi_value object, const char *name, std::size_t fallback) {
    return static_cast<std::size_t>(get_u64(env, object, name, fallback));
}

bool get_bool(napi_env env, napi_value object, const char *name, bool fallback) {
    napi_value value = nullptr;
    if (!get_named(env, object, name, &value) || is_nullish(env, value)) {
        return fallback;
    }
    bool out = fallback;
    napi_get_value_bool(env, value, &out);
    return out;
}

Bytes bytes_from_value(napi_env env, napi_value value) {
    Bytes out;
    if (is_nullish(env, value)) {
        return out;
    }

    bool is_buffer = false;
    if (napi_is_buffer(env, value, &is_buffer) == napi_ok && is_buffer) {
        void *data = nullptr;
        std::size_t length = 0;
        napi_get_buffer_info(env, value, &data, &length);
        const auto *bytes = static_cast<const std::uint8_t *>(data);
        out.storage.assign(bytes, bytes + length);
        return out;
    }

    bool is_array_buffer = false;
    if (napi_is_arraybuffer(env, value, &is_array_buffer) == napi_ok && is_array_buffer) {
        void *data = nullptr;
        std::size_t length = 0;
        napi_get_arraybuffer_info(env, value, &data, &length);
        const auto *bytes = static_cast<const std::uint8_t *>(data);
        out.storage.assign(bytes, bytes + length);
        return out;
    }

    if (value_type(env, value) == napi_string) {
        std::size_t length = 0;
        napi_get_value_string_utf8(env, value, nullptr, 0, &length);
        out.storage.resize(length + 1);
        napi_get_value_string_utf8(env, value, reinterpret_cast<char *>(out.storage.data()),
                                   out.storage.size(), &length);
        out.storage.resize(length);
    }
    return out;
}

Bytes get_bytes(napi_env env, napi_value object, const char *name) {
    napi_value value = nullptr;
    if (!get_named(env, object, name, &value)) {
        return {};
    }
    return bytes_from_value(env, value);
}

std::optional<Bytes> get_optional_bytes(napi_env env, napi_value object, const char *name) {
    napi_value value = nullptr;
    if (!get_named(env, object, name, &value) || is_nullish(env, value)) {
        return std::nullopt;
    }
    return bytes_from_value(env, value);
}

std::vector<std::uint32_t> get_u32_array(napi_env env, napi_value object, const char *name) {
    std::vector<std::uint32_t> out;
    napi_value value = nullptr;
    if (!get_named(env, object, name, &value) || is_nullish(env, value)) {
        return out;
    }
    bool is_array = false;
    napi_is_array(env, value, &is_array);
    if (!is_array) {
        return out;
    }
    std::uint32_t length = 0;
    napi_get_array_length(env, value, &length);
    out.reserve(length);
    for (std::uint32_t index = 0; index < length; ++index) {
        napi_value item = nullptr;
        napi_get_element(env, value, index, &item);
        std::uint32_t raw = 0;
        napi_get_value_uint32(env, item, &raw);
        out.push_back(raw);
    }
    return out;
}

napi_value make_object(napi_env env) {
    napi_value value = nullptr;
    napi_create_object(env, &value);
    return value;
}

napi_value make_array(napi_env env, std::size_t length = 0) {
    napi_value value = nullptr;
    napi_create_array_with_length(env, length, &value);
    return value;
}

napi_value make_bool(napi_env env, bool value) {
    napi_value out = nullptr;
    napi_get_boolean(env, value, &out);
    return out;
}

napi_value make_u32(napi_env env, std::uint32_t value) {
    napi_value out = nullptr;
    napi_create_uint32(env, value, &out);
    return out;
}

napi_value make_i64(napi_env env, std::uint64_t value) {
    napi_value out = nullptr;
    if (value <= 9007199254740991ull) {
        napi_create_double(env, static_cast<double>(value), &out);
    } else {
        napi_create_bigint_uint64(env, value, &out);
    }
    return out;
}

napi_value make_string(napi_env env, std::string_view value) {
    napi_value out = nullptr;
    napi_create_string_utf8(env, value.data(), value.size(), &out);
    return out;
}

napi_value make_buffer_copy(napi_env env, const std::uint8_t *data, std::size_t length) {
    napi_value out = nullptr;
    void *copied = nullptr;
    const void *source = data == nullptr ? static_cast<const void *>("") : data;
    napi_create_buffer_copy(env, length, source, &copied, &out);
    return out;
}

napi_value make_buffer_copy(napi_env env, coquic_bytes_view_t bytes) {
    return make_buffer_copy(env, bytes.data, bytes.length);
}

napi_value make_buffer_copy(napi_env env, coquic_bytes_t bytes) {
    return make_buffer_copy(env, bytes.data, bytes.length);
}

void set_named(napi_env env, napi_value object, const char *name, napi_value value) {
    napi_set_named_property(env, object, name, value);
}

void set_bool(napi_env env, napi_value object, const char *name, bool value) {
    set_named(env, object, name, make_bool(env, value));
}

void set_u32(napi_env env, napi_value object, const char *name, std::uint32_t value) {
    set_named(env, object, name, make_u32(env, value));
}

void set_u64(napi_env env, napi_value object, const char *name, std::uint64_t value) {
    set_named(env, object, name, make_i64(env, value));
}

void set_string(napi_env env, napi_value object, const char *name, std::string_view value) {
    set_named(env, object, name, make_string(env, value));
}

void set_buffer(napi_env env, napi_value object, const char *name, coquic_bytes_view_t bytes) {
    set_named(env, object, name, make_buffer_copy(env, bytes));
}

void set_buffer(napi_env env, napi_value object, const char *name, coquic_bytes_t bytes) {
    set_named(env, object, name, make_buffer_copy(env, bytes));
}

void set_buffer(napi_env env, napi_value object, const char *name, const std::uint8_t *data,
                std::size_t length) {
    set_named(env, object, name, make_buffer_copy(env, data, length));
}

void set_optional_u64(napi_env env, napi_value object, const char *name, bool has_value,
                      std::uint64_t value) {
    set_named(env, object, name, has_value ? make_i64(env, value) : null_value(env));
}

coquic_optional_route_handle_t optional_route_from_value(napi_env env, napi_value value) {
    if (is_nullish(env, value)) {
        return coquic_optional_route_handle_t{.has_value = 0, .value = 0};
    }
    return coquic_optional_route_handle_t{
        .has_value = 1,
        .value = number_to_u64(env, value),
    };
}

coquic_optional_route_handle_t get_optional_route(napi_env env, napi_value object,
                                                  const char *name) {
    napi_value value = nullptr;
    if (!get_named(env, object, name, &value)) {
        return coquic_optional_route_handle_t{.has_value = 0, .value = 0};
    }
    return optional_route_from_value(env, value);
}

napi_value optional_time_to_js(napi_env env, coquic_optional_time_us_t value) {
    if (value.has_value == 0) {
        return null_value(env);
    }
    return make_i64(env, value.value);
}

coquic_zero_rtt_config_t zero_rtt_from_object(napi_env env, napi_value value, Bytes &context,
                                              coquic_zero_rtt_config_t fallback) {
    if (is_nullish(env, value)) {
        context.storage.clear();
        return fallback;
    }
    context = get_bytes(env, value, "applicationContext");
    return coquic_zero_rtt_config_t{
        .attempt =
            static_cast<std::uint8_t>(get_bool(env, value, "attempt", fallback.attempt != 0)),
        .allow = static_cast<std::uint8_t>(get_bool(env, value, "allow", fallback.allow != 0)),
        .application_context = context.view(),
    };
}

coquic_transport_config_t transport_from_object(napi_env env, napi_value value,
                                                coquic_transport_config_t fallback) {
    if (is_nullish(env, value)) {
        return fallback;
    }
    fallback.max_idle_timeout = get_u64(env, value, "maxIdleTimeout", fallback.max_idle_timeout);
    fallback.max_udp_payload_size =
        get_u64(env, value, "maxUdpPayloadSize", fallback.max_udp_payload_size);
    fallback.pmtud_enabled =
        static_cast<std::uint8_t>(get_bool(env, value, "pmtudEnabled", fallback.pmtud_enabled));
    fallback.pmtud_base_datagram_size =
        get_size(env, value, "pmtudBaseDatagramSize", fallback.pmtud_base_datagram_size);
    fallback.pmtud_max_datagram_size =
        get_size(env, value, "pmtudMaxDatagramSize", fallback.pmtud_max_datagram_size);
    fallback.active_connection_id_limit =
        get_u64(env, value, "activeConnectionIdLimit", fallback.active_connection_id_limit);
    fallback.disable_active_migration = static_cast<std::uint8_t>(
        get_bool(env, value, "disableActiveMigration", fallback.disable_active_migration));
    fallback.ack_delay_exponent =
        get_u64(env, value, "ackDelayExponent", fallback.ack_delay_exponent);
    fallback.max_ack_delay = get_u64(env, value, "maxAckDelay", fallback.max_ack_delay);
    fallback.ack_eliciting_threshold =
        get_u64(env, value, "ackElicitingThreshold", fallback.ack_eliciting_threshold);
    fallback.initial_max_data = get_u64(env, value, "initialMaxData", fallback.initial_max_data);
    fallback.initial_max_stream_data_bidi_local = get_u64(
        env, value, "initialMaxStreamDataBidiLocal", fallback.initial_max_stream_data_bidi_local);
    fallback.initial_max_stream_data_bidi_remote = get_u64(
        env, value, "initialMaxStreamDataBidiRemote", fallback.initial_max_stream_data_bidi_remote);
    fallback.initial_max_stream_data_uni =
        get_u64(env, value, "initialMaxStreamDataUni", fallback.initial_max_stream_data_uni);
    fallback.initial_max_streams_bidi =
        get_u64(env, value, "initialMaxStreamsBidi", fallback.initial_max_streams_bidi);
    fallback.initial_max_streams_uni =
        get_u64(env, value, "initialMaxStreamsUni", fallback.initial_max_streams_uni);
    fallback.max_datagram_frame_size =
        get_u64(env, value, "maxDatagramFrameSize", fallback.max_datagram_frame_size);
    fallback.congestion_control =
        get_u8(env, value, "congestionControl", fallback.congestion_control);
    fallback.enable_hystart_plus_plus = static_cast<std::uint8_t>(
        get_bool(env, value, "enableHystartPlusPlus", fallback.enable_hystart_plus_plus));
    fallback.send_stream_fairness = static_cast<std::uint8_t>(
        get_bool(env, value, "sendStreamFairness", fallback.send_stream_fairness));
    fallback.enable_latency_spin_bit = static_cast<std::uint8_t>(
        get_bool(env, value, "enableLatencySpinBit", fallback.enable_latency_spin_bit));
    fallback.grease_reserved_versions = static_cast<std::uint8_t>(
        get_bool(env, value, "greaseReservedVersions", fallback.grease_reserved_versions));
    fallback.grease_quic_bit =
        static_cast<std::uint8_t>(get_bool(env, value, "greaseQuicBit", fallback.grease_quic_bit));
    fallback.enable_optimistic_ack_mitigation = static_cast<std::uint8_t>(get_bool(
        env, value, "enableOptimisticAckMitigation", fallback.enable_optimistic_ack_mitigation));
    return fallback;
}

napi_value transport_to_js(napi_env env, const coquic_transport_config_t &raw) {
    napi_value out = make_object(env);
    set_u64(env, out, "maxIdleTimeout", raw.max_idle_timeout);
    set_u64(env, out, "maxUdpPayloadSize", raw.max_udp_payload_size);
    set_bool(env, out, "pmtudEnabled", raw.pmtud_enabled != 0);
    set_u64(env, out, "pmtudBaseDatagramSize", raw.pmtud_base_datagram_size);
    set_u64(env, out, "pmtudMaxDatagramSize", raw.pmtud_max_datagram_size);
    set_u64(env, out, "activeConnectionIdLimit", raw.active_connection_id_limit);
    set_bool(env, out, "disableActiveMigration", raw.disable_active_migration != 0);
    set_u64(env, out, "ackDelayExponent", raw.ack_delay_exponent);
    set_u64(env, out, "maxAckDelay", raw.max_ack_delay);
    set_u64(env, out, "ackElicitingThreshold", raw.ack_eliciting_threshold);
    set_u64(env, out, "initialMaxData", raw.initial_max_data);
    set_u64(env, out, "initialMaxStreamDataBidiLocal", raw.initial_max_stream_data_bidi_local);
    set_u64(env, out, "initialMaxStreamDataBidiRemote", raw.initial_max_stream_data_bidi_remote);
    set_u64(env, out, "initialMaxStreamDataUni", raw.initial_max_stream_data_uni);
    set_u64(env, out, "initialMaxStreamsBidi", raw.initial_max_streams_bidi);
    set_u64(env, out, "initialMaxStreamsUni", raw.initial_max_streams_uni);
    set_u64(env, out, "maxDatagramFrameSize", raw.max_datagram_frame_size);
    set_u32(env, out, "congestionControl", raw.congestion_control);
    set_bool(env, out, "enableHystartPlusPlus", raw.enable_hystart_plus_plus != 0);
    set_bool(env, out, "sendStreamFairness", raw.send_stream_fairness != 0);
    set_bool(env, out, "enableLatencySpinBit", raw.enable_latency_spin_bit != 0);
    set_bool(env, out, "greaseReservedVersions", raw.grease_reserved_versions != 0);
    set_bool(env, out, "greaseQuicBit", raw.grease_quic_bit != 0);
    set_bool(env, out, "enableOptimisticAckMitigation", raw.enable_optimistic_ack_mitigation != 0);
    return out;
}

napi_value zero_rtt_to_js(napi_env env, const coquic_zero_rtt_config_t &raw) {
    napi_value out = make_object(env);
    set_bool(env, out, "attempt", raw.attempt != 0);
    set_bool(env, out, "allow", raw.allow != 0);
    set_buffer(env, out, "applicationContext", raw.application_context);
    return out;
}

EndpointConfigMaterialization endpoint_config_from_js(napi_env env, napi_value value) {
    EndpointConfigMaterialization out;
    coquic_endpoint_config_init(&out.config);

    out.supported_versions = get_u32_array(env, value, "supportedVersions");
    out.application_protocol = get_bytes(env, value, "applicationProtocol");
    out.config.role = get_u8(env, value, "role", out.config.role);
    out.config.supported_versions =
        out.supported_versions.empty() ? nullptr : out.supported_versions.data();
    out.config.supported_versions_count = out.supported_versions.size();
    out.config.verify_peer =
        static_cast<std::uint8_t>(get_bool(env, value, "verifyPeer", out.config.verify_peer));
    out.config.retry_enabled =
        static_cast<std::uint8_t>(get_bool(env, value, "retryEnabled", out.config.retry_enabled));
    out.config.application_protocol =
        reinterpret_cast<const char *>(out.application_protocol.view().data);
    out.config.application_protocol_length = out.application_protocol.storage.size();

    napi_value identity_value = nullptr;
    get_named(env, value, "identity", &identity_value);
    if (!is_nullish(env, identity_value)) {
        out.certificate_pem = get_bytes(env, identity_value, "certificatePem");
        out.private_key_pem = get_bytes(env, identity_value, "privateKeyPem");
        out.identity.certificate_pem =
            reinterpret_cast<const char *>(out.certificate_pem.view().data);
        out.identity.certificate_pem_length = out.certificate_pem.storage.size();
        out.identity.private_key_pem =
            reinterpret_cast<const char *>(out.private_key_pem.view().data);
        out.identity.private_key_pem_length = out.private_key_pem.storage.size();
        out.config.identity = &out.identity;
    }

    napi_value transport_value = nullptr;
    get_named(env, value, "transport", &transport_value);
    out.config.transport = transport_from_object(env, transport_value, out.config.transport);
    out.config.max_outbound_datagram_size =
        get_size(env, value, "maxOutboundDatagramSize", out.config.max_outbound_datagram_size);

    napi_value zero_rtt_value = nullptr;
    get_named(env, value, "zeroRtt", &zero_rtt_value);
    out.config.zero_rtt =
        zero_rtt_from_object(env, zero_rtt_value, out.zero_rtt_context, out.config.zero_rtt);
    out.config.emit_shared_receive_stream_data = static_cast<std::uint8_t>(get_bool(
        env, value, "emitSharedReceiveStreamData", out.config.emit_shared_receive_stream_data));
    out.config.enable_out_of_order_receive = static_cast<std::uint8_t>(
        get_bool(env, value, "enableOutOfOrderReceive", out.config.enable_out_of_order_receive));
    out.config.enable_packet_inspection = static_cast<std::uint8_t>(
        get_bool(env, value, "enablePacketInspection", out.config.enable_packet_inspection));
    out.config.allow_peer_address_change = static_cast<std::uint8_t>(
        get_bool(env, value, "allowPeerAddressChange", out.config.allow_peer_address_change));
    return out;
}

ClientConnectionConfigMaterialization client_connection_config_from_js(napi_env env,
                                                                       napi_value value) {
    ClientConnectionConfigMaterialization out;
    coquic_client_connection_config_init(&out.config);

    out.source_connection_id = get_bytes(env, value, "sourceConnectionId");
    out.initial_destination_connection_id = get_bytes(env, value, "initialDestinationConnectionId");
    const auto original_destination =
        get_optional_bytes(env, value, "originalDestinationConnectionId");
    const auto retry_source = get_optional_bytes(env, value, "retrySourceConnectionId");
    out.original_destination_connection_id =
        original_destination.has_value() ? *original_destination : Bytes{};
    out.retry_source_connection_id = retry_source.has_value() ? *retry_source : Bytes{};
    out.retry_token = get_bytes(env, value, "retryToken");
    out.server_name = get_bytes(env, value, "serverName");

    out.config.source_connection_id = out.source_connection_id.view();
    out.config.initial_destination_connection_id = out.initial_destination_connection_id.view();
    out.config.original_destination_connection_id = out.original_destination_connection_id.view();
    out.config.has_original_destination_connection_id =
        static_cast<std::uint8_t>(original_destination.has_value());
    out.config.retry_source_connection_id = out.retry_source_connection_id.view();
    out.config.has_retry_source_connection_id = static_cast<std::uint8_t>(retry_source.has_value());
    out.config.retry_token = out.retry_token.view();
    out.config.original_version =
        get_u32(env, value, "originalVersion", out.config.original_version);
    out.config.initial_version = get_u32(env, value, "initialVersion", out.config.initial_version);
    out.config.reacted_to_version_negotiation = static_cast<std::uint8_t>(get_bool(
        env, value, "reactedToVersionNegotiation", out.config.reacted_to_version_negotiation));
    out.config.server_name = reinterpret_cast<const char *>(out.server_name.view().data);
    out.config.server_name_length = out.server_name.storage.size();

    napi_value resumption_value = nullptr;
    get_named(env, value, "resumptionState", &resumption_value);
    if (!is_nullish(env, resumption_value)) {
        out.resumption_state_bytes = get_bytes(env, resumption_value, "serialized");
        out.resumption_state.serialized = out.resumption_state_bytes.view();
        out.config.resumption_state = &out.resumption_state;
    }

    napi_value zero_rtt_value = nullptr;
    get_named(env, value, "zeroRtt", &zero_rtt_value);
    out.config.zero_rtt =
        zero_rtt_from_object(env, zero_rtt_value, out.zero_rtt_context, out.config.zero_rtt);
    return out;
}

OpenConnectionMaterialization open_connection_from_js(napi_env env, napi_value value) {
    OpenConnectionMaterialization out;
    napi_value connection_value = nullptr;
    get_named(env, value, "connection", &connection_value);
    out.connection = client_connection_config_from_js(env, connection_value);
    out.address_validation_identity = get_bytes(env, value, "addressValidationIdentity");
    out.open = coquic_open_connection_t{
        .size = sizeof(coquic_open_connection_t),
        .connection = out.connection.config,
        .initial_route_handle = get_u64(env, value, "initialRouteHandle", 0),
        .address_validation_identity = out.address_validation_identity.view(),
    };
    return out;
}

coquic_inbound_datagram_t inbound_datagram_from_js(napi_env env, napi_value value, Bytes &bytes,
                                                   Bytes &address_validation_identity) {
    bytes = get_bytes(env, value, "bytes");
    address_validation_identity = get_bytes(env, value, "addressValidationIdentity");
    return coquic_inbound_datagram_t{
        .size = sizeof(coquic_inbound_datagram_t),
        .bytes = bytes.view(),
        .route_handle = get_optional_route(env, value, "routeHandle"),
        .address_validation_identity = address_validation_identity.view(),
        .ecn = get_u8(env, value, "ecn", COQUIC_ECN_UNAVAILABLE),
    };
}

EndpointHolder *endpoint_holder(napi_env env, napi_callback_info info, std::size_t *argc,
                                napi_value *argv) {
    napi_value this_value = nullptr;
    if (!check(env, napi_get_cb_info(env, info, argc, argv, &this_value, nullptr),
               "failed to read callback info")) {
        return nullptr;
    }
    void *data = nullptr;
    if (!check(env, napi_unwrap(env, this_value, &data), "failed to unwrap endpoint")) {
        return nullptr;
    }
    auto *endpoint_holder_value = static_cast<EndpointHolder *>(data);
    if (endpoint_holder_value == nullptr || endpoint_holder_value->endpoint == nullptr ||
        endpoint_holder_value->endpoint->get() == nullptr) {
        throw_status(env, COQUIC_STATUS_INVALID_ARGUMENT);
        return nullptr;
    }
    return endpoint_holder_value;
}

napi_value local_error_to_js(napi_env env, const coquic_local_error_t &raw) {
    napi_value out = make_object(env);
    set_optional_u64(env, out, "connection", raw.connection.has_value != 0, raw.connection.value);
    set_u32(env, out, "code", raw.code);
    set_optional_u64(env, out, "streamId", raw.stream_id.has_value != 0, raw.stream_id.value);
    return out;
}

napi_value preferred_address_to_js(napi_env env, const coquic_preferred_address_t &raw) {
    napi_value out = make_object(env);
    set_buffer(env, out, "ipv4Address", raw.ipv4_address, sizeof(raw.ipv4_address));
    set_u32(env, out, "ipv4Port", raw.ipv4_port);
    set_buffer(env, out, "ipv6Address", raw.ipv6_address, sizeof(raw.ipv6_address));
    set_u32(env, out, "ipv6Port", raw.ipv6_port);
    set_buffer(env, out, "connectionId", raw.connection_id);
    set_buffer(env, out, "statelessResetToken", raw.stateless_reset_token,
               sizeof(raw.stateless_reset_token));
    return out;
}

napi_value packet_inspection_to_js(napi_env env, const coquic_packet_inspection_effect_t &raw) {
    napi_value out = make_object(env);
    set_u64(env, out, "connection", raw.connection);
    set_u32(env, out, "direction", raw.direction);
    set_u32(env, out, "packetType", raw.packet_type);
    set_u64(env, out, "datagramId", raw.datagram_id);
    set_u64(env, out, "datagramLength", raw.datagram_length);
    set_u64(env, out, "datagramOffset", raw.datagram_offset);
    set_u64(env, out, "packetLength", raw.packet_length);
    set_u32(env, out, "version", raw.version);
    set_buffer(env, out, "destinationConnectionId", raw.destination_connection_id);
    set_buffer(env, out, "sourceConnectionId", raw.source_connection_id);
    set_buffer(env, out, "token", raw.token);
    set_bool(env, out, "spinBit", raw.spin_bit != 0);
    set_bool(env, out, "keyPhase", raw.key_phase != 0);
    set_u32(env, out, "packetNumberLength", raw.packet_number_length);
    set_u64(env, out, "packetNumber", raw.packet_number);
    set_buffer(env, out, "encryptedPacket", raw.encrypted_packet);
    set_buffer(env, out, "plaintextPayload", raw.plaintext_payload);
    return out;
}

napi_value effect_to_js(napi_env env, const coquic_effect_t &raw) {
    // Convert the tagged FFI union into the corresponding JavaScript object shape.
    napi_value out = make_object(env);
    switch (raw.kind) {
    case COQUIC_EFFECT_SEND_DATAGRAM: {
        const auto &value = raw.as.send_datagram;
        set_string(env, out, "kind", "send_datagram");
        set_u64(env, out, "connection", value.connection);
        set_optional_u64(env, out, "routeHandle", value.route_handle.has_value != 0,
                         value.route_handle.value);
        set_buffer(env, out, "bytes", value.bytes);
        set_u32(env, out, "ecn", value.ecn);
        set_bool(env, out, "isPmtuProbe", value.is_pmtu_probe != 0);
        break;
    }
    case COQUIC_EFFECT_RECEIVE_STREAM_DATA: {
        const auto &value = raw.as.receive_stream_data;
        set_string(env, out, "kind", "receive_stream_data");
        set_u64(env, out, "connection", value.connection);
        set_u64(env, out, "streamId", value.stream_id);
        set_u64(env, out, "offset", value.offset);
        set_buffer(env, out, "bytes", value.bytes);
        set_bool(env, out, "fin", value.fin != 0);
        set_optional_u64(env, out, "finalSize", value.final_size.has_value != 0,
                         value.final_size.value);
        break;
    }
    case COQUIC_EFFECT_RECEIVE_DATAGRAM_DATA: {
        const auto &value = raw.as.receive_datagram_data;
        set_string(env, out, "kind", "receive_datagram_data");
        set_u64(env, out, "connection", value.connection);
        set_buffer(env, out, "bytes", value.bytes);
        break;
    }
    case COQUIC_EFFECT_PEER_RESET_STREAM: {
        const auto &value = raw.as.peer_reset_stream;
        set_string(env, out, "kind", "peer_reset_stream");
        set_u64(env, out, "connection", value.connection);
        set_u64(env, out, "streamId", value.stream_id);
        set_u64(env, out, "applicationErrorCode", value.application_error_code);
        set_u64(env, out, "finalSize", value.final_size);
        break;
    }
    case COQUIC_EFFECT_PEER_STOP_SENDING: {
        const auto &value = raw.as.peer_stop_sending;
        set_string(env, out, "kind", "peer_stop_sending");
        set_u64(env, out, "connection", value.connection);
        set_u64(env, out, "streamId", value.stream_id);
        set_u64(env, out, "applicationErrorCode", value.application_error_code);
        break;
    }
    case COQUIC_EFFECT_STATE_EVENT: {
        const auto &value = raw.as.state_event;
        set_string(env, out, "kind", "state_event");
        set_u64(env, out, "connection", value.connection);
        set_u32(env, out, "change", value.change);
        break;
    }
    case COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT: {
        const auto &value = raw.as.connection_lifecycle_event;
        set_string(env, out, "kind", "connection_lifecycle_event");
        set_u64(env, out, "connection", value.connection);
        set_u32(env, out, "event", value.event);
        break;
    }
    case COQUIC_EFFECT_PEER_PREFERRED_ADDRESS_AVAILABLE: {
        const auto &value = raw.as.peer_preferred_address_available;
        set_string(env, out, "kind", "peer_preferred_address_available");
        set_u64(env, out, "connection", value.connection);
        // Keep nested address fields grouped so callers can distinguish absent and zero values.
        set_named(env, out, "preferredAddress",
                  preferred_address_to_js(env, value.preferred_address));
        break;
    }
    case COQUIC_EFFECT_RESUMPTION_STATE_AVAILABLE: {
        const auto &value = raw.as.resumption_state_available;
        set_string(env, out, "kind", "resumption_state_available");
        set_u64(env, out, "connection", value.connection);
        set_buffer(env, out, "serialized", value.serialized);
        break;
    }
    case COQUIC_EFFECT_ZERO_RTT_STATUS_EVENT: {
        const auto &value = raw.as.zero_rtt_status_event;
        set_string(env, out, "kind", "zero_rtt_status_event");
        set_u64(env, out, "connection", value.connection);
        set_u32(env, out, "status", value.status);
        break;
    }
    case COQUIC_EFFECT_PACKET_INSPECTION: {
        const auto &value = raw.as.packet_inspection;
        set_string(env, out, "kind", "packet_inspection");
        set_u64(env, out, "connection", value.connection);
        set_named(env, out, "packetInspection", packet_inspection_to_js(env, value));
        break;
    }
    case COQUIC_EFFECT_NEW_TOKEN_AVAILABLE: {
        const auto &value = raw.as.new_token_available;
        set_string(env, out, "kind", "new_token_available");
        set_u64(env, out, "connection", value.connection);
        set_buffer(env, out, "token", value.token);
        break;
    }
    default:
        // Preserve unknown effect discriminants so newer native libraries remain diagnosable.
        set_string(env, out, "kind", "unknown");
        set_u32(env, out, "unknown", raw.kind);
        break;
    }
    return out;
}

napi_value result_to_js(napi_env env, coquic_result_t *result) {
    napi_value out = make_object(env);
    if (result == nullptr) {
        set_named(env, out, "effects", make_array(env));
        set_named(env, out, "nextWakeup", null_value(env));
        set_named(env, out, "localError", null_value(env));
        set_bool(env, out, "sendContinuationPending", false);
        return out;
    }

    std::unique_ptr<coquic_result_t, decltype(&coquic_result_destroy)> guard(
        result, &coquic_result_destroy);
    const auto count = coquic_result_effect_count(result);
    napi_value effects = make_array(env, count);
    for (std::size_t index = 0; index < count; ++index) {
        coquic_effect_t effect{};
        const auto status = coquic_result_effect_at(result, index, &effect);
        if (status != COQUIC_STATUS_OK) {
            throw_status(env, status);
            return undefined(env);
        }
        napi_set_element(env, effects, static_cast<std::uint32_t>(index),
                         effect_to_js(env, effect));
    }
    set_named(env, out, "effects", effects);
    set_named(env, out, "nextWakeup", optional_time_to_js(env, coquic_result_next_wakeup(result)));
    if (coquic_result_has_local_error(result) != 0) {
        coquic_local_error_t local_error{};
        const auto status = coquic_result_local_error(result, &local_error);
        if (status != COQUIC_STATUS_OK) {
            throw_status(env, status);
            return undefined(env);
        }
        set_named(env, out, "localError", local_error_to_js(env, local_error));
    } else {
        set_named(env, out, "localError", null_value(env));
    }
    set_bool(env, out, "sendContinuationPending",
             coquic_result_send_continuation_pending(result) != 0);
    return out;
}

napi_value DefaultTransportConfig(napi_env env, napi_callback_info) {
    coquic_transport_config_t config{};
    coquic_transport_config_init(&config);
    return transport_to_js(env, config);
}

napi_value DefaultEndpointConfig(napi_env env, napi_callback_info) {
    coquic_endpoint_config_t config{};
    coquic_endpoint_config_init(&config);
    napi_value out = make_object(env);
    set_u32(env, out, "role", config.role);
    set_named(env, out, "supportedVersions", make_array(env));
    set_bool(env, out, "verifyPeer", config.verify_peer != 0);
    set_bool(env, out, "retryEnabled", config.retry_enabled != 0);
    set_buffer(env, out, "applicationProtocol",
               reinterpret_cast<const std::uint8_t *>(config.application_protocol),
               config.application_protocol_length);
    set_named(env, out, "identity", null_value(env));
    set_named(env, out, "transport", transport_to_js(env, config.transport));
    set_u64(env, out, "maxOutboundDatagramSize", config.max_outbound_datagram_size);
    set_named(env, out, "zeroRtt", zero_rtt_to_js(env, config.zero_rtt));
    set_bool(env, out, "emitSharedReceiveStreamData", config.emit_shared_receive_stream_data != 0);
    set_bool(env, out, "enableOutOfOrderReceive", config.enable_out_of_order_receive != 0);
    set_bool(env, out, "enablePacketInspection", config.enable_packet_inspection != 0);
    set_bool(env, out, "allowPeerAddressChange", config.allow_peer_address_change != 0);
    return out;
}

napi_value DefaultClientConnectionConfig(napi_env env, napi_callback_info) {
    coquic_client_connection_config_t config{};
    coquic_client_connection_config_init(&config);
    napi_value out = make_object(env);
    set_buffer(env, out, "sourceConnectionId", config.source_connection_id);
    set_buffer(env, out, "initialDestinationConnectionId",
               config.initial_destination_connection_id);
    set_named(env, out, "originalDestinationConnectionId", null_value(env));
    set_named(env, out, "retrySourceConnectionId", null_value(env));
    set_buffer(env, out, "retryToken", config.retry_token);
    set_u32(env, out, "originalVersion", config.original_version);
    set_u32(env, out, "initialVersion", config.initial_version);
    set_bool(env, out, "reactedToVersionNegotiation", config.reacted_to_version_negotiation != 0);
    set_buffer(env, out, "serverName", reinterpret_cast<const std::uint8_t *>(config.server_name),
               config.server_name_length);
    set_named(env, out, "resumptionState", null_value(env));
    set_named(env, out, "zeroRtt", zero_rtt_to_js(env, config.zero_rtt));
    return out;
}

napi_value FfiAbiVersion(napi_env env, napi_callback_info) {
    return make_u32(env, coquic_ffi_abi_version());
}

napi_value EndpointConstructor(napi_env env, napi_callback_info info) {
    std::size_t argc = 1;
    napi_value argv[1]{};
    napi_value this_value = nullptr;
    if (!check(env, napi_get_cb_info(env, info, &argc, argv, &this_value, nullptr),
               "failed to read endpoint constructor arguments")) {
        return nullptr;
    }
    if (coquic_ffi_abi_version() != kExpectedFfiAbiVersion) {
        throw_error(env, "coquic FFI ABI mismatch");
        return nullptr;
    }
    if (!require_argument(env, argv[0], "endpoint config is required")) {
        return nullptr;
    }

    auto materialized = endpoint_config_from_js(env, argv[0]);
    coquic_endpoint_t *endpoint = nullptr;
    const auto status = coquic_endpoint_create(&materialized.config, &endpoint);
    if (status != COQUIC_STATUS_OK) {
        throw_status(env, status);
        return nullptr;
    }

    auto *new_endpoint_holder = new EndpointHolder{std::make_unique<EndpointWrap>(endpoint)};
    if (!check(env,
               napi_wrap(
                   env, this_value, new_endpoint_holder,
                   [](napi_env, void *data, void *) { delete static_cast<EndpointHolder *>(data); },
                   nullptr, nullptr),
               "failed to wrap endpoint")) {
        delete new_endpoint_holder;
        return nullptr;
    }
    return this_value;
}

napi_value EndpointClose(napi_env env, napi_callback_info info) {
    std::size_t argc = 0;
    napi_value this_value = nullptr;
    if (!check(env, napi_get_cb_info(env, info, &argc, nullptr, &this_value, nullptr),
               "failed to read callback info")) {
        return nullptr;
    }
    void *data = nullptr;
    if (!check(env, napi_unwrap(env, this_value, &data), "failed to unwrap endpoint")) {
        return nullptr;
    }
    auto *endpoint_holder_value = static_cast<EndpointHolder *>(data);
    if (endpoint_holder_value != nullptr && endpoint_holder_value->endpoint != nullptr) {
        endpoint_holder_value->endpoint->close();
    }
    return undefined(env);
}

napi_value EndpointConnect(napi_env env, napi_callback_info info) {
    std::size_t argc = 2;
    napi_value argv[2]{};
    auto *holder = endpoint_holder(env, info, &argc, argv);
    if (holder == nullptr) {
        return nullptr;
    }
    auto open = open_connection_from_js(env, argv[0]);
    coquic_connection_handle_t connection = 0;
    coquic_result_t *result = nullptr;
    const auto status = coquic_quic_connect(holder->endpoint->get(), &open.open,
                                            number_to_u64(env, argv[1]), &connection, &result);
    if (status != COQUIC_STATUS_OK) {
        throw_status(env, status);
        return nullptr;
    }
    napi_value out = make_object(env);
    set_u64(env, out, "connection", connection);
    set_named(env, out, "result", result_to_js(env, result));
    return out;
}

napi_value EndpointReceiveDatagram(napi_env env, napi_callback_info info) {
    std::size_t argc = 2;
    napi_value argv[2]{};
    auto *holder = endpoint_holder(env, info, &argc, argv);
    if (holder == nullptr) {
        return nullptr;
    }
    Bytes bytes;
    Bytes identity;
    auto datagram = inbound_datagram_from_js(env, argv[0], bytes, identity);
    coquic_result_t *result = nullptr;
    const auto status = coquic_quic_receive_datagram(holder->endpoint->get(), &datagram,
                                                     number_to_u64(env, argv[1]), &result);
    if (status != COQUIC_STATUS_OK) {
        throw_status(env, status);
        return nullptr;
    }
    return result_to_js(env, result);
}

napi_value EndpointTimerExpired(napi_env env, napi_callback_info info) {
    std::size_t argc = 1;
    napi_value argv[1]{};
    auto *holder = endpoint_holder(env, info, &argc, argv);
    if (holder == nullptr) {
        return nullptr;
    }
    coquic_result_t *result = nullptr;
    const auto status =
        coquic_quic_timer_expired(holder->endpoint->get(), number_to_u64(env, argv[0]), &result);
    if (status != COQUIC_STATUS_OK) {
        throw_status(env, status);
        return nullptr;
    }
    return result_to_js(env, result);
}

napi_value EndpointSendStream(napi_env env, napi_callback_info info) {
    std::size_t argc = 6;
    napi_value argv[6]{};
    auto *holder = endpoint_holder(env, info, &argc, argv);
    if (holder == nullptr) {
        return nullptr;
    }
    if (!require_argument(env, argv[5], "stream priority is required")) {
        return nullptr;
    }
    Bytes bytes = bytes_from_value(env, argv[2]);
    bool fin = false;
    napi_get_value_bool(env, argv[3], &fin);
    const auto priority = number_to_u64(env, argv[5]);
    coquic_send_stream_data_t stream{
        .size = sizeof(coquic_send_stream_data_t),
        .stream_id = number_to_u64(env, argv[1]),
        .bytes = bytes.view(),
        .fin = static_cast<std::uint8_t>(fin),
        .priority = static_cast<std::int32_t>(priority),
    };
    coquic_result_t *result = nullptr;
    const auto status =
        coquic_quic_connection_send_stream(holder->endpoint->get(), number_to_u64(env, argv[0]),
                                           &stream, number_to_u64(env, argv[4]), &result);
    if (status != COQUIC_STATUS_OK) {
        throw_status(env, status);
        return nullptr;
    }
    return result_to_js(env, result);
}

napi_value EndpointSendDatagram(napi_env env, napi_callback_info info) {
    std::size_t argc = 4;
    napi_value argv[4]{};
    auto *holder = endpoint_holder(env, info, &argc, argv);
    if (holder == nullptr) {
        return nullptr;
    }
    if (!require_argument(env, argv[3], "datagram priority is required")) {
        return nullptr;
    }
    Bytes bytes = bytes_from_value(env, argv[1]);
    const auto priority = number_to_u64(env, argv[3]);
    coquic_send_datagram_data_t datagram{
        .size = sizeof(coquic_send_datagram_data_t),
        .bytes = bytes.view(),
        .priority = static_cast<std::int32_t>(priority),
    };
    coquic_result_t *result = nullptr;
    const auto status =
        coquic_quic_connection_send_datagram(holder->endpoint->get(), number_to_u64(env, argv[0]),
                                             &datagram, number_to_u64(env, argv[2]), &result);
    if (status != COQUIC_STATUS_OK) {
        throw_status(env, status);
        return nullptr;
    }
    return result_to_js(env, result);
}

napi_value EndpointCloseConnection(napi_env env, napi_callback_info info) {
    std::size_t argc = 4;
    napi_value argv[4]{};
    auto *holder = endpoint_holder(env, info, &argc, argv);
    if (holder == nullptr) {
        return nullptr;
    }
    Bytes reason = bytes_from_value(env, argv[2]);
    coquic_close_connection_t close{
        .size = sizeof(coquic_close_connection_t),
        .application_error_code = number_to_u64(env, argv[1]),
        .reason_phrase = reinterpret_cast<const char *>(reason.view().data),
        .reason_phrase_length = reason.storage.size(),
    };
    coquic_result_t *result = nullptr;
    const auto status =
        coquic_quic_connection_close(holder->endpoint->get(), number_to_u64(env, argv[0]), &close,
                                     number_to_u64(env, argv[3]), &result);
    if (status != COQUIC_STATUS_OK) {
        throw_status(env, status);
        return nullptr;
    }
    return result_to_js(env, result);
}

napi_value EndpointConnectionCount(napi_env env, napi_callback_info info) {
    std::size_t argc = 0;
    auto *holder = endpoint_holder(env, info, &argc, nullptr);
    if (holder == nullptr) {
        return nullptr;
    }
    return make_i64(env, coquic_endpoint_connection_count(holder->endpoint->get()));
}

napi_value EndpointNextWakeup(napi_env env, napi_callback_info info) {
    std::size_t argc = 0;
    auto *holder = endpoint_holder(env, info, &argc, nullptr);
    if (holder == nullptr) {
        return nullptr;
    }
    return optional_time_to_js(env, coquic_endpoint_next_wakeup(holder->endpoint->get()));
}

napi_value EndpointHasSendContinuationPending(napi_env env, napi_callback_info info) {
    std::size_t argc = 0;
    auto *holder = endpoint_holder(env, info, &argc, nullptr);
    if (holder == nullptr) {
        return nullptr;
    }
    return make_bool(env,
                     coquic_endpoint_has_send_continuation_pending(holder->endpoint->get()) != 0);
}

napi_value EndpointHasPendingStreamSend(napi_env env, napi_callback_info info) {
    std::size_t argc = 0;
    auto *holder = endpoint_holder(env, info, &argc, nullptr);
    if (holder == nullptr) {
        return nullptr;
    }
    return make_bool(env, coquic_endpoint_has_pending_stream_send(holder->endpoint->get()) != 0);
}

void set_function(napi_env env, napi_value object, const char *name, napi_callback callback) {
    napi_value fn = nullptr;
    napi_create_function(env, name, NAPI_AUTO_LENGTH, callback, nullptr, &fn);
    set_named(env, object, name, fn);
}

napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor endpoint_methods[] = {
        {"close", nullptr, EndpointClose, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"connect", nullptr, EndpointConnect, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"receiveDatagram", nullptr, EndpointReceiveDatagram, nullptr, nullptr, nullptr,
         napi_default, nullptr},
        {"timerExpired", nullptr, EndpointTimerExpired, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"sendStream", nullptr, EndpointSendStream, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"sendDatagram", nullptr, EndpointSendDatagram, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"closeConnection", nullptr, EndpointCloseConnection, nullptr, nullptr, nullptr,
         napi_default, nullptr},
        {"connectionCount", nullptr, EndpointConnectionCount, nullptr, nullptr, nullptr,
         napi_default, nullptr},
        {"nextWakeup", nullptr, EndpointNextWakeup, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"hasSendContinuationPending", nullptr, EndpointHasSendContinuationPending, nullptr,
         nullptr, nullptr, napi_default, nullptr},
        {"hasPendingStreamSend", nullptr, EndpointHasPendingStreamSend, nullptr, nullptr, nullptr,
         napi_default, nullptr},
    };
    napi_value endpoint_constructor = nullptr;
    napi_define_class(env, "Endpoint", NAPI_AUTO_LENGTH, EndpointConstructor, nullptr,
                      std::size(endpoint_methods), endpoint_methods, &endpoint_constructor);
    set_named(env, exports, "Endpoint", endpoint_constructor);

    set_function(env, exports, "ffiAbiVersion", FfiAbiVersion);
    set_function(env, exports, "defaultTransportConfig", DefaultTransportConfig);
    set_function(env, exports, "defaultEndpointConfig", DefaultEndpointConfig);
    set_function(env, exports, "defaultClientConnectionConfig", DefaultClientConnectionConfig);
    return exports;
}

} // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
