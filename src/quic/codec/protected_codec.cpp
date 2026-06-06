#include "src/quic/codec/protected_codec.h"
#include "src/quic/codec/protected_codec_internal.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/codec/buffer.h"
#include "src/quic/crypto/packet_crypto.h"
#include "src/quic/crypto/packet_crypto_test_hooks.h"
#include "src/quic/codec/packet_number.h"
#include "src/quic/codec/protected_codec_test_hooks.h"
#include "src/quic/transport/streams.h"
#include "src/quic/version.h"

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

#ifndef COQUIC_PROFILE_HOOKS
#define COQUIC_PROFILE_HOOKS 1
#endif

namespace coquic::quic {

namespace detail {

struct DeserializeProfileCounters {
    std::uint64_t one_rtt_in_place_calls = 0;
    std::uint64_t one_rtt_in_place_ns = 0;
    std::uint64_t one_rtt_in_place_bytes = 0;
    std::uint64_t one_rtt_plaintext_bytes = 0;
    std::uint64_t one_rtt_frames = 0;
    std::uint64_t key_lookup_ns = 0;
    std::uint64_t short_header_remove_ns = 0;
    std::uint64_t short_header_mask_ns = 0;
    std::uint64_t packet_number_recovery_ns = 0;
    std::uint64_t nonce_ns = 0;
    std::uint64_t aead_open_ns = 0;
    std::uint64_t frame_decode_ns = 0;
};

struct SerializeProfileCounters {
    std::uint64_t one_rtt_calls = 0;
    std::uint64_t one_rtt_ns = 0;
    std::uint64_t one_rtt_bytes = 0;
    std::uint64_t one_rtt_payload_bytes = 0;
    std::uint64_t one_rtt_frames = 0;
    std::uint64_t one_rtt_stream_fragments = 0;
    std::uint64_t one_rtt_packets_with_stream_fragments = 0;
    std::uint64_t one_rtt_single_stream_fragment_packets = 0;
    std::uint64_t one_rtt_multi_stream_fragment_packets = 0;
    std::uint64_t key_lookup_ns = 0;
    std::uint64_t packet_number_ns = 0;
    std::uint64_t nonce_ns = 0;
    std::uint64_t payload_size_ns = 0;
    std::uint64_t reserve_resize_ns = 0;
    std::uint64_t header_write_ns = 0;
    std::uint64_t payload_write_ns = 0;
    std::uint64_t aead_seal_ns = 0;
    std::uint64_t short_header_protect_ns = 0;
    std::uint64_t chunk_seal_calls = 0;
    std::uint64_t chunk_seal_ns = 0;
    std::uint64_t chunk_header_write_ns = 0;
    std::uint64_t chunk_frame_write_ns = 0;
    std::uint64_t simple_ack_fast_calls = 0;
};

COQUIC_NO_PROFILE void abort_if(bool condition) {
    if (condition) {
        std::abort();
    }
}

COQUIC_NO_PROFILE bool deserialize_profile_enabled() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return false;
    }

    static const bool enabled = [] {
        const char *value = std::getenv("COQUIC_DESERIALIZE_PROFILE");
        return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
    }();
    return enabled;
}

COQUIC_NO_PROFILE DeserializeProfileCounters &deserialize_profile_counters() {
    static DeserializeProfileCounters counters;
    return counters;
}

COQUIC_NO_PROFILE bool serialize_profile_enabled() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return false;
    }

    static const bool enabled = [] {
        const char *value = std::getenv("COQUIC_SERIALIZE_PROFILE");
        return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
    }();
    return enabled;
}

COQUIC_NO_PROFILE SerializeProfileCounters &serialize_profile_counters() {
    static SerializeProfileCounters counters;
    return counters;
}

COQUIC_NO_PROFILE void print_deserialize_profile() {
    if (!deserialize_profile_enabled()) {
        return;
    }

    const auto &c = deserialize_profile_counters();
    std::cerr << "coquic-deserialize-profile"
              << " one_rtt_in_place_calls=" << c.one_rtt_in_place_calls
              << " one_rtt_in_place_ns=" << c.one_rtt_in_place_ns
              << " one_rtt_in_place_bytes=" << c.one_rtt_in_place_bytes
              << " one_rtt_plaintext_bytes=" << c.one_rtt_plaintext_bytes
              << " one_rtt_frames=" << c.one_rtt_frames << " key_lookup_ns=" << c.key_lookup_ns
              << " short_header_remove_ns=" << c.short_header_remove_ns
              << " short_header_mask_ns=" << c.short_header_mask_ns
              << " packet_number_recovery_ns=" << c.packet_number_recovery_ns
              << " nonce_ns=" << c.nonce_ns << " aead_open_ns=" << c.aead_open_ns
              << " frame_decode_ns=" << c.frame_decode_ns << '\n';
}

COQUIC_NO_PROFILE void print_serialize_profile() {
    if (!serialize_profile_enabled()) {
        return;
    }

    const auto &c = serialize_profile_counters();
    std::cerr
        << "coquic-serialize-profile" << " one_rtt_calls=" << c.one_rtt_calls
        << " one_rtt_ns=" << c.one_rtt_ns << " one_rtt_bytes=" << c.one_rtt_bytes
        << " one_rtt_payload_bytes=" << c.one_rtt_payload_bytes
        << " one_rtt_frames=" << c.one_rtt_frames
        << " one_rtt_stream_fragments=" << c.one_rtt_stream_fragments
        << " one_rtt_packets_with_stream_fragments=" << c.one_rtt_packets_with_stream_fragments
        << " one_rtt_single_stream_fragment_packets=" << c.one_rtt_single_stream_fragment_packets
        << " one_rtt_multi_stream_fragment_packets=" << c.one_rtt_multi_stream_fragment_packets
        << " key_lookup_ns=" << c.key_lookup_ns << " packet_number_ns=" << c.packet_number_ns
        << " nonce_ns=" << c.nonce_ns << " payload_size_ns=" << c.payload_size_ns
        << " reserve_resize_ns=" << c.reserve_resize_ns << " header_write_ns=" << c.header_write_ns
        << " payload_write_ns=" << c.payload_write_ns << " aead_seal_ns=" << c.aead_seal_ns
        << " short_header_protect_ns=" << c.short_header_protect_ns
        << " chunk_seal_calls=" << c.chunk_seal_calls << " chunk_seal_ns=" << c.chunk_seal_ns
        << " chunk_header_write_ns=" << c.chunk_header_write_ns
        << " chunk_frame_write_ns=" << c.chunk_frame_write_ns
        << " simple_ack_fast_calls=" << c.simple_ack_fast_calls << '\n';
}

COQUIC_NO_PROFILE void register_deserialize_profile_printer_once() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return;
    }

    static const bool registered = [] {
        std::atexit(print_deserialize_profile);
        return true;
    }();
    static_cast<void>(registered);
}

COQUIC_NO_PROFILE void register_serialize_profile_printer_once() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return;
    }

    static const bool registered = [] {
        std::atexit(print_serialize_profile);
        return true;
    }();
    static_cast<void>(registered);
}

struct DeserializeProfileTimer {
    std::uint64_t *target = nullptr;
    std::chrono::steady_clock::time_point start{};

    COQUIC_NO_PROFILE explicit DeserializeProfileTimer(std::uint64_t &counter)
        : target(kCoquicProfileHooksEnabled && deserialize_profile_enabled() ? &counter : nullptr) {
        if (target != nullptr) {
            register_deserialize_profile_printer_once();
            start = std::chrono::steady_clock::now();
        }
    }

    COQUIC_NO_PROFILE ~DeserializeProfileTimer() {
        if (target == nullptr) {
            return;
        }
        *target += static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                  std::chrono::steady_clock::now() - start)
                                                  .count());
    }
};

struct SerializeProfileTimer {
    std::uint64_t *target = nullptr;
    std::chrono::steady_clock::time_point start{};

    COQUIC_NO_PROFILE explicit SerializeProfileTimer(std::uint64_t &counter)
        : target(kCoquicProfileHooksEnabled && serialize_profile_enabled() ? &counter : nullptr) {
        if (target != nullptr) {
            register_serialize_profile_printer_once();
            start = std::chrono::steady_clock::now();
        }
    }

    COQUIC_NO_PROFILE ~SerializeProfileTimer() {
        if (target == nullptr) {
            return;
        }
        *target += static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                  std::chrono::steady_clock::now() - start)
                                                  .count());
    }
};

#if COQUIC_PROFILE_HOOKS
#define COQUIC_DESERIALIZE_PROFILE_TIMER(name, counter)                                            \
    DeserializeProfileTimer name(deserialize_profile_counters().counter)
#define COQUIC_SERIALIZE_PROFILE_TIMER(name, counter)                                              \
    SerializeProfileTimer name(serialize_profile_counters().counter)
#define COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(counter, value)                                     \
    add_deserialize_profile_counter(deserialize_profile_counters().counter, value)
#define COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(counter, value)                                       \
    add_serialize_profile_counter(serialize_profile_counters().counter, value)
#else
#define COQUIC_DESERIALIZE_PROFILE_TIMER(name, counter) static_cast<void>(0)
#define COQUIC_SERIALIZE_PROFILE_TIMER(name, counter) static_cast<void>(0)
#define COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(counter, value) static_cast<void>(0)
#define COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(counter, value) static_cast<void>(0)
#endif

COQUIC_NO_PROFILE void add_deserialize_profile_counter(std::uint64_t &counter,
                                                       std::uint64_t value) {
    if (!deserialize_profile_enabled()) {
        return;
    }
    register_deserialize_profile_printer_once();
    counter += value;
}

COQUIC_NO_PROFILE void add_serialize_profile_counter(std::uint64_t &counter, std::uint64_t value) {
    if (!serialize_profile_enabled()) {
        return;
    }
    register_serialize_profile_printer_once();
    counter += value;
}

const TrafficSecret *one_rtt_secret_for_context(const DeserializeProtectionContext &context) {
    return context.one_rtt_secret_ref != nullptr
               ? context.one_rtt_secret_ref
               : (context.one_rtt_secret.has_value() ? &*context.one_rtt_secret : nullptr);
}

const TrafficSecret *handshake_secret_for_context(const SerializeProtectionContext &context) {
    return context.handshake_secret_ref != nullptr
               ? context.handshake_secret_ref
               : (context.handshake_secret.has_value() ? &*context.handshake_secret : nullptr);
}

const TrafficSecret *zero_rtt_secret_for_context(const SerializeProtectionContext &context) {
    return context.zero_rtt_secret_ref != nullptr
               ? context.zero_rtt_secret_ref
               : (context.zero_rtt_secret.has_value() ? &*context.zero_rtt_secret : nullptr);
}

const TrafficSecret *one_rtt_secret_for_context(const SerializeProtectionContext &context) {
    return context.one_rtt_secret_ref != nullptr
               ? context.one_rtt_secret_ref
               : (context.one_rtt_secret.has_value() ? &*context.one_rtt_secret : nullptr);
}

COQUIC_NO_PROFILE bool traffic_secret_cached_keys_available(const TrafficSecret *secret,
                                                            bool cache_primed) {
    return cache_primed && secret != nullptr && secret->cached_packet_protection_keys.has_value();
}

COQUIC_NO_PROFILE const PacketProtectionKeys &
traffic_secret_cached_keys_or_assert(const TrafficSecret *secret, bool cache_primed) {
    if (!cache_primed || secret == nullptr) {
        std::abort();
    }
    const auto &cached_keys = secret->cached_packet_protection_keys;
    if (!cached_keys.has_value()) {
        std::abort();
    }
    return cached_keys.value();
}

COQUIC_NO_PROFILE bool one_rtt_cached_keys_available(const DeserializeProtectionContext &context) {
    const auto *secret = one_rtt_secret_for_context(context);
    return traffic_secret_cached_keys_available(secret, context.one_rtt_secret_cache_primed);
}

COQUIC_NO_PROFILE const PacketProtectionKeys &
one_rtt_cached_keys_or_assert(const DeserializeProtectionContext &context) {
    const auto *secret = one_rtt_secret_for_context(context);
    return traffic_secret_cached_keys_or_assert(secret, context.one_rtt_secret_cache_primed);
}

std::uint8_t encoded_long_header_type(LongHeaderPacketType packet_type, std::uint32_t version) {
    const auto encoded_type = static_cast<std::uint8_t>(packet_type);
    return version == kQuicVersion2 ? static_cast<std::uint8_t>(encoded_type + 1u) : encoded_type;
}

ProtectedCodecFaultState &protected_codec_fault_state() {
#if defined(__wasi__) && defined(OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED)
    static ProtectedCodecFaultState state;
#else
    static thread_local ProtectedCodecFaultState state;
#endif
    return state;
}

void set_protected_codec_fault_state(std::optional<test::ProtectedCodecFaultPoint> fault_point,
                                     std::size_t occurrence) {
    protected_codec_fault_state() = ProtectedCodecFaultState{
        .fault_point = fault_point,
        .occurrence = occurrence,
    };
}

bool consume_protected_codec_fault(test::ProtectedCodecFaultPoint fault_point) {
    auto &state = protected_codec_fault_state();
    if (!state.fault_point.has_value() || state.fault_point.value() != fault_point)
        return false;
    if (state.occurrence > 1) {
        --state.occurrence;
        return false;
    }

    state.fault_point.reset();
    state.occurrence = 0;
    return true;
}

std::uint32_t read_u32_be(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }
    return value;
}

CodecResult<std::uint8_t> read_u8(BufferReader &reader) {
    const auto byte = reader.read_byte();
    if (!byte.has_value())
        return CodecResult<std::uint8_t>::failure(byte.error().code, byte.error().offset);

    return CodecResult<std::uint8_t>::success(std::to_integer<std::uint8_t>(byte.value()));
}

CodecResult<std::uint64_t> read_varint(BufferReader &reader) {
    const auto decoded = decode_varint(reader);
    if (!decoded.has_value())
        return CodecResult<std::uint64_t>::failure(decoded.error().code, decoded.error().offset);

    return CodecResult<std::uint64_t>::success(decoded.value().value);
}

std::optional<CodecError> append_varint(BufferWriter &writer, std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value);
    if (!written.has_value()) {
        return written.error();
    }

    writer.write_bytes(std::span<const std::byte>(encoded.data(), written.value()));
    return std::nullopt;
}

void append_varint_unchecked(BufferWriter &writer, std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value).value();
    writer.write_bytes(std::span<const std::byte>(encoded.data(), written));
}

void append_bytes(std::vector<std::byte> &bytes, std::span<const std::byte> appended) {
    const auto offset = bytes.size();
    bytes.resize(offset + appended.size());
    if (!appended.empty()) {
        std::memcpy(bytes.data() + static_cast<std::ptrdiff_t>(offset), appended.data(),
                    appended.size());
    }
}

std::optional<CodecError> append_varint(std::vector<std::byte> &bytes, std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value);
    if (!written.has_value()) {
        return written.error();
    }

    append_bytes(bytes, std::span<const std::byte>(encoded.data(), written.value()));
    return std::nullopt;
}

void append_varint_unchecked(std::vector<std::byte> &bytes, std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value).value();
    append_bytes(bytes, std::span<const std::byte>(encoded.data(), written));
}

std::uint8_t quic_bit_mask(bool grease_quic_bit, std::uint64_t seed, std::uint64_t packet_number) {
    if (!grease_quic_bit) {
        return 0x40u;
    }

    auto mixed = seed ^ (packet_number * 0x9e3779b97f4a7c15ull);
    mixed ^= mixed >> 30u;
    mixed *= 0xbf58476d1ce4e5b9ull;
    mixed ^= mixed >> 27u;
    mixed *= 0x94d049bb133111ebull;
    mixed ^= mixed >> 31u;
    return (mixed & 0x01u) != 0 ? 0x40u : 0u;
}

std::byte make_short_header_first_byte(bool spin_bit, bool key_phase,
                                       std::uint8_t packet_number_length, bool grease_quic_bit,
                                       std::uint64_t grease_quic_bit_seed,
                                       std::uint64_t packet_number) {
    return static_cast<std::byte>(
        quic_bit_mask(grease_quic_bit, grease_quic_bit_seed, packet_number) |
        (spin_bit ? 0x20u : 0u) | (key_phase ? 0x04u : 0u) | ((packet_number_length - 1) & 0x03u));
}

void append_packet_number(BufferWriter &writer, TruncatedPacketNumberEncoding encoding) {
    for (std::size_t index = 0; index < encoding.packet_number_length; ++index) {
        const auto shift = static_cast<unsigned>((encoding.packet_number_length - index - 1) * 8);
        writer.write_byte(
            static_cast<std::byte>((encoding.truncated_packet_number >> shift) & 0xffu));
    }
}

void append_packet_number(std::vector<std::byte> &bytes, TruncatedPacketNumberEncoding encoding) {
    for (std::size_t index = 0; index < encoding.packet_number_length; ++index) {
        const auto shift = static_cast<unsigned>((encoding.packet_number_length - index - 1) * 8);
        bytes.push_back(
            static_cast<std::byte>((encoding.truncated_packet_number >> shift) & 0xffu));
    }
}

std::optional<CodecError> write_u32_be(SpanBufferWriter &writer, std::uint32_t value) {
    if (const auto error = writer.write_byte(static_cast<std::byte>((value >> 24) & 0xffu))) {
        return error;
    }
    if (const auto error = writer.write_byte(static_cast<std::byte>((value >> 16) & 0xffu))) {
        return error;
    }
    if (const auto error = writer.write_byte(static_cast<std::byte>((value >> 8) & 0xffu))) {
        return error;
    }
    return writer.write_byte(static_cast<std::byte>(value & 0xffu));
}

std::optional<CodecError> append_packet_number(SpanBufferWriter &writer,
                                               TruncatedPacketNumberEncoding encoding) {
    for (std::size_t index = 0; index < encoding.packet_number_length; ++index) {
        const auto shift = static_cast<unsigned>((encoding.packet_number_length - index - 1) * 8);
        if (const auto error = writer.write_byte(
                static_cast<std::byte>((encoding.truncated_packet_number >> shift) & 0xffu))) {
            return error;
        }
    }
    return std::nullopt;
}

std::size_t minimum_payload_bytes_for_header_sample(std::uint8_t packet_number_length) {
    return packet_number_length >= kHeaderProtectionSampleOffset
               ? 0
               : kHeaderProtectionSampleOffset - packet_number_length;
}

CodecResult<std::size_t> serialized_frame_payload_size(std::span<const Frame> frames) {
    if (frames.empty()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::empty_packet_payload, 0);
    }

    std::size_t total = 0;
    for (const auto &frame : frames) {
        const auto encoded = serialized_frame_size(frame);
        if (!encoded.has_value()) {
            return CodecResult<std::size_t>::failure(encoded.error().code, encoded.error().offset);
        }
        total += encoded.value();
    }

    return CodecResult<std::size_t>::success(total);
}

CodecResult<ConnectionId> read_connection_id(BufferReader &reader, bool enforce_v1_limit) {
    const auto length = read_u8(reader);
    if (!length.has_value()) {
        return CodecResult<ConnectionId>::failure(length.error().code, length.error().offset);
    }
    if (enforce_v1_limit && length.value() > 20) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    const auto bytes = reader.read_exact(length.value());
    if (!bytes.has_value()) {
        return CodecResult<ConnectionId>::failure(bytes.error().code, bytes.error().offset);
    }

    return CodecResult<ConnectionId>::success(ConnectionId{
        bytes.value().begin(),
        bytes.value().end(),
    });
}

CodecResult<bool> skip_connection_id(BufferReader &reader, bool enforce_v1_limit) {
    const auto length = read_u8(reader);
    if (!length.has_value()) {
        return CodecResult<bool>::failure(length.error().code, length.error().offset);
    }
    if (enforce_v1_limit && length.value() > 20) {
        return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    const auto skipped = reader.read_exact(length.value());
    if (!skipped.has_value()) {
        return CodecResult<bool>::failure(skipped.error().code, skipped.error().offset);
    }

    return CodecResult<bool>::success(true);
}

bool frame_allowed_in_long_header_packet_type(const Frame &frame,
                                              LongHeaderPacketType packet_type) {
    const auto is_ack_like =
        std::holds_alternative<AckFrame>(frame) | std::holds_alternative<OutboundAckFrame>(frame);
    if (packet_type == LongHeaderPacketType::zero_rtt) {
        const auto forbidden_in_zero_rtt = is_ack_like |
                                           std::holds_alternative<CryptoFrame>(frame) |
                                           std::holds_alternative<HandshakeDoneFrame>(frame) |
                                           std::holds_alternative<NewTokenFrame>(frame) |
                                           std::holds_alternative<PathResponseFrame>(frame) |
                                           std::holds_alternative<RetireConnectionIdFrame>(frame);
        return !forbidden_in_zero_rtt;
    }

    const auto allowed_in_non_zero_rtt =
        std::holds_alternative<PaddingFrame>(frame) | std::holds_alternative<PingFrame>(frame) |
        is_ack_like | std::holds_alternative<CryptoFrame>(frame) |
        std::holds_alternative<TransportConnectionCloseFrame>(frame);
    return allowed_in_non_zero_rtt;
}

CodecResult<bool> validate_long_header_frames(std::span<const Frame> frames,
                                              LongHeaderPacketType packet_type) {
    for (std::size_t index = 0; index < frames.size(); ++index) {
        if (!frame_allowed_in_long_header_packet_type(frames[index], packet_type)) {
            return CodecResult<bool>::failure(CodecErrorCode::frame_not_allowed_in_packet_type,
                                              index);
        }

        const auto *stream = std::get_if<StreamFrame>(&frames[index]);
        if (stream != nullptr && !stream->has_length && index + 1 != frames.size()) {
            return CodecResult<bool>::failure(CodecErrorCode::packet_length_mismatch, index);
        }
        const auto *datagram = std::get_if<DatagramFrame>(&frames[index]);
        if (datagram != nullptr && !datagram->has_length && index + 1 != frames.size()) {
            return CodecResult<bool>::failure(CodecErrorCode::packet_length_mismatch, index);
        }
    }

    return CodecResult<bool>::success(true);
}

bool frame_allowed_in_protected_payload_packet_type(const ReceivedFrame &frame,
                                                    ProtectedPayloadPacketType packet_type) {
    if (packet_type == ProtectedPayloadPacketType::one_rtt) {
        return true;
    }

    if (packet_type == ProtectedPayloadPacketType::zero_rtt) {
        const auto forbidden_in_zero_rtt = std::holds_alternative<ReceivedAckFrame>(frame) |
                                           std::holds_alternative<ReceivedCryptoFrame>(frame) |
                                           std::holds_alternative<HandshakeDoneFrame>(frame) |
                                           std::holds_alternative<NewTokenFrame>(frame) |
                                           std::holds_alternative<PathResponseFrame>(frame) |
                                           std::holds_alternative<RetireConnectionIdFrame>(frame);
        return !forbidden_in_zero_rtt;
    }

    return std::holds_alternative<PaddingFrame>(frame) | std::holds_alternative<PingFrame>(frame) |
           std::holds_alternative<ReceivedAckFrame>(frame) |
           std::holds_alternative<ReceivedCryptoFrame>(frame) |
           std::holds_alternative<TransportConnectionCloseFrame>(frame);
}

CodecResult<ReceivedFrameList> deserialize_received_frame_sequence(
    const SharedBytes &payload, ProtectedPayloadPacketType packet_type, std::size_t base_offset) {
    if (payload.empty()) {
        return CodecResult<ReceivedFrameList>::failure(CodecErrorCode::empty_packet_payload,
                                                       base_offset);
    }

    ReceivedFrameList frames;
    frames.reserve(1);
    std::size_t offset = 0;
    while (offset < payload.size()) {
        auto decoded = deserialize_received_frame(payload.subspan(offset));
        if (!decoded.has_value()) {
            return CodecResult<ReceivedFrameList>::failure(
                decoded.error().code, base_offset + offset + decoded.error().offset);
        }
        if (!frame_allowed_in_protected_payload_packet_type(decoded.value().frame, packet_type)) {
            return CodecResult<ReceivedFrameList>::failure(
                CodecErrorCode::frame_not_allowed_in_packet_type, base_offset + offset);
        }

        frames.push_back(std::move(decoded.value().frame));
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<ReceivedFrameList>::success(std::move(frames));
}

std::size_t encoded_stream_frame_payload_size(std::uint64_t frame_stream_id,
                                              std::uint64_t frame_offset,
                                              std::size_t payload_size) {
    return 1 + encoded_varint_size(frame_stream_id) + encoded_varint_size(frame_offset) +
           encoded_varint_size(payload_size) + payload_size;
}

CodecResult<std::size_t> serialize_stream_frame_header_into(std::vector<std::byte> &bytes,
                                                            const StreamFrameHeaderFields &header) {
    if (header.offset > kMaxVarInt - header.payload_size) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto begin = bytes.size();
    std::byte type = std::byte{0x08};
    type |= std::byte{0x04};
    type |= std::byte{0x02};
    if (header.fin) {
        type |= std::byte{0x01};
    }

    bytes.push_back(type);
    if (const auto error = append_varint(bytes, header.stream_id)) {
        bytes.resize(begin);
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    append_varint_unchecked(bytes, header.offset);
    append_varint_unchecked(bytes, header.payload_size);
    return CodecResult<std::size_t>::success(bytes.size() - begin);
}

CodecResult<std::size_t> serialize_stream_frame_header_into(SpanBufferWriter &writer,
                                                            const StreamFrameHeaderFields &header) {
    if (header.offset > kMaxVarInt - header.payload_size) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto begin = writer.offset();
    std::byte type = std::byte{0x08};
    type |= std::byte{0x04};
    type |= std::byte{0x02};
    if (header.fin) {
        type |= std::byte{0x01};
    }

    if (const auto error = writer.write_byte(type)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_varint(header.stream_id)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    writer.write_varint_unchecked(header.offset);
    writer.write_varint_unchecked(header.payload_size);
    return CodecResult<std::size_t>::success(writer.offset() - begin);
}

CodecResult<std::size_t> append_stream_frame_payload_into(std::vector<std::byte> &bytes,
                                                          StreamFrameHeaderFields header,
                                                          std::span<const std::byte> payload) {
    const auto begin = bytes.size();
    header.payload_size = payload.size();
    const auto serialized_header = serialize_stream_frame_header_into(bytes, header);
    if (!serialized_header.has_value()) {
        return serialized_header;
    }

    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return CodecResult<std::size_t>::success(bytes.size() - begin);
}

CodecResult<std::size_t> serialize_stream_frame_into(std::span<std::byte> output,
                                                     const StreamFrameHeaderFields &header,
                                                     std::span<const std::byte> payload) {
    SpanBufferWriter writer(output);
    auto adjusted_header = header;
    adjusted_header.payload_size = payload.size();
    const auto serialized_header = serialize_stream_frame_header_into(writer, adjusted_header);
    if (!serialized_header.has_value()) {
        return serialized_header;
    }
    if (const auto error = writer.write_bytes(payload)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    return CodecResult<std::size_t>::success(writer.offset());
}

CodecResult<std::size_t>
append_stream_frame_view_into_datagram(std::vector<std::byte> &bytes,
                                       const StreamFrameView &stream_view) {
    if (stream_view.end < stream_view.begin) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload_size = stream_view.end - stream_view.begin;
    if (payload_size != 0 &&
        (!stream_view.storage || stream_view.end > stream_view.storage->size())) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload =
        payload_size == 0
            ? std::span<const std::byte>{}
            : std::span<const std::byte>(stream_view.storage->data() +
                                             static_cast<std::ptrdiff_t>(stream_view.begin),
                                         payload_size);
    return append_stream_frame_payload_into(bytes,
                                            StreamFrameHeaderFields{
                                                .fin = stream_view.fin,
                                                .stream_id = stream_view.stream_id,
                                                .offset = stream_view.offset,
                                            },
                                            payload);
}

CodecResult<std::size_t>
append_stream_frame_send_fragment_to_datagram(std::vector<std::byte> &bytes,
                                              const StreamFrameSendFragment &fragment) {
    if (fragment.offset > kMaxVarInt - fragment.bytes.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto begin = bytes.size();
    append_bytes(bytes, fragment.stream_frame_header_bytes());
    append_bytes(bytes, fragment.bytes.span());
    return CodecResult<std::size_t>::success(bytes.size() - begin);
}

CodecResult<std::size_t> serialize_stream_frame_view_into_span(std::span<std::byte> output,
                                                               const StreamFrameView &stream_view) {
    if (stream_view.end < stream_view.begin) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload_size = stream_view.end - stream_view.begin;
    if (payload_size != 0 &&
        (!stream_view.storage || stream_view.end > stream_view.storage->size())) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload =
        payload_size == 0
            ? std::span<const std::byte>{}
            : std::span<const std::byte>(stream_view.storage->data() +
                                             static_cast<std::ptrdiff_t>(stream_view.begin),
                                         payload_size);
    return serialize_stream_frame_into(output,
                                       StreamFrameHeaderFields{
                                           .fin = stream_view.fin,
                                           .stream_id = stream_view.stream_id,
                                           .offset = stream_view.offset,
                                       },
                                       payload);
}

CodecResult<std::span<const std::byte>>
stream_frame_view_payload_span(const StreamFrameView &stream_view) {
    if (stream_view.end < stream_view.begin) {
        return CodecResult<std::span<const std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload_size = stream_view.end - stream_view.begin;
    if (payload_size != 0 &&
        (!stream_view.storage || stream_view.end > stream_view.storage->size())) {
        return CodecResult<std::span<const std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }

    return CodecResult<std::span<const std::byte>>::success(
        payload_size == 0
            ? std::span<const std::byte>{}
            : std::span<const std::byte>(stream_view.storage->data() +
                                             static_cast<std::ptrdiff_t>(stream_view.begin),
                                         payload_size));
}

CodecResult<std::size_t> write_stream_frame_view_header_into_span(std::span<std::byte> output,
                                                                  const StreamFrameView &view) {
    if (view.end < view.begin) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    SpanBufferWriter writer(output);
    return serialize_stream_frame_header_into(writer, StreamFrameHeaderFields{
                                                          .fin = view.fin,
                                                          .stream_id = view.stream_id,
                                                          .offset = view.offset,
                                                          .payload_size = view.end - view.begin,
                                                      });
}

CodecResult<std::size_t>
serialize_stream_frame_send_fragment_into_span(std::span<std::byte> output,
                                               const StreamFrameSendFragment &fragment) {
    if (fragment.offset > kMaxVarInt - fragment.bytes.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto header_bytes = fragment.stream_frame_header_bytes();
    if (output.size() < header_bytes.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0);
    }
    std::memcpy(output.data(), header_bytes.data(), header_bytes.size());
    if (output.size() - header_bytes.size() < fragment.bytes.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input,
                                                 header_bytes.size());
    }
    if (!fragment.bytes.empty()) {
        std::memcpy(output.data() + static_cast<std::ptrdiff_t>(header_bytes.size()),
                    fragment.bytes.data(), fragment.bytes.size());
    }

    return CodecResult<std::size_t>::success(header_bytes.size() + fragment.bytes.size());
}

bool long_header_has_token(LongHeaderPacketType packet_type) {
    return packet_type == LongHeaderPacketType::initial;
}

CodecResult<LongHeaderPacketType> read_long_header_type(std::span<const std::byte> bytes,
                                                        bool accept_greased_quic_bit) {
    if (bytes.size() < 5) {
        return CodecResult<LongHeaderPacketType>::failure(CodecErrorCode::truncated_input,
                                                          bytes.size());
    }

    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x40u) == 0 && !accept_greased_quic_bit)
        return CodecResult<LongHeaderPacketType>::failure(CodecErrorCode::invalid_fixed_bit, 0);

    const auto version = read_u32_be(bytes.subspan(1, 4));
    const auto encoded_type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    if (encoded_type == encoded_long_header_type(LongHeaderPacketType::initial, version)) {
        return CodecResult<LongHeaderPacketType>::success(LongHeaderPacketType::initial);
    }
    if (encoded_type == encoded_long_header_type(LongHeaderPacketType::zero_rtt, version)) {
        return CodecResult<LongHeaderPacketType>::success(LongHeaderPacketType::zero_rtt);
    }
    if (encoded_type == encoded_long_header_type(LongHeaderPacketType::handshake, version)) {
        return CodecResult<LongHeaderPacketType>::success(LongHeaderPacketType::handshake);
    }

    return CodecResult<LongHeaderPacketType>::failure(CodecErrorCode::unsupported_packet_type, 0);
}

CodecResult<LongHeaderLayout> locate_long_header(std::span<const std::byte> bytes,
                                                 LongHeaderPacketType expected_type,
                                                 bool accept_greased_quic_bit) {
    BufferReader reader(bytes);
    const auto first_byte = std::to_integer<std::uint8_t>(reader.read_byte().value());
    if ((first_byte & 0x40u) == 0 && !accept_greased_quic_bit) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version_bytes = reader.read_exact(4).value();
    if (!is_supported_quic_version(read_u32_be(version_bytes)))
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::unsupported_packet_type, 0);

    const auto destination_connection_id_length = read_u8(reader);
    if (!destination_connection_id_length.has_value())
        return CodecResult<LongHeaderLayout>::failure(
            destination_connection_id_length.error().code,
            destination_connection_id_length.error().offset);
    if (destination_connection_id_length.value() > 20)
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::invalid_varint,
                                                      reader.offset());
    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length.value());
    if (!destination_connection_id.has_value())
        return CodecResult<LongHeaderLayout>::failure(destination_connection_id.error().code,
                                                      destination_connection_id.error().offset);

    auto source_connection_id = skip_connection_id(reader, /*enforce_v1_limit=*/true);
    if (!source_connection_id.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(source_connection_id.error().code,
                                                      source_connection_id.error().offset);
    }

    if (long_header_has_token(expected_type)) {
        const auto token_length = read_varint(reader);
        if (!token_length.has_value())
            return CodecResult<LongHeaderLayout>::failure(token_length.error().code,
                                                          token_length.error().offset);
        if (token_length.value() > static_cast<std::uint64_t>(reader.remaining()))
            return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::packet_length_mismatch,
                                                          reader.offset());
        reader.read_exact(static_cast<std::size_t>(token_length.value())).value();
    }

    const auto length_offset = reader.offset();
    auto payload_length = decode_varint(reader);
    if (!payload_length.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(payload_length.error().code,
                                                      payload_length.error().offset);
    }

    if (payload_length.value().value > static_cast<std::uint64_t>(reader.remaining()))
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::packet_length_mismatch,
                                                      reader.offset());

    return CodecResult<LongHeaderLayout>::success(LongHeaderLayout{
        .length_offset = length_offset,
        .length_size = payload_length.value().bytes_consumed,
        .length_value = payload_length.value().value,
        .packet_number_offset = reader.offset(),
        .packet_end_offset =
            reader.offset() + static_cast<std::size_t>(payload_length.value().value),
    });
}

CodecResult<PatchedLengthField> patch_long_header_length_field(std::vector<std::byte> &packet_bytes,
                                                               const LongHeaderLayout &layout,
                                                               std::uint64_t new_length_value) {
    std::array<std::byte, 8> encoded_length_bytes{};
    const auto encoded_length = encode_varint_into(encoded_length_bytes, new_length_value);
    if (!encoded_length.has_value()) {
        return CodecResult<PatchedLengthField>::failure(encoded_length.error().code,
                                                        encoded_length.error().offset);
    }
    const auto encoded_length_span =
        std::span<const std::byte>(encoded_length_bytes.data(), encoded_length.value());

    packet_bytes.erase(packet_bytes.begin() + static_cast<std::ptrdiff_t>(layout.length_offset),
                       packet_bytes.begin() +
                           static_cast<std::ptrdiff_t>(layout.length_offset + layout.length_size));
    packet_bytes.insert(packet_bytes.begin() + static_cast<std::ptrdiff_t>(layout.length_offset),
                        encoded_length_span.begin(), encoded_length_span.end());

    return CodecResult<PatchedLengthField>::success(PatchedLengthField{
        .packet_number_offset = layout.length_offset + encoded_length.value(),
    });
}

std::uint32_t read_packet_number(std::span<const std::byte> bytes,
                                 std::uint8_t packet_number_length) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < packet_number_length; ++index) {
        value = (value << 8) | std::to_integer<std::uint8_t>(bytes[index]);
    }
    return value;
}

EndpointRole opposite_endpoint_role(EndpointRole role) {
    return static_cast<EndpointRole>(1u - static_cast<std::uint8_t>(role));
}

CodecResult<PacketProtectionKeys>
derive_send_initial_keys(const SerializeProtectionContext &context, std::uint32_t version) {
    if (context.client_initial_destination_connection_id.empty()) {
        return CodecResult<PacketProtectionKeys>::failure(CodecErrorCode::missing_crypto_context,
                                                          0);
    }

    return derive_initial_packet_keys(context.local_role, true,
                                      context.client_initial_destination_connection_id, version);
}

CodecResult<PacketProtectionKeys>
derive_receive_initial_keys(const DeserializeProtectionContext &context, std::uint32_t version) {
    if (context.client_initial_destination_connection_id.empty()) {
        return CodecResult<PacketProtectionKeys>::failure(CodecErrorCode::missing_crypto_context,
                                                          0);
    }

    return derive_initial_packet_keys(opposite_endpoint_role(context.peer_role), false,
                                      context.client_initial_destination_connection_id, version);
}

CodecResult<InitialPacket> to_plaintext_initial(const ProtectedInitialPacket &packet) {
    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<InitialPacket>::failure(truncated_packet_number.error().code,
                                                   truncated_packet_number.error().offset);
    }

    return CodecResult<InitialPacket>::success(InitialPacket{
        .version = packet.version,
        .destination_connection_id = packet.destination_connection_id,
        .source_connection_id = packet.source_connection_id,
        .token = packet.token,
        .packet_number_length = packet.packet_number_length,
        .truncated_packet_number = truncated_packet_number.value(),
        .frames = packet.frames,
    });
}

CodecResult<HandshakePacket> to_plaintext_handshake(const ProtectedHandshakePacket &packet) {
    if (!is_supported_quic_version(packet.version)) {
        return CodecResult<HandshakePacket>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<HandshakePacket>::failure(truncated_packet_number.error().code,
                                                     truncated_packet_number.error().offset);
    }

    return CodecResult<HandshakePacket>::success(HandshakePacket{
        .version = packet.version,
        .destination_connection_id = packet.destination_connection_id,
        .source_connection_id = packet.source_connection_id,
        .packet_number_length = packet.packet_number_length,
        .truncated_packet_number = truncated_packet_number.value(),
        .frames = packet.frames,
    });
}

CodecResult<ZeroRttPacket> to_plaintext_zero_rtt(const ProtectedZeroRttPacket &packet) {
    if (!is_supported_quic_version(packet.version)) {
        return CodecResult<ZeroRttPacket>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<ZeroRttPacket>::failure(truncated_packet_number.error().code,
                                                   truncated_packet_number.error().offset);
    }

    return CodecResult<ZeroRttPacket>::success(ZeroRttPacket{
        .version = packet.version,
        .destination_connection_id = packet.destination_connection_id,
        .source_connection_id = packet.source_connection_id,
        .packet_number_length = packet.packet_number_length,
        .truncated_packet_number = truncated_packet_number.value(),
        .frames = packet.frames,
    });
}

CodecResult<OneRttPacket> to_plaintext_one_rtt(const ProtectedOneRttPacket &packet) {
    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<OneRttPacket>::failure(truncated_packet_number.error().code,
                                                  truncated_packet_number.error().offset);
    }

    return CodecResult<OneRttPacket>::success(OneRttPacket{
        .spin_bit = packet.spin_bit,
        .key_phase = packet.key_phase,
        .destination_connection_id = packet.destination_connection_id,
        .packet_number_length = packet.packet_number_length,
        .truncated_packet_number = truncated_packet_number.value(),
        .frames = packet.frames,
    });
}

CodecResult<bool> apply_long_header_protection_in_place(std::span<std::byte> packet_bytes,
                                                        PacketNumberSpan packet_number,
                                                        CipherSuite cipher_suite,
                                                        const PacketProtectionKeys &keys) {
    std::array<std::byte, 5> mask{};
    const auto mask_written = make_header_protection_mask_into(
        cipher_suite,
        HeaderProtectionMaskInput{
            .hp_key = keys.hp_key,
            .sample =
                std::span<const std::byte>(packet_bytes)
                    .subspan(packet_number.packet_number_offset + kHeaderProtectionSampleOffset),
        },
        mask);
    if (!mask_written.has_value()) {
        return CodecResult<bool>::failure(mask_written.error().code, mask_written.error().offset);
    }

    packet_bytes[0] ^= static_cast<std::byte>(std::to_integer<std::uint8_t>(mask[0]) & 0x0fu);
    for (std::size_t index = 0; index < packet_number.packet_number_length; ++index) {
        packet_bytes[packet_number.packet_number_offset + index] ^= mask[index + 1];
    }

    return CodecResult<bool>::success(true);
}

CodecResult<RemovedLongHeaderProtection>
remove_long_header_protection(std::span<const std::byte> bytes, const LongHeaderLayout &layout,
                              CipherSuite cipher_suite, const PacketProtectionKeys &keys) {
    const auto sample_too_short =
        (layout.packet_end_offset > bytes.size()) |
        (layout.packet_number_offset + kHeaderProtectionSampleOffset > layout.packet_end_offset);
    if (sample_too_short)
        return CodecResult<RemovedLongHeaderProtection>::failure(
            CodecErrorCode::header_protection_sample_too_short, 0);

    std::vector<std::byte> packet_bytes(
        bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(layout.packet_end_offset));
    std::array<std::byte, 5> mask{};
    const auto mask_written = make_header_protection_mask_into(
        cipher_suite,
        HeaderProtectionMaskInput{
            .hp_key = keys.hp_key,
            .sample = std::span<const std::byte>(packet_bytes)
                          .subspan(layout.packet_number_offset + kHeaderProtectionSampleOffset),
        },
        mask);
    if (!mask_written.has_value())
        return CodecResult<RemovedLongHeaderProtection>::failure(mask_written.error().code,
                                                                 mask_written.error().offset);

    packet_bytes[0] ^= static_cast<std::byte>(std::to_integer<std::uint8_t>(mask[0]) & 0x0fu);
    auto packet_number_length =
        static_cast<std::uint8_t>((std::to_integer<std::uint8_t>(packet_bytes[0]) & 0x03u) + 1u);
    if (consume_protected_codec_fault(
            test::ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch) |
        (layout.length_value < packet_number_length) |
        (layout.packet_number_offset + packet_number_length > packet_bytes.size())) {
        return CodecResult<RemovedLongHeaderProtection>::failure(
            CodecErrorCode::packet_length_mismatch, layout.packet_number_offset);
    }

    for (std::size_t index = 0; index < packet_number_length; ++index) {
        packet_bytes[layout.packet_number_offset + index] ^= mask[index + 1];
    }

    const auto truncated_packet_number = read_packet_number(
        std::span<const std::byte>(packet_bytes).subspan(layout.packet_number_offset),
        packet_number_length);

    return CodecResult<RemovedLongHeaderProtection>::success(RemovedLongHeaderProtection{
        .packet_bytes = std::move(packet_bytes),
        .packet_number_length = packet_number_length,
        .truncated_packet_number = truncated_packet_number,
    });
}

CodecResult<bool> apply_short_header_protection_in_place(std::span<std::byte> packet_bytes,
                                                         PacketNumberSpan packet_number,
                                                         CipherSuite cipher_suite,
                                                         const PacketProtectionKeys &keys) {
    std::array<std::byte, 5> mask{};
    const auto mask_written = make_header_protection_mask_into(
        cipher_suite,
        HeaderProtectionMaskInput{
            .hp_key = keys.hp_key,
            .sample =
                std::span<const std::byte>(packet_bytes)
                    .subspan(packet_number.packet_number_offset + kHeaderProtectionSampleOffset),
        },
        mask);
    if (!mask_written.has_value()) {
        return CodecResult<bool>::failure(mask_written.error().code, mask_written.error().offset);
    }

    packet_bytes[0] ^= static_cast<std::byte>(std::to_integer<std::uint8_t>(mask[0]) & 0x1fu);
    for (std::size_t index = 0; index < packet_number.packet_number_length; ++index) {
        packet_bytes[packet_number.packet_number_offset + index] ^= mask[index + 1];
    }

    return CodecResult<bool>::success(true);
}

CodecResult<RemovedShortHeaderProtection>
remove_short_header_protection(std::span<const std::byte> bytes, std::size_t packet_number_offset,
                               CipherSuite cipher_suite, const PacketProtectionKeys &keys) {
    if (packet_number_offset + kHeaderProtectionSampleOffset > bytes.size())
        return CodecResult<RemovedShortHeaderProtection>::failure(
            CodecErrorCode::header_protection_sample_too_short, 0);

    std::array<std::byte, 5> mask{};
    const auto mask_written = [&] {
        COQUIC_DESERIALIZE_PROFILE_TIMER(timer, short_header_mask_ns);
        return make_header_protection_mask_into(
            cipher_suite,
            HeaderProtectionMaskInput{
                .hp_key = keys.hp_key,
                .sample = bytes.subspan(packet_number_offset + kHeaderProtectionSampleOffset),
            },
            mask);
    }();
    if (!mask_written.has_value())
        return CodecResult<RemovedShortHeaderProtection>::failure(mask_written.error().code,
                                                                  mask_written.error().offset);

    const auto first_byte =
        bytes[0] ^ static_cast<std::byte>(std::to_integer<std::uint8_t>(mask[0]) & 0x1fu);
    auto packet_number_length =
        static_cast<std::uint8_t>((std::to_integer<std::uint8_t>(first_byte) & 0x03u) + 1u);
    if (consume_protected_codec_fault(
            test::ProtectedCodecFaultPoint::remove_short_header_packet_length_mismatch) |
        (packet_number_offset + packet_number_length > bytes.size())) {
        return CodecResult<RemovedShortHeaderProtection>::failure(
            CodecErrorCode::packet_length_mismatch, packet_number_offset);
    }

    const auto header_end = packet_number_offset + packet_number_length;
    RemovedShortHeaderProtection removed;
    removed.plaintext_header_size = header_end;
    removed.packet_number_length = packet_number_length;
    if (consume_protected_codec_fault(
            test::ProtectedCodecFaultPoint::remove_short_header_plaintext_header_overflow) |
        (header_end > removed.plaintext_header.size())) {
        return CodecResult<RemovedShortHeaderProtection>::failure(
            CodecErrorCode::malformed_short_header_context, packet_number_offset);
    }

    std::copy_n(bytes.begin(), header_end, removed.plaintext_header.begin());
    removed.plaintext_header[0] = first_byte;
    for (std::size_t index = 0; index < packet_number_length; ++index) {
        removed.plaintext_header[packet_number_offset + index] ^= mask[index + 1];
    }

    const auto truncated_packet_number = read_packet_number(
        removed.plaintext_header_span().subspan(packet_number_offset), packet_number_length);
    removed.truncated_packet_number = truncated_packet_number;

    return CodecResult<RemovedShortHeaderProtection>::success(removed);
}

LongHeaderLayout locate_long_header_or_assert(std::span<const std::byte> bytes,
                                              LongHeaderPacketType expected_type,
                                              bool accept_greased_quic_bit) {
    return locate_long_header(bytes, expected_type, accept_greased_quic_bit).value();
}

PatchedLengthField patch_long_header_length_field_or_assert(std::vector<std::byte> &packet_bytes,
                                                            const LongHeaderLayout &layout,
                                                            std::uint64_t new_length_value) {
    return patch_long_header_length_field(packet_bytes, layout, new_length_value).value();
}

COQUIC_NO_PROFILE std::span<const std::byte>
make_packet_protection_nonce_or_assert(std::span<const std::byte> iv, std::uint64_t packet_number,
                                       std::span<std::byte> storage) {
    abort_if(storage.size() < iv.size());

    auto nonce = storage.first(iv.size());
    std::copy(iv.begin(), iv.end(), nonce.begin());
    auto packet_number_value = packet_number;
    for (std::size_t index = 0; index < sizeof(packet_number) && index < nonce.size(); ++index) {
        const auto nonce_index = nonce.size() - 1 - index;
        nonce[nonce_index] ^= static_cast<std::byte>(packet_number_value & 0xffu);
        packet_number_value >>= 8;
    }

    return std::span<const std::byte>(nonce);
}

std::vector<std::byte> make_packet_protection_nonce_or_assert(std::span<const std::byte> iv,
                                                              std::uint64_t packet_number) {
    return make_packet_protection_nonce(PacketProtectionNonceInput{
                                            .iv = iv,
                                            .packet_number = packet_number,
                                        })
        .value();
}

CodecResult<PacketDecodeResult>
deserialize_plaintext_packet_image(std::span<const std::byte> plaintext_image,
                                   const DeserializeOptions &options) {
    if (consume_protected_codec_fault(test::ProtectedCodecFaultPoint::deserialize_plaintext_packet))
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::invalid_varint, 0);

    return deserialize_packet(plaintext_image, options);
}

CodecResult<ReceivedStreamFrame>
try_decode_single_received_stream_frame_value_fast(const SharedBytes &plaintext_payload,
                                                   std::size_t base_offset) {
    const auto payload = plaintext_payload.span();
    if (payload.empty()) {
        return CodecResult<ReceivedStreamFrame>::failure(CodecErrorCode::empty_packet_payload,
                                                         base_offset);
    }

    const auto frame_type = std::to_integer<std::uint8_t>(payload.front());
    if (frame_type < 0x08u || frame_type > 0x0fu) {
        return CodecResult<ReceivedStreamFrame>::failure(CodecErrorCode::unknown_frame_type,
                                                         base_offset);
    }

    std::size_t offset = 1;
    const auto read_small_varint = [&](std::uint64_t &value) -> bool {
        if (offset >= payload.size()) {
            return false;
        }
        const auto first = std::to_integer<std::uint8_t>(payload[offset]);
        const auto length = std::size_t{1} << (first >> 6u);
        if (payload.size() - offset < length) {
            return false;
        }

        value = first & 0x3fu;
        for (std::size_t index = 1; index < length; ++index) {
            value = (value << 8u) | std::to_integer<std::uint8_t>(payload[offset + index]);
        }
        offset += length;
        return true;
    };

    std::uint64_t stream_id = 0;
    if (!read_small_varint(stream_id)) {
        return CodecResult<ReceivedStreamFrame>::failure(CodecErrorCode::truncated_input,
                                                         base_offset + offset);
    }

    std::uint64_t stream_offset = 0;
    if ((frame_type & 0x04u) != 0) {
        if (!read_small_varint(stream_offset)) {
            return CodecResult<ReceivedStreamFrame>::failure(CodecErrorCode::truncated_input,
                                                             base_offset + offset);
        }
    }

    std::size_t stream_data_size = payload.size() - offset;
    if ((frame_type & 0x02u) != 0) {
        std::uint64_t length = 0;
        if (!read_small_varint(length)) {
            return CodecResult<ReceivedStreamFrame>::failure(CodecErrorCode::truncated_input,
                                                             base_offset + offset);
        }
        if (length > static_cast<std::uint64_t>(payload.size() - offset)) {
            return CodecResult<ReceivedStreamFrame>::failure(CodecErrorCode::truncated_input,
                                                             base_offset + offset);
        }
        stream_data_size = static_cast<std::size_t>(length);
        if (stream_data_size != payload.size() - offset) {
            return CodecResult<ReceivedStreamFrame>::failure(
                CodecErrorCode::unknown_frame_type, base_offset + offset + stream_data_size);
        }
    }

    if (stream_offset > kMaxVarInt - stream_data_size) {
        return CodecResult<ReceivedStreamFrame>::failure(CodecErrorCode::invalid_varint,
                                                         base_offset + offset);
    }

    return CodecResult<ReceivedStreamFrame>::success(ReceivedStreamFrame{
        .fin = (frame_type & 0x01u) != 0,
        .has_offset = (frame_type & 0x04u) != 0,
        .has_length = (frame_type & 0x02u) != 0,
        .stream_id = stream_id,
        .offset =
            (frame_type & 0x04u) != 0 ? std::optional<std::uint64_t>(stream_offset) : std::nullopt,
        .stream_data = plaintext_payload.subspan(offset, stream_data_size),
    });
}

CodecResult<ReceivedFrameList>
try_decode_single_received_stream_frame_fast(const SharedBytes &plaintext_payload,
                                             std::size_t base_offset) {
    auto stream =
        try_decode_single_received_stream_frame_value_fast(plaintext_payload, base_offset);
    if (!stream.has_value()) {
        return CodecResult<ReceivedFrameList>::failure(stream.error().code, stream.error().offset);
    }
    ReceivedFrameList frames;
    frames.emplace_back(std::move(stream.value()));
    return CodecResult<ReceivedFrameList>::success(std::move(frames));
}

CodecResult<std::vector<std::byte>>
build_long_header_plaintext_header(const RemovedLongHeaderProtection &unprotected,
                                   const LongHeaderLayout &layout,
                                   std::size_t plaintext_payload_size) {
    const auto header_end = layout.packet_number_offset + unprotected.packet_number_length;
    std::vector<std::byte> plaintext_header(unprotected.packet_bytes.begin(),
                                            unprotected.packet_bytes.begin() +
                                                static_cast<std::ptrdiff_t>(header_end));
    const auto patched = patch_long_header_length_field(
        plaintext_header, layout, unprotected.packet_number_length + plaintext_payload_size);
    if (!patched.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(patched.error().code,
                                                            patched.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(plaintext_header));
}

struct ParsedShortHeaderPlaintext {
    std::uint8_t first_byte = 0;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 0;

    bool spin_bit() const {
        return (first_byte & 0x20u) != 0;
    }
    bool key_phase() const {
        return (first_byte & 0x04u) != 0;
    }
};

CodecResult<ParsedShortHeaderPlaintext>
parse_short_header_plaintext(std::span<const std::byte> plaintext_header,
                             bool accept_greased_quic_bit) {
    BufferReader reader(plaintext_header);
    const auto first_byte = read_u8(reader);
    if (!first_byte.has_value()) {
        return CodecResult<ParsedShortHeaderPlaintext>::failure(first_byte.error().code,
                                                                first_byte.error().offset);
    }
    if ((first_byte.value() & 0x40u) == 0 && !accept_greased_quic_bit) {
        return CodecResult<ParsedShortHeaderPlaintext>::failure(CodecErrorCode::invalid_fixed_bit,
                                                                0);
    }
    if ((first_byte.value() & 0x18u) != 0) {
        return CodecResult<ParsedShortHeaderPlaintext>::failure(
            CodecErrorCode::invalid_reserved_bits, 0);
    }

    const auto packet_number_length = static_cast<std::uint8_t>((first_byte.value() & 0x03u) + 1u);
    if (reader.remaining() < packet_number_length) {
        return CodecResult<ParsedShortHeaderPlaintext>::failure(
            CodecErrorCode::packet_length_mismatch, reader.offset());
    }

    const auto destination_connection_id_length = reader.remaining() - packet_number_length;
    auto destination_connection_id = reader.read_exact(destination_connection_id_length).value();
    static_cast<void>(reader.read_exact(packet_number_length).value());

    return CodecResult<ParsedShortHeaderPlaintext>::success(ParsedShortHeaderPlaintext{
        .first_byte = first_byte.value(),
        .destination_connection_id =
            ConnectionId{destination_connection_id.begin(), destination_connection_id.end()},
        .packet_number_length = packet_number_length,
    });
}

CodecResult<ReceivedLongHeaderPacketFields> decode_received_long_header_packet_fields(
    std::span<const std::byte> plaintext_header, const SharedBytes &plaintext_payload,
    ProtectedPayloadPacketType packet_type, bool has_token, bool accept_greased_quic_bit) {
    BufferReader reader(plaintext_header);
    const auto first_byte = read_u8(reader);
    if (!first_byte.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(first_byte.error().code,
                                                                    first_byte.error().offset);
    }
    if ((first_byte.value() & 0x40u) == 0 && !accept_greased_quic_bit) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            CodecErrorCode::invalid_fixed_bit, 0);
    }
    if ((first_byte.value() & 0x0cu) != 0) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            CodecErrorCode::invalid_reserved_bits, 0);
    }

    const auto version_bytes = reader.read_exact(4);
    if (!version_bytes.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(version_bytes.error().code,
                                                                    version_bytes.error().offset);
    }
    const auto version = read_u32_be(version_bytes.value());

    auto destination_connection_id = read_connection_id(reader, version == kQuicVersion1);
    if (!destination_connection_id.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            destination_connection_id.error().code, destination_connection_id.error().offset);
    }

    const auto source_connection_id = read_connection_id(reader, version == kQuicVersion1);
    if (!source_connection_id.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            source_connection_id.error().code, source_connection_id.error().offset);
    }

    std::vector<std::byte> token;
    if (has_token) {
        const auto token_length = read_varint(reader);
        if (!token_length.has_value()) {
            return CodecResult<ReceivedLongHeaderPacketFields>::failure(
                token_length.error().code, token_length.error().offset);
        }
        if (token_length.value() > static_cast<std::uint64_t>(reader.remaining())) {
            return CodecResult<ReceivedLongHeaderPacketFields>::failure(
                CodecErrorCode::packet_length_mismatch, reader.offset());
        }

        const auto token_bytes =
            reader.read_exact(static_cast<std::size_t>(token_length.value())).value();
        token.assign(token_bytes.begin(), token_bytes.end());
    }

    const auto payload_length = read_varint(reader);
    if (!payload_length.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(payload_length.error().code,
                                                                    payload_length.error().offset);
    }

    const auto packet_number_length = static_cast<std::uint8_t>((first_byte.value() & 0x03u) + 1u);
    if (payload_length.value() !=
        static_cast<std::uint64_t>(packet_number_length + plaintext_payload.size())) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            CodecErrorCode::packet_length_mismatch, reader.offset());
    }

    const auto packet_number_bytes = reader.read_exact(packet_number_length);
    if (!packet_number_bytes.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            packet_number_bytes.error().code, packet_number_bytes.error().offset);
    }

    auto frames =
        deserialize_received_frame_sequence(plaintext_payload, packet_type, reader.offset());
    if (!frames.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(frames.error().code,
                                                                    frames.error().offset);
    }

    return CodecResult<ReceivedLongHeaderPacketFields>::success(ReceivedLongHeaderPacketFields{
        .version = version,
        .destination_connection_id = destination_connection_id.value(),
        .source_connection_id = source_connection_id.value(),
        .token = std::move(token),
        .packet_number_length = packet_number_length,
        .frames = std::move(frames.value()),
    });
}

CodecResult<ReceivedShortHeaderPacketFields>
decode_received_short_header_packet_fields(std::span<const std::byte> plaintext_header,
                                           const SharedBytes &plaintext_payload,
                                           bool accept_greased_quic_bit) {
    auto header = parse_short_header_plaintext(plaintext_header, accept_greased_quic_bit);
    if (!header.has_value()) {
        return CodecResult<ReceivedShortHeaderPacketFields>::failure(header.error().code,
                                                                     header.error().offset);
    }

    auto frames =
        try_decode_single_received_stream_frame_fast(plaintext_payload, plaintext_header.size());
    if (!frames.has_value()) {
        frames = deserialize_received_frame_sequence(
            plaintext_payload, ProtectedPayloadPacketType::one_rtt, plaintext_header.size());
    }
    if (!frames.has_value()) {
        return CodecResult<ReceivedShortHeaderPacketFields>::failure(frames.error().code,
                                                                     frames.error().offset);
    }

    return CodecResult<ReceivedShortHeaderPacketFields>::success(ReceivedShortHeaderPacketFields{
        .spin_bit = header.value().spin_bit(),
        .key_phase = header.value().key_phase(),
        .destination_connection_id = std::move(header.value().destination_connection_id),
        .packet_number_length = header.value().packet_number_length,
        .frames = std::move(frames.value()),
    });
}

CodecResult<ReceivedShortHeaderAckOnlyPacketFields>
try_decode_received_short_header_ack_only_packet_fields(std::span<const std::byte> plaintext_header,
                                                        const SharedBytes &plaintext_payload,
                                                        bool accept_greased_quic_bit) {
    const auto payload = plaintext_payload.span();
    if (payload.empty() ||
        (payload.front() != std::byte{0x02} && payload.front() != std::byte{0x03})) {
        return CodecResult<ReceivedShortHeaderAckOnlyPacketFields>::failure(
            CodecErrorCode::unknown_frame_type, plaintext_header.size());
    }

    auto header = parse_short_header_plaintext(plaintext_header, accept_greased_quic_bit);
    if (!header.has_value()) {
        return CodecResult<ReceivedShortHeaderAckOnlyPacketFields>::failure(header.error().code,
                                                                            header.error().offset);
    }

    auto ack_result = deserialize_received_ack_frame(plaintext_payload);
    if (!ack_result.has_value()) {
        return CodecResult<ReceivedShortHeaderAckOnlyPacketFields>::failure(
            ack_result.error().code, plaintext_header.size() + ack_result.error().offset);
    }
    if (ack_result.value().bytes_consumed != plaintext_payload.size()) {
        return CodecResult<ReceivedShortHeaderAckOnlyPacketFields>::failure(
            CodecErrorCode::unknown_frame_type,
            plaintext_header.size() + ack_result.value().bytes_consumed);
    }

    return CodecResult<ReceivedShortHeaderAckOnlyPacketFields>::success(
        ReceivedShortHeaderAckOnlyPacketFields{
            .spin_bit = header.value().spin_bit(),
            .key_phase = header.value().key_phase(),
            .destination_connection_id = std::move(header.value().destination_connection_id),
            .packet_number_length = header.value().packet_number_length,
            .ack = std::move(ack_result.value().frame),
        });
}

CodecResult<ReceivedShortHeaderAckOnlyFastPacketFields>
try_decode_received_short_header_ack_only_fast_packet_fields(
    std::span<const std::byte> plaintext_header, const SharedBytes &plaintext_payload,
    bool accept_greased_quic_bit) {
    const auto payload = plaintext_payload.span();
    if (payload.empty() ||
        (payload.front() != std::byte{0x02} && payload.front() != std::byte{0x03})) {
        return CodecResult<ReceivedShortHeaderAckOnlyFastPacketFields>::failure(
            CodecErrorCode::unknown_frame_type, plaintext_header.size());
    }

    auto header = parse_short_header_plaintext(plaintext_header, accept_greased_quic_bit);
    if (!header.has_value()) {
        return CodecResult<ReceivedShortHeaderAckOnlyFastPacketFields>::failure(
            header.error().code, header.error().offset);
    }

    auto ack_result = deserialize_received_ack_frame(plaintext_payload);
    if (!ack_result.has_value()) {
        return CodecResult<ReceivedShortHeaderAckOnlyFastPacketFields>::failure(
            ack_result.error().code, plaintext_header.size() + ack_result.error().offset);
    }
    if (ack_result.value().bytes_consumed != plaintext_payload.size()) {
        return CodecResult<ReceivedShortHeaderAckOnlyFastPacketFields>::failure(
            CodecErrorCode::unknown_frame_type,
            plaintext_header.size() + ack_result.value().bytes_consumed);
    }

    return CodecResult<ReceivedShortHeaderAckOnlyFastPacketFields>::success(
        ReceivedShortHeaderAckOnlyFastPacketFields{
            .spin_bit = header.value().spin_bit(),
            .key_phase = header.value().key_phase(),
            .destination_connection_id = std::move(header.value().destination_connection_id),
            .packet_number_length = header.value().packet_number_length,
            .ack = std::move(ack_result.value().frame),
        });
}

CodecResult<ReceivedShortHeaderStreamFastPacketFields>
try_decode_received_short_header_stream_fast_packet_fields(
    std::span<const std::byte> plaintext_header, const SharedBytes &plaintext_payload,
    bool accept_greased_quic_bit) {
    const auto payload = plaintext_payload.span();
    if (payload.empty()) {
        return CodecResult<ReceivedShortHeaderStreamFastPacketFields>::failure(
            CodecErrorCode::empty_packet_payload, plaintext_header.size());
    }
    const auto frame_type = std::to_integer<std::uint8_t>(payload.front());
    if (frame_type < 0x08u || frame_type > 0x0fu) {
        return CodecResult<ReceivedShortHeaderStreamFastPacketFields>::failure(
            CodecErrorCode::unknown_frame_type, plaintext_header.size());
    }

    auto header = parse_short_header_plaintext(plaintext_header, accept_greased_quic_bit);
    if (!header.has_value()) {
        return CodecResult<ReceivedShortHeaderStreamFastPacketFields>::failure(
            header.error().code, header.error().offset);
    }

    auto stream = try_decode_single_received_stream_frame_value_fast(plaintext_payload,
                                                                     plaintext_header.size());
    if (!stream.has_value()) {
        return CodecResult<ReceivedShortHeaderStreamFastPacketFields>::failure(
            stream.error().code, stream.error().offset);
    }

    return CodecResult<ReceivedShortHeaderStreamFastPacketFields>::success(
        ReceivedShortHeaderStreamFastPacketFields{
            .spin_bit = header.value().spin_bit(),
            .key_phase = header.value().key_phase(),
            .destination_connection_id = std::move(header.value().destination_connection_id),
            .packet_number_length = header.value().packet_number_length,
            .stream = std::move(stream.value()),
        });
}

template <typename PacketFactory>
CodecResult<ReceivedProtectedPacketDecodeResult> deserialize_received_long_header_packet(
    std::span<const std::byte> bytes, const DeserializeProtectionContext &context,
    LongHeaderPacketType long_header_type, ProtectedPayloadPacketType packet_type,
    CipherSuite cipher_suite, const PacketProtectionKeys &keys,
    std::optional<std::uint64_t> largest_authenticated_packet_number, bool has_token,
    PacketFactory make_packet) {
    const auto layout =
        locate_long_header(bytes, long_header_type, context.accept_greased_quic_bit);
    if (!layout.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                         layout.error().offset);
    }

    auto unprotected = remove_long_header_protection(bytes, layout.value(), cipher_suite, keys);
    if (!unprotected.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            unprotected.error().code, unprotected.error().offset);
    }

    auto packet_number = recover_packet_number(largest_authenticated_packet_number,
                                               unprotected.value().truncated_packet_number,
                                               unprotected.value().packet_number_length);
    if (!packet_number.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            packet_number.error().code, packet_number.error().offset);
    }

    auto header_end =
        layout.value().packet_number_offset + unprotected.value().packet_number_length;
    std::array<std::byte, 32> nonce_storage;
    auto nonce =
        make_packet_protection_nonce_or_assert(keys.iv, packet_number.value(), nonce_storage);
    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys.key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext = std::span<const std::byte>(unprotected.value().packet_bytes)
                          .subspan(header_end, layout.value().packet_end_offset - header_end),
    });
    if (!plaintext.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                         plaintext.error().offset);
    }

    auto plaintext_storage = std::make_shared<std::vector<std::byte>>(std::move(plaintext.value()));
    auto plaintext_header = build_long_header_plaintext_header(unprotected.value(), layout.value(),
                                                               plaintext_storage->size())
                                .value();

    auto decoded_fields = decode_received_long_header_packet_fields(
        plaintext_header, SharedBytes(plaintext_storage, 0, plaintext_storage->size()), packet_type,
        has_token, context.accept_greased_quic_bit);
    if (!decoded_fields.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            decoded_fields.error().code, decoded_fields.error().offset);
    }

    return CodecResult<ReceivedProtectedPacketDecodeResult>::success(
        ReceivedProtectedPacketDecodeResult{
            .packet = make_packet(decoded_fields.value(), packet_number.value(), plaintext_storage),
            .bytes_consumed = layout.value().packet_end_offset,
        });
}

CodecResult<std::size_t> append_protected_long_header_packet_to_datagram(
    std::vector<std::byte> &out_datagram, LongHeaderPacketType packet_type, std::uint32_t version,
    const ConnectionId &destination_connection_id, const ConnectionId &source_connection_id,
    std::span<const std::byte> token, TruncatedPacketNumberEncoding packet_number,
    std::uint64_t full_packet_number, std::span<const Frame> frames,
    CipherSuite packet_cipher_suite, const PacketProtectionKeys &keys, bool grease_quic_bit,
    std::uint64_t grease_quic_bit_seed) {
    auto datagram_begin = out_datagram.size();
    const auto rollback = [&]() { out_datagram.resize(datagram_begin); };

    if (version == kVersionNegotiationVersion) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    if (version == kQuicVersion1 &&
        (destination_connection_id.size() > 20 || source_connection_id.size() > 20)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto valid_frames = validate_long_header_frames(frames, packet_type);
    if (!valid_frames.has_value()) {
        return CodecResult<std::size_t>::failure(valid_frames.error().code,
                                                 valid_frames.error().offset);
    }

    const auto frame_payload_size = serialized_frame_payload_size(frames);
    if (!frame_payload_size.has_value()) {
        return CodecResult<std::size_t>::failure(frame_payload_size.error().code,
                                                 frame_payload_size.error().offset);
    }

    if (frame_payload_size.value() > kMaxVarInt) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }
    if (packet_type == LongHeaderPacketType::initial && token.size() > kMaxVarInt) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto plaintext_payload_size =
        std::max(frame_payload_size.value(),
                 minimum_payload_bytes_for_header_sample(packet_number.packet_number_length));
    auto payload_length = static_cast<std::uint64_t>(
        packet_number.packet_number_length + plaintext_payload_size + kPacketProtectionTagLength);
    if (payload_length > kMaxVarInt) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto token_size = packet_type == LongHeaderPacketType::initial
                                ? encoded_varint_size(token.size()) + token.size()
                                : 0u;
    auto length_size = encoded_varint_size(payload_length);
    auto packet_number_offset = 1 + 4 + 1 + destination_connection_id.size() + 1 +
                                source_connection_id.size() + token_size + length_size;
    auto header_end = packet_number_offset + packet_number.packet_number_length;
    auto packet_size = header_end + plaintext_payload_size + kPacketProtectionTagLength;

    out_datagram.resize(datagram_begin + packet_size);
    auto packet_bytes = std::span<std::byte>(out_datagram).subspan(datagram_begin, packet_size);

    SpanBufferWriter writer(packet_bytes.first(header_end));
    abort_if(
        writer
            .write_byte(static_cast<std::byte>(
                0x80u | quic_bit_mask(grease_quic_bit, grease_quic_bit_seed, full_packet_number) |
                ((encoded_long_header_type(packet_type, version) & 0x03u) << 4) |
                ((packet_number.packet_number_length - 1) & 0x03u)))
            .has_value());
    abort_if(write_u32_be(writer, version).has_value());
    abort_if(
        writer.write_byte(static_cast<std::byte>(destination_connection_id.size())).has_value());
    abort_if(writer.write_bytes(destination_connection_id).has_value());
    abort_if(writer.write_byte(static_cast<std::byte>(source_connection_id.size())).has_value());
    abort_if(writer.write_bytes(source_connection_id).has_value());
    if (packet_type == LongHeaderPacketType::initial) {
        writer.write_varint_unchecked(token.size());
        abort_if(writer.write_bytes(token).has_value());
    }
    writer.write_varint_unchecked(payload_length);
    abort_if(append_packet_number(writer, packet_number).has_value());

    auto payload_bytes = packet_bytes.subspan(header_end, plaintext_payload_size);
    std::size_t payload_offset = 0;
    for (const auto &frame : frames) {
        payload_offset +=
            write_frame_wire_bytes(payload_bytes.subspan(payload_offset), frame).value();
    }

    std::array<std::byte, 32> nonce_storage;
    auto nonce = make_packet_protection_nonce_or_assert(keys.iv, full_packet_number, nonce_storage);
    auto ciphertext = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = packet_cipher_suite,
        .key = keys.key,
        .nonce = nonce,
        .associated_data = std::span<const std::byte>(packet_bytes).first(header_end),
        .plaintext =
            std::span<const std::byte>(packet_bytes).subspan(header_end, plaintext_payload_size),
        .ciphertext = packet_bytes.subspan(header_end),
    });
    if (!ciphertext.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                 ciphertext.error().offset);
    }

    const auto final_packet_size = header_end + ciphertext.value();
    out_datagram.resize(datagram_begin + final_packet_size);
    auto protected_packet = apply_long_header_protection_in_place(
        std::span<std::byte>(out_datagram).subspan(datagram_begin, final_packet_size),
        PacketNumberSpan{
            .packet_number_offset = packet_number_offset,
            .packet_number_length = packet_number.packet_number_length,
        },
        packet_cipher_suite, keys);
    if (!protected_packet.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                 protected_packet.error().offset);
    }

    return CodecResult<std::size_t>::success(final_packet_size);
}

CodecResult<std::vector<std::byte>>
serialize_protected_initial_packet(const ProtectedInitialPacket &packet,
                                   const SerializeProtectionContext &context) {
    const auto keys = derive_send_initial_keys(context, packet.version);
    if (!keys.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(keys.error().code, keys.error().offset);
    }

    auto plaintext_packet = to_plaintext_initial(packet);
    if (!plaintext_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(plaintext_packet.error().code,
                                                            plaintext_packet.error().offset);
    }
    std::vector<std::byte> datagram;
    auto appended = append_protected_long_header_packet_to_datagram(
        datagram, LongHeaderPacketType::initial, packet.version, packet.destination_connection_id,
        packet.source_connection_id, packet.token,
        TruncatedPacketNumberEncoding{
            .packet_number_length = packet.packet_number_length,
            .truncated_packet_number = plaintext_packet.value().truncated_packet_number,
        },
        packet.packet_number, packet.frames, kInitialCipherSuite, keys.value(),
        context.grease_quic_bit, context.grease_quic_bit_seed);
    if (!appended.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(appended.error().code,
                                                            appended.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(datagram));
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_initial_packet(std::span<const std::byte> bytes,
                                     const DeserializeProtectionContext &context) {
    const auto layout =
        locate_long_header(bytes, LongHeaderPacketType::initial, context.accept_greased_quic_bit);
    if (!layout.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                 layout.error().offset);

    const auto version = read_u32_be(bytes.subspan(1, 4));
    const auto keys = derive_receive_initial_keys(context, version);
    if (!keys.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);

    auto unprotected =
        remove_long_header_protection(bytes, layout.value(), kInitialCipherSuite, keys.value());
    if (!unprotected.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(unprotected.error().code,
                                                                 unprotected.error().offset);

    auto packet_number = recover_packet_number(context.largest_authenticated_initial_packet_number,
                                               unprotected.value().truncated_packet_number,
                                               unprotected.value().packet_number_length);
    if (!packet_number.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(packet_number.error().code,
                                                                 packet_number.error().offset);

    auto header_end =
        layout.value().packet_number_offset + unprotected.value().packet_number_length;
    std::array<std::byte, 32> nonce_storage;
    auto nonce = make_packet_protection_nonce_or_assert(keys.value().iv, packet_number.value(),
                                                        nonce_storage);

    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = kInitialCipherSuite,
        .key = keys.value().key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext = std::span<const std::byte>(unprotected.value().packet_bytes)
                          .subspan(header_end, layout.value().packet_end_offset - header_end),
    });
    if (!plaintext.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);
    }

    auto plaintext_image = std::vector<std::byte>(unprotected.value().packet_bytes.begin(),
                                                  unprotected.value().packet_bytes.begin() +
                                                      static_cast<std::ptrdiff_t>(header_end));
    patch_long_header_length_field_or_assert(plaintext_image, layout.value(),
                                             unprotected.value().packet_number_length +
                                                 plaintext.value().size());
    plaintext_image.insert(plaintext_image.end(), plaintext.value().begin(),
                           plaintext.value().end());

    auto decoded = deserialize_plaintext_packet_image(
        plaintext_image, DeserializeOptions{
                             .accept_greased_quic_bit = context.accept_greased_quic_bit,
                         });
    if (!decoded.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(decoded.error().code,
                                                                 decoded.error().offset);

    const auto &initial = std::get<InitialPacket>(decoded.value().packet);

    return CodecResult<ProtectedPacketDecodeResult>::success(ProtectedPacketDecodeResult{
        .packet =
            ProtectedInitialPacket{
                .version = initial.version,
                .destination_connection_id = initial.destination_connection_id,
                .source_connection_id = initial.source_connection_id,
                .token = initial.token,
                .packet_number_length = initial.packet_number_length,
                .packet_number = packet_number.value(),
                .frames = initial.frames,
            },
        .bytes_consumed = layout.value().packet_end_offset,
    });
}

CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_initial_packet(std::span<const std::byte> bytes,
                                              const DeserializeProtectionContext &context) {
    const auto version = read_u32_be(bytes.subspan(1, 4));
    const auto keys = derive_receive_initial_keys(context, version);
    if (!keys.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                         keys.error().offset);
    }

    return deserialize_received_long_header_packet(
        bytes, context, LongHeaderPacketType::initial, ProtectedPayloadPacketType::initial,
        kInitialCipherSuite, keys.value(), context.largest_authenticated_initial_packet_number,
        true,
        [](ReceivedLongHeaderPacketFields fields, std::uint64_t packet_number,
           const std::shared_ptr<std::vector<std::byte>> &plaintext_storage)
            -> ReceivedProtectedPacket {
            return ReceivedProtectedInitialPacket{
                .version = fields.version,
                .destination_connection_id = std::move(fields.destination_connection_id),
                .source_connection_id = std::move(fields.source_connection_id),
                .token = std::move(fields.token),
                .packet_number_length = fields.packet_number_length,
                .packet_number = packet_number,
                .plaintext_storage = plaintext_storage,
                .frames = std::move(fields.frames),
            };
        });
}

CodecResult<std::vector<std::byte>>
serialize_protected_handshake_packet(const ProtectedHandshakePacket &handshake_packet,
                                     const SerializeProtectionContext &context) {
    const auto *handshake_secret = handshake_secret_for_context(context);
    if (handshake_secret == nullptr)
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::missing_crypto_context,
                                                            0);

    auto keys = CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::failure(
        CodecErrorCode::invalid_packet_protection_state, 0);
    if (!traffic_secret_cached_keys_available(handshake_secret,
                                              context.handshake_secret_cache_primed)) {
        keys = expand_traffic_secret_cached(*handshake_secret);
        if (!keys.has_value()) {
            return CodecResult<std::vector<std::byte>>::failure(keys.error().code,
                                                                keys.error().offset);
        }
    }
    const auto &keys_ref = traffic_secret_cached_keys_available(
                               handshake_secret, context.handshake_secret_cache_primed)
                               ? traffic_secret_cached_keys_or_assert(
                                     handshake_secret, context.handshake_secret_cache_primed)
                               : keys.value().get();

    auto plaintext_packet = to_plaintext_handshake(handshake_packet);
    if (!plaintext_packet.has_value())
        return CodecResult<std::vector<std::byte>>::failure(plaintext_packet.error().code,
                                                            plaintext_packet.error().offset);

    auto cipher_suite = handshake_secret->cipher_suite;
    std::vector<std::byte> datagram;
    auto appended = append_protected_long_header_packet_to_datagram(
        datagram, LongHeaderPacketType::handshake, handshake_packet.version,
        handshake_packet.destination_connection_id, handshake_packet.source_connection_id, {},
        TruncatedPacketNumberEncoding{
            .packet_number_length = handshake_packet.packet_number_length,
            .truncated_packet_number = plaintext_packet.value().truncated_packet_number,
        },
        handshake_packet.packet_number, handshake_packet.frames, cipher_suite, keys_ref,
        context.grease_quic_bit, context.grease_quic_bit_seed);
    if (!appended.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(appended.error().code,
                                                            appended.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(datagram));
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_handshake_packet(std::span<const std::byte> bytes,
                                       const DeserializeProtectionContext &context) {
    if (!context.handshake_secret.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);

    const auto layout =
        locate_long_header(bytes, LongHeaderPacketType::handshake, context.accept_greased_quic_bit);
    if (!layout.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                 layout.error().offset);

    const auto keys = expand_traffic_secret_cached(context.handshake_secret.value());
    if (!keys.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);
    const auto &keys_ref = keys.value().get();

    auto cipher_suite = context.handshake_secret->cipher_suite;
    auto unprotected = remove_long_header_protection(bytes, layout.value(), cipher_suite, keys_ref);
    if (!unprotected.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(unprotected.error().code,
                                                                 unprotected.error().offset);

    auto packet_number = recover_packet_number(
        context.largest_authenticated_handshake_packet_number,
        unprotected.value().truncated_packet_number, unprotected.value().packet_number_length);
    if (!packet_number.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(packet_number.error().code,
                                                                 packet_number.error().offset);

    auto header_end =
        layout.value().packet_number_offset + unprotected.value().packet_number_length;
    std::array<std::byte, 32> nonce_storage;
    auto nonce =
        make_packet_protection_nonce_or_assert(keys_ref.iv, packet_number.value(), nonce_storage);

    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys_ref.key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext = std::span<const std::byte>(unprotected.value().packet_bytes)
                          .subspan(header_end, layout.value().packet_end_offset - header_end),
    });
    if (!plaintext.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);
    }

    auto plaintext_image = std::vector<std::byte>(unprotected.value().packet_bytes.begin(),
                                                  unprotected.value().packet_bytes.begin() +
                                                      static_cast<std::ptrdiff_t>(header_end));
    patch_long_header_length_field_or_assert(plaintext_image, layout.value(),
                                             unprotected.value().packet_number_length +
                                                 plaintext.value().size());
    plaintext_image.insert(plaintext_image.end(), plaintext.value().begin(),
                           plaintext.value().end());

    auto decoded = deserialize_plaintext_packet_image(
        plaintext_image, DeserializeOptions{
                             .accept_greased_quic_bit = context.accept_greased_quic_bit,
                         });
    if (!decoded.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(decoded.error().code,
                                                                 decoded.error().offset);

    const auto &handshake = std::get<HandshakePacket>(decoded.value().packet);

    return CodecResult<ProtectedPacketDecodeResult>::success(ProtectedPacketDecodeResult{
        .packet =
            ProtectedHandshakePacket{
                .version = handshake.version,
                .destination_connection_id = handshake.destination_connection_id,
                .source_connection_id = handshake.source_connection_id,
                .packet_number_length = handshake.packet_number_length,
                .packet_number = packet_number.value(),
                .frames = handshake.frames,
            },
        .bytes_consumed = layout.value().packet_end_offset,
    });
}

CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_handshake_packet(std::span<const std::byte> bytes,
                                                const DeserializeProtectionContext &context) {
    if (!context.handshake_secret.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    }

    const auto keys = expand_traffic_secret_cached(context.handshake_secret.value());
    if (!keys.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                         keys.error().offset);
    }

    return deserialize_received_long_header_packet(
        bytes, context, LongHeaderPacketType::handshake, ProtectedPayloadPacketType::handshake,
        context.handshake_secret->cipher_suite, keys.value().get(),
        context.largest_authenticated_handshake_packet_number, false,
        [](ReceivedLongHeaderPacketFields fields, std::uint64_t packet_number,
           const std::shared_ptr<std::vector<std::byte>> &plaintext_storage)
            -> ReceivedProtectedPacket {
            return ReceivedProtectedHandshakePacket{
                .version = fields.version,
                .destination_connection_id = std::move(fields.destination_connection_id),
                .source_connection_id = std::move(fields.source_connection_id),
                .packet_number_length = fields.packet_number_length,
                .packet_number = packet_number,
                .plaintext_storage = plaintext_storage,
                .frames = std::move(fields.frames),
            };
        });
}

CodecResult<std::vector<std::byte>>
serialize_protected_zero_rtt_packet(const ProtectedZeroRttPacket &zero_rtt_packet,
                                    const SerializeProtectionContext &context) {
    const auto *zero_rtt_secret = zero_rtt_secret_for_context(context);
    if (zero_rtt_secret == nullptr) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::missing_crypto_context,
                                                            0);
    }

    auto keys = CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::failure(
        CodecErrorCode::invalid_packet_protection_state, 0);
    if (!traffic_secret_cached_keys_available(zero_rtt_secret,
                                              context.zero_rtt_secret_cache_primed)) {
        keys = expand_traffic_secret_cached(*zero_rtt_secret);
        if (!keys.has_value()) {
            return CodecResult<std::vector<std::byte>>::failure(keys.error().code,
                                                                keys.error().offset);
        }
    }
    const auto &keys_ref =
        traffic_secret_cached_keys_available(zero_rtt_secret, context.zero_rtt_secret_cache_primed)
            ? traffic_secret_cached_keys_or_assert(zero_rtt_secret,
                                                   context.zero_rtt_secret_cache_primed)
            : keys.value().get();

    auto plaintext_packet = to_plaintext_zero_rtt(zero_rtt_packet);
    if (!plaintext_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(plaintext_packet.error().code,
                                                            plaintext_packet.error().offset);
    }

    auto cipher_suite = zero_rtt_secret->cipher_suite;
    std::vector<std::byte> datagram;
    auto appended = append_protected_long_header_packet_to_datagram(
        datagram, LongHeaderPacketType::zero_rtt, zero_rtt_packet.version,
        zero_rtt_packet.destination_connection_id, zero_rtt_packet.source_connection_id, {},
        TruncatedPacketNumberEncoding{
            .packet_number_length = zero_rtt_packet.packet_number_length,
            .truncated_packet_number = plaintext_packet.value().truncated_packet_number,
        },
        zero_rtt_packet.packet_number, zero_rtt_packet.frames, cipher_suite, keys_ref,
        context.grease_quic_bit, context.grease_quic_bit_seed);
    if (!appended.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(appended.error().code,
                                                            appended.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(datagram));
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_zero_rtt_packet(std::span<const std::byte> bytes,
                                      const DeserializeProtectionContext &context) {
    if (!context.zero_rtt_secret.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    }

    const auto layout =
        locate_long_header(bytes, LongHeaderPacketType::zero_rtt, context.accept_greased_quic_bit);
    if (!layout.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                 layout.error().offset);
    }

    const auto keys = expand_traffic_secret_cached(context.zero_rtt_secret.value());
    if (!keys.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);
    }
    const auto &keys_ref = keys.value().get();

    auto cipher_suite = context.zero_rtt_secret->cipher_suite;
    auto unprotected = remove_long_header_protection(bytes, layout.value(), cipher_suite, keys_ref);
    if (!unprotected.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(unprotected.error().code,
                                                                 unprotected.error().offset);
    }

    auto packet_number = recover_packet_number(
        context.largest_authenticated_application_packet_number,
        unprotected.value().truncated_packet_number, unprotected.value().packet_number_length);
    if (!packet_number.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(packet_number.error().code,
                                                                 packet_number.error().offset);
    }

    auto header_end =
        layout.value().packet_number_offset + unprotected.value().packet_number_length;
    std::array<std::byte, 32> nonce_storage;
    auto nonce =
        make_packet_protection_nonce_or_assert(keys_ref.iv, packet_number.value(), nonce_storage);
    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys_ref.key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext = std::span<const std::byte>(unprotected.value().packet_bytes)
                          .subspan(header_end, layout.value().packet_end_offset - header_end),
    });
    if (!plaintext.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);
    }

    auto plaintext_image = std::vector<std::byte>(unprotected.value().packet_bytes.begin(),
                                                  unprotected.value().packet_bytes.begin() +
                                                      static_cast<std::ptrdiff_t>(header_end));
    patch_long_header_length_field_or_assert(plaintext_image, layout.value(),
                                             unprotected.value().packet_number_length +
                                                 plaintext.value().size());
    plaintext_image.insert(plaintext_image.end(), plaintext.value().begin(),
                           plaintext.value().end());

    auto decoded = deserialize_plaintext_packet_image(
        plaintext_image, DeserializeOptions{
                             .accept_greased_quic_bit = context.accept_greased_quic_bit,
                         });
    if (!decoded.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(decoded.error().code,
                                                                 decoded.error().offset);
    }

    const auto &zero_rtt = std::get<ZeroRttPacket>(decoded.value().packet);

    return CodecResult<ProtectedPacketDecodeResult>::success(ProtectedPacketDecodeResult{
        .packet =
            ProtectedZeroRttPacket{
                .version = zero_rtt.version,
                .destination_connection_id = zero_rtt.destination_connection_id,
                .source_connection_id = zero_rtt.source_connection_id,
                .packet_number_length = zero_rtt.packet_number_length,
                .packet_number = packet_number.value(),
                .frames = zero_rtt.frames,
            },
        .bytes_consumed = layout.value().packet_end_offset,
    });
}

CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_zero_rtt_packet(std::span<const std::byte> bytes,
                                               const DeserializeProtectionContext &context) {
    if (!context.zero_rtt_secret.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    }

    const auto keys = expand_traffic_secret_cached(context.zero_rtt_secret.value());
    if (!keys.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                         keys.error().offset);
    }

    return deserialize_received_long_header_packet(
        bytes, context, LongHeaderPacketType::zero_rtt, ProtectedPayloadPacketType::zero_rtt,
        context.zero_rtt_secret->cipher_suite, keys.value().get(),
        context.largest_authenticated_application_packet_number, false,
        [](ReceivedLongHeaderPacketFields fields, std::uint64_t packet_number,
           const std::shared_ptr<std::vector<std::byte>> &plaintext_storage)
            -> ReceivedProtectedPacket {
            return ReceivedProtectedZeroRttPacket{
                .version = fields.version,
                .destination_connection_id = std::move(fields.destination_connection_id),
                .source_connection_id = std::move(fields.source_connection_id),
                .packet_number_length = fields.packet_number_length,
                .packet_number = packet_number,
                .plaintext_storage = plaintext_storage,
                .frames = std::move(fields.frames),
            };
        });
}

void pad_short_header_plaintext_for_header_protection(std::vector<std::byte> &plaintext_image,
                                                      std::size_t packet_number_offset) {
    const auto minimum_plaintext_size = packet_number_offset + kHeaderProtectionSampleOffset;
    if (plaintext_image.size() < minimum_plaintext_size) {
        // Trailing zero bytes decode as PADDING frames and make the protected sample available.
        plaintext_image.resize(minimum_plaintext_size, std::byte{0x00});
    }
}

template <typename OneRttPacketLike>
bool packet_has_stream_payloads(const OneRttPacketLike &packet) {
    if constexpr (requires { packet.stream_frame_views; }) {
        return !packet.stream_frame_views.empty();
    } else {
        return !packet.stream_fragments.empty();
    }
}

template <typename OneRttPacketLike>
const OutboundAckFrame *simple_outbound_ack_frame_or_null(const OneRttPacketLike &packet) {
    if (packet.frames.size() != 1 || packet_has_stream_payloads(packet)) {
        return nullptr;
    }

    const auto *ack = std::get_if<OutboundAckFrame>(&packet.frames.front());
    if (ack == nullptr || ack->header.largest_acknowledged < ack->header.first_ack_range) {
        return nullptr;
    }

    return ack;
}

const OutboundAckFrame *simple_outbound_ack_frame_or_null(const ProtectedOneRttPacket &packet) {
    return simple_outbound_ack_frame_or_null<ProtectedOneRttPacket>(packet);
}

const OutboundAckFrame *simple_outbound_ack_frame_or_null(const ProtectedOneRttPacketView &packet) {
    return simple_outbound_ack_frame_or_null<ProtectedOneRttPacketView>(packet);
}

const OutboundAckFrame *
simple_outbound_ack_frame_or_null(const ProtectedOneRttPacketFragmentView &packet) {
    return simple_outbound_ack_frame_or_null<ProtectedOneRttPacketFragmentView>(packet);
}

template <typename OneRttPacketLike>
const OutboundAckFrame *single_ack_frame_or_null(const OneRttPacketLike &packet) {
    if (packet.frames.size() != 1) {
        return nullptr;
    }

    const auto *ack = std::get_if<OutboundAckFrame>(&packet.frames.front());
    if (ack == nullptr || ack->header.largest_acknowledged < ack->header.first_ack_range) {
        return nullptr;
    }

    return ack;
}

CodecResult<std::size_t> simple_outbound_ack_payload_size(const OutboundAckFrame &ack) {
    auto size = std::size_t{1} + encoded_varint_size(ack.header.largest_acknowledged) +
                encoded_varint_size(ack.header.ack_delay) +
                encoded_varint_size(ack.header.additional_ranges.size()) +
                encoded_varint_size(ack.header.first_ack_range);
    auto previous_smallest = ack.header.largest_acknowledged - ack.header.first_ack_range;
    for (const auto &range : ack.header.additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
        }
        const auto largest = previous_smallest - range.gap - 2;
        if (largest < range.range_length) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
        }
        size += encoded_varint_size(range.gap) + encoded_varint_size(range.range_length);
        previous_smallest = largest - range.range_length;
    }
    if (ack.header.ecn_counts.has_value()) {
        size += encoded_varint_size(ack.header.ecn_counts->ect0) +
                encoded_varint_size(ack.header.ecn_counts->ect1) +
                encoded_varint_size(ack.header.ecn_counts->ecn_ce);
    }
    return CodecResult<std::size_t>::success(size);
}

CodecResult<std::size_t> write_simple_outbound_ack_payload(std::span<std::byte> output,
                                                           const OutboundAckFrame &ack) {
    SpanBufferWriter writer(output);
    if (const auto error = writer.write_byte(ack.header.ecn_counts.has_value() ? std::byte{0x03}
                                                                               : std::byte{0x02})) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_varint(ack.header.largest_acknowledged)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_varint(ack.header.ack_delay)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_varint(ack.header.additional_ranges.size())) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_varint(ack.header.first_ack_range)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    auto previous_smallest = ack.header.largest_acknowledged - ack.header.first_ack_range;
    for (const auto &range : ack.header.additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
        }
        const auto largest = previous_smallest - range.gap - 2;
        if (largest < range.range_length) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
        }
        if (const auto error = writer.write_varint(range.gap)) {
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
        if (const auto error = writer.write_varint(range.range_length)) {
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
        previous_smallest = largest - range.range_length;
    }
    if (ack.header.ecn_counts.has_value()) {
        if (const auto error = writer.write_varint(ack.header.ecn_counts->ect0)) {
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
        if (const auto error = writer.write_varint(ack.header.ecn_counts->ect1)) {
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
        if (const auto error = writer.write_varint(ack.header.ecn_counts->ecn_ce)) {
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
    }
    return CodecResult<std::size_t>::success(writer.offset());
}

template <typename OneRttPacketLike>
CodecResult<std::size_t> packet_stream_payload_wire_size(const OneRttPacketLike &packet,
                                                         std::size_t frame_index_base = 0) {
    std::size_t total = 0;
    if constexpr (requires { packet.stream_frame_views; }) {
        for (std::size_t stream_index = 0; stream_index < packet.stream_frame_views.size();
             ++stream_index) {
            const auto &stream_view = packet.stream_frame_views[stream_index];
            if (stream_view.end < stream_view.begin) {
                return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint,
                                                         frame_index_base + stream_index);
            }
            total += encoded_stream_frame_payload_size(stream_view.stream_id, stream_view.offset,
                                                       stream_view.end - stream_view.begin);
        }
    } else {
        for (std::size_t stream_index = 0; stream_index < packet.stream_fragments.size();
             ++stream_index) {
            const auto &fragment = packet.stream_fragments[stream_index];
            if (fragment.offset > kMaxVarInt - fragment.bytes.size()) {
                return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint,
                                                         frame_index_base + stream_index);
            }
            total += fragment.stream_frame_wire_size();
        }
    }
    return CodecResult<std::size_t>::success(total);
}

CodecResult<std::size_t> packet_stream_payload_wire_size(const ProtectedOneRttPacketView &packet,
                                                         std::size_t frame_index_base) {
    return packet_stream_payload_wire_size<ProtectedOneRttPacketView>(packet, frame_index_base);
}

CodecResult<std::size_t>
packet_stream_payload_wire_size(const ProtectedOneRttPacketFragmentView &packet,
                                std::size_t frame_index_base) {
    return packet_stream_payload_wire_size<ProtectedOneRttPacketFragmentView>(packet,
                                                                              frame_index_base);
}

template <typename OneRttPacketLike>
COQUIC_NO_PROFILE CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(DatagramBuffer &out_datagram,
                                                 const OneRttPacketLike &packet,
                                                 const SerializeProtectionContext &context) {
    COQUIC_SERIALIZE_PROFILE_TIMER(one_rtt_timer, one_rtt_ns);
    COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_calls, 1);
    COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_frames, packet.frames.size());
    if constexpr (requires { packet.stream_fragments; }) {
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_stream_fragments,
                                             packet.stream_fragments.size());
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(
            one_rtt_packets_with_stream_fragments,
            static_cast<std::uint64_t>(!packet.stream_fragments.empty()));
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(
            one_rtt_single_stream_fragment_packets,
            static_cast<std::uint64_t>(packet.stream_fragments.size() == 1));
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(
            one_rtt_multi_stream_fragment_packets,
            static_cast<std::uint64_t>(packet.stream_fragments.size() > 1));
    } else if constexpr (requires { packet.stream_frame_views; }) {
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_stream_fragments,
                                             packet.stream_frame_views.size());
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(
            one_rtt_packets_with_stream_fragments,
            static_cast<std::uint64_t>(!packet.stream_frame_views.empty()));
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(
            one_rtt_single_stream_fragment_packets,
            static_cast<std::uint64_t>(packet.stream_frame_views.size() == 1));
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(
            one_rtt_multi_stream_fragment_packets,
            static_cast<std::uint64_t>(packet.stream_frame_views.size() > 1));
    }

    const auto *one_rtt_secret = one_rtt_secret_for_context(context);
    if (one_rtt_secret == nullptr)
        return CodecResult<std::size_t>::failure(CodecErrorCode::missing_crypto_context, 0);
    if (packet.key_phase != context.one_rtt_key_phase)
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);

    const PacketProtectionKeys *keys_ref_ptr = nullptr;
    {
        COQUIC_SERIALIZE_PROFILE_TIMER(key_timer, key_lookup_ns);
        auto keys = CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);
        if (!traffic_secret_cached_keys_available(one_rtt_secret,
                                                  context.one_rtt_secret_cache_primed)) {
            keys = expand_traffic_secret_cached(*one_rtt_secret);
            if (!keys.has_value())
                return CodecResult<std::size_t>::failure(keys.error().code, keys.error().offset);
        }
        keys_ref_ptr = traffic_secret_cached_keys_available(one_rtt_secret,
                                                            context.one_rtt_secret_cache_primed)
                           ? &traffic_secret_cached_keys_or_assert(
                                 one_rtt_secret, context.one_rtt_secret_cache_primed)
                           : &keys.value().get();
    }
    auto truncated_packet_number =
        CodecResult<std::uint32_t>::failure(CodecErrorCode::invalid_varint, 0);
    {
        COQUIC_SERIALIZE_PROFILE_TIMER(packet_number_timer, packet_number_ns);
        truncated_packet_number =
            truncate_packet_number(packet.packet_number, packet.packet_number_length);
    }
    if (!truncated_packet_number.has_value()) {
        return CodecResult<std::size_t>::failure(truncated_packet_number.error().code,
                                                 truncated_packet_number.error().offset);
    }

    auto cipher_suite = one_rtt_secret->cipher_suite;
    std::array<std::byte, 32> nonce_storage;
    std::span<const std::byte> nonce;
    {
        COQUIC_SERIALIZE_PROFILE_TIMER(nonce_timer, nonce_ns);
        nonce = make_packet_protection_nonce_or_assert(keys_ref_ptr->iv, packet.packet_number,
                                                       nonce_storage);
    }

    auto packet_number_offset = 1 + packet.destination_connection_id.size();
    const auto payload_offset = packet_number_offset + packet.packet_number_length;
    auto packet_number_span = PacketNumberSpan{
        .packet_number_offset = packet_number_offset,
        .packet_number_length = packet.packet_number_length,
    };
    auto datagram_begin = out_datagram.size();
    const auto rollback = [&]() { out_datagram.resize(datagram_begin); };

    const auto *simple_ack = simple_outbound_ack_frame_or_null(packet);
    if (simple_ack != nullptr) {
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(simple_ack_fast_calls, 1);

        std::size_t payload_size = 0;
        {
            COQUIC_SERIALIZE_PROFILE_TIMER(size_timer, payload_size_ns);
            const auto measured_payload_size = simple_outbound_ack_payload_size(*simple_ack);
            if (!measured_payload_size.has_value()) {
                return CodecResult<std::size_t>::failure(measured_payload_size.error().code,
                                                         measured_payload_size.error().offset);
            }
            payload_size = measured_payload_size.value();
        }
        auto maximum_packet_size = payload_offset + payload_size + kPacketProtectionTagLength;
        std::span<std::byte> packet_bytes;
        {
            COQUIC_SERIALIZE_PROFILE_TIMER(reserve_timer, reserve_resize_ns);
            packet_bytes = out_datagram.append_uninitialized_exact(maximum_packet_size);
        }

        {
            COQUIC_SERIALIZE_PROFILE_TIMER(header_timer, header_write_ns);
            SpanBufferWriter header_writer(packet_bytes.first(payload_offset));
            abort_if(header_writer
                         .write_byte(make_short_header_first_byte(
                             packet.spin_bit, packet.key_phase, packet.packet_number_length,
                             context.grease_quic_bit, context.grease_quic_bit_seed,
                             packet.packet_number))
                         .has_value());
            abort_if(header_writer.write_bytes(packet.destination_connection_id).has_value());
            abort_if(
                append_packet_number(header_writer,
                                     TruncatedPacketNumberEncoding{
                                         .packet_number_length = packet.packet_number_length,
                                         .truncated_packet_number = truncated_packet_number.value(),
                                     })
                    .has_value());
        }

        auto payload_bytes = packet_bytes.subspan(payload_offset, payload_size);
        {
            COQUIC_SERIALIZE_PROFILE_TIMER(payload_timer, payload_write_ns);
            auto written =
                write_simple_outbound_ack_payload(payload_bytes.first(payload_size), *simple_ack);
            if (consume_protected_codec_fault(
                    test::ProtectedCodecFaultPoint::simple_ack_payload_write_failure)) {
                written = CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0);
            }
            if (!written.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(written.error().code,
                                                         written.error().offset);
            }
            if (consume_protected_codec_fault(
                    test::ProtectedCodecFaultPoint::simple_ack_payload_size_mismatch)) {
                written = CodecResult<std::size_t>::success(written.value() + 1u);
            }
            if (written.value() != payload_size) {
                rollback();
                return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                         written.value());
            }
            auto force_padding_fill = consume_protected_codec_fault(
                test::ProtectedCodecFaultPoint::simple_ack_force_padding_fill);
            if (force_padding_fill) {
                const auto padding_offset = payload_size;
                std::fill(payload_bytes.begin() + static_cast<std::ptrdiff_t>(padding_offset),
                          payload_bytes.end(), std::byte{0x00});
            }
        }

        auto plaintext_payload =
            std::span<const std::byte>(packet_bytes).subspan(payload_offset, payload_size);

        auto ciphertext =
            CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
        {
            COQUIC_SERIALIZE_PROFILE_TIMER(seal_timer, aead_seal_ns);
            ciphertext = seal_payload_into(SealPayloadIntoInput{
                .cipher_suite = cipher_suite,
                .key = keys_ref_ptr->key,
                .nonce = nonce,
                .associated_data = std::span<const std::byte>(packet_bytes).first(payload_offset),
                .plaintext = plaintext_payload,
                .ciphertext = packet_bytes.subspan(payload_offset),
            });
        }
        if (!ciphertext.has_value()) {
            rollback();
            return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                     ciphertext.error().offset);
        }

        const auto final_packet_size = payload_offset + ciphertext.value();
        out_datagram.resize(datagram_begin + final_packet_size);
        auto protected_packet =
            CodecResult<bool>::failure(CodecErrorCode::header_protection_failed, 0);
        {
            COQUIC_SERIALIZE_PROFILE_TIMER(protect_timer, short_header_protect_ns);
            protected_packet = apply_short_header_protection_in_place(
                std::span<std::byte>(out_datagram).subspan(datagram_begin, final_packet_size),
                packet_number_span, cipher_suite, *keys_ref_ptr);
        }
        if (!protected_packet.has_value()) {
            rollback();
            return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                     protected_packet.error().offset);
        }

        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_bytes, final_packet_size);
        COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_payload_bytes, payload_size);
        return CodecResult<std::size_t>::success(final_packet_size);
    }

    if constexpr (requires { packet.stream_fragments; }) {
        const auto *single_ack = single_ack_frame_or_null(packet);
        if (single_ack != nullptr && packet.stream_fragments.size() == 1) {
            const auto measured_ack_payload_size = simple_outbound_ack_payload_size(*single_ack);
            if (!measured_ack_payload_size.has_value()) {
                return CodecResult<std::size_t>::failure(measured_ack_payload_size.error().code,
                                                         measured_ack_payload_size.error().offset);
            }
            const auto &fragment = packet.stream_fragments.front();
            if (fragment.offset > kMaxVarInt - fragment.bytes.size()) {
                return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint,
                                                         packet.frames.size());
            }
            const auto ack_payload_size = measured_ack_payload_size.value();
            const auto stream_header_bytes = fragment.stream_frame_header_bytes();
            const auto payload_size =
                ack_payload_size + stream_header_bytes.size() + fragment.bytes.size();
            if (payload_size == std::max(payload_size, minimum_payload_bytes_for_header_sample(
                                                           packet.packet_number_length))) {
                COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(simple_ack_fast_calls, 1);
                auto maximum_packet_size =
                    payload_offset + payload_size + kPacketProtectionTagLength;
                std::span<std::byte> packet_bytes;
                {
                    COQUIC_SERIALIZE_PROFILE_TIMER(reserve_timer, reserve_resize_ns);
                    packet_bytes = out_datagram.append_uninitialized_exact(maximum_packet_size);
                }

                {
                    COQUIC_SERIALIZE_PROFILE_TIMER(header_timer, header_write_ns);
                    SpanBufferWriter header_writer(packet_bytes.first(payload_offset));
                    abort_if(header_writer
                                 .write_byte(make_short_header_first_byte(
                                     packet.spin_bit, packet.key_phase, packet.packet_number_length,
                                     context.grease_quic_bit, context.grease_quic_bit_seed,
                                     packet.packet_number))
                                 .has_value());
                    abort_if(
                        header_writer.write_bytes(packet.destination_connection_id).has_value());
                    abort_if(append_packet_number(
                                 header_writer,
                                 TruncatedPacketNumberEncoding{
                                     .packet_number_length = packet.packet_number_length,
                                     .truncated_packet_number = truncated_packet_number.value(),
                                 })
                                 .has_value());
                }

                auto payload_bytes = packet_bytes.subspan(payload_offset, payload_size);
                {
                    COQUIC_SERIALIZE_PROFILE_TIMER(payload_timer, payload_write_ns);
                    auto ack_written = write_simple_outbound_ack_payload(
                        payload_bytes.first(ack_payload_size), *single_ack);
                    if (consume_protected_codec_fault(
                            test::ProtectedCodecFaultPoint::simple_ack_payload_write_failure)) {
                        ack_written =
                            CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0);
                    }
                    if (!ack_written.has_value()) {
                        rollback();
                        return CodecResult<std::size_t>::failure(ack_written.error().code,
                                                                 ack_written.error().offset);
                    }
                    if (consume_protected_codec_fault(
                            test::ProtectedCodecFaultPoint::simple_ack_payload_size_mismatch)) {
                        ack_written = CodecResult<std::size_t>::success(ack_written.value() + 1u);
                    }
                    if (ack_written.value() != ack_payload_size) {
                        rollback();
                        return CodecResult<std::size_t>::failure(
                            CodecErrorCode::packet_length_mismatch, ack_written.value());
                    }
                    std::memcpy(payload_bytes.data() +
                                    static_cast<std::ptrdiff_t>(ack_payload_size),
                                stream_header_bytes.data(), stream_header_bytes.size());
                }

                const std::array plaintext_chunks{
                    PlaintextChunk{
                        .bytes = std::span<const std::byte>(payload_bytes)
                                     .first(ack_payload_size + stream_header_bytes.size()),
                    },
                    PlaintextChunk{
                        .bytes = fragment.bytes.span(),
                    },
                };
                auto ciphertext = CodecResult<std::size_t>::failure(
                    CodecErrorCode::invalid_packet_protection_state, 0);
                {
                    COQUIC_SERIALIZE_PROFILE_TIMER(seal_timer, aead_seal_ns);
                    ciphertext = seal_payload_chunks_into(SealPayloadChunksIntoInput{
                        .cipher_suite = cipher_suite,
                        .key = keys_ref_ptr->key,
                        .nonce = nonce,
                        .associated_data =
                            std::span<const std::byte>(packet_bytes).first(payload_offset),
                        .plaintext_chunks = plaintext_chunks,
                        .ciphertext = packet_bytes.subspan(payload_offset),
                    });
                }
                if (!ciphertext.has_value()) {
                    rollback();
                    return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                             ciphertext.error().offset);
                }

                const auto final_packet_size = payload_offset + ciphertext.value();
                out_datagram.resize(datagram_begin + final_packet_size);
                auto protected_packet =
                    CodecResult<bool>::failure(CodecErrorCode::header_protection_failed, 0);
                {
                    COQUIC_SERIALIZE_PROFILE_TIMER(protect_timer, short_header_protect_ns);
                    protected_packet = apply_short_header_protection_in_place(
                        std::span<std::byte>(out_datagram)
                            .subspan(datagram_begin, final_packet_size),
                        packet_number_span, cipher_suite, *keys_ref_ptr);
                }
                if (!protected_packet.has_value()) {
                    rollback();
                    return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                             protected_packet.error().offset);
                }

                COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_bytes, final_packet_size);
                COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_payload_bytes, payload_size);
                return CodecResult<std::size_t>::success(final_packet_size);
            }
        }
    }

    bool has_stream_payloads = false;
    std::size_t frame_payload_size = 0;
    auto stream_payload_size = CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    {
        COQUIC_SERIALIZE_PROFILE_TIMER(size_timer, payload_size_ns);
        has_stream_payloads = packet_has_stream_payloads(packet);
        for (std::size_t frame_index = 0; frame_index < packet.frames.size(); ++frame_index) {
            if (const auto *stream = std::get_if<StreamFrame>(&packet.frames[frame_index]);
                stream != nullptr && !stream->has_length &&
                (frame_index + 1 != packet.frames.size() || has_stream_payloads)) {
                return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                         frame_index);
            }

            const auto encoded = serialized_frame_size(packet.frames[frame_index]);
            if (!encoded.has_value()) {
                return CodecResult<std::size_t>::failure(encoded.error().code,
                                                         encoded.error().offset);
            }
            frame_payload_size += encoded.value();
        }

        stream_payload_size = packet_stream_payload_wire_size(packet, packet.frames.size());
    }
    if (!stream_payload_size.has_value()) {
        return CodecResult<std::size_t>::failure(stream_payload_size.error().code,
                                                 stream_payload_size.error().offset);
    }
    const auto payload_size = frame_payload_size + stream_payload_size.value();
    if (payload_size == 0) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::empty_packet_payload, 0);
    }

    const auto plaintext_payload_size = std::max(
        payload_size, minimum_payload_bytes_for_header_sample(packet.packet_number_length));
    auto maximum_packet_size = payload_offset + plaintext_payload_size + kPacketProtectionTagLength;
    std::span<std::byte> packet_bytes;
    {
        COQUIC_SERIALIZE_PROFILE_TIMER(reserve_timer, reserve_resize_ns);
        packet_bytes = out_datagram.append_uninitialized_exact(maximum_packet_size);
    }

    {
        COQUIC_SERIALIZE_PROFILE_TIMER(header_timer, header_write_ns);
        SpanBufferWriter header_writer(packet_bytes.first(payload_offset));
        abort_if(
            header_writer
                .write_byte(make_short_header_first_byte(
                    packet.spin_bit, packet.key_phase, packet.packet_number_length,
                    context.grease_quic_bit, context.grease_quic_bit_seed, packet.packet_number))
                .has_value());
        abort_if(header_writer.write_bytes(packet.destination_connection_id).has_value());
        abort_if(
            append_packet_number(header_writer,
                                 TruncatedPacketNumberEncoding{
                                     .packet_number_length = packet.packet_number_length,
                                     .truncated_packet_number = truncated_packet_number.value(),
                                 })
                .has_value());
    }

    auto payload_bytes = packet_bytes.subspan(payload_offset, plaintext_payload_size);
    if constexpr (requires { packet.stream_fragments; }) {
        const bool can_contiguous_seal_single_stream_fragment =
            packet.frames.empty() && packet.stream_fragments.size() == 1 &&
            payload_size == plaintext_payload_size;
        if (can_contiguous_seal_single_stream_fragment) {
            const auto &fragment = packet.stream_fragments.front();
            std::span<const std::byte> header_bytes;
            {
                COQUIC_SERIALIZE_PROFILE_TIMER(payload_timer, payload_write_ns);
                header_bytes = fragment.stream_frame_header_bytes();
                if (payload_bytes.size() < header_bytes.size()) {
                    rollback();
                    return CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0);
                }
                std::memcpy(payload_bytes.data(), header_bytes.data(), header_bytes.size());
            }
            if (header_bytes.size() + fragment.bytes.size() != payload_size) {
                rollback();
                return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                         header_bytes.size() +
                                                             fragment.bytes.size());
            }

            const std::array plaintext_chunks{
                PlaintextChunk{
                    .bytes = std::span<const std::byte>(payload_bytes).first(header_bytes.size()),
                },
                PlaintextChunk{
                    .bytes = fragment.bytes.span(),
                },
            };
            auto ciphertext = CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
            {
                COQUIC_SERIALIZE_PROFILE_TIMER(seal_timer, aead_seal_ns);
                ciphertext = seal_payload_chunks_into(SealPayloadChunksIntoInput{
                    .cipher_suite = cipher_suite,
                    .key = keys_ref_ptr->key,
                    .nonce = nonce,
                    .associated_data =
                        std::span<const std::byte>(packet_bytes).first(payload_offset),
                    .plaintext_chunks = plaintext_chunks,
                    .ciphertext = packet_bytes.subspan(payload_offset),
                });
            }
            if (!ciphertext.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                         ciphertext.error().offset);
            }

            const auto final_packet_size = payload_offset + ciphertext.value();
            out_datagram.resize(datagram_begin + final_packet_size);
            auto protected_packet =
                CodecResult<bool>::failure(CodecErrorCode::header_protection_failed, 0);
            {
                COQUIC_SERIALIZE_PROFILE_TIMER(protect_timer, short_header_protect_ns);
                protected_packet = apply_short_header_protection_in_place(
                    std::span<std::byte>(out_datagram).subspan(datagram_begin, final_packet_size),
                    packet_number_span, cipher_suite, *keys_ref_ptr);
            }
            if (!protected_packet.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                         protected_packet.error().offset);
            }

            COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_bytes, final_packet_size);
            COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_payload_bytes, payload_size);
            return CodecResult<std::size_t>::success(final_packet_size);
        }

        const auto required_inline_chunks =
            static_cast<std::size_t>(!packet.frames.empty()) + (packet.stream_fragments.size() * 2);
        if (!packet.stream_fragments.empty() && payload_size == plaintext_payload_size &&
            (required_inline_chunks <= kMaxInlineSealPlaintextChunks)) {
            COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(chunk_seal_calls, 1);
            std::array<PlaintextChunk, kMaxInlineSealPlaintextChunks> plaintext_chunks{};
            std::size_t chunk_count = 0;
            std::size_t plaintext_offset = 0;
            std::size_t frame_index = 0;

            {
                COQUIC_SERIALIZE_PROFILE_TIMER(chunk_frame_timer, chunk_frame_write_ns);
                for (const auto &frame : packet.frames) {
                    plaintext_offset +=
                        write_frame_wire_bytes(payload_bytes.subspan(plaintext_offset), frame)
                            .value();
                    ++frame_index;
                }
            }
            if (plaintext_offset != 0) {
                plaintext_chunks[chunk_count++] = PlaintextChunk{
                    .bytes = std::span<const std::byte>(payload_bytes).first(plaintext_offset),
                };
            }

            {
                COQUIC_SERIALIZE_PROFILE_TIMER(chunk_header_timer, chunk_header_write_ns);
                for (const auto &fragment : packet.stream_fragments) {
                    const auto header_bytes = fragment.stream_frame_header_bytes();
                    plaintext_chunks[chunk_count++] = PlaintextChunk{
                        .bytes = std::span<const std::byte>(payload_bytes)
                                     .subspan(plaintext_offset, header_bytes.size()),
                    };
                    std::memcpy(payload_bytes.data() +
                                    static_cast<std::ptrdiff_t>(plaintext_offset),
                                header_bytes.data(), header_bytes.size());
                    plaintext_offset += header_bytes.size();
                    plaintext_chunks[chunk_count++] = PlaintextChunk{
                        .bytes = fragment.bytes.span(),
                    };
                    plaintext_offset += fragment.bytes.size();
                    ++frame_index;
                }
            }

            auto ciphertext = CodecResult<std::size_t>::failure(
                CodecErrorCode::invalid_packet_protection_state, 0);
            {
                COQUIC_SERIALIZE_PROFILE_TIMER(chunk_seal_timer, chunk_seal_ns);
                ciphertext = seal_payload_chunks_into(SealPayloadChunksIntoInput{
                    .cipher_suite = cipher_suite,
                    .key = keys_ref_ptr->key,
                    .nonce = nonce,
                    .associated_data =
                        std::span<const std::byte>(packet_bytes).first(payload_offset),
                    .plaintext_chunks =
                        std::span<const PlaintextChunk>(plaintext_chunks.data(), chunk_count),
                    .ciphertext = packet_bytes.subspan(payload_offset),
                });
            }
            if (!ciphertext.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                         ciphertext.error().offset);
            }

            const auto final_packet_size = payload_offset + ciphertext.value();
            out_datagram.resize(datagram_begin + final_packet_size);
            auto protected_packet =
                CodecResult<bool>::failure(CodecErrorCode::header_protection_failed, 0);
            {
                COQUIC_SERIALIZE_PROFILE_TIMER(protect_timer, short_header_protect_ns);
                protected_packet = apply_short_header_protection_in_place(
                    std::span<std::byte>(out_datagram).subspan(datagram_begin, final_packet_size),
                    packet_number_span, cipher_suite, *keys_ref_ptr);
            }
            if (!protected_packet.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                         protected_packet.error().offset);
            }

            COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_bytes, final_packet_size);
            COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_payload_bytes, payload_size);
            return CodecResult<std::size_t>::success(final_packet_size);
        }
    }
    std::size_t payload_written = 0;
    std::size_t frame_index = 0;
    {
        COQUIC_SERIALIZE_PROFILE_TIMER(payload_timer, payload_write_ns);
        for (const auto &frame : packet.frames) {
            payload_written +=
                write_frame_wire_bytes(payload_bytes.subspan(payload_written), frame).value();
            ++frame_index;
        }

        if constexpr (requires { packet.stream_frame_views; }) {
            for (const auto &stream_view : packet.stream_frame_views) {
                const auto written = serialize_stream_frame_view_into_span(
                    payload_bytes.subspan(payload_written), stream_view);
                if (!written.has_value()) {
                    rollback();
                    return CodecResult<std::size_t>::failure(written.error().code, frame_index);
                }
                payload_written += written.value();
                ++frame_index;
            }
        } else {
            for (const auto &fragment : packet.stream_fragments) {
                payload_written += serialize_stream_frame_send_fragment_into_span(
                                       payload_bytes.subspan(payload_written), fragment)
                                       .value();
                ++frame_index;
            }
        }

        if (payload_written < plaintext_payload_size) {
            // DatagramBuffer growth leaves bytes uninitialized, but short-header padding must
            // serialize as zero-valued PADDING frames before the payload is sealed.
            std::fill(payload_bytes.begin() + static_cast<std::ptrdiff_t>(payload_written),
                      payload_bytes.end(), std::byte{0x00});
        }
    }

    auto plaintext_payload =
        std::span<const std::byte>(packet_bytes).subspan(payload_offset, plaintext_payload_size);

    auto ciphertext =
        CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
    {
        COQUIC_SERIALIZE_PROFILE_TIMER(seal_timer, aead_seal_ns);
        ciphertext = seal_payload_into(SealPayloadIntoInput{
            .cipher_suite = cipher_suite,
            .key = keys_ref_ptr->key,
            .nonce = nonce,
            .associated_data = std::span<const std::byte>(packet_bytes).first(payload_offset),
            .plaintext = plaintext_payload,
            .ciphertext = packet_bytes.subspan(payload_offset),
        });
    }
    if (!ciphertext.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                 ciphertext.error().offset);
    }

    const auto final_packet_size = payload_offset + ciphertext.value();
    out_datagram.resize(datagram_begin + final_packet_size);
    auto protected_packet = CodecResult<bool>::failure(CodecErrorCode::header_protection_failed, 0);
    {
        COQUIC_SERIALIZE_PROFILE_TIMER(protect_timer, short_header_protect_ns);
        protected_packet = apply_short_header_protection_in_place(
            std::span<std::byte>(out_datagram).subspan(datagram_begin, final_packet_size),
            packet_number_span, cipher_suite, *keys_ref_ptr);
    }
    if (!protected_packet.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                 protected_packet.error().offset);
    }

    COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_bytes, final_packet_size);
    COQUIC_ADD_SERIALIZE_PROFILE_COUNTER(one_rtt_payload_bytes, plaintext_payload_size);
    return CodecResult<std::size_t>::success(final_packet_size);
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(DatagramBuffer &datagram,
                                                 const ProtectedOneRttPacket &packet,
                                                 const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl<ProtectedOneRttPacket>(datagram, packet,
                                                                                   context);
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(DatagramBuffer &datagram,
                                                 const ProtectedOneRttPacketView &packet,
                                                 const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl<ProtectedOneRttPacketView>(
        datagram, packet, context);
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(DatagramBuffer &datagram,
                                                 const ProtectedOneRttPacketFragmentView &packet,
                                                 const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl<ProtectedOneRttPacketFragmentView>(
        datagram, packet, context);
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_one_rtt_packet(std::span<const std::byte> bytes,
                                     const DeserializeProtectionContext &context) {
    const auto *one_rtt_secret = one_rtt_secret_for_context(context);
    if (one_rtt_secret == nullptr)
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);

    auto packet_number_offset = 1 + context.one_rtt_destination_connection_id_length;
    if (packet_number_offset > bytes.size())
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::malformed_short_header_context, 1);

    auto keys = CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::failure(
        CodecErrorCode::invalid_packet_protection_state, 0);
    if (!one_rtt_cached_keys_available(context)) {
        keys = expand_traffic_secret_cached(*one_rtt_secret);
        if (!keys.has_value())
            return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                     keys.error().offset);
    }
    const auto &keys_ref = one_rtt_cached_keys_available(context)
                               ? one_rtt_cached_keys_or_assert(context)
                               : keys.value().get();

    auto cipher_suite = one_rtt_secret->cipher_suite;
    auto unprotected =
        remove_short_header_protection(bytes, packet_number_offset, cipher_suite, keys_ref);
    if (!unprotected.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(unprotected.error().code,
                                                                 unprotected.error().offset);

    const auto &unprotected_value = unprotected.value();
    const auto plaintext_header = unprotected_value.plaintext_header_span();
    auto key_phase = (std::to_integer<std::uint8_t>(plaintext_header[0]) & 0x04u) != 0;
    if (key_phase != context.one_rtt_key_phase)
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);

    auto packet_number = recover_packet_number(
        context.largest_authenticated_application_packet_number,
        unprotected_value.truncated_packet_number, unprotected_value.packet_number_length);
    if (!packet_number.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(packet_number.error().code,
                                                                 packet_number.error().offset);

    auto header_end = packet_number_offset + unprotected_value.packet_number_length;
    std::array<std::byte, 32> nonce_storage;
    auto nonce =
        make_packet_protection_nonce_or_assert(keys_ref.iv, packet_number.value(), nonce_storage);

    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys_ref.key,
        .nonce = nonce,
        .associated_data = plaintext_header,
        .ciphertext = bytes.subspan(header_end),
    });
    if (!plaintext.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);

    auto plaintext_image = std::vector<std::byte>(plaintext_header.begin(), plaintext_header.end());
    plaintext_image.insert(plaintext_image.end(), plaintext.value().begin(),
                           plaintext.value().end());

    auto decoded = deserialize_plaintext_packet_image(
        plaintext_image, DeserializeOptions{
                             .one_rtt_destination_connection_id_length =
                                 context.one_rtt_destination_connection_id_length,
                             .accept_greased_quic_bit = context.accept_greased_quic_bit,
                         });
    if (!decoded.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(decoded.error().code,
                                                                 decoded.error().offset);

    const auto &one_rtt = std::get<OneRttPacket>(decoded.value().packet);

    return CodecResult<ProtectedPacketDecodeResult>::success(ProtectedPacketDecodeResult{
        .packet =
            ProtectedOneRttPacket{
                .spin_bit = one_rtt.spin_bit,
                .key_phase = one_rtt.key_phase,
                .destination_connection_id = one_rtt.destination_connection_id,
                .packet_number_length = one_rtt.packet_number_length,
                .packet_number = packet_number.value(),
                .frames = one_rtt.frames,
            },
        .bytes_consumed = bytes.size(),
    });
}

CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_one_rtt_packet(std::span<const std::byte> bytes,
                                              const DeserializeProtectionContext &context) {
    const auto *one_rtt_secret = one_rtt_secret_for_context(context);
    if (one_rtt_secret == nullptr) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    }

    auto packet_number_offset = 1 + context.one_rtt_destination_connection_id_length;
    if (packet_number_offset > bytes.size()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::malformed_short_header_context, 1);
    }

    auto keys = CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::failure(
        CodecErrorCode::invalid_packet_protection_state, 0);
    if (!one_rtt_cached_keys_available(context)) {
        keys = expand_traffic_secret_cached(*one_rtt_secret);
        if (!keys.has_value()) {
            return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                             keys.error().offset);
        }
    }
    const auto &keys_ref = one_rtt_cached_keys_available(context)
                               ? one_rtt_cached_keys_or_assert(context)
                               : keys.value().get();

    auto cipher_suite = one_rtt_secret->cipher_suite;
    auto unprotected =
        remove_short_header_protection(bytes, packet_number_offset, cipher_suite, keys_ref);
    if (!unprotected.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            unprotected.error().code, unprotected.error().offset);
    }

    const auto &unprotected_value = unprotected.value();
    const auto plaintext_header = unprotected_value.plaintext_header_span();
    auto key_phase = (std::to_integer<std::uint8_t>(plaintext_header[0]) & 0x04u) != 0;
    if (key_phase != context.one_rtt_key_phase) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);
    }

    auto packet_number = recover_packet_number(
        context.largest_authenticated_application_packet_number,
        unprotected_value.truncated_packet_number, unprotected_value.packet_number_length);
    if (!packet_number.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            packet_number.error().code, packet_number.error().offset);
    }

    auto header_end = packet_number_offset + unprotected_value.packet_number_length;
    std::array<std::byte, 32> nonce_storage;
    auto nonce =
        make_packet_protection_nonce_or_assert(keys_ref.iv, packet_number.value(), nonce_storage);
    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys_ref.key,
        .nonce = nonce,
        .associated_data = plaintext_header,
        .ciphertext = bytes.subspan(header_end),
    });
    if (!plaintext.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                         plaintext.error().offset);
    }

    auto plaintext_storage = std::make_shared<std::vector<std::byte>>(std::move(plaintext.value()));
    auto decoded_fields = decode_received_short_header_packet_fields(
        plaintext_header, SharedBytes(plaintext_storage, 0, plaintext_storage->size()),
        context.accept_greased_quic_bit);
    if (!decoded_fields.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            decoded_fields.error().code, decoded_fields.error().offset);
    }

    return CodecResult<ReceivedProtectedPacketDecodeResult>::success(
        ReceivedProtectedPacketDecodeResult{
            .packet =
                ReceivedProtectedOneRttPacket{
                    .spin_bit = decoded_fields.value().spin_bit,
                    .key_phase = decoded_fields.value().key_phase,
                    .destination_connection_id =
                        std::move(decoded_fields.value().destination_connection_id),
                    .packet_number_length = decoded_fields.value().packet_number_length,
                    .packet_number = packet_number.value(),
                    .plaintext_storage = plaintext_storage,
                    .frames = std::move(decoded_fields.value().frames),
                },
            .bytes_consumed = bytes.size(),
        });
}

COQUIC_NO_PROFILE CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_one_rtt_packet(
    const std::shared_ptr<std::vector<std::byte>> &storage, std::size_t begin, std::size_t end,
    const DeserializeProtectionContext &context, bool ack_only_fast) {
    COQUIC_DESERIALIZE_PROFILE_TIMER(one_rtt_timer, one_rtt_in_place_ns);
    if (!storage || begin > end || end > storage->size()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::truncated_input, 0);
    }
    const auto *one_rtt_secret = one_rtt_secret_for_context(context);
    if (one_rtt_secret == nullptr) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    }

    auto packet_bytes = std::span<std::byte>(*storage).subspan(begin, end - begin);
    const auto bytes = std::span<const std::byte>(packet_bytes);
    COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_in_place_calls, 1);
    COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_in_place_bytes, bytes.size());
    auto packet_number_offset = 1 + context.one_rtt_destination_connection_id_length;
    if (packet_number_offset > bytes.size()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::malformed_short_header_context, 1);
    }

    auto keys = CodecResult<std::reference_wrapper<const PacketProtectionKeys>>::failure(
        CodecErrorCode::invalid_packet_protection_state, 0);
    if (!one_rtt_cached_keys_available(context)) {
        keys = [&] {
            COQUIC_DESERIALIZE_PROFILE_TIMER(timer, key_lookup_ns);
            return expand_traffic_secret_cached(*one_rtt_secret);
        }();
        if (!keys.has_value()) {
            return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                             keys.error().offset);
        }
    }
    const auto &keys_ref = one_rtt_cached_keys_available(context)
                               ? one_rtt_cached_keys_or_assert(context)
                               : keys.value().get();

    auto cipher_suite = one_rtt_secret->cipher_suite;
    auto unprotected = [&] {
        COQUIC_DESERIALIZE_PROFILE_TIMER(timer, short_header_remove_ns);
        return remove_short_header_protection(bytes, packet_number_offset, cipher_suite, keys_ref);
    }();
    if (!unprotected.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            unprotected.error().code, unprotected.error().offset);
    }

    const auto &unprotected_value = unprotected.value();
    const auto plaintext_header = unprotected_value.plaintext_header_span();
    auto key_phase = (std::to_integer<std::uint8_t>(plaintext_header[0]) & 0x04u) != 0;
    if (key_phase != context.one_rtt_key_phase) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);
    }

    auto packet_number = [&] {
        COQUIC_DESERIALIZE_PROFILE_TIMER(timer, packet_number_recovery_ns);
        return recover_packet_number(context.largest_authenticated_application_packet_number,
                                     unprotected_value.truncated_packet_number,
                                     unprotected_value.packet_number_length);
    }();
    if (!packet_number.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            packet_number.error().code, packet_number.error().offset);
    }

    auto header_end = packet_number_offset + unprotected_value.packet_number_length;
    std::array<std::byte, 32> nonce_storage;
    auto nonce = [&] {
        COQUIC_DESERIALIZE_PROFILE_TIMER(timer, nonce_ns);
        return make_packet_protection_nonce_or_assert(keys_ref.iv, packet_number.value(),
                                                      nonce_storage);
    }();
    auto ciphertext = bytes.subspan(header_end);
    if (ciphertext.size() < kPacketProtectionTagLength) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::packet_decryption_failed, header_end);
    }
    const auto plaintext_size = ciphertext.size() - kPacketProtectionTagLength;
    auto plaintext_output = packet_bytes.subspan(header_end, plaintext_size);
    const auto plaintext = [&] {
        COQUIC_DESERIALIZE_PROFILE_TIMER(timer, aead_open_ns);
        return open_payload_into(OpenPayloadIntoInput{
            .cipher_suite = cipher_suite,
            .key = keys_ref.key,
            .nonce = nonce,
            .associated_data = plaintext_header,
            .ciphertext = ciphertext,
            .plaintext = plaintext_output,
        });
    }();
    if (!plaintext.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                         plaintext.error().offset);
    }
    const auto plaintext_bytes_written = plaintext.value();
    if (plaintext_bytes_written != plaintext_size) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::packet_length_mismatch, header_end + plaintext_bytes_written);
    }

    const auto plaintext_begin = begin + header_end;
    auto plaintext_payload =
        SharedBytes(storage, plaintext_begin, plaintext_begin + plaintext_size);
    if (ack_only_fast) {
        auto decoded_ack_only_fields = [&] {
            COQUIC_DESERIALIZE_PROFILE_TIMER(timer, frame_decode_ns);
            return try_decode_received_short_header_ack_only_fast_packet_fields(
                plaintext_header, plaintext_payload, context.accept_greased_quic_bit);
        }();
        if (decoded_ack_only_fields.has_value()) {
            COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_plaintext_bytes, plaintext_size);
            COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_frames, 1);

            return CodecResult<ReceivedProtectedPacketDecodeResult>::success(
                ReceivedProtectedPacketDecodeResult{
                    .packet =
                        ReceivedProtectedOneRttAckOnlyPacket{
                            .spin_bit = decoded_ack_only_fields.value().spin_bit,
                            .key_phase = decoded_ack_only_fields.value().key_phase,
                            .destination_connection_id = std::move(
                                decoded_ack_only_fields.value().destination_connection_id),
                            .packet_number_length =
                                decoded_ack_only_fields.value().packet_number_length,
                            .packet_number = packet_number.value(),
                            .plaintext_storage = storage,
                            .ack = std::move(decoded_ack_only_fields.value().ack),
                        },
                    .bytes_consumed = bytes.size(),
                });
        }
        auto decoded_stream_fields = [&] {
            COQUIC_DESERIALIZE_PROFILE_TIMER(timer, frame_decode_ns);
            return try_decode_received_short_header_stream_fast_packet_fields(
                plaintext_header, plaintext_payload, context.accept_greased_quic_bit);
        }();
        if (decoded_stream_fields.has_value()) {
            COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_plaintext_bytes, plaintext_size);
            COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_frames, 1);

            return CodecResult<ReceivedProtectedPacketDecodeResult>::success(
                ReceivedProtectedPacketDecodeResult{
                    .packet =
                        ReceivedProtectedOneRttStreamPacket{
                            .spin_bit = decoded_stream_fields.value().spin_bit,
                            .key_phase = decoded_stream_fields.value().key_phase,
                            .destination_connection_id =
                                std::move(decoded_stream_fields.value().destination_connection_id),
                            .packet_number_length =
                                decoded_stream_fields.value().packet_number_length,
                            .packet_number = packet_number.value(),
                            .plaintext_storage = storage,
                            .stream = std::move(decoded_stream_fields.value().stream),
                        },
                    .bytes_consumed = bytes.size(),
                });
        }
    } else {
        auto decoded_ack_only_fields = [&] {
            COQUIC_DESERIALIZE_PROFILE_TIMER(timer, frame_decode_ns);
            return try_decode_received_short_header_ack_only_packet_fields(
                plaintext_header, plaintext_payload, context.accept_greased_quic_bit);
        }();
        if (decoded_ack_only_fields.has_value()) {
            COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_plaintext_bytes, plaintext_size);
            COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_frames, 1);

            return CodecResult<ReceivedProtectedPacketDecodeResult>::success(
                ReceivedProtectedPacketDecodeResult{
                    .packet =
                        ReceivedProtectedOneRttAckOnlyPacket{
                            .spin_bit = decoded_ack_only_fields.value().spin_bit,
                            .key_phase = decoded_ack_only_fields.value().key_phase,
                            .destination_connection_id = std::move(
                                decoded_ack_only_fields.value().destination_connection_id),
                            .packet_number_length =
                                decoded_ack_only_fields.value().packet_number_length,
                            .packet_number = packet_number.value(),
                            .plaintext_storage = storage,
                            .ack = std::move(decoded_ack_only_fields.value().ack),
                        },
                    .bytes_consumed = bytes.size(),
                });
        }
    }

    auto decoded_fields = [&] {
        COQUIC_DESERIALIZE_PROFILE_TIMER(timer, frame_decode_ns);
        return decode_received_short_header_packet_fields(plaintext_header, plaintext_payload,
                                                          context.accept_greased_quic_bit);
    }();
    if (!decoded_fields.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            decoded_fields.error().code, decoded_fields.error().offset);
    }
    COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_plaintext_bytes, plaintext_size);
    COQUIC_ADD_DESERIALIZE_PROFILE_COUNTER(one_rtt_frames, decoded_fields.value().frames.size());

    return CodecResult<ReceivedProtectedPacketDecodeResult>::success(
        ReceivedProtectedPacketDecodeResult{
            .packet =
                ReceivedProtectedOneRttPacket{
                    .spin_bit = decoded_fields.value().spin_bit,
                    .key_phase = decoded_fields.value().key_phase,
                    .destination_connection_id =
                        std::move(decoded_fields.value().destination_connection_id),
                    .packet_number_length = decoded_fields.value().packet_number_length,
                    .packet_number = packet_number.value(),
                    .plaintext_storage = storage,
                    .frames = std::move(decoded_fields.value().frames),
                },
            .bytes_consumed = bytes.size(),
        });
}

CodecResult<bool> append_serialized_protected_packet(SerializedProtectedDatagram &datagram,
                                                     const ProtectedPacket &packet,
                                                     const SerializeProtectionContext &context) {
    const auto offset = datagram.bytes.size();
    const auto appended = std::visit(
        [&](const auto &typed_packet) -> CodecResult<std::size_t> {
            using PacketType = std::decay_t<decltype(typed_packet)>;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                const auto encoded = serialize_protected_initial_packet(typed_packet, context);
                if (!encoded.has_value()) {
                    return CodecResult<std::size_t>::failure(encoded.error().code,
                                                             encoded.error().offset);
                }
                datagram.bytes.append(encoded.value());
                return CodecResult<std::size_t>::success(encoded.value().size());
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                const auto encoded = serialize_protected_handshake_packet(typed_packet, context);
                if (!encoded.has_value()) {
                    return CodecResult<std::size_t>::failure(encoded.error().code,
                                                             encoded.error().offset);
                }
                datagram.bytes.append(encoded.value());
                return CodecResult<std::size_t>::success(encoded.value().size());
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                const auto encoded = serialize_protected_zero_rtt_packet(typed_packet, context);
                if (!encoded.has_value()) {
                    return CodecResult<std::size_t>::failure(encoded.error().code,
                                                             encoded.error().offset);
                }
                datagram.bytes.append(encoded.value());
                return CodecResult<std::size_t>::success(encoded.value().size());
            } else {
                return append_protected_one_rtt_packet_to_datagram_impl(datagram.bytes,
                                                                        typed_packet, context);
            }
        },
        packet);
    if (!appended.has_value()) {
        return CodecResult<bool>::failure(appended.error().code, appended.error().offset);
    }

    datagram.packet_metadata.push_back(SerializedProtectedPacketMetadata{
        .offset = offset,
        .length = appended.value(),
    });

    return CodecResult<bool>::success(true);
}

} // namespace detail

using namespace detail;

CodecResult<SerializedProtectedDatagram>
serialize_protected_datagram_with_metadata(std::span<const ProtectedPacket> packets,
                                           const SerializeProtectionContext &context) {
    SerializedProtectedDatagram out;
    out.packet_metadata.reserve(packets.size());
    for (const auto &packet : packets) {
        const auto appended = append_serialized_protected_packet(out, packet, context);
        if (!appended.has_value()) {
            return CodecResult<SerializedProtectedDatagram>::failure(appended.error().code,
                                                                     appended.error().offset);
        }
    }

    return CodecResult<SerializedProtectedDatagram>::success(std::move(out));
}

CodecResult<SerializedProtectedDatagram>
serialize_protected_datagram_with_metadata(std::span<const ProtectedPacket> packets,
                                           const ProtectedPacket &appended_packet,
                                           const SerializeProtectionContext &context) {
    auto encoded = serialize_protected_datagram_with_metadata(packets, context);
    if (!encoded.has_value()) {
        return CodecResult<SerializedProtectedDatagram>::failure(encoded.error().code,
                                                                 encoded.error().offset);
    }

    const auto appended =
        append_serialized_protected_packet(encoded.value(), appended_packet, context);
    if (!appended.has_value()) {
        return CodecResult<SerializedProtectedDatagram>::failure(appended.error().code,
                                                                 appended.error().offset);
    }

    return encoded;
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(DatagramBuffer &datagram,
                                            const ProtectedOneRttPacketView &packet,
                                            const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl(datagram, packet, context);
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacketView &packet,
                                            const SerializeProtectionContext &context) {
    DatagramBuffer encoded(datagram);
    const auto appended =
        append_protected_one_rtt_packet_to_datagram_impl(encoded, packet, context);
    if (!appended.has_value()) {
        return appended;
    }

    datagram = encoded.to_vector();
    return appended;
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(DatagramBuffer &datagram,
                                            const ProtectedOneRttPacketFragmentView &packet,
                                            const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl(datagram, packet, context);
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacketFragmentView &packet,
                                            const SerializeProtectionContext &context) {
    DatagramBuffer encoded(datagram);
    const auto appended =
        append_protected_one_rtt_packet_to_datagram_impl(encoded, packet, context);
    if (!appended.has_value()) {
        return appended;
    }

    datagram = encoded.to_vector();
    return appended;
}

CodecResult<std::vector<std::byte>>
serialize_protected_datagram(std::span<const ProtectedPacket> packets,
                             const SerializeProtectionContext &context) {
    auto encoded = serialize_protected_datagram_with_metadata(packets, context);
    if (!encoded.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                            encoded.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(encoded.value().bytes));
}

CodecResult<std::vector<ProtectedPacket>>
deserialize_protected_datagram(std::span<const std::byte> bytes,
                               const DeserializeProtectionContext &context) {
    if (bytes.empty())
        return CodecResult<std::vector<ProtectedPacket>>::failure(CodecErrorCode::truncated_input,
                                                                  0);

    std::vector<ProtectedPacket> packets;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        CodecResult<ProtectedPacketDecodeResult> decoded =
            CodecResult<ProtectedPacketDecodeResult>::failure(
                CodecErrorCode::unsupported_packet_type, 0);
        const auto first_byte = std::to_integer<std::uint8_t>(bytes[offset]);
        if ((first_byte & 0x80u) == 0) {
            decoded = deserialize_protected_one_rtt_packet(bytes.subspan(offset), context);
        } else {
            const auto type =
                read_long_header_type(bytes.subspan(offset), context.accept_greased_quic_bit);
            if (!type.has_value())
                return CodecResult<std::vector<ProtectedPacket>>::failure(
                    type.error().code, offset + type.error().offset);

            if (type.value() == LongHeaderPacketType::initial) {
                decoded = deserialize_protected_initial_packet(bytes.subspan(offset), context);
            } else if (type.value() == LongHeaderPacketType::zero_rtt) {
                decoded = deserialize_protected_zero_rtt_packet(bytes.subspan(offset), context);
            } else {
                decoded = deserialize_protected_handshake_packet(bytes.subspan(offset), context);
            }
        }
        if (!decoded.has_value())
            return CodecResult<std::vector<ProtectedPacket>>::failure(
                decoded.error().code, offset + decoded.error().offset);

        packets.push_back(std::move(decoded.value().packet));
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<std::vector<ProtectedPacket>>::success(std::move(packets));
}

CodecResult<ReceivedProtectedPacket>
deserialize_received_protected_packet(std::span<const std::byte> bytes,
                                      const DeserializeProtectionContext &context) {
    if (bytes.empty()) {
        return CodecResult<ReceivedProtectedPacket>::failure(CodecErrorCode::truncated_input, 0);
    }

    CodecResult<ReceivedProtectedPacketDecodeResult> decoded =
        CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::unsupported_packet_type, 0);
    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x80u) == 0) {
        decoded = deserialize_received_protected_one_rtt_packet(bytes, context);
    } else {
        const auto type = read_long_header_type(bytes, context.accept_greased_quic_bit);
        if (!type.has_value()) {
            return CodecResult<ReceivedProtectedPacket>::failure(type.error().code,
                                                                 type.error().offset);
        }

        if (type.value() == LongHeaderPacketType::initial) {
            decoded = deserialize_received_protected_initial_packet(bytes, context);
        } else if (type.value() == LongHeaderPacketType::zero_rtt) {
            decoded = deserialize_received_protected_zero_rtt_packet(bytes, context);
        } else {
            decoded = deserialize_received_protected_handshake_packet(bytes, context);
        }
    }
    if (!decoded.has_value()) {
        return CodecResult<ReceivedProtectedPacket>::failure(decoded.error().code,
                                                             decoded.error().offset);
    }
    if (decoded.value().bytes_consumed != bytes.size()) {
        return CodecResult<ReceivedProtectedPacket>::failure(CodecErrorCode::packet_length_mismatch,
                                                             decoded.value().bytes_consumed);
    }

    return CodecResult<ReceivedProtectedPacket>::success(std::move(decoded.value().packet));
}

CodecResult<ReceivedProtectedPacket>
deserialize_received_protected_packet(const std::shared_ptr<std::vector<std::byte>> &storage,
                                      std::size_t begin, std::size_t end,
                                      const DeserializeProtectionContext &context) {
    if (!storage || begin >= end || end > storage->size()) {
        return CodecResult<ReceivedProtectedPacket>::failure(CodecErrorCode::truncated_input, 0);
    }

    const auto bytes = std::span<const std::byte>(*storage).subspan(begin, end - begin);
    if ((std::to_integer<std::uint8_t>(bytes.front()) & 0x80u) != 0) {
        return deserialize_received_protected_packet(bytes, context);
    }

    auto decoded = deserialize_received_protected_one_rtt_packet(storage, begin, end, context);
    if (!decoded.has_value()) {
        return CodecResult<ReceivedProtectedPacket>::failure(decoded.error().code,
                                                             decoded.error().offset);
    }
    if (decoded.value().bytes_consumed != bytes.size()) {
        return CodecResult<ReceivedProtectedPacket>::failure(CodecErrorCode::packet_length_mismatch,
                                                             decoded.value().bytes_consumed);
    }

    return CodecResult<ReceivedProtectedPacket>::success(std::move(decoded.value().packet));
}

CodecResult<ReceivedProtectedPacket>
deserialize_received_protected_packet_fast(const std::shared_ptr<std::vector<std::byte>> &storage,
                                           std::size_t begin, std::size_t end,
                                           const DeserializeProtectionContext &context) {
    if (!storage || begin >= end || end > storage->size()) {
        return CodecResult<ReceivedProtectedPacket>::failure(CodecErrorCode::truncated_input, 0);
    }

    const auto bytes = std::span<const std::byte>(*storage).subspan(begin, end - begin);
    if ((std::to_integer<std::uint8_t>(bytes.front()) & 0x80u) != 0) {
        return deserialize_received_protected_packet(bytes, context);
    }

    auto decoded = deserialize_received_protected_one_rtt_packet(storage, begin, end, context,
                                                                 /*ack_only_fast=*/true);
    if (!decoded.has_value()) {
        return CodecResult<ReceivedProtectedPacket>::failure(decoded.error().code,
                                                             decoded.error().offset);
    }
    if (decoded.value().bytes_consumed != bytes.size()) {
        return CodecResult<ReceivedProtectedPacket>::failure(CodecErrorCode::packet_length_mismatch,
                                                             decoded.value().bytes_consumed);
    }

    return CodecResult<ReceivedProtectedPacket>::success(std::move(decoded.value().packet));
}

CodecResult<std::vector<ReceivedProtectedPacket>>
deserialize_received_protected_datagram(std::span<const std::byte> bytes,
                                        const DeserializeProtectionContext &context) {
    if (bytes.empty()) {
        return CodecResult<std::vector<ReceivedProtectedPacket>>::failure(
            CodecErrorCode::truncated_input, 0);
    }

    std::vector<ReceivedProtectedPacket> packets;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        CodecResult<ReceivedProtectedPacketDecodeResult> decoded =
            CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
                CodecErrorCode::unsupported_packet_type, 0);
        const auto first_byte = std::to_integer<std::uint8_t>(bytes[offset]);
        if ((first_byte & 0x80u) == 0) {
            decoded = deserialize_received_protected_one_rtt_packet(bytes.subspan(offset), context);
        } else {
            const auto type =
                read_long_header_type(bytes.subspan(offset), context.accept_greased_quic_bit);
            if (!type.has_value()) {
                return CodecResult<std::vector<ReceivedProtectedPacket>>::failure(
                    type.error().code, offset + type.error().offset);
            }

            if (type.value() == LongHeaderPacketType::initial) {
                decoded =
                    deserialize_received_protected_initial_packet(bytes.subspan(offset), context);
            } else if (type.value() == LongHeaderPacketType::zero_rtt) {
                decoded =
                    deserialize_received_protected_zero_rtt_packet(bytes.subspan(offset), context);
            } else {
                decoded =
                    deserialize_received_protected_handshake_packet(bytes.subspan(offset), context);
            }
        }
        if (!decoded.has_value()) {
            return CodecResult<std::vector<ReceivedProtectedPacket>>::failure(
                decoded.error().code, offset + decoded.error().offset);
        }

        packets.push_back(std::move(decoded.value().packet));
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<std::vector<ReceivedProtectedPacket>>::success(std::move(packets));
}

} // namespace coquic::quic
