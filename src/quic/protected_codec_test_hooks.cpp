#include "src/quic/protected_codec.h"
#include "src/quic/protected_codec_internal.h"

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

#include "src/quic/buffer.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/packet_number.h"
#include "src/quic/protected_codec_test_hooks.h"
#include "src/quic/streams.h"
#include "src/quic/version.h"

#if defined(COQUIC_COVERAGE_BUILD)
#define COQUIC_NO_PROFILE
#elif defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

#ifndef COQUIC_PROFILE_HOOKS
#define COQUIC_PROFILE_HOOKS 1
#endif

namespace coquic::quic::test {

using namespace detail;

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacket &packet,
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

COQUIC_NO_PROFILE bool coverage_check(bool &ok, std::string_view suite_name, std::string_view label,
                                      bool condition) {
    if (!condition) {
        std::cerr << suite_name << " failed: " << label << '\n';
        ok = false;
    }
    return condition;
}

COQUIC_NO_PROFILE bool coverage_check_failure_path_for_tests() {
    bool local_ok = true;
    const bool condition = coverage_check(local_ok, "protected_codec_internal_coverage_for_tests",
                                          "intentional local false branch for coverage", false);
    const auto observed_failures =
        static_cast<unsigned>(!condition) + static_cast<unsigned>(!local_ok);
    return observed_failures == 2u;
}

COQUIC_NO_PROFILE void append_u32_be_for_tests(std::vector<std::byte> &bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 24)));
    bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 16)));
    bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 8)));
    bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value)));
}

COQUIC_NO_PROFILE CodecResult<std::vector<std::byte>> build_received_long_header_packet_for_tests(
    LongHeaderPacketType packet_type, std::uint32_t version,
    const ConnectionId &destination_connection_id, const ConnectionId &source_connection_id,
    std::span<const std::byte> token, bool has_token, std::uint8_t packet_number_length,
    std::uint64_t packet_number, std::span<const std::byte> plaintext_payload,
    CipherSuite cipher_suite, const PacketProtectionKeys &keys) {
    const auto truncated_packet_number =
        truncate_packet_number(packet_number, packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(truncated_packet_number.error().code,
                                                            truncated_packet_number.error().offset);
    }
    const auto payload_length = static_cast<std::uint64_t>(
        packet_number_length + plaintext_payload.size() + kPacketProtectionTagLength);

    std::vector<std::byte> packet_bytes;
    packet_bytes.push_back(static_cast<std::byte>(
        0x80u | 0x40u | ((encoded_long_header_type(packet_type, version) & 0x03u) << 4u) |
        ((packet_number_length - 1u) & 0x03u)));
    append_u32_be_for_tests(packet_bytes, version);
    packet_bytes.push_back(
        static_cast<std::byte>(static_cast<std::uint8_t>(destination_connection_id.size())));
    append_bytes(packet_bytes, destination_connection_id);
    packet_bytes.push_back(
        static_cast<std::byte>(static_cast<std::uint8_t>(source_connection_id.size())));
    append_bytes(packet_bytes, source_connection_id);
    if (has_token) {
        append_varint_unchecked(packet_bytes, token.size());
        append_bytes(packet_bytes, token);
    }
    append_varint_unchecked(packet_bytes, payload_length);
    append_packet_number(packet_bytes,
                         TruncatedPacketNumberEncoding{
                             .packet_number_length = packet_number_length,
                             .truncated_packet_number = truncated_packet_number.value(),
                         });

    const auto packet_number_offset = packet_bytes.size() - packet_number_length;
    const auto header_end = packet_bytes.size();
    packet_bytes.resize(header_end + plaintext_payload.size() + kPacketProtectionTagLength);

    const auto nonce = make_packet_protection_nonce_or_assert(keys.iv, packet_number);
    const auto ciphertext = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = cipher_suite,
        .key = keys.key,
        .nonce = nonce,
        .associated_data = std::span<const std::byte>(packet_bytes).first(header_end),
        .plaintext = plaintext_payload,
        .ciphertext = std::span<std::byte>(packet_bytes).subspan(header_end),
    });
    if (!ciphertext.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(ciphertext.error().code,
                                                            ciphertext.error().offset);
    }
    packet_bytes.resize(header_end + ciphertext.value());

    const auto protected_packet =
        apply_long_header_protection_in_place(std::span<std::byte>(packet_bytes),
                                              PacketNumberSpan{
                                                  .packet_number_offset = packet_number_offset,
                                                  .packet_number_length = packet_number_length,
                                              },
                                              cipher_suite, keys);
    if (!protected_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(protected_packet.error().code,
                                                            protected_packet.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(packet_bytes));
}

COQUIC_NO_PROFILE CodecResult<std::vector<std::byte>> build_received_one_rtt_packet_for_tests(
    bool spin_bit, bool key_phase, const ConnectionId &destination_connection_id,
    std::uint8_t packet_number_length, std::uint64_t packet_number,
    std::span<const std::byte> plaintext_payload, CipherSuite cipher_suite,
    const PacketProtectionKeys &keys) {
    const auto truncated_packet_number =
        truncate_packet_number(packet_number, packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(truncated_packet_number.error().code,
                                                            truncated_packet_number.error().offset);
    }

    std::vector<std::byte> packet_bytes;
    packet_bytes.push_back(make_short_header_first_byte(spin_bit, key_phase, packet_number_length));
    append_bytes(packet_bytes, destination_connection_id);
    append_packet_number(packet_bytes,
                         TruncatedPacketNumberEncoding{
                             .packet_number_length = packet_number_length,
                             .truncated_packet_number = truncated_packet_number.value(),
                         });

    const auto packet_number_offset = 1 + destination_connection_id.size();
    const auto header_end = packet_bytes.size();
    packet_bytes.resize(header_end + plaintext_payload.size() + kPacketProtectionTagLength);

    const auto nonce = make_packet_protection_nonce_or_assert(keys.iv, packet_number);
    const auto ciphertext = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = cipher_suite,
        .key = keys.key,
        .nonce = nonce,
        .associated_data = std::span<const std::byte>(packet_bytes).first(header_end),
        .plaintext = plaintext_payload,
        .ciphertext = std::span<std::byte>(packet_bytes).subspan(header_end),
    });
    if (!ciphertext.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(ciphertext.error().code,
                                                            ciphertext.error().offset);
    }
    packet_bytes.resize(header_end + ciphertext.value());

    const auto protected_packet =
        apply_short_header_protection_in_place(std::span<std::byte>(packet_bytes),
                                               PacketNumberSpan{
                                                   .packet_number_offset = packet_number_offset,
                                                   .packet_number_length = packet_number_length,
                                               },
                                               cipher_suite, keys);
    if (!protected_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(protected_packet.error().code,
                                                            protected_packet.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(packet_bytes));
}

ScopedProtectedCodecFaultInjector::ScopedProtectedCodecFaultInjector(
    ProtectedCodecFaultPoint fault_point, std::size_t occurrence)
    : previous_fault_point_(protected_codec_fault_state().fault_point),
      previous_occurrence_(protected_codec_fault_state().occurrence) {
    set_protected_codec_fault_state(fault_point, occurrence);
}

ScopedProtectedCodecFaultInjector::~ScopedProtectedCodecFaultInjector() {
    set_protected_codec_fault_state(previous_fault_point_, previous_occurrence_);
}

COQUIC_NO_PROFILE bool protected_codec_internal_coverage_for_tests() {
    bool ok = true;
    // Local predicates keep repeated CodecResult assertions readable across helper groups.
    const auto codec_failure_impl = [](const CodecError *error, CodecErrorCode code) {
        return error != nullptr && error->code == code;
    };
    const auto codec_failure_offset_impl = [](const CodecError *error, CodecErrorCode code,
                                              std::size_t offset) {
        return error != nullptr && error->code == code && error->offset == offset;
    };
    const auto codec_failure = [&](const auto &result, CodecErrorCode code) {
        return codec_failure_impl(std::get_if<CodecError>(&result.storage), code);
    };
    const auto codec_any_failure = [&](const auto &result) {
        return std::holds_alternative<CodecError>(result.storage);
    };
    const auto codec_failure_offset = [&](const auto &result, CodecErrorCode code,
                                          std::size_t offset) {
        return codec_failure_offset_impl(std::get_if<CodecError>(&result.storage), code, offset);
    };
    const auto optional_failure = [&](const std::optional<CodecError> &error, CodecErrorCode code,
                                      std::size_t offset) {
        if (!error.has_value()) {
            return false;
        }
        return codec_failure_offset_impl(&*error, code, offset);
    };

    // Error helper checks cover successes, wrong codes, wrong offsets, and matching failures.
    {
        std::optional<CodecError> missing_error;
        const std::optional<CodecError> mismatched_code_error =
            CodecError{CodecErrorCode::truncated_input, 0};
        const std::optional<CodecError> mismatched_offset_error =
            CodecError{CodecErrorCode::invalid_varint, 1};
        const std::optional<CodecError> matching_error =
            CodecError{CodecErrorCode::invalid_varint, 0};
        missing_error = CodecError{CodecErrorCode::invalid_varint, 0};
        missing_error.reset();
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "coverage_check failure path updates only local state",
                       coverage_check_failure_path_for_tests());
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "codec failure helper rejects successes",
            !codec_failure(CodecResult<std::size_t>::success(0), CodecErrorCode::invalid_varint));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "codec failure helper rejects mismatched codes",
            !codec_failure(CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0),
                           CodecErrorCode::invalid_varint));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "codec failure helper matches expected failures",
            codec_failure(CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0),
                          CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "codec failure offset helper rejects successes",
                       !codec_failure_offset(CodecResult<std::size_t>::success(0),
                                             CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "codec failure offset helper rejects mismatched codes",
                       !codec_failure_offset(
                           CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0),
                           CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "codec failure offset helper rejects mismatched offsets",
                       !codec_failure_offset(
                           CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 1),
                           CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "codec failure offset helper matches expected failures",
                       codec_failure_offset(
                           CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0),
                           CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "optional failure helper rejects missing errors",
                       !optional_failure(missing_error, CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "optional failure helper rejects mismatched error codes",
                       !optional_failure(mismatched_code_error, CodecErrorCode::invalid_varint, 0));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "optional failure helper rejects mismatched error offsets",
            !optional_failure(mismatched_offset_error, CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "optional failure helper matches expected errors",
                       optional_failure(matching_error, CodecErrorCode::invalid_varint, 0));
    }

    // Packet builder guards are used by packet-path fixtures and should reject bad packet numbers
    // before attempting protection.
    {
        const auto valid_aes_128_keys = PacketProtectionKeys{
            .key = std::vector<std::byte>(16, std::byte{0x11}),
            .iv = std::vector<std::byte>(12, std::byte{0x22}),
            .hp_key = std::vector<std::byte>(16, std::byte{0x33}),
        };
        const std::array payload = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        const std::array header_sample_payload = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
            std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b}, std::byte{0x0c},
            std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f}, std::byte{0x10},
        };
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "build_received_long_header_packet_for_tests rejects invalid packet number "
                       "lengths",
                       codec_failure(build_received_long_header_packet_for_tests(
                                         LongHeaderPacketType::initial, kQuicVersion1,
                                         ConnectionId{std::byte{0xaa}},
                                         ConnectionId{std::byte{0xbb}}, {}, false,
                                         /*packet_number_length=*/0, /*packet_number=*/1, payload,
                                         kInitialCipherSuite, PacketProtectionKeys{}),
                                     CodecErrorCode::invalid_varint));
        {
            const ScopedPacketCryptoFaultInjector injector{
                PacketCryptoFaultPoint::seal_payload_update};
            coverage_check(
                ok, "protected_codec_internal_coverage_for_tests",
                "build_received_long_header_packet_for_tests propagates seal failures",
                codec_failure(build_received_long_header_packet_for_tests(
                                  LongHeaderPacketType::initial, kQuicVersion1,
                                  ConnectionId{std::byte{0xaa}}, ConnectionId{std::byte{0xbb}}, {},
                                  false, /*packet_number_length=*/1, /*packet_number=*/1, payload,
                                  kInitialCipherSuite, valid_aes_128_keys),
                              CodecErrorCode::invalid_packet_protection_state));
        }
        {
            const ScopedPacketCryptoFaultInjector injector{
                PacketCryptoFaultPoint::header_protection_aes_update};
            coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                           "build_received_long_header_packet_for_tests propagates header "
                           "protection failures",
                           codec_failure(build_received_long_header_packet_for_tests(
                                             LongHeaderPacketType::initial, kQuicVersion1,
                                             ConnectionId{std::byte{0xaa}},
                                             ConnectionId{std::byte{0xbb}}, {}, false,
                                             /*packet_number_length=*/1, /*packet_number=*/1,
                                             payload, kInitialCipherSuite, valid_aes_128_keys),
                                         CodecErrorCode::header_protection_failed));
        }
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "build_received_one_rtt_packet_for_tests rejects invalid packet number "
            "lengths",
            codec_failure(build_received_one_rtt_packet_for_tests(
                              false, false, ConnectionId{std::byte{0xcc}},
                              /*packet_number_length=*/0, /*packet_number=*/1, payload,
                              CipherSuite::tls_aes_128_gcm_sha256, PacketProtectionKeys{}),
                          CodecErrorCode::invalid_varint));
        {
            const ScopedPacketCryptoFaultInjector injector{
                PacketCryptoFaultPoint::seal_payload_update};
            coverage_check(
                ok, "protected_codec_internal_coverage_for_tests",
                "build_received_one_rtt_packet_for_tests propagates seal failures",
                codec_any_failure(build_received_one_rtt_packet_for_tests(
                    false, false, ConnectionId{std::byte{0xcc}},
                    /*packet_number_length=*/1, /*packet_number=*/1, header_sample_payload,
                    CipherSuite::tls_aes_128_gcm_sha256, valid_aes_128_keys)));
        }
        {
            const ScopedPacketCryptoFaultInjector injector{
                PacketCryptoFaultPoint::header_protection_aes_update};
            coverage_check(
                ok, "protected_codec_internal_coverage_for_tests",
                "build_received_one_rtt_packet_for_tests propagates header protection "
                "failures",
                codec_any_failure(build_received_one_rtt_packet_for_tests(
                    false, false, ConnectionId{std::byte{0xcc}},
                    /*packet_number_length=*/1, /*packet_number=*/1, header_sample_payload,
                    CipherSuite::tls_aes_128_gcm_sha256, valid_aes_128_keys)));
        }
    }

    // BufferWriter varint helpers are checked before vector overloads so both append paths run.
    {
        BufferWriter writer;
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_varint(BufferWriter) rejects out-of-range values",
                       optional_failure(append_varint(writer, kMaxVarInt + 1u),
                                        CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_varint(BufferWriter) leaves output empty after failures",
                       writer.bytes().empty());
        static_cast<void>(append_varint(writer, 0x25u));
        append_varint_unchecked(writer, 0x0fu);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_varint(BufferWriter) and unchecked helper append encoded values",
                       writer.bytes() == std::vector<std::byte>{
                                             std::byte{0x25},
                                             std::byte{0x0f},
                                         });
    }

    // Raw byte and vector varint appenders cover empty inputs, rollback, and encoded output.
    {
        std::vector<std::byte> bytes{std::byte{0xaa}};
        append_bytes(bytes, {});
        append_bytes(bytes, std::array{
                                std::byte{0xbb},
                                std::byte{0xcc},
                            });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_bytes preserves prefixes and appends non-empty payloads",
                       bytes == std::vector<std::byte>{
                                    std::byte{0xaa},
                                    std::byte{0xbb},
                                    std::byte{0xcc},
                                });

        std::vector<std::byte> varints;
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_varint(vector) rejects out-of-range values",
                       optional_failure(append_varint(varints, kMaxVarInt + 1u),
                                        CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_varint(vector) leaves output empty after failures", varints.empty());
        static_cast<void>(append_varint(varints, 0x2au));
        append_varint_unchecked(varints, 0x0cu);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_varint(vector) and unchecked helper append encoded values",
                       varints == std::vector<std::byte>{
                                      std::byte{0x2a},
                                      std::byte{0x0c},
                                  });
    }

    coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                   "make_short_header_first_byte encodes spin, key phase, and packet number length",
                   make_short_header_first_byte(/*spin_bit=*/true, /*key_phase=*/true,
                                                /*packet_number_length=*/2) == std::byte{0x65});

    // Packet number writers exercise BufferWriter, vector, truncated span, and full span outputs.
    {
        constexpr TruncatedPacketNumberEncoding encoding{
            .packet_number_length = 2,
            .truncated_packet_number = 0x1234u,
        };
        BufferWriter writer;
        append_packet_number(writer, encoding);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "append_packet_number(BufferWriter) writes the truncated packet number bytes",
            writer.bytes() == std::vector<std::byte>{
                                  std::byte{0x12},
                                  std::byte{0x34},
                              });

        std::vector<std::byte> bytes;
        append_packet_number(bytes, encoding);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_packet_number(vector) writes the truncated packet number bytes",
                       bytes == std::vector<std::byte>{
                                    std::byte{0x12},
                                    std::byte{0x34},
                                });

        std::array<std::byte, 1> too_small_packet_number{};
        SpanBufferWriter too_small_writer(too_small_packet_number);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_packet_number(SpanBufferWriter) reports truncated output",
                       optional_failure(append_packet_number(too_small_writer, encoding),
                                        CodecErrorCode::truncated_input, 1));

        std::array<std::byte, 2> packet_number_bytes{};
        SpanBufferWriter full_writer(packet_number_bytes);
        const auto packet_number_result = append_packet_number(full_writer, encoding);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_packet_number(SpanBufferWriter) writes the full packet number",
                       !packet_number_result.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_packet_number(SpanBufferWriter) writes big-endian bytes",
                       packet_number_bytes == std::array{std::byte{0x12}, std::byte{0x34}});
    }

    // Big-endian u32 writes cover every truncated-output boundary before the success case.
    {
        std::array<std::byte, 0> no_u32_bytes{};
        SpanBufferWriter no_u32_writer(no_u32_bytes);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "write_u32_be fails when no output space is available",
                       optional_failure(write_u32_be(no_u32_writer, 0x12345678u),
                                        CodecErrorCode::truncated_input, 0));

        std::array<std::byte, 1> one_u32_byte{};
        SpanBufferWriter one_u32_writer(one_u32_byte);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "write_u32_be fails on the second byte when only one byte fits",
                       optional_failure(write_u32_be(one_u32_writer, 0x12345678u),
                                        CodecErrorCode::truncated_input, 1));

        std::array<std::byte, 2> two_u32_bytes{};
        SpanBufferWriter two_u32_writer(two_u32_bytes);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "write_u32_be fails on the third byte when only two bytes fit",
                       optional_failure(write_u32_be(two_u32_writer, 0x12345678u),
                                        CodecErrorCode::truncated_input, 2));

        std::array<std::byte, 3> three_u32_bytes{};
        SpanBufferWriter three_u32_writer(three_u32_bytes);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "write_u32_be fails on the final byte when only three bytes fit",
                       optional_failure(write_u32_be(three_u32_writer, 0x12345678u),
                                        CodecErrorCode::truncated_input, 3));

        std::array<std::byte, 4> u32_bytes{};
        SpanBufferWriter u32_writer(u32_bytes);
        const auto u32_result = write_u32_be(u32_writer, 0x12345678u);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "write_u32_be writes big-endian u32 values", !u32_result.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "write_u32_be writes bytes in network order",
                       u32_bytes == std::array{std::byte{0x12}, std::byte{0x34}, std::byte{0x56},
                                               std::byte{0x78}});
    }

    coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                   "minimum_payload_bytes_for_header_sample reports remaining sample padding",
                   minimum_payload_bytes_for_header_sample(2) == 2);
    coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                   "minimum_payload_bytes_for_header_sample saturates when sample fits",
                   minimum_payload_bytes_for_header_sample(4) == 0);
    // Fixed-size helper coverage includes empty integer reads after padding math.
    coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                   "read_u32_be returns zero for empty spans", read_u32_be({}) == 0u);

    // Frame payload sizing covers empty packet rejection, valid summing, and frame failures.
    {
        const std::array<Frame, 0> empty_frames{};
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialized_frame_payload_size rejects empty payloads",
                       codec_failure(serialized_frame_payload_size(empty_frames),
                                     CodecErrorCode::empty_packet_payload));

        const std::array<Frame, 2> valid_frames = {
            PingFrame{},
            PaddingFrame{.length = 1},
        };
        const auto valid_size = serialized_frame_payload_size(valid_frames);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialized_frame_payload_size sums valid frame sizes",
                       valid_size.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialized_frame_payload_size returns the summed size",
                       valid_size.value() == 2);

        const std::array<Frame, 1> invalid_frames = {
            PaddingFrame{.length = 0},
        };
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialized_frame_payload_size propagates frame serialization failures",
                       codec_failure(serialized_frame_payload_size(invalid_frames),
                                     CodecErrorCode::invalid_varint));
    }

    // Connection-id decoding covers missing lengths, QUIC v1 size limits, truncation, and success.
    {
        BufferReader missing_length_reader({});
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "read_connection_id propagates missing length failures",
                       codec_failure_offset(
                           read_connection_id(missing_length_reader, /*enforce_v1_limit=*/true),
                           CodecErrorCode::truncated_input, 0));

        const std::array<std::byte, 22> oversized_connection_id = {
            std::byte{21},   std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
            std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b}, std::byte{0x0c}, std::byte{0x0d},
            std::byte{0x0e}, std::byte{0x0f}, std::byte{0x10}, std::byte{0x11}, std::byte{0x12},
            std::byte{0x13}, std::byte{0x14},
        };
        BufferReader oversized_reader(oversized_connection_id);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "read_connection_id enforces the QUIC v1 connection-id limit",
            codec_failure_offset(read_connection_id(oversized_reader, /*enforce_v1_limit=*/true),
                                 CodecErrorCode::invalid_varint, 1));

        const std::array<std::byte, 2> truncated_connection_id = {
            std::byte{2},
            std::byte{0xaa},
        };
        BufferReader truncated_reader(truncated_connection_id);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "read_connection_id propagates truncated connection-id bodies",
            codec_failure_offset(read_connection_id(truncated_reader, /*enforce_v1_limit=*/false),
                                 CodecErrorCode::truncated_input, 1));

        const std::array<std::byte, 3> valid_connection_id = {
            std::byte{2},
            std::byte{0xaa},
            std::byte{0xbb},
        };
        BufferReader valid_reader(valid_connection_id);
        const auto decoded_connection_id =
            read_connection_id(valid_reader, /*enforce_v1_limit=*/true);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "read_connection_id returns the decoded connection id",
                       decoded_connection_id.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "read_connection_id preserves bytes",
                       decoded_connection_id.value() == ConnectionId{
                                                            std::byte{0xaa},
                                                            std::byte{0xbb},
                                                        });
    }

    // Long-header frame validation covers packet-type allow-lists and terminal lengthless frames.
    {
        const Frame ping = PingFrame{};
        const Frame ack = AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        };
        const Frame stream = StreamFrame{
            .has_length = false,
            .stream_id = 3,
            .stream_data = {std::byte{0x01}},
        };
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "frame_allowed_in_long_header_packet_type distinguishes zero-rtt and handshake rules",
            frame_allowed_in_long_header_packet_type(ping, LongHeaderPacketType::initial));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "frame_allowed_in_long_header_packet_type rejects ack frames in zero-rtt",
            !frame_allowed_in_long_header_packet_type(ack, LongHeaderPacketType::zero_rtt));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "frame_allowed_in_long_header_packet_type rejects stream frames in handshake packets",
            !frame_allowed_in_long_header_packet_type(stream, LongHeaderPacketType::handshake));

        const std::array<Frame, 1> invalid_initial_frames = {
            Frame(StreamFrame{
                .has_length = true,
                .stream_id = 4,
                .stream_data = {std::byte{0x02}},
            }),
        };
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "validate_long_header_frames rejects frames not allowed in the packet type",
            codec_failure_offset(
                validate_long_header_frames(invalid_initial_frames, LongHeaderPacketType::initial),
                CodecErrorCode::frame_not_allowed_in_packet_type, 0));

        const std::array<Frame, 2> lengthless_stream_frames = {
            Frame(StreamFrame{
                .has_length = false,
                .stream_id = 5,
                .stream_data = {std::byte{0x03}},
            }),
            Frame(PingFrame{}),
        };
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "validate_long_header_frames rejects non-terminal lengthless stream frames",
            codec_failure_offset(validate_long_header_frames(lengthless_stream_frames,
                                                             LongHeaderPacketType::zero_rtt),
                                 CodecErrorCode::packet_length_mismatch, 0));

        const std::array<Frame, 2> lengthless_datagram_frames = {
            Frame(DatagramFrame{
                .has_length = false,
                .data = {std::byte{0x05}},
            }),
            Frame(PingFrame{}),
        };
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "validate_long_header_frames rejects non-terminal lengthless datagram frames",
            codec_failure_offset(validate_long_header_frames(lengthless_datagram_frames,
                                                             LongHeaderPacketType::zero_rtt),
                                 CodecErrorCode::packet_length_mismatch, 0));

        const std::array<Frame, 1> terminal_lengthless_stream_frames = {
            Frame(StreamFrame{
                .has_length = false,
                .stream_id = 5,
                .stream_data = {std::byte{0x04}},
            }),
        };
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "validate_long_header_frames accepts terminal lengthless stream frames",
                       validate_long_header_frames(terminal_lengthless_stream_frames,
                                                   LongHeaderPacketType::zero_rtt)
                           .has_value());

        const std::array<Frame, 1> terminal_lengthless_datagram_frames = {
            Frame(DatagramFrame{
                .has_length = false,
                .data = {std::byte{0x06}},
            }),
        };
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "validate_long_header_frames accepts terminal lengthless datagram frames",
                       validate_long_header_frames(terminal_lengthless_datagram_frames,
                                                   LongHeaderPacketType::zero_rtt)
                           .has_value());

        const std::array<Frame, 2> length_prefixed_datagram_frames = {
            Frame(DatagramFrame{
                .has_length = true,
                .data = {std::byte{0x07}},
            }),
            Frame(PingFrame{}),
        };
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "validate_long_header_frames accepts non-terminal length-prefixed datagram frames",
            validate_long_header_frames(length_prefixed_datagram_frames,
                                        LongHeaderPacketType::zero_rtt)
                .has_value());

        const std::array<Frame, 1> valid_long_header_frames = {
            Frame(PingFrame{}),
        };
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "validate_long_header_frames accepts valid long-header payloads",
            validate_long_header_frames(valid_long_header_frames, LongHeaderPacketType::initial)
                .has_value());
    }

    // Protected payload frame validation covers one-RTT rules and received frame decode errors.
    {
        const ReceivedFrame ack = ReceivedAckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        };
        const ReceivedFrame ping = PingFrame{};
        const ReceivedFrame stream = ReceivedStreamFrame{
            .has_length = true,
            .stream_id = 1,
        };
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "frame_allowed_in_protected_payload_packet_type distinguishes one-rtt and zero-rtt "
            "rules",
            frame_allowed_in_protected_payload_packet_type(ack,
                                                           ProtectedPayloadPacketType::one_rtt));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "frame_allowed_in_protected_payload_packet_type rejects ack frames in "
                       "zero-rtt",
                       !frame_allowed_in_protected_payload_packet_type(
                           ack, ProtectedPayloadPacketType::zero_rtt));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "frame_allowed_in_protected_payload_packet_type rejects stream frames in "
                       "handshake packets",
                       !frame_allowed_in_protected_payload_packet_type(
                           stream, ProtectedPayloadPacketType::handshake));

        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "deserialize_received_frame_sequence rejects empty payloads",
            codec_failure_offset(deserialize_received_frame_sequence(
                                     SharedBytes{}, ProtectedPayloadPacketType::one_rtt, 7),
                                 CodecErrorCode::empty_packet_payload, 7));

        const auto decode_failure = deserialize_received_frame_sequence(
            SharedBytes{
                std::byte{0x02},
            },
            ProtectedPayloadPacketType::one_rtt, 11);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "deserialize_received_frame_sequence propagates frame decode failures",
                       !decode_failure.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "deserialize_received_frame_sequence reports frame decode error codes",
                       decode_failure.error().code == CodecErrorCode::truncated_input);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "deserialize_received_frame_sequence reports absolute frame decode offsets",
                       decode_failure.error().offset > 11);

        const auto serialized_ack = serialize_frame(AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_frame builds an ack frame fixture for protected payload checks",
                       serialized_ack.has_value());
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "deserialize_received_frame_sequence rejects frames forbidden in zero-rtt payloads",
            codec_failure_offset(
                deserialize_received_frame_sequence(SharedBytes(serialized_ack.value()),
                                                    ProtectedPayloadPacketType::zero_rtt, 19),
                CodecErrorCode::frame_not_allowed_in_packet_type, 19));

        const auto serialized_ping = serialize_frame(PingFrame{});
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_frame builds a ping frame fixture for protected payload checks",
                       serialized_ping.has_value());
        const auto decoded = deserialize_received_frame_sequence(
            SharedBytes(serialized_ping.value()), ProtectedPayloadPacketType::one_rtt, 23);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "deserialize_received_frame_sequence accepts valid payloads",
                       decoded.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "deserialize_received_frame_sequence returns one frame",
                       decoded.value().size() == 1);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "deserialize_received_frame_sequence returns a ping frame",
                       std::holds_alternative<PingFrame>(decoded.value().front()));

        // Fast stream decoding rejects malformed frame encodings before accepting a valid frame.
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "fast stream frame decoder rejects empty payloads",
            codec_failure_offset(try_decode_single_received_stream_frame_fast(SharedBytes{}, 31),
                                 CodecErrorCode::empty_packet_payload, 31));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "fast stream frame decoder rejects non-stream frame types",
                       codec_failure_offset(try_decode_single_received_stream_frame_fast(
                                                SharedBytes{std::byte{0x01}}, 37),
                                            CodecErrorCode::unknown_frame_type, 37));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "fast stream frame decoder rejects truncated stream ids",
                       codec_failure_offset(try_decode_single_received_stream_frame_fast(
                                                SharedBytes{std::byte{0x08}}, 41),
                                            CodecErrorCode::truncated_input, 42));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "fast stream frame decoder rejects partially encoded multi-byte stream ids",
                       codec_failure_offset(try_decode_single_received_stream_frame_fast(
                                                SharedBytes{std::byte{0x08}, std::byte{0x40}}, 42),
                                            CodecErrorCode::truncated_input, 43));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "fast stream frame decoder rejects truncated stream offsets",
                       codec_failure_offset(try_decode_single_received_stream_frame_fast(
                                                SharedBytes{std::byte{0x0c}, std::byte{0x01}}, 43),
                                            CodecErrorCode::truncated_input, 45));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "fast stream frame decoder rejects truncated explicit lengths",
                       codec_failure_offset(try_decode_single_received_stream_frame_fast(
                                                SharedBytes{std::byte{0x0a}, std::byte{0x01}}, 47),
                                            CodecErrorCode::truncated_input, 49));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "fast stream frame decoder rejects explicit lengths beyond the payload",
                       codec_failure_offset(try_decode_single_received_stream_frame_fast(
                                                SharedBytes{std::byte{0x0a}, std::byte{0x01},
                                                            std::byte{0x02}, std::byte{0xaa}},
                                                53),
                                            CodecErrorCode::truncated_input, 56));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "fast stream frame decoder rejects trailing bytes after explicit-length stream data",
            codec_failure_offset(try_decode_single_received_stream_frame_fast(
                                     SharedBytes{std::byte{0x0a}, std::byte{0x01}, std::byte{0x01},
                                                 std::byte{0xaa}, std::byte{0xbb}},
                                     59),
                                 CodecErrorCode::unknown_frame_type, 63));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "fast stream frame decoder rejects overflowing stream data offsets",
            codec_failure_offset(
                try_decode_single_received_stream_frame_fast(
                    SharedBytes{std::byte{0x0c}, std::byte{0x01}, std::byte{0xff}, std::byte{0xff},
                                std::byte{0xff}, std::byte{0xff}, std::byte{0xff}, std::byte{0xff},
                                std::byte{0xff}, std::byte{0xff}, std::byte{0xaa}},
                    67),
                CodecErrorCode::invalid_varint, 77));
        const auto fast_stream = try_decode_single_received_stream_frame_fast(
            SharedBytes{std::byte{0x0f}, std::byte{0x01}, std::byte{0x01}, std::byte{0x02},
                        std::byte{0xaa}, std::byte{0xbb}},
            79);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "fast stream frame decoder accepts valid explicit-length stream frames",
                       fast_stream.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "fast stream frame decoder returns one stream frame",
                       fast_stream.value().size() == 1);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "fast stream frame decoder returns a stream frame variant",
                       std::holds_alternative<ReceivedStreamFrame>(fast_stream.value().front()));
    }

    // Short-header fast-path decoders cover ack-only and stream payload guard branches.
    {
        const auto empty_ack_payload = SharedBytes{};
        const auto non_ack_payload = SharedBytes{std::byte{0x01}};
        const auto invalid_ack_payload = SharedBytes{std::byte{0x02}};
        const auto invalid_ecn_ack_payload = SharedBytes{std::byte{0x03}};
        const auto valid_ack_payload = SharedBytes{
            std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
        const auto trailing_ack_payload =
            SharedBytes{std::byte{0x02}, std::byte{0x00}, std::byte{0x00},
                        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
        const auto stream_payload = SharedBytes{std::byte{0x08}, std::byte{0x00}};
        const auto length_prefixed_stream_payload =
            SharedBytes{std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}};
        const std::array<std::byte, 0> empty_header{};
        const std::array greased_header = {std::byte{0x00}, std::byte{0x00}};
        const std::array bad_fixed_header = {std::byte{0x00}};
        const std::array reserved_header = {std::byte{0x58}};
        const std::array missing_packet_number_header = {std::byte{0x41}};

        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header ack-only decoder rejects empty ack payload",
            codec_failure(try_decode_received_short_header_ack_only_packet_fields(
                              std::array{std::byte{0x40}, std::byte{0x00}}, empty_ack_payload),
                          CodecErrorCode::unknown_frame_type));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header ack-only decoder rejects non-ack payload",
            codec_failure(try_decode_received_short_header_ack_only_packet_fields(
                              std::array{std::byte{0x40}, std::byte{0x00}}, non_ack_payload),
                          CodecErrorCode::unknown_frame_type));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only decoder rejects empty header",
                       codec_failure(try_decode_received_short_header_ack_only_packet_fields(
                                         empty_header, valid_ack_payload),
                                     CodecErrorCode::truncated_input));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only decoder rejects invalid fixed bit",
                       codec_failure(try_decode_received_short_header_ack_only_packet_fields(
                                         bad_fixed_header, valid_ack_payload),
                                     CodecErrorCode::invalid_fixed_bit));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only decoder rejects reserved bits",
                       codec_failure(try_decode_received_short_header_ack_only_packet_fields(
                                         reserved_header, valid_ack_payload),
                                     CodecErrorCode::invalid_reserved_bits));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only decoder rejects missing packet number",
                       codec_failure(try_decode_received_short_header_ack_only_packet_fields(
                                         missing_packet_number_header, valid_ack_payload),
                                     CodecErrorCode::packet_length_mismatch));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header ack-only decoder rejects truncated ack",
            codec_failure(try_decode_received_short_header_ack_only_packet_fields(
                              std::array{std::byte{0x40}, std::byte{0x00}}, invalid_ack_payload),
                          CodecErrorCode::truncated_input));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only decoder rejects truncated ecn ack",
                       codec_failure(try_decode_received_short_header_ack_only_packet_fields(
                                         std::array{std::byte{0x40}, std::byte{0x00}},
                                         invalid_ecn_ack_payload),
                                     CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header ack-only decoder rejects trailing payload",
            codec_failure(try_decode_received_short_header_ack_only_packet_fields(
                              std::array{std::byte{0x40}, std::byte{0x00}}, trailing_ack_payload),
                          CodecErrorCode::unknown_frame_type));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only decoder accepts greased fixed bits when configured",
                       try_decode_received_short_header_ack_only_packet_fields(
                           greased_header, valid_ack_payload, true)
                           .has_value());

        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header ack-only fast decoder rejects empty ack payload",
            codec_failure(try_decode_received_short_header_ack_only_fast_packet_fields(
                              std::array{std::byte{0x40}, std::byte{0x00}}, empty_ack_payload),
                          CodecErrorCode::unknown_frame_type));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header ack-only fast decoder rejects non-ack payload",
            codec_failure(try_decode_received_short_header_ack_only_fast_packet_fields(
                              std::array{std::byte{0x40}, std::byte{0x00}}, non_ack_payload),
                          CodecErrorCode::unknown_frame_type));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only fast decoder rejects empty header",
                       codec_failure(try_decode_received_short_header_ack_only_fast_packet_fields(
                                         empty_header, valid_ack_payload),
                                     CodecErrorCode::truncated_input));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only fast decoder rejects invalid fixed bit",
                       codec_failure(try_decode_received_short_header_ack_only_fast_packet_fields(
                                         bad_fixed_header, valid_ack_payload),
                                     CodecErrorCode::invalid_fixed_bit));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only fast decoder rejects reserved bits",
                       codec_failure(try_decode_received_short_header_ack_only_fast_packet_fields(
                                         reserved_header, valid_ack_payload),
                                     CodecErrorCode::invalid_reserved_bits));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header ack-only fast decoder rejects missing packet number",
                       codec_failure(try_decode_received_short_header_ack_only_fast_packet_fields(
                                         missing_packet_number_header, valid_ack_payload),
                                     CodecErrorCode::packet_length_mismatch));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header ack-only fast decoder rejects truncated ack",
            codec_failure(try_decode_received_short_header_ack_only_fast_packet_fields(
                              std::array{std::byte{0x40}, std::byte{0x00}}, invalid_ack_payload),
                          CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header ack-only fast decoder rejects trailing payload",
            codec_failure(try_decode_received_short_header_ack_only_fast_packet_fields(
                              std::array{std::byte{0x40}, std::byte{0x00}}, trailing_ack_payload),
                          CodecErrorCode::unknown_frame_type));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header ack-only fast decoder accepts greased fixed bits when configured",
            try_decode_received_short_header_ack_only_fast_packet_fields(greased_header,
                                                                         valid_ack_payload, true)
                .has_value());

        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header stream fast decoder rejects empty payload",
                       codec_failure(try_decode_received_short_header_stream_fast_packet_fields(
                                         std::array<std::byte, 1>{std::byte{0x40}}, SharedBytes{}),
                                     CodecErrorCode::empty_packet_payload));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header stream fast decoder rejects empty header",
                       codec_failure(try_decode_received_short_header_stream_fast_packet_fields(
                                         empty_header, stream_payload),
                                     CodecErrorCode::truncated_input));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header stream fast decoder rejects invalid fixed bit",
                       codec_failure(try_decode_received_short_header_stream_fast_packet_fields(
                                         bad_fixed_header, stream_payload),
                                     CodecErrorCode::invalid_fixed_bit));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header stream fast decoder rejects reserved bits",
                       codec_failure(try_decode_received_short_header_stream_fast_packet_fields(
                                         reserved_header, stream_payload),
                                     CodecErrorCode::invalid_reserved_bits));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "short-header stream fast decoder rejects missing packet number",
                       codec_failure(try_decode_received_short_header_stream_fast_packet_fields(
                                         missing_packet_number_header, stream_payload),
                                     CodecErrorCode::packet_length_mismatch));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "short-header stream fast decoder accepts greased fixed bits when configured",
            try_decode_received_short_header_stream_fast_packet_fields(
                greased_header, length_prefixed_stream_payload, true)
                .has_value());
    }

    // Simple outbound ACK serialization covers invalid ranges, truncation, ECN, and sizing.
    {
        const OutboundAckFrame valid_ack{
            .header =
                OutboundAckHeader{
                    .largest_acknowledged = 0,
                    .first_ack_range = 0,
                },
        };
        const OutboundAckFrame invalid_gap_ack{
            .header =
                OutboundAckHeader{
                    .largest_acknowledged = 0,
                    .first_ack_range = 0,
                    .additional_range_count = 1,
                    .additional_ranges = {AckRange{.gap = 0, .range_length = 0}},
                },
        };
        const OutboundAckFrame invalid_length_ack{
            .header =
                OutboundAckHeader{
                    .largest_acknowledged = 3,
                    .first_ack_range = 0,
                    .additional_range_count = 1,
                    .additional_ranges = {AckRange{.gap = 0, .range_length = 2}},
                },
        };
        const OutboundAckFrame valid_range_ack{
            .header =
                OutboundAckHeader{
                    .largest_acknowledged = 3,
                    .first_ack_range = 0,
                    .additional_range_count = 1,
                    .additional_ranges = {AckRange{.gap = 0, .range_length = 0}},
                },
        };
        const OutboundAckFrame ecn_ack{
            .header =
                OutboundAckHeader{
                    .largest_acknowledged = 0,
                    .first_ack_range = 0,
                    .ecn_counts = AckEcnCounts{.ect0 = 1, .ect1 = 2, .ecn_ce = 3},
                },
        };
        const auto write_ack_with_capacity = [](const OutboundAckFrame &ack, std::size_t capacity) {
            std::vector<std::byte> output(capacity);
            return write_simple_outbound_ack_payload(output, ack);
        };

        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "simple outbound ack payload sizing rejects invalid additional ranges",
                       codec_failure(simple_outbound_ack_payload_size(invalid_gap_ack),
                                     CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "simple outbound ack payload sizing rejects invalid range lengths",
                       codec_failure(simple_outbound_ack_payload_size(invalid_length_ack),
                                     CodecErrorCode::invalid_varint));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "simple outbound ack payload writer reports missing type field",
            codec_failure(write_ack_with_capacity(valid_ack, 0), CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "simple outbound ack payload writer reports missing largest ack field",
            codec_failure(write_ack_with_capacity(valid_ack, 1), CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "simple outbound ack payload writer reports missing ack delay field",
            codec_failure(write_ack_with_capacity(valid_ack, 2), CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "simple outbound ack payload writer reports missing range count field",
            codec_failure(write_ack_with_capacity(valid_ack, 3), CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "simple outbound ack payload writer reports missing first range field",
            codec_failure(write_ack_with_capacity(valid_ack, 4), CodecErrorCode::truncated_input));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "simple outbound ack payload writer rejects invalid gaps",
                       codec_failure(write_ack_with_capacity(invalid_gap_ack, 8),
                                     CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "simple outbound ack payload writer rejects invalid range lengths",
                       codec_failure(write_ack_with_capacity(invalid_length_ack, 8),
                                     CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "simple outbound ack payload writer reports truncated additional gap fields",
                       codec_failure(write_ack_with_capacity(valid_range_ack, 5),
                                     CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "simple outbound ack payload writer reports truncated additional range length fields",
            codec_failure(write_ack_with_capacity(valid_range_ack, 6),
                          CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "simple outbound ack payload writer reports truncated ECN ECT0 counters",
            codec_failure(write_ack_with_capacity(ecn_ack, 5), CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "simple outbound ack payload writer reports truncated ECN ECT1 counters",
            codec_failure(write_ack_with_capacity(ecn_ack, 6), CodecErrorCode::truncated_input));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "simple outbound ack payload writer reports truncated ECN CE counters",
            codec_failure(write_ack_with_capacity(ecn_ack, 7), CodecErrorCode::truncated_input));
    }

    coverage_check(
        ok, "protected_codec_internal_coverage_for_tests",
        "encoded_stream_frame_payload_size includes type, varints, and payload bytes",
        encoded_stream_frame_payload_size(/*stream_id=*/3, /*offset=*/1, /*payload_size=*/2) == 6);

    // Vector stream header serialization covers rollback on failures and success sizing.
    {
        std::vector<std::byte> overflow_header_prefix{std::byte{0xfe}};
        const auto overflow_header =
            serialize_stream_frame_header_into(overflow_header_prefix, StreamFrameHeaderFields{
                                                                           .stream_id = 1,
                                                                           .offset = kMaxVarInt,
                                                                           .payload_size = 1,
                                                                       });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(vector) rejects offset overflows",
                       codec_failure(overflow_header, CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(vector) rolls back offset failures",
                       overflow_header_prefix == std::vector<std::byte>{std::byte{0xfe}});

        std::vector<std::byte> invalid_stream_id_prefix{std::byte{0xee}};
        const auto invalid_stream_id = serialize_stream_frame_header_into(
            invalid_stream_id_prefix, StreamFrameHeaderFields{
                                          .fin = true,
                                          .stream_id = kMaxVarInt + 1u,
                                          .offset = 0,
                                          .payload_size = 2,
                                      });
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "serialize_stream_frame_header_into(vector) rolls back when stream id encoding fails",
            codec_failure(invalid_stream_id, CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(vector) preserves prefix on stream id "
                       "failures",
                       invalid_stream_id_prefix == std::vector<std::byte>{std::byte{0xee}});

        std::vector<std::byte> encoded_header;
        const auto valid_header =
            serialize_stream_frame_header_into(encoded_header, StreamFrameHeaderFields{
                                                                   .fin = true,
                                                                   .stream_id = 3,
                                                                   .offset = 1,
                                                                   .payload_size = 2,
                                                               });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(vector) encodes valid stream headers",
                       valid_header.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(vector) returns the encoded size",
                       valid_header.value() == encoded_header.size());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(vector) writes bytes",
                       !encoded_header.empty());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(vector) writes stream frame type bits",
                       encoded_header.front() == std::byte{0x0f});
    }

    // Span stream header serialization covers each fixed-capacity boundary.
    {
        std::array<std::byte, 0> no_header_space{};
        SpanBufferWriter no_header_writer(no_header_space);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "serialize_stream_frame_header_into(span) fails when the type byte does not fit",
            codec_failure(serialize_stream_frame_header_into(no_header_writer,
                                                             StreamFrameHeaderFields{
                                                                 .stream_id = 1,
                                                                 .offset = 0,
                                                                 .payload_size = 0,
                                                             }),
                          CodecErrorCode::truncated_input));

        std::array<std::byte, 1> one_header_byte{};
        SpanBufferWriter one_header_writer(one_header_byte);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "serialize_stream_frame_header_into(span) fails when the stream id varint does not fit",
            codec_failure_offset(serialize_stream_frame_header_into(one_header_writer,
                                                                    StreamFrameHeaderFields{
                                                                        .stream_id = 64,
                                                                        .offset = 0,
                                                                        .payload_size = 0,
                                                                    }),
                                 CodecErrorCode::truncated_input, 1));

        std::array<std::byte, 8> overflow_header_space{};
        SpanBufferWriter overflow_header_writer(overflow_header_space);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(span) rejects offset overflows",
                       codec_failure(serialize_stream_frame_header_into(overflow_header_writer,
                                                                        StreamFrameHeaderFields{
                                                                            .stream_id = 1,
                                                                            .offset = kMaxVarInt,
                                                                            .payload_size = 1,
                                                                        }),
                                     CodecErrorCode::invalid_varint));

        std::array<std::byte, 8> header_space{};
        SpanBufferWriter header_writer(header_space);
        const auto valid_header =
            serialize_stream_frame_header_into(header_writer, StreamFrameHeaderFields{
                                                                  .fin = true,
                                                                  .stream_id = 3,
                                                                  .offset = 1,
                                                                  .payload_size = 2,
                                                              });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(span) encodes valid stream headers",
                       valid_header.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(span) returns the encoded size",
                       valid_header.value() == header_writer.offset());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_header_into(span) writes stream frame type bits",
                       header_space.front() == std::byte{0x0f});
    }

    // Stream payload append helpers cover header failures and successful header+payload writes.
    {
        const std::array payload = {
            std::byte{0x44},
            std::byte{0x55},
        };

        std::vector<std::byte> overflow_payload_prefix{std::byte{0xab}};
        const auto overflow_payload = append_stream_frame_payload_into(overflow_payload_prefix,
                                                                       StreamFrameHeaderFields{
                                                                           .stream_id = 1,
                                                                           .offset = kMaxVarInt,
                                                                       },
                                                                       payload);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_payload_into propagates header serialization failures",
                       codec_failure(overflow_payload, CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_payload_into rolls back header serialization failures",
                       overflow_payload_prefix == std::vector<std::byte>{std::byte{0xab}});

        std::vector<std::byte> stream_frame_bytes;
        const auto appended_payload = append_stream_frame_payload_into(stream_frame_bytes,
                                                                       StreamFrameHeaderFields{
                                                                           .fin = true,
                                                                           .stream_id = 5,
                                                                           .offset = 0,
                                                                       },
                                                                       payload);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_payload_into appends valid headers and payload bytes",
                       appended_payload.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_payload_into reports valid encoded sizes",
                       appended_payload.value() ==
                           encoded_stream_frame_payload_size(/*stream_id=*/5, /*offset=*/0,
                                                             /*payload_size=*/payload.size()));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_payload_into writes the reported byte count",
                       stream_frame_bytes.size() == appended_payload.value());
    }

    // Span stream frame serialization covers header failures, payload truncation, and success.
    {
        const std::array payload = {
            std::byte{0x66},
            std::byte{0x77},
        };
        const StreamFrameHeaderFields header{
            .stream_id = 9,
            .offset = 1,
        };
        std::vector<std::byte> overflow_stream_output(8);

        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_into propagates header serialization failures",
                       codec_failure(serialize_stream_frame_into(overflow_stream_output,
                                                                 StreamFrameHeaderFields{
                                                                     .stream_id = 1,
                                                                     .offset = kMaxVarInt,
                                                                 },
                                                                 payload),
                                     CodecErrorCode::invalid_varint));

        std::vector<std::byte> header_bytes;
        const auto header_size_result =
            serialize_stream_frame_header_into(header_bytes, StreamFrameHeaderFields{
                                                                 .stream_id = header.stream_id,
                                                                 .offset = header.offset,
                                                                 .payload_size = payload.size(),
                                                             });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_into computes a header size fixture",
                       header_size_result.has_value());
        const auto stream_header_size = header_size_result.value();
        std::vector<std::byte> truncated_output(stream_header_size);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "serialize_stream_frame_into reports truncated payload output",
            codec_failure_offset(serialize_stream_frame_into(truncated_output, header, payload),
                                 CodecErrorCode::truncated_input, stream_header_size));

        std::vector<std::byte> output(stream_header_size + payload.size());
        const auto serialized = serialize_stream_frame_into(output, header, payload);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "serialize_stream_frame_into writes complete frames when the span is large enough",
            serialized.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_into returns the complete frame size",
                       serialized.value() == output.size());
    }

    // StreamFrameView helpers validate range and storage invariants before writing backed views.
    {
        const auto storage = std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{
            std::byte{0x10},
            std::byte{0x11},
            std::byte{0x12},
        });

        std::vector<std::byte> invalid_view_bytes;
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_view_into_datagram rejects inverted byte ranges",
                       codec_failure(append_stream_frame_view_into_datagram(invalid_view_bytes,
                                                                            StreamFrameView{
                                                                                .stream_id = 1,
                                                                                .offset = 0,
                                                                                .storage = storage,
                                                                                .begin = 2,
                                                                                .end = 1,
                                                                            }),
                                     CodecErrorCode::invalid_varint));

        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "append_stream_frame_view_into_datagram rejects non-empty views without storage",
            codec_failure(append_stream_frame_view_into_datagram(invalid_view_bytes,
                                                                 StreamFrameView{
                                                                     .stream_id = 1,
                                                                     .offset = 0,
                                                                     .begin = 0,
                                                                     .end = 1,
                                                                 }),
                          CodecErrorCode::invalid_varint));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "append_stream_frame_view_into_datagram rejects storage-backed views that overrun "
            "storage",
            codec_failure(append_stream_frame_view_into_datagram(invalid_view_bytes,
                                                                 StreamFrameView{
                                                                     .stream_id = 1,
                                                                     .offset = 0,
                                                                     .storage = storage,
                                                                     .begin = 0,
                                                                     .end = 4,
                                                                 }),
                          CodecErrorCode::invalid_varint));

        std::vector<std::byte> zero_payload_bytes;
        const auto zero_payload_view =
            append_stream_frame_view_into_datagram(zero_payload_bytes, StreamFrameView{
                                                                           .fin = true,
                                                                           .stream_id = 7,
                                                                           .offset = 0,
                                                                           .begin = 0,
                                                                           .end = 0,
                                                                       });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_view_into_datagram accepts empty views without storage",
                       zero_payload_view.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_view_into_datagram reports empty view wire sizes",
                       zero_payload_view.value() ==
                           encoded_stream_frame_payload_size(/*stream_id=*/7, /*offset=*/0,
                                                             /*payload_size=*/0));

        std::vector<std::byte> nonzero_view_bytes;
        const auto nonzero_view =
            append_stream_frame_view_into_datagram(nonzero_view_bytes, StreamFrameView{
                                                                           .stream_id = 7,
                                                                           .offset = 1,
                                                                           .storage = storage,
                                                                           .begin = 1,
                                                                           .end = 3,
                                                                       });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_view_into_datagram accepts valid non-empty views",
                       nonzero_view.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_view_into_datagram reports non-empty view wire sizes",
                       nonzero_view.value() == encoded_stream_frame_payload_size(
                                                   /*stream_id=*/7, /*offset=*/1,
                                                   /*payload_size=*/2));

        std::vector<std::byte> invalid_view_output(8);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_view_into_span rejects inverted byte ranges",
                       codec_failure(serialize_stream_frame_view_into_span(invalid_view_output,
                                                                           StreamFrameView{
                                                                               .stream_id = 2,
                                                                               .offset = 0,
                                                                               .storage = storage,
                                                                               .begin = 2,
                                                                               .end = 1,
                                                                           }),
                                     CodecErrorCode::invalid_varint));

        std::vector<std::byte> missing_storage_output(8);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "serialize_stream_frame_view_into_span rejects non-empty views without storage",
            codec_failure(serialize_stream_frame_view_into_span(missing_storage_output,
                                                                StreamFrameView{
                                                                    .stream_id = 2,
                                                                    .offset = 0,
                                                                    .begin = 0,
                                                                    .end = 1,
                                                                }),
                          CodecErrorCode::invalid_varint));
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "serialize_stream_frame_view_into_span rejects storage-backed views that overrun "
            "storage",
            codec_failure(serialize_stream_frame_view_into_span(missing_storage_output,
                                                                StreamFrameView{
                                                                    .stream_id = 2,
                                                                    .offset = 0,
                                                                    .storage = storage,
                                                                    .begin = 0,
                                                                    .end = 4,
                                                                }),
                          CodecErrorCode::invalid_varint));

        std::vector<std::byte> serialized_view_output(
            encoded_stream_frame_payload_size(/*stream_id=*/2, /*offset=*/0, /*payload_size=*/2));
        const auto serialized_view =
            serialize_stream_frame_view_into_span(serialized_view_output, StreamFrameView{
                                                                              .stream_id = 2,
                                                                              .offset = 0,
                                                                              .storage = storage,
                                                                              .begin = 0,
                                                                              .end = 2,
                                                                          });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_view_into_span accepts valid views",
                       serialized_view.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_view_into_span reports the written byte count",
                       serialized_view.value() == serialized_view_output.size());

        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "stream_frame_view_payload_span rejects inverted ranges",
                       codec_failure(stream_frame_view_payload_span(StreamFrameView{
                                         .storage = storage,
                                         .begin = 2,
                                         .end = 1,
                                     }),
                                     CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "stream_frame_view_payload_span rejects missing backing storage",
                       codec_failure(stream_frame_view_payload_span(StreamFrameView{
                                         .begin = 0,
                                         .end = 1,
                                     }),
                                     CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "stream_frame_view_payload_span rejects undersized backing storage",
                       codec_failure(stream_frame_view_payload_span(StreamFrameView{
                                         .storage = storage,
                                         .begin = 0,
                                         .end = 4,
                                     }),
                                     CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "stream_frame_view_payload_span accepts empty views",
                       stream_frame_view_payload_span(StreamFrameView{}).has_value());
        const auto valid_payload_span = stream_frame_view_payload_span(StreamFrameView{
            .storage = storage,
            .begin = 1,
            .end = 3,
        });
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "stream_frame_view_payload_span accepts storage-backed views",
                       valid_payload_span.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "stream_frame_view_payload_span reports valid storage-backed view sizes",
                       valid_payload_span.value().size() == 2);

        std::array<std::byte, 8> invalid_header_output{};
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "write_stream_frame_view_header_into_span rejects inverted ranges",
            codec_failure(write_stream_frame_view_header_into_span(invalid_header_output,
                                                                   StreamFrameView{
                                                                       .storage = storage,
                                                                       .begin = 3,
                                                                       .end = 2,
                                                                   }),
                          CodecErrorCode::invalid_varint));

        std::array<std::byte, 8> valid_header_output{};
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "write_stream_frame_view_header_into_span writes valid stream headers",
                       write_stream_frame_view_header_into_span(valid_header_output,
                                                                StreamFrameView{
                                                                    .fin = true,
                                                                    .stream_id = 2,
                                                                    .offset = 1,
                                                                    .storage = storage,
                                                                    .begin = 1,
                                                                    .end = 3,
                                                                })
                           .has_value());
    }

    // StreamFrameSendFragment helpers cover datagram append, span serialization, and truncation.
    {
        const StreamFrameSendFragment valid_fragment{
            .stream_id = 11,
            .offset = 3,
            .bytes = SharedBytes(std::vector<std::byte>{
                std::byte{0xde},
                std::byte{0xad},
            }),
            .fin = true,
        };
        const auto fragment_header = valid_fragment.stream_frame_header_bytes();
        const auto fragment_size = fragment_header.size() + valid_fragment.bytes.size();

        std::vector<std::byte> fragment_bytes;
        const auto appended_fragment =
            append_stream_frame_send_fragment_to_datagram(fragment_bytes, valid_fragment);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_send_fragment_to_datagram appends valid fragments",
                       appended_fragment.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_send_fragment_to_datagram reports fragment sizes",
                       appended_fragment.value() == fragment_size);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_send_fragment_to_datagram writes fragment bytes",
                       fragment_bytes.size() == fragment_size);

        const StreamFrameSendFragment invalid_fragment{
            .stream_id = 11,
            .offset = kMaxVarInt,
            .bytes = SharedBytes(std::vector<std::byte>{
                std::byte{0xde},
            }),
            .fin = false,
        };
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "append_stream_frame_send_fragment_to_datagram rejects overflowing offsets",
                       codec_failure(append_stream_frame_send_fragment_to_datagram(
                                         fragment_bytes, invalid_fragment),
                                     CodecErrorCode::invalid_varint));

        std::vector<std::byte> invalid_fragment_output(fragment_size);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_send_fragment_into_span rejects overflowing offsets",
                       codec_failure(serialize_stream_frame_send_fragment_into_span(
                                         invalid_fragment_output, invalid_fragment),
                                     CodecErrorCode::invalid_varint));

        std::vector<std::byte> truncated_header_output(fragment_header.size() - 1);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "serialize_stream_frame_send_fragment_into_span reports truncated header space",
            codec_failure(serialize_stream_frame_send_fragment_into_span(truncated_header_output,
                                                                         valid_fragment),
                          CodecErrorCode::truncated_input));

        std::vector<std::byte> truncated_payload_output(fragment_size - 1);
        coverage_check(
            ok, "protected_codec_internal_coverage_for_tests",
            "serialize_stream_frame_send_fragment_into_span reports truncated payload space",
            codec_failure_offset(serialize_stream_frame_send_fragment_into_span(
                                     truncated_payload_output, valid_fragment),
                                 CodecErrorCode::truncated_input, fragment_header.size()));

        std::vector<std::byte> fragment_output(fragment_size);
        const auto serialized_fragment =
            serialize_stream_frame_send_fragment_into_span(fragment_output, valid_fragment);
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_send_fragment_into_span writes complete fragments",
                       serialized_fragment.has_value());
        coverage_check(ok, "protected_codec_internal_coverage_for_tests",
                       "serialize_stream_frame_send_fragment_into_span reports complete fragment "
                       "sizes",
                       serialized_fragment.value() == fragment_size);
    }

    return ok;
}

COQUIC_NO_PROFILE bool protected_codec_packet_path_coverage_for_tests() {
    bool ok = true;
    // Packet-path checks reuse compact CodecResult predicates for each packet family below.
    const auto codec_failure_impl = [](const CodecError *error, CodecErrorCode code) {
        return error != nullptr && error->code == code;
    };
    const auto codec_failure_offset_impl = [](const CodecError *error, CodecErrorCode code,
                                              std::size_t offset) {
        return error != nullptr && error->code == code && error->offset == offset;
    };
    const auto codec_failure = [&](const auto &result, CodecErrorCode code) {
        return codec_failure_impl(std::get_if<CodecError>(&result.storage), code);
    };
    const auto codec_failure_offset = [&](const auto &result, CodecErrorCode code,
                                          std::size_t offset) {
        return codec_failure_offset_impl(std::get_if<CodecError>(&result.storage), code, offset);
    };
    // Helper predicate coverage starts with success and mismatch rejection cases.
    {
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "packet-path codec failure helper matches expected failures and rejects successes",
            !codec_failure(CodecResult<std::size_t>::success(0), CodecErrorCode::invalid_varint));
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "packet-path codec failure helper matches expected failures",
            codec_failure(CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0),
                          CodecErrorCode::invalid_varint));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet-path codec failure offset helper rejects successes",
                       !codec_failure_offset(CodecResult<std::size_t>::success(0),
                                             CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet-path codec failure offset helper rejects mismatched codes",
                       !codec_failure_offset(
                           CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0),
                           CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet-path codec failure offset helper rejects mismatched offsets",
                       !codec_failure_offset(
                           CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 1),
                           CodecErrorCode::invalid_varint, 0));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet-path codec failure offset helper matches expected failures",
                       codec_failure_offset(
                           CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0),
                           CodecErrorCode::invalid_varint, 0));
    }
    const auto make_secret_bytes = [](std::size_t size, std::uint8_t seed) {
        std::vector<std::byte> secret(size);
        for (std::size_t index = 0; index < size; ++index) {
            secret[index] = static_cast<std::byte>(seed + static_cast<std::uint8_t>(index));
        }
        return secret;
    };
    // Invalid cipher suites and synthetic long headers are fixtures for negative packet paths.
    const auto invalid_cipher_suite = []() {
        const auto raw = static_cast<std::underlying_type_t<CipherSuite>>(0xff);
        CipherSuite cipher_suite{};
        std::memcpy(&cipher_suite, &raw, sizeof(cipher_suite));
        return cipher_suite;
    };
    const auto append_u32_be = [](std::vector<std::byte> &bytes, std::uint32_t value) {
        bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 24)));
        bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 16)));
        bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 8)));
        bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value)));
    };
    const auto build_long_header = [&](std::byte first_byte, std::uint32_t version,
                                       std::span<const std::byte> destination_connection_id,
                                       std::span<const std::byte> source_connection_id,
                                       std::span<const std::byte> token, bool has_token,
                                       std::uint64_t payload_length,
                                       std::span<const std::byte> packet_number_bytes) {
        std::vector<std::byte> header{first_byte};
        append_u32_be(header, version);
        header.push_back(
            static_cast<std::byte>(static_cast<std::uint8_t>(destination_connection_id.size())));
        append_bytes(header, destination_connection_id);
        header.push_back(
            static_cast<std::byte>(static_cast<std::uint8_t>(source_connection_id.size())));
        append_bytes(header, source_connection_id);
        if (has_token) {
            static_cast<void>(append_varint(header, token.size()));
            append_bytes(header, token);
        }
        static_cast<void>(append_varint(header, payload_length));
        append_bytes(header, packet_number_bytes);
        return header;
    };

    const auto crypto_payload = serialize_frame(CryptoFrame{
        .offset = 0,
        .crypto_data = {std::byte{0x42}},
    });
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "serialize_frame builds a crypto payload fixture", crypto_payload.has_value());

    const auto ping_payload = serialize_frame(PingFrame{});
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "serialize_frame builds a ping payload fixture", ping_payload.has_value());

    const auto ack_payload = serialize_frame(AckFrame{
        .largest_acknowledged = 0,
        .first_ack_range = 0,
    });
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "serialize_frame builds an ack payload fixture", ack_payload.has_value());

    const auto stream_payload = serialize_frame(StreamFrame{
        .has_length = true,
        .stream_id = 3,
        .stream_data = {std::byte{0x33}},
    });
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "serialize_frame builds a stream payload fixture", stream_payload.has_value());
    // Generic failure predicates also cover the concrete packet-result wrapper types.
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "codec_failure_offset rejects successful results",
                   !codec_failure_offset(CodecResult<std::size_t>::success(7),
                                         CodecErrorCode::invalid_varint, 0));
    coverage_check(
        ok, "protected_codec_packet_path_coverage_for_tests",
        "codec_failure_offset rejects mismatched error codes",
        !codec_failure_offset(CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0),
                              CodecErrorCode::invalid_varint, 0));
    coverage_check(
        ok, "protected_codec_packet_path_coverage_for_tests",
        "codec_failure_offset rejects mismatched offsets",
        !codec_failure_offset(CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 1),
                              CodecErrorCode::invalid_varint, 2));
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "codec_failure rejects successful received decode results",
                   !codec_failure(CodecResult<ReceivedProtectedPacketDecodeResult>::success(
                                      ReceivedProtectedPacketDecodeResult{
                                          .packet = ReceivedProtectedInitialPacket{},
                                          .bytes_consumed = 0,
                                      }),
                                  CodecErrorCode::invalid_varint));
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "codec_failure rejects mismatched received decode error codes",
                   !codec_failure(CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
                                      CodecErrorCode::truncated_input, 0),
                                  CodecErrorCode::invalid_varint));
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "codec_failure rejects successful serialized datagrams",
                   !codec_failure(CodecResult<SerializedProtectedDatagram>::success(
                                      SerializedProtectedDatagram{}),
                                  CodecErrorCode::invalid_varint));
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "codec_failure rejects mismatched serialized datagram error codes",
                   !codec_failure(CodecResult<SerializedProtectedDatagram>::failure(
                                      CodecErrorCode::truncated_input, 0),
                                  CodecErrorCode::invalid_varint));

    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "packet path fixtures serialize before dependent checks",
                   crypto_payload.has_value());
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "ping fixture serializes before dependent checks", ping_payload.has_value());
    coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                   "ack fixture serializes before dependent checks", ack_payload.has_value());

    {
        // Long-header layout coverage starts from a valid Initial packet fixture.
        const auto long_header_header = build_long_header(
            std::byte{0xc0}, kQuicVersion1, std::array{std::byte{0xaa}},
            std::array{std::byte{0xbb}}, std::array{std::byte{0xcc}},
            /*has_token=*/true,
            /*payload_length=*/1u + crypto_payload.value().size(), std::array{std::byte{0x01}});
        auto long_header_packet = long_header_header;
        append_bytes(long_header_packet, crypto_payload.value());

        const auto layout =
            locate_long_header_or_assert(long_header_packet, LongHeaderPacketType::initial);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "locate_long_header_or_assert finds an initial packet layout",
                       layout.length_offset > 0);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "locate_long_header_or_assert finds the packet end",
                       layout.packet_end_offset == long_header_packet.size());

        const std::array missing_fixed_bit_header = {
            std::byte{0x80},
        };
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "locate_long_header rejects missing fixed bits",
                       codec_failure(locate_long_header(missing_fixed_bit_header,
                                                        LongHeaderPacketType::initial),
                                     CodecErrorCode::invalid_fixed_bit));

        auto patched_packet = long_header_packet;
        const auto patched =
            patch_long_header_length_field_or_assert(patched_packet, layout, layout.length_value);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "patch_long_header_length_field_or_assert preserves valid packet layouts",
                       patched.packet_number_offset == layout.packet_number_offset);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "patch_long_header_length_field_or_assert preserves packet size",
                       patched_packet.size() == long_header_packet.size());

        auto unprotected = RemovedLongHeaderProtection{
            .packet_bytes = long_header_packet,
            .packet_number_length = 1,
            .truncated_packet_number = 1,
        };
        const auto rebuilt_header =
            build_long_header_plaintext_header(unprotected, layout, crypto_payload.value().size());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "build_long_header_plaintext_header rebuilds plaintext headers",
                       rebuilt_header.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "build_long_header_plaintext_header preserves header bytes",
                       rebuilt_header.value() == long_header_header);

        const auto oversized_rebuilt_header = build_long_header_plaintext_header(
            RemovedLongHeaderProtection{
                .packet_bytes =
                    {
                        std::byte{0xc0},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                    },
                .packet_number_length = 4,
                .truncated_packet_number = 0,
            },
            LongHeaderLayout{
                .length_offset = 0,
                .length_size = 1,
                .packet_number_offset = 0,
            },
            static_cast<std::size_t>(kMaxVarInt));
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "build_long_header_plaintext_header propagates oversized patched length failures",
            codec_failure_offset(oversized_rebuilt_header, CodecErrorCode::invalid_varint, 0));

        // Long-header append coverage exercises unsupported versions and length overflow guards.
        auto invalid_length_packet = long_header_packet;
        const auto oversized_length =
            patch_long_header_length_field(invalid_length_packet, layout, kMaxVarInt + 1u);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "patch_long_header_length_field rejects oversized payload lengths",
                       codec_failure_offset(oversized_length, CodecErrorCode::invalid_varint, 0));

        const std::array<Frame, 1> minimal_long_header_frames = {
            Frame(CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }),
        };
        std::vector<std::byte> version_negotiation_datagram;
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "append_protected_long_header_packet_to_datagram rejects version-negotiation packets",
            codec_failure(append_protected_long_header_packet_to_datagram(
                              version_negotiation_datagram, LongHeaderPacketType::initial,
                              kVersionNegotiationVersion, ConnectionId{std::byte{0xaa}}, {}, {},
                              TruncatedPacketNumberEncoding{
                                  .packet_number_length = 1,
                                  .truncated_packet_number = 0,
                              },
                              0, minimal_long_header_frames, kInitialCipherSuite,
                              PacketProtectionKeys{}),
                          CodecErrorCode::unsupported_packet_type));

        {
            const ScopedProtectedCodecFaultInjector injector{
                ProtectedCodecFaultPoint::long_header_frame_payload_varint_overflow};
            std::vector<std::byte> oversized_frame_payload_datagram;
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "append_protected_long_header_packet_to_datagram rejects frame payloads larger "
                "than the QUIC varint limit",
                codec_failure(append_protected_long_header_packet_to_datagram(
                                  oversized_frame_payload_datagram, LongHeaderPacketType::handshake,
                                  kQuicVersion1, ConnectionId{std::byte{0xaa}},
                                  ConnectionId{std::byte{0xbb}}, {},
                                  TruncatedPacketNumberEncoding{
                                      .packet_number_length = 1,
                                      .truncated_packet_number = 0,
                                  },
                                  0, minimal_long_header_frames, kInitialCipherSuite,
                                  PacketProtectionKeys{}),
                              CodecErrorCode::invalid_varint));
        }

        {
            const ScopedProtectedCodecFaultInjector injector{
                ProtectedCodecFaultPoint::long_header_payload_length_varint_overflow};
            std::vector<std::byte> oversized_payload_length_datagram;
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "append_protected_long_header_packet_to_datagram rejects payload lengths larger "
                "than the QUIC varint limit",
                codec_failure(append_protected_long_header_packet_to_datagram(
                                  oversized_payload_length_datagram,
                                  LongHeaderPacketType::handshake, kQuicVersion1,
                                  ConnectionId{std::byte{0xaa}}, ConnectionId{std::byte{0xbb}}, {},
                                  TruncatedPacketNumberEncoding{
                                      .packet_number_length = 1,
                                      .truncated_packet_number = 0,
                                  },
                                  0, minimal_long_header_frames, kInitialCipherSuite,
                                  PacketProtectionKeys{}),
                              CodecErrorCode::invalid_varint));
        }

        if constexpr (sizeof(std::size_t) >= sizeof(std::uint64_t)) {
            const auto oversized_token_size = static_cast<std::size_t>(kMaxVarInt) + 1u;
            const std::array fake_token_storage = {
                std::byte{0x7f},
            };
            std::vector<std::byte> oversized_token_datagram;
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "append_protected_long_header_packet_to_datagram rejects tokens larger than the "
                "QUIC varint limit",
                codec_failure(
                    append_protected_long_header_packet_to_datagram(
                        oversized_token_datagram, LongHeaderPacketType::initial, kQuicVersion1,
                        ConnectionId{std::byte{0xaa}}, ConnectionId{std::byte{0xbb}},
                        std::span<const std::byte>(fake_token_storage.data(), oversized_token_size),
                        TruncatedPacketNumberEncoding{
                            .packet_number_length = 1,
                            .truncated_packet_number = 0,
                        },
                        0, minimal_long_header_frames, kInitialCipherSuite, PacketProtectionKeys{}),
                    CodecErrorCode::invalid_varint));
        }

        // One-RTT plaintext conversion validates packet number length handling before decoding.
        const auto one_rtt_plaintext = to_plaintext_one_rtt(ProtectedOneRttPacket{
            .spin_bit = true,
            .key_phase = false,
            .destination_connection_id = {std::byte{0xde}, std::byte{0xad}},
            .packet_number_length = 2,
            .packet_number = 0x1234,
            .frames = {PingFrame{}},
        });
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "to_plaintext_one_rtt accepts valid packet number lengths",
                       one_rtt_plaintext.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "to_plaintext_one_rtt preserves truncated packet numbers",
                       one_rtt_plaintext.value().truncated_packet_number == 0x1234u);

        const auto invalid_one_rtt_plaintext = to_plaintext_one_rtt(ProtectedOneRttPacket{
            .destination_connection_id = {std::byte{0xde}},
            .packet_number_length = 0,
            .packet_number = 1,
            .frames = {PingFrame{}},
        });
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "to_plaintext_one_rtt rejects invalid packet number lengths",
            codec_failure_offset(invalid_one_rtt_plaintext, CodecErrorCode::invalid_varint, 0));

        // Received long-header plaintext decoding covers fixed, reserved, and length-field guards.
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decode_received_long_header_packet_fields rejects empty headers",
                       codec_failure_offset(decode_received_long_header_packet_fields(
                                                {}, SharedBytes(crypto_payload.value()),
                                                ProtectedPayloadPacketType::initial, true),
                                            CodecErrorCode::truncated_input, 0));

        const std::array missing_fixed_long_header = {
            std::byte{0x80},
        };
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "decode_received_long_header_packet_fields rejects missing fixed bits",
            codec_failure(decode_received_long_header_packet_fields(
                              missing_fixed_long_header, SharedBytes(crypto_payload.value()),
                              ProtectedPayloadPacketType::initial, true),
                          CodecErrorCode::invalid_fixed_bit));

        const std::array reserved_long_header = {
            std::byte{0xcc},
        };
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decode_received_long_header_packet_fields rejects reserved bits",
                       codec_failure(decode_received_long_header_packet_fields(
                                         reserved_long_header, SharedBytes(crypto_payload.value()),
                                         ProtectedPayloadPacketType::initial, true),
                                     CodecErrorCode::invalid_reserved_bits));

        const std::array truncated_version_long_header = {
            std::byte{0xc0},
        };
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "decode_received_long_header_packet_fields rejects truncated version bytes",
            codec_failure(decode_received_long_header_packet_fields(
                              truncated_version_long_header, SharedBytes(crypto_payload.value()),
                              ProtectedPayloadPacketType::initial, true),
                          CodecErrorCode::truncated_input));

        {
            std::vector<std::byte> header{std::byte{0xc0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x15});
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "decode_received_long_header_packet_fields rejects oversized destination "
                "connection ids",
                codec_failure(decode_received_long_header_packet_fields(
                                  header, SharedBytes(crypto_payload.value()),
                                  ProtectedPayloadPacketType::initial, true),
                              CodecErrorCode::invalid_varint));
        }

        {
            std::vector<std::byte> header{std::byte{0xc0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xaa});
            header.push_back(std::byte{0x15});
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "decode_received_long_header_packet_fields rejects oversized source connection ids",
                codec_failure(decode_received_long_header_packet_fields(
                                  header, SharedBytes(crypto_payload.value()),
                                  ProtectedPayloadPacketType::initial, true),
                              CodecErrorCode::invalid_varint));
        }

        {
            std::vector<std::byte> header{std::byte{0xc0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xaa});
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xbb});
            header.push_back(std::byte{0x40});
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "decode_received_long_header_packet_fields propagates malformed token lengths",
                codec_failure(decode_received_long_header_packet_fields(
                                  header, SharedBytes(crypto_payload.value()),
                                  ProtectedPayloadPacketType::initial, true),
                              CodecErrorCode::truncated_input));
        }

        {
            std::vector<std::byte> header{std::byte{0xc0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xaa});
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xbb});
            static_cast<void>(append_varint(header, 2u));
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "decode_received_long_header_packet_fields rejects token lengths longer than the "
                "remaining header",
                codec_failure(decode_received_long_header_packet_fields(
                                  header, SharedBytes(crypto_payload.value()),
                                  ProtectedPayloadPacketType::initial, true),
                              CodecErrorCode::packet_length_mismatch));
        }

        {
            std::vector<std::byte> header{std::byte{0xd0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xaa});
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xbb});
            header.push_back(std::byte{0x40});
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "decode_received_long_header_packet_fields propagates malformed payload lengths",
                codec_failure(decode_received_long_header_packet_fields(
                                  header, SharedBytes(ping_payload.value()),
                                  ProtectedPayloadPacketType::zero_rtt, false),
                              CodecErrorCode::truncated_input));
        }

        {
            auto header =
                build_long_header(std::byte{0xd1}, kQuicVersion1, std::array{std::byte{0xaa}},
                                  std::array{std::byte{0xbb}}, {},
                                  /*has_token=*/false,
                                  /*payload_length=*/3u, std::array{std::byte{0x01}});
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "decode_received_long_header_packet_fields rejects truncated packet number bytes",
                codec_failure(decode_received_long_header_packet_fields(
                                  header, SharedBytes(ping_payload.value()),
                                  ProtectedPayloadPacketType::zero_rtt, false),
                              CodecErrorCode::truncated_input));
        }

        {
            auto header =
                build_long_header(std::byte{0xc0}, kQuicVersion1, std::array{std::byte{0xaa}},
                                  std::array{std::byte{0xbb}}, std::array{std::byte{0xcc}},
                                  /*has_token=*/true,
                                  /*payload_length=*/1u, std::array{std::byte{0x01}});
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "decode_received_long_header_packet_fields rejects payload length mismatches",
                codec_failure(decode_received_long_header_packet_fields(
                                  header, SharedBytes(crypto_payload.value()),
                                  ProtectedPayloadPacketType::initial, true),
                              CodecErrorCode::packet_length_mismatch));
        }

        {
            auto header = build_long_header(
                std::byte{0xd0}, kQuicVersion1, std::array{std::byte{0xaa}},
                std::array{std::byte{0xbb}}, {},
                /*has_token=*/false,
                /*payload_length=*/1u + ack_payload.value().size(), std::array{std::byte{0x01}});
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "decode_received_long_header_packet_fields rejects frames forbidden in zero-rtt "
                "payloads",
                codec_failure(decode_received_long_header_packet_fields(
                                  header, SharedBytes(ack_payload.value()),
                                  ProtectedPayloadPacketType::zero_rtt, false),
                              CodecErrorCode::frame_not_allowed_in_packet_type));
        }

        const auto decoded_long_header = decode_received_long_header_packet_fields(
            long_header_header, SharedBytes(crypto_payload.value()),
            ProtectedPayloadPacketType::initial, true);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "decode_received_long_header_packet_fields accepts initial plaintext headers",
            decoded_long_header.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded long header preserves the QUIC version",
                       decoded_long_header.value().version == kQuicVersion1);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded long header preserves the destination connection id",
                       decoded_long_header.value().destination_connection_id ==
                           ConnectionId{std::byte{0xaa}});
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded long header preserves the source connection id",
                       decoded_long_header.value().source_connection_id ==
                           ConnectionId{std::byte{0xbb}});
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded long header preserves the token",
                       decoded_long_header.value().token ==
                           std::vector<std::byte>{std::byte{0xcc}});
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded long header preserves the packet number length",
                       decoded_long_header.value().packet_number_length == 1);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded long header returns one plaintext frame",
                       decoded_long_header.value().frames.size() == 1);
        const auto *decoded_long_header_crypto =
            std::get_if<ReceivedCryptoFrame>(&decoded_long_header.value().frames.front());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded long header returns a crypto frame",
                       decoded_long_header_crypto != nullptr);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded long header preserves the crypto offset",
                       decoded_long_header_crypto->offset == 0);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded long header preserves the crypto payload",
                       decoded_long_header_crypto->crypto_data ==
                           std::vector<std::byte>{std::byte{0x42}});

        // Short-header plaintext decoding covers helper predicates and header guard failures.
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "codec_failure_offset rejects successful short-header decode results",
                       !codec_failure_offset(CodecResult<ReceivedShortHeaderPacketFields>::success(
                                                 ReceivedShortHeaderPacketFields{
                                                     .packet_number_length = 1,
                                                 }),
                                             CodecErrorCode::truncated_input, 0));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "codec_failure_offset rejects mismatched short-header decode error codes",
                       !codec_failure_offset(CodecResult<ReceivedShortHeaderPacketFields>::failure(
                                                 CodecErrorCode::invalid_fixed_bit, 0),
                                             CodecErrorCode::truncated_input, 0));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "codec_failure_offset rejects mismatched short-header decode offsets",
                       !codec_failure_offset(CodecResult<ReceivedShortHeaderPacketFields>::failure(
                                                 CodecErrorCode::truncated_input, 1),
                                             CodecErrorCode::truncated_input, 0));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "codec_failure rejects successful short-header decode results",
                       !codec_failure(CodecResult<ReceivedShortHeaderPacketFields>::success(
                                          ReceivedShortHeaderPacketFields{
                                              .packet_number_length = 1,
                                          }),
                                      CodecErrorCode::truncated_input));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "codec_failure rejects mismatched short-header decode error codes",
                       !codec_failure(CodecResult<ReceivedShortHeaderPacketFields>::failure(
                                          CodecErrorCode::invalid_fixed_bit, 0),
                                      CodecErrorCode::truncated_input));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decode_received_short_header_packet_fields rejects empty headers",
                       codec_failure_offset(decode_received_short_header_packet_fields(
                                                {}, SharedBytes(ping_payload.value())),
                                            CodecErrorCode::truncated_input, 0));

        const std::array missing_fixed_short_header = {
            std::byte{0x01},
        };
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "decode_received_short_header_packet_fields rejects missing fixed bits",
            codec_failure(decode_received_short_header_packet_fields(
                              missing_fixed_short_header, SharedBytes(ping_payload.value())),
                          CodecErrorCode::invalid_fixed_bit));

        const std::array reserved_short_header = {
            std::byte{0x59},
        };
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decode_received_short_header_packet_fields rejects reserved bits",
                       codec_failure(decode_received_short_header_packet_fields(
                                         reserved_short_header, SharedBytes(ping_payload.value())),
                                     CodecErrorCode::invalid_reserved_bits));

        const std::array truncated_packet_number_short_header = {
            std::byte{0x41},
        };
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "decode_received_short_header_packet_fields rejects headers shorter than the packet "
            "number",
            codec_failure(
                decode_received_short_header_packet_fields(truncated_packet_number_short_header,
                                                           SharedBytes(ping_payload.value())),
                CodecErrorCode::packet_length_mismatch));

        const std::array empty_payload_short_header = {
            std::byte{0x41},
            std::byte{0xaa},
            std::byte{0x01},
            std::byte{0x02},
        };
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "decode_received_short_header_packet_fields propagates payload decode failures",
            codec_failure(decode_received_short_header_packet_fields(empty_payload_short_header,
                                                                     SharedBytes{}),
                          CodecErrorCode::empty_packet_payload));

        const std::array valid_short_header = {
            std::byte{0x65}, std::byte{0xaa}, std::byte{0xbb}, std::byte{0x01}, std::byte{0x02},
        };
        const auto decoded_short_header = decode_received_short_header_packet_fields(
            valid_short_header, SharedBytes(ping_payload.value()));
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decode_received_short_header_packet_fields accepts plaintext headers",
                       decoded_short_header.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded short header preserves the spin bit",
                       decoded_short_header.value().spin_bit);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded short header preserves the key phase",
                       decoded_short_header.value().key_phase);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded short header preserves the destination connection id",
                       decoded_short_header.value().destination_connection_id ==
                           ConnectionId{
                               std::byte{0xaa},
                               std::byte{0xbb},
                           });
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded short header preserves the packet number length",
                       decoded_short_header.value().packet_number_length == 2);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "decoded short header returns one frame",
                       decoded_short_header.value().frames.size() == 1);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "decoded short header returns a ping frame",
            std::holds_alternative<PingFrame>(decoded_short_header.value().frames.front()));
    }

    // Header-protection padding preserves large plaintexts and extends short plaintexts.
    {
        std::vector<std::byte> padded_plaintext{std::byte{0xaa}};
        pad_short_header_plaintext_for_header_protection(padded_plaintext, 2);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "pad_short_header_plaintext_for_header_protection extends short payloads with zeros",
            padded_plaintext.size() == 6);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "pad_short_header_plaintext_for_header_protection zero-fills padding",
                       padded_plaintext.back() == std::byte{0x00});

        std::vector<std::byte> unchanged_plaintext(6, std::byte{0xbb});
        pad_short_header_plaintext_for_header_protection(unchanged_plaintext, 2);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "pad_short_header_plaintext_for_header_protection leaves already-large payloads "
            "unchanged",
            unchanged_plaintext == std::vector<std::byte>(6, std::byte{0xbb}));
    }

    // Stream payload wire-size helpers cover view and fragment sizing, including invalid ranges.
    {
        const auto shared_storage = std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{
            std::byte{0x10},
            std::byte{0x11},
            std::byte{0x12},
        });
        const std::array valid_views = {
            StreamFrameView{
                .stream_id = 7,
                .offset = 1,
                .storage = shared_storage,
                .begin = 0,
                .end = 2,
            },
        };
        const auto view_wire_size = packet_stream_payload_wire_size(
            ProtectedOneRttPacketView{
                .destination_connection_id = {},
                .packet_number_length = 2,
                .packet_number = 0,
                .frames = {},
                .stream_frame_views = valid_views,
            },
            /*frame_index_base=*/5);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet_stream_payload_wire_size sums valid stream frame view payloads",
                       view_wire_size.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet_stream_payload_wire_size reports stream frame view wire sizes",
                       view_wire_size.value() ==
                           encoded_stream_frame_payload_size(/*stream_id=*/7,
                                                             /*offset=*/1,
                                                             /*payload_size=*/2));

        const std::array invalid_views = {
            StreamFrameView{
                .stream_id = 7,
                .offset = 1,
                .begin = 2,
                .end = 1,
            },
        };
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet_stream_payload_wire_size rejects inverted stream frame view ranges",
                       codec_failure_offset(packet_stream_payload_wire_size(
                                                ProtectedOneRttPacketView{
                                                    .destination_connection_id = {},
                                                    .packet_number_length = 2,
                                                    .packet_number = 0,
                                                    .frames = {},
                                                    .stream_frame_views = invalid_views,
                                                },
                                                /*frame_index_base=*/5),
                                            CodecErrorCode::invalid_varint, 5));

        const std::array oversized_storage_views = {
            StreamFrameView{
                .stream_id = 7,
                .offset = 1,
                .storage = shared_storage,
                .begin = 0,
                .end = 4,
            },
        };
        const auto oversized_storage_wire_size = packet_stream_payload_wire_size(
            ProtectedOneRttPacketView{
                .destination_connection_id = {},
                .packet_number_length = 2,
                .packet_number = 0,
                .frames = {},
                .stream_frame_views = oversized_storage_views,
            },
            /*frame_index_base=*/5);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "packet_stream_payload_wire_size sizes stream frame views from declared ranges",
            oversized_storage_wire_size.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet_stream_payload_wire_size reports declared stream frame view ranges",
                       oversized_storage_wire_size.value() ==
                           encoded_stream_frame_payload_size(/*stream_id=*/7, /*offset=*/1,
                                                             /*payload_size=*/4));

        const std::array valid_fragments = {
            StreamFrameSendFragment{
                .stream_id = 9,
                .offset = 3,
                .bytes =
                    SharedBytes{
                        std::byte{0xaa},
                        std::byte{0xbb},
                    },
            },
        };
        const auto fragment_wire_size = packet_stream_payload_wire_size(
            ProtectedOneRttPacketFragmentView{
                .destination_connection_id = {},
                .packet_number_length = 2,
                .packet_number = 0,
                .frames = {},
                .stream_fragments = valid_fragments,
            },
            /*frame_index_base=*/9);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet_stream_payload_wire_size sums valid stream fragment payloads",
                       fragment_wire_size.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "packet_stream_payload_wire_size reports stream fragment wire sizes",
                       fragment_wire_size.value() ==
                           valid_fragments.front().stream_frame_wire_size());

        const std::array invalid_fragments = {
            StreamFrameSendFragment{
                .stream_id = 9,
                .offset = kMaxVarInt,
                .bytes =
                    SharedBytes{
                        std::byte{0xaa},
                    },
            },
        };
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "packet_stream_payload_wire_size rejects overflowing stream fragment offsets",
            codec_failure_offset(packet_stream_payload_wire_size(
                                     ProtectedOneRttPacketFragmentView{
                                         .destination_connection_id = {},
                                         .packet_number_length = 2,
                                         .packet_number = 0,
                                         .frames = {},
                                         .stream_fragments = invalid_fragments,
                                     },
                                     /*frame_index_base=*/9),
                                 CodecErrorCode::invalid_varint, 9));
    }

    // Initial packet round-trip coverage checks missing context, protection failures, and success.
    {
        const auto initial_packet = ProtectedInitialPacket{
            .version = kQuicVersion1,
            .destination_connection_id =
                {
                    std::byte{0x83},
                    std::byte{0x94},
                },
            .source_connection_id = {std::byte{0xc1}},
            .token = {std::byte{0x55}},
            .packet_number_length = 2,
            .packet_number = 7,
            .frames =
                {
                    CryptoFrame{
                        .offset = 0,
                        .crypto_data = {std::byte{0x01}},
                    },
                },
        };
        const auto initial_bytes = serialize_protected_initial_packet(
            initial_packet, SerializeProtectionContext{
                                .local_role = EndpointRole::client,
                                .client_initial_destination_connection_id =
                                    initial_packet.destination_connection_id,
                            });
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "serialize_protected_initial_packet builds a received decode fixture",
                       initial_bytes.has_value());
        {
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "deserialize_received_protected_initial_packet rejects missing receive context",
                codec_failure(deserialize_received_protected_initial_packet(
                                  initial_bytes.value(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                  }),
                              CodecErrorCode::missing_crypto_context));

            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch};
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "deserialize_received_protected_initial_packet propagates header protection "
                    "failures",
                    codec_failure(deserialize_received_protected_initial_packet(
                                      initial_bytes.value(),
                                      DeserializeProtectionContext{
                                          .peer_role = EndpointRole::client,
                                          .client_initial_destination_connection_id =
                                              initial_packet.destination_connection_id,
                                      }),
                                  CodecErrorCode::packet_length_mismatch));
            }

            const auto initial_keys = derive_initial_packet_keys(
                EndpointRole::client, true, initial_packet.destination_connection_id,
                initial_packet.version);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "derive_initial_packet_keys builds a malformed initial payload fixture",
                           initial_keys.has_value());
            {
                const auto empty_payload_initial = build_received_long_header_packet_for_tests(
                    LongHeaderPacketType::initial, initial_packet.version,
                    initial_packet.destination_connection_id, initial_packet.source_connection_id,
                    initial_packet.token, true, initial_packet.packet_number_length, 21,
                    stream_payload.value(), kInitialCipherSuite, initial_keys.value());
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "build_received_long_header_packet_for_tests creates a malformed initial "
                    "payload fixture",
                    empty_payload_initial.has_value());
                {
                    coverage_check(
                        ok, "protected_codec_packet_path_coverage_for_tests",
                        "deserialize_received_protected_initial_packet rejects forbidden "
                        "decrypted stream frames",
                        codec_failure(deserialize_received_protected_initial_packet(
                                          empty_payload_initial.value(),
                                          DeserializeProtectionContext{
                                              .peer_role = EndpointRole::client,
                                              .client_initial_destination_connection_id =
                                                  initial_packet.destination_connection_id,
                                          }),
                                      CodecErrorCode::frame_not_allowed_in_packet_type));
                }
            }

            const auto decoded = deserialize_received_protected_initial_packet(
                initial_bytes.value(), DeserializeProtectionContext{
                                           .peer_role = EndpointRole::client,
                                           .client_initial_destination_connection_id =
                                               initial_packet.destination_connection_id,
                                       });
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "deserialize_received_protected_initial_packet decodes valid packets",
                           decoded.has_value());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "initial packet decode reports consumed bytes",
                           decoded.value().bytes_consumed > 0);
            const auto *packet =
                std::get_if<ReceivedProtectedInitialPacket>(&decoded.value().packet);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "initial packet decode returns an initial packet variant",
                           packet != nullptr);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "initial packet decode preserves the packet number",
                           packet->packet_number == initial_packet.packet_number);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "initial packet decode owns plaintext storage",
                           packet->plaintext_storage != nullptr);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "initial packet decode returns one frame", packet->frames.size() == 1);
        }
    }

    // Handshake packet round-trip coverage mirrors Initial checks with handshake traffic secrets.
    {
        const auto handshake_secret = TrafficSecret{
            .cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
            .secret = make_secret_bytes(32, 0x20),
        };
        const auto handshake_packet = ProtectedHandshakePacket{
            .version = kQuicVersion1,
            .destination_connection_id =
                {
                    std::byte{0xaa},
                    std::byte{0xbb},
                },
            .source_connection_id = {std::byte{0xcc}},
            .packet_number_length = 2,
            .packet_number = 9,
            .frames =
                {
                    CryptoFrame{
                        .offset = 0,
                        .crypto_data = {std::byte{0x11}, std::byte{0x22}},
                    },
                },
        };
        const auto handshake_bytes = serialize_protected_handshake_packet(
            handshake_packet, SerializeProtectionContext{
                                  .local_role = EndpointRole::client,
                                  .handshake_secret = handshake_secret,
                              });
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "serialize_protected_handshake_packet builds a received decode fixture",
                       handshake_bytes.has_value());
        {
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "deserialize_received_protected_handshake_packet rejects missing handshake secrets",
                codec_failure(deserialize_received_protected_handshake_packet(
                                  handshake_bytes.value(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                  }),
                              CodecErrorCode::missing_crypto_context));

            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "deserialize_received_protected_handshake_packet propagates secret expansion "
                "failures",
                codec_failure(deserialize_received_protected_handshake_packet(
                                  handshake_bytes.value(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                      .handshake_secret =
                                          TrafficSecret{
                                              .cipher_suite = invalid_cipher_suite(),
                                              .secret = make_secret_bytes(32, 0x21),
                                          },
                                  }),
                              CodecErrorCode::unsupported_cipher_suite));

            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch};
                coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                               "deserialize_received_protected_handshake_packet propagates header "
                               "protection failures",
                               codec_failure(deserialize_received_protected_handshake_packet(
                                                 handshake_bytes.value(),
                                                 DeserializeProtectionContext{
                                                     .peer_role = EndpointRole::client,
                                                     .handshake_secret = handshake_secret,
                                                 }),
                                             CodecErrorCode::packet_length_mismatch));
            }

            const auto handshake_keys = expand_traffic_secret_cached(handshake_secret);
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "expand_traffic_secret_cached builds a malformed handshake payload fixture",
                handshake_keys.has_value());
            {
                const auto empty_payload_handshake = build_received_long_header_packet_for_tests(
                    LongHeaderPacketType::handshake, handshake_packet.version,
                    handshake_packet.destination_connection_id,
                    handshake_packet.source_connection_id, {}, false,
                    handshake_packet.packet_number_length, 23, stream_payload.value(),
                    handshake_secret.cipher_suite, handshake_keys.value().get());
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "build_received_long_header_packet_for_tests creates a malformed handshake "
                    "payload fixture",
                    empty_payload_handshake.has_value());
                {
                    coverage_check(
                        ok, "protected_codec_packet_path_coverage_for_tests",
                        "deserialize_received_protected_handshake_packet rejects forbidden "
                        "decrypted stream frames",
                        codec_failure(deserialize_received_protected_handshake_packet(
                                          empty_payload_handshake.value(),
                                          DeserializeProtectionContext{
                                              .peer_role = EndpointRole::client,
                                              .handshake_secret = handshake_secret,
                                          }),
                                      CodecErrorCode::frame_not_allowed_in_packet_type));
                }
            }

            const auto decoded = deserialize_received_protected_handshake_packet(
                handshake_bytes.value(), DeserializeProtectionContext{
                                             .peer_role = EndpointRole::client,
                                             .handshake_secret = handshake_secret,
                                         });
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "deserialize_received_protected_handshake_packet decodes valid packets",
                           decoded.has_value());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "handshake packet decode reports consumed bytes",
                           decoded.value().bytes_consumed > 0);
            const auto *packet =
                std::get_if<ReceivedProtectedHandshakePacket>(&decoded.value().packet);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "handshake packet decode returns a handshake packet variant",
                           packet != nullptr);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "handshake packet decode preserves the packet number",
                           packet->packet_number == handshake_packet.packet_number);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "handshake packet decode owns plaintext storage",
                           packet->plaintext_storage != nullptr);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "handshake packet decode returns one frame", packet->frames.size() == 1);
        }
    }

    // Zero-RTT packet coverage verifies secret handling and payload frame allow-list enforcement.
    {
        const auto zero_rtt_secret = TrafficSecret{
            .cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
            .secret = make_secret_bytes(32, 0x40),
        };
        const auto zero_rtt_packet = ProtectedZeroRttPacket{
            .version = kQuicVersion1,
            .destination_connection_id =
                {
                    std::byte{0xaa},
                    std::byte{0xbb},
                },
            .source_connection_id = {std::byte{0xcc}},
            .packet_number_length = 2,
            .packet_number = 11,
            .frames = {PingFrame{}},
        };
        const auto zero_rtt_bytes = serialize_protected_zero_rtt_packet(
            zero_rtt_packet, SerializeProtectionContext{
                                 .local_role = EndpointRole::client,
                                 .zero_rtt_secret = zero_rtt_secret,
                             });
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "serialize_protected_zero_rtt_packet builds a received decode fixture",
                       zero_rtt_bytes.has_value());
        {
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "deserialize_received_protected_zero_rtt_packet rejects missing zero-rtt secrets",
                codec_failure(deserialize_received_protected_zero_rtt_packet(
                                  zero_rtt_bytes.value(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                  }),
                              CodecErrorCode::missing_crypto_context));

            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "deserialize_received_protected_zero_rtt_packet propagates secret expansion "
                "failures",
                codec_failure(deserialize_received_protected_zero_rtt_packet(
                                  zero_rtt_bytes.value(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                      .zero_rtt_secret =
                                          TrafficSecret{
                                              .cipher_suite = invalid_cipher_suite(),
                                              .secret = make_secret_bytes(32, 0x41),
                                          },
                                  }),
                              CodecErrorCode::unsupported_cipher_suite));

            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch};
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "deserialize_received_protected_zero_rtt_packet propagates header protection "
                    "failures",
                    codec_failure(deserialize_received_protected_zero_rtt_packet(
                                      zero_rtt_bytes.value(),
                                      DeserializeProtectionContext{
                                          .peer_role = EndpointRole::client,
                                          .zero_rtt_secret = zero_rtt_secret,
                                      }),
                                  CodecErrorCode::packet_length_mismatch));
            }

            const auto zero_rtt_keys = expand_traffic_secret_cached(zero_rtt_secret);
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "expand_traffic_secret_cached builds a malformed zero-rtt payload fixture",
                zero_rtt_keys.has_value());
            {
                const auto empty_payload_zero_rtt = build_received_long_header_packet_for_tests(
                    LongHeaderPacketType::zero_rtt, zero_rtt_packet.version,
                    zero_rtt_packet.destination_connection_id, zero_rtt_packet.source_connection_id,
                    {}, false, zero_rtt_packet.packet_number_length, 25, ack_payload.value(),
                    zero_rtt_secret.cipher_suite, zero_rtt_keys.value().get());
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "build_received_long_header_packet_for_tests creates a malformed zero-rtt "
                    "payload fixture",
                    empty_payload_zero_rtt.has_value());
                {
                    coverage_check(
                        ok, "protected_codec_packet_path_coverage_for_tests",
                        "deserialize_received_protected_zero_rtt_packet rejects forbidden "
                        "decrypted stream frames",
                        codec_failure(deserialize_received_protected_zero_rtt_packet(
                                          empty_payload_zero_rtt.value(),
                                          DeserializeProtectionContext{
                                              .peer_role = EndpointRole::client,
                                              .zero_rtt_secret = zero_rtt_secret,
                                          }),
                                      CodecErrorCode::frame_not_allowed_in_packet_type));
                }
            }

            const auto decoded = deserialize_received_protected_zero_rtt_packet(
                zero_rtt_bytes.value(), DeserializeProtectionContext{
                                            .peer_role = EndpointRole::client,
                                            .zero_rtt_secret = zero_rtt_secret,
                                        });
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "deserialize_received_protected_zero_rtt_packet decodes valid packets",
                           decoded.has_value());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "zero-rtt packet decode reports consumed bytes",
                           decoded.value().bytes_consumed > 0);
            const auto *packet =
                std::get_if<ReceivedProtectedZeroRttPacket>(&decoded.value().packet);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "zero-rtt packet decode returns a zero-rtt packet variant",
                           packet != nullptr);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "zero-rtt packet decode owns plaintext storage",
                           packet->plaintext_storage != nullptr);
        }
    }

    // One-RTT coverage includes fast ACK serialization, shared decode, and fragment paths.
    {
        const auto one_rtt_secret = TrafficSecret{
            .cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
            .secret = make_secret_bytes(32, 0x60),
        };
        const ConnectionId destination_connection_id = {
            std::byte{0xde},
            std::byte{0xad},
            std::byte{0xbe},
            std::byte{0xef},
        };
        const auto one_rtt_context = SerializeProtectionContext{
            .local_role = EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}},
            .one_rtt_secret = one_rtt_secret,
            .one_rtt_key_phase = false,
        };
        const auto one_rtt_receive_context = DeserializeProtectionContext{
            .peer_role = EndpointRole::client,
            .one_rtt_secret = one_rtt_secret,
            .one_rtt_destination_connection_id_length = destination_connection_id.size(),
        };
        const OutboundAckFrame simple_ack{
            .header =
                OutboundAckHeader{
                    .largest_acknowledged = 0,
                    .first_ack_range = 0,
                },
        };
        const auto make_simple_ack_packet = [&](std::uint64_t packet_number) {
            return ProtectedOneRttPacket{
                .spin_bit = false,
                .key_phase = false,
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = packet_number,
                .frames = {simple_ack},
            };
        };
        const auto destination_connection_id_span = std::span<const std::byte>(
            destination_connection_id.data(), destination_connection_id.size());
        const std::array<Frame, 1> non_ack_frames{Frame{PingFrame{}}};
        const std::array<Frame, 1> malformed_ack_frames{Frame{OutboundAckFrame{
            .header =
                OutboundAckHeader{
                    .largest_acknowledged = 0,
                    .first_ack_range = 1,
                },
        }}};
        const std::array<StreamFrameView, 0> empty_stream_views{};
        const std::array<StreamFrameSendFragment, 0> empty_stream_fragments{};
        // Simple ACK fast-path detection rejects mixed or malformed frame sets before sealing.
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "simple outbound ack fast path rejects non-ack packet candidates",
                       simple_outbound_ack_frame_or_null(ProtectedOneRttPacket{
                           .destination_connection_id = destination_connection_id,
                           .packet_number_length = 2,
                           .packet_number = 20,
                           .frames = {PingFrame{}},
                       }) == nullptr);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "simple outbound ack fast path rejects malformed ack packet candidates",
                       simple_outbound_ack_frame_or_null(ProtectedOneRttPacket{
                           .destination_connection_id = destination_connection_id,
                           .packet_number_length = 2,
                           .packet_number = 21,
                           .frames =
                               {
                                   OutboundAckFrame{
                                       .header =
                                           OutboundAckHeader{
                                               .largest_acknowledged = 0,
                                               .first_ack_range = 1,
                                           },
                                   },
                               },
                       }) == nullptr);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "simple outbound ack fast path rejects non-ack view candidates",
                       simple_outbound_ack_frame_or_null(ProtectedOneRttPacketView{
                           .destination_connection_id = destination_connection_id_span,
                           .packet_number_length = 2,
                           .packet_number = 30,
                           .frames = non_ack_frames,
                           .stream_frame_views = empty_stream_views,
                       }) == nullptr);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "simple outbound ack fast path rejects malformed ack view candidates",
                       simple_outbound_ack_frame_or_null(ProtectedOneRttPacketView{
                           .destination_connection_id = destination_connection_id_span,
                           .packet_number_length = 2,
                           .packet_number = 31,
                           .frames = malformed_ack_frames,
                           .stream_frame_views = empty_stream_views,
                       }) == nullptr);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "simple outbound ack fast path rejects non-ack fragment view candidates",
                       simple_outbound_ack_frame_or_null(ProtectedOneRttPacketFragmentView{
                           .destination_connection_id = destination_connection_id_span,
                           .packet_number_length = 2,
                           .packet_number = 32,
                           .frames = non_ack_frames,
                           .stream_fragments = empty_stream_fragments,
                       }) == nullptr);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "simple outbound ack fast path rejects malformed ack fragment view candidates",
            simple_outbound_ack_frame_or_null(ProtectedOneRttPacketFragmentView{
                .destination_connection_id = destination_connection_id_span,
                .packet_number_length = 2,
                .packet_number = 33,
                .frames = malformed_ack_frames,
                .stream_fragments = empty_stream_fragments,
            }) == nullptr);
        {
            // Simple ACK append coverage validates the normal one-RTT fast path.
            DatagramBuffer simple_ack_datagram;
            const auto appended = append_protected_one_rtt_packet_to_datagram_impl(
                simple_ack_datagram, make_simple_ack_packet(22), one_rtt_context);
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "append_protected_one_rtt_packet_to_datagram_impl serializes simple ack packets",
                appended.has_value());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack append returns the datagram size",
                           appended.value() == simple_ack_datagram.size());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack append writes datagram bytes", !simple_ack_datagram.empty());
        }
        {
            // Primed key-cache coverage ensures borrowed secrets avoid recomputation paths.
            const auto &cached_secret = one_rtt_secret;
            const auto cached_keys = expand_traffic_secret_cached(cached_secret);
            auto cached_context = one_rtt_context;
            cached_context.one_rtt_secret = std::nullopt;
            cached_context.one_rtt_secret_ref = &cached_secret;
            cached_context.one_rtt_secret_cache_primed = true;
            DatagramBuffer cached_simple_ack_datagram;
            const auto appended = append_protected_one_rtt_packet_to_datagram_impl(
                cached_simple_ack_datagram, make_simple_ack_packet(23), cached_context);
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "append_protected_one_rtt_packet_to_datagram_impl uses primed one-rtt key "
                "caches",
                cached_keys.has_value());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "primed one-rtt key cache append succeeds", appended.has_value());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "primed one-rtt key cache append returns the datagram size",
                           appended.value() == cached_simple_ack_datagram.size());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "primed one-rtt key cache append writes datagram bytes",
                           !cached_simple_ack_datagram.empty());
        }
        {
            // Invalid ACK ranges must roll back before the datagram buffer is committed.
            const auto invalid_range_ack_packet = ProtectedOneRttPacket{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 24,
                .frames =
                    {
                        OutboundAckFrame{
                            .header =
                                OutboundAckHeader{
                                    .largest_acknowledged = 0,
                                    .first_ack_range = 0,
                                    .additional_range_count = 1,
                                    .additional_ranges = {AckRange{.gap = 0, .range_length = 0}},
                                },
                        },
                    },
            };
            DatagramBuffer invalid_range_datagram;
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack fast path propagates measured payload size failures",
                           codec_failure(append_protected_one_rtt_packet_to_datagram_impl(
                                             invalid_range_datagram, invalid_range_ack_packet,
                                             one_rtt_context),
                                         CodecErrorCode::invalid_varint));
        }
        {
            // Injected simple-ACK writer failures cover rollback after payload sizing succeeds.
            const ScopedProtectedCodecFaultInjector injector{
                ProtectedCodecFaultPoint::simple_ack_payload_write_failure};
            DatagramBuffer write_failure_datagram;
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack fast path rolls back payload writer failures",
                           codec_failure(append_protected_one_rtt_packet_to_datagram_impl(
                                             write_failure_datagram, make_simple_ack_packet(25),
                                             one_rtt_context),
                                         CodecErrorCode::truncated_input));
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack payload writer failures leave datagrams empty",
                           write_failure_datagram.empty());
        }
        {
            // Payload size mismatch injection covers the simple-ACK post-write consistency check.
            const ScopedProtectedCodecFaultInjector injector{
                ProtectedCodecFaultPoint::simple_ack_payload_size_mismatch};
            DatagramBuffer size_mismatch_datagram;
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack fast path rolls back payload size mismatches",
                           codec_failure(append_protected_one_rtt_packet_to_datagram_impl(
                                             size_mismatch_datagram, make_simple_ack_packet(26),
                                             one_rtt_context),
                                         CodecErrorCode::packet_length_mismatch));
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack payload size mismatches leave datagrams empty",
                           size_mismatch_datagram.empty());
        }
        {
            // Padding and crypto fault injection cover late simple-ACK sealing branches.
            const ScopedProtectedCodecFaultInjector injector{
                ProtectedCodecFaultPoint::simple_ack_force_padding_fill};
            DatagramBuffer forced_padding_datagram;
            const auto appended = append_protected_one_rtt_packet_to_datagram_impl(
                forced_padding_datagram, make_simple_ack_packet(27), one_rtt_context);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack fast path covers padding fill branch", appended.has_value());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack padding fill returns the datagram size",
                           appended.value() == forced_padding_datagram.size());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack padding fill writes datagram bytes",
                           !forced_padding_datagram.empty());
        }
        {
            const ScopedPacketCryptoFaultInjector injector{
                PacketCryptoFaultPoint::seal_context_new};
            DatagramBuffer seal_failure_datagram;
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack fast path rolls back seal failures",
                           codec_failure(append_protected_one_rtt_packet_to_datagram_impl(
                                             seal_failure_datagram, make_simple_ack_packet(28),
                                             one_rtt_context),
                                         CodecErrorCode::invalid_packet_protection_state));
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack seal failures leave datagrams empty",
                           seal_failure_datagram.empty());
        }
        {
            const ScopedPacketCryptoFaultInjector injector{
                PacketCryptoFaultPoint::header_protection_context_new};
            DatagramBuffer protect_failure_datagram;
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack fast path rolls back header protection failures",
                           codec_failure(append_protected_one_rtt_packet_to_datagram_impl(
                                             protect_failure_datagram, make_simple_ack_packet(29),
                                             one_rtt_context),
                                         CodecErrorCode::header_protection_failed));
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "simple ack header protection failures leave datagrams empty",
                           protect_failure_datagram.empty());
        }
        // A regular protected datagram fixture drives the shared-storage receive decoder.
        const auto one_rtt_packet_bytes = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{ProtectedPacket{ProtectedOneRttPacket{
                .spin_bit = false,
                .key_phase = false,
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 12,
                .frames = {PingFrame{}},
            }}},
            one_rtt_context);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "serialize_protected_datagram builds a received one-rtt fixture",
                       one_rtt_packet_bytes.has_value());
        {
            // Shared-storage decoding covers malformed ranges, contexts, key phases, and secrets.
            const auto make_one_rtt_storage = [&]() {
                return std::make_shared<std::vector<std::byte>>(one_rtt_packet_bytes.value());
            };
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "shared-storage one-rtt decoder rejects null storage",
                           codec_failure(deserialize_received_protected_packet(
                                             nullptr, 0, one_rtt_packet_bytes.value().size(),
                                             one_rtt_receive_context),
                                         CodecErrorCode::truncated_input));
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "shared-storage one-rtt decoder rejects null storage through direct in-place path",
                codec_failure(
                    deserialize_received_protected_one_rtt_packet(
                        nullptr, 0, one_rtt_packet_bytes.value().size(), one_rtt_receive_context),
                    CodecErrorCode::truncated_input));
            const auto malformed_range_storage = make_one_rtt_storage();
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "shared-storage one-rtt decoder rejects malformed ranges",
                codec_failure(deserialize_received_protected_packet(malformed_range_storage,
                                                                    malformed_range_storage->size(),
                                                                    0, one_rtt_receive_context),
                              CodecErrorCode::truncated_input));
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "shared-storage one-rtt decoder rejects overrun ranges through direct in-place "
                "path",
                codec_failure(deserialize_received_protected_one_rtt_packet(
                                  malformed_range_storage, 0, malformed_range_storage->size() + 1,
                                  one_rtt_receive_context),
                              CodecErrorCode::truncated_input));
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "shared-storage one-rtt decoder rejects missing one-rtt secrets",
                codec_failure(deserialize_received_protected_packet(
                                  make_one_rtt_storage(), 0, one_rtt_packet_bytes.value().size(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                      .one_rtt_destination_connection_id_length =
                                          destination_connection_id.size(),
                                  }),
                              CodecErrorCode::missing_crypto_context));
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "shared-storage one-rtt decoder rejects oversized destination connection id "
                "contexts",
                codec_failure(deserialize_received_protected_packet(
                                  make_one_rtt_storage(), 0, one_rtt_packet_bytes.value().size(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                      .one_rtt_secret = one_rtt_secret,
                                      .one_rtt_destination_connection_id_length =
                                          one_rtt_packet_bytes.value().size(),
                                  }),
                              CodecErrorCode::malformed_short_header_context));
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "shared-storage one-rtt decoder propagates secret expansion failures",
                codec_failure(deserialize_received_protected_packet(
                                  make_one_rtt_storage(), 0, one_rtt_packet_bytes.value().size(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                      .one_rtt_secret =
                                          TrafficSecret{
                                              .cipher_suite = invalid_cipher_suite(),
                                              .secret = make_secret_bytes(32, 0x61),
                                          },
                                      .one_rtt_destination_connection_id_length =
                                          destination_connection_id.size(),
                                  }),
                              CodecErrorCode::unsupported_cipher_suite));
            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::remove_short_header_packet_length_mismatch};
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "shared-storage one-rtt decoder propagates header protection failures",
                    codec_failure(deserialize_received_protected_packet(
                                      make_one_rtt_storage(), 0,
                                      one_rtt_packet_bytes.value().size(), one_rtt_receive_context),
                                  CodecErrorCode::packet_length_mismatch));
            }
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "shared-storage one-rtt decoder rejects wrong key phases",
                codec_failure(deserialize_received_protected_packet(
                                  make_one_rtt_storage(), 0, one_rtt_packet_bytes.value().size(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                      .one_rtt_secret = one_rtt_secret,
                                      .one_rtt_key_phase = true,
                                      .one_rtt_destination_connection_id_length =
                                          destination_connection_id.size(),
                                  }),
                              CodecErrorCode::invalid_packet_protection_state));
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "shared-storage one-rtt decoder propagates packet number recovery failures",
                codec_failure(deserialize_received_protected_packet(
                                  make_one_rtt_storage(), 0, one_rtt_packet_bytes.value().size(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                      .one_rtt_secret = one_rtt_secret,
                                      .largest_authenticated_application_packet_number =
                                          (std::uint64_t{1} << 62) - 1u,
                                      .one_rtt_destination_connection_id_length =
                                          destination_connection_id.size(),
                                  }),
                              CodecErrorCode::packet_number_recovery_failed));

            {
                auto short_ciphertext_storage = make_one_rtt_storage();
                const ScopedProtectedCodecFaultInjector short_ciphertext_injector{
                    ProtectedCodecFaultPoint::one_rtt_in_place_short_ciphertext};
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "shared-storage one-rtt decoder rejects ciphertexts shorter than the AEAD tag",
                    codec_failure(deserialize_received_protected_packet(
                                      short_ciphertext_storage, 0, short_ciphertext_storage->size(),
                                      one_rtt_receive_context),
                                  CodecErrorCode::packet_decryption_failed));
            }

            auto wrong_one_rtt_secret = one_rtt_secret;
            wrong_one_rtt_secret.secret.back() ^= std::byte{0xff};
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "shared-storage one-rtt decoder rejects packets encrypted with different "
                "secrets",
                codec_failure(deserialize_received_protected_packet(
                                  make_one_rtt_storage(), 0, one_rtt_packet_bytes.value().size(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                      .one_rtt_secret = wrong_one_rtt_secret,
                                      .one_rtt_destination_connection_id_length =
                                          destination_connection_id.size(),
                                  }),
                              CodecErrorCode::packet_decryption_failed));
            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::one_rtt_in_place_plaintext_size_mismatch};
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "shared-storage one-rtt decoder rejects unexpected plaintext lengths",
                    codec_failure(deserialize_received_protected_packet(
                                      make_one_rtt_storage(), 0,
                                      one_rtt_packet_bytes.value().size(), one_rtt_receive_context),
                                  CodecErrorCode::packet_length_mismatch));
            }
            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::one_rtt_in_place_bytes_consumed_mismatch};
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "shared-storage one-rtt packet wrapper rejects trailing decoded bytes",
                    codec_failure(deserialize_received_protected_packet(
                                      make_one_rtt_storage(), 0,
                                      one_rtt_packet_bytes.value().size(), one_rtt_receive_context),
                                  CodecErrorCode::packet_length_mismatch));
            }
            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::one_rtt_in_place_bytes_consumed_mismatch};
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "fast shared-storage one-rtt packet wrapper rejects trailing decoded bytes",
                    codec_failure(deserialize_received_protected_packet_fast(
                                      make_one_rtt_storage(), 0,
                                      one_rtt_packet_bytes.value().size(), one_rtt_receive_context),
                                  CodecErrorCode::packet_length_mismatch));
            }
            const auto shared_decoded = deserialize_received_protected_packet(
                make_one_rtt_storage(), 0, one_rtt_packet_bytes.value().size(),
                one_rtt_receive_context);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "shared-storage one-rtt decoder decodes valid packets",
                           shared_decoded.has_value());
            const auto *packet =
                std::get_if<ReceivedProtectedOneRttPacket>(&shared_decoded.value());
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "shared-storage one-rtt decoder returns a one-rtt packet variant",
                           packet != nullptr);
            coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                           "shared-storage one-rtt decoder owns plaintext storage",
                           packet->plaintext_storage != nullptr);

            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::remove_short_header_packet_length_mismatch};
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "deserialize_received_protected_one_rtt_packet propagates header protection "
                    "failures",
                    codec_failure(deserialize_received_protected_one_rtt_packet(
                                      one_rtt_packet_bytes.value(), one_rtt_receive_context),
                                  CodecErrorCode::packet_length_mismatch));
            }

            // Span-based one-RTT decoding covers mismatched secrets outside the shared path.
            {
                auto wrong_one_rtt_secret_for_span = one_rtt_secret;
                wrong_one_rtt_secret_for_span.secret.back() ^= std::byte{0xff};
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "deserialize_received_protected_one_rtt_packet rejects packets encrypted "
                    "with different secrets",
                    codec_failure(deserialize_received_protected_one_rtt_packet(
                                      one_rtt_packet_bytes.value(),
                                      DeserializeProtectionContext{
                                          .peer_role = EndpointRole::client,
                                          .one_rtt_secret = wrong_one_rtt_secret_for_span,
                                          .one_rtt_destination_connection_id_length =
                                              destination_connection_id.size(),
                                      }),
                                  CodecErrorCode::packet_decryption_failed));
            }
        }

        const auto one_rtt_keys = expand_traffic_secret_cached(one_rtt_secret);
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "expand_traffic_secret_cached builds a malformed one-rtt payload fixture",
                       one_rtt_keys.has_value());
        {
            // Malformed decrypted one-RTT payloads exercise span and shared payload decoders.
            const std::array malformed_one_rtt_payload = {
                std::byte{0x02},
                std::byte{0x00},
            };
            const auto empty_payload_one_rtt = build_received_one_rtt_packet_for_tests(
                false, false, destination_connection_id, 2, 29, malformed_one_rtt_payload,
                one_rtt_secret.cipher_suite, one_rtt_keys.value().get());
            coverage_check(
                ok, "protected_codec_packet_path_coverage_for_tests",
                "build_received_one_rtt_packet_for_tests creates a malformed one-rtt payload "
                "fixture",
                empty_payload_one_rtt.has_value());
            {
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "deserialize_received_protected_one_rtt_packet propagates decrypted payload "
                    "decode failures",
                    codec_failure(deserialize_received_protected_one_rtt_packet(
                                      empty_payload_one_rtt.value(), one_rtt_receive_context),
                                  CodecErrorCode::truncated_input));
                coverage_check(
                    ok, "protected_codec_packet_path_coverage_for_tests",
                    "shared-storage one-rtt decoder propagates decrypted payload decode "
                    "failures",
                    codec_failure(
                        deserialize_received_protected_packet(
                            std::make_shared<std::vector<std::byte>>(empty_payload_one_rtt.value()),
                            0, empty_payload_one_rtt.value().size(), one_rtt_receive_context),
                        CodecErrorCode::truncated_input));
            }
        }

        // Fragment-view sealing covers chunked payloads, prefix frames, padding, and fallback
        // paths.
        std::vector<StreamFrameSendFragment> chunk_fragments{
            StreamFrameSendFragment{
                .stream_id = 1,
                .offset = 0,
                .bytes =
                    SharedBytes{
                        std::byte{0x01},
                    },
            },
            StreamFrameSendFragment{
                .stream_id = 3,
                .offset = 0,
                .bytes =
                    SharedBytes{
                        std::byte{0x02},
                    },
            },
        };
        DatagramBuffer chunk_datagram;
        const auto chunk_appended = append_protected_one_rtt_packet_to_datagram_impl(
            chunk_datagram,
            ProtectedOneRttPacketFragmentView{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 13,
                .frames = {},
                .stream_fragments = chunk_fragments,
            },
            one_rtt_context);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "append_protected_one_rtt_packet_to_datagram_impl chunk-seals multiple fragments",
            chunk_appended.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "chunk-sealed fragment append returns the datagram size",
                       chunk_appended.value() == chunk_datagram.size());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "chunk-sealed fragment append writes datagram bytes",
                       !chunk_datagram.empty());

        const std::array<Frame, 1> chunk_prefix_frames = {
            Frame(PingFrame{}),
        };
        DatagramBuffer chunk_with_prefix_datagram;
        const auto chunk_with_prefix_appended = append_protected_one_rtt_packet_to_datagram_impl(
            chunk_with_prefix_datagram,
            ProtectedOneRttPacketFragmentView{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 17,
                .frames = chunk_prefix_frames,
                .stream_fragments = chunk_fragments,
            },
            one_rtt_context);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "append_protected_one_rtt_packet_to_datagram_impl chunk-seals fragments after prefix "
            "frames",
            chunk_with_prefix_appended.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "chunk-sealed prefix append returns the datagram size",
                       chunk_with_prefix_appended.value() == chunk_with_prefix_datagram.size());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "chunk-sealed prefix append writes datagram bytes",
                       !chunk_with_prefix_datagram.empty());

        auto padded_fragment = StreamFrameSendFragment{};
        padded_fragment.cached_stream_frame_header_length = 1;
        padded_fragment.cached_stream_frame_header_bytes[0] = std::byte{0x08};
        std::array<StreamFrameSendFragment, 1> padded_fragments = {padded_fragment};
        DatagramBuffer padded_fragment_datagram;
        const auto padded_fragment_appended = append_protected_one_rtt_packet_to_datagram_impl(
            padded_fragment_datagram,
            ProtectedOneRttPacketFragmentView{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 1,
                .packet_number = 18,
                .frames = {},
                .stream_fragments = padded_fragments,
            },
            one_rtt_context);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "append_protected_one_rtt_packet_to_datagram_impl pads fragment payloads below "
            "header sample size",
            padded_fragment_appended.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "padded fragment append returns the datagram size",
                       padded_fragment_appended.value() == padded_fragment_datagram.size());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "padded fragment append writes datagram bytes",
                       !padded_fragment_datagram.empty());

        std::vector<StreamFrameSendFragment> fallback_fragments;
        fallback_fragments.reserve(17);
        for (std::uint64_t stream_id = 0; stream_id < 17; ++stream_id) {
            fallback_fragments.push_back(StreamFrameSendFragment{
                .stream_id = stream_id,
                .offset = 0,
                .bytes =
                    SharedBytes{
                        std::byte{static_cast<std::uint8_t>(stream_id)},
                    },
            });
        }
        DatagramBuffer fallback_datagram;
        const auto fallback_appended = append_protected_one_rtt_packet_to_datagram_impl(
            fallback_datagram,
            ProtectedOneRttPacketFragmentView{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 14,
                .frames = {},
                .stream_fragments = fallback_fragments,
            },
            one_rtt_context);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "append_protected_one_rtt_packet_to_datagram_impl falls back to serializing many "
            "fragments",
            fallback_appended.has_value());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "fragment fallback append returns the datagram size",
                       fallback_appended.value() == fallback_datagram.size());
        coverage_check(ok, "protected_codec_packet_path_coverage_for_tests",
                       "fragment fallback append writes datagram bytes",
                       !fallback_datagram.empty());

        const std::array invalid_views = {
            StreamFrameView{
                .stream_id = 5,
                .offset = 0,
                .begin = 0,
                .end = 1,
            },
        };
        DatagramBuffer invalid_view_datagram;
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "append_protected_one_rtt_packet_to_datagram_impl propagates stream view "
            "serialization failures",
            codec_failure_offset(append_protected_one_rtt_packet_to_datagram_impl(
                                     invalid_view_datagram,
                                     ProtectedOneRttPacketView{
                                         .destination_connection_id = destination_connection_id,
                                         .packet_number_length = 2,
                                         .packet_number = 15,
                                         .frames = {},
                                         .stream_frame_views = invalid_views,
                                     },
                                     one_rtt_context),
                                 CodecErrorCode::invalid_varint, 0));

        // Datagram metadata serialization reports failures from prefix and appended packet phases.
        const auto base_failure = serialize_protected_datagram_with_metadata(
            std::array<ProtectedPacket, 1>{ProtectedInitialPacket{
                .version = kQuicVersion1,
                .destination_connection_id = {std::byte{0x83}},
                .packet_number_length = 1,
                .packet_number = 0,
                .frames = {},
            }},
            ProtectedPacket{ProtectedInitialPacket{
                .version = kQuicVersion1,
                .destination_connection_id = {std::byte{0x83}},
                .packet_number_length = 1,
                .packet_number = 1,
                .frames =
                    {
                        CryptoFrame{
                            .offset = 0,
                            .crypto_data = {std::byte{0x01}},
                        },
                    },
            }},
            one_rtt_context);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "serialize_protected_datagram_with_metadata reports prefix serialization failures "
            "before appending",
            codec_failure(base_failure, CodecErrorCode::empty_packet_payload));

        const auto appended_failure = serialize_protected_datagram_with_metadata(
            std::array<ProtectedPacket, 1>{ProtectedInitialPacket{
                .version = kQuicVersion1,
                .destination_connection_id = {std::byte{0x83}},
                .packet_number_length = 1,
                .packet_number = 0,
                .frames =
                    {
                        CryptoFrame{
                            .offset = 0,
                            .crypto_data = {std::byte{0x01}},
                        },
                    },
            }},
            ProtectedPacket{ProtectedOneRttPacket{
                .key_phase = true,
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 16,
                .frames = {PingFrame{}},
            }},
            one_rtt_context);
        coverage_check(
            ok, "protected_codec_packet_path_coverage_for_tests",
            "serialize_protected_datagram_with_metadata reports appended packet serialization "
            "failures",
            codec_failure(appended_failure, CodecErrorCode::invalid_packet_protection_state));
    }

    return ok;
}

} // namespace coquic::quic::test
