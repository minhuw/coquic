# Protected Packet Direct Writer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace incremental protected-packet vector appends with fixed-size direct writes across Initial, Handshake, 0-RTT, and 1-RTT protected packet serializers while preserving wire bytes, rollback behavior, and public APIs.

**Architecture:** Add fixed-size and counting buffer writers, then make frame serialization target both growable and fixed-size writers with exact size accounting. Use those primitives to convert long-header protected packet assembly first, then the 1-RTT owned/view/fragment paths, and finally verify the exact local perf harness and `perf` profile.

**Tech Stack:** C++20, GoogleTest, Zig build, Linux `perf`, OpenSSL/AES-GCM QUIC packet protection

---

### Task 1: Add Fixed-Size And Counting Buffer Writers

**Files:**
- Modify: `src/quic/buffer.h`
- Modify: `src/quic/buffer.cpp`
- Test: `tests/core/packets/buffer_test.cpp`

- [ ] **Step 1: Write the failing buffer-writer tests**

Create `tests/core/packets/buffer_test.cpp` with these tests:

```cpp
#include <array>
#include <cstddef>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/buffer.h"

namespace {

TEST(QuicBufferTest, SpanBufferWriterWritesBytesAndVarintsIntoFixedSpan) {
    std::array<std::byte, 8> storage{};
    coquic::quic::SpanBufferWriter writer(std::span<std::byte>(storage));

    ASSERT_FALSE(writer.write_byte(std::byte{0xaa}).has_value());
    ASSERT_FALSE(writer.write_bytes(std::array<std::byte, 2>{
                                        std::byte{0xbb},
                                        std::byte{0xcc},
                                    })
                     .has_value());
    ASSERT_FALSE(writer.write_varint(0x1234).has_value());

    EXPECT_EQ(writer.offset(), 5u);
    EXPECT_EQ(writer.remaining(), 3u);
    EXPECT_EQ(storage[0], std::byte{0xaa});
    EXPECT_EQ(storage[1], std::byte{0xbb});
    EXPECT_EQ(storage[2], std::byte{0xcc});
    EXPECT_EQ(storage[3], std::byte{0x52});
    EXPECT_EQ(storage[4], std::byte{0x34});
}

TEST(QuicBufferTest, SpanBufferWriterRejectsOverflowWithoutAdvancingOffset) {
    std::array<std::byte, 3> storage{};
    coquic::quic::SpanBufferWriter writer(std::span<std::byte>(storage));

    ASSERT_FALSE(writer.write_bytes(std::array<std::byte, 2>{
                                        std::byte{0x01},
                                        std::byte{0x02},
                                    })
                     .has_value());
    const auto before = writer.offset();
    const auto error = writer.write_varint(0x1234);

    ASSERT_TRUE(error.has_value());
    EXPECT_EQ(error->code, coquic::quic::CodecErrorCode::truncated_input);
    EXPECT_EQ(error->offset, before);
    EXPECT_EQ(writer.offset(), before);
    EXPECT_EQ(storage[0], std::byte{0x01});
    EXPECT_EQ(storage[1], std::byte{0x02});
    EXPECT_EQ(storage[2], std::byte{0x00});
}

TEST(QuicBufferTest, CountingBufferWriterTracksWrittenSizeWithoutStorage) {
    coquic::quic::CountingBufferWriter writer;

    ASSERT_FALSE(writer.write_byte(std::byte{0x01}).has_value());
    ASSERT_FALSE(writer.write_bytes(std::array<std::byte, 3>{
                                        std::byte{0x02},
                                        std::byte{0x03},
                                        std::byte{0x04},
                                    })
                     .has_value());
    ASSERT_FALSE(writer.write_varint(63).has_value());
    ASSERT_FALSE(writer.write_varint(64).has_value());

    EXPECT_EQ(writer.offset(), 7u);
}

} // namespace
```

- [ ] **Step 2: Run the focused buffer tests to verify the red state**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicBufferTest.SpanBufferWriterWritesBytesAndVarintsIntoFixedSpan:QuicBufferTest.SpanBufferWriterRejectsOverflowWithoutAdvancingOffset:QuicBufferTest.CountingBufferWriterTracksWrittenSizeWithoutStorage'
```

Expected: build/test fails because `SpanBufferWriter` and `CountingBufferWriter` do not exist yet.

- [ ] **Step 3: Implement `SpanBufferWriter`, `CountingBufferWriter`, and the shared varint helpers**

Update `src/quic/buffer.h`:

```cpp
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "src/quic/varint.h"

namespace coquic::quic {

class BufferReader {
  public:
    explicit BufferReader(std::span<const std::byte> bytes);

    std::size_t offset() const;
    std::size_t remaining() const;
    CodecResult<std::byte> read_byte();
    CodecResult<std::span<const std::byte>> read_exact(std::size_t size);

  private:
    std::span<const std::byte> bytes_;
    std::size_t offset_ = 0;
};

class BufferWriter {
  public:
    BufferWriter();
    explicit BufferWriter(std::vector<std::byte> *bytes);

    std::size_t offset() const;
    void write_byte(std::byte value);
    void write_bytes(std::span<const std::byte> bytes);
    std::optional<CodecError> write_varint(std::uint64_t value);
    void write_varint_unchecked(std::uint64_t value);
    const std::vector<std::byte> &bytes() const;

  private:
    std::vector<std::byte> owned_bytes_;
    std::vector<std::byte> *bytes_ = &owned_bytes_;
};

class SpanBufferWriter {
  public:
    explicit SpanBufferWriter(std::span<std::byte> bytes);

    std::size_t offset() const;
    std::size_t remaining() const;
    std::span<const std::byte> written() const;
    std::optional<CodecError> write_byte(std::byte value);
    std::optional<CodecError> write_bytes(std::span<const std::byte> bytes);
    std::optional<CodecError> write_varint(std::uint64_t value);
    void write_varint_unchecked(std::uint64_t value);

  private:
    std::span<std::byte> bytes_;
    std::size_t offset_ = 0;
};

class CountingBufferWriter {
  public:
    std::size_t offset() const;
    std::optional<CodecError> write_byte(std::byte value);
    std::optional<CodecError> write_bytes(std::span<const std::byte> bytes);
    std::optional<CodecError> write_varint(std::uint64_t value);
    void write_varint_unchecked(std::uint64_t value);

  private:
    std::size_t offset_ = 0;
};

} // namespace coquic::quic
```

Update `src/quic/buffer.cpp`:

```cpp
#include "src/quic/buffer.h"

#include <algorithm>
#include <array>

namespace coquic::quic {

namespace {

std::optional<CodecError> write_varint_into_span(std::span<std::byte> output, std::size_t offset,
                                                 std::uint64_t value, std::size_t &written) {
    const auto required = encoded_varint_size(value);
    if (output.size() < required) {
        return CodecError{
            .code = CodecErrorCode::truncated_input,
            .offset = offset,
        };
    }

    const auto encoded = encode_varint_into(output, value);
    if (!encoded.has_value()) {
        return encoded.error();
    }

    written = encoded.value();
    return std::nullopt;
}

} // namespace

BufferReader::BufferReader(std::span<const std::byte> bytes) : bytes_(bytes) {
}

std::size_t BufferReader::offset() const {
    return offset_;
}

std::size_t BufferReader::remaining() const {
    return bytes_.size() - offset_;
}

CodecResult<std::byte> BufferReader::read_byte() {
    if (offset_ >= bytes_.size()) {
        return CodecResult<std::byte>::failure(CodecErrorCode::truncated_input, offset_);
    }

    return CodecResult<std::byte>::success(bytes_[offset_++]);
}

CodecResult<std::span<const std::byte>> BufferReader::read_exact(std::size_t size) {
    if (remaining() < size) {
        return CodecResult<std::span<const std::byte>>::failure(CodecErrorCode::truncated_input,
                                                                offset_);
    }

    const auto begin = bytes_.subspan(offset_, size);
    offset_ += size;
    return CodecResult<std::span<const std::byte>>::success(begin);
}

BufferWriter::BufferWriter() = default;

BufferWriter::BufferWriter(std::vector<std::byte> *bytes)
    : bytes_(bytes != nullptr ? bytes : &owned_bytes_) {
}

std::size_t BufferWriter::offset() const {
    return bytes_->size();
}

void BufferWriter::write_byte(std::byte value) {
    bytes_->push_back(value);
}

void BufferWriter::write_bytes(std::span<const std::byte> bytes) {
    const auto offset = bytes_->size();
    bytes_->resize(offset + bytes.size());
    std::copy(bytes.begin(), bytes.end(), bytes_->data() + static_cast<std::ptrdiff_t>(offset));
}

std::optional<CodecError> BufferWriter::write_varint(std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value);
    if (!written.has_value()) {
        return written.error();
    }
    write_bytes(std::span<const std::byte>(encoded.data(), written.value()));
    return std::nullopt;
}

void BufferWriter::write_varint_unchecked(std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value).value();
    write_bytes(std::span<const std::byte>(encoded.data(), written));
}

const std::vector<std::byte> &BufferWriter::bytes() const {
    return *bytes_;
}

SpanBufferWriter::SpanBufferWriter(std::span<std::byte> bytes) : bytes_(bytes) {
}

std::size_t SpanBufferWriter::offset() const {
    return offset_;
}

std::size_t SpanBufferWriter::remaining() const {
    return bytes_.size() - offset_;
}

std::span<const std::byte> SpanBufferWriter::written() const {
    return std::span<const std::byte>(bytes_.data(), offset_);
}

std::optional<CodecError> SpanBufferWriter::write_byte(std::byte value) {
    if (remaining() < 1) {
        return CodecError{
            .code = CodecErrorCode::truncated_input,
            .offset = offset_,
        };
    }
    bytes_[offset_++] = value;
    return std::nullopt;
}

std::optional<CodecError> SpanBufferWriter::write_bytes(std::span<const std::byte> bytes) {
    if (remaining() < bytes.size()) {
        return CodecError{
            .code = CodecErrorCode::truncated_input,
            .offset = offset_,
        };
    }
    std::copy(bytes.begin(), bytes.end(),
              bytes_.begin() + static_cast<std::ptrdiff_t>(offset_));
    offset_ += bytes.size();
    return std::nullopt;
}

std::optional<CodecError> SpanBufferWriter::write_varint(std::uint64_t value) {
    std::size_t written = 0;
    if (const auto error =
            write_varint_into_span(bytes_.subspan(offset_), offset_, value, written)) {
        return error;
    }
    offset_ += written;
    return std::nullopt;
}

void SpanBufferWriter::write_varint_unchecked(std::uint64_t value) {
    const auto error = write_varint(value);
    if (error.has_value()) {
        std::abort();
    }
}

std::size_t CountingBufferWriter::offset() const {
    return offset_;
}

std::optional<CodecError> CountingBufferWriter::write_byte(std::byte) {
    ++offset_;
    return std::nullopt;
}

std::optional<CodecError> CountingBufferWriter::write_bytes(std::span<const std::byte> bytes) {
    offset_ += bytes.size();
    return std::nullopt;
}

std::optional<CodecError> CountingBufferWriter::write_varint(std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value);
    if (!written.has_value()) {
        return written.error();
    }
    offset_ += written.value();
    return std::nullopt;
}

void CountingBufferWriter::write_varint_unchecked(std::uint64_t value) {
    offset_ += encoded_varint_size(value);
}

} // namespace coquic::quic
```

- [ ] **Step 4: Re-run the focused writer tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicBufferTest.SpanBufferWriterWritesBytesAndVarintsIntoFixedSpan:QuicBufferTest.SpanBufferWriterRejectsOverflowWithoutAdvancingOffset:QuicBufferTest.CountingBufferWriterTracksWrittenSizeWithoutStorage'
```

Expected: PASS with all three `QuicBufferTest` cases green.

- [ ] **Step 5: Commit Task 1**

Run:

```bash
git add src/quic/buffer.h src/quic/buffer.cpp tests/core/packets/buffer_test.cpp
SKIP=coquic-clang-tidy git commit -m "refactor: add fixed-size buffer writers"
```

Expected: commit succeeds and `git status --short` is clean.

### Task 2: Generalize Frame Serialization Across Writers And Add Exact Frame Sizing

**Files:**
- Modify: `src/quic/frame.h`
- Modify: `src/quic/frame.cpp`
- Test: `tests/core/packets/frame_test.cpp`

- [ ] **Step 1: Add the failing frame-size and span-serialization tests**

Add these tests to `tests/core/packets/frame_test.cpp`:

```cpp
TEST(QuicFrameTest, SerializedFrameSizeMatchesStandaloneSerialization) {
    const std::vector<Frame> frames = {
        PingFrame{},
        AckFrame{
            .largest_acknowledged = 42,
            .ack_delay = 7,
            .first_ack_range = 3,
        },
        CryptoFrame{
            .offset = 9,
            .crypto_data = {std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}},
        },
        StreamFrame{
            .fin = true,
            .has_offset = true,
            .has_length = true,
            .stream_id = 9,
            .offset = 4,
            .stream_data = {std::byte{0xbb}, std::byte{0xcc}},
        },
        ApplicationConnectionCloseFrame{
            .error_code = 0x1234,
            .reason = ConnectionCloseReason{
                .bytes = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}},
            },
        },
    };

    for (const auto &frame : frames) {
        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto size = coquic::quic::serialized_frame_size(frame);
        ASSERT_TRUE(size.has_value());
        EXPECT_EQ(size.value(), encoded.value().size());
    }
}

TEST(QuicFrameTest, SerializeFrameIntoSpanMatchesStandaloneSerialization) {
    const Frame frame = StreamFrame{
        .fin = true,
        .has_offset = true,
        .has_length = true,
        .stream_id = 9,
        .offset = 4,
        .stream_data = {std::byte{0xbb}, std::byte{0xcc}},
    };

    const auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    std::vector<std::byte> output(encoded.value().size() + 3, std::byte{0xee});
    const auto written = coquic::quic::serialize_frame_into(
        std::span<std::byte>(output).subspan(1, encoded.value().size()), frame);

    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), encoded.value().size());
    EXPECT_EQ(output.front(), std::byte{0xee});
    EXPECT_EQ(output.back(), std::byte{0xee});
    EXPECT_TRUE(std::equal(encoded.value().begin(), encoded.value().end(), output.begin() + 1));
}

TEST(QuicFrameTest, SerializeFrameIntoSpanRejectsTooSmallOutputWithoutClobberingPrefix) {
    const Frame frame = CryptoFrame{
        .offset = 9,
        .crypto_data = {std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}},
    };

    const auto size = coquic::quic::serialized_frame_size(frame);
    ASSERT_TRUE(size.has_value());

    std::vector<std::byte> output(size.value(), std::byte{0x7f});
    const auto result = coquic::quic::serialize_frame_into(
        std::span<std::byte>(output).first(size.value() - 1), frame);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::CodecErrorCode::truncated_input);
    EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](std::byte byte) {
        return byte == std::byte{0x7f};
    }));
}
```

- [ ] **Step 2: Run the focused frame tests to verify the red state**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicFrameTest.SerializedFrameSizeMatchesStandaloneSerialization:QuicFrameTest.SerializeFrameIntoSpanMatchesStandaloneSerialization:QuicFrameTest.SerializeFrameIntoSpanRejectsTooSmallOutputWithoutClobberingPrefix:QuicFrameTest.AppendSerializedFrameMatchesStandaloneSerialization'
```

Expected: build/test fails because `serialized_frame_size(...)` and `serialize_frame_into(std::span<std::byte>, ...)` do not exist yet.

- [ ] **Step 3: Add the public frame-size and fixed-span serialization entry points**

Update `src/quic/frame.h`:

```cpp
CodecResult<std::vector<AckPacketNumberRange>> ack_frame_packet_number_ranges(const AckFrame &ack);
CodecResult<std::size_t> serialized_frame_size(const Frame &frame);
CodecResult<std::size_t> serialize_frame_into(std::span<std::byte> output, const Frame &frame);
CodecResult<std::vector<std::byte>> serialize_frame(const Frame &frame);
CodecResult<std::size_t> append_serialized_frame(std::vector<std::byte> &bytes, const Frame &frame);
CodecResult<FrameDecodeResult> deserialize_frame(std::span<const std::byte> bytes);
```

Update `src/quic/frame.cpp` by lifting the existing serializer body into a shared template and then wiring the three concrete entry points through it:

```cpp
namespace {

template <typename Writer>
std::optional<CodecError> append_exact_length_bytes(Writer &writer,
                                                    std::span<const std::byte> bytes) {
    writer.write_varint_unchecked(bytes.size());
    return writer.write_bytes(bytes);
}

template <typename Writer>
std::optional<CodecError> append_single_varint_frame(Writer &writer, std::byte type,
                                                     std::uint64_t value) {
    if (const auto error = writer.write_byte(type)) {
        return error;
    }
    return writer.write_varint(value);
}

template <typename Writer>
std::optional<CodecError> serialize_frame_into_writer(Writer &writer, const Frame &frame) {
    // Move the existing frame variant switch body here unchanged in behavior.
    // Replace:
    //   writer.write_byte(...)                    with checked writer calls
    //   append_varint(writer, value)             with writer.write_varint(value)
    //   append_varint_unchecked(writer, value)   with writer.write_varint_unchecked(value)
    //   append_exact_length_bytes(writer, bytes) with the templated helper above
    // The per-frame validation and emitted bytes must remain identical.
}

} // namespace

CodecResult<std::size_t> serialized_frame_size(const Frame &frame) {
    CountingBufferWriter writer;
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    return CodecResult<std::size_t>::success(writer.offset());
}

CodecResult<std::size_t> serialize_frame_into(std::span<std::byte> output, const Frame &frame) {
    SpanBufferWriter writer(output);
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    return CodecResult<std::size_t>::success(writer.offset());
}

CodecResult<std::vector<std::byte>> serialize_frame(const Frame &frame) {
    BufferWriter writer;
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        return failure_result(error->code, error->offset);
    }
    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

CodecResult<std::size_t> append_serialized_frame(std::vector<std::byte> &bytes,
                                                 const Frame &frame) {
    const auto begin = bytes.size();
    BufferWriter writer(&bytes);
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        bytes.resize(begin);
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    return CodecResult<std::size_t>::success(bytes.size() - begin);
}
```

- [ ] **Step 4: Re-run the focused frame tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicFrameTest.SerializedFrameSizeMatchesStandaloneSerialization:QuicFrameTest.SerializeFrameIntoSpanMatchesStandaloneSerialization:QuicFrameTest.SerializeFrameIntoSpanRejectsTooSmallOutputWithoutClobberingPrefix:QuicFrameTest.AppendSerializedFrameMatchesStandaloneSerialization'
```

Expected: PASS with all four `QuicFrameTest` cases green.

- [ ] **Step 5: Commit Task 2**

Run:

```bash
git add src/quic/frame.h src/quic/frame.cpp tests/core/packets/frame_test.cpp
SKIP=coquic-clang-tidy git commit -m "refactor: generalize frame serialization writers"
```

Expected: commit succeeds and `git status --short` is clean.

### Task 3: Direct-Write Initial, Handshake, And 0-RTT Protected Packets

**Files:**
- Modify: `src/quic/protected_codec.cpp`
- Test: `tests/core/packets/protected_codec_test.cpp`

- [ ] **Step 1: Add the failing long-header parity and metadata tests**

Add these tests to `tests/core/packets/protected_codec_test.cpp`:

```cpp
TEST(QuicProtectedCodecTest,
     SerializeProtectedDatagramWithMetadataAppendedInitialPacketMatchesFullVectorSerialization) {
    const std::array<coquic::quic::ProtectedPacket, 1> prefix_packets = {
        make_minimal_initial_packet(),
    };
    const auto appended_packet = coquic::quic::ProtectedPacket{make_minimal_initial_packet()};
    const std::array<coquic::quic::ProtectedPacket, 2> full_packets = {
        prefix_packets.front(),
        appended_packet,
    };

    const auto encoded = coquic::quic::serialize_protected_datagram_with_metadata(
        prefix_packets, appended_packet, make_rfc9001_client_initial_serialize_context());
    const auto encoded_full = coquic::quic::serialize_protected_datagram_with_metadata(
        full_packets, make_rfc9001_client_initial_serialize_context());

    ASSERT_TRUE(encoded.has_value());
    ASSERT_TRUE(encoded_full.has_value());
    EXPECT_EQ(encoded.value().bytes, encoded_full.value().bytes);
    EXPECT_EQ(encoded.value().packet_metadata, encoded_full.value().packet_metadata);
}

TEST(QuicProtectedCodecTest,
     SerializeProtectedDatagramWithMetadataAppendedZeroRttPacketMatchesFullVectorSerialization) {
    const auto context =
        make_zero_rtt_serialize_context(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 16);
    const std::array<coquic::quic::ProtectedPacket, 1> prefix_packets = {
        make_minimal_zero_rtt_packet(),
    };
    const auto appended_packet = coquic::quic::ProtectedPacket{make_minimal_zero_rtt_packet()};
    const std::array<coquic::quic::ProtectedPacket, 2> full_packets = {
        prefix_packets.front(),
        appended_packet,
    };

    const auto encoded = coquic::quic::serialize_protected_datagram_with_metadata(
        prefix_packets, appended_packet, context);
    const auto encoded_full =
        coquic::quic::serialize_protected_datagram_with_metadata(full_packets, context);

    ASSERT_TRUE(encoded.has_value());
    ASSERT_TRUE(encoded_full.has_value());
    EXPECT_EQ(encoded.value().bytes, encoded_full.value().bytes);
    EXPECT_EQ(encoded.value().packet_metadata, encoded_full.value().packet_metadata);
}

TEST(QuicProtectedCodecTest, SerializeProtectedDatagramWithMetadataTracksCoalescedInitialOffsets) {
    const std::array<coquic::quic::ProtectedPacket, 2> packets = {
        make_minimal_initial_packet(),
        make_minimal_initial_packet(),
    };

    const auto encoded = coquic::quic::serialize_protected_datagram_with_metadata(
        packets, make_rfc9001_client_initial_serialize_context());

    ASSERT_TRUE(encoded.has_value());
    ASSERT_EQ(encoded.value().packet_metadata.size(), 2u);
    EXPECT_EQ(encoded.value().packet_metadata[0].offset, 0u);
    EXPECT_EQ(encoded.value().packet_metadata[1].offset,
              encoded.value().packet_metadata[0].length);
    EXPECT_EQ(encoded.value().packet_metadata[0].length +
                  encoded.value().packet_metadata[1].length,
              encoded.value().bytes.size());
}
```

- [ ] **Step 2: Run the focused protected-codec slice to verify the red state**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataAppendedInitialPacketMatchesFullVectorSerialization:QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataAppendedZeroRttPacketMatchesFullVectorSerialization:QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataTracksCoalescedInitialOffsets:QuicProtectedCodecTest.SerializesClientInitialFromRfc9001AppendixA2:QuicProtectedCodecTest.RoundTripsProtectedZeroRttPacket'
```

Expected: the new tests fail once the long-header serializers stop returning standalone vectors and before the direct-write metadata path is wired through consistently.

- [ ] **Step 3: Add direct-write long-header helpers and route Initial/Handshake/0-RTT through them**

Update `src/quic/protected_codec.cpp` with these helper declarations near the existing internal
serializer helpers:

```cpp
constexpr std::size_t minimum_payload_bytes_for_header_sample(std::uint8_t packet_number_length) {
    return packet_number_length >= kHeaderProtectionSampleOffset
               ? 0u
               : kHeaderProtectionSampleOffset - packet_number_length;
}

CodecResult<bool> apply_long_header_protection_in_place(std::span<std::byte> packet_bytes,
                                                        PacketNumberSpan packet_number,
                                                        CipherSuite cipher_suite,
                                                        const PacketProtectionKeys &keys);

CodecResult<std::size_t> serialized_frame_payload_size(std::span<const Frame> frames) {
    std::size_t total = 0;
    for (const auto &frame : frames) {
        const auto size = serialized_frame_size(frame);
        if (!size.has_value()) {
            return size;
        }
        total += size.value();
    }
    return CodecResult<std::size_t>::success(total);
}

std::optional<CodecError> write_u32_be(SpanBufferWriter &writer, std::uint32_t value);
std::optional<CodecError> append_packet_number(SpanBufferWriter &writer,
                                               TruncatedPacketNumberEncoding encoding);
```

Then add a single long-header append path and make the existing three serializers wrap it:

```cpp
template <typename PacketLike>
CodecResult<std::size_t> append_protected_long_header_packet_to_datagram(
    std::vector<std::byte> &datagram, const PacketLike &packet, LongHeaderPacketType packet_type,
    CipherSuite cipher_suite, const PacketProtectionKeys &keys, std::span<const std::byte> token) {
    const auto datagram_begin = datagram.size();
    const auto rollback = [&]() { datagram.resize(datagram_begin); };

    const auto raw_payload_size = serialized_frame_payload_size(packet.frames);
    if (!raw_payload_size.has_value()) {
        return CodecResult<std::size_t>::failure(raw_payload_size.error().code,
                                                 raw_payload_size.error().offset);
    }

    const auto plaintext_payload_size =
        std::max(raw_payload_size.value(),
                 minimum_payload_bytes_for_header_sample(packet.packet_number_length));
    const auto protected_payload_size = plaintext_payload_size + kPacketProtectionTagLength;
    const auto length_value = packet.packet_number_length + protected_payload_size;
    const auto packet_number_offset = 1 + 4 + 1 + packet.destination_connection_id.size() + 1 +
                                      packet.source_connection_id.size() +
                                      (packet_type == LongHeaderPacketType::initial
                                           ? encoded_varint_size(token.size()) + token.size()
                                           : 0u) +
                                      encoded_varint_size(length_value);
    const auto packet_size = packet_number_offset + packet.packet_number_length +
                             protected_payload_size;

    datagram.resize(datagram_begin + packet_size);
    auto packet_bytes = std::span<std::byte>(datagram).subspan(datagram_begin, packet_size);
    SpanBufferWriter writer(packet_bytes);

    if (const auto error = writer.write_byte(static_cast<std::byte>(
            0xc0u | (encoded_long_header_type(packet_type, packet.version) << 4) |
            ((packet.packet_number_length - 1) & 0x03u)))) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = write_u32_be(writer, packet.version)) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error =
            writer.write_byte(static_cast<std::byte>(packet.destination_connection_id.size()))) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_bytes(packet.destination_connection_id)) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error =
            writer.write_byte(static_cast<std::byte>(packet.source_connection_id.size()))) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_bytes(packet.source_connection_id)) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (packet_type == LongHeaderPacketType::initial) {
        writer.write_varint_unchecked(token.size());
        if (const auto error = writer.write_bytes(token)) {
            rollback();
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
    }
    writer.write_varint_unchecked(length_value);
    if (const auto error = append_packet_number(writer, TruncatedPacketNumberEncoding{
                                                            .packet_number_length =
                                                                packet.packet_number_length,
                                                            .truncated_packet_number =
                                                                truncate_packet_number(
                                                                    packet.packet_number,
                                                                    packet.packet_number_length)
                                                                    .value(),
                                                        })) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    for (const auto &frame : packet.frames) {
        auto frame_span = packet_bytes.subspan(writer.offset());
        const auto written = serialize_frame_into(frame_span, frame);
        if (!written.has_value()) {
            rollback();
            return CodecResult<std::size_t>::failure(written.error().code, written.error().offset);
        }
        if (const auto error = writer.write_bytes(frame_span.first(written.value()))) {
            rollback();
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
    }
    if (writer.offset() < packet_number_offset + packet.packet_number_length + plaintext_payload_size) {
        std::fill(packet_bytes.begin() + static_cast<std::ptrdiff_t>(writer.offset()),
                  packet_bytes.begin() + static_cast<std::ptrdiff_t>(
                      packet_number_offset + packet.packet_number_length + plaintext_payload_size),
                  std::byte{0x00});
    }

    const auto protected_payload_offset = packet_number_offset + packet.packet_number_length;
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys.iv, packet.packet_number);
    const auto ciphertext = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = cipher_suite,
        .key = keys.key,
        .nonce = nonce,
        .associated_data = std::span<const std::byte>(packet_bytes).first(protected_payload_offset),
        .plaintext =
            std::span<const std::byte>(packet_bytes).subspan(protected_payload_offset,
                                                             plaintext_payload_size),
        .ciphertext = packet_bytes.subspan(protected_payload_offset),
    });
    if (!ciphertext.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(ciphertext.error().code, ciphertext.error().offset);
    }

    const auto final_packet_size = protected_payload_offset + ciphertext.value();
    datagram.resize(datagram_begin + final_packet_size);
    const auto protected_packet = apply_long_header_protection_in_place(
        std::span<std::byte>(datagram).subspan(datagram_begin, final_packet_size),
        PacketNumberSpan{
            .packet_number_offset = packet_number_offset,
            .packet_number_length = packet.packet_number_length,
        },
        cipher_suite, keys);
    if (!protected_packet.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                 protected_packet.error().offset);
    }

    return CodecResult<std::size_t>::success(final_packet_size);
}
```

Wire `serialize_protected_initial_packet(...)`, `serialize_protected_handshake_packet(...)`, and
`serialize_protected_zero_rtt_packet(...)` through a local empty datagram plus the append helper,
and update `append_serialized_protected_packet(...)` so long-header packets push metadata from the
returned packet length instead of concatenating a returned vector.

- [ ] **Step 4: Re-run the focused long-header codec tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataAppendedInitialPacketMatchesFullVectorSerialization:QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataAppendedZeroRttPacketMatchesFullVectorSerialization:QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataTracksCoalescedInitialOffsets:QuicProtectedCodecTest.SerializesClientInitialFromRfc9001AppendixA2:QuicProtectedCodecTest.RoundTripsQuicV2InitialPacket:QuicProtectedCodecTest.RoundTripsQuicV2HandshakePacket:QuicProtectedCodecTest.RoundTripsProtectedZeroRttPacket'
```

Expected: PASS with the new metadata tests green and the existing RFC/round-trip coverage still green.

- [ ] **Step 5: Commit Task 3**

Run:

```bash
git add src/quic/protected_codec.cpp tests/core/packets/protected_codec_test.cpp
SKIP=coquic-clang-tidy git commit -m "refactor: direct-write long-header protected packets"
```

Expected: commit succeeds and `git status --short` is clean.

### Task 4: Direct-Write 1-RTT Owned, View, And Fragment Protected Packets

**Files:**
- Modify: `src/quic/protected_codec.cpp`
- Test: `tests/core/packets/protected_codec_test.cpp`

- [ ] **Step 1: Add the failing 1-RTT rollback and metadata tests**

Add these tests to `tests/core/packets/protected_codec_test.cpp`:

```cpp
TEST(QuicProtectedCodecTest,
     SerializeProtectedDatagramWithMetadataAppendedOneRttPacketMatchesFullVectorSerialization) {
    const auto packet = make_minimal_one_rtt_packet();
    const auto context = make_one_rtt_serialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, /*secret_size=*/16);

    const std::array<coquic::quic::ProtectedPacket, 1> prefix_packets = {packet};
    const auto appended_packet = coquic::quic::ProtectedPacket{packet};
    const std::array<coquic::quic::ProtectedPacket, 2> full_packets = {
        prefix_packets.front(),
        appended_packet,
    };

    const auto encoded = coquic::quic::serialize_protected_datagram_with_metadata(
        prefix_packets, appended_packet, context);
    const auto encoded_full =
        coquic::quic::serialize_protected_datagram_with_metadata(full_packets, context);

    ASSERT_TRUE(encoded.has_value());
    ASSERT_TRUE(encoded_full.has_value());
    EXPECT_EQ(encoded.value().bytes, encoded_full.value().bytes);
    EXPECT_EQ(encoded.value().packet_metadata, encoded_full.value().packet_metadata);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketRollsBackDatagramOnHeaderProtectionFault) {
    const auto packet = make_minimal_one_rtt_packet();
    const auto context = make_one_rtt_serialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, /*secret_size=*/16);
    const std::vector<std::byte> prefix{
        std::byte{0xaa},
        std::byte{0xbb},
        std::byte{0xcc},
    };
    auto datagram = prefix;

    const auto injector = coquic::quic::test::ScopedPacketCryptoFaultInjector(
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new);
    const auto appended =
        coquic::quic::test::append_protected_one_rtt_packet_to_datagram(datagram, packet, context);

    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(datagram, prefix);
}

TEST(QuicProtectedCodecTest, AppendOneRttPacketFragmentViewRollsBackDatagramOnSealFault) {
    auto packet = make_minimal_one_rtt_packet();
    packet.frames.clear();
    auto shared_payload = std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{
        std::byte{0xaa},
        std::byte{0xbb},
        std::byte{0xcc},
        std::byte{0xdd},
    });
    const std::vector<coquic::quic::StreamFrameSendFragment> fragments = {
        coquic::quic::StreamFrameSendFragment{
            .stream_id = 9,
            .offset = 4,
            .bytes = coquic::quic::SharedBytes(shared_payload, 1, 3),
            .fin = true,
        },
    };

    const auto context = make_one_rtt_serialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, /*secret_size=*/16);
    const auto packet_view = coquic::quic::ProtectedOneRttPacketFragmentView{
        .spin_bit = packet.spin_bit,
        .key_phase = packet.key_phase,
        .destination_connection_id = packet.destination_connection_id,
        .packet_number_length = packet.packet_number_length,
        .packet_number = packet.packet_number,
        .frames = packet.frames,
        .stream_fragments = fragments,
    };
    const std::vector<std::byte> prefix{
        std::byte{0xdd},
        std::byte{0xee},
    };
    auto datagram = prefix;

    const auto injector = coquic::quic::test::ScopedPacketCryptoFaultInjector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);
    const auto appended =
        coquic::quic::append_protected_one_rtt_packet_to_datagram(datagram, packet_view, context);

    ASSERT_FALSE(appended.has_value());
    EXPECT_EQ(datagram, prefix);
}
```

- [ ] **Step 2: Run the focused 1-RTT slice to verify the red state**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataAppendedOneRttPacketMatchesFullVectorSerialization:QuicProtectedCodecTest.AppendOneRttPacketRollsBackDatagramOnHeaderProtectionFault:QuicProtectedCodecTest.AppendOneRttPacketFragmentViewRollsBackDatagramOnSealFault:QuicProtectedCodecTest.AppendsOneRttPacketIntoExistingDatagramBuffer:QuicProtectedCodecTest.AppendsOneRttPacketViewIntoExistingDatagramBuffer:QuicProtectedCodecTest.AppendsOneRttPacketFragmentViewIntoExistingDatagramBuffer'
```

Expected: the new rollback tests fail until `append_protected_one_rtt_packet_to_datagram_impl(...)`
stops partially mutating the datagram on failure and the metadata append path is fully aligned.

- [ ] **Step 3: Convert the 1-RTT serializer to fixed-size direct writes**

Update `src/quic/protected_codec.cpp` by replacing the incremental append logic in
`append_protected_one_rtt_packet_to_datagram_impl(...)` with an exact-size direct-write path:

```cpp
template <typename OneRttPacketLike>
CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(std::vector<std::byte> &datagram,
                                                 const OneRttPacketLike &packet,
                                                 const SerializeProtectionContext &context) {
    // Keep the existing secret, key-phase, and packet-number validation exactly as-is.

    const auto packet_number_offset = 1 + packet.destination_connection_id.size();
    const auto payload_offset = packet_number_offset + packet.packet_number_length;
    const auto datagram_begin = datagram.size();
    const auto rollback = [&]() { datagram.resize(datagram_begin); };

    std::size_t non_stream_frame_bytes = 0;
    for (const auto &frame : packet.frames) {
        if (const auto *stream = std::get_if<StreamFrame>(&frame);
            stream != nullptr && !stream->has_length) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch, 0);
        }
        const auto size = serialized_frame_size(frame);
        if (!size.has_value()) {
            return CodecResult<std::size_t>::failure(size.error().code, size.error().offset);
        }
        non_stream_frame_bytes += size.value();
    }

    const auto stream_frame_bytes = packet_stream_payload_wire_size(packet);
    const auto plaintext_payload_size = std::max(
        non_stream_frame_bytes + stream_frame_bytes,
        minimum_payload_bytes_for_header_sample(packet.packet_number_length));
    const auto maximum_packet_size =
        payload_offset + plaintext_payload_size + kPacketProtectionTagLength;

    datagram.resize(datagram_begin + maximum_packet_size);
    auto packet_bytes =
        std::span<std::byte>(datagram).subspan(datagram_begin, maximum_packet_size);
    SpanBufferWriter writer(packet_bytes.first(payload_offset + plaintext_payload_size));

    if (const auto error = writer.write_byte(make_short_header_first_byte(
            packet.spin_bit, packet.key_phase, packet.packet_number_length))) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_bytes(packet.destination_connection_id)) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = append_packet_number(writer, TruncatedPacketNumberEncoding{
                                                            .packet_number_length =
                                                                packet.packet_number_length,
                                                            .truncated_packet_number =
                                                                truncate_packet_number(
                                                                    packet.packet_number,
                                                                    packet.packet_number_length)
                                                                    .value(),
                                                        })) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    std::size_t frame_index = 0;
    for (const auto &frame : packet.frames) {
        auto frame_span = packet_bytes.subspan(writer.offset());
        const auto written = serialize_frame_into(frame_span, frame);
        if (!written.has_value()) {
            rollback();
            return CodecResult<std::size_t>::failure(written.error().code, frame_index);
        }
        if (const auto error = writer.write_bytes(frame_span.first(written.value()))) {
            rollback();
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
        ++frame_index;
    }

    if constexpr (requires { packet.stream_frame_views; }) {
        for (const auto &stream_view : packet.stream_frame_views) {
            auto frame_span = packet_bytes.subspan(writer.offset());
            const auto written = serialize_stream_frame_view_into_span(frame_span, stream_view);
            if (!written.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(written.error().code, frame_index);
            }
            if (const auto error = writer.write_bytes(frame_span.first(written.value()))) {
                rollback();
                return CodecResult<std::size_t>::failure(error->code, error->offset);
            }
            ++frame_index;
        }
    } else {
        for (const auto &fragment : packet.stream_fragments) {
            auto frame_span = packet_bytes.subspan(writer.offset());
            const auto written =
                serialize_stream_frame_send_fragment_into_span(frame_span, fragment);
            if (!written.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(written.error().code, frame_index);
            }
            if (const auto error = writer.write_bytes(frame_span.first(written.value()))) {
                rollback();
                return CodecResult<std::size_t>::failure(error->code, error->offset);
            }
            ++frame_index;
        }
    }

    if (writer.offset() < payload_offset + plaintext_payload_size) {
        std::fill(packet_bytes.begin() + static_cast<std::ptrdiff_t>(writer.offset()),
                  packet_bytes.begin() +
                      static_cast<std::ptrdiff_t>(payload_offset + plaintext_payload_size),
                  std::byte{0x00});
    }

    const auto ciphertext = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = context.one_rtt_secret->cipher_suite,
        .key = keys.value().key,
        .nonce = nonce,
        .associated_data = std::span<const std::byte>(packet_bytes).first(payload_offset),
        .plaintext = std::span<const std::byte>(packet_bytes).subspan(payload_offset,
                                                                      plaintext_payload_size),
        .ciphertext = packet_bytes.subspan(payload_offset),
    });
    if (!ciphertext.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(ciphertext.error().code, ciphertext.error().offset);
    }

    const auto final_packet_size = payload_offset + ciphertext.value();
    datagram.resize(datagram_begin + final_packet_size);
    const auto protected_packet = apply_short_header_protection_in_place(
        std::span<std::byte>(datagram).subspan(datagram_begin, final_packet_size),
        PacketNumberSpan{
            .packet_number_offset = packet_number_offset,
            .packet_number_length = packet.packet_number_length,
        },
        context.one_rtt_secret->cipher_suite, keys.value());
    if (!protected_packet.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                 protected_packet.error().offset);
    }

    return CodecResult<std::size_t>::success(final_packet_size);
}
```

Also add fixed-span STREAM helpers by mirroring the existing vector-based logic:

```cpp
CodecResult<std::size_t> serialize_stream_frame_into(std::span<std::byte> output,
                                                     const StreamFrameHeaderFields &header,
                                                     std::span<const std::byte> payload);
CodecResult<std::size_t> serialize_stream_frame_view_into_span(std::span<std::byte> output,
                                                               const StreamFrameView &stream_view);
CodecResult<std::size_t> serialize_stream_frame_send_fragment_into_span(
    std::span<std::byte> output, const StreamFrameSendFragment &fragment);
```

Keep the existing vector-returning wrapper behavior unchanged by routing
`serialize_protected_datagram_with_metadata(...)` and the `test::append_protected_one_rtt_packet_to_datagram(...)`
hook through the refactored append helper.

- [ ] **Step 4: Re-run the focused 1-RTT codec tests**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataAppendedOneRttPacketMatchesFullVectorSerialization:QuicProtectedCodecTest.AppendOneRttPacketRollsBackDatagramOnHeaderProtectionFault:QuicProtectedCodecTest.AppendOneRttPacketFragmentViewRollsBackDatagramOnSealFault:QuicProtectedCodecTest.AppendsOneRttPacketIntoExistingDatagramBuffer:QuicProtectedCodecTest.AppendsOneRttPacketViewIntoExistingDatagramBuffer:QuicProtectedCodecTest.AppendsOneRttPacketFragmentViewIntoExistingDatagramBuffer:QuicProtectedCodecTest.OneRttPacketSerializesSharedStreamFrameViews'
```

Expected: PASS with the new rollback/metadata coverage green and the existing append parity tests still green.

- [ ] **Step 5: Commit Task 4**

Run:

```bash
git add src/quic/protected_codec.cpp tests/core/packets/protected_codec_test.cpp
SKIP=coquic-clang-tidy git commit -m "refactor: direct-write one-rtt protected packets"
```

Expected: commit succeeds and `git status --short` is clean.

### Task 5: Full Codec Verification And Perf Re-Measurement

**Files:**
- No code changes expected

- [ ] **Step 1: Run the focused protected-codec regression slice**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicBufferTest.*:QuicFrameTest.SerializedFrameSizeMatchesStandaloneSerialization:QuicFrameTest.SerializeFrameIntoSpanMatchesStandaloneSerialization:QuicFrameTest.SerializeFrameIntoSpanRejectsTooSmallOutputWithoutClobberingPrefix:QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataAppendedInitialPacketMatchesFullVectorSerialization:QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataAppendedZeroRttPacketMatchesFullVectorSerialization:QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataTracksCoalescedInitialOffsets:QuicProtectedCodecTest.SerializeProtectedDatagramWithMetadataAppendedOneRttPacketMatchesFullVectorSerialization:QuicProtectedCodecTest.AppendOneRttPacketRollsBackDatagramOnHeaderProtectionFault:QuicProtectedCodecTest.AppendOneRttPacketFragmentViewRollsBackDatagramOnSealFault:QuicProtectedCodecTest.SerializesClientInitialFromRfc9001AppendixA2:QuicProtectedCodecTest.RoundTripsQuicV2InitialPacket:QuicProtectedCodecTest.RoundTripsQuicV2HandshakePacket:QuicProtectedCodecTest.RoundTripsProtectedZeroRttPacket:QuicProtectedCodecTest.AppendsOneRttPacketIntoExistingDatagramBuffer:QuicProtectedCodecTest.AppendsOneRttPacketViewIntoExistingDatagramBuffer:QuicProtectedCodecTest.AppendsOneRttPacketFragmentViewIntoExistingDatagramBuffer'
```

Expected: PASS.

- [ ] **Step 2: Run the full repo test suite**

Run:

```bash
nix develop -c zig build test
```

Expected: PASS.

- [ ] **Step 3: Run the release build**

Run:

```bash
nix develop -c zig build -Doptimize=ReleaseFast
```

Expected: PASS.

- [ ] **Step 4: Re-run the exact local bulk-download harness**

Run:

```bash
bash -lc 'set -euo pipefail
port=9571
server_log=$(mktemp)
json_out=$(mktemp)
cleanup() {
  if [ -n "${server_pid:-}" ]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
cd /home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send
taskset -c 2 ./zig-out/bin/coquic-perf server --host 127.0.0.1 --port "$port" --certificate-chain tests/fixtures/quic-server-cert.pem --private-key tests/fixtures/quic-server-key.pem --io-backend socket >"$server_log" 2>&1 &
server_pid=$!
sleep 1
taskset -c 3 ./zig-out/bin/coquic-perf client --host 127.0.0.1 --port "$port" --mode bulk --io-backend socket --request-bytes 0 --response-bytes 1048576 --streams 4 --connections 1 --requests-in-flight 1 --direction download --warmup 0ms --duration 5s --json-out "$json_out"
cat "$json_out"'
```

Expected: throughput is at least not worse than the current `57.289-60.271 MiB/s` unsampled range,
and ideally moves up while preserving correctness.

- [ ] **Step 5: Take a fresh `perf` sample and compare the hotspot profile**

Run:

```bash
bash -lc 'set -euo pipefail
port=9572
server_log=$(mktemp)
perf_log=$(mktemp)
perf_data=/tmp/coquic-protected-direct-writer.perf.data
json_out=$(mktemp)
cleanup() {
  if [ -n "${perf_pid:-}" ]; then
    wait "$perf_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "${server_pid:-}" ]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
cd /home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send
rm -f "$perf_data"
taskset -c 2 ./zig-out/bin/coquic-perf server --host 127.0.0.1 --port "$port" --certificate-chain tests/fixtures/quic-server-cert.pem --private-key tests/fixtures/quic-server-key.pem --io-backend socket >"$server_log" 2>&1 &
server_pid=$!
sleep 1
sudo perf record -F 799 -g --call-graph dwarf,16384 -p "$server_pid" -o "$perf_data" -- sleep 8 >"$perf_log" 2>&1 &
perf_pid=$!
sleep 1
taskset -c 3 ./zig-out/bin/coquic-perf client --host 127.0.0.1 --port "$port" --mode bulk --io-backend socket --request-bytes 0 --response-bytes 1048576 --streams 4 --connections 1 --requests-in-flight 1 --direction download --warmup 0ms --duration 5s --json-out "$json_out"
wait "$perf_pid"
sudo perf report -f --stdio --no-inline --no-children --percent-limit 0.5 -i "$perf_data" --sort overhead,comm,dso,symbol | sed -n "1,80p"'
```

Expected: `append_protected_one_rtt_packet_to_datagram`, `append_stream_frame_payload_into`,
`append_bytes`, and `memmove` all drop materially relative to the current sampled profile.
