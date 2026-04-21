#include <array>
#include <cstddef>
#include <vector>

#include <gtest/gtest.h>

#define private public
#include "src/quic/buffer.h"
#undef private

namespace {

bool buffer_internal_coverage_for_tests();

bool buffer_internal_coverage_for_tests() {
    const std::array<std::byte, 3> source{
        std::byte{0xaa},
        std::byte{0xbb},
        std::byte{0xcc},
    };
    coquic::quic::DatagramBuffer datagram{std::span<const std::byte>(source)};
    if (datagram.to_vector() != std::vector<std::byte>(source.begin(), source.end())) {
        return false;
    }

    datagram.truncate(1);
    datagram.push_back(std::byte{0xdd});
    if (datagram.to_vector() != std::vector<std::byte>{std::byte{0xaa}, std::byte{0xdd}}) {
        return false;
    }

    coquic::quic::BufferWriter null_writer(nullptr);
    null_writer.write_byte(std::byte{0xee});
    if (null_writer.bytes() != std::vector<std::byte>{std::byte{0xee}}) {
        return false;
    }

    std::array<std::byte, 2> storage{};
    coquic::quic::SpanBufferWriter writer{std::span<std::byte>(storage)};
    writer.offset_ = 3;
    const auto error = writer.write_varint(1);
    return error.has_value() && error->code == coquic::quic::CodecErrorCode::truncated_input &&
           error->offset == 3;
}

TEST(QuicBufferTest, SpanBufferWriterWritesBytesAndVarintsIntoFixedSpan) {
    std::array<std::byte, 8> storage{};
    coquic::quic::SpanBufferWriter writer{std::span<std::byte>(storage)};

    ASSERT_FALSE(writer.write_byte(std::byte{0xaa}).has_value());
    ASSERT_FALSE(writer
                     .write_bytes(std::array<std::byte, 2>{
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
    coquic::quic::SpanBufferWriter writer{std::span<std::byte>(storage)};

    ASSERT_FALSE(writer
                     .write_bytes(std::array<std::byte, 2>{
                         std::byte{0x01},
                         std::byte{0x02},
                     })
                     .has_value());
    const auto before = writer.offset();
    const auto error = writer.write_varint(0x1234);

    ASSERT_TRUE(error.has_value());
    if (!error.has_value()) {
        return;
    }
    const auto actual_error = *error;
    EXPECT_EQ(actual_error.code, coquic::quic::CodecErrorCode::truncated_input);
    EXPECT_EQ(actual_error.offset, before);
    EXPECT_EQ(writer.offset(), before);
    EXPECT_EQ(storage[0], std::byte{0x01});
    EXPECT_EQ(storage[1], std::byte{0x02});
    EXPECT_EQ(storage[2], std::byte{0x00});
}

TEST(QuicBufferTest, SpanBufferWriterUncheckedVarintWritesWithoutThrowing) {
    std::array<std::byte, 8> storage{};
    coquic::quic::SpanBufferWriter writer{std::span<std::byte>(storage)};

    writer.write_varint_unchecked(0x1234);
    writer.write_varint_unchecked(63);

    EXPECT_EQ(writer.offset(), 3u);
    ASSERT_EQ(writer.written().size(), 3u);
    EXPECT_EQ(storage[0], std::byte{0x52});
    EXPECT_EQ(storage[1], std::byte{0x34});
    EXPECT_EQ(storage[2], std::byte{0x3f});
}

TEST(QuicBufferTest, SpanBufferWriterUncheckedVarintAbortsOnOverflow) {
#if GTEST_HAS_DEATH_TEST
    std::array<std::byte, 1> storage{};
    coquic::quic::SpanBufferWriter writer{std::span<std::byte>(storage)};

    EXPECT_DEATH(writer.write_varint_unchecked(0x1234), "");
#else
    GTEST_SKIP() << "Death tests are not supported in this configuration";
#endif
}

TEST(QuicBufferTest, SpanBufferWriterUncheckedVarintAbortsOnInvalidInput) {
#if GTEST_HAS_DEATH_TEST
    std::array<std::byte, 8> storage{};
    coquic::quic::SpanBufferWriter writer{std::span<std::byte>(storage)};

    EXPECT_DEATH(writer.write_varint_unchecked(4611686018427387904ull), "");
#else
    GTEST_SKIP() << "Death tests are not supported in this configuration";
#endif
}

TEST(QuicBufferTest, CountingBufferWriterTracksWrittenSizeWithoutStorage) {
    coquic::quic::CountingBufferWriter writer;

    ASSERT_FALSE(writer.write_byte(std::byte{0x01}).has_value());
    ASSERT_FALSE(writer
                     .write_bytes(std::array<std::byte, 3>{
                         std::byte{0x02},
                         std::byte{0x03},
                         std::byte{0x04},
                     })
                     .has_value());
    ASSERT_FALSE(writer.write_varint(63).has_value());
    ASSERT_FALSE(writer.write_varint(64).has_value());

    EXPECT_EQ(writer.offset(), 7u);
}

TEST(QuicBufferTest, CountingBufferWriterUsesEncodedVarintBoundaries) {
    coquic::quic::CountingBufferWriter writer;

    ASSERT_FALSE(writer.write_varint(63).has_value());
    ASSERT_FALSE(writer.write_varint(64).has_value());
    ASSERT_FALSE(writer.write_varint(16383).has_value());
    ASSERT_FALSE(writer.write_varint(16384).has_value());

    EXPECT_EQ(writer.offset(), 1u + 2u + 2u + 4u);
}

TEST(QuicBufferTest, CountingBufferWriterUncheckedVarintTracksSize) {
    coquic::quic::CountingBufferWriter writer;

    writer.write_varint_unchecked(0x1234);
    writer.write_varint_unchecked(63);

    EXPECT_EQ(writer.offset(), 3u);
}

TEST(QuicBufferTest, CountingBufferWriterUncheckedVarintAbortsOnInvalidInput) {
#if GTEST_HAS_DEATH_TEST
    coquic::quic::CountingBufferWriter writer;

    EXPECT_DEATH(writer.write_varint_unchecked(4611686018427387904ull), "");
#else
    GTEST_SKIP() << "Death tests are not supported in this configuration";
#endif
}

TEST(QuicBufferTest, BufferWriterWritesVarintsAndTracksOffset) {
    coquic::quic::BufferWriter writer;

    ASSERT_FALSE(writer.write_varint(0x1234).has_value());
    writer.write_varint_unchecked(63);

    EXPECT_EQ(writer.offset(), 3u);
    ASSERT_EQ(writer.bytes().size(), 3u);
    EXPECT_EQ(writer.bytes()[0], std::byte{0x52});
    EXPECT_EQ(writer.bytes()[1], std::byte{0x34});
    EXPECT_EQ(writer.bytes()[2], std::byte{0x3f});
}

TEST(QuicBufferTest, BufferWriterAppendsIntoExternalStorage) {
    std::vector<std::byte> bytes{std::byte{0xaa}};
    coquic::quic::BufferWriter writer(&bytes);

    writer.write_byte(std::byte{0xbb});
    writer.write_varint_unchecked(63);

    EXPECT_EQ(writer.offset(), 3u);
    EXPECT_EQ(bytes, (std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}, std::byte{0x3f}}));
}

TEST(QuicBufferTest, BufferWriterWriteVarintRejectsInvalidInput) {
    coquic::quic::BufferWriter writer;

    const auto error = writer.write_varint(4611686018427387904ull);

    ASSERT_TRUE(error.has_value());
    if (!error.has_value()) {
        return;
    }
    const auto actual_error = *error;
    EXPECT_EQ(actual_error.code, coquic::quic::CodecErrorCode::invalid_varint);
    EXPECT_EQ(actual_error.offset, 0u);
    EXPECT_EQ(writer.offset(), 0u);
    EXPECT_TRUE(writer.bytes().empty());
}

TEST(QuicBufferTest, BufferWriterWriteVarintRejectsInvalidInputAtCurrentOffset) {
    coquic::quic::BufferWriter writer;
    writer.write_byte(std::byte{0x01});

    const auto error = writer.write_varint(4611686018427387904ull);

    ASSERT_TRUE(error.has_value());
    if (!error.has_value()) {
        return;
    }
    const auto actual_error = *error;
    EXPECT_EQ(actual_error.code, coquic::quic::CodecErrorCode::invalid_varint);
    EXPECT_EQ(actual_error.offset, 1u);
    EXPECT_EQ(writer.offset(), 1u);
    ASSERT_EQ(writer.bytes().size(), 1u);
    EXPECT_EQ(writer.bytes()[0], std::byte{0x01});
}

TEST(QuicBufferTest, BufferWriterUncheckedVarintAbortsOnInvalidInput) {
#if GTEST_HAS_DEATH_TEST
    coquic::quic::BufferWriter writer;

    EXPECT_DEATH(writer.write_varint_unchecked(4611686018427387904ull), "");
#else
    GTEST_SKIP() << "Death tests are not supported in this configuration";
#endif
}

TEST(QuicBufferTest, CountingBufferWriterWriteVarintRejectsInvalidInputAtCurrentOffset) {
    coquic::quic::CountingBufferWriter writer;
    ASSERT_FALSE(writer.write_byte(std::byte{0x01}).has_value());

    const auto error = writer.write_varint(4611686018427387904ull);

    ASSERT_TRUE(error.has_value());
    if (!error.has_value()) {
        return;
    }
    const auto actual_error = *error;
    EXPECT_EQ(actual_error.code, coquic::quic::CodecErrorCode::invalid_varint);
    EXPECT_EQ(actual_error.offset, 1u);
    EXPECT_EQ(writer.offset(), 1u);
}

TEST(QuicBufferTest, DatagramBufferAppendUninitializedExtendsWritableTail) {
    coquic::quic::DatagramBuffer buffer;
    buffer.append(std::array<std::byte, 2>{
        std::byte{0x01},
        std::byte{0x02},
    });

    auto tail = buffer.append_uninitialized(3);
    ASSERT_EQ(buffer.size(), 5u);
    ASSERT_EQ(tail.size(), 3u);
    tail[0] = std::byte{0x03};
    tail[1] = std::byte{0x04};
    tail[2] = std::byte{0x05};

    const std::array<std::byte, 5> expected{
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{0x05},
    };
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), buffer.begin(), buffer.end()));
}

TEST(QuicBufferTest, DatagramBufferConstructsFromInitializerList) {
    const coquic::quic::DatagramBuffer buffer{
        std::byte{0xaa},
        std::byte{0xbb},
        std::byte{0xcc},
    };

    EXPECT_EQ(buffer, std::vector<std::byte>({
                          std::byte{0xaa},
                          std::byte{0xbb},
                          std::byte{0xcc},
                      }));
}

TEST(QuicBufferTest, DatagramBufferComparesEqualToStandardByteVector) {
    const std::vector<std::byte> expected{
        std::byte{0xaa},
        std::byte{0xbb},
        std::byte{0xcc},
    };

    coquic::quic::DatagramBuffer buffer(expected);

    EXPECT_EQ(buffer, expected);
    EXPECT_EQ(expected, buffer);
}

TEST(QuicBufferTest, InternalCoverageHelperExercisesSpanOffsetAndDatagramUtilityPaths) {
    EXPECT_TRUE(buffer_internal_coverage_for_tests());
}

} // namespace
