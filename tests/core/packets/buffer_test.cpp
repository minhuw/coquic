#include <array>
#include <cstddef>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/buffer.h"

namespace {

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

} // namespace
