#include <array>
#include <cstddef>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#define private public
#include "src/quic/codec/buffer.h"
#undef private
#include "src/quic/object_cache.h"

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

TEST(QuicBufferTest, DatagramByteStorageAllocationHandlesZeroAndNullInputs) {
    using coquic::quic::detail::allocate_datagram_byte_storage;
    using coquic::quic::detail::deallocate_datagram_byte_storage;

    EXPECT_EQ(allocate_datagram_byte_storage(0), nullptr);
    deallocate_datagram_byte_storage(nullptr, 16);

    auto *allocated = allocate_datagram_byte_storage(1);
    ASSERT_NE(allocated, nullptr);
    deallocate_datagram_byte_storage(allocated, 0);
    deallocate_datagram_byte_storage(allocated, 1);

    constexpr std::size_t larger_than_cache = 64u * 1024u + 1u;
    auto *uncached = allocate_datagram_byte_storage(larger_than_cache);
    ASSERT_NE(uncached, nullptr);
    deallocate_datagram_byte_storage(uncached, larger_than_cache);
}

TEST(QuicObjectCacheTest, FixedObjectCacheReusesStableSlotsAndTracksOwnership) {
    struct CachedObject {
        int value = 0;
    };

    coquic::quic::detail::FixedObjectCache<CachedObject, 2> cache;
    EXPECT_EQ(cache.available(), 2u);
    EXPECT_EQ(cache.in_use(), 0u);

    auto *first = cache.take();
    auto *second = cache.take();
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_NE(first, second);
    EXPECT_TRUE(cache.owns(first));
    EXPECT_TRUE(cache.owns(second));
    EXPECT_FALSE(cache.cached(first));
    EXPECT_EQ(cache.take(), nullptr);
    EXPECT_EQ(cache.available(), 0u);
    EXPECT_EQ(cache.in_use(), 2u);

    first->value = 42;
    EXPECT_TRUE(cache.put(first, [](CachedObject &object) { object.value = 7; }));
    EXPECT_TRUE(cache.cached(first));
    EXPECT_EQ(cache.available(), 1u);
    auto *reused = cache.take();
    EXPECT_EQ(reused, first);
    EXPECT_EQ(reused->value, 7);

    EXPECT_TRUE(cache.put(reused));
    EXPECT_TRUE(cache.put(second));
    EXPECT_FALSE(cache.put(second));
    EXPECT_EQ(cache.available(), 2u);
}

TEST(QuicObjectCacheTest, FixedObjectCacheRejectsForeignPointers) {
    struct CachedObject {
        int value = 0;
    };

    coquic::quic::detail::FixedObjectCache<CachedObject, 1> cache;
    CachedObject foreign{};

    EXPECT_FALSE(cache.owns(&foreign));
    EXPECT_FALSE(cache.put(&foreign));

    auto *cached = cache.take_assign(CachedObject{.value = 9});
    ASSERT_NE(cached, nullptr);
    EXPECT_EQ(cached->value, 9);
    EXPECT_TRUE(cache.owns(cached));
    EXPECT_TRUE(cache.put(cached));
}

TEST(QuicObjectCacheTest, FixedObjectCacheSupportsBulkTakeAndPut) {
    struct CachedObject {
        int value = 0;
    };

    coquic::quic::detail::FixedObjectCache<CachedObject, 3> cache;
    std::array<CachedObject *, 4> objects{};

    EXPECT_EQ(cache.take_bulk(objects), 3u);
    EXPECT_NE(objects[0], nullptr);
    EXPECT_NE(objects[1], nullptr);
    EXPECT_NE(objects[2], nullptr);
    EXPECT_EQ(objects[3], nullptr);
    EXPECT_EQ(cache.available(), 0u);

    objects[0]->value = 1;
    objects[1]->value = 2;
    objects[2]->value = 3;
    EXPECT_EQ(cache.put_bulk(std::span<CachedObject *const>(objects.data(), 2),
                             [](CachedObject &object) { object.value = 0; }),
              2u);
    EXPECT_EQ(cache.available(), 2u);

    std::array<CachedObject *, 2> reused{};
    EXPECT_EQ(cache.take_bulk(reused), 2u);
    ASSERT_NE(reused[0], nullptr);
    ASSERT_NE(reused[1], nullptr);
    EXPECT_EQ(reused[0]->value, 0);
    EXPECT_EQ(reused[1]->value, 0);

    EXPECT_EQ(cache.put_bulk(std::span<CachedObject *const>(reused)), 2u);
    EXPECT_TRUE(cache.put(objects[2]));
    EXPECT_EQ(cache.available(), 3u);
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

TEST(QuicBufferTest, DatagramBufferRejectsSameSizeDifferentByteVector) {
    const std::vector<std::byte> expected{
        std::byte{0xaa},
        std::byte{0xbb},
        std::byte{0xcc},
    };
    const std::vector<std::byte> different{
        std::byte{0xaa},
        std::byte{0xbc},
        std::byte{0xcc},
    };

    const coquic::quic::DatagramBuffer buffer(expected);

    EXPECT_FALSE(buffer == different);
    EXPECT_FALSE(different == buffer);
}

TEST(QuicBufferTest, DatagramBufferRejectsDifferentSizeByteVector) {
    const std::vector<std::byte> expected{
        std::byte{0xaa},
        std::byte{0xbb},
        std::byte{0xcc},
    };
    const std::vector<std::byte> truncated{
        std::byte{0xaa},
        std::byte{0xbb},
    };

    const coquic::quic::DatagramBuffer buffer(expected);

    EXPECT_FALSE(buffer == truncated);
    EXPECT_FALSE(truncated == buffer);
}

} // namespace
