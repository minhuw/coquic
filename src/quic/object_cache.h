#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <type_traits>
#include <utility>

#if defined(__clang__)
#define COQUIC_OBJECT_CACHE_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_OBJECT_CACHE_NO_PROFILE
#endif

namespace coquic::quic::detail {

COQUIC_OBJECT_CACHE_NO_PROFILE inline std::size_t
round_up_to_cache_bucket(std::size_t bytes, std::size_t bucket_bytes) noexcept {
    return ((bytes + bucket_bytes - 1) / bucket_bytes) * bucket_bytes;
}

COQUIC_OBJECT_CACHE_NO_PROFILE inline void *allocate_aligned_cache_storage(std::size_t bytes,
                                                                           std::size_t alignment) {
    if (alignment > __STDCPP_DEFAULT_NEW_ALIGNMENT__) {
        return ::operator new(bytes, std::align_val_t{alignment});
    }
    return ::operator new(bytes);
}

COQUIC_OBJECT_CACHE_NO_PROFILE inline void
deallocate_aligned_cache_storage(void *pointer, std::size_t alignment) noexcept {
    if (alignment > __STDCPP_DEFAULT_NEW_ALIGNMENT__) {
        ::operator delete(pointer, std::align_val_t{alignment});
        return;
    }
    ::operator delete(pointer);
}

template <std::size_t SlotCount> class FixedByteBlockCache {
  public:
    FixedByteBlockCache() = default;

    FixedByteBlockCache(const FixedByteBlockCache &) = delete;
    FixedByteBlockCache &operator=(const FixedByteBlockCache &) = delete;

    COQUIC_OBJECT_CACHE_NO_PROFILE FixedByteBlockCache(FixedByteBlockCache &&other) noexcept {
        move_from(other);
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE FixedByteBlockCache &
    operator=(FixedByteBlockCache &&other) noexcept {
        if (this == &other) {
            return *this;
        }
        clear();
        move_from(other);
        return *this;
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE ~FixedByteBlockCache() {
        clear();
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE std::byte *take(std::size_t count) noexcept {
        for (std::size_t index = 0; index < used_; ++index) {
            if (entries_[index].count != count) {
                continue;
            }

            auto *pointer = entries_[index].pointer;
            remove_at(index);
            return pointer;
        }
        return nullptr;
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE bool put(std::byte *pointer, std::size_t count) noexcept {
        if (pointer == nullptr || used_ == entries_.size()) {
            return false;
        }

        entries_[used_] = Entry{
            .pointer = pointer,
            .count = count,
        };
        ++used_;
        return true;
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE void clear() noexcept {
        for (std::size_t index = 0; index < used_; ++index) {
            auto &entry = entries_[index];
            if (entry.pointer != nullptr) {
                std::allocator<std::byte>{}.deallocate(entry.pointer, entry.count);
            }
            entry = Entry{};
        }
        used_ = 0;
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE std::size_t size() const noexcept {
        return used_;
    }

    [[nodiscard]] static constexpr std::size_t capacity() noexcept {
        return SlotCount;
    }

  private:
    struct Entry {
        std::byte *pointer = nullptr;
        std::size_t count = 0;
    };

    COQUIC_OBJECT_CACHE_NO_PROFILE void remove_at(std::size_t index) noexcept {
        --used_;
        entries_[index] = entries_[used_];
        entries_[used_] = Entry{};
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE void move_from(FixedByteBlockCache &other) noexcept {
        for (std::size_t index = 0; index < other.used_; ++index) {
            entries_[index] = other.entries_[index];
            other.entries_[index] = Entry{};
        }
        used_ = other.used_;
        other.used_ = 0;
    }

    std::array<Entry, SlotCount> entries_{};
    std::size_t used_ = 0;
};

template <std::size_t SlotCount> class FixedAlignedBlockCache {
  public:
    FixedAlignedBlockCache() = default;

    FixedAlignedBlockCache(const FixedAlignedBlockCache &) = delete;
    FixedAlignedBlockCache &operator=(const FixedAlignedBlockCache &) = delete;

    COQUIC_OBJECT_CACHE_NO_PROFILE FixedAlignedBlockCache(FixedAlignedBlockCache &&other) noexcept {
        move_from(other);
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE FixedAlignedBlockCache &
    operator=(FixedAlignedBlockCache &&other) noexcept {
        if (this == &other) {
            return *this;
        }
        clear();
        move_from(other);
        return *this;
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE ~FixedAlignedBlockCache() {
        clear();
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE void *take(std::size_t bytes,
                                                            std::size_t alignment) noexcept {
        for (std::size_t index = 0; index < used_; ++index) {
            if (entries_[index].bytes != bytes || entries_[index].alignment != alignment) {
                continue;
            }

            auto *pointer = entries_[index].pointer;
            remove_at(index);
            return pointer;
        }
        return nullptr;
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE bool put(void *pointer, std::size_t bytes,
                                            std::size_t alignment) noexcept {
        if (pointer == nullptr || used_ == entries_.size()) {
            return false;
        }

        entries_[used_] = Entry{
            .pointer = pointer,
            .bytes = bytes,
            .alignment = alignment,
        };
        ++used_;
        return true;
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE void clear() noexcept {
        for (std::size_t index = 0; index < used_; ++index) {
            auto &entry = entries_[index];
            if (entry.pointer != nullptr) {
                deallocate_aligned_cache_storage(entry.pointer, entry.alignment);
            }
            entry = Entry{};
        }
        used_ = 0;
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE std::size_t size() const noexcept {
        return used_;
    }

    [[nodiscard]] static constexpr std::size_t capacity() noexcept {
        return SlotCount;
    }

  private:
    struct Entry {
        void *pointer = nullptr;
        std::size_t bytes = 0;
        std::size_t alignment = 0;
    };

    COQUIC_OBJECT_CACHE_NO_PROFILE void remove_at(std::size_t index) noexcept {
        --used_;
        entries_[index] = entries_[used_];
        entries_[used_] = Entry{};
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE void move_from(FixedAlignedBlockCache &other) noexcept {
        for (std::size_t index = 0; index < other.used_; ++index) {
            entries_[index] = other.entries_[index];
            other.entries_[index] = Entry{};
        }
        used_ = other.used_;
        other.used_ = 0;
    }

    std::array<Entry, SlotCount> entries_{};
    std::size_t used_ = 0;
};

template <typename T, std::size_t SlotCount> class FixedObjectCache {
    static_assert(SlotCount > 0);
    static_assert(std::is_default_constructible_v<T>);

  public:
    COQUIC_OBJECT_CACHE_NO_PROFILE
    FixedObjectCache() noexcept(std::is_nothrow_default_constructible_v<T>) {
        for (std::size_t index = 0; index < SlotCount; ++index) {
            free_indices_[index] = SlotCount - index - 1;
            in_cache_[index] = true;
        }
    }

    FixedObjectCache(const FixedObjectCache &) = delete;
    FixedObjectCache &operator=(const FixedObjectCache &) = delete;
    FixedObjectCache(FixedObjectCache &&) = delete;
    FixedObjectCache &operator=(FixedObjectCache &&) = delete;

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE T *take() noexcept {
        if (free_count_ == 0) {
            return nullptr;
        }

        const auto index = free_indices_[--free_count_];
        in_cache_[index] = false;
        return &objects_[index];
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE std::size_t
    take_bulk(std::span<T *> output) noexcept {
        const auto count = output.size() < free_count_ ? output.size() : free_count_;
        for (std::size_t index = 0; index < count; ++index) {
            const auto object_index = free_indices_[--free_count_];
            in_cache_[object_index] = false;
            output[index] = &objects_[object_index];
        }
        return count;
    }

    template <typename... Args>
    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE T *take_assign(Args &&...args) {
        if (auto *object = take(); object != nullptr) {
            *object = T(std::forward<Args>(args)...);
            return object;
        }
        return nullptr;
    }

    template <typename Reset> COQUIC_OBJECT_CACHE_NO_PROFILE bool put(T *object, Reset &&reset) {
        const auto index = index_for(object);
        if (index == SlotCount || in_cache_[index]) {
            return false;
        }

        reset(objects_[index]);
        in_cache_[index] = true;
        free_indices_[free_count_++] = index;
        return true;
    }

    template <typename Reset>
    COQUIC_OBJECT_CACHE_NO_PROFILE std::size_t put_bulk(std::span<T *const> objects,
                                                        Reset &&reset) {
        std::size_t returned = 0;
        for (auto *object : objects) {
            if (!put(object, reset)) {
                break;
            }
            ++returned;
        }
        return returned;
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE bool put(T *object) noexcept {
        const auto index = index_for(object);
        if (index == SlotCount || in_cache_[index]) {
            return false;
        }

        in_cache_[index] = true;
        free_indices_[free_count_++] = index;
        return true;
    }

    COQUIC_OBJECT_CACHE_NO_PROFILE std::size_t put_bulk(std::span<T *const> objects) noexcept {
        std::size_t returned = 0;
        for (auto *object : objects) {
            if (!put(object)) {
                break;
            }
            ++returned;
        }
        return returned;
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE bool owns(const T *object) const noexcept {
        if (object == nullptr) {
            return false;
        }

        return index_for(object) != SlotCount;
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE bool cached(const T *object) const noexcept {
        const auto index = index_for(object);
        if (index == SlotCount) {
            return false;
        }
        return in_cache_[index];
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE std::size_t size() const noexcept {
        return free_count_;
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE std::size_t available() const noexcept {
        return free_count_;
    }

    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE std::size_t in_use() const noexcept {
        return SlotCount - free_count_;
    }

    [[nodiscard]] static constexpr std::size_t capacity() noexcept {
        return SlotCount;
    }

  private:
    [[nodiscard]] COQUIC_OBJECT_CACHE_NO_PROFILE std::size_t
    index_for(const T *object) const noexcept {
        if (object == nullptr) {
            return SlotCount;
        }

        const auto begin = reinterpret_cast<std::uintptr_t>(objects_.data());
        const auto end = reinterpret_cast<std::uintptr_t>(objects_.data() + objects_.size());
        const auto pointer = reinterpret_cast<std::uintptr_t>(object);
        if (pointer < begin || pointer >= end) {
            return SlotCount;
        }

        const auto offset = pointer - begin;
        if (offset % sizeof(T) != 0) {
            return SlotCount;
        }
        const auto index = offset / sizeof(T);
        if (index >= SlotCount || &objects_[index] != object) {
            return SlotCount;
        }
        return index;
    }

    std::array<T, SlotCount> objects_{};
    std::array<std::size_t, SlotCount> free_indices_{};
    std::array<bool, SlotCount> in_cache_{};
    std::size_t free_count_ = SlotCount;
};

} // namespace coquic::quic::detail

#undef COQUIC_OBJECT_CACHE_NO_PROFILE
