#pragma once

#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <memory>
#include <span>
#include <vector>

namespace coquic::quic {

class SharedBytes {
  public:
    using iterator = std::vector<std::byte>::const_iterator;

    SharedBytes() = default;

    SharedBytes(std::initializer_list<std::byte> bytes)
        : SharedBytes(std::vector<std::byte>(bytes)) {
    }

    SharedBytes(std::vector<std::byte> bytes)
        : storage_(std::make_shared<std::vector<std::byte>>(std::move(bytes))), begin_(0),
          end_(storage_->size()) {
    }

    SharedBytes(std::shared_ptr<std::vector<std::byte>> storage, std::size_t begin, std::size_t end)
        : storage_(std::move(storage)), begin_(begin), end_(end) {
    }

    std::size_t size() const {
        return end_ - begin_;
    }

    bool empty() const {
        return size() == 0;
    }

    const std::byte *data() const {
        if (!storage_ || empty()) {
            return nullptr;
        }

        return storage_->data() + static_cast<std::ptrdiff_t>(begin_);
    }

    iterator begin() const {
        if (!storage_) {
            return empty_storage().cbegin();
        }

        return storage_->cbegin() + static_cast<std::ptrdiff_t>(begin_);
    }

    iterator end() const {
        if (!storage_) {
            return empty_storage().cend();
        }

        return storage_->cbegin() + static_cast<std::ptrdiff_t>(end_);
    }

    std::span<const std::byte> span() const {
        if (!storage_ || empty()) {
            return {};
        }

        return std::span<const std::byte>(storage_->data() + static_cast<std::ptrdiff_t>(begin_),
                                          size());
    }

    void resize(std::size_t new_size) {
        end_ = begin_ + std::min(new_size, size());
    }

    // Mirrors std::span::subspan(offset, count).
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    SharedBytes subspan(std::size_t offset, std::size_t count = std::dynamic_extent) const {
        if (offset >= size()) {
            return {};
        }

        const auto available = size() - offset;
        const auto subrange_size =
            count == std::dynamic_extent ? available : std::min(count, available);
        return SharedBytes{
            storage_,
            begin_ + offset,
            begin_ + offset + subrange_size,
        };
    }

    std::vector<std::byte> to_vector() const {
        return std::vector<std::byte>(begin(), end());
    }

    const std::shared_ptr<std::vector<std::byte>> &storage() const {
        return storage_;
    }

    std::size_t begin_offset() const {
        return begin_;
    }

    std::size_t end_offset() const {
        return end_;
    }

    friend bool operator==(const SharedBytes &lhs, const SharedBytes &rhs) {
        return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
    }

    friend bool operator==(const SharedBytes &lhs, std::span<const std::byte> rhs) {
        return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
    }

    friend bool operator==(std::span<const std::byte> lhs, const SharedBytes &rhs) {
        return rhs == lhs;
    }

    friend bool operator==(const SharedBytes &lhs, const std::vector<std::byte> &rhs) {
        return lhs == std::span<const std::byte>(rhs);
    }

    friend bool operator==(const std::vector<std::byte> &lhs, const SharedBytes &rhs) {
        return std::span<const std::byte>(lhs) == rhs;
    }

  private:
    static const std::vector<std::byte> &empty_storage() {
        static const auto *storage = new std::vector<std::byte>();
        return *storage;
    }

    std::shared_ptr<std::vector<std::byte>> storage_;
    std::size_t begin_ = 0;
    std::size_t end_ = 0;
};

} // namespace coquic::quic
