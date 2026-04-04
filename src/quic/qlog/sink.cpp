#include "src/quic/qlog/sink.h"

#include <system_error>
#include <utility>

namespace coquic::quic::qlog {

QlogFileSeqSink::QlogFileSeqSink(std::filesystem::path path) : path_(std::move(path)) {
}

bool QlogFileSeqSink::open() {
    std::error_code error;
    std::filesystem::create_directories(path_.parent_path(), error);
    if (error) {
        healthy_ = false;
        return false;
    }

    output_.open(path_, std::ios::binary | std::ios::out | std::ios::trunc);
    healthy_ = output_.is_open();
    return healthy_;
}

bool QlogFileSeqSink::write_record(std::string_view record) {
    if (!healthy_) {
        return false;
    }

    output_.write(record.data(), static_cast<std::streamsize>(record.size()));
    output_.flush();
    healthy_ = output_.good();
    return healthy_;
}

bool QlogFileSeqSink::healthy() const {
    return healthy_;
}

const std::filesystem::path &QlogFileSeqSink::path() const {
    return path_;
}

} // namespace coquic::quic::qlog
