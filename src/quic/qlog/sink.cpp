#include "src/quic/qlog/sink.h"

#include <system_error>
#include <utility>

namespace coquic::quic::qlog {

QlogFileSeqSink::QlogFileSeqSink(std::filesystem::path path) : path_(std::move(path)) {
}

bool QlogFileSeqSink::open() {
#if defined(COQUIC_WASM_NO_FILESYSTEM)
    healthy_ = false;
    return false;
#else
    std::error_code error;
    std::filesystem::create_directories(path_.parent_path(), error);
    if (error) {
        healthy_ = false;
        return false;
    }

    output_.open(path_, std::ios::binary | std::ios::out | std::ios::trunc);
    healthy_ = output_.is_open();
    return healthy_;
#endif
}

bool QlogFileSeqSink::write_record(std::string_view record) {
#if defined(COQUIC_WASM_NO_FILESYSTEM)
    static_cast<void>(record);
    healthy_ = false;
    return false;
#else
    if (!healthy_) {
        return false;
    }

    output_.write(record.data(), static_cast<std::streamsize>(record.size()));
    output_.flush();
    healthy_ = output_.good();
    return healthy_;
#endif
}

bool QlogFileSeqSink::healthy() const {
    return healthy_;
}

const std::filesystem::path &QlogFileSeqSink::path() const {
    return path_;
}

} // namespace coquic::quic::qlog
