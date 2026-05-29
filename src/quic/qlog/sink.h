#pragma once

#include <filesystem>
#if !defined(COQUIC_WASM_NO_FILESYSTEM)
#include <fstream>
#endif
#include <string_view>

namespace coquic::quic::qlog {

class QlogFileSeqSink {
  public:
    explicit QlogFileSeqSink(std::filesystem::path path);

    bool open();
    bool write_record(std::string_view record);
    bool healthy() const;
    const std::filesystem::path &path() const;

  private:
    std::filesystem::path path_;
#if !defined(COQUIC_WASM_NO_FILESYSTEM)
    std::ofstream output_;
#endif
    bool healthy_ = true;
};

} // namespace coquic::quic::qlog
