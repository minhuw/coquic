#pragma once

#include <filesystem>
#include <fstream>
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
    std::ofstream output_;
    bool healthy_ = true;
};

} // namespace coquic::quic::qlog
