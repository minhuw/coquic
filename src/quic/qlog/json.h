#pragma once

#include <string>
#include <string_view>

#include "src/quic/qlog/types.h"

namespace coquic::quic::qlog {

std::string escape_json_string(std::string_view value);
std::string serialize_file_seq_preamble(const FilePreamble &preamble);
std::string make_json_seq_record(std::string_view json_object);

} // namespace coquic::quic::qlog
