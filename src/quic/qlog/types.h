#pragma once

#include <string>
#include <vector>

namespace coquic::quic::qlog {

struct FilePreamble {
    std::string title;
    std::string description;
    std::string group_id;
    std::string vantage_point_type;
    std::vector<std::string> event_schemas;
};

} // namespace coquic::quic::qlog
