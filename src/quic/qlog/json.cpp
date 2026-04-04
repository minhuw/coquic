#include "src/quic/qlog/json.h"

namespace coquic::quic::qlog {

std::string escape_json_string(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const auto ch : value) {
        switch (ch) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out.push_back(ch);
            break;
        }
    }
    return out;
}

std::string serialize_file_seq_preamble(const FilePreamble &preamble) {
    return std::string("{") + "\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"," +
           "\"serialization_format\":\"application/qlog+json-seq\"," + "\"title\":\"" +
           escape_json_string(preamble.title) + "\"," + "\"description\":\"" +
           escape_json_string(preamble.description) + "\"," + "\"trace\":{" +
           "\"common_fields\":{" + "\"group_id\":\"" + escape_json_string(preamble.group_id) +
           "\"," + "\"time_format\":\"relative_to_epoch\"," +
           "\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}" + "}," +
           "\"vantage_point\":{\"type\":\"" + escape_json_string(preamble.vantage_point_type) +
           "\"}," + "\"event_schemas\":[\"" + escape_json_string(preamble.event_schemas.front()) +
           "\"]" + "}" + "}";
}

std::string make_json_seq_record(std::string_view json_object) {
    std::string out;
    out.reserve(json_object.size() + 2);
    out.push_back('\x1e');
    out.append(json_object);
    out.push_back('\n');
    return out;
}

} // namespace coquic::quic::qlog
