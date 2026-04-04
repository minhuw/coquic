#include <filesystem>
#include <string>

#include <gtest/gtest.h>

#include "src/quic/qlog/json.h"
#include "src/quic/qlog/sink.h"

namespace {

using coquic::quic::qlog::FilePreamble;
using coquic::quic::qlog::QlogFileSeqSink;

TEST(QuicQlogTest, SerializesSequentialPreambleWithDraftQuicSchema) {
    const auto preamble = coquic::quic::qlog::serialize_file_seq_preamble(FilePreamble{
        .title = "coquic qlog",
        .description = "client trace",
        .group_id = "8394c8f03e515708",
        .vantage_point_type = "client",
        .event_schemas = {"urn:ietf:params:qlog:events:quic-12"},
    });

    EXPECT_NE(preamble.find("\"file_schema\":\"urn:ietf:params:qlog:file:sequential\""),
              std::string::npos);
    EXPECT_NE(preamble.find("\"serialization_format\":\"application/qlog+json-seq\""),
              std::string::npos);
    EXPECT_NE(preamble.find("\"event_schemas\":[\"urn:ietf:params:qlog:events:quic-12\"]"),
              std::string::npos);
    EXPECT_NE(preamble.find("\"group_id\":\"8394c8f03e515708\""), std::string::npos);
    EXPECT_NE(preamble.find("\"type\":\"client\""), std::string::npos);
}

TEST(QuicQlogTest, EscapesJsonStringsAndFramesJsonSeqRecords) {
    EXPECT_EQ(coquic::quic::qlog::escape_json_string("a\"b\\c\n"), "a\\\"b\\\\c\\n");

    const auto record = coquic::quic::qlog::make_json_seq_record("{\"time\":1}");
    ASSERT_FALSE(record.empty());
    EXPECT_EQ(record.front(), '\x1e');
    EXPECT_EQ(record.back(), '\n');
    EXPECT_NE(record.find("{\"time\":1}"), std::string::npos);
}

TEST(QuicQlogTest, SinkDisablesAfterAppendFailure) {
    QlogFileSeqSink sink(std::filesystem::path("/dev/full"));
    ASSERT_TRUE(sink.open());
    EXPECT_FALSE(sink.write_record("\x1e{\"time\":0}\n"));
    EXPECT_FALSE(sink.healthy());
}

} // namespace
