#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/codec/frame.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    constexpr std::size_t kMaxFrameInputSize = 1500;
    if (size > kMaxFrameInputSize) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    const auto span = std::span<const std::byte>(bytes.data(), bytes.size());

    const auto decoded = coquic::quic::deserialize_frame(span);
    if (!decoded.has_value()) {
        coquic::fuzz::require_error_offset(decoded.error(), bytes.size());
    } else {
        coquic::fuzz::require(decoded.value().bytes_consumed <= bytes.size(),
                              "frame decoder over-consumed input");

        const auto encoded = coquic::quic::serialize_frame(decoded.value().frame);
        if (encoded.has_value()) {
            const auto size_result = coquic::quic::serialized_frame_size(decoded.value().frame);
            coquic::fuzz::require(size_result.has_value(),
                                  "serialized_frame_size failed for decoded frame");
            coquic::fuzz::require(size_result.value() == encoded.value().size(),
                                  "serialized_frame_size does not match serialized bytes");

            const auto redecode = coquic::quic::deserialize_frame(encoded.value());
            coquic::fuzz::require(redecode.has_value(), "serialized decoded frame is invalid");
            coquic::fuzz::require(redecode.value().bytes_consumed == encoded.value().size(),
                                  "serialized decoded frame was not fully consumed");
            coquic::fuzz::require(decoded.value().frame.index() == redecode.value().frame.index(),
                                  "frame variant changed after round-trip");
        } else {
            coquic::fuzz::fail("decoded frame failed to serialize");
        }
    }

    auto storage = std::make_shared<std::vector<std::byte>>(bytes.begin(), bytes.end());
    const auto received =
        coquic::quic::deserialize_received_frame(coquic::quic::SharedBytes(storage, 0, size));
    if (!received.has_value()) {
        coquic::fuzz::require_error_offset(received.error(), bytes.size());
    } else {
        coquic::fuzz::require(received.value().bytes_consumed <= bytes.size(),
                              "received frame decoder over-consumed input");
    }

    if (!decoded.has_value() && !received.has_value()) {
        coquic::fuzz::require(decoded.error().offset == received.error().offset,
                              "ordinary and received frame error offsets diverged");
    }

    return 0;
}
