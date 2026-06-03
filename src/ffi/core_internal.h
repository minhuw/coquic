#pragma once

#include "coquic/core.h"
#include "coquic/ffi/core.h"

#include <utility>

struct coquic_endpoint {
    explicit coquic_endpoint(const coquic::core::EndpointConfig &config) : endpoint(config) {
    }

    coquic::core::Endpoint endpoint;
};

struct coquic_result {
    explicit coquic_result(coquic::core::Result value) : result(std::move(value)) {
    }

    coquic::core::Result result;
};
