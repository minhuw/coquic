#include "src/io/io_uring_io_engine.h"

#include "src/io/io_backend_test_hooks.h"
#include "src/io/poll_io_engine.h"

#include <liburing.h>

#include <memory>
#include <utility>

namespace coquic::io {

namespace {

constexpr unsigned kIoUringQueueEntries = 256;

} // namespace

namespace internal {

test::IoUringBackendOpsOverride make_default_io_uring_backend_ops() {
    return test::IoUringBackendOpsOverride{
        .queue_init_fn = ::io_uring_queue_init,
        .queue_exit_fn = ::io_uring_queue_exit,
    };
}

test::IoUringBackendOpsOverride &io_uring_backend_ops_state() {
    static thread_local auto ops = make_default_io_uring_backend_ops();
    return ops;
}

void apply_io_uring_backend_ops_override(const test::IoUringBackendOpsOverride &override_ops) {
    auto &ops = io_uring_backend_ops_state();
    if (override_ops.queue_init_fn != nullptr) {
        ops.queue_init_fn = override_ops.queue_init_fn;
    }
    if (override_ops.queue_exit_fn != nullptr) {
        ops.queue_exit_fn = override_ops.queue_exit_fn;
    }
}

} // namespace internal

struct IoUringIoEngine::Impl {
    std::unique_ptr<QuicIoEngine> fallback_engine = std::make_unique<PollIoEngine>();
    io_uring ring{};
    bool initialized = false;
};

IoUringIoEngine::IoUringIoEngine() : impl_(std::make_unique<Impl>()) {
}

IoUringIoEngine::~IoUringIoEngine() {
    if (impl_ != nullptr && impl_->initialized) {
        internal::io_uring_backend_ops_state().queue_exit_fn(&impl_->ring);
    }
}

std::unique_ptr<IoUringIoEngine> IoUringIoEngine::create() {
    auto engine = std::unique_ptr<IoUringIoEngine>(new IoUringIoEngine());
    if (!engine->initialize()) {
        return nullptr;
    }
    return engine;
}

bool IoUringIoEngine::initialize() {
    if (internal::io_uring_backend_ops_state().queue_init_fn(kIoUringQueueEntries, &impl_->ring,
                                                             0) != 0) {
        return false;
    }
    impl_->initialized = true;
    return true;
}

bool IoUringIoEngine::register_socket(int socket_fd) {
    return impl_->fallback_engine->register_socket(socket_fd);
}

bool IoUringIoEngine::send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
                           std::span<const std::byte> datagram, std::string_view role_name,
                           quic::QuicEcnCodepoint ecn) {
    return impl_->fallback_engine->send(socket_fd, peer, peer_len, datagram, role_name, ecn);
}

std::optional<QuicIoEngineEvent>
IoUringIoEngine::wait(std::span<const int> socket_fds, int idle_timeout_ms,
                      std::optional<quic::QuicCoreTimePoint> next_wakeup,
                      std::string_view role_name) {
    return impl_->fallback_engine->wait(socket_fds, idle_timeout_ms, next_wakeup, role_name);
}

std::unique_ptr<QuicIoEngine> make_io_uring_io_engine() {
    return IoUringIoEngine::create();
}

namespace test {

IoUringBackendOpsOverride &io_uring_backend_ops_for_runtime_tests() {
    return internal::io_uring_backend_ops_state();
}

void io_uring_backend_apply_ops_override_for_runtime_tests(
    const IoUringBackendOpsOverride &override_ops) {
    internal::apply_io_uring_backend_ops_override(override_ops);
}

ScopedIoUringBackendOpsOverride::ScopedIoUringBackendOpsOverride(
    IoUringBackendOpsOverride override_ops)
    : previous_(internal::io_uring_backend_ops_state()) {
    internal::apply_io_uring_backend_ops_override(override_ops);
}

ScopedIoUringBackendOpsOverride::~ScopedIoUringBackendOpsOverride() {
    internal::io_uring_backend_ops_state() = previous_;
}

} // namespace test

} // namespace coquic::io
