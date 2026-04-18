# Demo HTTP/3 Speed Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the diagnostics demo with a focused HTTP/3 speed test and add dedicated QUIC speed routes to the `h3-server` runtime.

**Architecture:** Extract the demo-owned HTTP/3 routes into a shared helper so the endpoint default routes and the runtime server path stay aligned without duplicating echo, inspect, and new speed-route logic. Keep the public page as one static `demo/site/index.html` file that runs a balanced browser-side sequence over same-origin QUIC routes: ping, download, and upload.

**Tech Stack:** C++20, GoogleTest, existing `src/http3/*` runtime and endpoint code, shell contract tests under `tests/nix/`, single-file HTML/CSS/JavaScript demo page, `nix develop`, `zig build test`, `pre-commit`.

---

## File Map

- Create: `src/http3/http3_demo_routes.h`
  Purpose: shared declarations for demo-owned HTTP/3 routes and route limits.
- Create: `src/http3/http3_demo_routes.cpp`
  Purpose: shared implementation for `/_coquic/echo`, `/_coquic/inspect`, `/_coquic/speed/ping`, `/_coquic/speed/download`, and `/_coquic/speed/upload`.
- Modify: `build.zig`
  Purpose: compile the new shared route source into the library and test binary.
- Modify: `src/http3/http3_server.cpp`
  Purpose: replace the current duplicated default demo-route logic with the shared helper and keep the default upload route bounded before full buffering.
- Modify: `src/http3/http3_server.h`
  Purpose: expose the fallback server-handler hook needed for the standalone runtime to preserve bounded demo-route behavior.
- Modify: `src/http3/http3_runtime.cpp`
  Purpose: call the shared helper before static-file fallback in the standalone `h3-server` runtime.
- Modify: `tests/http3/server_test.cpp`
  Purpose: add protocol-level route tests for the new speed endpoints and limit handling.
- Modify: `tests/http3/runtime_test.cpp`
  Purpose: add loopback integration coverage for the speed routes through real runtime server/client execution.
- Modify: `demo/site/index.html`
  Purpose: replace the diagnostics UI with the focused speed-test page.
- Modify: `tests/nix/demo_package_contract_test.sh`
  Purpose: assert the new page contract and verify the old diagnostics copy is gone.

### Task 1: Extract shared demo routes and add protocol-level speed route tests

**Files:**
- Create: `src/http3/http3_demo_routes.h`
- Create: `src/http3/http3_demo_routes.cpp`
- Modify: `build.zig`
- Modify: `src/http3/http3_server.cpp`
- Modify: `tests/http3/server_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*Speed*'`

- [ ] **Step 1: Write the failing server tests**

Add these tests to `tests/http3/server_test.cpp`:

```cpp
TEST(QuicHttp3ServerTest, DefaultSpeedPingRouteReturnsNoContent) {}

TEST(QuicHttp3ServerTest, DefaultSpeedDownloadRouteReturnsSizedPayload) {}

TEST(QuicHttp3ServerTest, DefaultSpeedUploadRouteReturnsReceivedByteSummary) {}

TEST(QuicHttp3ServerTest, DefaultSpeedDownloadRouteRejectsMissingBytesQuery) {}

TEST(QuicHttp3ServerTest, DefaultSpeedDownloadRouteRejectsOversizedBytesQuery) {}

TEST(QuicHttp3ServerTest, DefaultSpeedDownloadRouteRejectsMalformedBytesQuery) {}

TEST(QuicHttp3ServerTest, DefaultSpeedUploadRouteRejectsNonPostMethod) {}

TEST(QuicHttp3ServerTest, DefaultSpeedUploadRouteRejectsOversizedBodyBeforeRequestComplete) {}
```

Make the assertions exact:

```cpp
const std::array response_headers{
    coquic::http3::Http3Field{"cache-control", "no-store"},
};
const auto expected_headers = headers_frame_bytes(
    0, response_fields(204, response_headers, 0u));
```

```cpp
const std::array response_headers{
    coquic::http3::Http3Field{"content-type", "application/octet-stream"},
    coquic::http3::Http3Field{"cache-control", "no-store"},
};
const auto expected_headers = headers_frame_bytes(
    0, response_fields(200, response_headers, 16u));
```

Use the download success case to cover the cache-busting query shape the page will send:

```cpp
coquic::http3::Http3Field{":path", "/_coquic/speed/download?bytes=16&ts=1712345678"},
```

```cpp
const std::string json = "{\"received_bytes\":4}";
const std::array response_headers{
    coquic::http3::Http3Field{"content-type", "application/json"},
    coquic::http3::Http3Field{"cache-control", "no-store"},
};
```

Use the existing test helpers already in the file:
- `prime_server_transport(endpoint);`
- `receive_result(...)`
- `headers_frame_bytes(...)`
- `data_frame_bytes(...)`
- `response_fields(...)`
- `send_stream_inputs_from(...)`

- [ ] **Step 2: Run the focused suite to verify RED**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*Speed*'`

Expected: FAIL because the speed routes do not exist yet and the new tests either receive `404`, `405`, or mismatched headers/body.

- [ ] **Step 3: Define the shared demo route API**

Create `src/http3/http3_demo_routes.h` with:

```cpp
#pragma once

#include "src/http3/http3.h"

#include <cstddef>
#include <optional>

namespace coquic::http3 {

struct Http3DemoRouteLimits {
    std::size_t max_speed_download_bytes = 4 * 1024 * 1024;
    std::size_t max_speed_upload_bytes = 4 * 1024 * 1024;
};

std::optional<Http3Response> try_demo_route_response(
    const Http3Request &request,
    const Http3DemoRouteLimits &limits = {});

} // namespace coquic::http3
```

Update `build.zig` in the source list to compile the new helper:

```zig
        "src/http3/http3_demo_routes.cpp",
```

- [ ] **Step 4: Implement the shared route helper**

In `src/http3/http3_demo_routes.cpp`, implement:

```cpp
namespace {

constexpr std::string_view kNoStoreValue = "no-store";

std::string request_path_without_query(std::string_view path) {
    const auto query = path.find('?');
    return std::string(query == std::string_view::npos ? path : path.substr(0, query));
}

std::optional<std::size_t> parse_bytes_query(std::string_view path) {
    const auto query = path.find('?');
    if (query == std::string_view::npos) {
        return std::nullopt;
    }
    constexpr auto expected = std::string_view{"bytes="};
    const auto tail = path.substr(query + 1);

    std::optional<std::size_t> parsed_bytes;
    std::size_t param_begin = 0;
    while (param_begin <= tail.size()) {
        const auto param_end = tail.find('&', param_begin);
        const auto param =
            tail.substr(param_begin, param_end == std::string_view::npos ? std::string_view::npos
                                                                         : param_end - param_begin);
        if (param.starts_with(expected)) {
            if (parsed_bytes.has_value()) {
                return std::nullopt;
            }

            std::size_t parsed = 0;
            const auto value = param.substr(expected.size());
            const auto *begin = value.data();
            const auto *end = value.data() + value.size();
            const auto result = std::from_chars(begin, end, parsed);
            if (result.ec != std::errc{} || result.ptr != end || parsed == 0) {
                return std::nullopt;
            }
            parsed_bytes = parsed;
        }

        if (param_end == std::string_view::npos) {
            break;
        }
        param_begin = param_end + 1;
    }

    return parsed_bytes;
}

std::vector<std::byte> make_demo_download_payload(std::size_t bytes) {
    std::vector<std::byte> payload(bytes);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>('A' + (index % 23));
    }
    return payload;
}

std::vector<std::byte> upload_summary_json(std::size_t received_bytes) {
    const auto json = std::string("{\"received_bytes\":") + std::to_string(received_bytes) + "}";
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte *>(json.data()),
        reinterpret_cast<const std::byte *>(json.data()) + json.size());
}

} // namespace
```

Implement `try_demo_route_response(...)` so it preserves the existing echo and inspect behavior and adds:

```cpp
if (path == "/_coquic/speed/ping") {
    if (request.head.method != "GET" && request.head.method != "HEAD") {
        return Http3Response{
            .head = {
                .status = 405,
                .content_length = 0,
                .headers = {{"allow", "GET, HEAD"}},
            },
        };
    }
    return Http3Response{
        .head = {
            .status = 204,
            .content_length = 0,
            .headers = {{"cache-control", "no-store"}},
        },
    };
}
```

```cpp
if (path == "/_coquic/speed/download") {
    if (request.head.method != "GET" && request.head.method != "HEAD") {
        return Http3Response{
            .head = {
                .status = 405,
                .content_length = 0,
                .headers = {{"allow", "GET, HEAD"}},
            },
        };
    }
    const auto bytes = parse_bytes_query(request.head.path);
    if (!bytes.has_value() || *bytes > limits.max_speed_download_bytes) {
        return Http3Response{
            .head = {
                .status = 400,
                .content_length = 0,
                .headers = {{"cache-control", "no-store"}},
            },
        };
    }
    auto body = make_demo_download_payload(*bytes);
    return Http3Response{
        .head = {
            .status = 200,
            .content_length = static_cast<std::uint64_t>(body.size()),
            .headers = {
                {"content-type", "application/octet-stream"},
                {"cache-control", "no-store"},
            },
        },
        .body = std::move(body),
    };
}
```

```cpp
if (path == "/_coquic/speed/upload") {
    if (request.head.method != "POST") {
        return Http3Response{
            .head = {
                .status = 405,
                .content_length = 0,
                .headers = {{"allow", "POST"}},
            },
        };
    }
    if (request.body.size() > limits.max_speed_upload_bytes) {
        return Http3Response{
            .head = {
                .status = 400,
                .content_length = 0,
                .headers = {{"cache-control", "no-store"}},
            },
        };
    }
    auto body = upload_summary_json(request.body.size());
    return Http3Response{
        .head = {
            .status = 200,
            .content_length = static_cast<std::uint64_t>(body.size()),
            .headers = {
                {"content-type", "application/json"},
                {"cache-control", "no-store"},
            },
        },
        .body = std::move(body),
    };
}
```

Return `std::nullopt` only for non-demo paths.

- [ ] **Step 5: Wire the endpoint default routes to the shared helper**

Replace the current hand-written demo-route branches in `src/http3/http3_server.cpp` with:

```cpp
#include "src/http3/http3_demo_routes.h"
```

```cpp
Http3Response default_route_response(const Http3Request &request) {
    if (const auto response = try_demo_route_response(request); response.has_value()) {
        return *response;
    }

    return Http3Response{
        .head = {
            .status = 404,
            .content_length = 0,
        },
    };
}
```

Also keep the default upload route bounded before full buffering when no custom request handler is
installed:

- use the existing early-response path for `/_coquic/speed/upload`
- return `400` with `cache-control: no-store` when `content-length` already exceeds the limit
- return the same `400` response if streamed body growth crosses the limit before request
  completion
- continue to preserve the existing `404` fallback for non-demo routes

- [ ] **Step 6: Re-run the focused server suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*Speed*'`

Expected: PASS.

- [ ] **Step 7: Commit the shared route slice**

Run:

```bash
git add build.zig src/http3/http3_demo_routes.h src/http3/http3_demo_routes.cpp \
  src/http3/http3_server.cpp tests/http3/server_test.cpp
git commit -m "feat: add shared demo speed routes"
```

Expected: commit succeeds with only the shared route helper and protocol-level tests staged.

### Task 2: Wire the shared routes into the runtime and add loopback coverage

**Files:**
- Modify: `src/http3/http3_server.h`
- Modify: `src/http3/http3_server.cpp`
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `tests/http3/server_test.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Test: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.Speed*'`

- [ ] **Step 1: Write the failing loopback runtime tests**

Add these tests to `tests/http3/runtime_test.cpp`:

```cpp
TEST(QuicHttp3RuntimeTest, SpeedPingRouteReturnsNoBodyOverLoopback) {}

TEST(QuicHttp3RuntimeTest, SpeedDownloadRouteWritesSizedBodyOverLoopback) {}

TEST(QuicHttp3RuntimeTest, SpeedUploadRouteReturnsReceivedByteSummaryOverLoopback) {}
```

Add one focused endpoint regression test in `tests/http3/server_test.cpp` that proves the new
fallback handler still preserves the default speed-upload early rejection path when
`content-length` already exceeds the upload cap.

Use the existing server process fixture pattern:

```cpp
const auto server = coquic::http3::Http3RuntimeConfig{
    .mode = coquic::http3::Http3RuntimeMode::server,
    .host = "127.0.0.1",
    .port = port,
    .document_root = document_root.path(),
    .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
    .private_key_path = "tests/fixtures/quic-server-key.pem",
};

ScopedHttp3Process server_process(server);
```

The exact runtime assertions should be:

```cpp
ScopedStdoutCapture capture;
EXPECT_EQ(coquic::http3::run_http3_runtime(client), 0);
EXPECT_EQ(capture.finish_and_read(), "");
```

```cpp
EXPECT_EQ(std::filesystem::file_size(output_root.path() / "download.bin"), 131072u);
```

```cpp
EXPECT_EQ(
    coquic::quic::test::read_text_file(output_root.path() / "upload.json"),
    "{\"received_bytes\":4096}");
```

- [ ] **Step 2: Run the focused runtime suite to verify RED**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.Speed*'`

Expected: FAIL because `runtime_server_response(...)` still only knows about the old inspect/echo routes and static files.

Also run the focused endpoint regression you added for the fallback-handler path and verify it is
RED before the server/runtime plumbing change.

- [ ] **Step 3: Replace the runtime-owned duplicated route branches with the shared helper**

In `src/http3/http3_runtime.cpp`:

```cpp
#include "src/http3/http3_demo_routes.h"
```

At the start of `runtime_server_response(...)`, replace the hard-coded inspect/echo branches with:

```cpp
if (const auto demo_route = try_demo_route_response(request); demo_route.has_value()) {
    return *demo_route;
}
```

Delete the now-duplicated echo/inspect branches from this function, leaving only:
- the shared demo-route dispatch
- the existing GET/HEAD static file fallback
- the existing path resolution and content-type logic

Keep the standalone runtime on the bounded default demo-route path instead of bypassing it with a
custom request handler:

- extend `Http3ServerConfig` in `src/http3/http3_server.h` with a fallback request handler that is
  used only when no shared demo route matches
- update `src/http3/http3_server.cpp` so the default demo-route handling still runs first, and only
  then delegates non-demo requests to the optional fallback handler before returning `404`
- wire the standalone runtime to use that fallback for static-file serving so the existing default
  speed-upload early rejection remains active for `/_coquic/speed/upload`

- [ ] **Step 4: Re-run the focused runtime suite**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3RuntimeTest.Speed*'`

Expected: PASS.

- [ ] **Step 5: Commit the runtime integration slice**

Run:

```bash
git add src/http3/http3_runtime.cpp tests/http3/runtime_test.cpp
git commit -m "feat: expose demo speed routes in h3 runtime"
```

Expected: commit succeeds with only the runtime wire-up and loopback coverage staged.

### Task 3: Replace the diagnostics page with the focused speed-test UI

**Files:**
- Modify: `demo/site/index.html`
- Modify: `tests/nix/demo_package_contract_test.sh`
- Test: `bash tests/nix/demo_package_contract_test.sh`

- [ ] **Step 1: Write the failing page contract update**

In `tests/nix/demo_package_contract_test.sh`, replace the old positive marker list:

```bash
for marker in \
  "coquic-demo-v1" \
  "https://coquic.minhuw.dev/" \
  "/_coquic/inspect" \
  "/_coquic/echo" \
  "localStorage" \
  "window.location" \
  "How To Verify In Chrome" \
  "safeStorageGet" \
  "safeStorageSet" \
  "safeReadJson" \
  "runProbe"; do
```

with the new focused speed-test marker list:

```bash
for marker in \
  "coquic-demo-v1" \
  "coquic HTTP/3 speed test" \
  "Start test" \
  "Latency" \
  "Download" \
  "Upload" \
  "Connecting" \
  "/_coquic/speed/ping" \
  "/_coquic/speed/download" \
  "/_coquic/speed/upload" \
  "AbortController" \
  "withTimeout" \
  "runSpeedTest" \
  "runLatencyPhase" \
  "runDownloadPhase" \
  "runUploadPhase"; do
```

Add explicit negative checks so the diagnostics copy stays gone:

```bash
for removed_marker in \
  "Run Live Checks" \
  "How To Verify In Chrome" \
  "/_coquic/inspect" \
  "/_coquic/echo" \
  "safeStorageGet" \
  "safeStorageSet" \
  "safeReadJson" \
  "runProbe" \
  "fonts.googleapis.com" \
  "fonts.gstatic.com"; do
  if grep -Fq -- "${removed_marker}" "${output_dir}/index.html"; then
    echo "packaged demo page still contains removed marker: ${removed_marker}" >&2
    exit 1
  fi
done
```

- [ ] **Step 2: Run the package contract test to verify RED**

Run: `bash tests/nix/demo_package_contract_test.sh`

Expected: FAIL because `demo/site/index.html` still contains the diagnostics UI and does not contain the new speed-test markers.

- [ ] **Step 3: Replace the page HTML and CSS**

In `demo/site/index.html`, keep the stable page marker and replace the current hero, toggles, cards, and copy with a single-column structure like:

```html
<main class="shell">
  <section class="hero">
    <p class="eyebrow">HTTP/3 demo</p>
    <h1>coquic HTTP/3 speed test</h1>
    <p class="lede">
      Measure browser-observable QUIC latency, download, and upload against
      <strong>coquic.minhuw.dev</strong>.
    </p>
    <button id="startTest" type="button">Start test</button>
  </section>

  <section class="progress-card" aria-live="polite">
    <div class="phase-row">
      <span id="phaseLabel">Idle</span>
      <span id="phaseDetail">Ready to test</span>
    </div>
    <div class="progress-track" aria-hidden="true">
      <div id="progressBar" class="progress-bar"></div>
    </div>
  </section>

  <section class="results-grid">
    <article class="metric-card">
      <h2>Latency</h2>
      <p id="latencyValue" class="metric-value">Not run</p>
      <p id="latencyMeta" class="metric-meta">Median of 7 samples</p>
    </article>
    <article class="metric-card">
      <h2>Download</h2>
      <p id="downloadValue" class="metric-value">Not run</p>
      <p id="downloadMeta" class="metric-meta">4 workers · 4.5s window</p>
    </article>
    <article class="metric-card">
      <h2>Upload</h2>
      <p id="uploadValue" class="metric-value">Not run</p>
      <p id="uploadMeta" class="metric-meta">4 workers · 4.5s window</p>
    </article>
  </section>

  <section class="summary-card">
    <h2>Summary</h2>
    <dl class="summary-grid">
      <dt>Host</dt><dd id="summaryHost">coquic.minhuw.dev</dd>
      <dt>Time</dt><dd id="summaryTime">Not run</dd>
      <dt>Run state</dt><dd id="summaryState">Idle</dd>
      <dt>Configuration</dt><dd id="summaryConfig">7 pings · 4x4.5s throughput</dd>
    </dl>
  </section>
</main>
```

Use a restrained light theme in the existing `<style>` block:

```css
:root {
  --bg: #f4f7fb;
  --panel: #ffffff;
  --ink: #102033;
  --muted: #5b6b7e;
  --line: #d7e0ea;
  --accent: #1677ff;
  --accent-strong: #0f5ecc;
  --good: #0d8a5f;
  --bad: #c43d34;
}

.results-grid {
  display: grid;
  gap: 1rem;
}

@media (min-width: 860px) {
  .results-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}
```

Keep the page self-contained: do not introduce third-party font or asset fetches for the demo UI.

- [ ] **Step 4: Replace the page JavaScript with the balanced speed-test flow**

Replace the current diagnostics script with a single run orchestrator:

```html
<script>
  const SPEED_CONFIG = {
    latencySamples: 7,
    downloadWorkers: 4,
    uploadWorkers: 4,
    throughputWindowMs: 4500,
    downloadRequestBytes: 262144,
    uploadRequestBytes: 131072,
  };

  async function runLatencyPhase() {
    const samples = [];
    for (let index = 0; index < SPEED_CONFIG.latencySamples; index += 1) {
      const started = performance.now();
      const response = await fetch("/_coquic/speed/ping?ts=" + Date.now() + "-" + index, {
        cache: "no-store",
      });
      if (!response.ok && response.status !== 204) {
        throw new Error("Latency test failed");
      }
      samples.push(performance.now() - started);
    }
    samples.sort((lhs, rhs) => lhs - rhs);
    return {
      valueMs: samples[Math.floor(samples.length / 2)],
      samples,
    };
  }

  async function runDownloadPhase() {
    return runTimedWorkers(SPEED_CONFIG.downloadWorkers, async function () {
      const response = await fetch(
        "/_coquic/speed/download?bytes=" + SPEED_CONFIG.downloadRequestBytes + "&ts=" + Date.now(),
        { cache: "no-store" }
      );
      if (!response.ok || !response.body) {
        throw new Error("Download test failed");
      }
      const reader = response.body.getReader();
      let total = 0;
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) {
          break;
        }
        total += chunk.value.byteLength;
      }
      return total;
    });
  }

  async function runUploadPhase() {
    const payload = new Uint8Array(SPEED_CONFIG.uploadRequestBytes);
    payload.fill(117);
    return runTimedWorkers(SPEED_CONFIG.uploadWorkers, async function () {
      const response = await fetch("/_coquic/speed/upload?ts=" + Date.now(), {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: payload,
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error("Upload test failed");
      }
      const json = await response.json();
      if (json.received_bytes !== payload.byteLength) {
        throw new Error("Upload byte count mismatch");
      }
      return payload.byteLength;
    });
  }
```

Complete the script with:

```html
  const ui = {
    startTest: document.getElementById("startTest"),
    phaseLabel: document.getElementById("phaseLabel"),
    phaseDetail: document.getElementById("phaseDetail"),
    progressBar: document.getElementById("progressBar"),
    latencyValue: document.getElementById("latencyValue"),
    latencyMeta: document.getElementById("latencyMeta"),
    downloadValue: document.getElementById("downloadValue"),
    downloadMeta: document.getElementById("downloadMeta"),
    uploadValue: document.getElementById("uploadValue"),
    uploadMeta: document.getElementById("uploadMeta"),
    summaryHost: document.getElementById("summaryHost"),
    summaryTime: document.getElementById("summaryTime"),
    summaryState: document.getElementById("summaryState"),
    summaryConfig: document.getElementById("summaryConfig"),
  };

  function formatLatency(valueMs) {
    return valueMs.toFixed(1) + " ms";
  }

  function formatMbps(value) {
    return value.toFixed(2) + " Mbps";
  }

  function setPhase(label, detail, percent) {
    ui.phaseLabel.textContent = label;
    ui.phaseDetail.textContent = detail;
    ui.progressBar.style.width = percent + "%";
  }

  function resetRun() {
    ui.latencyValue.textContent = "Not run";
    ui.downloadValue.textContent = "Not run";
    ui.uploadValue.textContent = "Not run";
    ui.summaryTime.textContent = "In progress";
    ui.summaryState.textContent = "Running";
    ui.summaryConfig.textContent = "7 pings · 4x4.5s throughput";
    setPhase("Connecting", "Preparing same-origin HTTP/3 checks", 8);
  }

  function renderLatency(result) {
    ui.latencyValue.textContent = formatLatency(result.valueMs);
    ui.latencyMeta.textContent = "Median of " + result.samples.length + " samples";
  }

  function renderDownload(result) {
    ui.downloadValue.textContent = formatMbps(result.mbps);
    ui.downloadMeta.textContent =
      result.totalBytes + " bytes in " + result.elapsedMs.toFixed(0) + " ms";
  }

  function renderUpload(result) {
    ui.uploadValue.textContent = formatMbps(result.mbps);
    ui.uploadMeta.textContent =
      result.totalBytes + " bytes in " + result.elapsedMs.toFixed(0) + " ms";
  }

  function renderSummary(state) {
    ui.summaryHost.textContent = window.location.host;
    ui.summaryTime.textContent = new Date().toISOString();
    ui.summaryState.textContent = state;
    ui.summaryConfig.textContent =
      "7 pings · 4 download workers/4.5s · 4 upload workers/4.5s";
  }

  function renderFailure(error) {
    const message = error instanceof Error ? error.message : String(error);
    ui.summaryState.textContent = "Failed";
    ui.phaseLabel.textContent = "Failed";
    ui.phaseDetail.textContent = message;
    ui.progressBar.style.width = "100%";
  }

  function toMbps(bytes, elapsedMs) {
    return (bytes * 8) / (elapsedMs / 1000) / 1000 / 1000;
  }

  async function runTimedWorkers(workerCount, worker) {
    const deadline = performance.now() + SPEED_CONFIG.throughputWindowMs;
    const started = performance.now();
    const results = await Promise.all(
      Array.from({ length: workerCount }, async function () {
        let totalBytes = 0;
        while (performance.now() < deadline) {
          totalBytes += await worker();
        }
        return totalBytes;
      })
    );
    const elapsedMs = performance.now() - started;
    return {
      totalBytes: results.reduce((sum, value) => sum + value, 0),
      elapsedMs,
      mbps: toMbps(results.reduce((sum, value) => sum + value, 0), elapsedMs),
    };
  }

  async function runSpeedTest() {
    setPhase("Connecting", "Preparing same-origin HTTP/3 checks", 8);
    try {
      setPhase("Latency", "Measuring median round-trip time", 28);
      const latency = await runLatencyPhase();
      renderLatency(latency);

      setPhase("Download", "Measuring aggregate download throughput", 58);
      const download = await runDownloadPhase();
      renderDownload(download);

      setPhase("Upload", "Measuring aggregate upload throughput", 84);
      const upload = await runUploadPhase();
      renderUpload(upload);

      setPhase("Complete", "Run finished", 100);
      renderSummary("Complete");
    } catch (error) {
      renderFailure(error);
    } finally {
      ui.startTest.disabled = false;
      ui.startTest.textContent = "Run again";
    }
  }

  document.getElementById("startTest").addEventListener("click", function () {
    ui.startTest.disabled = true;
    ui.startTest.textContent = "Running…";
    resetRun();
    void runSpeedTest();
  });

  resetRun();
</script>
```

Add per-request abort handling with `AbortController` so stalled latency, download, and upload
requests fail explicitly instead of leaving the button stuck in the running state. Timeout/abort
errors should flow through the existing failure rendering so the run always terminates cleanly and
restores the retry button. Keep the timeout active for the full request/response work unit, not
just until response headers arrive.

Keep the stable deployment marker unchanged:

```html
<meta name="coquic-demo-marker" content="coquic-demo-v1">
```

- [ ] **Step 5: Re-run the package contract test**

Run: `bash tests/nix/demo_package_contract_test.sh`

Expected: PASS.

- [ ] **Step 6: Commit the demo page slice**

Run:

```bash
git add demo/site/index.html tests/nix/demo_package_contract_test.sh
git commit -m "feat: replace diagnostics demo with speed test page"
```

Expected: commit succeeds with only the page rewrite and page contract update staged.

### Task 4: Run the full verification set and finalize

**Files:**
- Modify: `build.zig`
- Modify: `src/http3/http3_demo_routes.h`
- Modify: `src/http3/http3_demo_routes.cpp`
- Modify: `src/http3/http3_server.cpp`
- Modify: `src/http3/http3_runtime.cpp`
- Modify: `tests/http3/server_test.cpp`
- Modify: `tests/http3/runtime_test.cpp`
- Modify: `demo/site/index.html`
- Modify: `tests/nix/demo_package_contract_test.sh`

- [ ] **Step 1: Run the focused C++ route suites together**

Run: `nix develop -c zig build test -- --gtest_filter='QuicHttp3ServerTest.*Speed*:QuicHttp3RuntimeTest.Speed*'`

Expected: PASS.

- [ ] **Step 2: Run the demo shell contract tests**

Run:

```bash
bash tests/nix/demo_package_contract_test.sh
bash tests/nix/demo_layout_contract_test.sh
bash tests/nix/demo_remote_deploy_contract_test.sh
```

Expected: all three scripts print their `looks correct` success lines and exit `0`.

- [ ] **Step 3: Run the full project test suite**

Run: `nix develop -c zig build test`

Expected: PASS.

- [ ] **Step 4: Run formatting on the touched C++ files**

Run:

```bash
nix develop -c pre-commit run clang-format --files \
  src/http3/http3_demo_routes.h \
  src/http3/http3_demo_routes.cpp \
  src/http3/http3_server.cpp \
  src/http3/http3_runtime.cpp \
  tests/http3/server_test.cpp \
  tests/http3/runtime_test.cpp
```

Expected: PASS.

- [ ] **Step 5: Run clang-tidy on the touched C++ files**

Run:

```bash
nix develop -c pre-commit run coquic-clang-tidy --files \
  src/http3/http3_demo_routes.h \
  src/http3/http3_demo_routes.cpp \
  src/http3/http3_server.cpp \
  src/http3/http3_runtime.cpp \
  tests/http3/server_test.cpp \
  tests/http3/runtime_test.cpp
```

Expected: PASS.

- [ ] **Step 6: Create the final implementation commit**

Run:

```bash
git add build.zig \
  src/http3/http3_demo_routes.h src/http3/http3_demo_routes.cpp \
  src/http3/http3_server.cpp src/http3/http3_runtime.cpp \
  tests/http3/server_test.cpp tests/http3/runtime_test.cpp \
  demo/site/index.html tests/nix/demo_package_contract_test.sh
git commit -m "feat: add focused HTTP/3 speed test demo"
```

Expected: commit succeeds after all verification commands are green.
