const fallbackPerfSnapshot = {
  schema_version: 1,
  generated_at: "2026-05-24T15:22:59Z",
  event_name: "local",
  commit: "local-snapshot",
  sources: [
    {
      label: "coquic",
      path: ".bench-results/coquic-ci-20260524T133349Z/manifest.json",
      missing: false,
      preset: "ci",
      ok_runs: 12,
      total_runs: 12,
    },
    {
      label: "quic-go",
      path: ".bench-results/quicgo2quicgo-ci-20260524T142238Z/manifest.json",
      missing: false,
      preset: "ci",
      ok_runs: 3,
      total_runs: 3,
    },
    {
      label: "quinn",
      path: ".bench-results/quinn2quinn-ci-20260524T145152Z/manifest.json",
      missing: false,
      preset: "ci",
      ok_runs: 3,
      total_runs: 3,
    },
    {
      label: "picoquic",
      path: ".bench-results/picoquic2picoquic-ci-20260524T152259Z/manifest.json",
      missing: false,
      preset: "ci",
      ok_runs: 3,
      total_runs: 3,
    },
  ],
  rows: [
    { implementation: "coquic", pair: "coquic -> coquic", mode: "bulk", status: "ok", congestion_control: "newreno", elapsed_ms: 60000, throughput_mib_per_s: 68.831, throughput_gbit_per_s: 0.577, requests_per_s: 0, p50_us: 0, p99_us: 0, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "bulk", status: "ok", congestion_control: "cubic", elapsed_ms: 60000, throughput_mib_per_s: 69.431, throughput_gbit_per_s: 0.582, requests_per_s: 0, p50_us: 0, p99_us: 0, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "bulk", status: "ok", congestion_control: "bbr", elapsed_ms: 60000, throughput_mib_per_s: 46.626, throughput_gbit_per_s: 0.391, requests_per_s: 0, p50_us: 0, p99_us: 0, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "bulk", status: "ok", congestion_control: "copa", elapsed_ms: 60000, throughput_mib_per_s: 39.838, throughput_gbit_per_s: 0.334, requests_per_s: 0, p50_us: 0, p99_us: 0, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "rr", status: "ok", congestion_control: "newreno", elapsed_ms: 45000, throughput_mib_per_s: 0.247, throughput_gbit_per_s: 0.002, requests_per_s: 4034.4, p50_us: 125061, p99_us: 158189, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "rr", status: "ok", congestion_control: "cubic", elapsed_ms: 45000, throughput_mib_per_s: 0.244, throughput_gbit_per_s: 0.002, requests_per_s: 3987.6, p50_us: 126640, p99_us: 158163, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "rr", status: "ok", congestion_control: "bbr", elapsed_ms: 45000, throughput_mib_per_s: 0.246, throughput_gbit_per_s: 0.002, requests_per_s: 4030.511, p50_us: 125211, p99_us: 155389, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "rr", status: "ok", congestion_control: "copa", elapsed_ms: 45000, throughput_mib_per_s: 0.27, throughput_gbit_per_s: 0.002, requests_per_s: 4418.156, p50_us: 114122, p99_us: 148284, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "crr", status: "ok", congestion_control: "newreno", elapsed_ms: 45000, throughput_mib_per_s: 0.004, throughput_gbit_per_s: 0, requests_per_s: 63.578, p50_us: 284, p99_us: 4455, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "crr", status: "ok", congestion_control: "cubic", elapsed_ms: 45000, throughput_mib_per_s: 0.004, throughput_gbit_per_s: 0, requests_per_s: 63.6, p50_us: 286, p99_us: 1083, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "crr", status: "ok", congestion_control: "bbr", elapsed_ms: 45000, throughput_mib_per_s: 0.004, throughput_gbit_per_s: 0, requests_per_s: 63.578, p50_us: 288, p99_us: 4262, skipped_setup_errors: 0 },
    { implementation: "coquic", pair: "coquic -> coquic", mode: "crr", status: "ok", congestion_control: "copa", elapsed_ms: 45000, throughput_mib_per_s: 0.004, throughput_gbit_per_s: 0, requests_per_s: 63.689, p50_us: 229, p99_us: 5055, skipped_setup_errors: 0 },
    { implementation: "quic-go", pair: "quic-go -> quic-go", mode: "bulk", status: "ok", congestion_control: "default", elapsed_ms: 60000, throughput_mib_per_s: 358.083, throughput_gbit_per_s: 3.004, requests_per_s: 0, p50_us: 0, p99_us: 0, skipped_setup_errors: 0 },
    { implementation: "quic-go", pair: "quic-go -> quic-go", mode: "rr", status: "ok", congestion_control: "default", elapsed_ms: 45000, throughput_mib_per_s: 0.699, throughput_gbit_per_s: 0.006, requests_per_s: 11454.067, p50_us: 35797, p99_us: 165843, skipped_setup_errors: 0 },
    { implementation: "quic-go", pair: "quic-go -> quic-go", mode: "crr", status: "ok", congestion_control: "default", elapsed_ms: 45000, throughput_mib_per_s: 0.025, throughput_gbit_per_s: 0, requests_per_s: 404.622, p50_us: 9207, p99_us: 105008, skipped_setup_errors: 89 },
    { implementation: "quinn", pair: "quinn -> quinn", mode: "bulk", status: "ok", congestion_control: "default", elapsed_ms: 60000, throughput_mib_per_s: 527.217, throughput_gbit_per_s: 4.423, requests_per_s: 0, p50_us: 0, p99_us: 0, skipped_setup_errors: 0 },
    { implementation: "quinn", pair: "quinn -> quinn", mode: "rr", status: "ok", congestion_control: "default", elapsed_ms: 45000, throughput_mib_per_s: 2.067, throughput_gbit_per_s: 0.017, requests_per_s: 33868.733, p50_us: 2213, p99_us: 3040, skipped_setup_errors: 0 },
    { implementation: "quinn", pair: "quinn -> quinn", mode: "crr", status: "ok", congestion_control: "default", elapsed_ms: 45000, throughput_mib_per_s: 0.04, throughput_gbit_per_s: 0, requests_per_s: 648.822, p50_us: 25806, p99_us: 55323, skipped_setup_errors: 0 },
    { implementation: "picoquic", pair: "picoquic -> picoquic", mode: "bulk", status: "ok", congestion_control: "default", elapsed_ms: 19247, throughput_mib_per_s: 399.023, throughput_gbit_per_s: 3.347, requests_per_s: 0.208, p50_us: 0, p99_us: 0, skipped_setup_errors: 0 },
    { implementation: "picoquic", pair: "picoquic -> picoquic", mode: "rr", status: "ok", congestion_control: "default", elapsed_ms: 3429, throughput_mib_per_s: 40.051, throughput_gbit_per_s: 0.336, requests_per_s: 656200.642, p50_us: 0, p99_us: 0, skipped_setup_errors: 0 },
    { implementation: "picoquic", pair: "picoquic -> picoquic", mode: "crr", status: "ok", congestion_control: "default", elapsed_ms: 45038, throughput_mib_per_s: 0.055, throughput_gbit_per_s: 0, requests_per_s: 895.244, p50_us: 0, p99_us: 0, skipped_setup_errors: 0 },
  ],
};

const colors = {
  coquic: "#24b5a6",
  "quic-go": "#63a6ff",
  quinn: "#e39a3b",
  picoquic: "#f5c451",
};

const modeConfig = {
  bulk: {
    title: "Bulk Download",
    metric: "throughput_mib_per_s",
    unit: "MiB/s",
    decimals: 3,
    summaryLabel: "bulk leader",
  },
  rr: {
    title: "Request/Response",
    metric: "requests_per_s",
    unit: "req/s",
    decimals: 0,
    summaryLabel: "rr leader",
  },
  crr: {
    title: "Connection Request/Response",
    metric: "requests_per_s",
    unit: "req/s",
    decimals: 0,
    summaryLabel: "crr leader",
  },
};

let activeSnapshot = fallbackPerfSnapshot;
let dataSource = "fallback snapshot";

function formatNumber(value, decimals = 3) {
  return Number(value).toLocaleString("en-US", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function bestRowsByImplementation(mode) {
  const config = modeConfig[mode];
  const best = new Map();
  for (const row of activeSnapshot.rows.filter((candidate) => candidate.mode === mode && candidate.status === "ok")) {
    const current = best.get(row.implementation);
    if (!current || Number(row[config.metric]) > Number(current[config.metric])) {
      best.set(row.implementation, row);
    }
  }
  return [...best.values()].sort((left, right) => Number(right[config.metric]) - Number(left[config.metric]));
}

function bestRow(mode) {
  return bestRowsByImplementation(mode)[0];
}

function renderSnapshot() {
  const cards = ["bulk", "rr", "crr"].map((mode) => {
    const config = modeConfig[mode];
    const row = bestRow(mode);
    return {
      label: config.summaryLabel,
      value: `${formatNumber(row[config.metric], config.decimals)} ${config.unit}`,
      detail: `${row.implementation}, ${row.congestion_control}`,
    };
  });

  const coquicBulkRows = activeSnapshot.rows.filter((row) => row.mode === "bulk" && row.implementation === "coquic" && row.status === "ok");
  const bestCoquic = coquicBulkRows.reduce((best, row) => (Number(row.throughput_mib_per_s) > Number(best.throughput_mib_per_s) ? row : best), coquicBulkRows[0]);
  cards.push({
    label: "coquic best bulk",
    value: `${formatNumber(bestCoquic.throughput_mib_per_s)} MiB/s`,
    detail: `${bestCoquic.congestion_control}, current CI snapshot`,
  });

  document.getElementById("snapshot-grid").replaceChildren(
    ...cards.map((card) => {
      const element = document.createElement("article");
      element.className = "stat-card";

      const label = document.createElement("span");
      label.textContent = card.label;
      const value = document.createElement("strong");
      value.textContent = card.value;
      const detail = document.createElement("small");
      detail.textContent = card.detail;

      element.append(label, value, detail);
      return element;
    }),
  );
}

function renderBarplot(mode) {
  const config = modeConfig[mode];
  const rows = bestRowsByImplementation(mode);
  const maxValue = Math.max(...rows.map((row) => Number(row[config.metric])));
  const plot = document.createElement("section");
  plot.className = "plot";
  const heading = document.createElement("h3");
  heading.textContent = config.title;
  const subtitle = document.createElement("p");
  subtitle.textContent = config.metric;
  const list = document.createElement("div");
  list.className = "bar-list";

  list.replaceChildren(
    ...rows.map((row) => {
      const value = Number(row[config.metric]);
      const percent = maxValue > 0 ? Math.max((value / maxValue) * 100, 0.8) : 0;
      const element = document.createElement("div");
      element.className = "bar-row";

      const label = document.createElement("div");
      label.className = "bar-label";
      const name = document.createElement("strong");
      name.textContent = row.implementation;
      const cc = document.createElement("span");
      cc.textContent = row.congestion_control;
      label.append(name, cc);

      const track = document.createElement("div");
      track.className = "bar-track";
      const fill = document.createElement("div");
      fill.className = "bar-fill";
      fill.style.setProperty("--bar-width", `${percent}%`);
      fill.style.setProperty("--bar-color", colors[row.implementation] || "#c3d4d8");
      track.append(fill);

      const metricValue = document.createElement("div");
      metricValue.className = "bar-value";
      metricValue.textContent = `${formatNumber(value, config.decimals)} ${config.unit}`;

      element.append(label, track, metricValue);
      return element;
    }),
  );

  plot.append(heading, subtitle, list);
  return plot;
}

function renderPlots() {
  document.getElementById("data-source-label").textContent = dataSource;
  document.getElementById("plot-grid").replaceChildren(
    renderBarplot("bulk"),
    renderBarplot("rr"),
    renderBarplot("crr"),
  );
}

function renderTable() {
  const rows = [...activeSnapshot.rows].sort((left, right) => {
    const implOrder = ["coquic", "quic-go", "quinn", "picoquic"];
    const modeOrder = { bulk: 0, rr: 1, crr: 2 };
    return (
      implOrder.indexOf(left.implementation) - implOrder.indexOf(right.implementation) ||
      modeOrder[left.mode] - modeOrder[right.mode] ||
      left.congestion_control.localeCompare(right.congestion_control)
    );
  });
  document.getElementById("comparison-body").replaceChildren(
    ...rows.map((row) => {
      const tr = document.createElement("tr");
      const statusClass = row.status === "ok" && !row.skipped_setup_errors ? "ok" : "warn";
      const statusText = row.skipped_setup_errors ? `${row.status}, ${row.skipped_setup_errors} skipped` : row.status;

      tr.innerHTML = `
        <td>
          <div class="impl-cell">
            <strong>${row.implementation}</strong>
            <span>${row.mode}</span>
          </div>
        </td>
        <td>${row.pair}</td>
        <td><span class="pill">${row.congestion_control}</span></td>
        <td><span class="pill ${statusClass}">${statusText}</span></td>
        <td class="metric">${formatNumber(row.throughput_mib_per_s)}</td>
        <td class="metric">${formatNumber(row.throughput_gbit_per_s)}</td>
        <td class="metric">${row.mode === "rr" ? formatNumber(row.requests_per_s, 0) : "-"}</td>
        <td class="metric">${row.mode === "crr" ? formatNumber(row.requests_per_s, 0) : "-"}</td>
      `;
      return tr;
    }),
  );
}

function renderSources() {
  document.getElementById("source-list").replaceChildren(
    ...activeSnapshot.sources.map((source) => {
      const element = document.createElement("div");
      element.className = "source-item";
      const name = document.createElement("strong");
      name.textContent = source.label;
      const pair = document.createElement("span");
      pair.textContent = source.missing ? "missing manifest" : `${source.ok_runs}/${source.total_runs} ok, ${source.preset}`;
      const sourcePath = document.createElement("span");
      sourcePath.textContent = source.path;
      element.append(name, pair, sourcePath);
      return element;
    }),
  );
}

function renderAll() {
  renderSnapshot();
  renderPlots();
  renderTable();
  renderSources();
}

async function loadLiveSnapshot() {
  try {
    const response = await fetch("./perf-results.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const snapshot = await response.json();
    if (!Array.isArray(snapshot.rows) || !Array.isArray(snapshot.sources)) {
      throw new Error("invalid perf-results.json");
    }
    activeSnapshot = snapshot;
    dataSource = `perf-results.json from ${snapshot.generated_at || "latest workflow"}`;
  } catch {
    activeSnapshot = fallbackPerfSnapshot;
    dataSource = "fallback local CI snapshot";
  }
  renderAll();
}

loadLiveSnapshot();
