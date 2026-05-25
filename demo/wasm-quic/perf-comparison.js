const fallbackPerfSnapshot = {
  schema_version: 1,
  generated_at: "unavailable",
  event_name: "local",
  commit: "awaiting-ci-results",
  sources: [
    {
      label: "coquic",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "quic-go",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "quinn",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "picoquic",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "msquic",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "quiche",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "quicly",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "google-quiche",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "tquic",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "mvfst",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "s2n-quic",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "xquic",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "aioquic",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "ngtcp2",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "lsquic",
      path: "perf-results.json",
      missing: true,
    },
    {
      label: "neqo",
      path: "perf-results.json",
      missing: true,
    },
  ],
  rows: [],
};

const colors = {
  coquic: "#24b5a6",
  "quic-go": "#63a6ff",
  quinn: "#e39a3b",
  picoquic: "#f5c451",
  msquic: "#b56cff",
  quiche: "#ea6a7a",
  quicly: "#47c1a8",
  "google-quiche": "#4f8df7",
  tquic: "#f08b44",
  mvfst: "#57c785",
  "s2n-quic": "#9b8cff",
  xquic: "#f47f42",
  aioquic: "#4db7e5",
  ngtcp2: "#d979a8",
  lsquic: "#6f9d55",
  neqo: "#c59b72",
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
let dataSource = "waiting for perf-results.json";

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

function emptyCard(label, detail) {
  return {
    label,
    value: "-",
    detail,
  };
}

function renderSnapshot() {
  const cards = ["bulk", "rr", "crr"].map((mode) => {
    const config = modeConfig[mode];
    const row = bestRow(mode);
    if (!row) {
      return emptyCard(config.summaryLabel, "waiting for CI benchmark data");
    }
    return {
      label: config.summaryLabel,
      value: `${formatNumber(row[config.metric], config.decimals)} ${config.unit}`,
      detail: `${row.implementation}, ${row.congestion_control}`,
    };
  });

  const coquicBulkRows = activeSnapshot.rows.filter((row) => row.mode === "bulk" && row.implementation === "coquic" && row.status === "ok");
  if (coquicBulkRows.length) {
    const bestCoquic = coquicBulkRows.reduce((best, row) => (Number(row.throughput_mib_per_s) > Number(best.throughput_mib_per_s) ? row : best), coquicBulkRows[0]);
    cards.push({
      label: "coquic best bulk",
      value: `${formatNumber(bestCoquic.throughput_mib_per_s)} MiB/s`,
      detail: `${bestCoquic.congestion_control}, current CI snapshot`,
    });
  } else {
    cards.push(emptyCard("coquic best bulk", "waiting for CoQUIC rows"));
  }

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
  const maxValue = rows.length ? Math.max(...rows.map((row) => Number(row[config.metric]))) : 0;
  const plot = document.createElement("section");
  plot.className = "plot";
  const heading = document.createElement("h3");
  heading.textContent = config.title;
  const subtitle = document.createElement("p");
  subtitle.textContent = config.metric;
  const list = document.createElement("div");
  list.className = "bar-list";

  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No completed benchmark rows loaded.";
    list.append(empty);
    plot.append(heading, subtitle, list);
    return plot;
  }

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
    const implOrder = ["coquic", "quic-go", "quinn", "picoquic", "msquic", "quiche", "quicly", "google-quiche", "tquic", "mvfst", "s2n-quic", "xquic", "aioquic", "ngtcp2", "lsquic", "neqo"];
    const modeOrder = { bulk: 0, rr: 1, crr: 2 };
    const leftImpl = implOrder.indexOf(left.implementation);
    const rightImpl = implOrder.indexOf(right.implementation);
    return (
      (leftImpl === -1 ? implOrder.length : leftImpl) - (rightImpl === -1 ? implOrder.length : rightImpl) ||
      modeOrder[left.mode] - modeOrder[right.mode] ||
      left.congestion_control.localeCompare(right.congestion_control)
    );
  });
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.className = "empty-cell";
    td.colSpan = 8;
    td.textContent = "No benchmark rows loaded. The dashboard will use perf-results.json when the perf workflow uploads it.";
    tr.append(td);
    document.getElementById("comparison-body").replaceChildren(tr);
    return;
  }
  document.getElementById("comparison-body").replaceChildren(
    ...rows.map((row) => {
      const tr = document.createElement("tr");
      const statusClass = row.status === "ok" && !row.skipped_setup_errors ? "ok" : "warn";
      const statusText = row.skipped_setup_errors ? `${row.status}, ${row.skipped_setup_errors} skipped` : row.status;

      const implementation = document.createElement("td");
      const implCell = document.createElement("div");
      implCell.className = "impl-cell";
      const name = document.createElement("strong");
      name.textContent = row.implementation;
      const mode = document.createElement("span");
      mode.textContent = row.mode;
      implCell.append(name, mode);
      implementation.append(implCell);

      const pair = document.createElement("td");
      pair.textContent = row.pair;

      const cc = document.createElement("td");
      const ccPill = document.createElement("span");
      ccPill.className = "pill";
      ccPill.textContent = row.congestion_control;
      cc.append(ccPill);

      const status = document.createElement("td");
      const statusPill = document.createElement("span");
      statusPill.className = `pill ${statusClass}`;
      statusPill.textContent = statusText;
      status.append(statusPill);

      const bulkMib = document.createElement("td");
      bulkMib.className = "metric";
      bulkMib.textContent = formatNumber(row.throughput_mib_per_s);
      const bulkGbit = document.createElement("td");
      bulkGbit.className = "metric";
      bulkGbit.textContent = formatNumber(row.throughput_gbit_per_s);
      const rr = document.createElement("td");
      rr.className = "metric";
      rr.textContent = row.mode === "rr" ? formatNumber(row.requests_per_s, 0) : "-";
      const crr = document.createElement("td");
      crr.className = "metric";
      crr.textContent = row.mode === "crr" ? formatNumber(row.requests_per_s, 0) : "-";

      tr.append(implementation, pair, cc, status, bulkMib, bulkGbit, rr, crr);
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
    dataSource = "perf-results.json not available yet";
  }
  renderAll();
}

loadLiveSnapshot();
