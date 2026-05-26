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

const implementationOrder = ["coquic", "quic-go", "quinn", "picoquic", "msquic", "quiche", "quicly", "google-quiche", "tquic", "mvfst", "s2n-quic", "xquic", "aioquic", "ngtcp2", "lsquic", "neqo"];

const implementationMeta = {
  coquic: { company: "CoQUIC", companyCode: "CQ", language: "C++", languageCode: "C++" },
  "quic-go": { company: "quic-go", companyCode: "QG", language: "Go", languageCode: "Go" },
  quinn: { company: "Quinn", companyCode: "QN", language: "Rust", languageCode: "Rs" },
  picoquic: { company: "Private Octopus", companyCode: "PO", language: "C", languageCode: "C" },
  msquic: { company: "Microsoft", companyCode: "MS", language: "C", languageCode: "C" },
  quiche: { company: "Cloudflare", companyCode: "CF", language: "Rust", languageCode: "Rs" },
  quicly: { company: "H2O Project", companyCode: "H2", language: "C", languageCode: "C" },
  "google-quiche": { company: "Google", companyCode: "G", language: "C++", languageCode: "C++" },
  tquic: { company: "Tencent", companyCode: "TC", language: "Rust", languageCode: "Rs" },
  mvfst: { company: "Meta", companyCode: "M", language: "C++", languageCode: "C++" },
  "s2n-quic": { company: "AWS", companyCode: "AWS", language: "Rust", languageCode: "Rs" },
  xquic: { company: "Alibaba", companyCode: "A", language: "C", languageCode: "C" },
  aioquic: { company: "aioquic", companyCode: "AQ", language: "Python", languageCode: "Py" },
  ngtcp2: { company: "ngtcp2", companyCode: "NG", language: "C", languageCode: "C" },
  lsquic: { company: "LiteSpeed", companyCode: "LS", language: "C", languageCode: "C" },
  neqo: { company: "Mozilla", companyCode: "MZ", language: "Rust", languageCode: "Rs" },
};

const iconPaths = {
  company: [
    { name: "path", attrs: { d: "M4 21V7.5L12 3l8 4.5V21" } },
    { name: "path", attrs: { d: "M8 21v-8h8v8" } },
    { name: "path", attrs: { d: "M8 9h.01" } },
    { name: "path", attrs: { d: "M12 9h.01" } },
    { name: "path", attrs: { d: "M16 9h.01" } },
  ],
  code: [
    { name: "path", attrs: { d: "m8 9-4 3 4 3" } },
    { name: "path", attrs: { d: "m16 9 4 3-4 3" } },
    { name: "path", attrs: { d: "m14 5-4 14" } },
  ],
  warning: [
    { name: "path", attrs: { d: "M12 3 2.8 19h18.4L12 3Z" } },
    { name: "path", attrs: { d: "M12 8v5" } },
    { name: "path", attrs: { d: "M12 16.5h.01" } },
  ],
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
let activeHistory = { schema_version: 1, generated_at: "unavailable", snapshots: [] };
let dataSource = "waiting for perf-results.json";
let historySource = "waiting for perf-history.json";

function formatNumber(value, decimals = 3) {
  return Number(value).toLocaleString("en-US", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function implementationInfo(implementation) {
  return implementationMeta[implementation] || { company: "unknown", companyCode: "?", language: "unknown", languageCode: "?" };
}

function makeIcon(name) {
  const svg = makeSvgElement("svg");
  svg.setAttribute("class", "meta-icon-svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  for (const part of iconPaths[name] || []) {
    const node = makeSvgElement(part.name);
    for (const [key, value] of Object.entries(part.attrs)) {
      node.setAttribute(key, value);
    }
    svg.append(node);
  }
  return svg;
}

function renderMetaLine(iconName, code, label) {
  const line = document.createElement("span");
  line.className = `meta-line ${iconName}`;

  const icon = document.createElement("span");
  icon.className = "meta-icon";
  icon.append(makeIcon(iconName));

  const codeLabel = document.createElement("b");
  codeLabel.className = "meta-code";
  codeLabel.textContent = code;

  const text = document.createElement("span");
  text.className = "meta-label";
  text.textContent = label;

  line.append(icon, codeLabel, text);
  return line;
}

function formatDateLabel(date) {
  if (!date) {
    return "-";
  }
  const parts = String(date).split("-");
  if (parts.length === 3) {
    return `${parts[1]}/${parts[2]}`;
  }
  return String(date);
}

function dateFromGeneratedAt(generatedAt) {
  const parsed = new Date(generatedAt);
  if (Number.isNaN(parsed.getTime())) {
    return "latest";
  }
  return parsed.toISOString().slice(0, 10);
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
      const info = implementationInfo(row.implementation);
      cc.textContent = `${info.company} · ${info.language} · ${row.congestion_control}`;
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

function historySnapshots() {
  if (Array.isArray(activeHistory.snapshots) && activeHistory.snapshots.length) {
    return activeHistory.snapshots;
  }
  if (Array.isArray(activeSnapshot.rows) && activeSnapshot.rows.length) {
    return [
      {
        date: dateFromGeneratedAt(activeSnapshot.generated_at),
        generated_at: activeSnapshot.generated_at,
        rows: activeSnapshot.rows,
      },
    ];
  }
  return [];
}

function bestHistoryValue(snapshot, implementation, mode) {
  const config = modeConfig[mode];
  const rows = Array.isArray(snapshot.rows) ? snapshot.rows : [];
  let best = null;
  for (const row of rows) {
    if (row.implementation !== implementation || row.mode !== mode || row.status !== "ok") {
      continue;
    }
    if (!best || Number(row[config.metric]) > Number(best[config.metric])) {
      best = row;
    }
  }
  return best ? Number(best[config.metric]) : null;
}

function makeSvgElement(name) {
  return document.createElementNS("http://www.w3.org/2000/svg", name);
}

function renderTrendChart(mode) {
  const config = modeConfig[mode];
  const snapshots = historySnapshots();
  const chart = document.createElement("section");
  chart.className = "trend-chart";

  const heading = document.createElement("div");
  heading.className = "trend-head";
  const title = document.createElement("h3");
  title.textContent = config.title;
  const subtitle = document.createElement("p");
  subtitle.textContent = `${config.metric} over ${snapshots.length || 0} day${snapshots.length === 1 ? "" : "s"}`;
  heading.append(title, subtitle);

  if (!snapshots.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No performance history loaded.";
    chart.append(heading, empty);
    return chart;
  }

  const valuesByImplementation = new Map();
  let maxValue = 0;
  for (const implementation of implementationOrder) {
    const points = snapshots.map((snapshot, index) => {
      const value = bestHistoryValue(snapshot, implementation, mode);
      if (value !== null) {
        maxValue = Math.max(maxValue, value);
      }
      return { index, value };
    });
    if (points.some((point) => point.value !== null)) {
      valuesByImplementation.set(implementation, points);
    }
  }

  if (!valuesByImplementation.size || maxValue <= 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No completed history rows for this mode.";
    chart.append(heading, empty);
    return chart;
  }

  const width = 680;
  const height = 260;
  const margin = { top: 18, right: 18, bottom: 34, left: 58 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const xForIndex = (index) => margin.left + (snapshots.length === 1 ? plotWidth / 2 : (index / (snapshots.length - 1)) * plotWidth);
  const yForValue = (value) => margin.top + (1 - value / maxValue) * plotHeight;

  const svg = makeSvgElement("svg");
  svg.setAttribute("class", "trend-svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `${config.title} trend`);

  for (let tick = 0; tick <= 4; tick += 1) {
    const value = (maxValue * tick) / 4;
    const y = yForValue(value);
    const line = makeSvgElement("line");
    line.setAttribute("class", "trend-grid-line");
    line.setAttribute("x1", margin.left);
    line.setAttribute("x2", width - margin.right);
    line.setAttribute("y1", y);
    line.setAttribute("y2", y);
    svg.append(line);

    const label = makeSvgElement("text");
    label.setAttribute("class", "trend-axis-label");
    label.setAttribute("x", margin.left - 8);
    label.setAttribute("y", y + 4);
    label.setAttribute("text-anchor", "end");
    label.textContent = formatNumber(value, config.decimals);
    svg.append(label);
  }

  const dateLabelIndexes = new Set([0, snapshots.length - 1]);
  if (snapshots.length > 3) {
    dateLabelIndexes.add(Math.floor((snapshots.length - 1) / 2));
  }
  for (const index of dateLabelIndexes) {
    const label = makeSvgElement("text");
    label.setAttribute("class", "trend-axis-label");
    label.setAttribute("x", xForIndex(index));
    label.setAttribute("y", height - 8);
    label.setAttribute("text-anchor", index === 0 ? "start" : index === snapshots.length - 1 ? "end" : "middle");
    label.textContent = formatDateLabel(snapshots[index]?.date);
    svg.append(label);
  }

  for (const [implementation, points] of valuesByImplementation.entries()) {
    const filtered = points.filter((point) => point.value !== null);
    const pathData = filtered.map((point, index) => `${index === 0 ? "M" : "L"} ${xForIndex(point.index).toFixed(2)} ${yForValue(point.value).toFixed(2)}`).join(" ");
    const path = makeSvgElement("path");
    path.setAttribute("class", "trend-line");
    path.setAttribute("d", pathData);
    path.setAttribute("stroke", colors[implementation] || "#c3d4d8");
    svg.append(path);

    for (const point of filtered) {
      const circle = makeSvgElement("circle");
      circle.setAttribute("class", "trend-point");
      circle.setAttribute("cx", xForIndex(point.index));
      circle.setAttribute("cy", yForValue(point.value));
      circle.setAttribute("r", "2.7");
      circle.setAttribute("fill", colors[implementation] || "#c3d4d8");
      const titleNode = makeSvgElement("title");
      titleNode.textContent = `${implementation} ${snapshots[point.index].date}: ${formatNumber(point.value, config.decimals)} ${config.unit}`;
      circle.append(titleNode);
      svg.append(circle);
    }
  }

  const legend = document.createElement("div");
  legend.className = "trend-legend";
  legend.replaceChildren(
    ...[...valuesByImplementation.keys()].map((implementation) => {
      const info = implementationInfo(implementation);
      const item = document.createElement("span");
      const swatch = document.createElement("i");
      swatch.style.setProperty("--legend-color", colors[implementation] || "#c3d4d8");
      const text = document.createElement("b");
      text.textContent = implementation;
      const meta = document.createElement("small");
      meta.textContent = `${info.company} · ${info.language}`;
      item.append(swatch, text, meta);
      return item;
    }),
  );

  chart.append(heading, svg, legend);
  return chart;
}

function renderTrends() {
  document.getElementById("history-source-label").textContent = historySource;
  document.getElementById("trend-grid").replaceChildren(
    renderTrendChart("bulk"),
    renderTrendChart("rr"),
    renderTrendChart("crr"),
  );
}

function renderTable() {
  const rows = [...activeSnapshot.rows].sort((left, right) => {
    const modeOrder = { bulk: 0, rr: 1, crr: 2 };
    const leftImpl = implementationOrder.indexOf(left.implementation);
    const rightImpl = implementationOrder.indexOf(right.implementation);
    return (
      (leftImpl === -1 ? implementationOrder.length : leftImpl) - (rightImpl === -1 ? implementationOrder.length : rightImpl) ||
      modeOrder[left.mode] - modeOrder[right.mode] ||
      left.congestion_control.localeCompare(right.congestion_control)
    );
  });
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.className = "empty-cell";
    td.colSpan = 9;
    td.textContent = "No benchmark rows loaded. The dashboard will use perf-results.json when the perf workflow uploads it.";
    tr.append(td);
    document.getElementById("comparison-body").replaceChildren(tr);
    return;
  }
  document.getElementById("comparison-body").replaceChildren(
    ...rows.map((row) => {
      const tr = document.createElement("tr");
      const setupSkips = Number(row.skipped_setup_errors || 0);
      const statusClass = row.status === "ok" ? "ok" : "warn";

      const implementation = document.createElement("td");
      const implCell = document.createElement("div");
      implCell.className = "impl-cell";
      const name = document.createElement("strong");
      name.textContent = row.implementation;
      const mode = document.createElement("span");
      mode.textContent = row.mode;
      implCell.append(name, mode);
      implementation.append(implCell);

      const info = implementationInfo(row.implementation);
      const metadata = document.createElement("td");
      const metadataCell = document.createElement("div");
      metadataCell.className = "meta-cell";
      metadataCell.append(renderMetaLine("company", info.companyCode, info.company), renderMetaLine("code", info.languageCode, info.language));
      metadata.append(metadataCell);

      const pair = document.createElement("td");
      pair.textContent = row.pair;

      const cc = document.createElement("td");
      const ccPill = document.createElement("span");
      ccPill.className = "pill";
      ccPill.textContent = row.congestion_control;
      cc.append(ccPill);

      const status = document.createElement("td");
      const statusCell = document.createElement("div");
      statusCell.className = "status-cell";
      const statusPill = document.createElement("span");
      statusPill.className = `pill ${statusClass}`;
      statusPill.textContent = row.status;
      statusCell.append(statusPill);
      if (setupSkips > 0) {
        const setupDetail = document.createElement("span");
        setupDetail.className = "status-detail";
        setupDetail.title = "Individual timed CRR connection setup attempts skipped inside this completed benchmark run.";
        setupDetail.append(makeIcon("warning"), document.createTextNode(`${setupSkips} setup skips`));
        statusCell.append(setupDetail);
      }
      status.append(statusCell);

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

      tr.append(implementation, metadata, pair, cc, status, bulkMib, bulkGbit, rr, crr);
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
  renderTrends();
  renderTable();
  renderSources();
}

async function loadLiveData() {
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
  try {
    const response = await fetch("./perf-history.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const history = await response.json();
    if (!Array.isArray(history.snapshots)) {
      throw new Error("invalid perf-history.json");
    }
    activeHistory = history;
    historySource = `perf-history.json from ${history.generated_at || "latest workflow"}`;
  } catch {
    activeHistory = { schema_version: 1, generated_at: "unavailable", snapshots: [] };
    historySource = "perf-history.json not available yet";
  }
  renderAll();
}

loadLiveData();
