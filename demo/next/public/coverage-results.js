const fallbackCoverageSnapshot = {
  schema_version: 1,
  generated_at: "unavailable",
  event_name: "local",
  commit: "awaiting-ci-results",
  report_url: "./coverage/index.html",
  totals: {
    functions: { covered: 0, total: 0, percent: 0 },
    lines: { covered: 0, total: 0, percent: 0 },
    branches: { covered: 0, total: 0, percent: 0 },
  },
  components: [],
  least_covered_files: [],
};

let activeSnapshot = fallbackCoverageSnapshot;
let dataSource = "waiting for coverage-results.json";

function formatPercent(value) {
  return `${Number(value || 0).toFixed(2)}%`;
}

function formatCount(value) {
  return Number(value || 0).toLocaleString("en-US");
}

function metricLabel(key) {
  const labels = {
    functions: "Function Coverage",
    lines: "Line Coverage",
    branches: "Branch Coverage",
  };
  return labels[key] || key;
}

function metricCard(key, metric) {
  const card = document.createElement("article");
  card.className = "metric-card";
  const label = document.createElement("span");
  label.textContent = metricLabel(key);
  const value = document.createElement("strong");
  value.textContent = formatPercent(metric.percent);
  const bar = document.createElement("div");
  bar.className = "metric-bar";
  bar.style.setProperty("--coverage-width", formatPercent(metric.percent));
  const fill = document.createElement("i");
  const count = document.createElement("span");
  count.textContent = `${formatCount(metric.covered)} / ${formatCount(metric.total)} covered`;
  bar.append(fill);
  card.append(label, value, bar, count);
  return card;
}

function rowBar(metric) {
  const bar = document.createElement("div");
  bar.className = "metric-bar";
  bar.style.setProperty("--coverage-width", formatPercent(metric.percent));
  const fill = document.createElement("i");
  bar.append(fill);
  return bar;
}

function metricChip(label, metric) {
  const chip = document.createElement("span");
  chip.textContent = `${label} ${formatPercent(metric.percent)}`;
  return chip;
}

function componentRow(component) {
  const row = document.createElement("div");
  row.className = "component-row";
  const lineMetric = component.metrics?.lines || { covered: 0, total: 0, percent: 0 };
  const functionMetric = component.metrics?.functions || { covered: 0, total: 0, percent: 0 };
  const branchMetric = component.metrics?.branches || { covered: 0, total: 0, percent: 0 };

  const top = document.createElement("div");
  top.className = "row-top";
  const name = document.createElement("strong");
  name.textContent = component.name;
  const percent = document.createElement("span");
  percent.textContent = formatPercent(lineMetric.percent);
  top.append(name, percent);

  const meta = document.createElement("div");
  meta.className = "row-meta";
  meta.append(
    metricChip("fn", functionMetric),
    metricChip("line", lineMetric),
    metricChip("branch", branchMetric),
  );
  row.append(top, rowBar(lineMetric), meta);
  return row;
}

function fileRow(file) {
  const row = document.createElement("div");
  row.className = "file-row";
  const lineMetric = file.metrics?.lines || { covered: 0, total: 0, percent: 0 };
  const functionMetric = file.metrics?.functions || { covered: 0, total: 0, percent: 0 };
  const branchMetric = file.metrics?.branches || { covered: 0, total: 0, percent: 0 };

  const top = document.createElement("div");
  top.className = "row-top";
  const name = document.createElement("strong");
  name.textContent = file.path;
  name.title = file.path;
  const percent = document.createElement("span");
  percent.textContent = formatPercent(lineMetric.percent);
  top.append(name, percent);

  const meta = document.createElement("div");
  meta.className = "row-meta";
  meta.append(
    metricChip("fn", functionMetric),
    metricChip("line", lineMetric),
    metricChip("branch", branchMetric),
  );
  row.append(top, rowBar(lineMetric), meta);
  return row;
}

function emptyState(text) {
  const node = document.createElement("div");
  node.className = "empty-state";
  node.textContent = text;
  return node;
}

function renderAll() {
  document.getElementById("coverage-source-label").textContent = dataSource;
  document.getElementById("summary-grid").replaceChildren(
    metricCard("functions", activeSnapshot.totals.functions),
    metricCard("lines", activeSnapshot.totals.lines),
    metricCard("branches", activeSnapshot.totals.branches),
  );

  const components = [...(activeSnapshot.components || [])].sort((left, right) => {
    const leftPercent = left.metrics?.lines?.percent ?? 0;
    const rightPercent = right.metrics?.lines?.percent ?? 0;
    return leftPercent - rightPercent || left.name.localeCompare(right.name);
  });
  document.getElementById("component-list").replaceChildren(
    ...(components.length ? components.map(componentRow) : [emptyState("No component coverage loaded.")]),
  );
  document.getElementById("file-list").replaceChildren(
    ...((activeSnapshot.least_covered_files || []).length
      ? activeSnapshot.least_covered_files.map(fileRow)
      : [emptyState("No file coverage loaded.")]),
  );
}

async function loadCoverageSnapshot() {
  try {
    const response = await fetch("./coverage-results.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const snapshot = await response.json();
    if (!snapshot.totals || !Array.isArray(snapshot.components)) {
      throw new Error("invalid coverage-results.json");
    }
    activeSnapshot = snapshot;
    dataSource = `coverage-results.json from ${snapshot.generated_at || "latest workflow"}`;
  } catch {
    activeSnapshot = fallbackCoverageSnapshot;
    dataSource = "coverage-results.json not available yet";
  }
  renderAll();
}

loadCoverageSnapshot();
