const metricKeys = ["functions", "lines", "branches"];
const metricLabels = {
  functions: "Functions",
  lines: "Lines",
  branches: "Branches",
};

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isMetric(value) {
  return (
    isRecord(value) &&
    Number.isFinite(value.covered) &&
    Number.isFinite(value.total) &&
    Number.isFinite(value.percent) &&
    value.covered >= 0 &&
    value.total >= 0 &&
    value.covered <= value.total &&
    value.percent >= 0 &&
    value.percent <= 100
  );
}

function hasMetrics(value) {
  return isRecord(value) && metricKeys.every((key) => isMetric(value[key]));
}

function isCoverageSnapshot(value) {
  return (
    isRecord(value) &&
    value.schema_version === 1 &&
    typeof value.generated_at === "string" &&
    typeof value.event_name === "string" &&
    typeof value.commit === "string" &&
    typeof value.report_url === "string" &&
    hasMetrics(value.totals) &&
    Array.isArray(value.components) &&
    value.components.every(
      (component) => isRecord(component) && typeof component.name === "string" && hasMetrics(component.metrics),
    ) &&
    Array.isArray(value.files) &&
    value.files.every(
      (file) => isRecord(file) && typeof file.path === "string" && typeof file.component === "string" && hasMetrics(file.metrics),
    ) &&
    Array.isArray(value.least_covered_files) &&
    value.least_covered_files.every(
      (file) => isRecord(file) && typeof file.path === "string" && typeof file.component === "string" && hasMetrics(file.metrics),
    )
  );
}

function formatPercent(value) {
  return `${value.toFixed(2)}%`;
}

function formatCount(value) {
  return value.toLocaleString("en-US");
}

function metricCount(metric) {
  return `${formatCount(metric.covered)} / ${formatCount(metric.total)}`;
}

function coverageMeter(metric, label) {
  const meter = document.createElement("div");
  meter.className = "coverage-meter";
  meter.setAttribute("role", "meter");
  meter.setAttribute("aria-label", label);
  meter.setAttribute("aria-valuemin", "0");
  meter.setAttribute("aria-valuemax", "100");
  meter.setAttribute("aria-valuenow", String(metric.percent));
  const fill = document.createElement("span");
  fill.style.width = formatPercent(metric.percent);
  meter.append(fill);
  return meter;
}

function metricEvidence(key, metric) {
  const evidence = document.createElement("article");
  evidence.className = "coverage-metric";
  evidence.dataset.coverageMetric = key;
  evidence.dataset.metric = key;

  const heading = document.createElement("div");
  heading.className = "coverage-metric-heading";
  const label = document.createElement("h3");
  label.textContent = metricLabels[key];
  const percent = document.createElement("strong");
  percent.className = "coverage-metric-percent";
  percent.textContent = formatPercent(metric.percent);
  heading.append(label, percent);

  const count = document.createElement("p");
  count.className = "coverage-metric-count";
  count.textContent = `${metricCount(metric)} covered`;

  evidence.append(heading, count, coverageMeter(metric, `${metricLabels[key]} coverage: ${formatPercent(metric.percent)}`));
  return evidence;
}

function rowMetric(label, metric) {
  const item = document.createElement("div");
  const term = document.createElement("dt");
  term.textContent = label;
  const value = document.createElement("dd");
  value.textContent = `${metricCount(metric)} (${formatPercent(metric.percent)})`;
  item.append(term, value);
  return item;
}

function componentRow(component) {
  const row = document.createElement("article");
  row.className = "coverage-list-row";
  row.dataset.componentName = component.name;

  const heading = document.createElement("div");
  heading.className = "coverage-row-heading";
  const name = document.createElement("strong");
  name.textContent = component.name;
  const linePercent = document.createElement("span");
  linePercent.className = "coverage-row-percent";
  linePercent.textContent = formatPercent(component.metrics.lines.percent);
  heading.append(name, linePercent);

  const details = document.createElement("dl");
  details.className = "coverage-row-metrics";
  details.append(
    rowMetric("Functions", component.metrics.functions),
    rowMetric("Lines", component.metrics.lines),
    rowMetric("Branches", component.metrics.branches),
  );

  row.append(
    heading,
    coverageMeter(component.metrics.lines, `Line coverage for ${component.name}: ${formatPercent(component.metrics.lines.percent)}`),
    details,
  );
  return row;
}

function fileRow(file) {
  const row = document.createElement("article");
  row.className = "coverage-list-row coverage-file-row";
  row.dataset.filePath = file.path;

  const heading = document.createElement("div");
  heading.className = "coverage-row-heading";
  const name = document.createElement("strong");
  name.textContent = file.path;
  name.title = file.path;
  const linePercent = document.createElement("span");
  linePercent.className = "coverage-row-percent";
  linePercent.textContent = formatPercent(file.metrics.lines.percent);
  heading.append(name, linePercent);

  const details = document.createElement("dl");
  details.className = "coverage-row-metrics";
  details.append(
    rowMetric("Functions", file.metrics.functions),
    rowMetric("Lines", file.metrics.lines),
    rowMetric("Branches", file.metrics.branches),
  );

  row.append(
    heading,
    coverageMeter(file.metrics.lines, `Line coverage for ${file.path}: ${formatPercent(file.metrics.lines.percent)}`),
    details,
  );
  return row;
}

function emptyState(text) {
  const node = document.createElement("p");
  node.className = "coverage-empty-state";
  node.textContent = text;
  return node;
}

function loadingRow() {
  const row = document.createElement("div");
  row.className = "coverage-loading-row";
  row.dataset.coverageLoadingRow = "true";
  row.setAttribute("aria-hidden", "true");
  return row;
}

function renderLoading() {
  document.getElementById("summary-grid").replaceChildren(loadingRow(), loadingRow(), loadingRow());
  document.getElementById("component-list").replaceChildren(loadingRow(), loadingRow());
  document.getElementById("file-list").replaceChildren(loadingRow(), loadingRow(), loadingRow());
}

function renderUnavailable() {
  const unavailable = () => {
    const row = document.createElement("div");
    row.className = "coverage-unavailable-row";
    row.textContent = "Coverage metric unavailable.";
    return row;
  };
  document.getElementById("summary-grid").replaceChildren(unavailable(), unavailable(), unavailable());
  document.getElementById("component-list").replaceChildren(emptyState("No component coverage loaded."));
  document.getElementById("file-list").replaceChildren(emptyState("No file coverage loaded."));
}

function setSourceMetadata(snapshot) {
  document.getElementById("coverage-generated-at").textContent = snapshot?.generated_at || "unavailable";
  document.getElementById("coverage-event").textContent = snapshot?.event_name || "unavailable";
  document.getElementById("coverage-commit").textContent = snapshot?.commit || "unavailable";
}

function renderLoaded(snapshot) {
  const components = [...snapshot.components].sort((left, right) => {
    const lineDifference = left.metrics.lines.percent - right.metrics.lines.percent;
    return lineDifference || left.name.localeCompare(right.name);
  });

  document.getElementById("summary-grid").replaceChildren(
    ...metricKeys.map((key) => metricEvidence(key, snapshot.totals[key])),
  );
  document.getElementById("component-list").replaceChildren(
    ...(components.length ? components.map(componentRow) : [emptyState("No component coverage loaded.")]),
  );
  document.getElementById("file-list").replaceChildren(
    ...(snapshot.least_covered_files.length
      ? snapshot.least_covered_files.map(fileRow)
      : [emptyState("No file coverage loaded.")]),
  );
}

function setState(state, statusText, sourceText) {
  const report = document.getElementById("coverage-evidence");
  report.dataset.coverageState = state;
  report.setAttribute("aria-busy", state === "loading" ? "true" : "false");
  document.getElementById("coverage-source-label").textContent = sourceText;
  const status = document.getElementById("coverage-status");
  status.textContent = statusText;
  status.setAttribute("aria-live", state === "unavailable" || state === "malformed" ? "assertive" : "polite");
}

function addRetryAction(status, onRetry) {
  const retry = document.createElement("button");
  retry.dataset.coverageAction = "retry";
  retry.type = "button";
  retry.textContent = "Retry";
  retry.setAttribute("aria-label", "Retry coverage results");
  retry.addEventListener("click", onRetry, { once: true });
  status.append(" ", retry);
}

async function loadCoverageSnapshot() {
  renderLoading();
  setState("loading", "Loading coverage-results.json.", "waiting for coverage-results.json");
  setSourceMetadata(null);

  try {
    const response = await fetch("./coverage-results.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    let snapshot;
    try {
      snapshot = await response.json();
    } catch {
      throw new Error("invalid coverage-results.json");
    }
    if (!isCoverageSnapshot(snapshot)) throw new Error("invalid coverage-results.json");

    renderLoaded(snapshot);
    setSourceMetadata(snapshot);
    setState(
      snapshot.components.length || snapshot.least_covered_files.length ? "loaded" : "loaded-empty",
      snapshot.components.length || snapshot.least_covered_files.length
        ? "Coverage results loaded."
        : "Coverage results loaded; no components or files were reported.",
      `coverage-results.json from ${snapshot.generated_at}`,
    );
  } catch (error) {
    const reason = error instanceof Error ? error.message : "request failed";
    setSourceMetadata(null);
    renderUnavailable();
    setState(
      reason === "invalid coverage-results.json" ? "malformed" : "unavailable",
      reason === "invalid coverage-results.json"
        ? "Coverage results could not be read: invalid coverage-results.json."
        : `Coverage results unavailable: ${reason}.`,
      reason === "invalid coverage-results.json"
        ? "coverage-results.json is malformed"
        : "coverage-results.json not available yet",
    );
    const status = document.getElementById("coverage-status");
    addRetryAction(status, loadCoverageSnapshot);
  }
}

loadCoverageSnapshot();
