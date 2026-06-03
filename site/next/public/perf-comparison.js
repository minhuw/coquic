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
      label: "coquic-rust",
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
  "coquic-rust": "#ce8cff",
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

const implementationOrder = ["coquic", "coquic-rust", "quic-go", "quinn", "picoquic", "msquic", "quiche", "quicly", "google-quiche", "tquic", "mvfst", "s2n-quic", "xquic", "aioquic", "ngtcp2", "lsquic", "neqo"];

const deviconBase = "https://cdn.jsdelivr.net/gh/devicons/devicon@v2.17.0/icons/";

const languageIconSources = {
  C: `${deviconBase}c/c-original.svg`,
  "C++": `${deviconBase}cplusplus/cplusplus-original.svg`,
  Go: `${deviconBase}go/go-original.svg`,
  Python: `${deviconBase}python/python-original.svg`,
  Rust: `${deviconBase}rust/rust-original.svg`,
};

function vendorFavicon(domain) {
  return `https://www.google.com/s2/favicons?sz=64&domain=${domain}`;
}

function githubAvatar(owner) {
  return `https://github.com/${owner}.png?size=64`;
}

function githubPage(owner, repo) {
  return repo ? `https://github.com/${owner}/${repo}` : `https://github.com/${owner}`;
}

const implementationMeta = {
  coquic: { company: "CoQUIC", companyCode: "CQ", companyIcon: "./coquic-logo.svg", companyUrl: githubPage("minhuw"), sourceUrl: githubPage("minhuw", "coquic"), language: "C++", languageCode: "C++" },
  "coquic-rust": { company: "CoQUIC Rust", companyCode: "CQR", companyIcon: "./coquic-logo.svg", companyUrl: githubPage("minhuw"), sourceUrl: "https://github.com/minhuw/coquic/tree/main/src/perf/rust", language: "Rust", languageCode: "Rs" },
  "quic-go": { company: "quic-go", companyCode: "QG", companyIcon: githubAvatar("quic-go"), companyUrl: githubPage("quic-go"), sourceUrl: githubPage("quic-go", "quic-go"), language: "Go", languageCode: "Go" },
  quinn: { company: "Quinn", companyCode: "QN", companyIcon: githubAvatar("quinn-rs"), companyUrl: githubPage("quinn-rs"), sourceUrl: githubPage("quinn-rs", "quinn"), language: "Rust", languageCode: "Rs" },
  picoquic: { company: "Private Octopus", companyCode: "PO", companyIcon: githubAvatar("private-octopus"), companyUrl: githubPage("private-octopus"), sourceUrl: githubPage("private-octopus", "picoquic"), language: "C", languageCode: "C" },
  msquic: { company: "Microsoft", companyCode: "MS", companyIcon: vendorFavicon("microsoft.com"), companyUrl: "https://github.com/microsoft", sourceUrl: githubPage("microsoft", "msquic"), language: "C", languageCode: "C" },
  quiche: { company: "Cloudflare", companyCode: "CF", companyIcon: vendorFavicon("cloudflare.com"), companyUrl: "https://github.com/cloudflare", sourceUrl: githubPage("cloudflare", "quiche"), language: "Rust", languageCode: "Rs" },
  quicly: { company: "H2O Project", companyCode: "H2", companyIcon: githubAvatar("h2o"), companyUrl: githubPage("h2o"), sourceUrl: githubPage("h2o", "quicly"), language: "C", languageCode: "C" },
  "google-quiche": { company: "Google", companyCode: "G", companyIcon: vendorFavicon("google.com"), companyUrl: "https://github.com/google", sourceUrl: githubPage("google", "quiche"), language: "C++", languageCode: "C++" },
  tquic: { company: "Tencent", companyCode: "TC", companyIcon: vendorFavicon("tencent.com"), companyUrl: "https://github.com/tencent", sourceUrl: githubPage("tencent", "tquic"), language: "Rust", languageCode: "Rs" },
  mvfst: { company: "Meta", companyCode: "M", companyIcon: vendorFavicon("meta.com"), companyUrl: "https://github.com/facebook", sourceUrl: githubPage("facebook", "mvfst"), language: "C++", languageCode: "C++" },
  "s2n-quic": { company: "AWS", companyCode: "AWS", companyIcon: vendorFavicon("aws.amazon.com"), companyUrl: "https://github.com/aws", sourceUrl: githubPage("aws", "s2n-quic"), language: "Rust", languageCode: "Rs" },
  xquic: { company: "Alibaba", companyCode: "A", companyIcon: vendorFavicon("alibabacloud.com"), companyUrl: "https://github.com/alibaba", sourceUrl: githubPage("alibaba", "xquic"), language: "C", languageCode: "C" },
  aioquic: { company: "aioquic", companyCode: "AQ", companyIcon: githubAvatar("aiortc"), companyUrl: githubPage("aiortc"), sourceUrl: githubPage("aiortc", "aioquic"), language: "Python", languageCode: "Py" },
  ngtcp2: { company: "ngtcp2", companyCode: "NG", companyIcon: githubAvatar("ngtcp2"), companyUrl: githubPage("ngtcp2"), sourceUrl: githubPage("ngtcp2", "ngtcp2"), language: "C", languageCode: "C" },
  lsquic: { company: "LiteSpeed", companyCode: "LS", companyIcon: vendorFavicon("litespeedtech.com"), companyUrl: "https://github.com/litespeedtech", sourceUrl: githubPage("litespeedtech", "lsquic"), language: "C", languageCode: "C" },
  neqo: { company: "Mozilla", companyCode: "MZ", companyIcon: vendorFavicon("mozilla.org"), companyUrl: "https://github.com/mozilla", sourceUrl: githubPage("mozilla", "neqo"), language: "Rust", languageCode: "Rs" },
};

const iconPaths = {
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
    metricLabel: "Throughput",
    metricDetail: "MiB/s",
    unit: "MiB/s",
    decimals: 3,
  },
  rr: {
    title: "Request/Response",
    metric: "requests_per_s",
    metricLabel: "Requests",
    metricDetail: "Reqs/s",
    unit: "req/s",
    decimals: 0,
  },
  crr: {
    title: "Connection Request/Response",
    metric: "requests_per_s",
    metricLabel: "Connection requests",
    metricDetail: "Reqs/s",
    unit: "req/s",
    decimals: 0,
  },
};

let activeSnapshot = fallbackPerfSnapshot;
let activeHistory = { schema_version: 1, generated_at: "unavailable", snapshots: [] };
let dataSourceTime = "waiting";
let historySource = "waiting for perf-history.json";
let activePlotMode = "bulk";

function formatNumber(value, decimals = 3) {
  return Number(value).toLocaleString("en-US", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function implementationInfo(implementation) {
  return implementationMeta[implementation] || { company: "unknown", companyCode: "?", companyIcon: "", companyUrl: "", sourceUrl: "", language: "unknown", languageCode: "?" };
}

function normalizeLibraryVersion(value) {
  if (value === null || value === undefined || value === "") {
    return "unknown";
  }
  return String(value);
}

function libraryVersionFor(rowOrImplementation) {
  const implementation = typeof rowOrImplementation === "string" ? rowOrImplementation : rowOrImplementation.implementation;
  const direct = typeof rowOrImplementation === "string" ? "" : rowOrImplementation.library_version;
  if (direct) {
    return normalizeLibraryVersion(direct);
  }
  const source = activeSnapshot.sources.find((candidate) => candidate.label === implementation);
  return normalizeLibraryVersion(source?.library_version);
}

function libraryVersionLabel(rowOrImplementation) {
  const version = libraryVersionFor(rowOrImplementation);
  return version === "unknown" ? "version unknown" : version;
}

function decorateExternalLink(link, label) {
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.title = label;
  link.setAttribute("aria-label", label);
}

function renderIdentityIcon(kind, iconUrl, code, label, url) {
  const badge = document.createElement(url ? "a" : "span");
  badge.className = `identity-icon ${kind}`;
  if (url) {
    badge.href = url;
    decorateExternalLink(badge, label);
  } else {
    badge.title = label;
    badge.setAttribute("aria-label", label);
  }

  if (iconUrl) {
    const image = document.createElement("img");
    image.src = iconUrl;
    image.alt = "";
    image.loading = "lazy";
    image.decoding = "async";
    image.referrerPolicy = "no-referrer";
    image.addEventListener("error", () => image.remove(), { once: true });
    badge.append(image);
  }

  const fallback = document.createElement("span");
  fallback.className = "identity-fallback";
  fallback.textContent = code;

  badge.append(fallback);
  return badge;
}

function renderImplementationName(implementation, info) {
  const name = document.createElement(info.sourceUrl ? "a" : "span");
  name.className = "identity-name";
  name.textContent = implementation;
  if (info.sourceUrl) {
    name.href = info.sourceUrl;
    decorateExternalLink(name, implementation);
  } else {
    name.title = implementation;
  }
  return name;
}

function renderImplementationIdentity(implementation, info) {
  const group = document.createElement("span");
  group.className = "identity-group";
  group.setAttribute("aria-label", `${implementation}, ${info.company}, ${info.language}`);

  const name = renderImplementationName(implementation, info);

  const separatorA = document.createElement("span");
  separatorA.className = "identity-separator";
  separatorA.setAttribute("aria-hidden", "true");
  separatorA.textContent = "|";

  const separatorB = document.createElement("span");
  separatorB.className = "identity-separator";
  separatorB.setAttribute("aria-hidden", "true");
  separatorB.textContent = "|";

  group.append(
    name,
    separatorA,
    renderIdentityIcon("vendor", info.companyIcon, info.companyCode, info.company, info.companyUrl),
    separatorB,
    renderIdentityIcon("language", languageIconSources[info.language], info.languageCode, info.language),
  );

  return group;
}

function renderBarImplementationIdentity(implementation, info, versionLabel) {
  const group = document.createElement("span");
  group.className = "bar-identity";
  group.setAttribute("aria-label", `${implementation}, ${versionLabel}, ${info.company}, ${info.language}`);

  const text = document.createElement("span");
  text.className = "bar-identity-text";
  const version = document.createElement("small");
  version.className = "bar-version";
  version.textContent = versionLabel;
  text.append(renderImplementationName(implementation, info), version);

  const icons = document.createElement("span");
  icons.className = "bar-identity-icons";
  icons.append(
    renderIdentityIcon("vendor", info.companyIcon, info.companyCode, info.company, info.companyUrl),
    renderIdentityIcon("language", languageIconSources[info.language], info.languageCode, info.language),
  );

  group.append(text, icons);

  return group;
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

function timeFromGeneratedAt(generatedAt) {
  const parsed = new Date(generatedAt);
  if (Number.isNaN(parsed.getTime())) {
    return "unavailable";
  }
  return parsed.toISOString().slice(11, 19) + "Z";
}

function leaderboardRows(mode) {
  const config = modeConfig[mode];
  const best = new Map();
  for (const row of activeSnapshot.rows.filter((candidate) => candidate.mode === mode && candidate.status === "ok")) {
    const key = row.implementation === "coquic" ? `${row.implementation}:${row.congestion_control || "default"}` : row.implementation;
    const current = best.get(key);
    if (!current || Number(row[config.metric]) > Number(current[config.metric])) {
      best.set(key, row);
    }
  }
  return [...best.values()].sort((left, right) => Number(right[config.metric]) - Number(left[config.metric]));
}

function renderBarplot(mode) {
  const config = modeConfig[mode];
  const rows = leaderboardRows(mode);
  const maxValue = rows.length ? Math.max(...rows.map((row) => Number(row[config.metric]))) : 0;
  const plot = document.createElement("section");
  plot.className = "plot";
  const heading = document.createElement("h3");
  heading.textContent = config.title;
  const subtitle = document.createElement("p");
  subtitle.textContent = config.metricDetail;
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
    ...rows.map((row, index) => {
      const value = Number(row[config.metric]);
      const percent = maxValue > 0 ? Math.max((value / maxValue) * 100, 0.8) : 0;
      const element = document.createElement("div");
      element.className = `bar-row${row.implementation === "coquic" ? " own-impl" : ""}`;

      const rank = index + 1;
      const rankBadge = document.createElement("span");
      rankBadge.className = `rank-badge rank-${rank <= 3 ? rank : "default"}`;
      rankBadge.title = `Rank ${rank}`;
      rankBadge.textContent = String(rank);

      const label = document.createElement("div");
      label.className = "bar-label";
      const info = implementationInfo(row.implementation);
      const displayName = row.implementation === "coquic" && row.congestion_control ? `coquic[${row.congestion_control}]` : row.implementation;
      label.append(renderBarImplementationIdentity(displayName, info, libraryVersionLabel(row)));

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

      element.append(rankBadge, label, track, metricValue);
      return element;
    }),
  );

  plot.append(heading, subtitle, list);
  return plot;
}

function selectPlotMode(mode) {
  if (!modeConfig[mode]) {
    return;
  }
  activePlotMode = mode;
  renderPlots();
}

function renderPlots() {
  const dataSourceLabel = document.getElementById("data-source-label");
  if (dataSourceLabel) {
    dataSourceLabel.title = dataSourceTime;
    dataSourceLabel.dataset.tooltip = dataSourceTime;
    dataSourceLabel.setAttribute("aria-label", `Benchmark data time: ${dataSourceTime}`);
  }
  const tabs = document.createElement("div");
  tabs.className = "plot-tabs";
  tabs.setAttribute("role", "tablist");
  tabs.setAttribute("aria-label", "Benchmark mode");
  tabs.replaceChildren(
    ...Object.entries(modeConfig).map(([mode, config]) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "plot-tab";
      button.id = `plot-tab-${mode}`;
      button.setAttribute("role", "tab");
      button.setAttribute("aria-selected", mode === activePlotMode ? "true" : "false");
      button.setAttribute("aria-controls", "plot-panel");
      button.addEventListener("click", () => selectPlotMode(mode));

      const label = document.createElement("span");
      label.textContent = mode.toUpperCase();
      const title = document.createElement("strong");
      title.textContent = config.title;
      const metric = document.createElement("small");
      metric.textContent = config.metricDetail;
      button.append(label, title, metric);
      return button;
    }),
  );

  const panel = document.createElement("div");
  panel.className = "plot-panel-active";
  panel.id = "plot-panel";
  panel.setAttribute("role", "tabpanel");
  panel.setAttribute("aria-labelledby", `plot-tab-${activePlotMode}`);
  panel.append(renderBarplot(activePlotMode));

  document.getElementById("plot-grid").replaceChildren(
    tabs,
    panel,
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
  subtitle.textContent = `${config.metricDetail} over ${snapshots.length || 0} day${snapshots.length === 1 ? "" : "s"}`;
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
  const tooltip = document.createElement("div");
  tooltip.className = "trend-tooltip";
  tooltip.setAttribute("role", "tooltip");

  function showTrendTooltip(event, detail, x, y) {
    tooltip.replaceChildren();
    const name = document.createElement("strong");
    name.textContent = detail.title;
    const value = document.createElement("span");
    value.textContent = detail.value;
    const date = document.createElement("span");
    date.textContent = detail.date;
    tooltip.append(name, value, date);
    tooltip.classList.add("visible");

    const chartRect = chart.getBoundingClientRect();
    const svgRect = svg.getBoundingClientRect();
    const pointX = (x / width) * svgRect.width + svgRect.left - chartRect.left;
    const pointY = (y / height) * svgRect.height + svgRect.top - chartRect.top;
    tooltip.style.left = `${Math.min(Math.max(pointX + 12, 8), chartRect.width - 180)}px`;
    tooltip.style.top = `${Math.max(pointY - 56, 8)}px`;
  }

  function hideTrendTooltip() {
    tooltip.classList.remove("visible");
  }
  const interactivePoints = [];

  function showNearestTrendPoint(event) {
    if (!interactivePoints.length) {
      return;
    }
    const svgRect = svg.getBoundingClientRect();
    const x = ((event.clientX - svgRect.left) / svgRect.width) * width;
    const y = ((event.clientY - svgRect.top) / svgRect.height) * height;
    const nearest = interactivePoints.reduce((best, point) => {
      const distance = (point.x - x) ** 2 + (point.y - y) ** 2;
      return !best || distance < best.distance ? { point, distance } : best;
    }, null);
    if (nearest) {
      showTrendTooltip(event, nearest.point.detail, nearest.point.x, nearest.point.y);
    }
  }

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
      const x = xForIndex(point.index);
      const y = yForValue(point.value);
      const detail = {
        title: implementation,
        value: `${formatNumber(point.value, config.decimals)} ${config.unit}`,
        date: snapshots[point.index].date || snapshots[point.index].generated_at || "latest",
      };
      const circle = makeSvgElement("circle");
      circle.setAttribute("class", "trend-point");
      circle.setAttribute("cx", x);
      circle.setAttribute("cy", y);
      circle.setAttribute("r", "2.7");
      circle.setAttribute("fill", colors[implementation] || "#c3d4d8");
      svg.append(circle);

      const hitPoint = makeSvgElement("circle");
      hitPoint.setAttribute("class", "trend-hit-point");
      hitPoint.setAttribute("cx", x);
      hitPoint.setAttribute("cy", y);
      hitPoint.setAttribute("r", "9");
      hitPoint.setAttribute("tabindex", "0");
      hitPoint.setAttribute("aria-label", `${detail.title}, ${detail.value}, ${detail.date}`);
      hitPoint.addEventListener("mouseenter", (event) => showTrendTooltip(event, detail, x, y));
      hitPoint.addEventListener("mousemove", (event) => showTrendTooltip(event, detail, x, y));
      hitPoint.addEventListener("mouseleave", hideTrendTooltip);
      hitPoint.addEventListener("focus", (event) => showTrendTooltip(event, detail, x, y));
      hitPoint.addEventListener("blur", hideTrendTooltip);
      svg.append(hitPoint);
      interactivePoints.push({ x, y, detail });
    }
  }

  const hoverPlane = makeSvgElement("rect");
  hoverPlane.setAttribute("class", "trend-hover-plane");
  hoverPlane.setAttribute("x", margin.left);
  hoverPlane.setAttribute("y", margin.top);
  hoverPlane.setAttribute("width", plotWidth);
  hoverPlane.setAttribute("height", plotHeight);
  hoverPlane.addEventListener("mousemove", showNearestTrendPoint);
  hoverPlane.addEventListener("mouseleave", hideTrendTooltip);
  svg.addEventListener("mousemove", showNearestTrendPoint);
  svg.addEventListener("mouseleave", hideTrendTooltip);
  svg.append(hoverPlane);

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
      meta.textContent = `${info.company} | ${info.language} | ${libraryVersionLabel(implementation)}`;
      item.append(swatch, text, meta);
      return item;
    }),
  );

  chart.append(heading, svg, tooltip, legend);
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

function renderAll() {
  renderPlots();
  renderTrends();
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
    dataSourceTime = timeFromGeneratedAt(snapshot.generated_at);
  } catch {
    activeSnapshot = fallbackPerfSnapshot;
    dataSourceTime = "unavailable";
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
