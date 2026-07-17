const implementationOrder = [
  "coquic",
  "coquic-rust",
  "coquic-python",
  "coquic-go",
  "coquic-js",
  "quic-go",
  "quinn",
  "picoquic",
  "msquic",
  "quiche",
  "quicly",
  "google-quiche",
  "tquic",
  "mvfst",
  "s2n-quic",
  "xquic",
  "aioquic",
  "ngtcp2",
  "lsquic",
  "neqo",
];

const coquicFamily = new Set(["coquic", "coquic-rust", "coquic-python", "coquic-go", "coquic-js"]);
const fallbackPerfSnapshot = {
  schema_version: 1,
  generated_at: "unavailable",
  event_name: "local",
  commit: "awaiting-ci-results",
  sources: implementationOrder.map((label) => ({ label, path: "perf-results.json", missing: true })),
  rows: [],
};

const deviconBase = "https://cdn.jsdelivr.net/gh/devicons/devicon@v2.17.0/icons/";
const languageIconSources = {
  C: `${deviconBase}c/c-original.svg`,
  "C++": `${deviconBase}cplusplus/cplusplus-original.svg`,
  Go: `${deviconBase}go/go-original.svg`,
  JavaScript: `${deviconBase}javascript/javascript-original.svg`,
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
  coquic: { company: "CoQUIC", companyCode: "CQ", companyIcon: "./coquic-logo.svg", companyUrl: githubPage("minhuw"), sourceUrl: githubPage("minhuw", "coquic"), language: "C++", languageCode: "C++", familyLabel: "CoQUIC", surfaceLabel: "C++ core" },
  "coquic-rust": { company: "CoQUIC Rust", companyCode: "CQR", companyIcon: "./coquic-logo.svg", companyUrl: githubPage("minhuw"), sourceUrl: "https://github.com/minhuw/coquic/tree/main/bench/coquic-rust-perf", language: "Rust", languageCode: "Rs", familyLabel: "CoQUIC", surfaceLabel: "Rust facade" },
  "coquic-python": { company: "CoQUIC Python", companyCode: "CQP", companyIcon: "./coquic-logo.svg", companyUrl: githubPage("minhuw"), sourceUrl: "https://github.com/minhuw/coquic/tree/main/bench/coquic-python-perf", language: "Python", languageCode: "Py", familyLabel: "CoQUIC", surfaceLabel: "Python facade" },
  "coquic-go": { company: "CoQUIC Go", companyCode: "CQG", companyIcon: "./coquic-logo.svg", companyUrl: githubPage("minhuw"), sourceUrl: "https://github.com/minhuw/coquic/tree/main/bench/coquic-go-perf", language: "Go", languageCode: "Go", familyLabel: "CoQUIC", surfaceLabel: "Go facade" },
  "coquic-js": { company: "CoQUIC JavaScript", companyCode: "CQJ", companyIcon: "./coquic-logo.svg", companyUrl: githubPage("minhuw"), sourceUrl: "https://github.com/minhuw/coquic/tree/main/bench/coquic-js-perf", language: "JavaScript", languageCode: "JS", familyLabel: "CoQUIC", surfaceLabel: "Node.js facade" },
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
  info: [
    { name: "circle", attrs: { cx: "12", cy: "12", r: "9" } },
    { name: "path", attrs: { d: "M12 10v6" } },
    { name: "path", attrs: { d: "M12 7.5h.01" } },
  ],
  x: [
    { name: "path", attrs: { d: "M6 6l12 12" } },
    { name: "path", attrs: { d: "M18 6 6 18" } },
  ],
};

const modeConfig = {
  bulk: {
    label: "Bulk",
    title: "Bulk download",
    metric: "throughput_mib_per_s",
    metricLabel: "Throughput",
    metricDetail: "MiB/s",
    unit: "MiB/s",
    decimals: 3,
  },
  rr: {
    label: "Stream",
    title: "Stream request/response",
    metric: "requests_per_s",
    metricLabel: "Requests",
    metricDetail: "req/s",
    unit: "req/s",
    decimals: 0,
  },
  "persistent-rr": {
    label: "RPS",
    title: "Persistent request/response",
    metric: "requests_per_s",
    metricLabel: "Requests",
    metricDetail: "req/s",
    unit: "req/s",
    decimals: 0,
  },
  crr: {
    label: "CRR",
    title: "Connection request/response",
    metric: "requests_per_s",
    metricLabel: "Connection requests",
    metricDetail: "req/s",
    unit: "req/s",
    decimals: 0,
  },
};

const filterOrder = {
  languages: ["C", "C++", "Go", "JavaScript", "Python", "Rust"],
  vendors: ["CoQUIC"],
};

let activeSnapshot = fallbackPerfSnapshot;
let activeHistory = { schema_version: 1, generated_at: "unavailable", snapshots: [] };
let currentState = "loading";
let historyState = "loading";
let activePlotMode = "bulk";
let perfDetailTrigger = null;
let perfFlamegraphTrigger = null;
let filterTrigger = null;
let controlsReady = false;
let dialogListenersReady = false;
let loadToken = 0;
const perfHistorySnapshotLimit = 180;
const activePlotFilters = {
  languages: new Set(),
  vendors: new Set(),
};
const filterGroupsOpen = {
  languages: true,
  vendors: true,
};

function byId(id) {
  return document.getElementById(id);
}

function formatNumber(value, decimals = 3) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "-";
  }
  return number.toLocaleString("en-US", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function formatPercent(value, decimals = 1) {
  if (!Number.isFinite(Number(value))) {
    return "-";
  }
  return `${formatNumber(Number(value) * 100, decimals)}%`;
}

function formatCpuPercent(value, decimals = 1) {
  if (!Number.isFinite(Number(value))) {
    return "-";
  }
  return `${formatNumber(Number(value), decimals)}%`;
}

function formatBytes(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) {
    return "-";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let scaled = number;
  let unitIndex = 0;
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024;
    unitIndex += 1;
  }
  return `${formatNumber(scaled, unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function implementationInfo(implementation) {
  return implementationMeta[implementation] || {
    company: "unknown",
    companyCode: "?",
    companyIcon: "",
    companyUrl: "",
    sourceUrl: "",
    language: "unknown",
    languageCode: "?",
  };
}

function implementationVendor(info) {
  return info.familyLabel || info.company;
}

function isCoquicFamilyImplementation(implementation) {
  return coquicFamily.has(implementation);
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
    image.addEventListener("load", () => badge.classList.add("has-image"), { once: true });
    image.addEventListener("error", () => {
      badge.classList.remove("has-image");
      image.remove();
    }, { once: true });
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

function renderBarImplementationIdentity(implementation, info, versionLabel, displayName = implementation) {
  const group = document.createElement("span");
  group.className = "bar-identity";
  group.setAttribute("aria-label", `${displayName}, ${versionLabel}, ${info.company}, ${info.language}`);

  const text = document.createElement("span");
  text.className = "bar-identity-text";
  const nameRow = document.createElement("span");
  nameRow.className = "bar-name-row";
  const name = renderImplementationName(implementation, info);
  name.textContent = displayName;
  name.setAttribute("aria-label", displayName);
  nameRow.append(name);
  if (info.familyLabel) {
    const family = document.createElement("span");
    family.className = "coquic-family-chip";
    family.textContent = info.surfaceLabel || info.familyLabel;
    family.title = `${info.familyLabel} ${info.surfaceLabel || ""}`.trim();
    nameRow.append(family);
  }
  const version = document.createElement("small");
  version.className = "bar-version";
  version.textContent = versionLabel;
  text.append(nameRow, version);

  const icons = document.createElement("span");
  icons.className = "bar-identity-icons";
  icons.append(
    renderIdentityIcon("vendor", info.companyIcon, info.companyCode, info.company, info.companyUrl),
    renderIdentityIcon("language", languageIconSources[info.language], info.languageCode, info.language),
  );
  group.append(text, icons);
  return group;
}

function makeSvgElement(name) {
  return document.createElementNS("http://www.w3.org/2000/svg", name);
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

function rowPassesPlotFilters(row) {
  const info = implementationInfo(row.implementation);
  return (!activePlotFilters.languages.size || activePlotFilters.languages.has(info.language))
    && (!activePlotFilters.vendors.size || activePlotFilters.vendors.has(implementationVendor(info)));
}

function leaderboardRows(mode, { applyFilters = true } = {}) {
  const config = modeConfig[mode];
  const best = new Map();
  for (const row of activeSnapshot.rows.filter((candidate) => candidate.mode === mode && candidate.status === "ok")) {
    const key = row.implementation === "coquic" ? `${row.implementation}:${row.congestion_control || "default"}` : row.implementation;
    const current = best.get(key);
    if (!current || Number(row[config.metric]) > Number(current[config.metric])) {
      best.set(key, row);
    }
  }
  const rows = [...best.values()].sort((left, right) => Number(right[config.metric]) - Number(left[config.metric]));
  return applyFilters ? rows.filter(rowPassesPlotFilters) : rows;
}

function sortedFilterEntries(counts, preferredOrder = []) {
  const order = new Map(preferredOrder.map((item, index) => [item, index]));
  return [...counts.entries()].sort(([left], [right]) => {
    const leftOrder = order.has(left) ? order.get(left) : Number.POSITIVE_INFINITY;
    const rightOrder = order.has(right) ? order.get(right) : Number.POSITIVE_INFINITY;
    if (leftOrder !== rightOrder) {
      return leftOrder - rightOrder;
    }
    return left.localeCompare(right);
  });
}

function makeFilterChoice(kind, value, count, selected) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "filter-choice";
  button.dataset.filterKind = kind;
  button.dataset.filterValue = value;
  button.setAttribute("aria-pressed", selected ? "true" : "false");
  button.addEventListener("click", () => togglePlotFilter(kind, value));
  const label = document.createElement("span");
  label.className = "filter-choice__label";
  label.textContent = value;
  const tally = document.createElement("small");
  tally.className = "filter-choice__count";
  tally.textContent = String(count);
  button.append(label, tally);
  return button;
}

function updateFilterChoice(button, count, selected) {
  button.setAttribute("aria-pressed", selected ? "true" : "false");
  const tally = button.querySelector(".filter-choice__count");
  if (tally) {
    tally.textContent = String(count);
  }
}

function createFilterGroup(title, kind) {
  const group = document.createElement("section");
  group.className = "plot-filter-group";
  group.dataset.filterGroup = kind;
  const optionsId = `plot-filter-options-${kind}`;
  const heading = document.createElement("button");
  heading.type = "button";
  heading.className = "plot-filter-group-title";
  heading.setAttribute("aria-expanded", filterGroupsOpen[kind] ? "true" : "false");
  heading.setAttribute("aria-controls", optionsId);
  heading.addEventListener("click", () => togglePlotFilterGroup(kind));
  const label = document.createElement("span");
  label.textContent = title;
  const count = document.createElement("small");
  count.className = "plot-filter-group-count";
  const chevron = document.createElement("i");
  chevron.setAttribute("aria-hidden", "true");
  heading.append(label, count, chevron);

  const options = document.createElement("div");
  options.id = optionsId;
  options.className = `plot-filter-options ${kind === "vendors" ? "vendor-options" : ""}`;
  options.hidden = !filterGroupsOpen[kind];
  group.append(heading, options);
  return group;
}

function ensureFilterChoice(group, kind, value, count, selected) {
  const options = group.querySelector(".plot-filter-options");
  const existing = options.querySelector(`[data-filter-value="${CSS.escape(value)}"]`);
  if (existing) {
    updateFilterChoice(existing, count, selected);
    return existing;
  }
  const choice = makeFilterChoice(kind, value, count, selected);
  options.append(choice);
  return choice;
}

function syncFilterGroup(title, kind, entries, totalCount) {
  const filters = byId("performance-filters");
  let group = filters.querySelector(`[data-filter-group="${CSS.escape(kind)}"]`);
  if (!group) {
    group = createFilterGroup(title, kind);
    filters.append(group);
  }
  const headingCount = group.querySelector(".plot-filter-group-count");
  if (headingCount) {
    headingCount.textContent = String(totalCount);
  }
  const options = group.querySelector(".plot-filter-options");
  const wanted = new Set(["__all__", ...entries.map(([value]) => value)]);
  const allChoice = options.querySelector('[data-filter-value="__all__"]') || makeFilterChoice(kind, "__all__", totalCount, !activePlotFilters[kind].size);
  allChoice.classList.add("filter-choice-all");
  allChoice.querySelector(".filter-choice__label").textContent = "All";
  allChoice.addEventListener("click", () => clearPlotFilter(kind));
  updateFilterChoice(allChoice, totalCount, !activePlotFilters[kind].size);
  if (!allChoice.parentElement) {
    options.prepend(allChoice);
  }
  for (const [value, count] of entries) {
    ensureFilterChoice(group, kind, value, count, activePlotFilters[kind].has(value));
  }
  for (const choice of [...options.querySelectorAll("[data-filter-value]")]) {
    if (!wanted.has(choice.dataset.filterValue)) {
      choice.remove();
    }
  }
  options.hidden = !filterGroupsOpen[kind];
  group.querySelector(".plot-filter-group-title").setAttribute("aria-expanded", filterGroupsOpen[kind] ? "true" : "false");
}

function updateFilterControls() {
  const allRows = currentState === "ready" ? leaderboardRows(activePlotMode, { applyFilters: false }) : [];
  const languageCounts = new Map();
  const vendorCounts = new Map();
  for (const row of allRows) {
    const info = implementationInfo(row.implementation);
    languageCounts.set(info.language, (languageCounts.get(info.language) || 0) + 1);
    const vendor = implementationVendor(info);
    vendorCounts.set(vendor, (vendorCounts.get(vendor) || 0) + 1);
  }
  syncFilterGroup("Language", "languages", sortedFilterEntries(languageCounts, filterOrder.languages), allRows.length);
  syncFilterGroup("Vendor", "vendors", sortedFilterEntries(vendorCounts, filterOrder.vendors), allRows.length);

  const activeCount = activePlotFilters.languages.size + activePlotFilters.vendors.size;
  const countLabel = byId("performance-filter-count");
  if (countLabel) {
    countLabel.textContent = `${activeCount} filter${activeCount === 1 ? "" : "s"} active`;
  }
  const selection = byId("performance-filter-selection");
  if (selection) {
    const values = [...activePlotFilters.languages, ...activePlotFilters.vendors];
    selection.textContent = values.length ? values.join(" / ") : "All implementations";
  }
  const reset = byId("performance-filter-reset");
  if (reset) {
    reset.disabled = activeCount === 0;
  }
}

function togglePlotFilter(kind, value) {
  const selected = activePlotFilters[kind];
  if (!selected || value === "__all__") {
    return;
  }
  if (selected.has(value)) {
    selected.delete(value);
  } else {
    selected.add(value);
  }
  updateFilterControls();
  renderCurrentRanking();
  renderHistoryChart();
}

function clearPlotFilter(kind) {
  const selected = activePlotFilters[kind];
  if (!selected || !selected.size) {
    return;
  }
  selected.clear();
  updateFilterControls();
  renderCurrentRanking();
  renderHistoryChart();
}

function clearAllPlotFilters() {
  if (!activePlotFilters.languages.size && !activePlotFilters.vendors.size) {
    return;
  }
  activePlotFilters.languages.clear();
  activePlotFilters.vendors.clear();
  updateFilterControls();
  renderCurrentRanking();
  renderHistoryChart();
}

function togglePlotFilterGroup(kind) {
  filterGroupsOpen[kind] = !filterGroupsOpen[kind];
  updateFilterControls();
}

function createModeTabs() {
  const tablist = byId("performance-mode-tabs");
  if (tablist.children.length) {
    return;
  }
  tablist.setAttribute("role", "tablist");
  tablist.setAttribute("aria-label", "Benchmark mode");
  for (const [mode, config] of Object.entries(modeConfig)) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "plot-tab";
    button.id = `plot-tab-${mode}`;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-controls", "plot-panel");
    button.addEventListener("click", () => selectPlotMode(mode));
    button.addEventListener("keydown", (event) => {
      const modes = Object.keys(modeConfig);
      const currentIndex = modes.indexOf(activePlotMode);
      let nextIndex = currentIndex;
      if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % modes.length;
      if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + modes.length) % modes.length;
      if (event.key === "Home") nextIndex = 0;
      if (event.key === "End") nextIndex = modes.length - 1;
      if (nextIndex !== currentIndex) {
        event.preventDefault();
        selectPlotMode(modes[nextIndex], true);
      }
    });
    const label = document.createElement("span");
    label.textContent = config.label;
    const title = document.createElement("strong");
    title.textContent = config.title;
    const metric = document.createElement("small");
    metric.textContent = config.metricDetail;
    button.append(label, title, metric);
    tablist.append(button);
  }
  updateModeTabs();
}

function updateModeTabs() {
  for (const [mode] of Object.entries(modeConfig)) {
    const button = byId(`plot-tab-${mode}`);
    const selected = mode === activePlotMode;
    button.setAttribute("aria-selected", selected ? "true" : "false");
    button.tabIndex = selected ? 0 : -1;
  }
}

function selectPlotMode(mode, moveFocus = false) {
  if (!modeConfig[mode]) {
    return;
  }
  activePlotMode = mode;
  updateModeTabs();
  updateFilterControls();
  renderCurrentRanking();
  renderHistoryChart();
  if (moveFocus) {
    byId(`plot-tab-${mode}`).focus({ preventScroll: true });
  }
}

function setFilterPanelOpen(open, restoreFocus = false) {
  const panel = byId("performance-filter-panel");
  const toggle = byId("performance-filter-toggle");
  if (!panel || !toggle) {
    return;
  }
  panel.hidden = !open;
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
  if (!open && restoreFocus) {
    toggle.focus({ preventScroll: true });
  }
}

function ensureControls() {
  if (controlsReady) {
    return;
  }
  createModeTabs();
  const reset = document.createElement("button");
  reset.type = "button";
  reset.id = "performance-filter-reset";
  reset.className = "plot-filter-reset";
  reset.textContent = "Reset";
  reset.disabled = true;
  reset.addEventListener("click", clearAllPlotFilters);
  byId("performance-filters").append(reset);

  filterTrigger = byId("performance-filter-toggle");
  filterTrigger.addEventListener("click", () => {
    const open = filterTrigger.getAttribute("aria-expanded") !== "true";
    setFilterPanelOpen(open);
  });
  if (!window.matchMedia("(max-width: 680px)").matches) {
    setFilterPanelOpen(true);
  }
  controlsReady = true;
  updateFilterControls();
}

function setStateMessage(element, state, title, detail = "") {
  element.replaceChildren();
  const strong = document.createElement("strong");
  strong.textContent = title;
  element.append(strong);
  if (detail) {
    const text = document.createElement("span");
    text.textContent = detail;
    element.append(text);
  }
  element.dataset.state = state;
}

function renderSummary() {
  const sourceLabel = byId("performance-source");
  const timestamp = byId("performance-timestamp");
  const availability = byId("performance-availability");
  if (currentState === "loading") {
    sourceLabel.textContent = "Waiting for perf-results.json";
    timestamp.textContent = "Waiting for benchmark timestamp";
    availability.textContent = "Checking benchmark data";
    return;
  }
  if (currentState === "error") {
    sourceLabel.textContent = "perf-results.json unavailable";
    timestamp.textContent = "Generated timestamp unavailable";
    availability.textContent = "Current benchmark unavailable; retry when the artifact is published";
    return;
  }
  const totalSources = Array.isArray(activeSnapshot.sources) ? activeSnapshot.sources.length : 0;
  const availableSources = activeSnapshot.sources.filter((source) => !source.missing).length;
  const completedRows = activeSnapshot.rows.filter((row) => row.status === "ok").length;
  const event = activeSnapshot.event_name || "benchmark run";
  sourceLabel.textContent = `${event} | ${availableSources}/${totalSources} sources available`;
  timestamp.textContent = activeSnapshot.generated_at ? String(activeSnapshot.generated_at) : "Generated timestamp unavailable";
  availability.textContent = `${completedRows} completed result${completedRows === 1 ? "" : "s"}`;
}

function rowDisplayName(row) {
  return row.implementation === "coquic" && row.congestion_control ? `coquic[${row.congestion_control}]` : row.implementation;
}

function roleUtilization(row, role) {
  const utilization = row.utilization && typeof row.utilization === "object" ? row.utilization[role] : null;
  return utilization && typeof utilization === "object" ? utilization : {};
}

function profileFor(row, role) {
  const profiles = row.profiles && typeof row.profiles === "object" ? row.profiles[role] : null;
  return profiles && typeof profiles === "object" ? profiles : {};
}

function artifactUrl(path) {
  if (!path) {
    return "";
  }
  return `./perf-artifacts/${path}`;
}

function hasPerfDetails(row) {
  return Object.keys(roleUtilization(row, "client")).length
    || Object.keys(roleUtilization(row, "server")).length
    || Object.keys(profileFor(row, "client")).length
    || Object.keys(profileFor(row, "server")).length;
}

function metricDisplayName(row) {
  const config = modeConfig[row.mode] || modeConfig.bulk;
  return `${formatNumber(row[config.metric], config.decimals)} ${config.unit}`;
}

function renderDetailStatCell(label, value, detail = "") {
  const cell = document.createElement("span");
  cell.className = "perf-detail-stat";
  const key = document.createElement("small");
  key.textContent = label;
  const strong = document.createElement("strong");
  strong.textContent = value;
  cell.append(key, strong);
  if (detail) {
    const meta = document.createElement("em");
    meta.textContent = detail;
    cell.append(meta);
  }
  return cell;
}

function renderDetailUtilizationRows(util) {
  const cpuRow = document.createElement("div");
  cpuRow.className = "utilization-metric-row";
  const cpuLabel = document.createElement("span");
  cpuLabel.className = "utilization-metric-row-label";
  cpuLabel.textContent = "CPU";
  cpuRow.append(
    cpuLabel,
    renderDetailStatCell("avg", formatPercent(util.cpu_utilization_avg), `${formatCpuPercent(util.cpu_percent_avg)} raw`),
    renderDetailStatCell("max", formatPercent(util.cpu_utilization_max), `${formatCpuPercent(util.cpu_percent_max)} raw`),
  );

  const memoryRow = document.createElement("div");
  memoryRow.className = "utilization-metric-row";
  const memoryLabel = document.createElement("span");
  memoryLabel.className = "utilization-metric-row-label";
  memoryLabel.textContent = "Memory";
  memoryRow.append(
    memoryLabel,
    renderDetailStatCell("avg", formatBytes(util.memory_bytes_avg), util.samples ? `${util.samples} samples` : ""),
    renderDetailStatCell("max", formatBytes(util.memory_bytes_max), "peak"),
  );
  return [cpuRow, memoryRow];
}

function profileLabel(row, role) {
  const profile = profileFor(row, role);
  if (profile.svg_file) {
    return "flamegraph ready";
  }
  return profile.status || "unavailable";
}

function renderDetailProfileLink(row, role) {
  const profile = profileFor(row, role);
  const item = document.createElement("article");
  item.className = "detail-profile-card";
  const title = document.createElement("div");
  title.className = "detail-profile-title";
  const label = document.createElement("strong");
  label.textContent = role;
  const status = document.createElement("span");
  status.textContent = profileLabel(row, role);
  title.append(label, status);

  const links = document.createElement("div");
  links.className = "detail-profile-links";
  if (profile.svg_file) {
    const flamegraphLabel = `${rowDisplayName(row)} ${role} flamegraph`;
    const flamegraphUrl = artifactUrl(profile.svg_file);
    const preview = document.createElement("div");
    preview.className = "detail-flamegraph";
    const frame = document.createElement("iframe");
    frame.className = "detail-flamegraph-frame";
    frame.src = flamegraphUrl;
    frame.title = flamegraphLabel;
    frame.loading = "lazy";
    const fullscreen = document.createElement("button");
    fullscreen.type = "button";
    fullscreen.className = "detail-flamegraph-fullscreen-button";
    fullscreen.setAttribute("aria-label", `Expand ${flamegraphLabel}`);
    fullscreen.title = "Expand flamegraph";
    fullscreen.dataset.flamegraphUrl = flamegraphUrl;
    fullscreen.dataset.flamegraphLabel = flamegraphLabel;
    fullscreen.append(makeIcon("info"));
    fullscreen.addEventListener("click", () => openFlamegraphDialog(row, role, fullscreen));
    preview.append(frame, fullscreen);
    item.append(preview);

    const openSvg = document.createElement("a");
    openSvg.href = flamegraphUrl;
    decorateExternalLink(openSvg, `${row.implementation} ${role} flamegraph`);
    openSvg.textContent = "Open SVG";
    links.append(openSvg);
  }
  if (profile.log_file) {
    const log = document.createElement("a");
    log.href = artifactUrl(profile.log_file);
    decorateExternalLink(log, `${row.implementation} ${role} perf log`);
    log.textContent = "Perf log";
    links.append(log);
  }
  if (!links.children.length) {
    const empty = document.createElement("span");
    empty.textContent = profile.reason || "No profile artifact for this endpoint.";
    links.append(empty);
  }
  item.prepend(title);
  item.append(links);
  return item;
}

function populateDetailDialog(row) {
  const title = byId("perf-detail-title");
  title.textContent = `${rowDisplayName(row)} details`;
  const body = byId("perf-detail-body");
  body.replaceChildren();

  const summary = document.createElement("div");
  summary.className = "perf-detail-summary";
  summary.append(
    renderDetailStatCell("metric", metricDisplayName(row), modeConfig[row.mode]?.metricLabel || "selected"),
    renderDetailStatCell("elapsed", `${row.elapsed_ms ?? "-"} ms`),
    renderDetailStatCell("p50", `${formatNumber(row.p50_us, 0)} us`),
    renderDetailStatCell("p99", `${formatNumber(row.p99_us, 0)} us`),
  );

  const utilizationSection = document.createElement("section");
  utilizationSection.className = "perf-detail-section";
  const utilizationTitle = document.createElement("h3");
  utilizationTitle.textContent = "Endpoint utilization";
  const utilizationGrid = document.createElement("div");
  utilizationGrid.className = "perf-detail-utilization";
  for (const role of ["client", "server"]) {
    const card = document.createElement("article");
    card.className = "perf-detail-endpoint";
    const roleTitle = document.createElement("h4");
    roleTitle.textContent = role;
    const metrics = document.createElement("div");
    metrics.className = "perf-detail-metrics";
    metrics.append(...renderDetailUtilizationRows(roleUtilization(row, role)));
    card.append(roleTitle, metrics);
    utilizationGrid.append(card);
  }
  utilizationSection.append(utilizationTitle, utilizationGrid);

  const profileSection = document.createElement("section");
  profileSection.className = "perf-detail-section";
  const profileTitle = document.createElement("h3");
  profileTitle.textContent = "Perf flamegraphs";
  const profileGrid = document.createElement("div");
  profileGrid.className = "perf-detail-profiles";
  profileGrid.append(renderDetailProfileLink(row, "client"), renderDetailProfileLink(row, "server"));
  profileSection.append(profileTitle, profileGrid);
  body.append(summary, utilizationSection, profileSection);
}

function closeFlamegraphDialog(restoreFocus = true) {
  const dialog = byId("perf-flamegraph-dialog");
  if (dialog.open) {
    dialog.close();
  }
  byId("performance-page")?.removeAttribute("data-flamegraph-open");
  const trigger = perfFlamegraphTrigger;
  perfFlamegraphTrigger = null;
  if (restoreFocus && trigger?.isConnected) {
    trigger.focus({ preventScroll: true });
  }
}

function openFlamegraphDialog(row, role, trigger) {
  const profile = profileFor(row, role);
  const url = artifactUrl(profile.svg_file);
  if (!url) {
    return;
  }
  closeFlamegraphDialog(false);
  perfFlamegraphTrigger = trigger;
  const dialog = byId("perf-flamegraph-dialog");
  byId("perf-flamegraph-title").textContent = `${rowDisplayName(row)} ${role} flamegraph`;
  const body = byId("perf-flamegraph-body");
  body.replaceChildren();
  const frame = document.createElement("iframe");
  frame.className = "detail-flamegraph-frame detail-flamegraph-frame--fullscreen";
  frame.src = url;
  frame.title = `${rowDisplayName(row)} ${role} flamegraph`;
  const links = document.createElement("div");
  links.className = "detail-profile-links";
  const openSvg = document.createElement("a");
  openSvg.href = url;
  decorateExternalLink(openSvg, `${row.implementation} ${role} flamegraph`);
  openSvg.textContent = "Open SVG";
  links.append(openSvg);
  if (profile.log_file) {
    const log = document.createElement("a");
    log.href = artifactUrl(profile.log_file);
    decorateExternalLink(log, `${row.implementation} ${role} perf log`);
    log.textContent = "Perf log";
    links.append(log);
  }
  body.append(frame, links);
  dialog.showModal();
  byId("performance-page")?.setAttribute("data-flamegraph-open", "true");
  byId("perf-flamegraph-close").focus({ preventScroll: true });
}

function closePerfDetailModal(restoreFocus = true) {
  closeFlamegraphDialog(false);
  const dialog = byId("perf-detail-dialog");
  if (dialog.open) {
    dialog.close();
  }
  byId("performance-page")?.removeAttribute("data-detail-open");
  const trigger = perfDetailTrigger;
  perfDetailTrigger = null;
  if (restoreFocus && trigger?.isConnected) {
    trigger.focus({ preventScroll: true });
  }
}

function openPerfDetail(row, trigger) {
  closePerfDetailModal(false);
  perfDetailTrigger = trigger;
  populateDetailDialog(row);
  const dialog = byId("perf-detail-dialog");
  dialog.showModal();
  byId("performance-page")?.setAttribute("data-detail-open", "true");
  byId("perf-detail-close").focus({ preventScroll: true });
}

function renderPerfDetailButton(row) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "bar-detail-button";
  button.disabled = !hasPerfDetails(row);
  button.title = button.disabled ? "No utilization or profile metadata for this run" : "Show utilization and flamegraph details";
  button.setAttribute("aria-label", `Show utilization and flamegraph details for ${rowDisplayName(row)}`);
  button.append(makeIcon("info"));
  button.addEventListener("click", () => openPerfDetail(row, button));
  return button;
}

function renderCurrentRanking() {
  const ranking = byId("performance-ranking");
  const content = byId("performance-ranking-content");
  const panel = byId("plot-panel");
  const skeleton = byId("performance-current-skeleton");
  const state = byId("performance-current-state");
  const unit = byId("performance-ranking-unit");
  const config = modeConfig[activePlotMode];
  unit.textContent = config.metricDetail;
  skeleton.hidden = currentState !== "loading";
  panel.setAttribute("aria-labelledby", `plot-tab-${activePlotMode}`);
  if (currentState === "loading") {
    content.hidden = true;
    panel.hidden = true;
    setStateMessage(state, "loading", "Current benchmark loading", "Current evidence will appear before retained history.");
    ranking.setAttribute("aria-busy", "true");
    return;
  }
  if (currentState === "error") {
    content.hidden = true;
    panel.hidden = true;
    setStateMessage(state, "error", "Benchmark data unavailable", "perf-results.json could not be loaded or did not match the benchmark schema. Retry after the artifact is published.");
    ranking.setAttribute("aria-busy", "false");
    return;
  }

  const allRows = leaderboardRows(activePlotMode, { applyFilters: false });
  const rows = leaderboardRows(activePlotMode);
  ranking.setAttribute("aria-busy", "false");
  if (!allRows.length) {
    content.hidden = false;
    panel.hidden = false;
    panel.replaceChildren();
    setStateMessage(state, "ready", "No completed benchmark rows loaded", "The source responded, but this mode has no successful results.");
    return;
  }
  const stateDetail = `${rows.length} of ${allRows.length} completed implementation result${allRows.length === 1 ? "" : "s"} shown.`;
  setStateMessage(state, "ready", "Current ranking available", stateDetail);
  content.hidden = false;
  panel.hidden = false;
  panel.replaceChildren(renderBarplot(activePlotMode, rows, allRows));
}

function renderBarplot(mode, rows, unfilteredRows) {
  const config = modeConfig[mode];
  const plot = document.createElement("div");
  plot.className = "plot performance-ranking-panel";
  const heading = document.createElement("div");
  heading.className = "performance-panel-heading";
  const title = document.createElement("h3");
  title.textContent = config.title;
  const subtitle = document.createElement("p");
  subtitle.textContent = `${config.metricLabel} | ${config.unit}`;
  heading.append(title, subtitle);
  const list = document.createElement("div");
  list.className = "bar-list performance-bar-list";
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = unfilteredRows.length ? "No implementations match the current filters." : "No completed benchmark rows loaded.";
    list.append(empty);
    plot.append(heading, list);
    return plot;
  }

  const maxValue = Math.max(...rows.map((row) => Number(row[config.metric])));
  list.replaceChildren(...rows.map((row, index) => {
    const value = Number(row[config.metric]);
    const element = document.createElement("article");
    const isCoquicFamily = isCoquicFamilyImplementation(row.implementation);
    element.className = `bar-row performance-bar-row${isCoquicFamily ? " own-impl coquic-family" : ""}`;
    element.setAttribute("aria-label", `${rowDisplayName(row)}, ${formatNumber(value, config.decimals)} ${config.unit}`);

    const marker = document.createElement("span");
    marker.className = "performance-family-marker";
    marker.setAttribute("aria-hidden", "true");

    const rankBadge = document.createElement("span");
    rankBadge.className = "rank-badge";
    rankBadge.title = `Rank ${index + 1}`;
    rankBadge.textContent = String(index + 1);

    const label = document.createElement("div");
    label.className = "bar-label";
    const info = implementationInfo(row.implementation);
    label.append(renderBarImplementationIdentity(row.implementation, info, libraryVersionLabel(row), rowDisplayName(row)));

    const track = document.createElement("div");
    track.className = "bar-track";
    track.setAttribute("role", "img");
    track.setAttribute("aria-label", `${rowDisplayName(row)} relative performance ${formatNumber(value, config.decimals)} ${config.unit}`);
    const fill = document.createElement("div");
    fill.className = "bar-fill performance-bar-fill";
    fill.style.setProperty("--bar-width", `${maxValue > 0 ? Math.max((value / maxValue) * 100, 0.8) : 0}%`);
    track.append(fill);

    const metricValue = document.createElement("div");
    metricValue.className = "bar-value";
    const metricText = document.createElement("span");
    metricText.textContent = `${formatNumber(value, config.decimals)} ${config.unit}`;
    metricValue.append(metricText, renderPerfDetailButton(row));
    element.append(marker, rankBadge, label, track, metricValue);
    return element;
  }));
  plot.append(heading, list);
  return plot;
}

function historySnapshots() {
  return Array.isArray(activeHistory.snapshots) ? activeHistory.snapshots : [];
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

function seriesMarker(index) {
  return ["circle", "square", "diamond", "triangle", "cross", "ring"][index % 6];
}

function setSeriesStyle(element, index) {
  element.dataset.seriesIndex = String(index);
  element.dataset.marker = seriesMarker(index);
  if (index < 6) {
    element.style.setProperty("--series-color", `var(--chart-${index + 1})`);
  } else {
    element.classList.add("performance-series-secondary");
  }
}

function renderSeriesMarker(markerName, x, y, className = "trend-point") {
  if (markerName === "square") {
    const square = makeSvgElement("rect");
    square.setAttribute("x", x - 3.2);
    square.setAttribute("y", y - 3.2);
    square.setAttribute("width", "6.4");
    square.setAttribute("height", "6.4");
    square.setAttribute("class", className);
    return square;
  }
  if (markerName === "diamond") {
    const diamond = makeSvgElement("path");
    diamond.setAttribute("d", `M ${x} ${y - 4} L ${x + 4} ${y} L ${x} ${y + 4} L ${x - 4} ${y} Z`);
    diamond.setAttribute("class", className);
    return diamond;
  }
  if (markerName === "triangle") {
    const triangle = makeSvgElement("path");
    triangle.setAttribute("d", `M ${x} ${y - 4} L ${x + 4} ${y + 3.5} L ${x - 4} ${y + 3.5} Z`);
    triangle.setAttribute("class", className);
    return triangle;
  }
  if (markerName === "cross") {
    const cross = makeSvgElement("path");
    cross.setAttribute("d", `M ${x - 3.5} ${y - 3.5} L ${x + 3.5} ${y + 3.5} M ${x + 3.5} ${y - 3.5} L ${x - 3.5} ${y + 3.5}`);
    cross.setAttribute("class", className);
    return cross;
  }
  const circle = makeSvgElement("circle");
  circle.setAttribute("cx", x);
  circle.setAttribute("cy", y);
  circle.setAttribute("r", markerName === "ring" ? "3.5" : "3");
  circle.setAttribute("class", `${className}${markerName === "ring" ? " trend-point-ring" : ""}`);
  return circle;
}

function renderTrendDataTable(mode, snapshots, valuesByImplementation) {
  const details = document.createElement("details");
  details.className = "performance-data-table";
  const summary = document.createElement("summary");
  summary.textContent = "Data table";
  details.append(summary);
  const wrapper = document.createElement("div");
  wrapper.className = "performance-data-table__scroll";
  wrapper.tabIndex = 0;
  const table = document.createElement("table");
  const caption = document.createElement("caption");
  caption.textContent = `${modeConfig[mode].title} values by retained snapshot`;
  table.append(caption);
  const head = document.createElement("thead");
  const headRow = document.createElement("tr");
  const implementationHead = document.createElement("th");
  implementationHead.scope = "col";
  implementationHead.textContent = "Implementation";
  headRow.append(implementationHead);
  for (const snapshot of snapshots) {
    const cell = document.createElement("th");
    cell.scope = "col";
    cell.textContent = snapshot.date || snapshot.generated_at || "latest";
    headRow.append(cell);
  }
  head.append(headRow);
  const body = document.createElement("tbody");
  for (const [implementation, points] of valuesByImplementation.entries()) {
    const row = document.createElement("tr");
    const name = document.createElement("th");
    name.scope = "row";
    name.textContent = implementation;
    row.append(name);
    for (const point of points) {
      const cell = document.createElement("td");
      cell.textContent = point.value === null ? "-" : `${formatNumber(point.value, modeConfig[mode].decimals)} ${modeConfig[mode].unit}`;
      row.append(cell);
    }
    body.append(row);
  }
  table.append(head, body);
  wrapper.append(table);
  details.append(wrapper);
  return details;
}

function renderTrendChart(mode) {
  const config = modeConfig[mode];
  const snapshots = historySnapshots();
  const chart = document.createElement("section");
  chart.className = "trend-chart performance-trend-chart";
  chart.tabIndex = 0;
  chart.setAttribute("role", "region");
  chart.setAttribute("aria-label", `${config.title} trend comparison`);

  const heading = document.createElement("div");
  heading.className = "trend-head";
  const title = document.createElement("h3");
  title.textContent = config.title;
  const subtitle = document.createElement("p");
  subtitle.textContent = `${config.metricDetail} over ${snapshots.length} retained snapshot${snapshots.length === 1 ? "" : "s"}`;
  heading.append(title, subtitle);

  const valuesByImplementation = new Map();
  let maxValue = 0;
  for (const implementation of implementationOrder) {
    if (!rowPassesPlotFilters({ implementation })) {
      continue;
    }
    const points = snapshots.map((snapshot, index) => {
      const value = bestHistoryValue(snapshot, implementation, mode);
      if (value !== null) maxValue = Math.max(maxValue, value);
      return { index, value };
    });
    if (points.some((point) => point.value !== null)) {
      valuesByImplementation.set(implementation, points);
    }
  }
  if (!valuesByImplementation.size || maxValue <= 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = activePlotFilters.languages.size || activePlotFilters.vendors.size
      ? "No history series match the current filters."
      : "No completed history rows for this mode.";
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
  svg.setAttribute("aria-label", `${config.title} trend chart in ${config.unit}`);

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
  if (snapshots.length > 3) dateLabelIndexes.add(Math.floor((snapshots.length - 1) / 2));
  for (const index of dateLabelIndexes) {
    const label = makeSvgElement("text");
    label.setAttribute("class", "trend-axis-label");
    label.setAttribute("x", xForIndex(index));
    label.setAttribute("y", height - 8);
    label.setAttribute("text-anchor", index === 0 ? "start" : index === snapshots.length - 1 ? "end" : "middle");
    label.textContent = formatDateLabel(snapshots[index]?.date);
    svg.append(label);
  }

  const tooltip = document.createElement("div");
  tooltip.className = "trend-tooltip";
  tooltip.setAttribute("role", "tooltip");
  const interactivePoints = [];
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
    tooltip.style.left = `${Math.min(Math.max(pointX + 12, 8), Math.max(chartRect.width - 180, 8))}px`;
    tooltip.style.top = `${Math.max(pointY - 56, 8)}px`;
  }
  function hideTrendTooltip() {
    tooltip.classList.remove("visible");
  }

  for (const [seriesIndex, [implementation, points]] of [...valuesByImplementation.entries()].entries()) {
    const filtered = points.filter((point) => point.value !== null);
    const pathData = filtered.map((point, index) => `${index === 0 ? "M" : "L"} ${xForIndex(point.index).toFixed(2)} ${yForValue(point.value).toFixed(2)}`).join(" ");
    const path = makeSvgElement("path");
    const isCoquicFamily = isCoquicFamilyImplementation(implementation);
    path.setAttribute("class", `trend-line${isCoquicFamily ? " coquic-family" : ""}`);
    path.setAttribute("d", pathData);
    setSeriesStyle(path, seriesIndex);
    svg.append(path);

    for (const point of filtered) {
      const x = xForIndex(point.index);
      const y = yForValue(point.value);
      const detail = {
        title: implementation,
        value: `${formatNumber(point.value, config.decimals)} ${config.unit}`,
        date: snapshots[point.index].date || snapshots[point.index].generated_at || "latest",
      };
      const marker = renderSeriesMarker(seriesMarker(seriesIndex), x, y);
      setSeriesStyle(marker, seriesIndex);
      if (isCoquicFamily) marker.classList.add("coquic-family");
      svg.append(marker);
      const hitPoint = makeSvgElement("circle");
      hitPoint.setAttribute("class", "trend-hit-point");
      hitPoint.setAttribute("cx", x);
      hitPoint.setAttribute("cy", y);
      hitPoint.setAttribute("r", "10");
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

  function showNearestTrendPoint(event) {
    if (!interactivePoints.length) return;
    const svgRect = svg.getBoundingClientRect();
    const x = ((event.clientX - svgRect.left) / svgRect.width) * width;
    const y = ((event.clientY - svgRect.top) / svgRect.height) * height;
    const nearest = interactivePoints.reduce((best, point) => {
      const distance = (point.x - x) ** 2 + (point.y - y) ** 2;
      return !best || distance < best.distance ? { point, distance } : best;
    }, null);
    if (nearest) showTrendTooltip(event, nearest.point.detail, nearest.point.x, nearest.point.y);
  }
  svg.addEventListener("mousemove", showNearestTrendPoint);
  svg.addEventListener("mouseleave", hideTrendTooltip);

  const legend = document.createElement("div");
  legend.className = "trend-legend";
  for (const [seriesIndex, implementation] of [...valuesByImplementation.keys()].entries()) {
    const info = implementationInfo(implementation);
    const item = document.createElement("span");
    if (isCoquicFamilyImplementation(implementation)) item.classList.add("coquic-family");
    const marker = document.createElement("i");
    marker.className = `trend-marker trend-marker--${seriesMarker(seriesIndex)}`;
    setSeriesStyle(marker, seriesIndex);
    marker.setAttribute("aria-hidden", "true");
    const text = document.createElement("b");
    text.textContent = implementation;
    item.append(marker, text);
    if (info.familyLabel) {
      const family = document.createElement("em");
      family.className = "trend-family-chip";
      family.textContent = info.surfaceLabel || info.familyLabel;
      item.append(family);
    }
    const meta = document.createElement("small");
    meta.textContent = `${info.company} | ${info.language} | ${libraryVersionLabel(implementation)}`;
    item.append(meta);
    legend.append(item);
  }
  chart.append(heading, svg, tooltip, legend, renderTrendDataTable(mode, snapshots, valuesByImplementation));
  return chart;
}

function renderHistoryChart() {
  const trend = byId("performance-trend");
  const history = byId("performance-history");
  const state = byId("performance-history-state");
  const unit = byId("performance-history-unit");
  unit.textContent = historyState === "ready" ? modeConfig[activePlotMode].metricDetail : historyState === "loading" ? "History loading" : "Unavailable";
  if (historyState === "loading") {
    history.setAttribute("aria-busy", "true");
    trend.replaceChildren(renderLoadingSkeleton("history"));
    setStateMessage(state, "loading", "History loading", "Current ranking remains available while retained snapshots load.");
    return;
  }
  if (historyState === "error") {
    history.setAttribute("aria-busy", "false");
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No performance history loaded.";
    trend.replaceChildren(empty);
    setStateMessage(state, "error", "History unavailable", "Current benchmark evidence is retained. Retry when history artifacts are available.");
    return;
  }
  history.setAttribute("aria-busy", "false");
  const snapshots = historySnapshots();
  if (!snapshots.length) {
    trend.replaceChildren();
    setStateMessage(state, "ready", "No retained history", "No history snapshots were published for this benchmark.");
    return;
  }
  setStateMessage(state, "ready", "History available", `${snapshots.length} retained snapshot${snapshots.length === 1 ? "" : "s"}.`);
  trend.replaceChildren(renderTrendChart(activePlotMode));
}

function renderLoadingSkeleton(kind) {
  const skeleton = document.createElement("div");
  skeleton.className = `performance-skeleton performance-skeleton--${kind}`;
  skeleton.setAttribute("aria-hidden", "true");
  for (let index = 0; index < (kind === "history" ? 5 : 4); index += 1) {
    skeleton.append(document.createElement("span"));
  }
  return skeleton;
}

function isValidSnapshot(snapshot) {
  return Boolean(snapshot && Array.isArray(snapshot.rows) && Array.isArray(snapshot.sources));
}

function normalizeHistorySnapshot(snapshot, metadata = {}) {
  if (!isValidSnapshot(snapshot)) {
    return null;
  }
  return {
    ...snapshot,
    date: snapshot.date || metadata.date || dateFromGeneratedAt(snapshot.generated_at || metadata.generated_at),
    generated_at: snapshot.generated_at || metadata.generated_at,
    event_name: snapshot.event_name || metadata.event_name,
    commit: snapshot.commit || metadata.commit,
  };
}

function isSafePerfHistoryPath(path) {
  return typeof path === "string" && /^[0-9A-Za-z._-]+\.json$/.test(path) && path !== "index.json";
}

async function loadPerfHistoryFromIndex() {
  const response = await fetch("./perf-history/index.json", { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const index = await response.json();
  if (!index || !Array.isArray(index.snapshots)) throw new Error("invalid perf-history/index.json");
  const entries = index.snapshots.filter((entry) => entry && isSafePerfHistoryPath(entry.path)).slice(-perfHistorySnapshotLimit);
  const loaded = await Promise.all(entries.map(async (entry) => {
    try {
      const snapshotResponse = await fetch(`./perf-history/${entry.path}`, { cache: "force-cache" });
      if (!snapshotResponse.ok) throw new Error(`HTTP ${snapshotResponse.status}`);
      return normalizeHistorySnapshot(await snapshotResponse.json(), entry);
    } catch {
      return null;
    }
  }));
  return {
    schema_version: 1,
    generated_at: index.generated_at || "unavailable",
    snapshots: loaded.filter(Boolean),
  };
}

async function loadLegacyPerfHistory() {
  const response = await fetch("./perf-history.json", { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const history = await response.json();
  if (!Array.isArray(history.snapshots)) throw new Error("invalid perf-history.json");
  return {
    ...history,
    snapshots: history.snapshots.map((snapshot) => normalizeHistorySnapshot(snapshot)).filter(Boolean),
  };
}

async function loadCurrentSnapshot() {
  const response = await fetch("./perf-results.json", { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const snapshot = await response.json();
  if (!isValidSnapshot(snapshot)) throw new Error("invalid perf-results.json");
  return snapshot;
}

async function loadHistory() {
  try {
    const indexed = await loadPerfHistoryFromIndex();
    if (indexed.snapshots.length) return indexed;
    return await loadLegacyPerfHistory();
  } catch {
    return await loadLegacyPerfHistory();
  }
}

function renderAll() {
  ensureControls();
  renderSummary();
  updateFilterControls();
  renderCurrentRanking();
  renderHistoryChart();
}

function setupDialogs() {
  if (dialogListenersReady) return;
  const detailDialog = byId("perf-detail-dialog");
  const flamegraphDialog = byId("perf-flamegraph-dialog");
  byId("perf-detail-close").addEventListener("click", () => closePerfDetailModal());
  byId("perf-flamegraph-close").addEventListener("click", () => closeFlamegraphDialog());
  detailDialog.addEventListener("click", (event) => {
    if (event.target === detailDialog) closePerfDetailModal();
  });
  flamegraphDialog.addEventListener("click", (event) => {
    if (event.target === flamegraphDialog) closeFlamegraphDialog();
  });
  detailDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    closePerfDetailModal();
  });
  flamegraphDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    closeFlamegraphDialog();
  });
  dialogListenersReady = true;
}

function startLoading() {
  const token = ++loadToken;
  currentState = "loading";
  historyState = "loading";
  activeSnapshot = fallbackPerfSnapshot;
  activeHistory = { schema_version: 1, generated_at: "unavailable", snapshots: [] };
  renderAll();
  setupDialogs();

  const currentPromise = loadCurrentSnapshot();
  const historyPromise = loadHistory();
  currentPromise.then((snapshot) => {
    if (token !== loadToken || !byId("performance-page")?.isConnected) return;
    activeSnapshot = snapshot;
    currentState = "ready";
    renderSummary();
    updateFilterControls();
    renderCurrentRanking();
  }).catch(() => {
    if (token !== loadToken || !byId("performance-page")?.isConnected) return;
    activeSnapshot = fallbackPerfSnapshot;
    currentState = "error";
    renderSummary();
    updateFilterControls();
    renderCurrentRanking();
  });
  historyPromise.then((history) => {
    if (token !== loadToken || !byId("performance-page")?.isConnected) return;
    activeHistory = history;
    historyState = historySnapshots().length ? "ready" : "error";
    renderHistoryChart();
  }).catch(() => {
    if (token !== loadToken || !byId("performance-page")?.isConnected) return;
    activeHistory = { schema_version: 1, generated_at: "unavailable", snapshots: [] };
    historyState = "error";
    renderHistoryChart();
  });
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    const filterPanel = byId("performance-filter-panel");
    if (filterPanel && !filterPanel.hidden && window.matchMedia("(max-width: 680px)").matches) {
      event.preventDefault();
      setFilterPanelOpen(false, true);
    }
  }
});

startLoading();
