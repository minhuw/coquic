const fallbackInteropSnapshot = {
  schema_version: 1,
  generated_at: "unavailable",
  event_name: "local",
  commit: "awaiting-ci-results",
  sources: [
    { label: "quic-go", path: "interop-results.json", missing: true },
    { label: "picoquic", path: "interop-results.json", missing: true },
    { label: "quinn", path: "interop-results.json", missing: true },
    { label: "self", path: "interop-results.json", missing: true },
  ],
  rows: [],
};

const caseOrder = [
  "handshake",
  "handshakeloss",
  "transfer",
  "keyupdate",
  "transferloss",
  "handshakecorruption",
  "transfercorruption",
  "blackhole",
  "chacha20",
  "longrtt",
  "ipv6",
  "multiplexing",
  "retry",
  "resumption",
  "zerortt",
  "v2",
  "amplificationlimit",
  "rebind-port",
  "rebind-addr",
  "connectionmigration",
  "ecn",
  "goodput",
  "crosstraffic",
];

let activeSnapshot = fallbackInteropSnapshot;
let dataSource = "waiting for interop-results.json";
let interopState = "loading";

function interopRoot() {
  return document.querySelector("[data-interop-root]");
}

function queryInterop(selector) {
  return interopRoot()?.querySelector(selector) || null;
}

function interopElement(id) {
  return queryInterop(`#${id}`);
}

function setInteropState(state, message) {
  interopState = state;
  const page = interopRoot();
  const stateLabel = interopElement("interop-state");
  const matrixRegion = interopElement("interop-matrix-region");
  page?.setAttribute("data-interop-state", state);
  page?.setAttribute("aria-busy", state === "loading" ? "true" : "false");
  stateLabel?.replaceChildren(document.createTextNode(message));
  matrixRegion?.setAttribute("aria-busy", state === "loading" ? "true" : "false");
}

function updateSnapshotContext(snapshot, available) {
  const values = available
    ? {
        generated: snapshot.generated_at || "not reported",
        event: snapshot.event_name || "not reported",
        commit: snapshot.commit || "not reported",
      }
    : { generated: "not available", event: "not available", commit: "not available" };
  const generated = queryInterop("[data-interop-generated]");
  const event = queryInterop("[data-interop-event]");
  const commit = queryInterop("[data-interop-commit]");
  generated?.replaceChildren(document.createTextNode(values.generated));
  event?.replaceChildren(document.createTextNode(values.event));
  commit?.replaceChildren(document.createTextNode(values.commit));
}

function githubAvatar(owner) {
  return `https://github.com/${owner}.png?size=64`;
}

function vendorFavicon(domain) {
  return `https://www.google.com/s2/favicons?sz=64&domain=${domain}`;
}

const deviconBase = "https://cdn.jsdelivr.net/gh/devicons/devicon@v2.17.0/icons/";

const languageIconSources = {
  C: `${deviconBase}c/c-original.svg`,
  "C++": `${deviconBase}cplusplus/cplusplus-original.svg`,
  Go: `${deviconBase}go/go-original.svg`,
  Python: `${deviconBase}python/python-original.svg`,
  Rust: `${deviconBase}rust/rust-original.svg`,
};

const implementationMeta = {
  coquic: { name: "CoQUIC", code: "CQ", sourceIcon: "./coquic-logo.svg", language: "C++", languageCode: "C++" },
  "quic-go": { name: "quic-go", code: "QG", sourceIcon: githubAvatar("quic-go"), language: "Go", languageCode: "Go" },
  quinn: { name: "quinn", code: "QN", sourceIcon: githubAvatar("quinn-rs"), language: "Rust", languageCode: "Rs" },
  picoquic: { name: "picoquic", code: "PO", sourceIcon: githubAvatar("private-octopus"), language: "C", languageCode: "C" },
  msquic: { name: "msquic", code: "MS", sourceIcon: vendorFavicon("microsoft.com"), language: "C", languageCode: "C" },
  quiche: { name: "quiche", code: "CF", sourceIcon: vendorFavicon("cloudflare.com"), language: "Rust", languageCode: "Rs" },
  quicly: { name: "quicly", code: "H2", sourceIcon: githubAvatar("h2o"), language: "C", languageCode: "C" },
  "google-quiche": { name: "google-quiche", code: "G", sourceIcon: vendorFavicon("google.com"), language: "C++", languageCode: "C++" },
  tquic: { name: "tquic", code: "TC", sourceIcon: vendorFavicon("tencent.com"), language: "Rust", languageCode: "Rs" },
  mvfst: { name: "mvfst", code: "M", sourceIcon: vendorFavicon("meta.com"), language: "C++", languageCode: "C++" },
  "s2n-quic": { name: "s2n-quic", code: "AWS", sourceIcon: vendorFavicon("aws.amazon.com"), language: "Rust", languageCode: "Rs" },
  xquic: { name: "xquic", code: "A", sourceIcon: vendorFavicon("alibabacloud.com"), language: "C", languageCode: "C" },
  aioquic: { name: "aioquic", code: "AQ", sourceIcon: githubAvatar("aiortc"), language: "Python", languageCode: "Py" },
  ngtcp2: { name: "ngtcp2", code: "NG", sourceIcon: githubAvatar("ngtcp2"), language: "C", languageCode: "C" },
  lsquic: { name: "lsquic", code: "LS", sourceIcon: vendorFavicon("litespeedtech.com"), language: "C", languageCode: "C" },
  neqo: { name: "neqo", code: "MZ", sourceIcon: vendorFavicon("mozilla.org"), language: "Rust", languageCode: "Rs" },
};

function sourceRows() {
  return (activeSnapshot.sources || []).filter((source) => !source.missing && source.server && source.client);
}

function loadedRows() {
  return activeSnapshot.rows || [];
}

function caseSortKey(name) {
  const index = caseOrder.indexOf(name);
  return index === -1 ? caseOrder.length : index;
}

function implementationOrder(names) {
  const preferred = ["coquic", "quic-go", "picoquic", "quinn", "msquic", "quiche", "ngtcp2", "lsquic", "mvfst"];
  return [...names].sort((left, right) => {
    const leftIndex = preferred.indexOf(left);
    const rightIndex = preferred.indexOf(right);
    return (leftIndex === -1 ? preferred.length : leftIndex) - (rightIndex === -1 ? preferred.length : rightIndex) || left.localeCompare(right);
  });
}

function sourceKey(server, client) {
  return `${server}->${client}`;
}

function laneSortKey(source) {
  const peer = source.server === "coquic" ? source.client : source.server;
  const direction = source.server === "coquic" ? 0 : 1;
  const orderedPeers = implementationOrder(new Set(sourceRows().map((row) => (row.server === "coquic" ? row.client : row.server))));
  const peerIndex = orderedPeers.indexOf(peer);
  return [peerIndex === -1 ? orderedPeers.length : peerIndex, direction, sourceKey(source.server, source.client)];
}

function resultToken(result) {
  if (result === "succeeded") {
    return "PASS";
  }
  if (isKnownPeerBrokenResult(result)) {
    return "KNOWN";
  }
  if (isPeerBrokenResult(result)) {
    return "PEER";
  }
  if (result === "failed") {
    return "FAIL";
  }
  if (isSkippedResult(result)) {
    return "UNSUP";
  }
  return "N/R";
}

function resultTokenForRow(row, result) {
  if (isKnownBrokenFailure(row, result)) {
    return "KNOWN";
  }
  return resultToken(result);
}

function rowResultToken(result) {
  if (result === "succeeded") {
    return "PASS";
  }
  if (isPeerBrokenResult(result)) {
    return "PEER";
  }
  if (isSkippedResult(result)) {
    return "UNSUP";
  }
  if (result === "failed") {
    return "FAIL";
  }
  return "N/R";
}

function isKnownBrokenFailure(row, result) {
  return result === "failed" && row && row.known_broken;
}

function isRowAcceptableResult(row, result) {
  return (
    result === "succeeded" ||
    isSkippedResult(result) ||
    isPeerBrokenResult(result) ||
    isKnownPeerBrokenResult(result) ||
    isKnownBrokenFailure(row, result)
  );
}

function resultClass(result, row) {
  if (result === "succeeded") {
    return "succeeded";
  }
  if (isKnownPeerBrokenResult(result) || isKnownBrokenFailure(row, result)) {
    return "known-peer-broken";
  }
  if (isPeerBrokenResult(result)) {
    return "peer-broken";
  }
  if (isSkippedResult(result)) {
    return "unsupported";
  }
  if (result === "failed") {
    return result;
  }
  return "unknown";
}

function isSkippedResult(result) {
  return result === "unsupported";
}

function isPeerBrokenResult(result) {
  return result === "peer_broken";
}

function isKnownPeerBrokenResult(result) {
  return result === "known_peer_broken";
}

function knownBrokenTitle(row) {
  const known = row && row.known_broken;
  if (!known) {
    return "";
  }
  const failed = known.failed_supported_peers ?? 0;
  const supported = known.supported_peers ?? failed;
  const unsupported = known.unsupported_peers ?? 0;
  const run = known.run || "latest";
  return ` Upstream compatibility note: ${known.peer || row.peer} ${known.role || "peer"} fails ${known.case || row.name} against ${failed}/${supported} supported peers in ${known.source || "upstream"} run ${run}${unsupported ? `; ${unsupported} unsupported upstream peers` : ""}.`;
}

function implementationDisplayName(name) {
  return (implementationMeta[name] || { name }).name;
}

function resultLabel(result, row) {
  if (result === "succeeded") {
    return "PASS";
  }
  if (isKnownPeerBrokenResult(result) || isKnownBrokenFailure(row, result)) {
    return "KNOWN PEER ISSUE";
  }
  if (isPeerBrokenResult(result)) {
    return "PEER BROKEN";
  }
  if (isSkippedResult(result)) {
    return "UNSUPPORTED";
  }
  if (result === "failed") {
    return "FAIL";
  }
  return "NOT REPORTED";
}

function resultDetails(source, test, row, result) {
  const details = row && row.details ? row.details : "";
  const known = knownBrokenTitle(row).trim();
  return {
    title: test === "all" ? "All test cases" : test,
    client: implementationDisplayName(source.client),
    server: implementationDisplayName(source.server),
    result: resultLabel(result, row),
    details: [details, known].filter(Boolean).join(" "),
  };
}

let activeTooltipTarget = null;
let pinnedTooltipTarget = null;
let focusedTooltipTarget = null;
let restoringFocusTarget = null;
let tooltipTargetSequence = 0;
let tooltipDocumentListenersAttached = false;
let focusScrollTarget = null;
let focusScrollTimer = 0;
let focusScrollBehavior = null;

function settleFocusScrollGuard() {
  focusScrollTimer = 0;
  focusScrollTarget = null;
  document.documentElement.style.scrollBehavior = focusScrollBehavior;
  focusScrollBehavior = null;
}

function isAuthoritativeTooltipTarget(target) {
  return focusedTooltipTarget === target || pinnedTooltipTarget === target;
}

function markFocusScrollTarget(target) {
  focusScrollTarget = target;
  if (focusScrollBehavior === null) {
    focusScrollBehavior = document.documentElement.style.scrollBehavior;
  }
  document.documentElement.style.scrollBehavior = "auto";
  if (focusScrollTimer) {
    window.clearTimeout(focusScrollTimer);
  }
  focusScrollTimer = window.setTimeout(settleFocusScrollGuard, 200);
}

function consumeFocusScroll() {
  if (!focusScrollTarget || document.activeElement !== focusScrollTarget) {
    return false;
  }
  if (activeTooltipTarget === focusScrollTarget) {
    positionInteropTooltip(activeTooltipTarget);
  }
  if (focusScrollTimer) {
    window.clearTimeout(focusScrollTimer);
  }
  focusScrollTimer = window.setTimeout(settleFocusScrollGuard, 200);
  return true;
}

function ensureInteropTooltip() {
  const root = interopRoot();
  if (!root) {
    return null;
  }
  let tooltip = root.querySelector(".interop-tooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.className = "interop-tooltip";
    tooltip.id = "interop-tooltip";
    tooltip.setAttribute("role", "tooltip");
    tooltip.setAttribute("aria-hidden", "true");
    tooltip.hidden = true;
    root.append(tooltip);
  }
  if (!tooltipDocumentListenersAttached) {
    tooltipDocumentListenersAttached = true;
    document.addEventListener("pointerdown", (event) => {
      const target = event.target;
      if (target instanceof Element && (target.closest(".test-cell") || target.closest(".interop-tooltip"))) {
        return;
      }
      hideInteropTooltip(true);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        hideInteropTooltip(true);
      }
    });
    document.addEventListener("scroll", () => {
      if (!consumeFocusScroll()) {
        hideInteropTooltip(true);
      }
    }, true);
  }
  return tooltip;
}

function positionInteropTooltip(target, event) {
  const tooltip = ensureInteropTooltip();
  if (!tooltip) {
    return;
  }
  const targetRect = target.getBoundingClientRect();
  const anchorX = event && typeof event.clientX === "number" ? event.clientX : targetRect.left + targetRect.width / 2;
  const anchorY = event && typeof event.clientY === "number" ? event.clientY : targetRect.top + targetRect.height / 2;
  const margin = 12;
  const gap = 12;
  const tooltipRect = tooltip.getBoundingClientRect();
  let left = anchorX + gap;
  let top = anchorY + gap;

  if (left + tooltipRect.width > window.innerWidth - margin) {
    left = Math.max(margin, anchorX - tooltipRect.width - gap);
  }
  if (top + tooltipRect.height > window.innerHeight - margin) {
    top = Math.max(margin, targetRect.top - tooltipRect.height - gap);
  }

  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${top}px`;
}

function showInteropTooltip(target, details, event) {
  const tooltip = ensureInteropTooltip();
  if (!tooltip) {
    return;
  }
  if (activeTooltipTarget && activeTooltipTarget !== target) {
    if (isAuthoritativeTooltipTarget(activeTooltipTarget)) {
      return;
    }
    hideInteropTooltip(false);
  }
  activeTooltipTarget = target;
  const title = document.createElement("strong");
  title.textContent = details.title;

  const client = tooltipLine("Client", details.client);
  const server = tooltipLine("Server", details.server);
  const result = tooltipLine("Result", details.result);

  const children = [title, client, server, result];
  if (details.details) {
    const extra = document.createElement("small");
    extra.textContent = details.details;
    children.push(extra);
  }

  tooltip.replaceChildren(...children);
  tooltip.hidden = false;
  tooltip.setAttribute("aria-hidden", "false");
  tooltip.classList.add("visible");
  target.setAttribute("aria-expanded", "true");
  positionInteropTooltip(target, event);
}

function tooltipLine(label, value) {
  const line = document.createElement("span");
  const key = document.createElement("b");
  key.textContent = label;
  line.append(key, document.createTextNode(value));
  return line;
}

function hideInteropTooltip(restoreFocus = false) {
  const tooltip = queryInterop(".interop-tooltip");
  const target = activeTooltipTarget;
  const returnFocus = restoreFocus && pinnedTooltipTarget === target;
  const targetsToCollapse = new Set([target]);
  if (restoreFocus) {
    targetsToCollapse.add(pinnedTooltipTarget);
    targetsToCollapse.add(focusedTooltipTarget);
  }
  activeTooltipTarget = null;
  if (restoreFocus || pinnedTooltipTarget === target) {
    pinnedTooltipTarget = null;
  }
  if (restoreFocus || focusedTooltipTarget === target) {
    focusedTooltipTarget = null;
  }
  if (tooltip) {
    tooltip.classList.remove("visible");
    tooltip.setAttribute("aria-hidden", "true");
    tooltip.hidden = true;
  }
  for (const collapsedTarget of targetsToCollapse) {
    collapsedTarget?.setAttribute("aria-expanded", "false");
  }
  if (returnFocus && target && document.contains(target)) {
    restoringFocusTarget = target;
    if (document.activeElement === target) {
      restoringFocusTarget = null;
    }
    target.focus({ preventScroll: true });
  }
}

function attachResultTooltip(cell, details) {
  const label = `${details.title}: client ${details.client}, server ${details.server}, result ${details.result}${details.details ? `. ${details.details}` : ""}`;
  cell.id = `interop-result-${tooltipTargetSequence += 1}`;
  cell.tabIndex = 0;
  cell.setAttribute("aria-label", label);
  cell.setAttribute("aria-controls", "interop-tooltip");
  cell.setAttribute("aria-describedby", "interop-tooltip");
  cell.setAttribute("aria-expanded", "false");
  cell.addEventListener("pointerenter", (event) => {
    showInteropTooltip(cell, details, event);
  });
  cell.addEventListener("pointermove", (event) => {
    if (activeTooltipTarget === cell) {
      positionInteropTooltip(cell, event);
    }
  });
  cell.addEventListener("pointerleave", () => {
    if (activeTooltipTarget === cell && !isAuthoritativeTooltipTarget(cell)) {
      hideInteropTooltip();
    }
  });
  cell.addEventListener("focus", () => {
    if (restoringFocusTarget === cell) {
      restoringFocusTarget = null;
      return;
    }
    if (pinnedTooltipTarget && pinnedTooltipTarget !== cell) {
      pinnedTooltipTarget = null;
    }
    focusedTooltipTarget = cell;
    markFocusScrollTarget(cell);
    showInteropTooltip(cell, details);
  });
  cell.addEventListener("blur", () => {
    if (focusedTooltipTarget === cell) {
      focusedTooltipTarget = null;
    }
    if (activeTooltipTarget === cell && !isAuthoritativeTooltipTarget(cell)) {
      hideInteropTooltip();
    }
  });
  cell.addEventListener("click", (event) => {
    event.stopPropagation();
    if (pinnedTooltipTarget && pinnedTooltipTarget !== cell) {
      pinnedTooltipTarget = null;
    }
    pinnedTooltipTarget = cell;
    focusedTooltipTarget = cell;
    markFocusScrollTarget(cell);
    showInteropTooltip(cell, details, event);
  });
}

function rowResultForTests(laneKey, tests, rowByLaneAndTest) {
  if (!tests.length) {
    return "unknown";
  }
  let sawFailed = false;
  let sawUnknown = false;
  let sawAcceptable = false;
  for (const test of tests) {
    const row = rowByLaneAndTest.get(`${laneKey}:${test}`);
    if (!row) {
      sawUnknown = true;
      continue;
    }
    const result = row.result || "unknown";
    if (isRowAcceptableResult(row, result)) {
      sawAcceptable = true;
      continue;
    }
    if (result === "failed") {
      sawFailed = true;
      continue;
    }
    sawUnknown = true;
  }
  if (sawFailed) {
    return "failed";
  }
  if (sawUnknown) {
    return "unknown";
  }
  if (sawAcceptable) {
    return "succeeded";
  }
  return "unknown";
}

function legendCategoryForResult(result, row) {
  if (result === "succeeded") {
    return "pass";
  }
  if (isKnownPeerBrokenResult(result) || isKnownBrokenFailure(row, result)) {
    return "known-peer-broken";
  }
  if (isPeerBrokenResult(result)) {
    return "peer-broken";
  }
  if (isSkippedResult(result)) {
    return "unsupported";
  }
  if (result === "failed") {
    return "failed";
  }
  return "not-reported";
}

function updateLegendCounts(lanes, tests, rowByLaneAndTest) {
  const counts = {
    pass: 0,
    unsupported: 0,
    "peer-broken": 0,
    "known-peer-broken": 0,
    failed: 0,
    "not-reported": 0,
  };

  for (const source of lanes) {
    const laneKey = sourceKey(source.server, source.client);
    for (const test of tests) {
      const row = rowByLaneAndTest.get(`${laneKey}:${test}`);
      const category = legendCategoryForResult(row ? row.result : "unknown", row);
      counts[category] += 1;
    }
  }

  for (const [category, count] of Object.entries(counts)) {
    const target = queryInterop(`[data-interop-count="${category}"]`);
    if (target) {
      target.textContent = count.toLocaleString();
    }
  }
}

function clearLegendCounts() {
  for (const category of ["pass", "unsupported", "peer-broken", "known-peer-broken", "failed", "not-reported"]) {
    const target = queryInterop(`[data-interop-count="${category}"]`);
    if (target) {
      target.textContent = "-";
    }
  }
}

function updateInteropConclusion(lanes, tests, rowByLaneAndTest) {
  const conclusion = interopElement("interop-conclusion");
  if (!conclusion) {
    return;
  }
  if (interopState === "unavailable") {
    conclusion.textContent = "Interop evidence is unavailable; no conclusion can be drawn until interop-results.json is published.";
    return;
  }
  if (!lanes.length || !tests.length) {
    conclusion.textContent = "No CoQUIC interop lanes are reported in this snapshot.";
    return;
  }

  let missing = 0;
  for (const source of lanes) {
    const laneKey = sourceKey(source.server, source.client);
    for (const test of tests) {
      if (!rowByLaneAndTest.has(`${laneKey}:${test}`)) {
        missing += 1;
      }
    }
  }
  const hasUnannotatedFailure = [...rowByLaneAndTest.values()].some(
    (row) => row.result === "failed" && !row.known_broken,
  );
  if (hasUnannotatedFailure) {
    conclusion.textContent = `Conclusion: unannotated CoQUIC failure${missing ? `; ${missing} cell${missing === 1 ? " is" : "s are"} not reported` : " requires attention"}.`;
  } else if (missing) {
    conclusion.textContent = `Conclusion: reported results are accepted or passing; ${missing} cell${missing === 1 ? " is" : "s are"} not reported.`;
  } else {
    conclusion.textContent = "Conclusion: every reported CoQUIC result is passing or an explicitly accepted exception.";
  }
}

function updateMatrixRegionFocus() {
  const region = interopElement("interop-matrix-region");
  if (!region) {
    return;
  }
  const horizontalOverflow = region.scrollWidth > region.clientWidth + 1;
  const verticalOverflow = region.scrollHeight > region.clientHeight + 1;
  region.dataset.overflow = horizontalOverflow || verticalOverflow ? "true" : "false";
  if (horizontalOverflow) {
    region.dataset.horizontalOverflow = "true";
  } else {
    delete region.dataset.horizontalOverflow;
  }
  if (horizontalOverflow || verticalOverflow) {
    region.tabIndex = 0;
  } else {
    region.removeAttribute("tabindex");
  }
}

function renderParticipantIcon(kind, iconUrl, code, label) {
  const badge = document.createElement("span");
  badge.className = `participant-identity-icon ${kind}`;
  badge.setAttribute("role", "img");
  badge.title = label;
  badge.setAttribute("aria-label", label);

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
  fallback.className = "participant-fallback";
  fallback.textContent = code;
  badge.append(fallback);
  return badge;
}

function renderParticipant(name) {
  const code = name.slice(0, 2).toUpperCase();
  const meta = implementationMeta[name] || { name, code, sourceIcon: "", language: "unknown", languageCode: "?" };
  const chip = document.createElement("span");
  chip.className = `participant-chip${name === "coquic" ? " coquic" : ""}`;

  const icons = document.createElement("span");
  icons.className = "participant-icons";
  icons.append(
    renderParticipantIcon("source", meta.sourceIcon, meta.code, meta.name),
    renderParticipantIcon("language", languageIconSources[meta.language], meta.languageCode, meta.language),
  );

  const label = document.createElement("strong");
  label.textContent = meta.name;
  chip.append(icons, label);
  return chip;
}

function renderMatrix() {
  const sources = sourceRows().filter((source) => source.server === "coquic" || source.client === "coquic");
  const rows = loadedRows().filter((row) => row.server === "coquic" || row.client === "coquic");
  const head = interopElement("matrix-head");
  const body = interopElement("matrix-body");
  const dataSourceLabel = interopElement("data-source-label");
  if (dataSourceLabel) {
    dataSourceLabel.textContent = dataSource;
  }
  if (!head || !body) {
    return;
  }

  const tests = [...new Set(rows.map((row) => row.name))].sort((left, right) => caseSortKey(left) - caseSortKey(right) || left.localeCompare(right));
  const rowByLaneAndTest = new Map(rows.map((row) => [`${sourceKey(row.server, row.client)}:${row.name}`, row]));
  const lanes = [...sources].sort((left, right) => {
    const leftKey = laneSortKey(left);
    const rightKey = laneSortKey(right);
    return leftKey[0] - rightKey[0] || leftKey[1] - rightKey[1] || leftKey[2].localeCompare(rightKey[2]);
  });
  if (interopState === "ready") {
    updateLegendCounts(lanes, tests, rowByLaneAndTest);
  } else {
    clearLegendCounts();
  }

  const headRow = document.createElement("tr");
  const rowHeader = document.createElement("th");
  rowHeader.className = "row-status-column";
  rowHeader.scope = "col";
  rowHeader.title = "Overall result across every testcase in this row";
  rowHeader.textContent = "All";
  headRow.append(rowHeader);
  const clientHeader = document.createElement("th");
  clientHeader.className = "corner";
  clientHeader.scope = "col";
  clientHeader.textContent = "Client";
  headRow.append(clientHeader);
  const serverHeader = document.createElement("th");
  serverHeader.className = "server-column";
  serverHeader.scope = "col";
  serverHeader.textContent = "Server";
  headRow.append(serverHeader);
  for (const test of tests) {
    const th = document.createElement("th");
    th.scope = "col";
    th.title = test;
    th.textContent = test;
    headRow.append(th);
  }
  head.replaceChildren(headRow);

  if (!lanes.length || !tests.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.className = "empty-cell";
    td.colSpan = Math.max(tests.length + 3, 1);
    td.textContent = "No CoQUIC interop rows loaded.";
    tr.append(td);
    body.replaceChildren(tr);
    updateInteropConclusion(lanes, tests, rowByLaneAndTest);
    updateMatrixRegionFocus();
    return;
  }

  ensureInteropTooltip();
  body.replaceChildren(
    ...lanes.map((source) => {
      const tr = document.createElement("tr");
      const laneKey = sourceKey(source.server, source.client);
      tr.dataset.client = source.client;
      tr.dataset.server = source.server;
      const rowStatusCell = document.createElement("td");
      const rowStatus = rowResultForTests(laneKey, tests, rowByLaneAndTest);
      rowStatusCell.className = `row-status-column result-cell ${resultClass(rowStatus)}`;
      rowStatusCell.dataset.result = rowStatus;
      const rowStatusControl = document.createElement("button");
      rowStatusControl.type = "button";
      rowStatusControl.className = "test-cell";
      rowStatusControl.textContent = rowResultToken(rowStatus);
      attachResultTooltip(rowStatusControl, resultDetails(source, "all", null, rowStatus));
      rowStatusCell.append(rowStatusControl);
      tr.append(rowStatusCell);

      const clientCell = document.createElement("th");
      clientCell.className = "participant-name";
      clientCell.scope = "row";
      clientCell.dataset.participant = source.client;
      clientCell.append(renderParticipant(source.client));
      tr.append(clientCell);

      const serverCell = document.createElement("td");
      serverCell.className = "server-column";
      serverCell.dataset.participant = source.server;
      serverCell.append(renderParticipant(source.server));
      tr.append(serverCell);

      for (const test of tests) {
        const td = document.createElement("td");
        const row = rowByLaneAndTest.get(`${laneKey}:${test}`);
        const result = row ? row.result : "unknown";
        td.className = `result-cell ${resultClass(result, row)}`;
        td.dataset.case = test;
        td.dataset.result = result;
        const cell = document.createElement("button");
        cell.type = "button";
        cell.className = "test-cell";
        cell.textContent = resultTokenForRow(row, result);
        attachResultTooltip(cell, resultDetails(source, test, row, result));
        td.append(cell);
        tr.append(td);
      }
      return tr;
    }),
  );
  updateInteropConclusion(lanes, tests, rowByLaneAndTest);
  updateMatrixRegionFocus();
}

function renderAll() {
  renderMatrix();
}

async function loadLiveSnapshot() {
  try {
    const response = await fetch("./interop-results.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const snapshot = await response.json();
    if (!Array.isArray(snapshot.rows) || !Array.isArray(snapshot.sources)) {
      throw new Error("invalid interop-results.json");
    }
    activeSnapshot = snapshot;
    dataSource = `interop-results.json from ${snapshot.generated_at || "latest workflow"}`;
    updateSnapshotContext(snapshot, true);
    setInteropState("ready", "Interop evidence loaded.");
  } catch {
    activeSnapshot = fallbackInteropSnapshot;
    dataSource = "interop-results.json not available yet";
    updateSnapshotContext(fallbackInteropSnapshot, false);
    setInteropState("unavailable", "Interop evidence unavailable. interop-results.json is not present yet; retry after the next workflow run.");
  }
  renderAll();
}

window.addEventListener("resize", updateMatrixRegionFocus);
loadLiveSnapshot();
