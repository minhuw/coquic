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

function githubAvatar(owner) {
  return `https://github.com/${owner}.png?size=64`;
}

function vendorFavicon(domain) {
  return `https://www.google.com/s2/favicons?sz=64&domain=${domain}`;
}

const implementationMeta = {
  coquic: { name: "CoQUIC", code: "CQ", avatar: githubAvatar("minhuw") },
  "quic-go": { name: "quic-go", code: "QG", avatar: githubAvatar("quic-go") },
  quinn: { name: "quinn", code: "QN", avatar: githubAvatar("quinn-rs") },
  picoquic: { name: "picoquic", code: "PO", avatar: githubAvatar("private-octopus") },
  msquic: { name: "msquic", code: "MS", avatar: vendorFavicon("microsoft.com") },
  quiche: { name: "quiche", code: "CF", avatar: vendorFavicon("cloudflare.com") },
  quicly: { name: "quicly", code: "H2", avatar: githubAvatar("h2o") },
  "google-quiche": { name: "google-quiche", code: "G", avatar: vendorFavicon("google.com") },
  tquic: { name: "tquic", code: "TC", avatar: vendorFavicon("tencent.com") },
  mvfst: { name: "mvfst", code: "M", avatar: vendorFavicon("meta.com") },
  "s2n-quic": { name: "s2n-quic", code: "AWS", avatar: vendorFavicon("aws.amazon.com") },
  xquic: { name: "xquic", code: "A", avatar: vendorFavicon("alibabacloud.com") },
  aioquic: { name: "aioquic", code: "AQ", avatar: githubAvatar("aiortc") },
  ngtcp2: { name: "ngtcp2", code: "NG", avatar: githubAvatar("ngtcp2") },
  lsquic: { name: "lsquic", code: "LS", avatar: vendorFavicon("litespeedtech.com") },
  neqo: { name: "neqo", code: "MZ", avatar: vendorFavicon("mozilla.org") },
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
    return "pass";
  }
  if (result === "failed") {
    return "fail";
  }
  if (result === "unsupported") {
    return "skip";
  }
  return "-";
}

function resultClass(result) {
  if (result === "succeeded" || result === "failed" || result === "unsupported") {
    return result;
  }
  return "unknown";
}

function rowResultForTests(laneKey, tests, rowByLaneAndTest) {
  if (!tests.length) {
    return "unknown";
  }
  let sawFailed = false;
  let sawUnknown = false;
  let sawSucceeded = false;
  let sawUnsupported = false;
  for (const test of tests) {
    const result = rowByLaneAndTest.get(`${laneKey}:${test}`)?.result || "unknown";
    if (result === "failed") {
      sawFailed = true;
      continue;
    }
    if (result === "unsupported") {
      sawUnsupported = true;
      continue;
    }
    if (result === "succeeded") {
      sawSucceeded = true;
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
  if (sawSucceeded) {
    return "succeeded";
  }
  return sawUnsupported ? "unsupported" : "unknown";
}

function renderParticipant(name) {
  const meta = implementationMeta[name] || { name, code: name.slice(0, 2).toUpperCase(), avatar: "" };
  const chip = document.createElement("span");
  chip.className = `participant-chip${name === "coquic" ? " coquic" : ""}`;

  if (meta.avatar) {
    const image = document.createElement("img");
    image.src = meta.avatar;
    image.alt = "";
    image.loading = "lazy";
    image.decoding = "async";
    image.referrerPolicy = "no-referrer";
    image.addEventListener("error", () => image.remove(), { once: true });
    chip.append(image);
  }

  const fallback = document.createElement("span");
  fallback.className = "participant-fallback";
  fallback.textContent = meta.code;
  const label = document.createElement("strong");
  label.textContent = meta.name;
  chip.append(fallback, label);
  return chip;
}

function renderMatrix() {
  const sources = sourceRows().filter((source) => source.server === "coquic" || source.client === "coquic");
  const rows = loadedRows().filter((row) => row.server === "coquic" || row.client === "coquic");
  const head = document.getElementById("matrix-head");
  const body = document.getElementById("matrix-body");
  const dataSourceLabel = document.getElementById("data-source-label");
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

  const headRow = document.createElement("tr");
  const rowHeader = document.createElement("th");
  rowHeader.className = "row-status-column";
  rowHeader.title = "Overall result across every testcase in this row";
  rowHeader.textContent = "All";
  headRow.append(rowHeader);
  const clientHeader = document.createElement("th");
  clientHeader.className = "corner";
  clientHeader.textContent = "Client";
  headRow.append(clientHeader);
  const serverHeader = document.createElement("th");
  serverHeader.className = "server-column";
  serverHeader.textContent = "Server";
  headRow.append(serverHeader);
  for (const test of tests) {
    const th = document.createElement("th");
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
    return;
  }

  body.replaceChildren(
    ...lanes.map((source) => {
      const tr = document.createElement("tr");
      const laneKey = sourceKey(source.server, source.client);
      const rowStatusCell = document.createElement("td");
      rowStatusCell.className = "row-status-column";
      const rowStatus = rowResultForTests(laneKey, tests, rowByLaneAndTest);
      const rowStatusPill = document.createElement("span");
      rowStatusPill.className = `test-cell row-status ${resultClass(rowStatus)}`;
      rowStatusPill.textContent = resultToken(rowStatus);
      rowStatusPill.title = `${source.server} -> ${source.client}: row ${rowStatus}`;
      rowStatusCell.append(rowStatusPill);
      tr.append(rowStatusCell);

      const clientCell = document.createElement("th");
      clientCell.className = "participant-name";
      clientCell.scope = "row";
      clientCell.append(renderParticipant(source.client));
      tr.append(clientCell);

      const serverCell = document.createElement("td");
      serverCell.className = "server-column";
      serverCell.append(renderParticipant(source.server));
      tr.append(serverCell);

      for (const test of tests) {
        const td = document.createElement("td");
        const row = rowByLaneAndTest.get(`${laneKey}:${test}`);
        const result = row ? row.result : "unknown";
        const cell = document.createElement("span");
        cell.className = `test-cell ${resultClass(result)}`;
        cell.textContent = resultToken(result);
        cell.title = row ? `${source.server} -> ${source.client}: ${test} ${row.result}${row.details ? ` (${row.details})` : ""}` : `${source.server} -> ${source.client}: ${test} not reported`;
        td.append(cell);
        tr.append(td);
      }
      return tr;
    }),
  );
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
  } catch {
    activeSnapshot = fallbackInteropSnapshot;
    dataSource = "interop-results.json not available yet";
  }
  renderAll();
}

loadLiveSnapshot();
