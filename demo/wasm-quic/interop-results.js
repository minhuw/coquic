const fallbackInteropSnapshot = {
  schema_version: 1,
  generated_at: "unavailable",
  event_name: "local",
  commit: "awaiting-ci-results",
  sources: [
    {
      label: "quic-go",
      path: "interop-results.json",
      missing: true,
    },
    {
      label: "picoquic",
      path: "interop-results.json",
      missing: true,
    },
    {
      label: "quinn",
      path: "interop-results.json",
      missing: true,
    },
    {
      label: "self",
      path: "interop-results.json",
      missing: true,
    },
  ],
  rows: [],
};

const resultColors = {
  succeeded: "#6be0a3",
  failed: "#ff786d",
  unsupported: "#f5c451",
  unknown: "#91a5ad",
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

function formatNumber(value) {
  return Number(value || 0).toLocaleString("en-US");
}

function sourceRows() {
  return activeSnapshot.sources.filter((source) => !source.missing);
}

function loadedRows() {
  return activeSnapshot.rows || [];
}

function statusForRow(row) {
  return resultColors[row.result] ? row.result : "unknown";
}

function caseSortKey(name) {
  const index = caseOrder.indexOf(name);
  return index === -1 ? caseOrder.length : index;
}

function peerLabel(source) {
  if (!source || source.missing) {
    return "missing";
  }
  if (source.server === "coquic" && source.client === "coquic") {
    return "coquic self";
  }
  return source.peer || `${source.server} / ${source.client}`;
}

function columnLabel(source) {
  const direction = source.direction ? ` ${source.direction}` : "";
  return `${peerLabel(source)}${direction}`;
}

function renderSnapshot() {
  const rows = loadedRows();
  const total = rows.length;
  const succeeded = rows.filter((row) => row.result === "succeeded").length;
  const failed = rows.filter((row) => row.result === "failed").length;
  const unsupported = rows.filter((row) => row.result === "unsupported").length;
  const peers = new Set(sourceRows().map((source) => peerLabel(source)));
  const cards = [
    {
      label: "cases succeeded",
      value: `${formatNumber(succeeded)} / ${formatNumber(total)}`,
      detail: total ? "official runner snapshot" : "waiting for CI interop data",
    },
    {
      label: "peer lanes",
      value: formatNumber(peers.size),
      detail: peers.size ? [...peers].join(", ") : "quic-go, picoquic, quinn, self",
    },
    {
      label: "failed cases",
      value: formatNumber(failed),
      detail: failed ? "inspect the matrix below" : "no loaded failures",
    },
    {
      label: "unsupported",
      value: formatNumber(unsupported),
      detail: unsupported ? "reported by the official runner" : "none in loaded data",
    },
  ];

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

function renderPeerCards() {
  const sources = sourceRows();
  const peerGrid = document.getElementById("peer-grid");
  if (!sources.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No interop sources loaded. The dashboard will use interop-results.json when the interop workflow uploads it.";
    peerGrid.replaceChildren(empty);
    return;
  }

  peerGrid.replaceChildren(
    ...sources.map((source) => {
      const total = Number(source.total || 0);
      const succeeded = Number(source.succeeded || 0);
      const percent = total > 0 ? Math.round((succeeded / total) * 100) : 0;
      const element = document.createElement("article");
      element.className = "peer-card";

      const header = document.createElement("div");
      header.className = "peer-head";
      const title = document.createElement("strong");
      title.textContent = peerLabel(source);
      const direction = document.createElement("span");
      direction.className = "pill";
      direction.textContent = source.direction || "unknown";
      header.append(title, direction);

      const score = document.createElement("div");
      score.className = "score";
      const scoreText = document.createElement("span");
      scoreText.textContent = `${succeeded}/${total}`;
      const scoreMeta = document.createElement("small");
      scoreMeta.textContent = `${percent}% succeeded`;
      score.append(scoreText, scoreMeta);

      const bar = document.createElement("div");
      bar.className = "result-track";
      const fill = document.createElement("div");
      fill.className = "result-fill";
      fill.style.setProperty("--bar-width", `${percent}%`);
      fill.style.setProperty("--bar-color", failedColor(source));
      bar.append(fill);

      const detail = document.createElement("p");
      detail.textContent = `${source.server} -> ${source.client}${source.quic_version ? `, ${source.quic_version}` : ""}`;

      element.append(header, score, bar, detail);
      return element;
    }),
  );
}

function failedColor(source) {
  if (Number(source.failed || 0) > 0 || Number(source.other || 0) > 0) {
    return resultColors.failed;
  }
  if (Number(source.unsupported || 0) > 0) {
    return resultColors.unsupported;
  }
  return resultColors.succeeded;
}

function testNames() {
  const names = new Set(loadedRows().map((row) => row.name));
  return [...names].sort((left, right) => caseSortKey(left) - caseSortKey(right) || left.localeCompare(right));
}

function sourceKey(source) {
  return `${source.label}:${source.server}:${source.client}`;
}

function rowKey(row) {
  return `${row.label}:${row.server}:${row.client}`;
}

function renderMatrix() {
  const sources = sourceRows();
  const tests = testNames();
  const body = document.getElementById("matrix-body");
  const head = document.getElementById("matrix-head");

  head.replaceChildren();
  const headRow = document.createElement("tr");
  const testHeader = document.createElement("th");
  testHeader.textContent = "Case";
  headRow.append(testHeader);
  for (const source of sources) {
    const th = document.createElement("th");
    th.textContent = columnLabel(source);
    headRow.append(th);
  }
  head.append(headRow);

  if (!sources.length || !tests.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.className = "empty-cell";
    td.colSpan = Math.max(sources.length + 1, 1);
    td.textContent = "No interop rows loaded.";
    tr.append(td);
    body.replaceChildren(tr);
    return;
  }

  const bySourceAndTest = new Map();
  for (const row of loadedRows()) {
    bySourceAndTest.set(`${rowKey(row)}:${row.name}`, row);
  }

  body.replaceChildren(
    ...tests.map((test) => {
      const tr = document.createElement("tr");
      const name = document.createElement("td");
      name.className = "case-name";
      name.textContent = test;
      tr.append(name);

      for (const source of sources) {
        const row = bySourceAndTest.get(`${sourceKey(source)}:${test}`);
        const td = document.createElement("td");
        const pill = document.createElement("span");
        const status = row ? statusForRow(row) : "unknown";
        pill.className = `result-pill ${status}`;
        pill.textContent = row ? row.result : "-";
        if (row && row.details) {
          pill.title = row.details;
        }
        td.append(pill);
        tr.append(td);
      }
      return tr;
    }),
  );
}

function renderFailures() {
  const notable = loadedRows().filter((row) => row.result !== "succeeded");
  const body = document.getElementById("failure-body");
  if (!notable.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.className = "empty-cell";
    td.colSpan = 5;
    td.textContent = loadedRows().length ? "No failed or unsupported cases in the loaded snapshot." : "No interop rows loaded.";
    tr.append(td);
    body.replaceChildren(tr);
    return;
  }

  body.replaceChildren(
    ...notable.map((row) => {
      const tr = document.createElement("tr");
      for (const value of [row.peer, row.direction, row.name, row.result, row.details || "-"]) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.append(td);
      }
      return tr;
    }),
  );
}

function renderSources() {
  document.getElementById("data-source-label").textContent = dataSource;
  document.getElementById("source-list").replaceChildren(
    ...activeSnapshot.sources.map((source) => {
      const element = document.createElement("div");
      element.className = "source-item";
      const name = document.createElement("strong");
      name.textContent = source.label;
      const pair = document.createElement("span");
      pair.textContent = source.missing
        ? "missing result"
        : `${source.server} -> ${source.client}, ${source.succeeded}/${source.total} succeeded`;
      const sourcePath = document.createElement("span");
      sourcePath.textContent = source.path;
      element.append(name, pair, sourcePath);
      return element;
    }),
  );
}

function renderAll() {
  renderSnapshot();
  renderPeerCards();
  renderMatrix();
  renderFailures();
  renderSources();
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
