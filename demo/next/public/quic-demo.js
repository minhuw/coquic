const wasmPath = "./coquic-wasm-quic.wasm";
const packetDelayMs = 1000;
const initialDestinationConnectionId = Uint8Array.from([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const pingPongPayloadBytes = 360;
const maxPendingPingPong = 2;

const certPem = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUfGLiwBSFPX9DqQSNXv+f3CUruwswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDMxODEzMjIxNVoXDTI3MDMx
ODEzMjIxNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA/ilQZWcEKdgT7VAyku7JOVvmtJSk0/u2IJvEmfb7Cdbl
zt039tBRsiFrdFikSTGm7rBqCzzT7wAHv4J0+nP/tQs53uslpViTi7rVAvml/jHX
ng3JevgJzz3AdEpTTPL3NKjQESuNiXsuoutTzNJ1ltDywQz4+vGe9ctQye51TsBD
mr/fJAzult7m1PTroiTp7ZJkq6ybUhmT943fT40WGy1uk5LwVYmbh4sbzweVbIQp
RLT3YZeYG0Klocez2o3v5PMXE94eOBZGLVhYA1iwmubZpqtPfnMYFPApwoYdJfZ4
xOBT4eYqgzZu/Be9VR7KKX82eFViGhLg69lMSjR4KwIDAQABo1MwUTAdBgNVHQ4E
FgQUShGJTwym+VNTqADxkzCXDDXOTN8wHwYDVR0jBBgwFoAUShGJTwym+VNTqADx
kzCXDDXOTN8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAVOf+
NQ52+nRbePlhxeLVaIiQBKZcUCVkWcZfG6xpkrgF7OQXsPq7RzFzd/OFLuUXkEPR
G/jE+thaj+jytTXvTKmXPhQNoihem9r0HzaYJP7gL0tBc5hZjJDbwN7xNy77nTDD
EENFyvRWDs1Dn7lXJFoYSpYhbfqBw12uPfM1wyqNDnALcVpMZCkOWu9Xgeg2Qqr1
I4OQhcypFBscgLaILsmon74WpYGR1DygjufmAwVbRHw9B2Ep9XP/zVQNJ9bOnljw
c0PxBwkqi65cndFE++WVC2flc1hRRARfZejA/Xrg54vujrQ7xzUXCNGV+B1B4Svl
p+Y0wRfxl6nd2jrw7g==
-----END CERTIFICATE-----
`;

const keyPem = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD+KVBlZwQp2BPt
UDKS7sk5W+a0lKTT+7Ygm8SZ9vsJ1uXO3Tf20FGyIWt0WKRJMabusGoLPNPvAAe/
gnT6c/+1Czne6yWlWJOLutUC+aX+MdeeDcl6+AnPPcB0SlNM8vc0qNARK42Jey6i
61PM0nWW0PLBDPj68Z71y1DJ7nVOwEOav98kDO6W3ubU9OuiJOntkmSrrJtSGZP3
jd9PjRYbLW6TkvBViZuHixvPB5VshClEtPdhl5gbQqWhx7Paje/k8xcT3h44FkYt
WFgDWLCa5tmmq09+cxgU8CnChh0l9njE4FPh5iqDNm78F71VHsopfzZ4VWIaEuDr
2UxKNHgrAgMBAAECggEBAIxMoA2pxTmYBr/8gj5rw/Z+zaanWymNjGcJtYhMNx2i
W+9KXIdJTZ+oJRnviJjC6ORfy9nyNQd8m8pSqGJMwD3fOY3dfkV81M3QT5+50bC1
MNIVyD+yRi/5ZZCMKtmSUXXnLhwcT6AxuHfEsdih4LllFGwOzi4wTNBf8HPXxze1
fr4WCJ9J4PunT/WKjgHSqN30JsPupc0J2+MfbxKkmrUT+xsSCG51JTYM3xws+1pY
KEVtX2Rj74bWCf66lvSR2tBjhVpjvql1CR0n3uQ6ukPIPpD936t92gAAh1ah5LuM
q3jn8feFYdbjH7u1SPuxzPcHhS6nHs8cnTV9fOpUI0ECgYEA/9xSF18qCES0VLau
GHPBOIIgkqu3xXmIf4vBgIywWf1a+Tr6ABk2Kpe15CnLms9ozFjq5qlt9vFBGXL6
7JJcaHiVS+fRKhMyXPODEm8OR4UoX+sJE58LBj9lpfHTy7phzi+fUcS4jWBIMAGV
fqyK02E75bGQyS0rcwCW0vvc4csCgYEA/kzBpNS9peT2YrqsgCxeMmqqhIyGSKz1
MGE3iiVCwGvP+vmVK5adnhNHD1+wBRAoOv439Gpw6r7J6i3gOCXuaEr4ili3M9Ys
6dN3mFt6Q56KM0W5mF8qcEL3LSvv3YOaG5222eG94E2PA/3VomDN7bReNDyF2S8O
up5T/CCSdyECgYAjLfTvl7scxe2RlEidvhS8I1A9OnUbJtm4x8uEVFPPG8HNcOl8
5/qForR0ubZwA8KiDjvGGVewU32i9SdBLeKczq+gbzBYO6l6FFVaTIDHHqzte1CV
LRID+uWMCpMXePoHso6SXJ0Pe0SRrTYT4792zvDAZUjGEHrf5h3WxqCZPwKBgQC9
4kKV+eTCgv0XK5yy+G495zf8UZHTopJS1cTK+pelZtud489nBMgcyPg+moysuyvP
IRRXBUPbhSrwGeFbC7fBWHnNlAD4S+ytjKG4ulXJOBCpyF6VUDo4KUi4Ch7JoQLp
rBJlDxLg8gjgSiHDZdVesVfGWYr4aRLudlrv4MJ9AQKBgC6ru7V4pXSXhu0d1zdJ
I6+gmCCVlulCj89YpX9DN11IrLHD7p3g+vLfLFJEzSLjVJi/vF+avjnePOY58xg9
1vvDklAgaW7GxDoi8OgNVOj1mStu3sphJtTlzI8q2DqB0ICbJlwTKcjWcms2wVnd
rmZ1jkyEbwNB4p2YPXDQJ3hW
-----END PRIVATE KEY-----
`;

const stateCodes = ["handshake_ready", "handshake_confirmed", "failed"];
const packetQueueGap = 10;
let wasm;
let packetSerial = 0;
let packetRecords = [];
let datagramRecords = [];
let selectedPacketId = 0;
let demoState = "idle";
let activeRunToken = 0;
let paused = false;
let pauseWaiters = [];
let modalLastFocus = null;
let stepBudget = 0;
let schedulerWaiters = [];
let currentRunPromise = null;
let protocolStepInProgress = false;
let activeWorkbenchRoot = null;
const activePackets = new Map();
const activeDatagrams = new Map();
const boundControlNodes = new WeakSet();

function el(id) {
  return document.getElementById(id);
}

function isWorkbenchMounted() {
  return Boolean(el("packet-rail") && el("log"));
}

function stopDemoForUnmount() {
  if (demoState === "idle" && !currentRunPromise) return;
  activeRunToken += 1;
  demoState = "idle";
  paused = false;
  stepBudget = 0;
  protocolStepInProgress = false;
  releasePauseWaiters();
  wakeScheduler();
}

function bindControl(id, event, handler) {
  const node = el(id);
  if (!node || boundControlNodes.has(node)) return;
  node.addEventListener(event, handler);
  boundControlNodes.add(node);
}

function log(timeMs, text, cls = "") {
  const list = el("log");
  if (!list) return;
  const row = document.createElement("div");
  row.className = `entry ${cls}`;
  row.innerHTML = `<span class="time">${timeMs}ms</span><span class="text"></span>`;
  row.querySelector(".text").textContent = text;
  list.append(row);
  list.scrollTop = list.scrollHeight;
}

function waitForAnimationFrame() {
  return new Promise((resolve) => requestAnimationFrame(resolve));
}

function waitUntilRunning() {
  if (!paused) return Promise.resolve();
  return new Promise((resolve) => pauseWaiters.push(resolve));
}

function releasePauseWaiters() {
  const waiters = pauseWaiters;
  pauseWaiters = [];
  for (const resolve of waiters) resolve();
}

async function pauseAwareSleep(ms) {
  let remaining = ms;
  while (remaining > 0) {
    await waitUntilRunning();
    const previous = performance.now();
    await waitForAnimationFrame();
    if (paused) continue;
    const now = performance.now();
    remaining -= Math.max(0, now - previous);
  }
}

function updateRunButton() {
  const startButton = el("start");
  const stopButton = el("stop");
  const stepButton = el("step");
  const startLabel = el("start-label");
  const stepLabel = el("step-label");
  if (!startButton) return;
  startButton.disabled = wasm === undefined || demoState === "running";
  startButton.setAttribute("aria-label", demoState === "paused" ? "Resume protocol exchange" : "Start protocol exchange");
  if (startLabel) startLabel.textContent = demoState === "paused" ? "Resume" : "Start";
  if (stopButton) {
    stopButton.disabled = wasm === undefined || demoState !== "running";
    stopButton.setAttribute("aria-label", "Stop protocol exchange");
  }
  if (stepButton) {
    stepButton.disabled = wasm === undefined;
    stepButton.setAttribute(
      "aria-label",
      demoState === "running" ? "Pause after current protocol action" : "Step one protocol action",
    );
    if (stepLabel) stepLabel.textContent = "Step";
  }
}

function setModuleState(text, className = "") {
  const node = el("module-state");
  if (!node) return;
  node.className = `module-state${className ? ` ${className}` : ""}`;
  node.textContent = text;
}

function setGlobalTimer(timeMs) {
  const node = el("global-timer");
  if (node) node.textContent = `${timeMs}ms`;
}

function wasmI64ToNumber(value, label) {
  const number = typeof value === "bigint" ? Number(value) : Number(value);
  if (!Number.isSafeInteger(number)) {
    throw new Error(`${label} is outside JavaScript's safe integer range`);
  }
  return number;
}

function pingPongPayload(sender, sequence) {
  const prefix = `${sender} ping-pong ${sequence} `;
  const fill = "flow-control-window ";
  let text = prefix;
  while (encoder.encode(text).length < pingPongPayloadBytes) {
    text += fill;
  }
  return encoder.encode(text).slice(0, pingPongPayloadBytes);
}

function pauseDemo() {
  if (demoState !== "running") return;
  paused = true;
  demoState = "paused";
  updateRunButton();
}

function resumeDemo() {
  if (demoState !== "paused") return;
  paused = false;
  demoState = "running";
  stepBudget = 0;
  releasePauseWaiters();
  wakeScheduler();
  updateRunButton();
}

function isRunActive(runToken) {
  return runToken === activeRunToken && demoState !== "idle" && isWorkbenchMounted();
}

function wakeScheduler() {
  const waiters = schedulerWaiters;
  schedulerWaiters = [];
  for (const resolve of waiters) resolve();
}

async function waitForProtocolStep(runState, description) {
  while (isRunActive(runState.runToken)) {
    if (stepBudget > 0) {
      stepBudget -= 1;
      paused = false;
      runState.stepIndex += 1;
      runState.stepMode = "single";
      updateRunButton();
      return true;
    }
    if (demoState === "running") {
      runState.stepIndex += 1;
      runState.stepMode = "running";
      updateRunButton();
      return true;
    }
    await new Promise((resolve) => schedulerWaiters.push(resolve));
  }
  return false;
}

async function runProtocolStep(runState, description, action) {
  if (!(await waitForProtocolStep(runState, description))) return false;
  if (!isRunActive(runState.runToken)) return false;
  protocolStepInProgress = true;
  try {
    await action(runState.stepMode);
    if (!isRunActive(runState.runToken)) return false;
    drainInternalEvents(runState);
    updateEndpointDiagnostics(runState.clientEndpoint, runState.serverEndpoint, runState);
  } finally {
    protocolStepInProgress = false;
  }
  return true;
}

async function runAutomaticStep(runState, action) {
  if (!isRunActive(runState.runToken)) return false;
  await action();
  if (!isRunActive(runState.runToken)) return false;
  drainInternalEvents(runState);
  updateEndpointDiagnostics(runState.clientEndpoint, runState.serverEndpoint, runState);
  return true;
}

function startDemo(startPaused) {
  if (demoState !== "idle" || currentRunPromise) return;
  activeRunToken += 1;
  currentRunPromise = runDemo({ startPaused })
    .catch((error) => {
      demoState = "idle";
      paused = false;
      stepBudget = 0;
      protocolStepInProgress = false;
      wakeScheduler();
      updateRunButton();
      log(0, error.message, "error");
    })
    .finally(() => {
      currentRunPromise = null;
      updateRunButton();
    });
}

function requestNextStep() {
  if (wasm === undefined) return;
  if (demoState === "idle") {
    stepBudget += 1;
    startDemo(true);
    return;
  }
  if (demoState === "running") {
    demoState = "paused";
    paused = false;
    if (!protocolStepInProgress) stepBudget += 1;
    releasePauseWaiters();
    wakeScheduler();
    updateRunButton();
    return;
  }

  if (protocolStepInProgress && paused) {
    paused = false;
  } else {
    stepBudget += 1;
    paused = false;
  }
  releasePauseWaiters();
  wakeScheduler();
  updateRunButton();
}

function packetKind(bytes) {
  if (bytes.length === 0) return "empty";
  const first = bytes[0];
  if ((first & 0x80) === 0) return "1-RTT";
  switch (first & 0x30) {
    case 0x00:
      return "Initial";
    case 0x10:
      return "0-RTT";
    case 0x20:
      return "Handshake";
    case 0x30:
      return "Retry";
    default:
      return "Long";
  }
}

function readU32(bytes, offset) {
  if (offset + 4 > bytes.length) return null;
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function readVarint(bytes, offset) {
  if (offset >= bytes.length) return null;
  const first = bytes[offset];
  const length = 1 << (first >> 6);
  if (offset + length > bytes.length) return null;
  let value = BigInt(first & 0x3f);
  for (let index = 1; index < length; index += 1) {
    value = (value << 8n) | BigInt(bytes[offset + index]);
  }
  return { value, length };
}

function hex(bytes, max = bytes.length) {
  const used = bytes.slice(0, max);
  return Array.from(used, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function spacedHex(bytes, max = bytes.length) {
  const used = bytes.slice(0, max);
  return Array.from(used, (byte) => byte.toString(16).padStart(2, "0")).join(" ");
}

function hexDump(bytes) {
  const lines = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16);
    const hexPart = Array.from(chunk, (byte) => byte.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const ascii = Array.from(chunk, (byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".")).join("");
    lines.push(`${offset.toString(16).padStart(4, "0")}  ${hexPart}  ${ascii}`);
  }
  return lines.join("\n");
}

function longHeaderType(version, encodedType) {
  if (version === 0) return "Version Negotiation";
  if (version === 0x6b3343cf) {
    if (encodedType === 0x01) return "Initial";
    if (encodedType === 0x02) return "0-RTT";
    if (encodedType === 0x03) return "Handshake";
    if (encodedType === 0x00) return "Retry";
  }
  if (encodedType === 0x00) return "Initial";
  if (encodedType === 0x01) return "0-RTT";
  if (encodedType === 0x02) return "Handshake";
  if (encodedType === 0x03) return "Retry";
  return "Long";
}

function field(name, value, offset, length) {
  return { name, value, offset, length };
}

function parsePacket(bytes, offset, direction) {
  const start = offset;
  if (offset >= bytes.length) return null;
  const first = bytes[offset];
  if ((first & 0x80) === 0) {
    const dcidLength = direction === "client" ? 2 : 8;
    const headerLength = Math.min(bytes.length - offset, 1 + dcidLength);
    return {
      kind: "1-RTT",
      start,
      end: bytes.length,
      protected: true,
      fields: [
        field("Header Form", "Short", start, 1),
        field("Fixed Bit", (first & 0x40) !== 0 ? "1" : "0", start, 1),
        field("Spin Bit", (first & 0x20) !== 0 ? "1" : "0", start, 1),
        field("Key Phase", (first & 0x04) !== 0 ? "1" : "0", start, 1),
        field("Packet Number Length Bits", `${first & 0x03}`, start, 1),
        field("Destination Connection ID", hex(bytes.slice(offset + 1, offset + 1 + dcidLength)), offset + 1, dcidLength),
      ],
      headerEnd: start + headerLength,
      payloadStart: start + headerLength,
      packetNumberOffset: null,
      packetNumberLength: null,
      note: "Short header packet. Header protection hides the packet number length and packet number until 1-RTT keys are available.",
    };
  }

  if (offset + 6 > bytes.length) {
    return {
      kind: "Truncated Long Header",
      start,
      end: bytes.length,
      protected: true,
      fields: [field("First Byte", `0x${first.toString(16).padStart(2, "0")}`, start, 1)],
      headerEnd: bytes.length,
      payloadStart: bytes.length,
      note: "The datagram ended before the long header could be parsed.",
    };
  }

  const version = readU32(bytes, offset + 1);
  let cursor = offset + 5;
  const fields = [
    field("Header Form", "Long", start, 1),
    field("Fixed Bit", (first & 0x40) !== 0 ? "1" : "0", start, 1),
    field("Long Packet Type Bits", `${(first >> 4) & 0x03}`, start, 1),
    field("Version", `0x${version.toString(16).padStart(8, "0")}`, offset + 1, 4),
  ];
  const kind = longHeaderType(version, (first >> 4) & 0x03);
  const dcidLength = bytes[cursor] ?? 0;
  fields.push(field("Destination Connection ID Length", `${dcidLength}`, cursor, 1));
  cursor += 1;
  const dcid = bytes.slice(cursor, Math.min(cursor + dcidLength, bytes.length));
  fields.push(field("Destination Connection ID", hex(dcid), cursor, dcid.length));
  cursor += dcidLength;
  if (cursor >= bytes.length) {
    return { kind, start, end: bytes.length, protected: true, fields, headerEnd: bytes.length, payloadStart: bytes.length };
  }
  const scidLength = bytes[cursor] ?? 0;
  fields.push(field("Source Connection ID Length", `${scidLength}`, cursor, 1));
  cursor += 1;
  const scid = bytes.slice(cursor, Math.min(cursor + scidLength, bytes.length));
  fields.push(field("Source Connection ID", hex(scid), cursor, scid.length));
  cursor += scidLength;

  if (version === 0) {
    return {
      kind,
      start,
      end: bytes.length,
      protected: false,
      fields,
      headerEnd: cursor,
      payloadStart: cursor,
      note: "Version Negotiation has no protected payload.",
    };
  }

  if (kind === "Retry") {
    const tagStart = Math.max(cursor, bytes.length - 16);
    fields.push(field("Retry Token", `${Math.max(0, tagStart - cursor)} bytes`, cursor, Math.max(0, tagStart - cursor)));
    fields.push(field("Retry Integrity Tag", spacedHex(bytes.slice(tagStart, bytes.length)), tagStart, bytes.length - tagStart));
    return {
      kind,
      start,
      end: bytes.length,
      protected: false,
      fields,
      headerEnd: cursor,
      payloadStart: cursor,
      note: "Retry is integrity protected, but it does not carry encrypted frames.",
    };
  }

  if (kind === "Initial") {
    const tokenLength = readVarint(bytes, cursor);
    if (!tokenLength) {
      return { kind, start, end: bytes.length, protected: true, fields, headerEnd: bytes.length, payloadStart: bytes.length };
    }
    fields.push(field("Token Length", `${tokenLength.value}`, cursor, tokenLength.length));
    cursor += tokenLength.length;
    const tokenLen = Number(tokenLength.value);
    fields.push(field("Token", `${tokenLen} bytes`, cursor, Math.min(tokenLen, Math.max(0, bytes.length - cursor))));
    cursor += tokenLen;
  }

  const payloadLength = readVarint(bytes, cursor);
  if (!payloadLength) {
    return { kind, start, end: bytes.length, protected: true, fields, headerEnd: bytes.length, payloadStart: bytes.length };
  }
  fields.push(field("Length", `${payloadLength.value}`, cursor, payloadLength.length));
  cursor += payloadLength.length;
  const payloadEnd = Math.min(bytes.length, cursor + Number(payloadLength.value));
  fields.push(field("Protected Packet Number + Payload", `${Math.max(0, payloadEnd - cursor)} bytes`, cursor, Math.max(0, payloadEnd - cursor)));
  return {
    kind,
    start,
    end: payloadEnd,
    protected: true,
    fields,
    headerEnd: cursor,
    payloadStart: cursor,
    packetNumberOffset: cursor,
    packetNumberLength: (first & 0x03) + 1,
    note: "Packet number and frames are protected on the wire. Initial packets can be decoded here because their initial secret is derived from the original destination connection ID.",
  };
}

function splitDatagram(bytes, direction) {
  const packets = [];
  let offset = 0;
  while (offset < bytes.length) {
    const parsed = parsePacket(bytes, offset, direction);
    if (!parsed) break;
    packets.push({ ...parsed, bytes: bytes.slice(parsed.start, parsed.end) });
    if (parsed.end <= offset) break;
    offset = parsed.end;
  }
  return packets;
}

function clearPackets() {
  const rail = el("packet-rail");
  if (!rail) return;
  activePackets.clear();
  activeDatagrams.clear();
  rail.querySelectorAll(".packet").forEach((packet) => packet.remove());
  rail.querySelectorAll(".datagram").forEach((datagram) => datagram.remove());
}

function packetLaneBaseTop(direction) {
  const mobile = window.matchMedia("(max-width: 680px)").matches;
  if (direction === "client") return mobile ? 99 : 95;
  return mobile ? 165 : 167;
}

function packetTravelBounds(item) {
  const rail = el("packet-rail");
  if (!rail) return { leftEdge: 0, rightEdge: 0 };
  const laneInset = window.matchMedia("(max-width: 680px)").matches ? 18 : 48;
  const leftEdge = laneInset;
  const rightEdge = Math.max(leftEdge, rail.clientWidth - laneInset - item.node.offsetWidth);
  return { leftEdge, rightEdge };
}

function packetRawX(item) {
  const { leftEdge, rightEdge } = packetTravelBounds(item);
  const progress = Math.max(0, Math.min(1, item.elapsedMs / packetDelayMs));
  const eased = progress < 0.5 ? 2 * progress * progress : 1 - ((-2 * progress + 2) ** 2) / 2;
  return item.direction === "client" ? leftEdge + (rightEdge - leftEdge) * eased : rightEdge - (rightEdge - leftEdge) * eased;
}

function packetStride(items) {
  return Math.max(...items.map((item) => item.node.offsetWidth)) + packetQueueGap;
}

function directionPackets(direction) {
  return [...activePackets.values()]
    .filter((item) => item.direction === direction)
    .sort((a, b) => a.serial - b.serial);
}

function renderPacketItem(item, x) {
  item.node.style.left = `${x}px`;
  item.node.style.top = `${packetLaneBaseTop(item.direction)}px`;
  item.node.style.opacity = item.phase === "accepted" ? "0.2" : "1";
}

function renderDatagramEnvelope(datagram) {
  const packets = datagram.items.filter((item) => activePackets.has(item.record.id));
  if (packets.length === 0) {
    datagram.node.style.opacity = "0";
    return;
  }
  const left = Math.min(...packets.map((item) => item.node.offsetLeft)) - 10;
  const right = Math.max(...packets.map((item) => item.node.offsetLeft + item.node.offsetWidth)) + 10;
  const top = packetLaneBaseTop(datagram.direction) - 12;
  datagram.node.style.left = `${left}px`;
  datagram.node.style.top = `${top}px`;
  datagram.node.style.width = `${Math.max(168, right - left)}px`;
  datagram.node.style.height = `${Math.max(66, packets[0].node.offsetHeight + 24)}px`;
}

function renderDatagramEnvelopes(direction) {
  for (const datagram of activeDatagrams.values()) {
    if (datagram.direction === direction) renderDatagramEnvelope(datagram);
  }
}

function renderPacketDirection(direction) {
  if (!isWorkbenchMounted()) return;
  const items = directionPackets(direction);
  if (items.length === 0) {
    renderDatagramEnvelopes(direction);
    return;
  }
  const newestToOldest = [...items].reverse();
  const stride = packetStride(items);
  const positions = new Map();

  if (direction === "client") {
    let previous = null;
    for (const item of newestToOldest) {
      const raw = packetRawX(item);
      const x = previous === null ? raw : Math.max(raw, previous + stride);
      positions.set(item, x);
      previous = x;
    }
    const overflow = positions.get(items[0]) - packetTravelBounds(items[0]).rightEdge;
    if (overflow > 0) {
      for (const item of items) positions.set(item, positions.get(item) - overflow);
    }
  } else {
    let previous = null;
    for (const item of newestToOldest) {
      const raw = packetRawX(item);
      const x = previous === null ? raw : Math.min(raw, previous - stride);
      positions.set(item, x);
      previous = x;
    }
    const underflow = packetTravelBounds(items[0]).leftEdge - positions.get(items[0]);
    if (underflow > 0) {
      for (const item of items) positions.set(item, positions.get(item) + underflow);
    }
  }

  for (const item of items) renderPacketItem(item, positions.get(item));
  renderDatagramEnvelopes(direction);
}

function renderPacketPosition(item) {
  renderPacketDirection(item.direction);
}

function renderPacketQueues() {
  renderPacketDirection("client");
  renderPacketDirection("server");
}

function advancePacketClock(item, previousTime) {
  if (paused) return previousTime;
  const now = performance.now();
  item.elapsedMs += Math.max(0, now - previousTime);
  renderPacketDirection(item.direction);
  return now;
}

function setPacketPhase(item, phase) {
  item.phase = phase;
  item.node.dataset.phase = phase;
  const status = item.node.querySelector("span");
  if (status) {
    status.textContent = phase === "received" || phase === "accepted" ? phase : item.sizeLabel;
  }
  item.node.setAttribute(
    "aria-label",
    `Inspect ${phase} packet ${item.record.id}, ${item.record.directionLabel} ${item.record.kind}`,
  );
  renderPacketPosition(item);
}

function setDatagramPhase(datagram, phase) {
  datagram.phase = phase;
  datagram.node.dataset.phase = phase;
  renderDatagramEnvelope(datagram);
}

function retirePacket(item) {
  if (!activePackets.has(item.record.id)) return;
  activePackets.delete(item.record.id);
  item.node.remove();
  renderPacketDirection(item.direction);
}

function retireDatagram(datagram) {
  if (!activeDatagrams.has(datagram.id)) return;
  setDatagramPhase(datagram, "accepted");
  setTimeout(() => {
    activeDatagrams.delete(datagram.id);
    datagram.node.remove();
  }, 180);
}

function markSelectedPacket() {
  for (const [id, item] of activePackets) {
    item.node.classList.toggle("selected", id === selectedPacketId);
  }
}

function visualizePacket(direction, record) {
  const packet = document.createElement("button");
  const fromClient = direction === "client";
  packetSerial += 1;
  packet.type = "button";
  packet.className = `packet ${fromClient ? "from-client" : "from-server"}`;
  packet.innerHTML = "<strong></strong><span></span>";
  packet.querySelector("strong").textContent = `#${record.id} ${record.kind}`;
  packet.addEventListener("click", () => selectPacket(record.id, { openModal: true }));
  el("packet-rail").append(packet);
  const sizeLabel = `${record.bytes.length}B`;
  const item = {
    node: packet,
    direction,
    record,
    sizeLabel,
    serial: packetSerial,
    phase: "generated",
    elapsedMs: 0,
  };
  activePackets.set(record.id, item);
  setPacketPhase(item, "generated");
  renderPacketDirection(direction);
  markSelectedPacket();
  return {
    item,
    async wait({ instant = false } = {}) {
      setPacketPhase(item, "in-flight");
      if (instant) {
        item.elapsedMs = packetDelayMs;
        setPacketPhase(item, "arrived");
        return;
      }
      while (item.elapsedMs < packetDelayMs) {
        await waitUntilRunning();
        const previous = performance.now();
        await waitForAnimationFrame();
        if (paused) continue;
        advancePacketClock(item, previous);
      }
      item.elapsedMs = packetDelayMs;
      setPacketPhase(item, "arrived");
    },
    receive() {
      item.elapsedMs = packetDelayMs;
      setPacketPhase(item, "received");
    },
    accept() {
      item.elapsedMs = packetDelayMs;
      setPacketPhase(item, "accepted");
      setTimeout(() => retirePacket(item), 180);
    },
  };
}

function visualizeDatagram(direction, datagram, records, packetItems) {
  const node = document.createElement("div");
  const fromClient = direction === "client";
  node.className = `datagram ${fromClient ? "from-client" : "from-server"}`;
  node.innerHTML = '<span class="datagram-label"></span>';
  node.querySelector(".datagram-label").textContent =
    `UDP d${datagramRecords.length} ${records.length} QUIC pkt${records.length === 1 ? "" : "s"} ${datagram.bytes.length}B`;
  el("packet-rail").prepend(node);
  const item = {
    id: datagramRecords.length,
    node,
    direction,
    records,
    items: packetItems,
    phase: "generated",
  };
  activeDatagrams.set(item.id, item);
  setDatagramPhase(item, "generated");
  return item;
}

function inspectInitialPacket(direction, packetBytes) {
  if (packetKind(packetBytes) !== "Initial") return null;
  const peerRole = direction === "client" ? 0 : 1;
  const inputPointer = allocBytes(packetBytes);
  const dcidPointer = allocBytes(initialDestinationConnectionId);
  const outputPointer = wasm.coquic_wasm_alloc(16384);
  try {
    const written = wasm.coquic_wasm_inspect_initial_packet(
      peerRole,
      inputPointer,
      packetBytes.length,
      dcidPointer,
      initialDestinationConnectionId.length,
      outputPointer,
      16384,
    );
    if (written <= 0) return { ok: false, error: written };
    return JSON.parse(decoder.decode(readBytes(outputPointer, written)));
  } catch (error) {
    return { ok: false, error: error.message };
  } finally {
    if (inputPointer) wasm.coquic_wasm_free(inputPointer);
    if (dcidPointer) wasm.coquic_wasm_free(dcidPointer);
    wasm.coquic_wasm_free(outputPointer);
  }
}

function resetPacketInspector() {
  packetRecords = [];
  datagramRecords = [];
  selectedPacketId = 0;
  el("packet-list").textContent = "";
  el("packet-count").textContent = "0 captured";
  updateDownloadPcapButton();
  el("packet-selected").textContent = "none selected";
  el("packet-modal-selected").textContent = "none selected";
  el("packet-detail").innerHTML =
    '<p class="empty-detail">Run the exchange, then select a packet in the pipe or log to inspect it in the packet detail window.</p>';
  el("packet-modal-detail").innerHTML =
    '<p class="empty-detail">Select a packet to inspect its QUIC header, protected payload, and raw bytes.</p>';
  closePacketModal();
}

function addText(parent, text) {
  parent.append(document.createTextNode(text));
}

function frameSummary(record) {
  const frames = record.inspect?.ok && Array.isArray(record.inspect.frames)
    ? record.inspect.frames.map((frame) => frame.type).filter(Boolean)
    : [];
  if (frames.length === 0) return record.inspect?.ok ? "no frames" : "protected";
  const flowFrames = frames.filter((type) =>
    type === "MAX_DATA" ||
    type === "MAX_STREAM_DATA" ||
    type === "DATA_BLOCKED" ||
    type === "STREAM_DATA_BLOCKED"
  );
  const visible = flowFrames.length > 0 ? flowFrames : frames;
  const suffix = frames.length > visible.length ? ` +${frames.length - visible.length}` : "";
  return `${visible.join(", ")}${suffix}`;
}

function renderPacketList() {
  const list = el("packet-list");
  list.textContent = "";
  for (const record of packetRecords) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = `packet-row${record.id === selectedPacketId ? " selected" : ""}`;
    row.innerHTML =
      '<strong class="mono"></strong><span></span><strong class="packet-kind"></strong><span class="packet-frames"></span><span class="packet-size"></span>';
    row.children[0].textContent = `#${record.id}`;
    row.children[1].textContent = `${record.now}ms`;
    row.children[2].textContent = `${record.directionLabel} ${record.kind}`;
    row.children[3].textContent = frameSummary(record);
    row.children[4].textContent = `${record.bytes.length}B`;
    row.addEventListener("click", () => selectPacket(record.id, { openModal: true }));
    list.append(row);
  }
  el("packet-count").textContent = `${packetRecords.length} captured`;
  updateDownloadPcapButton();
  list.scrollTop = list.scrollHeight;
  markSelectedPacket();
}

function addFieldRows(parent, rows) {
  const dl = document.createElement("dl");
  dl.className = "field-list";
  for (const row of rows) {
    const wrap = document.createElement("div");
    wrap.className = "field-row";
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = row.name;
    dd.textContent = row.value;
    if (row.offset !== undefined && row.length !== undefined) {
      const meta = document.createElement("span");
      meta.className = "field-meta";
      meta.textContent = `offset ${row.offset}, ${row.length} byte${row.length === 1 ? "" : "s"}`;
      dd.append(meta);
    }
    wrap.append(dt, dd);
    dl.append(wrap);
  }
  parent.append(dl);
}

function addDetails(parent, title, rows, open = true) {
  const details = document.createElement("details");
  details.open = open;
  const summary = document.createElement("summary");
  summary.textContent = title;
  details.append(summary);
  addFieldRows(details, rows);
  parent.append(details);
}

function decodedFrameRows(inspect) {
  if (!inspect || !inspect.ok || !Array.isArray(inspect.frames)) return [];
  return inspect.frames.map((frame, index) => ({
    name: `Frame ${index + 1}`,
    value: Object.entries(frame)
      .map(([key, value]) => `${key}=${value}`)
      .join(", "),
  }));
}

function inspectionByOffset(inspections) {
  const byOffset = new Map();
  for (const inspection of inspections ?? []) {
    if (inspection && Number.isFinite(inspection.datagram_offset)) {
      byOffset.set(inspection.datagram_offset, inspection);
    }
  }
  return byOffset;
}

function packetSelectedText(record) {
  return `#${record.id} ${record.kind}`;
}

function renderPacketDetail(record, target = el("packet-modal-detail")) {
  const detail = target;
  detail.textContent = "";

  const summary = document.createElement("div");
  summary.className = "detail-summary";
  for (const item of [
    ["Time", `${record.now}ms`],
    ["Direction", record.directionLabel],
    ["Type", record.kind],
    ["Length", `${record.bytes.length} bytes`],
    ["Inspect ID", `${record.datagramId ?? 0n}`],
  ]) {
    const node = document.createElement("div");
    node.className = "summary-item";
    node.innerHTML = "<span></span><strong></strong>";
    node.children[0].textContent = item[0];
    node.children[1].textContent = item[1];
    summary.append(node);
  }
  detail.append(summary);

  const tree = document.createElement("div");
  tree.className = "packet-tree";
  addDetails(tree, "QUIC Header", record.fields);

  const protectedRows = [
    { name: "Header Bytes", value: `${Math.max(0, record.headerEnd - record.start)} bytes`, offset: record.start, length: Math.max(0, record.headerEnd - record.start) },
    { name: "Protected Region", value: `${Math.max(0, record.end - record.payloadStart)} bytes`, offset: record.payloadStart, length: Math.max(0, record.end - record.payloadStart) },
  ];
  if (record.packetNumberOffset !== null && record.packetNumberOffset !== undefined) {
    protectedRows.push({
      name: "Header Protection Sample",
      value: spacedHex(record.datagramBytes.slice(record.packetNumberOffset + 4, record.packetNumberOffset + 20)),
      offset: record.packetNumberOffset + 4,
      length: Math.min(16, Math.max(0, record.end - (record.packetNumberOffset + 4))),
    });
  }
  addDetails(tree, "Packet Protection", protectedRows, true);

  if (record.inspect?.ok) {
    const decodeTitle = record.inspect.source === "core" ? "Core Packet Inspection" : "Decoded Initial Packet";
    addDetails(tree, decodeTitle, [
      { name: "Packet Number", value: `${record.inspect.packet_number}` },
      { name: "Packet Number Length", value: `${record.inspect.packet_number_length} bytes` },
      { name: "Plaintext Payload", value: `${record.inspect.plaintext_payload_length} bytes` },
      { name: "Datagram Offset", value: `${record.inspect.datagram_offset ?? record.start}` },
      { name: "Token Length", value: `${record.inspect.token_length ?? 0} bytes` },
    ]);
    addDetails(tree, "Decoded Frames", decodedFrameRows(record.inspect), true);
    if (record.inspect.plaintext_payload) {
      const plain = document.createElement("pre");
      plain.className = "hex-dump";
      plain.textContent = `Plaintext payload\n${record.inspect.plaintext_payload}`;
      tree.append(plain);
    }
  } else {
    const note = document.createElement("p");
    note.className = "frame-note";
    note.textContent =
      record.kind === "Initial"
        ? "Initial frame decode failed for this packet. The raw header and bytes are still shown below."
        : "Frame bytes are protected on the wire. Core inspection records are emitted when this endpoint has the matching packet keys.";
    tree.append(note);
  }

  const raw = document.createElement("pre");
  raw.className = "hex-dump";
  raw.textContent = hexDump(record.bytes);
  tree.append(raw);
  detail.append(tree);
}

function openPacketModal() {
  const modal = el("packet-modal");
  modalLastFocus = document.activeElement;
  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
  el("packet-modal-close").focus();
}

function closePacketModal() {
  const modal = el("packet-modal");
  if (!modal) return;
  const shouldRestoreFocus = modal.classList.contains("open");
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  if (shouldRestoreFocus && modalLastFocus && typeof modalLastFocus.focus === "function") {
    modalLastFocus.focus();
  }
  modalLastFocus = null;
}

function selectPacket(id, options = {}) {
  selectedPacketId = id;
  renderPacketList();
  const record = packetRecords.find((item) => item.id === id);
  if (record) {
    const text = packetSelectedText(record);
    el("packet-selected").textContent = text;
    el("packet-modal-selected").textContent = text;
    renderPacketDetail(record);
    if (options.openModal) openPacketModal();
  }
  markSelectedPacket();
}

function capturePcapDatagram(direction, datagram, now) {
  datagramRecords.push({
    id: datagramRecords.length + 1,
    now,
    direction,
    bytes: datagram.bytes.slice(),
  });
}

function captureDatagram(direction, datagram, now, inspections = []) {
  const directionLabel = direction === "client" ? "C -> S" : "S -> C";
  capturePcapDatagram(direction, datagram, now);
  const parsedPackets = splitDatagram(datagram.bytes, direction);
  const coreInspection = inspectionByOffset(inspections);
  let firstNewId = 0;
  const newRecords = [];
  for (const parsed of parsedPackets) {
    const id = packetRecords.length + 1;
    const inspect = coreInspection.get(parsed.start) ?? inspectInitialPacket(direction, parsed.bytes);
    if (inspect) inspect.source ??= coreInspection.has(parsed.start) ? "core" : "initial";
    const kind = inspect?.source === "core" && inspect.kind ? inspect.kind : parsed.kind;
    if (firstNewId === 0) firstNewId = id;
    packetRecords.push({
      id,
      now,
      direction,
      directionLabel,
      route: datagram.route,
      ecn: datagram.ecn,
      datagramId: datagram.inspectionDatagramId,
      datagramBytes: datagram.bytes,
      ...parsed,
      kind,
      inspect,
    });
    newRecords.push(packetRecords[packetRecords.length - 1]);
  }
  if (selectedPacketId === 0) selectedPacketId = firstNewId;
  renderPacketList();
  if (selectedPacketId !== 0) {
    const selected = packetRecords.find((item) => item.id === selectedPacketId);
    if (selected) {
      const text = packetSelectedText(selected);
      el("packet-selected").textContent = text;
      el("packet-modal-selected").textContent = text;
      renderPacketDetail(selected);
    }
  }
  return newRecords;
}

function updateDownloadPcapButton() {
  const button = el("download-pcap");
  if (button) button.disabled = datagramRecords.length === 0;
}

function writeU16(view, offset, value, littleEndian = false) {
  view.setUint16(offset, value & 0xffff, littleEndian);
}

function writeU32(view, offset, value, littleEndian = false) {
  view.setUint32(offset, value >>> 0, littleEndian);
}

function internetChecksum(bytes, start, length) {
  let sum = 0;
  for (let offset = start; offset < start + length; offset += 2) {
    const hi = bytes[offset] ?? 0;
    const lo = offset + 1 < start + length ? bytes[offset + 1] : 0;
    sum += (hi << 8) | lo;
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  }
  return (~sum) & 0xffff;
}

function ipv4Address(a, b, c, d) {
  return Uint8Array.from([a, b, c, d]);
}

function buildUdpIpv4Frame(record) {
  const payload = record.bytes;
  const frame = new Uint8Array(14 + 20 + 8 + payload.length);
  const view = new DataView(frame.buffer);
  const fromClient = record.direction === "client";
  const dstMac = fromClient ? [0x02, 0x00, 0x00, 0x00, 0x00, 0x02] : [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
  const srcMac = fromClient ? [0x02, 0x00, 0x00, 0x00, 0x00, 0x01] : [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
  frame.set(dstMac, 0);
  frame.set(srcMac, 6);
  writeU16(view, 12, 0x0800);

  const ipOffset = 14;
  const udpOffset = ipOffset + 20;
  const payloadOffset = udpOffset + 8;
  const srcIp = fromClient ? ipv4Address(10, 0, 0, 1) : ipv4Address(10, 0, 0, 2);
  const dstIp = fromClient ? ipv4Address(10, 0, 0, 2) : ipv4Address(10, 0, 0, 1);
  const srcPort = fromClient ? 44330 : 4433;
  const dstPort = fromClient ? 4433 : 44330;

  frame[ipOffset] = 0x45;
  frame[ipOffset + 1] = 0;
  writeU16(view, ipOffset + 2, 20 + 8 + payload.length);
  writeU16(view, ipOffset + 4, record.id);
  writeU16(view, ipOffset + 6, 0x4000);
  frame[ipOffset + 8] = 64;
  frame[ipOffset + 9] = 17;
  frame.set(srcIp, ipOffset + 12);
  frame.set(dstIp, ipOffset + 16);
  writeU16(view, ipOffset + 10, internetChecksum(frame, ipOffset, 20));

  writeU16(view, udpOffset, srcPort);
  writeU16(view, udpOffset + 2, dstPort);
  writeU16(view, udpOffset + 4, 8 + payload.length);
  writeU16(view, udpOffset + 6, 0);
  frame.set(payload, payloadOffset);
  return frame;
}

function buildPcap() {
  const frames = datagramRecords.map((record) => ({ record, frame: buildUdpIpv4Frame(record) }));
  const totalLength = 24 + frames.reduce((sum, item) => sum + 16 + item.frame.length, 0);
  const bytes = new Uint8Array(totalLength);
  const view = new DataView(bytes.buffer);
  let offset = 0;
  writeU32(view, offset, 0xa1b2c3d4, true); offset += 4;
  writeU16(view, offset, 2, true); offset += 2;
  writeU16(view, offset, 4, true); offset += 2;
  writeU32(view, offset, 0, true); offset += 4;
  writeU32(view, offset, 0, true); offset += 4;
  writeU32(view, offset, 65535, true); offset += 4;
  writeU32(view, offset, 1, true); offset += 4;

  for (const { record, frame } of frames) {
    const totalUsec = Math.max(0, record.now) * 1000;
    const seconds = Math.floor(totalUsec / 1000000);
    const usec = totalUsec - seconds * 1000000;
    writeU32(view, offset, seconds, true); offset += 4;
    writeU32(view, offset, usec, true); offset += 4;
    writeU32(view, offset, frame.length, true); offset += 4;
    writeU32(view, offset, frame.length, true); offset += 4;
    bytes.set(frame, offset);
    offset += frame.length;
  }
  return bytes;
}

function downloadPcap() {
  if (datagramRecords.length === 0) return;
  const bytes = buildPcap();
  const blob = new Blob([bytes], { type: "application/vnd.tcpdump.pcap" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "coquic-wasm-demo.pcap";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function loadModule() {
  let instance;
  const imports = {
    wasi_snapshot_preview1: {
      args_get: () => 0,
      args_sizes_get: (argc, argvBufSize) => {
        view().setUint32(argc, 0, true);
        view().setUint32(argvBufSize, 0, true);
        return 0;
      },
      clock_time_get: (_clockId, _precision, time) => {
        view().setBigUint64(time, BigInt(Math.trunc(performance.now() * 1_000_000)), true);
        return 0;
      },
      environ_get: () => 0,
      environ_sizes_get: (environCount, environBufSize) => {
        view().setUint32(environCount, 0, true);
        view().setUint32(environBufSize, 0, true);
        return 0;
      },
      fd_close: () => 0,
      fd_fdstat_get: () => 8,
      fd_prestat_get: () => 8,
      fd_prestat_dir_name: () => 8,
      fd_read: () => 8,
      fd_seek: () => 8,
      fd_write: (_fd, _iovs, _iovsLen, nwritten) => {
        view().setUint32(nwritten, 0, true);
        return 0;
      },
      proc_exit: (code) => {
        throw new Error(`WASI proc_exit(${code})`);
      },
      random_get: (pointer, length) => {
        crypto.getRandomValues(new Uint8Array(instance.exports.memory.buffer, pointer, length));
        return 0;
      },
    },
  };

  setModuleState("fetching wasm");
  const response = await fetch(wasmPath);
  if (!response.ok) {
    throw new Error(`wasm fetch failed: HTTP ${response.status}`);
  }

  setModuleState("instantiating wasm");
  let result;
  if (response.headers.get("content-type")?.toLowerCase().startsWith("application/wasm")) {
    result = await WebAssembly.instantiateStreaming(response, imports);
  } else {
    const bytes = await response.arrayBuffer();
    result = await WebAssembly.instantiate(bytes, imports);
  }
  instance = result.instance;
  wasm = instance.exports;
  if (typeof wasm._initialize !== "function") {
    throw new Error("wasm module is missing _initialize export");
  }
  wasm._initialize();
  resetEndpointDiagnostics();
  setModuleState("wasm ready", "ready");
  updateRunButton();
}

function memory() {
  return new Uint8Array(wasm.memory.buffer);
}

function view() {
  return new DataView(wasm.memory.buffer);
}

function allocBytes(bytes) {
  if (bytes.length === 0) return 0;
  const pointer = wasm.coquic_wasm_alloc(bytes.length);
  memory().set(bytes, pointer);
  return pointer;
}

function withBytes(bytes, callback) {
  const pointer = allocBytes(bytes);
  try {
    return callback(pointer, bytes.length);
  } finally {
    if (pointer) wasm.coquic_wasm_free(pointer);
  }
}

function readBytes(pointer, length) {
  return new Uint8Array(memory().slice(pointer, pointer + length));
}

function endpointDiagnostics(endpoint) {
  if (!wasm?.coquic_wasm_endpoint_diagnostics || !endpoint) return null;
  for (const size of [16384, 65536, 262144, 1048576]) {
    const pointer = wasm.coquic_wasm_alloc(size);
    try {
      const written = wasm.coquic_wasm_endpoint_diagnostics(endpoint, pointer, size);
      if (written === -2) continue;
      if (written < 0) throw new Error(`endpoint diagnostics failed ${written}`);
      return JSON.parse(decoder.decode(readBytes(pointer, written)));
    } finally {
      wasm.coquic_wasm_free(pointer);
    }
  }
  throw new Error("endpoint diagnostics buffer too small");
}

function formatBytes(value) {
  const bytes = Number(value ?? 0);
  if (!Number.isFinite(bytes)) return "0B";
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)}KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MiB`;
}

function formatCount(value) {
  if (value === null || value === undefined) return "none";
  return `${value}`;
}

function formatVersion(value) {
  const version = Number(value ?? 0);
  if (!version) return "none";
  return `0x${version.toString(16).padStart(8, "0")}`;
}

function boolText(value) {
  return value ? "yes" : "no";
}

function setText(id, text) {
  const node = el(id);
  if (node) node.textContent = text;
}

function renderStateMachine(label, status) {
  const node = el(`${label}-state-machine`);
  const states = [
    ["idle", "Idle", "endpoint allocated"],
    ["in_progress", "Handshake", "TLS and transport"],
    ["connected", "Connected", "1-RTT ready"],
    ["failed", "Failed", "terminal error"],
  ];
  const currentIndex = Math.max(0, states.findIndex(([key]) => key === status));
  node.textContent = "";
  for (const [index, [key, title, caption]] of states.entries()) {
    const step = document.createElement("div");
    step.className = `state-step${index === currentIndex ? " current" : ""}${index < currentIndex && status !== "failed" ? " done" : ""}`;
    step.innerHTML = "<strong></strong><span></span>";
    step.children[0].textContent = title;
    step.children[1].textContent = caption;
    step.dataset.state = key;
    node.append(step);
  }
}

function renderStatList(id, rows, flag = false) {
  const list = el(id);
  list.textContent = "";
  for (const row of rows) {
    const item = document.createElement("div");
    item.className = flag ? `diag-flag${row.value ? " on" : ""}` : "diag-stat";
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = row.label;
    dd.textContent = flag ? boolText(row.value) : row.value;
    item.append(dt, dd);
    list.append(item);
  }
}

function pill(value) {
  return `<span class="diag-pill${value ? " on" : ""}">${value ? "yes" : "no"}</span>`;
}

function renderTable(id, columns, rows, emptyText) {
  const wrap = el(id);
  wrap.textContent = "";
  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "diag-empty";
    empty.textContent = emptyText;
    wrap.append(empty);
    return;
  }
  const table = document.createElement("table");
  table.className = "diag-table";
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const column of columns) {
    const th = document.createElement("th");
    th.textContent = column.label;
    headRow.append(th);
  }
  thead.append(headRow);
  table.append(thead);
  const tbody = document.createElement("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const column of columns) {
      const td = document.createElement("td");
      const value = row[column.key];
      if (typeof value === "object" && value?.html !== undefined) {
        td.innerHTML = value.html;
      } else {
        td.textContent = value ?? "";
      }
      tr.append(td);
    }
    tbody.append(tr);
  }
  table.append(tbody);
  wrap.append(table);
}

function streamState(stream) {
  if (stream.peer_reset_received) return "reset";
  if (stream.send_closed && stream.receive_closed) return "closed";
  if (stream.outstanding_send) return "in flight";
  if (stream.pending_send) return "queued";
  if (stream.peer_fin_delivered) return "peer fin";
  return "open";
}

function defaultEndpointStats() {
  return {
    sentDatagrams: 0,
    sentBytes: 0,
    receivedDatagrams: 0,
    receivedBytes: 0,
    events: 0,
  };
}

function makeEndpointStats() {
  return {
    client: defaultEndpointStats(),
    server: defaultEndpointStats(),
  };
}

function resetEndpointDiagnostics() {
  const runState = { endpointStats: makeEndpointStats() };
  renderEndpointDiagnostics("client", { role: "client", connection_count: 0, connections: [] }, runState);
  renderEndpointDiagnostics("server", { role: "server", connection_count: 0, connections: [] }, runState);
}

function renderEndpointDiagnostics(label, diagnostics, runState) {
  const connection = diagnostics?.connections?.[0] ?? null;
  const stats = runState?.endpointStats?.[label] ?? defaultEndpointStats();
  const status = connection?.handshake_status ?? "idle";
  const connectionText = connection?.handle ? `${connection.handle}` : "none";

  setText(`${label}-state`, status);
  setText(`${label}-connection`, connectionText);
  setText(`${label}-version`, formatVersion(connection?.current_version));
  setText(`${label}-sent`, `${stats.sentDatagrams} / ${formatBytes(stats.sentBytes)}`);
  setText(`${label}-received`, `${stats.receivedDatagrams} / ${formatBytes(stats.receivedBytes)}`);
  setText(`${label}-events`, `${stats.events}`);
  setText(`${label}-stream-count`, `${connection?.active_streams ?? 0} active`);
  setText(
    `${label}-endpoint-chip`,
    connection ? `${diagnostics.role} / ${diagnostics.connection_count} conn` : `${diagnostics?.role ?? label} / no connection`,
  );
  renderStateMachine(label, status);

  renderStatList(`${label}-path-flags`, [
    { label: "Peer Packet", value: connection?.processed_peer_packet },
    { label: "TP Validated", value: connection?.peer_transport_parameters_validated },
    { label: "Address Valid", value: connection?.peer_address_validated },
    { label: "Ready Event", value: connection?.handshake_ready_emitted },
    { label: "Confirmed", value: connection?.handshake_confirmed },
    { label: "Failed Event", value: connection?.failed_emitted },
  ], true);

  const recovery = connection?.recovery ?? {};
  setText(`${label}-recovery-caption`, `${recovery.algorithm ?? "newreno"} / pto ${recovery.pto_count ?? 0}`);
  renderStatList(`${label}-recovery`, [
    { label: "CWND", value: formatBytes(recovery.congestion_window) },
    { label: "In Flight", value: formatBytes(recovery.bytes_in_flight) },
    { label: "Latest RTT", value: recovery.latest_rtt_ms === null || recovery.latest_rtt_ms === undefined ? "none" : `${recovery.latest_rtt_ms}ms` },
    { label: "Min RTT", value: recovery.min_rtt_ms === null || recovery.min_rtt_ms === undefined ? "none" : `${recovery.min_rtt_ms}ms` },
    { label: "SRTT", value: `${recovery.smoothed_rtt_ms ?? 0}ms` },
    { label: "RTTVar", value: `${recovery.rttvar_ms ?? 0}ms` },
    { label: "PTO Count", value: `${recovery.pto_count ?? 0}` },
    { label: "Paths", value: `${connection?.active_paths ?? 0}` },
  ]);

  const spaces = connection?.packet_spaces ?? [];
  const keyedSpaces = spaces.filter((space) => space.read_secret_available || space.write_secret_available).length;
  setText(`${label}-packet-caption`, `${keyedSpaces}/${spaces.length || 4} spaces keyed`);
  renderTable(
    `${label}-packet-spaces`,
    [
      { key: "name", label: "Space" },
      { key: "keys", label: "Keys" },
      { key: "next", label: "Next PN" },
      { key: "acked", label: "Largest Acked" },
      { key: "outstanding", label: "Out" },
      { key: "lost", label: "Lost" },
      { key: "ack", label: "ACK Due" },
      { key: "work", label: "Work" },
    ],
    spaces.map((space) => ({
      name: space.name,
      keys: { html: `${pill(space.read_secret_available)} r&nbsp; ${pill(space.write_secret_available)} w` },
      next: formatCount(space.next_send_packet_number),
      acked: formatCount(space.largest_authenticated_packet_number),
      outstanding: formatCount(space.outstanding_packets),
      lost: formatCount(space.declared_lost_packets),
      ack: space.pending_ack_deadline_ms === null || space.pending_ack_deadline_ms === undefined ? "none" : `${space.pending_ack_deadline_ms}ms`,
      work: [
        space.pending_crypto ? "crypto" : "",
        space.pending_probe ? "probe" : "",
        space.force_ack ? "ack" : "",
      ].filter(Boolean).join(", ") || "none",
    })),
    "No packet spaces have been exported yet.",
  );

  const flow = connection?.flow_control ?? {};
  renderStatList(`${label}-flow`, [
    { label: "Peer Max", value: formatBytes(flow.peer_max_data) },
    { label: "Highest Sent", value: formatBytes(flow.highest_sent) },
    { label: "Advertised", value: formatBytes(flow.advertised_max_data) },
    { label: "Delivered", value: formatBytes(flow.delivered_bytes) },
  ]);

  const limits = connection?.stream_limits ?? {};
  renderStatList(`${label}-stream-limits`, [
    { label: "Peer Bidi", value: formatCount(limits.peer_max_bidirectional ?? 0) },
    { label: "Peer Uni", value: formatCount(limits.peer_max_unidirectional ?? 0) },
    { label: "Local Bidi", value: formatCount(limits.advertised_max_bidirectional ?? 0) },
    { label: "Local Uni", value: formatCount(limits.advertised_max_unidirectional ?? 0) },
  ]);

  const streams = connection?.streams ?? [];
  setText(`${label}-stream-caption`, streams.length ? `${streams.length} active / ${connection?.retired_streams ?? 0} retired` : `${connection?.retired_streams ?? 0} retired`);
  renderTable(
    `${label}-streams`,
    [
      { key: "id", label: "ID" },
      { key: "owner", label: "Owner" },
      { key: "direction", label: "Dir" },
      { key: "state", label: "State" },
      { key: "sendable", label: "Sendable" },
      { key: "sentLimit", label: "Send FC" },
      { key: "recv", label: "Recv" },
      { key: "fin", label: "FIN" },
    ],
    streams.map((stream) => ({
      id: formatCount(stream.stream_id),
      owner: stream.initiator,
      direction: stream.direction,
      state: streamState(stream),
      sendable: formatBytes(stream.sendable_bytes),
      sentLimit: formatBytes(stream.send_flow_control_limit),
      recv: `${formatBytes(stream.highest_received_offset)} / ${formatBytes(stream.receive_flow_control_limit)}`,
      fin: stream.send_fin_state,
    })),
    "No active streams.",
  );
}

function updateEndpointDiagnostics(client, server, runState) {
  renderEndpointDiagnostics("client", endpointDiagnostics(client), runState);
  renderEndpointDiagnostics("server", endpointDiagnostics(server), runState);
}

function header(size, fn) {
  const pointer = wasm.coquic_wasm_alloc(size);
  try {
    const status = fn(pointer, size);
    if (status < 0) throw new Error(`header read failed ${status}`);
    if (status === 0) return null;
    return new DataView(memory().slice(pointer, pointer + size).buffer);
  } finally {
    wasm.coquic_wasm_free(pointer);
  }
}

function popDatagram(endpoint) {
  const h = header(40, (p, n) => wasm.coquic_wasm_endpoint_next_datagram_header(endpoint, p, n));
  if (!h) return null;
  const length = h.getUint32(28, true);
  const pointer = wasm.coquic_wasm_alloc(length);
  try {
    const read = wasm.coquic_wasm_endpoint_pop_datagram(endpoint, pointer, length);
    if (read < 0) throw new Error(`pop datagram failed ${read}`);
    return {
      route: h.getBigUint64(8, true),
      ecn: h.getUint32(20, true),
      inspectionDatagramId: h.getBigUint64(32, true),
      bytes: readBytes(pointer, read),
    };
  } finally {
    wasm.coquic_wasm_free(pointer);
  }
}

function popEvent(endpoint) {
  const h = header(48, (p, n) => wasm.coquic_wasm_endpoint_next_event_header(endpoint, p, n));
  if (!h) return null;
  const length = h.getUint32(28, true);
  const pointer = wasm.coquic_wasm_alloc(length);
  try {
    const read = wasm.coquic_wasm_endpoint_pop_event(endpoint, pointer, length);
    if (read < 0) throw new Error(`pop event failed ${read}`);
    return {
      type: h.getUint32(0, true),
      code: h.getUint32(4, true),
      connection: h.getBigUint64(8, true),
      streamId: h.getBigUint64(16, true),
      fin: h.getUint32(24, true) !== 0,
      payload: readBytes(pointer, read),
    };
  } finally {
    wasm.coquic_wasm_free(pointer);
  }
}

function hasDatagram(endpoint) {
  return header(40, (p, n) => wasm.coquic_wasm_endpoint_next_datagram_header(endpoint, p, n)) !== null;
}

function hasEvent(endpoint) {
  return header(48, (p, n) => wasm.coquic_wasm_endpoint_next_event_header(endpoint, p, n)) !== null;
}

function popPacketInspection(endpoint) {
  const h = header(48, (p, n) => wasm.coquic_wasm_endpoint_next_packet_inspection_header(endpoint, p, n));
  if (!h) return null;
  const length = h.getUint32(36, true);
  const pointer = wasm.coquic_wasm_alloc(length);
  try {
    const read = wasm.coquic_wasm_endpoint_pop_packet_inspection(endpoint, pointer, length);
    if (read < 0) throw new Error(`pop packet inspection failed ${read}`);
    const inspection = JSON.parse(decoder.decode(readBytes(pointer, read)));
    return {
      ...inspection,
      header: {
        connection: h.getBigUint64(0, true),
        direction: h.getUint32(8, true),
        packetType: h.getUint32(12, true),
        packetNumber: h.getBigUint64(16, true),
        datagramId: h.getBigUint64(24, true),
        packetLength: h.getUint32(32, true),
      },
    };
  } finally {
    wasm.coquic_wasm_free(pointer);
  }
}

function packetInspectionKey(endpoint, datagramId) {
  return `${endpoint}:${datagramId.toString()}`;
}

function drainEndpointPacketInspections(endpoint, runState) {
  for (;;) {
    const inspection = popPacketInspection(endpoint);
    if (!inspection) break;
    const key = packetInspectionKey(endpoint, inspection.header.datagramId);
    const existing = runState.packetInspections.get(key) ?? [];
    existing.push(inspection);
    runState.packetInspections.set(key, existing);
  }
}

function noteReceivedPingPongChunk(label, event, runState) {
  const key = `${label}:${event.streamId.toString()}`;
  const total = (runState.streamReceiveBytes.get(key) ?? 0) + event.payload.length;
  const completeMessages = Math.floor(total / pingPongPayloadBytes);
  const remainingBytes = total % pingPongPayloadBytes;
  runState.streamReceiveBytes.set(key, remainingBytes);
  for (let index = 0; index < completeMessages; index += 1) {
    if (runState.pendingPingPong.length >= maxPendingPingPong) break;
    runState.pendingPingPong.push({
      sender: label,
      streamId: event.streamId,
    });
  }
}

function handleOneEvent(endpoint, label, runState) {
  const event = popEvent(endpoint);
  if (!event) return false;
  runState.endpointStats[label].events += 1;
  if (event.type === 1) {
    const name = stateCodes[event.code] ?? `state_${event.code}`;
    runState[`${label}State`] = name;
    el(`${label}-state`).textContent = name;
    log(runState.timelineMs, `${label} ${name}`);
  } else if (event.type === 2) {
    runState[`${label}Connection`] = event.connection;
    el(`${label}-connection`).textContent = `${event.connection}`;
    log(runState.timelineMs, `${label} connection ${event.connection}`);
  } else if (event.type === 3) {
    const text = decoder.decode(event.payload);
    runState.receivedStreamText = text;
    noteReceivedPingPongChunk(label, event, runState);
    log(runState.timelineMs, `${label} stream ${event.streamId}: ${text}`);
  } else if (event.type === 4) {
    log(runState.timelineMs, `${label} local error ${event.code}`, "error");
    throw new Error(`${label} local error ${event.code}`);
  }
  return true;
}

function drainInternalEvents(runState) {
  let drained = false;
  for (;;) {
    let progressed = false;
    if (hasEvent(runState.clientEndpoint)) {
      if (!handleOneEvent(runState.clientEndpoint, "client", runState)) {
        throw new Error("client event disappeared before internal drain");
      }
      progressed = true;
    }
    if (hasEvent(runState.serverEndpoint)) {
      if (!handleOneEvent(runState.serverEndpoint, "server", runState)) {
        throw new Error("server event disappeared before internal drain");
      }
      progressed = true;
    }
    if (!progressed) break;
    drained = true;
  }
  return drained;
}

function queueDatagramIfAvailable(from, to, toRoute, runState, label, direction) {
  drainEndpointPacketInspections(from, runState);
  const datagram = popDatagram(from);
  if (!datagram) return false;
  drainEndpointPacketInspections(from, runState);
  const key = packetInspectionKey(from, datagram.inspectionDatagramId);
  const inspections = runState.packetInspections.get(key) ?? [];
  runState.packetInspections.delete(key);
  const records = captureDatagram(direction, datagram, runState.timelineMs, inspections);
  const animations = records.map((record) => visualizePacket(direction, record));
  const visual = visualizeDatagram(direction, datagram, records, animations.map((animation) => animation.item));
  setDatagramPhase(visual, "in-flight");
  runState.endpointStats[direction].sentDatagrams += 1;
  runState.endpointStats[direction].sentBytes += datagram.bytes.length;
  const sentAtMs = runState.timelineMs;
  runState.inFlight.push({
    datagram,
    records,
    animations,
    visual,
    to,
    toRoute,
    label,
    direction,
    sentAtMs,
    arrivalAtMs: sentAtMs + packetDelayMs,
  });
  log(runState.timelineMs, `${label} ${datagram.bytes.length} bytes in flight`);
  return true;
}

async function arriveDueDatagrams(runState, { instant = false } = {}) {
  if (!isRunActive(runState.runToken)) return false;
  if (runState.inFlight.length === 0) return false;
  const arrivalAtMs = Math.min(...runState.inFlight.map((item) => item.arrivalAtMs));
  const due = runState.inFlight.filter((item) => item.arrivalAtMs === arrivalAtMs);
  runState.inFlight = runState.inFlight.filter((item) => item.arrivalAtMs !== arrivalAtMs);
  await Promise.all(due.flatMap((item) => item.animations.map((animation) => animation.wait({ instant }))));
  if (!isRunActive(runState.runToken)) return false;
  runState.timelineMs = Math.max(runState.timelineMs, arrivalAtMs);
  setGlobalTimer(runState.timelineMs);
  for (const item of due) {
    setDatagramPhase(item.visual, "arrived");
    runState.arrived.push(item);
    log(runState.timelineMs, `${item.label} ${item.datagram.bytes.length} bytes arrived`);
  }
  return true;
}

async function receiveNextArrivedDatagram(runState, protocolNow) {
  if (!isRunActive(runState.runToken)) return false;
  const item = runState.arrived.shift();
  if (!item) return false;
  const receiver = item.direction === "client" ? "server" : "client";
  withBytes(item.datagram.bytes, (pointer, length) => {
    const rc = wasm.coquic_wasm_endpoint_input_datagram(
      item.to,
      BigInt(protocolNow),
      pointer,
      length,
      BigInt(item.toRoute),
      item.datagram.ecn,
    );
    if (rc < 0) throw new Error(`input datagram failed ${rc}`);
  });
  runState.endpointStats[receiver].receivedDatagrams += 1;
  runState.endpointStats[receiver].receivedBytes += item.datagram.bytes.length;
  drainEndpointPacketInspections(item.to, runState);
  runState.datagrams += 1;
  setDatagramPhase(item.visual, "received");
  if (item.animations.length > 0) {
    for (const animation of item.animations) animation.receive();
    item.acceptIndex = 0;
    runState.accepting.push(item);
  }
  log(runState.timelineMs, `${item.label} ${item.datagram.bytes.length} bytes received`);
  return true;
}

async function acceptNextPacket(runState) {
  if (!isRunActive(runState.runToken)) return false;
  const item = runState.accepting[0];
  if (!item) return false;
  const animation = item.animations[item.acceptIndex];
  if (!animation) {
    runState.accepting.shift();
    return false;
  }
  animation.accept();
  const record = item.records[item.acceptIndex];
  log(runState.timelineMs, `${item.label} packet #${record.id} ${record.kind} accepted`);
  item.acceptIndex += 1;
  if (item.acceptIndex >= item.animations.length) {
    runState.accepting.shift();
    retireDatagram(item.visual);
  }
  return true;
}

function readWakeups(runState) {
  const cw = wasmI64ToNumber(
    wasm.coquic_wasm_endpoint_next_wakeup_ms(runState.clientEndpoint),
    "client wakeup",
  );
  const sw = wasmI64ToNumber(
    wasm.coquic_wasm_endpoint_next_wakeup_ms(runState.serverEndpoint),
    "server wakeup",
  );
  el("client-wakeup").textContent = cw >= 0 ? `${cw}ms` : "none";
  el("server-wakeup").textContent = sw >= 0 ? `${sw}ms` : "none";
  return { client: cw, server: sw };
}

function queuePingPongMessage(runState, protocolNow, sender, streamId) {
  const endpoint = sender === "client" ? runState.clientEndpoint : runState.serverEndpoint;
  const connection =
    sender === "client" ? runState.clientConnection : runState.serverConnection;
  if (connection === 0n) {
    throw new Error(`${sender} connection is not ready for stream send`);
  }
  runState.pingPongSequence += 1;
  const payload = pingPongPayload(sender, runState.pingPongSequence);
  withBytes(payload, (pointer, length) => {
    const rc = wasm.coquic_wasm_endpoint_send_stream(
      endpoint,
      BigInt(protocolNow),
      connection,
      streamId,
      pointer,
      length,
      0,
    );
    if (rc < 0) throw new Error(`${sender} send stream failed ${rc}`);
  });
  log(
    runState.timelineMs,
    `${sender} queued stream ${streamId} message ${runState.pingPongSequence} (${payload.length} bytes)`,
  );
}

async function runDemo({ startPaused = false } = {}) {
  const runToken = activeRunToken;
  demoState = startPaused ? "paused" : "running";
  paused = startPaused;
  if (!startPaused) stepBudget = 0;
  updateRunButton();
  setGlobalTimer(0);
  el("log").textContent = "";
  clearPackets();
  resetPacketInspector();
  packetSerial = 0;
  el("client-state").textContent = "idle";
  el("server-state").textContent = "idle";
  el("client-connection").textContent = "none";
  el("server-connection").textContent = "none";
  el("client-wakeup").textContent = "none";
  el("server-wakeup").textContent = "none";
  resetEndpointDiagnostics();
  const cert = encoder.encode(certPem);
  const key = encoder.encode(keyPem);
  const client = wasm.coquic_wasm_endpoint_create(0, 0, 0, 0, 0);
  const server = withBytes(cert, (cp, cn) =>
    withBytes(key, (kp, kn) => wasm.coquic_wasm_endpoint_create(1, cp, cn, kp, kn)),
  );
  const runState = {
    clientState: "idle",
    serverState: "idle",
    datagrams: 0,
    clientConnection: 0n,
    serverConnection: 0n,
    packetInspections: new Map(),
    timelineMs: 0,
    receivedStreamText: "",
    inFlight: [],
    arrived: [],
    accepting: [],
    pendingPingPong: [],
    streamReceiveBytes: new Map(),
    pingPongSequence: 0,
    runToken,
    stepIndex: 0,
    endpointStats: makeEndpointStats(),
    clientEndpoint: client,
    serverEndpoint: server,
  };
  let protocolNow = 0;

  try {
    updateEndpointDiagnostics(client, server, runState);

    await runAutomaticStep(runState, () => {
      const opened = wasm.coquic_wasm_endpoint_open_connection(
        client,
        BigInt(protocolNow),
        0,
        0,
        0,
        0,
        1n,
      );
      if (opened <= 0) throw new Error(`open failed ${opened}`);
      runState.clientConnection = BigInt(opened);
      el("client-connection").textContent = `${runState.clientConnection}`;
      log(runState.timelineMs, `client open connection ${runState.clientConnection}`);
    });

    let idleRounds = 0;
    while (isRunActive(runToken)) {
      protocolNow += 1;
      let progressed = false;
      const wakeups = readWakeups(runState);

      if (runState.accepting.length > 0) {
        const item = runState.accepting[0];
        const record = item.records[item.acceptIndex];
        if (!record) {
          runState.accepting.shift();
          continue;
        }
        if (!(await runProtocolStep(runState, `packet #${record.id} accepted`, () =>
          acceptNextPacket(runState)
        ))) {
          break;
        }
        progressed = true;
        continue;
      }
      if (runState.arrived.length > 0) {
        if (!(await runProtocolStep(runState, `${runState.arrived[0].label} received`, () =>
          receiveNextArrivedDatagram(runState, protocolNow)
        ))) {
          break;
        }
        progressed = true;
        continue;
      }
      if (hasDatagram(client)) {
        if (!(await runProtocolStep(runState, "client emits datagram", () => {
          if (!queueDatagramIfAvailable(client, server, 7, runState, "client -> server", "client")) {
            throw new Error("client datagram disappeared before emit step");
          }
        }))) {
          break;
        }
        progressed = true;
        continue;
      }
      if (hasDatagram(server)) {
        if (!(await runProtocolStep(runState, "server emits datagram", () => {
          if (!queueDatagramIfAvailable(server, client, 1, runState, "server -> client", "server")) {
            throw new Error("server datagram disappeared before emit step");
          }
        }))) {
          break;
        }
        progressed = true;
        continue;
      }
      if (runState.inFlight.length > 0) {
        const arrivalAtMs = Math.min(...runState.inFlight.map((item) => item.arrivalAtMs));
        const dueCount = runState.inFlight.filter((item) => item.arrivalAtMs === arrivalAtMs).length;
        if (!(await runProtocolStep(runState, `${dueCount} datagram${dueCount === 1 ? "" : "s"} arrive`, (stepMode) =>
          arriveDueDatagrams(runState, { instant: stepMode === "single" })
        ))) {
          break;
        }
        progressed = true;
        continue;
      }
      if (hasEvent(client) || hasEvent(server)) {
        drainInternalEvents(runState);
        updateEndpointDiagnostics(client, server, runState);
        progressed = true;
        continue;
      }

      const handshakeReady =
        runState.clientState === "handshake_confirmed" &&
        runState.serverState === "handshake_confirmed";
      if (handshakeReady && runState.pingPongSequence === 0) {
        if (!(await runAutomaticStep(runState, () => {
          queuePingPongMessage(runState, protocolNow, "client", 0n);
        }))) {
          break;
        }
        progressed = true;
        continue;
      }
      if (runState.pendingPingPong.length > 0) {
        const next = runState.pendingPingPong.shift();
        if (!(await runAutomaticStep(runState, () => {
          queuePingPongMessage(runState, protocolNow, next.sender, next.streamId);
        }))) {
          break;
        }
        progressed = true;
        continue;
      }

      const clientTimerDue = wakeups.client >= 0 && wakeups.client <= protocolNow;
      const serverTimerDue = wakeups.server >= 0 && wakeups.server <= protocolNow;
      if (clientTimerDue) {
        if (!(await runAutomaticStep(runState, () => {
          const rc = wasm.coquic_wasm_endpoint_timer_expired(client, BigInt(protocolNow));
          if (rc < 0) throw new Error(`client timer failed ${rc}`);
          log(runState.timelineMs, `client timer fired at ${protocolNow}ms`);
        }))) {
          break;
        }
        progressed = true;
        continue;
      }
      if (serverTimerDue) {
        if (!(await runAutomaticStep(runState, () => {
          const rc = wasm.coquic_wasm_endpoint_timer_expired(server, BigInt(protocolNow));
          if (rc < 0) throw new Error(`server timer failed ${rc}`);
          log(runState.timelineMs, `server timer fired at ${protocolNow}ms`);
        }))) {
          break;
        }
        progressed = true;
        continue;
      }

      idleRounds += progressed ? 0 : 1;
      if (!progressed) {
        const futureWakeups = [wakeups.client, wakeups.server]
          .filter((value) => value >= 0 && value > protocolNow);
        if (futureWakeups.length > 0) {
          const nextWakeup = Math.min(...futureWakeups);
          if (!(await runAutomaticStep(runState, () => {
            protocolNow = nextWakeup;
            log(runState.timelineMs, `scheduler advanced to ${protocolNow}ms`);
          }))) {
            break;
          }
          continue;
        }
        if (demoState === "running") {
          await pauseAwareSleep(15);
        } else {
          await new Promise((resolve) => schedulerWaiters.push(resolve));
        }
      }
    }
  } finally {
    wasm.coquic_wasm_endpoint_destroy(client);
    wasm.coquic_wasm_endpoint_destroy(server);
    if (runToken === activeRunToken) {
      demoState = "idle";
      paused = false;
      stepBudget = 0;
      protocolStepInProgress = false;
      setGlobalTimer(runState.timelineMs);
      updateRunButton();
    }
  }
}

function handleStartClick() {
  if (demoState === "paused") {
    resumeDemo();
    return;
  }
  startDemo(false);
}

function bindWorkbenchControls() {
  bindControl("start", "click", handleStartClick);
  bindControl("stop", "click", pauseDemo);
  bindControl("step", "click", requestNextStep);
  bindControl("download-pcap", "click", downloadPcap);
  bindControl("packet-modal-close", "click", closePacketModal);
  bindControl("packet-modal", "click", (event) => {
    if (event.target === el("packet-modal")) closePacketModal();
  });
}

function initializeWorkbenchPage() {
  const root = el("packet-rail");
  if (!root || root === activeWorkbenchRoot) return;
  activeWorkbenchRoot = root;
  stopDemoForUnmount();
  bindWorkbenchControls();
  resetPacketInspector();
  resetEndpointDiagnostics();
  setModuleState(wasm ? "wasm ready" : "loading wasm", wasm ? "ready" : "");
  updateRunButton();
}

loadModule().catch((error) => {
  setModuleState("wasm failed", "failed");
  log(0, error.message, "error");
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && el("packet-modal")?.classList.contains("open")) {
    closePacketModal();
  }
});

window.addEventListener("resize", () => {
  if (!isWorkbenchMounted()) {
    stopDemoForUnmount();
    return;
  }
  renderPacketQueues();
});

const pageObserver = new MutationObserver(() => {
  if (activeWorkbenchRoot && !document.body.contains(activeWorkbenchRoot)) {
    activeWorkbenchRoot = null;
    stopDemoForUnmount();
  }
  initializeWorkbenchPage();
});
pageObserver.observe(document.body, { childList: true, subtree: true });

initializeWorkbenchPage();
