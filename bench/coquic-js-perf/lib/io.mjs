import dgram from "node:dgram";
import dns from "node:dns/promises";
import net from "node:net";

import { EcnCodepoint, InboundDatagram } from "@coquic/coquic";

import { PerfError } from "./error.mjs";

const MAX_UDP_DATAGRAM_SIZE = 64 * 1024;
const MAX_BUFFERED_SEND_DATAGRAMS = 4096;

export function timeUsToNumber(value) {
  if (value == null) {
    return null;
  }
  if (typeof value === "bigint") {
    return value > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(value);
  }
  return Math.min(Number(value), Number.MAX_SAFE_INTEGER);
}

export class WaitEvent {
  constructor(kind, datagram = null) {
    this.kind = kind;
    this.datagram = datagram;
  }
}

export class UdpRuntime {
  constructor(socket) {
    this.socket = socket;
    this.start = process.hrtime.bigint();
    this.routesByHandle = new Map();
    this.handlesByPeer = new Map();
    this.nextRouteHandle = 1;
    this.sendBuffer = [];
    this.recvQueue = [];
    this.waiters = [];

    this.socket.on("message", (data, rinfo) => {
      const peer = { address: rinfo.address, port: rinfo.port, family: rinfo.family };
      const item = { data: Buffer.from(data.subarray(0, MAX_UDP_DATAGRAM_SIZE)), peer };
      const waiter = this.waiters.shift();
      if (waiter) {
        waiter(item);
      } else {
        this.recvQueue.push(item);
      }
    });
  }

  static async client(host, port) {
    const peer = await resolveRemote(host, port);
    const bindAddress = clientBindAddress(peer);
    const socket = dgram.createSocket(peer.family === 6 ? "udp6" : "udp4");
    await bindSocket(socket, 0, bindAddress);
    const runtime = new UdpRuntime(socket);
    const route = runtime.ensureRoute(peer);
    const identity = runtime.addressValidationIdentity(route);
    if (identity == null) {
      throw new PerfError("missing client primary route identity");
    }
    return { io: runtime, primaryRoute: route, primaryIdentity: identity };
  }

  static async server(host, port) {
    const family = host.includes(":") ? "udp6" : "udp4";
    const socket = dgram.createSocket(family);
    await bindSocket(socket, port, host);
    return new UdpRuntime(socket);
  }

  close() {
    this.socket.close();
  }

  nowUs() {
    const elapsedNs = process.hrtime.bigint() - this.start;
    return Math.min(Number(elapsedNs / 1000n), Number.MAX_SAFE_INTEGER);
  }

  ensureRoute(peer) {
    const key = peerKey(peer);
    if (this.handlesByPeer.has(key)) {
      return this.handlesByPeer.get(key);
    }
    const handle = this.nextRouteHandle++;
    this.handlesByPeer.set(key, handle);
    this.routesByHandle.set(handle, {
      peer,
      addressValidationIdentity: addressValidationIdentity(peer),
    });
    return handle;
  }

  inboundDatagram(rx) {
    return new InboundDatagram({
      bytes: rx.bytes,
      routeHandle: rx.routeHandle,
      addressValidationIdentity: rx.addressValidationIdentity,
      ecn: EcnCodepoint.UNAVAILABLE,
    });
  }

  collectResultEffects(result) {
    const out = [];
    for (const effect of result.effects) {
      if (effect.kind === "send_datagram") {
        if (this.sendBuffer.length >= MAX_BUFFERED_SEND_DATAGRAMS) {
          throw new PerfError("send buffer exceeded before flush; call flushSends more often");
        }
        if (effect.routeHandle == null) {
          throw new PerfError("send datagram missing route handle");
        }
        this.sendBuffer.push({
          routeHandle: Number(effect.routeHandle),
          bytes: effect.bytes,
          ecn: effect.ecn,
          isPmtuProbe: effect.isPmtuProbe,
        });
      } else if (
        [
          "receive_stream_data",
          "state_event",
          "connection_lifecycle_event",
          "peer_reset_stream",
          "peer_stop_sending",
        ].includes(effect.kind)
      ) {
        out.push(effect);
      }
    }
    return out;
  }

  async flushSends() {
    const datagrams = this.sendBuffer;
    this.sendBuffer = [];
    for (const datagram of datagrams) {
      const route = this.routesByHandle.get(datagram.routeHandle);
      if (route == null) {
        throw new PerfError(`unknown route handle ${datagram.routeHandle}`);
      }
      await send(this.socket, datagram.bytes, route.peer.port, route.peer.address);
    }
  }

  async recv() {
    const item =
      this.recvQueue.length > 0
        ? this.recvQueue.shift()
        : await new Promise((resolve) => this.waiters.push(resolve));
    const routeHandle = this.ensureRoute(item.peer);
    return {
      bytes: item.data,
      routeHandle,
      addressValidationIdentity: this.addressValidationIdentity(routeHandle) ?? Buffer.alloc(0),
    };
  }

  async wait(nextWakeup, idleTimeout) {
    nextWakeup = timeUsToNumber(nextWakeup);
    if (this.recvQueue.length > 0) {
      return new WaitEvent("datagram", await this.recv());
    }

    let timerTimeout = null;
    if (nextWakeup != null) {
      const now = this.nowUs();
      if (nextWakeup <= now) {
        return new WaitEvent("timer");
      }
      timerTimeout = (nextWakeup - now) / 1_000_000.0;
    }
    const timerIsEarlier = timerTimeout != null && timerTimeout <= idleTimeout;
    const timeout = timerIsEarlier ? timerTimeout : idleTimeout;

    return await new Promise((resolve) => {
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(onDatagram);
        if (index >= 0) {
          this.waiters.splice(index, 1);
        }
        if (timerIsEarlier) {
          resolve(new WaitEvent("timer"));
        } else {
          resolve(new WaitEvent("idle"));
        }
      }, Math.max(0, Math.trunc(timeout * 1000)));

      const onDatagram = (item) => {
        clearTimeout(timer);
        this.recvQueue.unshift(item);
        this.recv().then((datagram) => resolve(new WaitEvent("datagram", datagram)));
      };
      this.waiters.push(onDatagram);
    });
  }

  addressValidationIdentity(routeHandle) {
    const route = this.routesByHandle.get(Number(routeHandle));
    return route?.addressValidationIdentity ?? null;
  }
}

export function addressValidationIdentity(peer) {
  const addressBytes = ipAddressBytes(peer.address);
  const port = Buffer.alloc(2);
  port.writeUInt16BE(Number(peer.port));
  return Buffer.concat([Buffer.from([addressBytes.version]), addressBytes.bytes, port]);
}

function ipAddressBytes(address) {
  if (net.isIPv4(address)) {
    return { version: 4, bytes: Buffer.from(address.split(".").map((part) => Number(part))) };
  }
  const sections = expandIpv6(address);
  const bytes = Buffer.alloc(16);
  for (let index = 0; index < sections.length; index += 1) {
    bytes.writeUInt16BE(sections[index], index * 2);
  }
  return { version: 6, bytes };
}

async function resolveRemote(host, port) {
  const records = await dns.lookup(host, { all: true });
  if (records.length === 0) {
    throw new PerfError("failed to resolve remote address");
  }
  const record = records[0];
  return { address: record.address, port, family: record.family };
}

function clientBindAddress(peer) {
  if (isLoopback(peer.address)) {
    return peer.family === 4 ? "127.0.0.1" : "::1";
  }
  return peer.family === 4 ? "0.0.0.0" : "::";
}

function isLoopback(address) {
  return address === "::1" || address.startsWith("127.");
}

function bindSocket(socket, port, host) {
  return new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(port, host, () => {
      socket.off("error", reject);
      resolve();
    });
  });
}

function send(socket, bytes, port, host) {
  return new Promise((resolve, reject) => {
    socket.send(bytes, port, host, (error) => (error ? reject(error) : resolve()));
  });
}

function peerKey(peer) {
  return `${peer.address}:${peer.port}`;
}

function expandIpv6(address) {
  const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) {
    return [0, 0, 0, 0, 0, 0xffff, ...ipv4ToWords(mapped[1])];
  }

  const [headRaw, tailRaw] = address.split("::");
  const head = headRaw ? headRaw.split(":").filter(Boolean).map((x) => Number.parseInt(x, 16)) : [];
  const tail = tailRaw ? tailRaw.split(":").filter(Boolean).map((x) => Number.parseInt(x, 16)) : [];
  if (address.includes("::")) {
    return [...head, ...Array(8 - head.length - tail.length).fill(0), ...tail];
  }
  return head;
}

function ipv4ToWords(address) {
  const bytes = address.split(".").map((part) => Number(part));
  return [(bytes[0] << 8) | bytes[1], (bytes[2] << 8) | bytes[3]];
}
