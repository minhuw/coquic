import { writeSync } from "node:fs";

const mode = process.argv[2] ?? "";
const modes = new Set(["malformed", "oversized-stdout", "oversized-stderr", "timeout"]);

function writeAll(fd, byte) {
  const payload = Buffer.alloc(128 * 1024, byte);
  let offset = 0;
  while (offset < payload.length) offset += writeSync(fd, payload, offset, payload.length - offset);
}

if (!modes.has(mode)) {
  writeSync(2, Buffer.from("unknown child mode\n"));
  process.exitCode = 1;
} else if (mode === "malformed") {
  writeSync(1, Buffer.from('{"case":"child-boundary","ok":true,"extra":true}\n'));
} else if (mode === "oversized-stdout") {
  writeAll(1, 120);
} else if (mode === "oversized-stderr") {
  writeAll(2, 120);
  writeSync(1, Buffer.from('{"case":"child-boundary","ok":true}\n'));
} else {
  setInterval(() => {}, 1000);
}
