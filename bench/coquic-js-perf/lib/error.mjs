export class PerfError extends Error {
  constructor(message) {
    super(message);
    this.name = "PerfError";
  }
}
