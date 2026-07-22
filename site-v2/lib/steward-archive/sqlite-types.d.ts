declare module "node:sqlite" {
  export class DatabaseSync {
    constructor(location: string, options?: Record<string, unknown>);
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
  export interface StatementSync {
    run(...parameters: unknown[]): unknown;
    get(...parameters: unknown[]): Record<string, unknown> | undefined;
    all(...parameters: unknown[]): Array<Record<string, unknown>>;
  }
}
