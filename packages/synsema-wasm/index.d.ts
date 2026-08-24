// Tipos de @synsema/wasm — la frontera JSON de synsema-wasm-web.

export type HeaderPairs = Array<[string, string]>;

export interface HttpRequestPayload {
  method: string;
  url: string;
  headers: HeaderPairs;
  /** Body como texto (o `body_base64` si era binario). */
  body?: string | null;
  body_base64?: string;
  /** Segundos. */
  timeout: number;
}

export interface HttpResponsePayload {
  status: number;
  headers?: HeaderPairs | Record<string, string> | Headers;
  body?: string | Uint8Array | ArrayBuffer | null;
  /** Error de transporte (DNS, timeout…): el programa lo ve en `{error: …}`. */
  error?: string;
}

export interface KvStore {
  get(ns: string, key: string): string | null | undefined | Promise<string | null | undefined>;
  set(ns: string, key: string, value: string): void | Promise<void>;
  delete?(ns: string, key: string): void | Promise<void>;
  /** Claves del namespace (para `state_all`). */
  list?(ns: string): string[] | Promise<string[]>;
}

export interface LlmResult {
  content: string;
  /** Tokens consumidos (alimenta `llm_usage()`). */
  tokens?: number;
}

/**
 * Lo que tu app le PRESTA al programa. Cada hook es opcional; lo que falta hace que el
 * builtin correspondiente falle con un error claro. El programa igual debe declarar
 * `require net("host")` / `require llm` / `require memory("x")`, y `ceiling` manda.
 * En la API síncrona los hooks deben ser síncronos; en `*Async` pueden devolver Promise.
 */
export interface Host {
  http?(req: HttpRequestPayload): HttpResponsePayload | Promise<HttpResponsePayload>;
  kv?: KvStore;
  llm?(op: string, prompt: string): string | LlmResult | Promise<string | LlmResult>;
  log?(line: string): void | Promise<void>;
  /** Una función, o `true` para la pausa por defecto (Atomics.wait / setTimeout). */
  sleep?: ((secs: number) => void | Promise<void>) | true;
}

export interface RunOptions {
  filename?: string;
  /** Reemplaza al `.env`: `secret("KEY")`/`env("KEY")` resuelven de acá. */
  env?: Record<string, string>;
  /** `"sandbox"` (stdout + time) o la lista de `--cap-set`: `"stdout,secret=ETH_*"`. */
  ceiling?: string;
  host?: Host;
}

export interface AuditEntry {
  capability: string;
  granted: boolean;
  source: string;
  reason: string;
}

export interface RunResult {
  ok: boolean;
  /** Las líneas de `print`. */
  output: string[];
  errors: string[];
  audit: AuditEntry[];
  llm_tokens: number;
}

export interface TestResult {
  ok: boolean;
  passed: number;
  failed: number;
  lines: string[];
  audit: AuditEntry[];
}

export interface CheckResult {
  ok: boolean;
  errors: string[];
}

export interface HandleRequest {
  method?: string;
  /** Path, con `?query` opcional. */
  path?: string;
  headers?: HeaderPairs | Record<string, string> | Headers;
  body?: string | Uint8Array | ArrayBuffer | null;
  ip?: string;
}

export interface HandleResult {
  status: number;
  content_type: string;
  headers: HeaderPairs;
  body?: string;
  /** Cuerpo binario (cuando no es UTF-8). */
  body_base64?: string;
  /** Líneas de `print` del handler. */
  log: string[];
  /** Errores de preparación del programa (parse/top-level); el status es 500. */
  errors: string[];
  audit: AuditEntry[];
}

export type ModuleSource = WebAssembly.Module | Uint8Array | ArrayBuffer | URL | string | Response;

export declare function readModule(src: ModuleSource): Promise<WebAssembly.Module>;
export declare function offersOf(host?: Host): Record<string, boolean>;
export declare function sleepSync(secs: number): void;
export declare function instantiate(
  module: WebAssembly.Module,
  hostCall: (kind: string, payload: any) => any,
): Promise<{ exports: WebAssembly.Exports; call(request: object): any }>;

export declare class Synsema {
  constructor(module: WebAssembly.Module);
  static load(src: ModuleSource): Promise<Synsema>;
  /** Prepara la instancia síncrona (obligatorio antes de run/test/check/handle). */
  ready(): Promise<this>;
  version(): string;
  run(source: string, opts?: RunOptions): RunResult;
  test(source: string, opts?: RunOptions): TestResult;
  check(source: string, opts?: { filename?: string }): CheckResult;
  handle(source: string, request: HandleRequest, opts?: RunOptions): HandleResult;
  /** Modo asíncrono (Worker + Atomics): los hooks del host pueden ser async. */
  runAsync(source: string, opts?: RunOptions): Promise<RunResult>;
  testAsync(source: string, opts?: RunOptions): Promise<TestResult>;
  handleAsync(source: string, request: HandleRequest, opts?: RunOptions): Promise<HandleResult>;
  close(): Promise<void>;
}

export default Synsema;
