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
  /**
   * v0.6.46: `"error"` cuando la request lleva un secret (en la URL, la query, el body o un header:
   * `fetch` sólo quita `Authorization` al cambiar de host). Pasalo a `fetch` (`{redirect: req.redirect}`): un redirect no puede llevar la clave
   * a otro host. Un hook que lo ignore queda fuera de lo que el motor puede imponer.
   */
  redirect?: "error";
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
  /**
   * Comparar-y-cambiar atómico: escribe `value` sólo si el valor actual es exactamente `expected`
   * (`null` = la clave no existe) y devuelve si escribió. Con esto `state_merge`/`state_cas` son
   * atómicos aunque varias instancias compartan el KV; sin esto, esas dos lo dicen con un error.
   */
  cas?(ns: string, key: string, expected: string | null, value: string): boolean | Promise<boolean>;
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
  /**
   * v0.6.46: en nativo, un `require net` con comodín sólo llega a IPs públicas (el motor resuelve
   * y chequea la IP antes de conectar). Acá la conexión es tuya y el motor no ve la IP: si el
   * programa no es tuyo, resolvé el nombre y chequeá la IP a la que vas a conectar (un nombre como
   * `127.0.0.1.nip.io` resuelve al loopback), y conectá a ésa. Negá loopback (`127.0.0.0/8`,
   * `::1`), las redes privadas (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, CGNAT
   * `100.64.0.0/10`, ULA `fc00::/7`), link-local (`169.254.0.0/16` con la metadata de la nube
   * `169.254.169.254`, `fe80::/10`), multicast y los rangos de documentación; una IPv4 dentro de una
   * IPv6 (`::ffff:a.b.c.d`) cuenta como esa IPv4. El hook no sabe si el programa nombró el host
   * (`require net("db")`): si tus programas necesitan llegar a una red privada, nombrá vos esos
   * destinos en el hook.
   */
  http?(req: HttpRequestPayload): HttpResponsePayload | Promise<HttpResponsePayload>;
  kv?: KvStore;
  /**
   * `info.principals`: los dueños de lo privado que lleva el prompt (vacío con datos públicos).
   * Sólo llega al hook si el techo lo permite (`llm=<principal>@embedder`). Un hook que lanza hace
   * fallar esa llamada con su mensaje.
   */
  llm?(op: string, prompt: string, info: { principals: string[] }): string | LlmResult | Promise<string | LlmResult>;
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
  /**
   * v0.6.45 — etiquetas de flujo de información (`private`/`declassify`). Con `true`, un valor
   * privado (o una rama que dependió de uno) no llega a ningún sumidero: ni `print`, ni el hook
   * `http` (`fetch`/`http_*`), ni el `kv` (`state_*`, `remember`), ni el `llm`. Es lo que hay que
   * encender para correr código que escribió un modelo sobre datos de un usuario.
   */
  labels?: boolean;
  /** Nombre de una variable global cuyo valor final vuelve en `RunResult.result` CON sus etiquetas. */
  result?: string;
  /**
   * La entrada del host, ligada como variable global antes de correr. Cada clave de `sources`
   * presente llega al programa como `private(valor, principales)`. Exige `labels: true`.
   */
  input?: { var: string; value: unknown; sources?: Record<string, string[]> };
  /**
   * Sólo en el modo asíncrono: si la llamada no termina en este plazo — contado desde que EMPIEZA a
   * correr, no desde que entró a la cola —, su Worker se termina y la Promise falla con un error
   * claro (el código no confiable nunca bloquea el hilo del servidor). Un hook del host sin plazo
   * propio que nunca contesta ocupa su Worker si la llamada no tiene `timeoutMs`. `0` = sin plazo;
   * si no, un número finito de milisegundos, como mucho 2147483647.
   */
  timeoutMs?: number;
  /**
   * Tope de pasos del intérprete (los de `steps()`, deterministas), contados desde que empieza la
   * corrida (en `handle`, cada request). Al pasarlo la corrida termina con `ok: false` y un error
   * que lo dice, no con un trap. Sirve en los dos modos. Un entero positivo.
   */
  maxSteps?: number;
  /**
   * Tope en MB de la memoria que RESERVA la corrida (los bytes vivos que cuenta el allocator del
   * módulo desde que empieza, no lo que la instancia ya tenía). La reserva que lo pasaría se
   * rechaza y la corrida termina con `ok: false` y "memory limit reached" (en `handle`, un 500).
   * Cuenta bytes pedidos: la memoria del módulo puede crecer hasta ~2× eso y no se devuelve.
   * Igual que `maxSteps`. Un entero positivo.
   */
  maxMemoryMb?: number;
  /**
   * v0.6.46 — módulos de confianza: `{ nombre: fuente }`. El programa los importa con
   * `use "trusted:nombre" as t` y sólo puede llamar a sus tasks exportadas, que corren con SUS
   * `require` (acotados por `trustedCeiling`) y nada de lo del programa. Es la forma de dejar que
   * código escrito por un modelo, bajo un `ceiling` sin `declassify`, publique sólo lo que la
   * política de una persona publica. Los argumentos de una task de confianza son datos (una task
   * o una lambda entre ellos es error).
   */
  trusted?: Record<string, string>;
  /** El techo de los módulos de confianza, con la gramática de `ceiling` (`"stdout,declassify=clientes"`). */
  trustedCeiling?: string;
}

export interface AuditEntry {
  capability: string;
  granted: boolean;
  source: string;
  reason: string;
  /** "program" (the program asked or called) or "runtime" (an ambient host grant, e.g. time/llm under a ceiling). */
  origin: "program" | "runtime";
}

export interface RunResult {
  ok: boolean;
  /** Las líneas de `print`. */
  output: string[];
  errors: string[];
  audit: AuditEntry[];
  llm_tokens: number;
  /** v0.6.42 — el código de salida: el de `exit(code)` si el programa lo pidió, si no 0 (ok) o 1. */
  exit: number;
  /** Los pasos del intérprete que llevó la corrida; `null` con `labels` si tocó un valor o una rama privada. */
  steps: number | null;
  /** Con `result`: el valor final de esa variable (las partes privadas como `{"$private": [...]}`). */
  result?: unknown;
  /** Con `labels`: cada `declassify` que corrió (quién, qué principal, dónde). */
  declassify?: unknown[];
  /** Con `labels`: si algún valor privado pasó por la corrida (entonces `steps` no se publica). */
  private_seen?: boolean;
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

export interface LoadOptions {
  /** Cuántos Workers usa el modo asíncrono (default 1). Con más, `runAsync` corre en paralelo. */
  workers?: number;
  /**
   * Cuánto puede tardar un Worker en arrancar antes de darlo por perdido (ms, default 30 000; entre 1
   * y 2147483647). Opción de `Synsema.load`/`loadNode`.
   */
  startMs?: number;
}

export declare function instantiateSync(
  module: WebAssembly.Module,
  hostCall: (kind: string, payload: any) => any,
): { exports: WebAssembly.Exports; call(request: object): any };

export declare class Synsema {
  constructor(module: WebAssembly.Module, opts?: LoadOptions);
  static load(src: ModuleSource, opts?: LoadOptions): Promise<Synsema>;
  /**
   * Node: carga el `synsema.wasm` que trae el paquete (sin resolver rutas; anda en Next, rutas
   * `/api` y Server Actions).
   */
  static loadNode(opts?: LoadOptions): Promise<Synsema>;
  /**
   * Prepara la instancia síncrona (obligatorio antes de run/test/check/handle). Después de un trap
   * la instancia se recrea sola; no hace falta volver a llamarlo.
   */
  ready(): Promise<this>;
  version(): string;
  run(source: string, opts?: RunOptions): RunResult;
  test(source: string, opts?: RunOptions): TestResult;
  check(source: string, opts?: { filename?: string }): CheckResult;
  handle(source: string, request: HandleRequest, opts?: RunOptions): HandleResult;
  /**
   * Modo asíncrono (Worker + Atomics): los hooks del host pueden ser async. Las llamadas esperan en
   * una sola cola y van al primer Worker libre (hasta `workers`).
   */
  runAsync(source: string, opts?: RunOptions): Promise<RunResult>;
  testAsync(source: string, opts?: RunOptions): Promise<TestResult>;
  handleAsync(source: string, request: HandleRequest, opts?: RunOptions): Promise<HandleResult>;
  /**
   * Termina los Workers del modo asíncrono. Es final: lo que espera en la cola falla con "closed" y
   * una llamada asíncrona posterior también (la API síncrona sigue andando).
   */
  close(): Promise<void>;
}

export default Synsema;
