// F0: correr el bin wasip1 (synsema-wasm.wasm, el de wasmtime/TEEs) desde Node sin
// instalar wasmtime: Node trae WASI (`node:wasi`; sigue marcado experimental — emite
// un ExperimentalWarning — pero corre el bin entero, verificado en Node 24).
//
//   node examples/embed/node/run-wasip1.mjs [ruta/al/synsema-wasm.wasm] programa.syn
//
// Es la vía "job confidencial": el programa lee archivos/env por WASI (`preopens`)
// y no hay hooks del host — red/LLM/memoria fallan con la verdad del entorno. Para
// prestarle http/kv/llm desde tu app usá el artefacto embebible (demo.mjs).

import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { WASI } from "node:wasi";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const program = args.pop() ?? resolve(here, "../../../tests/wasm_pure.probe.syn");
const wasmPath = args[0] ?? resolve(here, "../../../engine/target/wasm32-wasip1/wasm/synsema-wasm.wasm");

const wasi = new WASI({
  version: "preview1",
  args: ["synsema-wasm", program],
  env: { ETH_KEY: process.env.ETH_KEY ?? "0000000000000000000000000000000000000000000000000000000000000001" },
  preopens: { ".": resolve(here, "../../..") }, // el programa ve el repo como `.`
  returnOnExit: true,
});
const module = await WebAssembly.compile(await readFile(wasmPath));
const instance = await WebAssembly.instantiate(module, wasi.getImportObject());
const code = wasi.start(instance);
process.exit(code);
