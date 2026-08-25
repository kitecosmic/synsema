#!/usr/bin/env node
// Launcher de `synsema` instalado por npm: localiza el binario nativo de la plataforma
// (paquete @synsema/cli-<os>-<cpu>, instalado como optionalDependency por os/cpu) y lo
// ejecuta con los mismos argumentos, stdio heredado y el mismo exit code. Sin
// postinstall ni descargas: el binario viene dentro del paquete de plataforma, así
// `--ignore-scripts` y los registries espejo funcionan igual.
"use strict";

const { spawnSync } = require("node:child_process");
const { createRequire } = require("node:module");
const path = require("node:path");

const PLATFORMS = {
  "linux-x64": "@synsema/cli-linux-x64",
  "darwin-arm64": "@synsema/cli-darwin-arm64",
  "darwin-x64": "@synsema/cli-darwin-x64",
  "win32-x64": "@synsema/cli-win32-x64",
};

function binaryPath() {
  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORMS[key];
  if (!pkg) {
    console.error(
      `synsema: no prebuilt binary for ${key} (supported: ${Object.keys(PLATFORMS).join(", ")}).\n` +
        "Install the native binary instead: https://docs.synsema.com/en/latest/00-quickstart",
    );
    process.exit(2);
  }
  const exe = process.platform === "win32" ? "synsema.exe" : "synsema";
  try {
    // require.resolve desde ESTE archivo: encuentra el paquete de plataforma tanto en una
    // instalación global como en node_modules del proyecto (npx).
    const req = createRequire(__filename);
    return path.join(path.dirname(req.resolve(`${pkg}/package.json`)), exe);
  } catch {
    console.error(
      `synsema: the platform package ${pkg} is not installed. npm skips it when the install\n` +
        "ran with --no-optional or on a different os/cpu; reinstall with `npm i -g synsema`\n" +
        "(or `npm i synsema` in the project) without --no-optional.",
    );
    process.exit(2);
  }
}

const r = spawnSync(binaryPath(), process.argv.slice(2), {
  stdio: "inherit",
  // Le dice al binario que lo administra npm: `synsema update` no se sobreescribe a sí
  // mismo, sugiere `npm i -g synsema@latest`.
  env: { ...process.env, SYNSEMA_INSTALLED_BY: "npm" },
  windowsHide: true,
});
if (r.error) {
  console.error(`synsema: could not launch the binary: ${r.error.message}`);
  process.exit(2);
}
if (r.signal) {
  process.kill(process.pid, r.signal);
}
process.exit(r.status ?? 1);
