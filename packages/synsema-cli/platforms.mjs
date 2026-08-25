// Arma los paquetes de plataforma @synsema/cli-<os>-<cpu> a partir de los binarios de un
// release (los assets que sube release.yml) y deja `synsema` (este paquete) con la
// versión y las optionalDependencies pineadas a esa misma versión.
//
//   node packages/synsema-cli/platforms.mjs <version> <dir-con-assets> <dir-salida>
//
// <dir-con-assets> debe tener synsema-linux-x86_64, synsema-macos-aarch64,
// synsema-macos-x86_64, synsema-windows-x86_64.exe (los nombres de los assets del release;
// los que falten se omiten con aviso — útil para la sonda de CI, que sólo tiene linux).
// Cada paquete de plataforma lleva SOLO el binario (+ package.json con os/cpu, así npm
// instala únicamente el de la máquina) — sin scripts, sin descargas.

import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [version, assetsDir, outDir] = process.argv.slice(2);
if (!version || !assetsDir || !outDir) {
  console.error("usage: platforms.mjs <version> <assets-dir> <out-dir>");
  process.exit(2);
}
const here = dirname(fileURLToPath(import.meta.url));

export const PLATFORMS = [
  { name: "@synsema/cli-linux-x64", os: "linux", cpu: "x64", asset: "synsema-linux-x86_64", exe: "synsema" },
  { name: "@synsema/cli-darwin-arm64", os: "darwin", cpu: "arm64", asset: "synsema-macos-aarch64", exe: "synsema" },
  { name: "@synsema/cli-darwin-x64", os: "darwin", cpu: "x64", asset: "synsema-macos-x86_64", exe: "synsema" },
  { name: "@synsema/cli-win32-x64", os: "win32", cpu: "x64", asset: "synsema-windows-x86_64.exe", exe: "synsema.exe" },
];

const built = [];
for (const p of PLATFORMS) {
  const src = join(assetsDir, p.asset);
  if (!existsSync(src)) {
    console.warn(`platforms: ${p.asset} not found in ${assetsDir} — skipping ${p.name}`);
    continue;
  }
  const dir = join(outDir, p.name.replace("@synsema/", ""));
  mkdirSync(dir, { recursive: true });
  copyFileSync(src, join(dir, p.exe));
  if (p.os !== "win32") chmodSync(join(dir, p.exe), 0o755);
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify(
      {
        name: p.name,
        version,
        description: `Synsema native binary for ${p.os}-${p.cpu} (installed by the \`synsema\` package; do not depend on it directly)`,
        license: "MIT",
        os: [p.os],
        cpu: [p.cpu],
        files: [p.exe],
        repository: { type: "git", url: "git+https://github.com/kitecosmic/synsema.git", directory: "packages/synsema-cli" },
      },
      null,
      2,
    ) + "\n",
  );
  writeFileSync(join(dir, "README.md"), `# ${p.name}\n\nNative \`synsema\` binary for ${p.os}-${p.cpu}. Installed automatically by the [\`synsema\`](https://www.npmjs.com/package/synsema) package — install that one.\n`);
  built.push(p.name);
  console.log(`platforms: built ${p.name}@${version} (${p.asset})`);
}

// El paquete principal: versión + optionalDependencies a la misma versión.
const mainDir = join(outDir, "synsema");
mkdirSync(join(mainDir, "bin"), { recursive: true });
const pkg = JSON.parse(readFileSync(join(here, "package.json"), "utf8"));
pkg.version = version;
for (const k of Object.keys(pkg.optionalDependencies)) pkg.optionalDependencies[k] = version;
writeFileSync(join(mainDir, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
copyFileSync(join(here, "bin", "synsema.js"), join(mainDir, "bin", "synsema.js"));
copyFileSync(join(here, "README.md"), join(mainDir, "README.md"));
console.log(`platforms: built synsema@${version} (optional: ${built.join(", ") || "none"})`);
