import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = path.join(root, "src");
const dist = path.join(root, "dist");
fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });
for (const name of fs.readdirSync(src)) {
  if (!name.endsWith(".js")) continue;
  const source = path.join(src, name);
  execFileSync(process.execPath, ["--check", source], { stdio: "inherit" });
  fs.copyFileSync(source, path.join(dist, name));
}
console.log(`built ${fs.readdirSync(dist).length} modules -> dist/`);
