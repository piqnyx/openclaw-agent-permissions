import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validatePolicy } from "../src/exec-paths.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requested = process.argv[2] ?? path.join(root, "permissions.example.json");
const target = path.resolve(requested);
try {
  const parsed = JSON.parse(fs.readFileSync(target, "utf8"));
  validatePolicy(parsed);
  console.log(`policy OK: ${target}`);
} catch (err) {
  console.error(`policy INVALID: ${target}: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
}
