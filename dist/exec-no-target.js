import fs from "node:fs";
import {
  LearnedRuleStore,
  evaluatePolicy as evaluatePhysicalPolicy,
  validatePolicy as validatePhysicalPolicy,
} from "./exec-physical.js";

const PATHLESS_KEYS = new Set(["allow"]);

function assertObject(value, where) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${where}: must be object`);
}

function validatePathless(pathless) {
  if (pathless === undefined) return;
  assertObject(pathless, "exec.paths.pathless");
  for (const key of Object.keys(pathless)) {
    if (!PATHLESS_KEYS.has(key)) throw new Error(`exec.paths.pathless.${key}: unknown field`);
  }
  if (!Array.isArray(pathless.allow)) throw new Error("exec.paths.pathless.allow must be array");
  if (pathless.allow.some((value) => typeof value !== "string" || !/^[A-Za-z0-9_.+-]+$/u.test(value))) {
    throw new Error("exec.paths.pathless.allow entries must be non-empty simple command names");
  }
  if (new Set(pathless.allow).size !== pathless.allow.length) {
    throw new Error("exec.paths.pathless.allow contains duplicate command names");
  }
}

function stripPathless(policy) {
  const copy = structuredClone(policy);
  if (copy?.exec?.paths && typeof copy.exec.paths === "object" && !Array.isArray(copy.exec.paths)) {
    delete copy.exec.paths.pathless;
  }
  return copy;
}

export function validatePolicy(policy) {
  validatePathless(policy?.exec?.paths?.pathless);
  validatePhysicalPolicy(stripPathless(policy));
  return policy;
}

function splitSimpleCommands(command) {
  if (typeof command !== "string" || !command.trim()) return null;
  const segments = [];
  let current = "";
  let quote = null;

  const flush = () => {
    const segment = current.trim();
    current = "";
    if (!segment) return false;
    segments.push(segment);
    return true;
  };

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    const next = command[i + 1] ?? "";

    if (quote === "'") {
      current += ch;
      if (ch === "'") quote = null;
      continue;
    }
    if (quote === '"') {
      current += ch;
      if (ch === '"') quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
      continue;
    }

    if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) {
      if (!flush()) return null;
      i++;
      continue;
    }
    if (ch === ";" || ch === "|") {
      if (!flush()) return null;
      continue;
    }

    current += ch;
  }

  if (quote !== null || !flush()) return null;
  return segments;
}

export function extractPathlessCommandWords(command) {
  const segments = splitSimpleCommands(command);
  if (!segments) return null;
  const words = [];
  for (const segment of segments) {
    const match = segment.match(/^([A-Za-z0-9_.+-]+)(?=\s|$)/u);
    if (!match) return null;
    words.push(match[1]);
  }
  return words;
}

export function evaluatePolicy(policy, call, learnedStore = null, virtualWorkspaceRoot = "/workspace") {
  const decision = evaluatePhysicalPolicy(policy, call, learnedStore, virtualWorkspaceRoot);
  if (call.capability !== "exec" || !policy.exec?.paths || decision.effect !== "allow") return decision;

  if (Array.isArray(call.paths) && call.paths.length > 0) return decision;

  const command = typeof call.params.command === "string" ? call.params.command : typeof call.params.cmd === "string" ? call.params.cmd : "";
  const commandWords = extractPathlessCommandWords(command);
  const allowed = new Set(policy.exec.paths.pathless?.allow ?? []);
  if (commandWords && commandWords.length > 0 && commandWords.every((word) => allowed.has(word))) {
    return decision;
  }

  return {
    kind: "exec",
    effect: "ask",
    ruleId: `${decision.ruleId}+<exec-path-no-targets>`,
    reason: `${decision.reason}; no explicit filesystem path operands were detected and pathless command trust was not proven${commandWords ? ` for: ${commandWords.join(", ")}` : ""}`,
    allowAlways: false,
    command: decision.command,
  };
}

export class PolicyLoader {
  constructor(policyPath) { this.policyPath = policyPath; this.cacheKey = null; this.cached = null; }
  load() {
    const stat = fs.statSync(this.policyPath, { bigint: true });
    if (!stat.isFile()) throw new Error(`policy path is not a regular file: ${this.policyPath}`);
    const key = `${stat.mtimeNs}:${stat.size}:${stat.ino}`;
    if (this.cached && this.cacheKey === key) return this.cached;
    const parsed = validatePolicy(JSON.parse(fs.readFileSync(this.policyPath, "utf8")));
    this.cached = parsed;
    this.cacheKey = key;
    return parsed;
  }
}

export { LearnedRuleStore };
