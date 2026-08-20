import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { matchAny, matchValue, validateMatcher } from "./matchers.js";
import { getValuesAtPath } from "./paths.js";
import { validateToolProfiles } from "./profiles.js";

const EFFECTS = new Set(["allow", "ask", "deny"]);
import { isCodeModeCall } from "./code-mode.js";

const FS_OPERATIONS = ["read", "write", "delete", "move", "execute"];
const TOP_KEYS = new Set(["version", "defaults", "learning", "filesystem", "exec", "codeMode", "tools", "toolProfiles"]);

function asArray(value) { return Array.isArray(value) ? value : [value]; }
function assertObject(value, where) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${where}: must be object`);
}
function assertOnlyKeys(object, allowed, where) {
  for (const key of Object.keys(object)) if (!allowed.has(key)) throw new Error(`${where}.${key}: unknown field`);
}
function validateEffect(value, where) {
  if (!EFFECTS.has(value)) throw new Error(`${where}: allow/ask/deny required`);
}
function validateBoolean(value, where) {
  if (value !== undefined && typeof value !== "boolean") throw new Error(`${where}: boolean required`);
}
function validateMatcherList(value, where) {
  if (value === undefined) return;
  const list = asArray(value);
  if (list.length === 0) throw new Error(`${where}: empty matcher list`);
  list.forEach((matcher, i) => validateMatcher(matcher, `${where}[${i}]`));
}
function validateStringList(value, where) {
  if (value === undefined) return;
  if (!Array.isArray(value) || value.length === 0 || value.some((x) => typeof x !== "string" || !x)) {
    throw new Error(`${where}: must be a non-empty string[]`);
  }
}
function contextMatches(object, call) {
  if (object.agents !== undefined && !(typeof call.agentId === "string" && matchAny(object.agents, call.agentId))) return false;
  if (object.sessions !== undefined && !(typeof call.sessionKey === "string" && matchAny(object.sessions, call.sessionKey))) return false;
  if (object.tools !== undefined && !(typeof call.toolName === "string" && matchAny(object.tools, call.toolName))) return false;
  return true;
}

function validateFilesystem(fsPolicy) {
  if (fsPolicy === undefined) return;
  assertObject(fsPolicy, "filesystem");
  assertOnlyKeys(fsPolicy, new Set(["default", "allowAlways", "zones"]), "filesystem");
  validateEffect(fsPolicy.default ?? "ask", "filesystem.default");
  validateBoolean(fsPolicy.allowAlways, "filesystem.allowAlways");
  if (!Array.isArray(fsPolicy.zones)) throw new Error("filesystem.zones must be array");
  const ids = new Set();
  fsPolicy.zones.forEach((zone, i) => {
    const where = `filesystem.zones[${i}]`;
    assertObject(zone, where);
    assertOnlyKeys(zone, new Set(["id", "description", "path", "agents", "sessions", "allowAlways", ...FS_OPERATIONS]), where);
    if (typeof zone.id !== "string" || !zone.id) throw new Error(`${where}.id: required`);
    if (ids.has(zone.id)) throw new Error(`${where}.id: duplicate '${zone.id}'`);
    ids.add(zone.id);
    if (zone.description !== undefined && typeof zone.description !== "string") throw new Error(`${where}.description: string required`);
    validateMatcher(zone.path, `${where}.path`);
    validateMatcherList(zone.agents, `${where}.agents`);
    validateMatcherList(zone.sessions, `${where}.sessions`);
    validateBoolean(zone.allowAlways, `${where}.allowAlways`);
    let hasEffect = false;
    for (const op of FS_OPERATIONS) {
      if (zone[op] !== undefined) {
        validateEffect(zone[op], `${where}.${op}`);
        hasEffect = true;
      }
    }
    if (!hasEffect) throw new Error(`${where}: at least one filesystem operation is required`);
  });
}

function execEntryObject(entry) { return typeof entry === "string" ? { regex: entry } : entry; }
function validateExecEntry(entry, where, defaultMatch) {
  const object = execEntryObject(entry);
  assertObject(object, where);
  assertOnlyKeys(object, new Set(["id", "description", "regex", "flags", "match", "allowAlways", "agents", "sessions", "tools"]), where);
  if (object.id !== undefined && (typeof object.id !== "string" || !object.id)) throw new Error(`${where}.id: non-empty string required`);
  if (object.description !== undefined && typeof object.description !== "string") throw new Error(`${where}.description: string required`);
  if (typeof object.regex !== "string" || !object.regex) throw new Error(`${where}.regex: required`);
  validateMatcher({ regex: object.regex, ...(object.flags ? { flags: object.flags } : {}) }, `${where}.regex`);
  const mode = object.match ?? defaultMatch;
  if (!["search", "full"].includes(mode)) throw new Error(`${where}.match: search/full only`);
  validateBoolean(object.allowAlways, `${where}.allowAlways`);
  if (object.allowAlways === true) {
    throw new Error(`${where}.allowAlways=true is intentionally unsupported; use an exec.allow regex rule instead`);
  }
  validateMatcherList(object.agents, `${where}.agents`);
  validateMatcherList(object.sessions, `${where}.sessions`);
  validateMatcherList(object.tools, `${where}.tools`);
}
function validateExec(execPolicy) {
  if (execPolicy === undefined) return;
  assertObject(execPolicy, "exec");
  assertOnlyKeys(execPolicy, new Set(["default", "allowAlways", "deny", "ask", "allow"]), "exec");
  validateEffect(execPolicy.default ?? "ask", "exec.default");
  validateBoolean(execPolicy.allowAlways, "exec.allowAlways");
  if (execPolicy.allowAlways === true) {
    throw new Error("exec.allowAlways=true is intentionally unsupported; use explicit exec.allow regex rules for durable command trust");
  }
  const ids = new Set();
  for (const [bucket, defaultMatch] of [["deny", "search"], ["ask", "search"], ["allow", "full"]]) {
    const list = execPolicy[bucket] ?? [];
    if (!Array.isArray(list)) throw new Error(`exec.${bucket} must be array`);
    list.forEach((entry, i) => {
      validateExecEntry(entry, `exec.${bucket}[${i}]`, defaultMatch);
      const id = execEntryObject(entry).id;
      if (id) {
        if (ids.has(id)) throw new Error(`exec.${bucket}[${i}].id: duplicate '${id}'`);
        ids.add(id);
      }
    });
  }
}

function validateToolRule(rule, where) {
  assertObject(rule, where);
  assertOnlyKeys(rule, new Set(["id", "description", "tools", "capabilities", "operations", "agents", "sessions", "params", "allowAlways"]), where);
  if (typeof rule.id !== "string" || !rule.id) throw new Error(`${where}.id: required`);
  if (rule.description !== undefined && typeof rule.description !== "string") throw new Error(`${where}.description: string required`);
  validateMatcherList(rule.tools, `${where}.tools`);
  validateStringList(rule.capabilities, `${where}.capabilities`);
  validateStringList(rule.operations, `${where}.operations`);
  validateMatcherList(rule.agents, `${where}.agents`);
  validateMatcherList(rule.sessions, `${where}.sessions`);
  if (rule.params !== undefined) {
    assertObject(rule.params, `${where}.params`);
    for (const [selector, matcher] of Object.entries(rule.params)) validateMatcherList(matcher, `${where}.params.${selector}`);
  }
  validateBoolean(rule.allowAlways, `${where}.allowAlways`);
  const selectors = [rule.tools, rule.capabilities, rule.operations, rule.agents, rule.sessions, rule.params];
  if (selectors.every((value) => value === undefined)) {
    throw new Error(`${where}: at least one match selector is required; use tools.default for a catch-all rule`);
  }
}
function validateTools(toolsPolicy) {
  if (toolsPolicy === undefined) return;
  assertObject(toolsPolicy, "tools");
  assertOnlyKeys(toolsPolicy, new Set(["default", "defaultAllowAlways", "deny", "ask", "allow"]), "tools");
  validateEffect(toolsPolicy.default ?? "ask", "tools.default");
  validateBoolean(toolsPolicy.defaultAllowAlways, "tools.defaultAllowAlways");
  const ids = new Set();
  for (const bucket of ["deny", "ask", "allow"]) {
    const list = toolsPolicy[bucket] ?? [];
    if (!Array.isArray(list)) throw new Error(`tools.${bucket} must be array`);
    list.forEach((rule, i) => {
      validateToolRule(rule, `tools.${bucket}[${i}]`);
      if (ids.has(rule.id)) throw new Error(`tools.${bucket}[${i}].id: duplicate '${rule.id}'`);
      ids.add(rule.id);
    });
  }
}

export function validatePolicy(policy) {
  assertObject(policy, "policy");
  assertOnlyKeys(policy, TOP_KEYS, "policy");
  if (policy.version !== 3) throw new Error("policy.version must be 3");
  if (policy.defaults !== undefined) {
    assertObject(policy.defaults, "defaults");
    assertOnlyKeys(policy.defaults, new Set(["effect"]), "defaults");
  }
  validateEffect(policy.defaults?.effect ?? "ask", "defaults.effect");
  if (policy.learning !== undefined) {
    assertObject(policy.learning, "learning");
    assertOnlyKeys(policy.learning, new Set(["enabled", "path"]), "learning");
    validateBoolean(policy.learning.enabled, "learning.enabled");
    if (policy.learning.path !== undefined && (typeof policy.learning.path !== "string" || !policy.learning.path)) throw new Error("learning.path must be non-empty string");
  }
  validateToolProfiles(policy.toolProfiles);
  validateFilesystem(policy.filesystem);
  validateExec(policy.exec);
  validateCodeMode(policy.codeMode);
  validateTools(policy.tools);
  return policy;
}

function fsOperation(call) {
  if (call.capability === "fs.read") return "read";
  if (call.capability === "fs.write") return "write";
  if (call.capability === "fs.delete") return "delete";
  if (call.capability === "fs.move") return "move";
  if (call.capability === "fs.execute") return "execute";
  return null;
}

function evaluateFilesystem(policy, call, learnedStore) {
  const defaultOperation = fsOperation(call);
  if (!defaultOperation) return null;

  const targets = Array.isArray(call.fsTargets) && call.fsTargets.length > 0
    ? call.fsTargets
    : call.paths.map((filePath) => ({ operation: defaultOperation, path: filePath }));

  if (targets.length === 0) {
    return {
      kind: "filesystem",
      operation: defaultOperation,
      effect: "deny",
      ruleId: "<filesystem-unresolved-path>",
      reason: `filesystem target could not be resolved for ${call.toolName}`,
      allowAlways: false,
      askPaths: [],
      askTargets: []
    };
  }

  const effects = [];
  const zoneIds = [];
  const askTargets = [];
  let canAlways = true;

  for (const targetEntry of targets) {
    const operation = targetEntry.operation;
    const target = targetEntry.path;
    if (!FS_OPERATIONS.includes(operation) || typeof target !== "string" || !target) {
      return {
        kind: "filesystem",
        operation: "mixed",
        effect: "deny",
        ruleId: "<filesystem-invalid-target>",
        reason: `invalid filesystem target metadata for ${call.toolName}`,
        allowAlways: false,
        askPaths: [],
        askTargets: []
      };
    }

    let effect = policy.filesystem?.default ?? policy.defaults?.effect ?? "ask";
    let zone = null;
    for (const candidate of policy.filesystem?.zones ?? []) {
      if (!contextMatches(candidate, call)) continue;
      if (!matchValue(candidate.path, target)) continue;
      if (candidate[operation] === undefined) continue;
      effect = candidate[operation];
      zone = candidate;
      break;
    }

    if (effect === "ask" && learnedStore?.matchesFilesystem(call.agentId, operation, target)) effect = "allow";
    if (effect === "ask") {
      askTargets.push({ operation, path: target });
      canAlways = canAlways && (zone?.allowAlways ?? policy.filesystem?.allowAlways ?? false);
    }
    effects.push(effect);
    zoneIds.push(zone?.id ?? "<filesystem-default>");
  }

  const effect = effects.includes("deny") ? "deny" : effects.includes("ask") ? "ask" : "allow";
  const operations = [...new Set(targets.map((target) => target.operation))];
  const operation = operations.length === 1 ? operations[0] : "mixed";
  return {
    kind: "filesystem",
    operation,
    effect,
    ruleId: [...new Set(zoneIds)].join(","),
    reason: `filesystem policy for ${targets.map((target) => `${target.operation}:${target.path}`).join(", ")}`,
    allowAlways: effect === "ask" && canAlways,
    askPaths: [...new Set(askTargets.map((target) => target.path))],
    askTargets
  };
}

function execMatches(entry, call, defaultMatch) {
  const e = execEntryObject(entry);
  if (!contextMatches(e, call)) return false;
  const command = typeof call.params.command === "string" ? call.params.command : typeof call.params.cmd === "string" ? call.params.cmd : "";
  const mode = e.match ?? defaultMatch;
  const flags = e.flags ?? "u";
  const regex = new RegExp(e.regex, flags.includes("u") ? flags : `${flags}u`);
  if (mode === "search") return regex.test(command);
  const match = regex.exec(command);
  return Boolean(match && match.index === 0 && match[0].length === command.length);
}
function validateCodeMode(section) {
  if (section === undefined) return;
  assertObject(section, "codeMode");
  assertOnlyKeys(section, new Set(["default", "description", "agents", "sessions", "tools"]), "codeMode");
  validateEffect(section.default ?? "ask", "codeMode.default");
  if (section.description !== undefined && typeof section.description !== "string") {
    throw new Error("codeMode.description: string required");
  }
  validateMatcherList(section.agents, "codeMode.agents");
  validateMatcherList(section.sessions, "codeMode.sessions");
  validateMatcherList(section.tools, "codeMode.tools");
}

/**
 * The decision for a program, or null to leave the call to the exec rules.
 *
 * Null when the section is absent, when the payload is an ordinary command, and
 * when the section is scoped to agents or sessions this call is not among -- a
 * narrow scope must not widen into a blanket answer for everybody else.
 */
function evaluateCodeMode(policy, call) {
  const section = policy.codeMode;
  if (section === undefined || !isCodeModeCall(call)) return null;
  if (!contextMatches(section, call)) return null;
  return {
    kind: "code-mode",
    effect: section.default ?? "ask",
    ruleId: "<code-mode>",
    reason: section.description ?? "code-mode program; the tool calls it makes are policed individually",
    allowAlways: false,
    command: ""
  };
}

function evaluateExec(policy, call, learnedStore) {
  if (call.capability !== "exec") return null;
  const command = typeof call.params.command === "string" ? call.params.command : typeof call.params.cmd === "string" ? call.params.cmd : "";
  if (!command) {
    return { kind: "exec", effect: "deny", ruleId: "<exec-unresolved-command>", reason: `exec command could not be resolved for ${call.toolName}`, allowAlways: false, command };
  }
  const p = policy.exec ?? {};
  for (const entry of p.deny ?? []) {
    if (execMatches(entry, call, "search")) {
      const e = execEntryObject(entry);
      return { kind: "exec", effect: "deny", ruleId: e.id ?? "exec.deny", reason: e.description ?? "exec deny regex", allowAlways: false, command };
    }
  }
  for (const entry of p.ask ?? []) {
    const e = execEntryObject(entry);
    if (!execMatches(e, call, "search")) continue;
    return { kind: "exec", effect: "ask", ruleId: e.id ?? "exec.ask", reason: e.description ?? "exec ask regex", allowAlways: false, command };
  }
  for (const entry of p.allow ?? []) {
    const e = execEntryObject(entry);
    if (execMatches(e, call, "full")) return { kind: "exec", effect: "allow", ruleId: e.id ?? "exec.allow", reason: e.description ?? "exec allow regex", allowAlways: false, command };
  }
  const effect = p.default ?? policy.defaults?.effect ?? "ask";
  return { kind: "exec", effect, ruleId: "<exec-default>", reason: "exec default", allowAlways: false, command };
}

function toolRuleMatches(rule, call) {
  if (!contextMatches(rule, call)) return false;
  if (rule.capabilities && !rule.capabilities.includes(call.capability)) return false;
  if (rule.operations && !rule.operations.includes(call.operation)) return false;
  if (rule.params !== undefined) {
    for (const [selector, matcher] of Object.entries(rule.params)) {
      const values = getValuesAtPath(call.params, selector).flatMap((value) => Array.isArray(value) ? value : [value]);
      if (!values.some((value) => typeof value === "string" && matchAny(matcher, value))) return false;
    }
  }
  return true;
}
function evaluateTools(policy, call, learnedStore) {
  const p = policy.tools ?? {};
  for (const rule of p.deny ?? []) {
    if (toolRuleMatches(rule, call)) return { kind: "tool", effect: "deny", ruleId: rule.id, reason: rule.description ?? rule.id, allowAlways: false };
  }
  for (const rule of p.ask ?? []) {
    if (!toolRuleMatches(rule, call)) continue;
    if (learnedStore?.matchesTool(call.agentId, call.toolName, call.capability)) return { kind: "tool", effect: "allow", ruleId: "<learned-tool>", reason: "persisted tool approval", allowAlways: false };
    return { kind: "tool", effect: "ask", ruleId: rule.id, reason: rule.description ?? rule.id, allowAlways: rule.allowAlways === true };
  }
  for (const rule of p.allow ?? []) {
    if (toolRuleMatches(rule, call)) return { kind: "tool", effect: "allow", ruleId: rule.id, reason: rule.description ?? rule.id, allowAlways: false };
  }
  let effect = p.default ?? policy.defaults?.effect ?? "ask";
  if (effect === "ask" && learnedStore?.matchesTool(call.agentId, call.toolName, call.capability)) effect = "allow";
  return { kind: "tool", effect, ruleId: effect === "allow" ? "<learned-tool>" : "<tool-default>", reason: effect === "allow" ? "persisted tool approval" : "tool default", allowAlways: effect === "ask" ? (p.defaultAllowAlways ?? false) : false };
}

export function evaluatePolicy(policy, call, learnedStore = null) {
  const fsDecision = evaluateFilesystem(policy, call, learnedStore);
  if (fsDecision?.effect === "deny") return fsDecision;
  // A program is not a command, so the exec rules are not asked about it. Its own
  // tool calls arrive separately and are policed by the same rules as ever.
  const execDecision = evaluateCodeMode(policy, call) ?? evaluateExec(policy, call, learnedStore);
  if (execDecision?.effect === "deny") return execDecision;
  const toolDecision = evaluateTools(policy, call, learnedStore);
  if (toolDecision?.effect === "deny") return toolDecision;
  if (fsDecision) return fsDecision;
  if (execDecision) return execDecision;
  return toolDecision;
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

function learnedEntryKey(entry) {
  if (entry.kind === "filesystem") return JSON.stringify(["filesystem", entry.agentId ?? null, entry.operation, entry.path]);
  if (entry.kind === "tool") return JSON.stringify(["tool", entry.agentId ?? null, entry.toolName, entry.capability]);
  if (entry.kind === "exec") return JSON.stringify(["exec", entry.agentId ?? null, entry.toolName, entry.command]);
  return null;
}
function validateLearnedEntry(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
  if (!["filesystem", "tool", "exec"].includes(entry.kind)) return null;
  if (typeof entry.agentId !== "string" || !entry.agentId) return null;
  if (entry.kind === "filesystem" && (!FS_OPERATIONS.includes(entry.operation) || typeof entry.path !== "string" || !entry.path)) return null;
  if (entry.kind === "tool" && (typeof entry.toolName !== "string" || !entry.toolName || typeof entry.capability !== "string" || !entry.capability)) return null;
  if (entry.kind === "exec" && (typeof entry.toolName !== "string" || !entry.toolName || typeof entry.command !== "string")) return null;
  return entry;
}

export class LearnedRuleStore {
  constructor(filePath) { this.filePath = filePath; this.cacheKey = null; this.entries = []; this.keys = new Set(); }
  load() {
    try {
      const stat = fs.statSync(this.filePath, { bigint: true });
      if (!stat.isFile()) throw new Error(`learned path is not a regular file: ${this.filePath}`);
      const key = `${stat.mtimeNs}:${stat.size}:${stat.ino}`;
      if (key === this.cacheKey) return;
      const parsed = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
      if (parsed?.version !== 2 || !Array.isArray(parsed.allow)) throw new Error("learned policy must have version 2 and allow[]");
      this.entries = parsed.allow.map((entry, i) => {
        const validated = validateLearnedEntry(entry);
        if (!validated) throw new Error(`learned policy allow[${i}] is invalid`);
        return validated;
      });
      this.keys = new Set(this.entries.map(learnedEntryKey).filter(Boolean));
      this.cacheKey = key;
    } catch (err) {
      if (err?.code === "ENOENT") { this.entries = []; this.keys = new Set(); this.cacheKey = "missing"; return; }
      throw err;
    }
  }
  has(entry) { this.load(); const key = learnedEntryKey(entry); return key ? this.keys.has(key) : false; }
  matchesFilesystem(agentId, operation, filePath) { return this.has({ kind: "filesystem", agentId: agentId ?? null, operation, path: filePath }); }
  matchesTool(agentId, toolName, capability) { return this.has({ kind: "tool", agentId: agentId ?? null, toolName, capability }); }
  matchesExec(agentId, toolName, command) { return this.has({ kind: "exec", agentId: agentId ?? null, toolName, command }); }
  persist(call, decision) {
    this.load();
    const createdAt = new Date().toISOString();
    const additions = [];
    if (decision?.kind === "filesystem") {
      for (const target of decision.askTargets ?? []) {
        additions.push({ kind: "filesystem", agentId: call.agentId ?? null, operation: target.operation, path: target.path, createdAt });
      }
    } else if (decision?.kind === "exec") {
      throw new Error("exec allow-always is disabled; use exec.allow regex rules");
    } else {
      additions.push({ kind: "tool", agentId: call.agentId ?? null, toolName: call.toolName, capability: call.capability, createdAt });
    }
    const unique = additions.filter((entry) => !this.keys.has(learnedEntryKey(entry)));
    if (unique.length === 0) return;
    const data = { version: 2, allow: [...this.entries, ...unique] };
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp-${process.pid}-${randomUUID()}`;
    try {
      fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
      fs.renameSync(tmp, this.filePath);
      fs.chmodSync(this.filePath, 0o600);
    } finally {
      try { fs.unlinkSync(tmp); } catch {}
    }
    this.cacheKey = null;
    this.load();
  }
}
