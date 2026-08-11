import fs from "node:fs";
import { matchAny, matchValue, validateMatcher } from "./matchers.js";
import { normalizeToolPath } from "./paths.js";
import {
  LearnedRuleStore,
  evaluatePolicy as evaluateBasePolicy,
  validatePolicy as validateBasePolicy,
} from "./policy.js";

const EFFECTS = new Set(["allow", "ask", "deny"]);
const EXEC_PATH_KEYS = new Set(["default", "deny", "ask", "allow"]);
const EXEC_PATH_RULE_KEYS = new Set(["id", "description", "path", "agents", "sessions", "tools"]);
const FIND_PATTERN_OPTIONS = new Set([
  "-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-wholename", "-iwholename",
]);

const ALL_POSITIONAL_PATH_COMMANDS = new Set([
  "ls", "cat", "tac", "head", "tail", "wc", "stat", "du", "df", "readlink", "realpath",
  "cut", "diff", "cmp", "md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum",
]);

const OPTION_VALUE_WORDS = new Map([
  ["ls", new Set(["-I", "--ignore", "--hide", "--quoting-style", "--time-style", "--block-size"])],
  ["head", new Set(["-n", "--lines", "-c", "--bytes"])],
  ["tail", new Set(["-n", "--lines", "-c", "--bytes", "-s", "--sleep-interval", "--pid", "--max-unchanged-stats"])],
  ["stat", new Set(["-c", "--format", "--printf"])],
  ["du", new Set(["-B", "--block-size", "-d", "--max-depth", "--threshold", "--exclude"])],
  ["df", new Set(["-B", "--block-size", "--output", "-t", "--type", "-x", "--exclude-type"])],
  ["cut", new Set(["-b", "--bytes", "-c", "--characters", "-d", "--delimiter", "-f", "--fields", "--output-delimiter"])],
  ["diff", new Set(["-I", "--ignore-matching-lines", "-F", "--show-function-line", "--label", "--width", "--horizon-lines", "--tabsize", "--ifdef"])],
  ["cmp", new Set(["-i", "--ignore-initial", "-n", "--bytes"])],
]);

const PATH_OPTION_WORDS = new Map([
  ["wc", new Set(["--files0-from"])],
  ["du", new Set(["--exclude-from", "--files0-from"])],
  ["realpath", new Set(["--relative-to", "--relative-base"])],
]);

function asArray(value) { return Array.isArray(value) ? value : [value]; }
function assertObject(value, where) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${where}: must be object`);
}
function validateEffect(value, where) {
  if (!EFFECTS.has(value)) throw new Error(`${where}: allow/ask/deny required`);
}
function validateMatcherList(value, where) {
  if (value === undefined) return;
  const list = asArray(value);
  if (list.length === 0) throw new Error(`${where}: empty matcher list`);
  list.forEach((matcher, i) => validateMatcher(matcher, `${where}[${i}]`));
}
function contextMatches(rule, call) {
  if (rule.agents !== undefined && !(typeof call.agentId === "string" && matchAny(rule.agents, call.agentId))) return false;
  if (rule.sessions !== undefined && !(typeof call.sessionKey === "string" && matchAny(rule.sessions, call.sessionKey))) return false;
  if (rule.tools !== undefined && !(typeof call.toolName === "string" && matchAny(rule.tools, call.toolName))) return false;
  return true;
}

function validateExecPathRule(rule, where) {
  assertObject(rule, where);
  for (const key of Object.keys(rule)) if (!EXEC_PATH_RULE_KEYS.has(key)) throw new Error(`${where}.${key}: unknown field`);
  if (typeof rule.id !== "string" || !rule.id) throw new Error(`${where}.id: required`);
  if (rule.description !== undefined && typeof rule.description !== "string") throw new Error(`${where}.description: string required`);
  validateMatcher(rule.path, `${where}.path`);
  validateMatcherList(rule.agents, `${where}.agents`);
  validateMatcherList(rule.sessions, `${where}.sessions`);
  validateMatcherList(rule.tools, `${where}.tools`);
}

export function validateExecPaths(execPaths) {
  if (execPaths === undefined) return;
  assertObject(execPaths, "exec.paths");
  for (const key of Object.keys(execPaths)) if (!EXEC_PATH_KEYS.has(key)) throw new Error(`exec.paths.${key}: unknown field`);
  validateEffect(execPaths.default ?? "ask", "exec.paths.default");
  const ids = new Set();
  for (const bucket of ["deny", "ask", "allow"]) {
    const rules = execPaths[bucket] ?? [];
    if (!Array.isArray(rules)) throw new Error(`exec.paths.${bucket} must be array`);
    rules.forEach((rule, i) => {
      validateExecPathRule(rule, `exec.paths.${bucket}[${i}]`);
      if (ids.has(rule.id)) throw new Error(`exec.paths.${bucket}[${i}].id: duplicate '${rule.id}'`);
      ids.add(rule.id);
    });
  }
}

function stripExecPaths(policy) {
  const copy = structuredClone(policy);
  if (copy && copy.exec && typeof copy.exec === "object" && !Array.isArray(copy.exec)) delete copy.exec.paths;
  return copy;
}

export function validatePolicy(policy) {
  validateExecPaths(policy?.exec?.paths);
  validateBasePolicy(stripExecPaths(policy));
  return policy;
}

function flushWord(words, state) {
  if (!state.text) return;
  words.push({ text: state.text, quoted: state.quoted, segment: state.segment });
  state.text = "";
  state.quoted = false;
}

function stripSafeRedirections(command) {
  let out = "";
  let quote = null;

  for (let i = 0; i < command.length;) {
    const ch = command[i];

    if (quote === "'") {
      out += ch;
      i++;
      if (ch === "'") quote = null;
      continue;
    }
    if (quote === '"') {
      out += ch;
      i++;
      if (ch === "\\" && i < command.length) {
        out += command[i];
        i++;
        continue;
      }
      if (ch === '"') quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      out += ch;
      i++;
      continue;
    }
    if (ch === "\\" && i + 1 < command.length) {
      out += ch + command[i + 1];
      i += 2;
      continue;
    }

    const rest = command.slice(i);
    const safe = rest.match(/^(?:(?:[012]?>>?|&>>?|[012]?<)[ \t]*\/dev\/null|[12]>&[12])(?=$|[ \t\r\n;&|])/u);
    if (safe) {
      out += " ".repeat(safe[0].length);
      i += safe[0].length;
      continue;
    }

    out += ch;
    i++;
  }

  return out;
}

function tokenize(command) {
  const words = [];
  const reasons = [];
  const state = { text: "", quoted: false, segment: 0 };
  let quote = null;

  const ambiguous = (reason) => {
    if (!reasons.includes(reason)) reasons.push(reason);
  };

  const sanitized = stripSafeRedirections(command);
  for (let i = 0; i < sanitized.length; i++) {
    const ch = sanitized[i];
    const next = sanitized[i + 1] ?? "";

    if (quote === "'") {
      if (ch === "'") quote = null;
      else state.text += ch;
      continue;
    }

    if (quote === '"') {
      if (ch === '"') {
        quote = null;
        continue;
      }
      if (ch === "$" || ch === "`") ambiguous("dynamic double-quoted shell expression");
      if (ch === "\\") {
        if (next === "\n" || next === "\r" || !next) {
          ambiguous("dynamic double-quoted shell expression");
          state.text += ch;
          continue;
        }
        state.text += ch + next;
        i++;
        continue;
      }
      state.text += ch;
      continue;
    }

    if (ch === "'" || ch === '"') {
      quote = ch;
      state.quoted = true;
      continue;
    }

    if (/\s/u.test(ch)) {
      flushWord(words, state);
      if (ch === "\n" || ch === "\r") ambiguous("multi-line shell command");
      continue;
    }

    if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) {
      flushWord(words, state);
      state.segment++;
      i++;
      continue;
    }
    if (ch === ";" || ch === "|") {
      flushWord(words, state);
      state.segment++;
      continue;
    }

    if (ch === "&") {
      flushWord(words, state);
      ambiguous("background shell operator");
      continue;
    }
    if (ch === "<" || ch === ">") {
      flushWord(words, state);
      ambiguous("shell redirection or process substitution");
      continue;
    }
    if (ch === "$" || ch === "`" || ch === "(" || ch === ")") {
      state.text += ch;
      ambiguous("dynamic shell expression");
      continue;
    }
    if (ch === "\\") {
      if (next === "\n" || next === "\r" || !next) {
        state.text += ch;
        ambiguous("dynamic shell expression");
        continue;
      }
      state.text += ch + next;
      i++;
      continue;
    }
    if (ch === "#" && state.text.length === 0) {
      ambiguous("shell comment syntax");
      state.text += ch;
      continue;
    }

    state.text += ch;
  }

  if (quote !== null) ambiguous("unterminated shell quote");
  flushWord(words, state);
  return { words, ambiguous: reasons.length > 0, reasons };
}

function isUri(value) {
  return /^[A-Za-z][A-Za-z0-9+.-]*:\/\//u.test(value);
}

function looksLikeExplicitPath(value, quoted) {
  if (!value || isUri(value)) return false;
  if (quoted && /\s/u.test(value) && !(value.startsWith("/") || value.startsWith("./") || value.startsWith("../") || value.startsWith("~/"))) return false;
  if (value === "." || value === ".." || value === "~") return true;
  if (value.startsWith("/") || value.startsWith("./") || value.startsWith("../") || value.startsWith("~/")) return true;
  if (value.includes("/")) return true;
  return false;
}

function explicitPathValueFromWord(word) {
  const text = word.text;
  if (!text) return null;

  const equals = text.indexOf("=");
  if (equals > 0) {
    const rhs = text.slice(equals + 1);
    if (looksLikeExplicitPath(rhs, word.quoted)) return rhs;
  }

  return looksLikeExplicitPath(text, word.quoted) ? text : null;
}

function hasPathExpansion(value) {
  return /[*?\[\]{}]/u.test(value);
}

function wordsBySegment(words) {
  const bySegment = new Map();
  words.forEach((word, index) => {
    if (!bySegment.has(word.segment)) bySegment.set(word.segment, []);
    bySegment.get(word.segment).push(index);
  });
  return bySegment;
}

function optionValueIndexes(command, words, indexes) {
  const ignored = new Set();
  const pathValues = new Set();
  const ordinary = OPTION_VALUE_WORDS.get(command) ?? new Set();
  const pathOptions = PATH_OPTION_WORDS.get(command) ?? new Set();

  for (let pos = 1; pos < indexes.length - 1; pos++) {
    const index = indexes[pos];
    const text = words[index].text;
    if (ordinary.has(text)) ignored.add(indexes[pos + 1]);
    if (pathOptions.has(text)) pathValues.add(indexes[pos + 1]);
  }
  return { ignored, pathValues };
}

function grepOperandIndexes(words, indexes, command) {
  const paths = new Set();
  const ignored = new Set();
  let patternProvided = false;
  let positionalPatternSeen = false;
  let optionsEnded = false;

  const nonPathValueOptions = command === "grep"
    ? new Set(["-A", "--after-context", "-B", "--before-context", "-C", "--context", "-m", "--max-count", "--label", "-D", "--devices", "-d", "--directories", "--exclude", "--include", "--exclude-dir"])
    : new Set(["-A", "--after-context", "-B", "--before-context", "-C", "--context", "-m", "--max-count", "-d", "--max-depth", "-g", "--glob", "--iglob", "-t", "--type", "-T", "--type-not", "-E", "--encoding", "-j", "--threads", "-r", "--replace", "--sort", "--sortr", "--pre-glob"]);

  for (let pos = 1; pos < indexes.length; pos++) {
    const index = indexes[pos];
    const text = words[index].text;

    if (!optionsEnded && text === "--") {
      optionsEnded = true;
      continue;
    }

    if (!optionsEnded && (text === "-f" || text === "--file" || (command === "rg" && text === "--ignore-file"))) {
      if (pos + 1 < indexes.length) {
        paths.add(indexes[pos + 1]);
        patternProvided = text !== "--ignore-file" || patternProvided;
        pos++;
      }
      continue;
    }
    if (!optionsEnded && (text.startsWith("--file=") || (command === "rg" && text.startsWith("--ignore-file=")))) {
      if (text.startsWith("--file=")) patternProvided = true;
      continue;
    }
    if (!optionsEnded && command === "grep" && (text === "-e" || text === "--regexp")) {
      if (pos + 1 < indexes.length) {
        ignored.add(indexes[pos + 1]);
        patternProvided = true;
        pos++;
      }
      continue;
    }
    if (!optionsEnded && command === "grep" && (text.startsWith("--regexp=") || /^-e.+/u.test(text))) {
      patternProvided = true;
      continue;
    }
    if (!optionsEnded && nonPathValueOptions.has(text)) {
      if (pos + 1 < indexes.length) {
        ignored.add(indexes[pos + 1]);
        pos++;
      }
      continue;
    }
    if (!optionsEnded && text.startsWith("-")) continue;

    if (!patternProvided && !positionalPatternSeen) {
      positionalPatternSeen = true;
      continue;
    }
    paths.add(index);
  }

  return { paths, ignored, hasSearchPaths: paths.size > 0 };
}

function jqOperandIndexes(words, indexes) {
  const paths = new Set();
  const ignored = new Set();
  let filterSeen = false;

  for (let pos = 1; pos < indexes.length; pos++) {
    const index = indexes[pos];
    const text = words[index].text;
    if (text === "--arg" || text === "--argjson") {
      if (pos + 1 < indexes.length) ignored.add(indexes[++pos]);
      if (pos + 1 < indexes.length) ignored.add(indexes[++pos]);
      continue;
    }
    if (text === "--slurpfile" || text === "--rawfile") {
      if (pos + 1 < indexes.length) ignored.add(indexes[++pos]);
      if (pos + 1 < indexes.length) paths.add(indexes[++pos]);
      continue;
    }
    if (text === "-L") {
      if (pos + 1 < indexes.length) paths.add(indexes[++pos]);
      continue;
    }
    if (text.startsWith("-")) continue;
    if (!filterSeen) {
      filterSeen = true;
      continue;
    }
    paths.add(index);
  }
  return { paths, ignored };
}

function classifyOperandIndexes(words, reasons) {
  const pathIndexes = new Set();
  const ignoredIndexes = new Set();
  const commandIndexes = new Set();

  for (const indexes of wordsBySegment(words).values()) {
    if (indexes.length === 0) continue;
    const commandIndex = indexes[0];
    const command = words[commandIndex].text;
    commandIndexes.add(commandIndex);

    if (command === "find") {
      let rootCount = 0;
      for (let pos = 1; pos < indexes.length; pos++) {
        const index = indexes[pos];
        const text = words[index].text;
        if (FIND_PATTERN_OPTIONS.has(text) && pos + 1 < indexes.length) {
          ignoredIndexes.add(indexes[++pos]);
          continue;
        }
        if (text.startsWith("-") || text === "!" || text === "(" || text === ")") continue;
        if (rootCount === pos - 1) {
          pathIndexes.add(index);
          rootCount++;
        }
      }
      if (rootCount === 0 && !reasons.includes("implicit recursive cwd access")) reasons.push("implicit recursive cwd access");
      continue;
    }

    if (command === "grep" || command === "rg") {
      const classified = grepOperandIndexes(words, indexes, command);
      classified.paths.forEach((index) => pathIndexes.add(index));
      classified.ignored.forEach((index) => ignoredIndexes.add(index));
      if (command === "rg" && !classified.hasSearchPaths && !reasons.includes("implicit recursive cwd access")) {
        reasons.push("implicit recursive cwd access");
      }
      const recursiveGrep = command === "grep" && indexes.some((index) => /^(?:-.*[rR].*|--recursive|--dereference-recursive)$/u.test(words[index].text));
      if (recursiveGrep && !classified.hasSearchPaths && !reasons.includes("implicit recursive cwd access")) {
        reasons.push("implicit recursive cwd access");
      }
      continue;
    }

    if (command === "jq") {
      const classified = jqOperandIndexes(words, indexes);
      classified.paths.forEach((index) => pathIndexes.add(index));
      classified.ignored.forEach((index) => ignoredIndexes.add(index));
      continue;
    }

    const optionValues = optionValueIndexes(command, words, indexes);
    optionValues.ignored.forEach((index) => ignoredIndexes.add(index));
    optionValues.pathValues.forEach((index) => pathIndexes.add(index));

    if (ALL_POSITIONAL_PATH_COMMANDS.has(command)) {
      let positionalCount = 0;
      let optionsEnded = false;
      for (let pos = 1; pos < indexes.length; pos++) {
        const index = indexes[pos];
        if (ignoredIndexes.has(index) || pathIndexes.has(index)) continue;
        const text = words[index].text;
        if (!optionsEnded && text === "--") {
          optionsEnded = true;
          continue;
        }
        if (!optionsEnded && text.startsWith("-") && text !== "-") continue;
        pathIndexes.add(index);
        positionalCount++;
      }
      if (command === "du" && positionalCount === 0 && !reasons.includes("implicit recursive cwd access")) {
        reasons.push("implicit recursive cwd access");
      }
    }
  }

  return { pathIndexes, ignoredIndexes, commandIndexes };
}

function normalizeExecPath(raw, virtualWorkspaceRoot) {
  const normalized = normalizeToolPath(raw, virtualWorkspaceRoot);
  return typeof normalized === "string" && normalized ? normalized : null;
}

export function analyzeExecPaths(command, virtualWorkspaceRoot = "/workspace") {
  if (typeof command !== "string" || !command) return { paths: [], ambiguous: true, reasons: ["missing command"] };
  const scanned = tokenize(command);
  const paths = [];
  const reasons = [...scanned.reasons];
  const classified = classifyOperandIndexes(scanned.words, reasons);

  scanned.words.forEach((word, index) => {
    if (classified.ignoredIndexes.has(index)) return;

    let raw = null;
    if (classified.pathIndexes.has(index)) {
      raw = word.text;
    } else if (classified.commandIndexes.has(index)) {
      raw = explicitPathValueFromWord(word);
    } else {
      raw = explicitPathValueFromWord(word);
    }
    if (!raw) return;

    if (hasPathExpansion(raw)) {
      if (!reasons.includes("path expansion or glob")) reasons.push("path expansion or glob");
      return;
    }
    const normalized = normalizeExecPath(raw, virtualWorkspaceRoot);
    if (!normalized) {
      if (!reasons.includes("unresolved path operand")) reasons.push("unresolved path operand");
      return;
    }
    paths.push(normalized);
  });

  return { paths: [...new Set(paths)], ambiguous: reasons.length > 0, reasons };
}

function execPathRuleMatches(rule, call, target) {
  return contextMatches(rule, call) && matchValue(rule.path, target);
}

function decisionForPath(execPaths, call, target) {
  for (const bucket of ["deny", "ask", "allow"]) {
    for (const rule of execPaths[bucket] ?? []) {
      if (!execPathRuleMatches(rule, call, target)) continue;
      return { effect: bucket, ruleId: rule.id, reason: rule.description ?? rule.id };
    }
  }
  return { effect: execPaths.default ?? "ask", ruleId: "<exec-path-default>", reason: "exec path default" };
}

export function evaluateExecPaths(policy, call, virtualWorkspaceRoot = "/workspace") {
  if (call.capability !== "exec") return null;
  const execPaths = policy.exec?.paths;
  if (!execPaths) return { kind: "exec-path", effect: "allow", ruleId: "<exec-path-disabled>", reason: "exec path policy disabled", paths: [] };

  const command = typeof call.params.command === "string" ? call.params.command : typeof call.params.cmd === "string" ? call.params.cmd : "";
  const analysis = analyzeExecPaths(command, virtualWorkspaceRoot);
  call.paths = analysis.paths;

  if (analysis.ambiguous) {
    return {
      kind: "exec-path",
      effect: "ask",
      ruleId: "<exec-path-ambiguous>",
      reason: `exec path analysis is ambiguous: ${analysis.reasons.join(", ")}`,
      paths: analysis.paths,
    };
  }

  if (analysis.paths.length === 0) {
    return { kind: "exec-path", effect: "allow", ruleId: "<exec-path-no-targets>", reason: "no explicit filesystem path operands detected", paths: [] };
  }

  const decisions = analysis.paths.map((target) => ({ target, ...decisionForPath(execPaths, call, target) }));
  const effect = decisions.some((entry) => entry.effect === "deny")
    ? "deny"
    : decisions.some((entry) => entry.effect === "ask")
      ? "ask"
      : "allow";

  return {
    kind: "exec-path",
    effect,
    ruleId: [...new Set(decisions.map((entry) => entry.ruleId))].join(","),
    reason: decisions.map((entry) => `${entry.target}: ${entry.reason}`).join("; "),
    paths: analysis.paths,
  };
}

function mergeExecDecision(baseDecision, pathDecision) {
  if (!baseDecision || !pathDecision) return baseDecision ?? pathDecision;
  if (baseDecision.effect === "deny") return baseDecision;
  if (pathDecision.effect === "deny") {
    return {
      kind: "exec",
      effect: "deny",
      ruleId: pathDecision.ruleId,
      reason: pathDecision.reason,
      allowAlways: false,
      command: baseDecision.command,
    };
  }
  if (baseDecision.effect === "ask") return baseDecision;
  if (pathDecision.effect === "ask") {
    return {
      kind: "exec",
      effect: "ask",
      ruleId: `${baseDecision.ruleId}+${pathDecision.ruleId}`,
      reason: `${baseDecision.reason}; ${pathDecision.reason}`,
      allowAlways: false,
      command: baseDecision.command,
    };
  }
  return baseDecision;
}

export function evaluatePolicy(policy, call, learnedStore = null, virtualWorkspaceRoot = "/workspace") {
  const pathDecision = evaluateExecPaths(policy, call, virtualWorkspaceRoot);
  const baseDecision = evaluateBasePolicy(policy, call, learnedStore);
  if (call.capability !== "exec" || !policy.exec?.paths) return baseDecision;
  return mergeExecDecision(baseDecision, pathDecision);
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
