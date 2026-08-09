import { matchAny, validateMatcher } from "./matchers.js";
import { getValuesAtPath, normalizeToolPath } from "./paths.js";
import { resolveMappedPath, selectPathMapping } from "./path-mappings.js";

const URI_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//u;
const FS_OPERATIONS = new Set(["read", "write", "delete", "move", "execute"]);
const LOCAL_INPUT_KEYS = new Set([
  "id", "description", "tools", "selector", "operation", "remotePrefixes",
  "mappingIds", "agents", "sessions", "unmappedHint"
]);

function asArray(value) { return Array.isArray(value) ? value : [value]; }
function assertObject(value, where) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${where}: must be object`);
}
function validateMatcherList(value, where) {
  if (value === undefined) return;
  const list = asArray(value);
  if (list.length === 0) throw new Error(`${where}: empty matcher list`);
  list.forEach((matcher, i) => validateMatcher(matcher, `${where}[${i}]`));
}
function validateStringList(value, where) {
  if (value === undefined) return;
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== "string" || !item)) {
    throw new Error(`${where}: non-empty string[] required`);
  }
  if (new Set(value).size !== value.length) throw new Error(`${where}: duplicate entries are not allowed`);
}

export function validateLocalInputs(inputs) {
  if (inputs === undefined) return;
  if (!Array.isArray(inputs)) throw new Error("localInputs must be array");
  const ids = new Set();
  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i];
    const where = `localInputs[${i}]`;
    assertObject(input, where);
    for (const key of Object.keys(input)) {
      if (!LOCAL_INPUT_KEYS.has(key)) throw new Error(`${where}.${key}: unknown field`);
    }
    if (typeof input.id !== "string" || !input.id) throw new Error(`${where}.id: required`);
    if (ids.has(input.id)) throw new Error(`${where}.id: duplicate '${input.id}'`);
    ids.add(input.id);
    if (input.description !== undefined && typeof input.description !== "string") throw new Error(`${where}.description: string required`);
    validateMatcherList(input.tools, `${where}.tools`);
    if (input.tools === undefined) throw new Error(`${where}.tools: required`);
    validateMatcherList(input.agents, `${where}.agents`);
    validateMatcherList(input.sessions, `${where}.sessions`);
    if (typeof input.selector !== "string" || !input.selector) throw new Error(`${where}.selector: required`);
    if (!FS_OPERATIONS.has(input.operation)) throw new Error(`${where}.operation: unsupported filesystem operation`);
    validateStringList(input.remotePrefixes, `${where}.remotePrefixes`);
    validateStringList(input.mappingIds, `${where}.mappingIds`);
    if (input.unmappedHint !== undefined && (typeof input.unmappedHint !== "string" || !input.unmappedHint)) {
      throw new Error(`${where}.unmappedHint: non-empty string required`);
    }
  }
}

function contextMatches(input, call) {
  if (!(typeof call.toolName === "string" && matchAny(input.tools, call.toolName))) return false;
  if (input.agents !== undefined && !(typeof call.agentId === "string" && matchAny(input.agents, call.agentId))) return false;
  if (input.sessions !== undefined && !(typeof call.sessionKey === "string" && matchAny(input.sessions, call.sessionKey))) return false;
  return true;
}

function scalarStrings(value) {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(scalarStrings);
  return [];
}

function addFsTarget(call, operation, filePath) {
  if (!Array.isArray(call.fsTargets)) call.fsTargets = [];
  if (!Array.isArray(call.paths)) call.paths = [];
  if (!call.paths.includes(filePath)) call.paths.push(filePath);
  if (!call.fsTargets.some((target) => target.operation === operation && target.path === filePath)) {
    call.fsTargets.push({ operation, path: filePath });
  }
}

function deny(ruleId, reason) {
  return {
    kind: "local-input",
    effect: "deny",
    ruleId,
    reason,
    allowAlways: false,
  };
}

function hintSuffix(input) {
  return input.unmappedHint ? ` ${input.unmappedHint}` : "";
}

function rewriteStringValues(value, rewrite) {
  if (typeof value === "string") return rewrite(value);
  if (!Array.isArray(value)) return value;
  let changed = false;
  const next = value.map((item) => {
    const rewritten = rewriteStringValues(item, rewrite);
    if (rewritten !== item) changed = true;
    return rewritten;
  });
  return changed ? next : value;
}

function rewriteValuesAtSelector(root, selector, rewrite) {
  const parts = selector.split(".").filter(Boolean);
  if (parts.length === 0) return false;
  let changed = false;

  const visit = (node, index) => {
    if (!node || typeof node !== "object") return;
    const rawPart = parts[index];
    const arrayMode = rawPart.endsWith("[]");
    const key = arrayMode ? rawPart.slice(0, -2) : rawPart;
    if (!Object.hasOwn(node, key)) return;
    const isLast = index === parts.length - 1;

    if (arrayMode) {
      const value = node[key];
      if (!Array.isArray(value)) return;
      if (isLast) {
        node[key] = value.map((item) => {
          const next = rewriteStringValues(item, rewrite);
          if (next !== item) changed = true;
          return next;
        });
        return;
      }
      for (const item of value) visit(item, index + 1);
      return;
    }

    if (isLast) {
      const current = node[key];
      const next = rewriteStringValues(current, rewrite);
      if (next !== current) {
        node[key] = next;
        changed = true;
      }
      return;
    }
    visit(node[key], index + 1);
  };

  visit(root, 0);
  return changed;
}

export function analyzeLocalInputs(policy, call, virtualWorkspaceRoot = "/workspace") {
  const inputs = (policy.localInputs ?? []).filter((input) => contextMatches(input, call));
  if (inputs.length === 0) {
    call.localInputCandidates = [];
    return null;
  }

  const candidates = [];
  const seen = new Map();

  for (const input of inputs) {
    const values = getValuesAtPath(call.params, input.selector).flatMap(scalarStrings);
    for (const rawValue of values) {
      const raw = rawValue.trim();
      if (!raw) continue;
      if ((input.remotePrefixes ?? []).some((prefix) => raw.startsWith(prefix))) continue;

      if (URI_SCHEME.test(raw)) {
        return deny(
          "<local-input-unsupported-uri>",
          `${call.toolName}.${input.selector} uses URI scheme not declared as remote: ${raw}`,
        );
      }

      const normalized = normalizeToolPath(raw, virtualWorkspaceRoot);
      if (typeof normalized !== "string" || !normalized.startsWith("/")) {
        return deny(
          "<local-input-invalid-path>",
          `${call.toolName}.${input.selector} could not be normalized as a local sandbox path`,
        );
      }

      const mapping = selectPathMapping(policy.pathMappings ?? [], call, normalized, input.mappingIds);
      if (!mapping) {
        return deny(
          "<local-input-unmapped>",
          `${call.toolName}.${input.selector} local path ${normalized} has no configured gateway mapping.${hintSuffix(input)}`.trim(),
        );
      }

      const key = `${input.selector}\0${rawValue}`;
      const declaration = JSON.stringify({ operation: input.operation, mappingIds: input.mappingIds ?? null });
      const prior = seen.get(key);
      if (prior && prior !== declaration) {
        return deny(
          "<local-input-conflict>",
          `${call.toolName}.${input.selector} matched conflicting local-input declarations`,
        );
      }
      if (prior) continue;
      seen.set(key, declaration);

      addFsTarget(call, input.operation, normalized);
      candidates.push({
        ruleId: input.id,
        selector: input.selector,
        rawValue,
        normalized,
        operation: input.operation,
        mappingIds: input.mappingIds,
        unmappedHint: input.unmappedHint,
      });
    }
  }

  call.localInputCandidates = candidates;
  return null;
}

export function resolveLocalInputMappings(policy, call) {
  const candidates = Array.isArray(call.localInputCandidates) ? call.localInputCandidates : [];
  if (candidates.length === 0) {
    call.localInputRewrites = [];
    return null;
  }

  const rewrites = [];
  const seen = new Map();

  for (const candidate of candidates) {
    const resolved = resolveMappedPath(policy.pathMappings ?? [], call, candidate.normalized, {
      mappingIds: candidate.mappingIds,
      requireExistingTarget: candidate.operation === "read",
    });
    if (!resolved.ok) {
      const hint = candidate.unmappedHint ? ` ${candidate.unmappedHint}` : "";
      return deny(
        "<local-input-physical>",
        `${call.toolName}.${candidate.selector} local path ${candidate.normalized} is not safely gateway-resolvable: ${resolved.reason}.${hint}`.trim(),
      );
    }

    const key = `${candidate.selector}\0${candidate.rawValue}`;
    const prior = seen.get(key);
    if (prior && prior !== resolved.hostPath) {
      return deny(
        "<local-input-conflict>",
        `${call.toolName}.${candidate.selector} resolved to conflicting gateway paths`,
      );
    }
    seen.set(key, resolved.hostPath);
    rewrites.push({
      selector: candidate.selector,
      from: candidate.rawValue,
      to: resolved.hostPath,
    });
  }

  call.localInputRewrites = rewrites;
  return null;
}

export function rewriteLocalInputParams(call, baseParams = call?.params) {
  if (!call || !Array.isArray(call.localInputRewrites) || call.localInputRewrites.length === 0) return null;
  if (!baseParams || typeof baseParams !== "object" || Array.isArray(baseParams)) return null;

  const cloned = structuredClone(baseParams);
  let changed = false;
  const bySelector = new Map();
  for (const rewrite of call.localInputRewrites) {
    if (!bySelector.has(rewrite.selector)) bySelector.set(rewrite.selector, new Map());
    bySelector.get(rewrite.selector).set(rewrite.from, rewrite.to);
  }

  for (const [selector, replacements] of bySelector) {
    changed = rewriteValuesAtSelector(cloned, selector, (value) => replacements.get(value) ?? value) || changed;
  }
  return changed ? cloned : null;
}
