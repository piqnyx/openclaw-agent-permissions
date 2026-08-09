import { getValuesAtPath, normalizeToolPath } from "./paths.js";
import { resolveMappedPath } from "./path-mappings.js";

const URI_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//u;

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

export function prepareLocalInputs(policy, call, virtualWorkspaceRoot = "/workspace") {
  const inputs = policy.toolProfiles?.[call.toolName]?.localInputs;
  if (!Array.isArray(inputs) || inputs.length === 0) return null;

  const rewrites = [];
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

      addFsTarget(call, input.operation, normalized);
      const resolved = resolveMappedPath(policy.pathMappings ?? [], call, normalized, {
        mappingIds: input.mappingIds,
      });
      if (!resolved.ok) {
        const hint = input.unmappedHint ? ` ${input.unmappedHint}` : "";
        return deny(
          "<local-input-unmapped>",
          `${call.toolName}.${input.selector} local path ${normalized} is not safely gateway-mapped: ${resolved.reason}.${hint}`.trim(),
        );
      }

      rewrites.push({
        selector: input.selector,
        from: rawValue,
        to: resolved.hostPath,
      });
    }
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
