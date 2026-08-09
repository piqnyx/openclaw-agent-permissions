import path from "node:path";

function scalarStrings(value) {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(scalarStrings);
  return [];
}

export function getValuesAtPath(root, selector) {
  const parts = selector.split(".").filter(Boolean);
  let current = [root];
  for (const rawPart of parts) {
    const arrayMode = rawPart.endsWith("[]");
    const key = arrayMode ? rawPart.slice(0, -2) : rawPart;
    const next = [];
    for (const item of current) {
      if (!item || typeof item !== "object") continue;
      const value = item[key];
      if (arrayMode) {
        if (Array.isArray(value)) next.push(...value);
      } else {
        next.push(value);
      }
    }
    current = next;
  }
  return current;
}

export function normalizeToolPath(raw, virtualWorkspaceRoot = "/workspace") {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.includes("\0")) return null;

  // OpenClaw sandbox paths are POSIX even when the gateway host isn't.
  let candidate = trimmed.replaceAll("\\", "/");
  if (candidate.startsWith("~/") || candidate === "~") {
    // Deliberately do not guess sandbox $HOME. Unresolved home paths fall back
    // to the policy's default effect instead of accidentally matching /workspace.
    return path.posix.normalize(candidate);
  }
  if (!candidate.startsWith("/")) {
    candidate = path.posix.join(virtualWorkspaceRoot, candidate);
  }
  return path.posix.normalize(candidate);
}

export function pathsFromSelectors(params, selectors, virtualWorkspaceRoot) {
  const out = [];
  for (const selector of selectors ?? []) {
    for (const value of getValuesAtPath(params, selector)) {
      for (const raw of scalarStrings(value)) {
        const normalized = normalizeToolPath(raw, virtualWorkspaceRoot);
        if (normalized) out.push(normalized);
      }
    }
  }
  return dedupe(out);
}

export function extractPatchTargets(patchText, virtualWorkspaceRoot) {
  if (typeof patchText !== "string") return [];
  const targets = [];
  const lines = patchText.split(/\r?\n/);
  let currentUpdatePath = null;
  let unifiedOld = null;

  const push = (operation, rawPath) => {
    const normalized = normalizeToolPath(rawPath, virtualWorkspaceRoot);
    if (normalized) targets.push({ operation, path: normalized });
  };

  for (const line of lines) {
    const add = line.match(/^\s*\*\*\*\s+Add File:\s+(.+?)\s*$/);
    if (add) {
      currentUpdatePath = null;
      push("write", add[1]);
      continue;
    }

    const update = line.match(/^\s*\*\*\*\s+Update File:\s+(.+?)\s*$/);
    if (update) {
      currentUpdatePath = normalizeToolPath(update[1], virtualWorkspaceRoot);
      if (currentUpdatePath) targets.push({ operation: "write", path: currentUpdatePath });
      continue;
    }

    const remove = line.match(/^\s*\*\*\*\s+Delete File:\s+(.+?)\s*$/);
    if (remove) {
      currentUpdatePath = null;
      push("delete", remove[1]);
      continue;
    }

    const moveTo = line.match(/^\s*\*\*\*\s+Move to:\s+(.+?)\s*$/);
    if (moveTo) {
      const destination = normalizeToolPath(moveTo[1], virtualWorkspaceRoot);
      if (currentUpdatePath) targets.push({ operation: "move", path: currentUpdatePath });
      if (destination) {
        targets.push({ operation: "move", path: destination });
        targets.push({ operation: "write", path: destination });
      }
      continue;
    }

    const oldHeader = line.match(/^---\s+(?:a\/)?([^\t]+?)(?:\t.*)?\s*$/);
    if (oldHeader) {
      unifiedOld = oldHeader[1];
      continue;
    }

    const newHeader = line.match(/^\+\+\+\s+(?:b\/)?([^\t]+?)(?:\t.*)?\s*$/);
    if (newHeader) {
      const oldPath = unifiedOld;
      const newPath = newHeader[1];
      unifiedOld = null;
      if (oldPath === "/dev/null" && newPath !== "/dev/null") {
        push("write", newPath);
      } else if (newPath === "/dev/null" && oldPath && oldPath !== "/dev/null") {
        push("delete", oldPath);
      } else if (oldPath && oldPath !== "/dev/null" && newPath !== "/dev/null") {
        const oldNormalized = normalizeToolPath(oldPath, virtualWorkspaceRoot);
        const newNormalized = normalizeToolPath(newPath, virtualWorkspaceRoot);
        if (oldNormalized && newNormalized && oldNormalized !== newNormalized) {
          targets.push({ operation: "move", path: oldNormalized });
          targets.push({ operation: "move", path: newNormalized });
          targets.push({ operation: "write", path: newNormalized });
        } else if (newNormalized) {
          targets.push({ operation: "write", path: newNormalized });
        }
      }
    }
  }

  return dedupeTargets(targets);
}

export function extractPatchPaths(patchText, virtualWorkspaceRoot) {
  return dedupe(extractPatchTargets(patchText, virtualWorkspaceRoot).map((target) => target.path));
}

function dedupe(values) {
  return [...new Set(values)];
}

function dedupeTargets(targets) {
  const seen = new Set();
  const out = [];
  for (const target of targets) {
    const key = `${target.operation}\0${target.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(target);
  }
  return out;
}
