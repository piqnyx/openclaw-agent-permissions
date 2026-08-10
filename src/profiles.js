import path from "node:path";
import { extractPatchTargets, normalizeToolPath, pathsFromSelectors } from "./paths.js";

const FS_READ_SELECTORS = [
  "path", "file", "file_path", "filePath", "directory", "dir", "root",
  "paths[]", "files[].path", "targets[].path", "edits[].path", "changes[].path"
];
const FS_WRITE_SELECTORS = [
  "path", "file", "file_path", "filePath", "target", "target_path", "targetPath",
  "destination", "destination_path", "destinationPath", "paths[]", "files[].path", "targets[].path",
  "edits[].path", "changes[].path"
];
const COPY_SOURCE_SELECTORS = ["source", "source_path", "sourcePath", "src", "from"];
const COPY_DESTINATION_SELECTORS = ["destination", "destination_path", "destinationPath", "dst", "to", "target"];

const BUILTIN = {
  read: { capability: "fs.read", operation: "read", pathParams: FS_READ_SELECTORS },
  Read: { capability: "fs.read", operation: "read", pathParams: FS_READ_SELECTORS },
  read_file: { capability: "fs.read", operation: "read", pathParams: FS_READ_SELECTORS },
  read_text_file: { capability: "fs.read", operation: "read", pathParams: FS_READ_SELECTORS },
  list: { capability: "fs.read", operation: "list", pathParams: FS_READ_SELECTORS },
  ls: { capability: "fs.read", operation: "list", pathParams: FS_READ_SELECTORS },
  list_dir: { capability: "fs.read", operation: "list", pathParams: FS_READ_SELECTORS },
  list_directory: { capability: "fs.read", operation: "list", pathParams: FS_READ_SELECTORS },
  glob: { capability: "fs.read", operation: "glob", pathParams: ["path", "cwd", "root"] },
  grep: { capability: "fs.read", operation: "grep", pathParams: ["path", "cwd", "root"] },
  search_files: { capability: "fs.read", operation: "search", pathParams: ["path", "cwd", "root"] },

  write: { capability: "fs.write", operation: "write", pathParams: FS_WRITE_SELECTORS },
  Write: { capability: "fs.write", operation: "write", pathParams: FS_WRITE_SELECTORS },
  write_file: { capability: "fs.write", operation: "write", pathParams: FS_WRITE_SELECTORS },
  create_file: { capability: "fs.write", operation: "create", pathParams: FS_WRITE_SELECTORS },
  edit: { capability: "fs.write", operation: "edit", pathParams: FS_WRITE_SELECTORS },
  Edit: { capability: "fs.write", operation: "edit", pathParams: FS_WRITE_SELECTORS },
  edit_file: { capability: "fs.write", operation: "edit", pathParams: FS_WRITE_SELECTORS },
  multi_edit: { capability: "fs.write", operation: "edit", pathParams: FS_WRITE_SELECTORS },
  str_replace: { capability: "fs.write", operation: "edit", pathParams: FS_WRITE_SELECTORS },
  apply_patch: { capability: "fs.write", operation: "patch", pathParams: [], patchParams: ["patch", "input", "text"] },
  copy: {
    capability: "fs.write",
    operation: "copy",
    pathOperations: { read: COPY_SOURCE_SELECTORS, write: COPY_DESTINATION_SELECTORS }
  },
  copy_file: {
    capability: "fs.write",
    operation: "copy",
    pathOperations: { read: COPY_SOURCE_SELECTORS, write: COPY_DESTINATION_SELECTORS }
  },

  delete: { capability: "fs.delete", operation: "delete", pathParams: FS_WRITE_SELECTORS },
  delete_file: { capability: "fs.delete", operation: "delete", pathParams: FS_WRITE_SELECTORS },
  remove_file: { capability: "fs.delete", operation: "delete", pathParams: FS_WRITE_SELECTORS },
  unlink: { capability: "fs.delete", operation: "delete", pathParams: FS_WRITE_SELECTORS },
  move: { capability: "fs.move", operation: "move", pathParams: ["source", "src", "from", "destination", "dst", "to"] },
  rename: { capability: "fs.move", operation: "rename", pathParams: ["source", "src", "from", "destination", "dst", "to"] },

  bash: { capability: "exec", operation: "exec", pathParams: [] },
  exec: { capability: "exec", operation: "exec", pathParams: [] },
  process: { capability: "process", operation: "process", pathParams: [] },

  memory_search: { capability: "memory.read", operation: "search", pathParams: [] },
  memory_get: { capability: "memory.read", operation: "get", pathParams: [] },
  memory_recall: { capability: "memory.read", operation: "recall", pathParams: [] },
  ov_archive_search: { capability: "memory.read", operation: "archive_search", pathParams: [] },
  ov_archive_expand: { capability: "memory.read", operation: "archive_expand", pathParams: [] },
  ov_search: { capability: "memory.read", operation: "search", pathParams: [] },
  ov_read: { capability: "memory.read", operation: "read", pathParams: [] },
  ov_multi_read: { capability: "memory.read", operation: "multi_read", pathParams: [] },
  ov_list: { capability: "memory.read", operation: "list", pathParams: [] },
  openviking_tool_result_read: { capability: "memory.read", operation: "result_read", pathParams: [] },
  openviking_tool_result_search: { capability: "memory.read", operation: "result_search", pathParams: [] },
  openviking_tool_result_list: { capability: "memory.read", operation: "result_list", pathParams: [] },
  memory_store: { capability: "memory.write", operation: "store", pathParams: [] },
  memory_forget: { capability: "memory.write", operation: "forget", pathParams: [] },
  add_resource: { capability: "memory.write", operation: "add_resource", pathParams: [] },
  remove_resource: { capability: "memory.write", operation: "remove_resource", pathParams: [] },
  add_skill: { capability: "memory.write", operation: "add_skill", pathParams: [] },

  web_search: { capability: "network.read", operation: "search", pathParams: [] },
  web_fetch: { capability: "network.read", operation: "fetch", pathParams: [] },
  browser: { capability: "browser", operation: "browser", pathParams: [] },
  message: { capability: "external.write", operation: "message", pathParams: [] },
  sessions_send: { capability: "external.write", operation: "sessions_send", pathParams: [] },
  sessions_spawn: { capability: "external.write", operation: "sessions_spawn", pathParams: [] },
  conversations_send: { capability: "external.write", operation: "conversations_send", pathParams: [] },
  conversations_turn: { capability: "external.write", operation: "conversations_turn", pathParams: [] },
  sessions_list: { capability: "session.read", operation: "sessions_list", pathParams: [] },
  sessions_history: { capability: "session.read", operation: "sessions_history", pathParams: [] },
  conversations_list: { capability: "session.read", operation: "conversations_list", pathParams: [] }
};

function mergeProfile(base, override) {
  if (!override) return base;
  return {
    capability: override.capability ?? base?.capability ?? "tool",
    operation: override.operation ?? base?.operation,
    pathParams: override.pathParams ?? base?.pathParams ?? [],
    patchParams: override.patchParams ?? base?.patchParams ?? [],
    pathOperations: override.pathOperations ?? base?.pathOperations
  };
}

function addFsTarget(fsTargets, operation, filePath) {
  if (!filePath) return;
  const key = `${operation}\0${filePath}`;
  if (fsTargets.some((target) => `${target.operation}\0${target.path}` === key)) return;
  fsTargets.push({ operation, path: filePath });
}

export function buildCallContext(event, hookContext, policy, virtualWorkspaceRoot) {
  const toolName = String(event?.toolName ?? "");
  const params = event?.params && typeof event.params === "object" && !Array.isArray(event.params) ? event.params : {};
  const profile = mergeProfile(BUILTIN[toolName], policy.toolProfiles?.[toolName]);
  const capability = profile?.capability ?? "tool";
  const operation = profile?.operation ?? toolName;
  const paths = [];
  const fsTargets = [];

  for (const filePath of pathsFromSelectors(params, profile?.pathParams ?? [], virtualWorkspaceRoot)) paths.push(filePath);

  for (const [fsOperation, selectors] of Object.entries(profile?.pathOperations ?? {})) {
    for (const filePath of pathsFromSelectors(params, selectors, virtualWorkspaceRoot)) {
      paths.push(filePath);
      addFsTarget(fsTargets, fsOperation, filePath);
    }
  }

  for (const selector of profile?.patchParams ?? []) {
    for (const raw of pathsFromPatchSelector(params, selector)) {
      for (const target of extractPatchTargets(raw, virtualWorkspaceRoot)) {
        paths.push(target.path);
        addFsTarget(fsTargets, target.operation, target.path);
      }
    }
  }

  // OpenClaw supplies best-effort derivedPaths for selected tools such as apply_patch.
  // In sandbox mode these hints can be host-side. Prefer sandbox-visible parsing and
  // use host hints only when our own parser found nothing. Derived paths do not encode
  // delete/move semantics, so they are only a conservative WRITE fallback.
  if (paths.length === 0 && Array.isArray(event?.derivedPaths)) {
    const workspaceDir = hookContext?.workspaceDir ?? event?.context?.workspaceDir;
    for (const raw of event.derivedPaths) {
      if (typeof raw !== "string") continue;
      const mapped = normalizeDerivedPath(raw, workspaceDir, virtualWorkspaceRoot);
      if (mapped) {
        paths.push(mapped);
        if (capability === "fs.write") addFsTarget(fsTargets, "write", mapped);
      }
    }
  }

  return {
    agentId: hookContext?.agentId ?? event?.context?.agentId,
    sessionKey: hookContext?.sessionKey ?? event?.context?.sessionKey,
    workspaceDir: hookContext?.workspaceDir ?? event?.context?.workspaceDir,
    toolName,
    capability,
    operation,
    paths: [...new Set(paths)],
    fsTargets,
    params
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

export function relativizeSandboxWorkspacePath(raw, virtualWorkspaceRoot = "/workspace") {
  if (typeof raw !== "string") return raw;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.includes("\0")) return raw;
  const candidate = trimmed.replaceAll("\\", "/");
  if (!candidate.startsWith("/")) return raw;

  const root = path.posix.normalize(String(virtualWorkspaceRoot).replaceAll("\\", "/"));
  const normalized = path.posix.normalize(candidate);
  if (normalized === root) return ".";
  const prefix = root.endsWith("/") ? root : `${root}/`;
  if (!normalized.startsWith(prefix)) return raw;
  return normalized.slice(prefix.length);
}

export function rewritePatchWorkspacePaths(patchText, virtualWorkspaceRoot = "/workspace") {
  if (typeof patchText !== "string") return patchText;
  let changed = false;
  const lines = patchText.split(/(\r?\n)/);
  for (let i = 0; i < lines.length; i += 2) {
    const line = lines[i];
    let next = line;

    const special = line.match(/^(\s*\*\*\*\s+(?:Add File|Update File|Delete File|Move to):\s+)(.+?)(\s*)$/);
    if (special) {
      const rewritten = relativizeSandboxWorkspacePath(special[2], virtualWorkspaceRoot);
      if (rewritten !== special[2]) next = `${special[1]}${rewritten}${special[3]}`;
    } else {
      const unified = line.match(/^((?:---|\+\+\+)\s+)([^\t]+?)(\t.*)?$/);
      if (unified && unified[2] !== "/dev/null") {
        const rewritten = relativizeSandboxWorkspacePath(unified[2], virtualWorkspaceRoot);
        if (rewritten !== unified[2]) next = `${unified[1]}${rewritten}${unified[3] ?? ""}`;
      }
    }

    if (next !== line) {
      lines[i] = next;
      changed = true;
    }
  }
  return changed ? lines.join("") : patchText;
}

export function rewriteAllowedFilesystemMutationParams(call, policy, virtualWorkspaceRoot = "/workspace") {
  if (!call || !["fs.write", "fs.delete", "fs.move"].includes(call.capability)) return null;
  const params = call.params;
  if (!params || typeof params !== "object" || Array.isArray(params)) return null;

  const profile = mergeProfile(BUILTIN[call.toolName], policy.toolProfiles?.[call.toolName]);
  if (!profile) return null;
  const cloned = structuredClone(params);
  let changed = false;
  const rewrite = (value) => relativizeSandboxWorkspacePath(value, virtualWorkspaceRoot);

  const selectors = new Set([
    ...(profile.pathParams ?? []),
    ...Object.values(profile.pathOperations ?? {}).flat(),
  ]);
  for (const selector of selectors) {
    changed = rewriteValuesAtSelector(cloned, selector, rewrite) || changed;
  }

  for (const selector of profile.patchParams ?? []) {
    changed = rewriteValuesAtSelector(
      cloned,
      selector,
      (value) => rewritePatchWorkspacePaths(value, virtualWorkspaceRoot),
    ) || changed;
  }

  return changed ? cloned : null;
}

function normalizeDerivedPath(raw, workspaceDir, virtualWorkspaceRoot) {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (typeof workspaceDir === "string" && workspaceDir && path.isAbsolute(trimmed)) {
    const root = path.resolve(workspaceDir);
    const target = path.resolve(trimmed);
    const relative = path.relative(root, target);
    if (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))) {
      const posixRelative = relative.split(path.sep).join(path.posix.sep);
      return normalizeToolPath(posixRelative || ".", virtualWorkspaceRoot);
    }
  }
  return normalizeToolPath(trimmed, virtualWorkspaceRoot);
}

function pathsFromPatchSelector(params, selector) {
  const value = params?.[selector];
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((item) => typeof item === "string");
  return [];
}

export function validateToolProfiles(toolProfiles) {
  if (toolProfiles === undefined) return;
  if (!toolProfiles || typeof toolProfiles !== "object" || Array.isArray(toolProfiles)) throw new Error("toolProfiles must be an object");
  for (const [tool, profile] of Object.entries(toolProfiles)) {
    if (!tool) throw new Error("toolProfiles: empty tool name");
    if (!profile || typeof profile !== "object" || Array.isArray(profile)) throw new Error(`toolProfiles.${tool} must be an object`);
    for (const key of Object.keys(profile)) {
      if (!["capability", "operation", "pathParams", "patchParams", "pathOperations"].includes(key)) throw new Error(`toolProfiles.${tool}.${key}: unknown field`);
    }
    if (profile.capability !== undefined && (typeof profile.capability !== "string" || !profile.capability)) throw new Error(`toolProfiles.${tool}.capability must be non-empty string`);
    if (profile.operation !== undefined && (typeof profile.operation !== "string" || !profile.operation)) throw new Error(`toolProfiles.${tool}.operation must be non-empty string`);
    for (const key of ["pathParams", "patchParams"]) {
      if (profile[key] !== undefined && (!Array.isArray(profile[key]) || profile[key].some((x) => typeof x !== "string" || !x))) throw new Error(`toolProfiles.${tool}.${key} must be string[] values`);
    }
    if (profile.pathOperations !== undefined) {
      if (!profile.pathOperations || typeof profile.pathOperations !== "object" || Array.isArray(profile.pathOperations)) throw new Error(`toolProfiles.${tool}.pathOperations must be an object`);
      for (const [operation, selectors] of Object.entries(profile.pathOperations)) {
        if (!['read', 'write', 'delete', 'move', 'execute'].includes(operation)) throw new Error(`toolProfiles.${tool}.pathOperations.${operation}: unsupported filesystem operation`);
        if (!Array.isArray(selectors) || selectors.length === 0 || selectors.some((x) => typeof x !== "string" || !x)) throw new Error(`toolProfiles.${tool}.pathOperations.${operation} must be non-empty string[]`);
      }
    }
  }
}
