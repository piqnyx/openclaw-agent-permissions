import fs from "node:fs";
import path from "node:path";
import { matchAny, validateMatcher } from "./matchers.js";

const PATH_MAPPING_KEYS = new Set([
  "id", "description", "virtual", "host", "agents", "sessions", "tools"
]);
const AGENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const TEMPLATE_PATTERN = /\{([^{}]+)\}/gu;
const ANY_TEMPLATE_PATTERN = /\{[^{}]+\}/u;

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

function validateHostTemplate(value, where) {
  if (typeof value !== "string" || !value || value.includes("\0")) {
    throw new Error(`${where}: absolute host path template required`);
  }
  const placeholders = [...value.matchAll(TEMPLATE_PATTERN)].map((match) => match[1]);
  if (placeholders.some((name) => name !== "agentId")) {
    throw new Error(`${where}: only {agentId} template variable is supported`);
  }
  const rendered = value.replaceAll("{agentId}", "agent");
  if (!path.isAbsolute(rendered)) throw new Error(`${where}: absolute host path template required`);
}

export function validatePathMappings(mappings, where = "pathMappings") {
  if (mappings === undefined) return;
  if (!Array.isArray(mappings)) throw new Error(`${where} must be array`);
  const ids = new Set();
  for (let i = 0; i < mappings.length; i++) {
    const mapping = mappings[i];
    const itemWhere = `${where}[${i}]`;
    assertObject(mapping, itemWhere);
    for (const key of Object.keys(mapping)) {
      if (!PATH_MAPPING_KEYS.has(key)) throw new Error(`${itemWhere}.${key}: unknown field`);
    }
    if (typeof mapping.id !== "string" || !mapping.id) throw new Error(`${itemWhere}.id: required`);
    if (ids.has(mapping.id)) throw new Error(`${itemWhere}.id: duplicate '${mapping.id}'`);
    ids.add(mapping.id);
    if (mapping.description !== undefined && typeof mapping.description !== "string") {
      throw new Error(`${itemWhere}.description: string required`);
    }
    if (typeof mapping.virtual !== "string" || !mapping.virtual.startsWith("/") || mapping.virtual.includes("\0")) {
      throw new Error(`${itemWhere}.virtual: absolute POSIX path required`);
    }
    const normalizedVirtual = path.posix.normalize(mapping.virtual.replaceAll("\\", "/"));
    if (normalizedVirtual !== mapping.virtual || (mapping.virtual.length > 1 && mapping.virtual.endsWith("/"))) {
      throw new Error(`${itemWhere}.virtual: normalized absolute POSIX path required`);
    }
    validateHostTemplate(mapping.host, `${itemWhere}.host`);
    validateMatcherList(mapping.agents, `${itemWhere}.agents`);
    validateMatcherList(mapping.sessions, `${itemWhere}.sessions`);
    validateMatcherList(mapping.tools, `${itemWhere}.tools`);
  }
}

function contextMatches(mapping, call) {
  if (mapping.agents !== undefined && !(typeof call.agentId === "string" && matchAny(mapping.agents, call.agentId))) return false;
  if (mapping.sessions !== undefined && !(typeof call.sessionKey === "string" && matchAny(mapping.sessions, call.sessionKey))) return false;
  if (mapping.tools !== undefined && !(typeof call.toolName === "string" && matchAny(mapping.tools, call.toolName))) return false;
  return true;
}

function mappingMatchesPath(mapping, lexical) {
  return lexical === mapping.virtual || lexical.startsWith(`${mapping.virtual}/`);
}

function renderHost(mapping, call) {
  let host = mapping.host;
  if (host.includes("{agentId}")) {
    if (typeof call.agentId !== "string" || !AGENT_ID_PATTERN.test(call.agentId)) {
      return { ok: false, reason: `mapping ${mapping.id} requires a safe agentId` };
    }
    host = host.replaceAll("{agentId}", call.agentId);
  }
  if (ANY_TEMPLATE_PATTERN.test(host)) {
    return { ok: false, reason: `mapping ${mapping.id} contains an unresolved host template variable` };
  }
  if (!path.isAbsolute(host)) return { ok: false, reason: `mapping ${mapping.id} resolved to a non-absolute host path` };
  return { ok: true, host: path.normalize(host) };
}

function isInside(root, target) {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function deepestExistingAncestor(target) {
  let current = target;
  const suffix = [];
  while (true) {
    try {
      fs.lstatSync(current);
      return { ancestor: current, suffix };
    } catch (err) {
      if (err?.code !== "ENOENT" && err?.code !== "ENOTDIR") throw err;
    }
    const parent = path.dirname(current);
    if (parent === current) return null;
    suffix.unshift(path.basename(current));
    current = parent;
  }
}

export function selectPathMapping(mappings, call, lexical, mappingIds) {
  const allowedIds = Array.isArray(mappingIds) && mappingIds.length > 0 ? new Set(mappingIds) : null;
  return (mappings ?? [])
    .filter((mapping) => (!allowedIds || allowedIds.has(mapping.id)) && contextMatches(mapping, call) && mappingMatchesPath(mapping, lexical))
    .toSorted((a, b) => b.virtual.length - a.virtual.length)[0] ?? null;
}

export function resolveMappedPath(mappings, call, lexical, options = {}) {
  if (typeof lexical !== "string" || !lexical.startsWith("/")) {
    return { ok: false, code: "invalid", reason: `invalid virtual path: ${String(lexical)}` };
  }
  const mapping = selectPathMapping(mappings, call, lexical, options.mappingIds);
  if (!mapping) {
    return { ok: false, code: "unmapped", reason: `no path mapping covers ${lexical}` };
  }

  const rendered = renderHost(mapping, call);
  if (!rendered.ok) return { ok: false, code: "context", reason: rendered.reason };

  let hostRoot;
  try {
    hostRoot = fs.realpathSync.native(rendered.host);
  } catch (err) {
    return { ok: false, code: "root", reason: `path mapping ${mapping.id} host root cannot be resolved: ${String(err)}` };
  }

  const relativePosix = lexical === mapping.virtual ? "" : path.posix.relative(mapping.virtual, lexical);
  const hostCandidate = path.resolve(rendered.host, ...relativePosix.split("/").filter(Boolean));
  let ancestorInfo;
  let realAncestor;
  try {
    ancestorInfo = deepestExistingAncestor(hostCandidate);
    if (!ancestorInfo) return { ok: false, code: "physical", reason: `cannot resolve an existing ancestor for ${lexical}` };
    realAncestor = fs.realpathSync.native(ancestorInfo.ancestor);
  } catch (err) {
    return { ok: false, code: "physical", reason: `physical path verification failed for ${lexical}: ${String(err)}` };
  }

  if (!isInside(hostRoot, realAncestor)) {
    return { ok: false, code: "escape", reason: `${lexical} resolves through a symlink outside path mapping ${mapping.id}` };
  }

  const realCandidate = path.resolve(realAncestor, ...ancestorInfo.suffix);
  if (!isInside(hostRoot, realCandidate)) {
    return { ok: false, code: "escape", reason: `${lexical} resolves outside path mapping ${mapping.id}` };
  }

  const physicalRelative = path.relative(hostRoot, realCandidate).split(path.sep).join("/");
  const physicalVirtual = physicalRelative ? path.posix.join(mapping.virtual, physicalRelative) : mapping.virtual;
  if (physicalVirtual !== lexical) {
    return { ok: false, code: "alias", reason: `${lexical} physically resolves to ${physicalVirtual} via path mapping ${mapping.id}` };
  }

  return {
    ok: true,
    mappingId: mapping.id,
    virtualRoot: mapping.virtual,
    hostRoot,
    hostPath: realCandidate,
  };
}
