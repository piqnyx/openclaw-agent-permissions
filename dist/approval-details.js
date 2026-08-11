const TOOL_APPROVAL_FIELDS = Object.freeze({
  remove_resource: Object.freeze([
    Object.freeze({ param: "uri", label: "Target URI", maxChars: 220 }),
    Object.freeze({ param: "recursive", label: "Recursive", maxChars: 32 }),
    Object.freeze({ param: "wait", label: "Wait", maxChars: 32 }),
  ]),
});

const DESCRIPTION_MAX_CHARS = 500;
const ACTION_CONTENT_MAX_CHARS = 190;
const BOX_RULE_WIDTH = 36;

function clamp(value, maxChars) {
  const text = String(value);
  return text.length <= maxChars ? text : `${text.slice(0, Math.max(0, maxChars - 1))}…`;
}

function truncateMiddle(value, maxChars) {
  const text = String(value);
  if (text.length <= maxChars) return text;
  const markerBase = " … omitted … ";
  if (maxChars <= markerBase.length + 8) return clamp(text, maxChars);
  const remaining = maxChars - markerBase.length;
  const head = Math.ceil(remaining * 0.6);
  const tail = Math.floor(remaining * 0.4);
  return `${text.slice(0, head)}${markerBase}${text.slice(text.length - tail)}`;
}

function sanitizeScalar(value, maxChars) {
  let text;
  if (typeof value === "string") text = value;
  else if (typeof value === "boolean") text = value ? "true" : "false";
  else if (typeof value === "number" && Number.isFinite(value)) text = String(value);
  else return null;

  const normalized = text
    .replace(/[\u0000-\u001f\u007f-\u009f]+/gu, " ")
    .replace(/[\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069]/gu, "?")
    .replace(/\s+/gu, " ")
    .trim();
  if (!normalized) return null;
  return truncateMiddle(normalized, maxChars);
}

function visibleCommand(value) {
  if (typeof value !== "string" || !value) return "<unresolved command>";
  const normalized = value.replace(/\r\n/gu, "\n");
  let out = "";
  for (const ch of normalized) {
    const code = ch.codePointAt(0);
    if (ch === "\n") {
      out += " ↵\n";
      continue;
    }
    if (ch === "\r") {
      out += "\\r";
      continue;
    }
    if (ch === "\t") {
      out += "⇥";
      continue;
    }
    if (
      code < 0x20 ||
      (code >= 0x7f && code <= 0x9f) ||
      code === 0x061c ||
      (code >= 0x200b && code <= 0x200f) ||
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069)
    ) {
      out += `\\u${code.toString(16).padStart(4, "0")}`;
      continue;
    }
    out += ch;
  }
  return truncateMiddle(out, ACTION_CONTENT_MAX_CHARS);
}

function wrapLine(value, width = 96) {
  const text = String(value);
  if (!text) return ["<empty>"];
  const lines = [];
  let remaining = text;
  while (remaining.length > width) {
    lines.push(remaining.slice(0, width));
    remaining = `↳ ${remaining.slice(width)}`;
  }
  lines.push(remaining);
  return lines;
}

function renderBox(label, values) {
  const safeLabel = sanitizeScalar(label, 28) ?? "REQUEST";
  const horizontal = "─".repeat(Math.max(4, BOX_RULE_WIDTH - safeLabel.length));
  const lines = [`┌─ ${safeLabel} ${horizontal}`];
  const raw = truncateMiddle(
    values.map((value) => String(value)).join("\n"),
    ACTION_CONTENT_MAX_CHARS,
  );
  for (const logicalLine of raw.split("\n")) {
    for (const visualLine of wrapLine(logicalLine)) lines.push(`│ ${visualLine}`);
  }
  lines.push(`└${"─".repeat(BOX_RULE_WIDTH + 3)}`);
  return lines.join("\n");
}

export function approvalDetailsForCall(call) {
  const fields = TOOL_APPROVAL_FIELDS[call?.toolName];
  if (!fields) return [];
  const params = call?.params;
  if (!params || typeof params !== "object" || Array.isArray(params)) return [];

  const details = [];
  for (const field of fields) {
    if (!Object.hasOwn(params, field.param)) continue;
    const value = sanitizeScalar(params[field.param], field.maxChars);
    if (value === null) continue;
    details.push({ label: field.label, value });
  }
  return details;
}

export function formatApprovalDetails(call) {
  const details = approvalDetailsForCall(call);
  return details.map(({ label, value }) => `${label}: ${value}`).join("\n");
}

function actionForCall(call, decision) {
  if (call?.capability === "exec") {
    const command =
      typeof call?.params?.command === "string"
        ? call.params.command
        : typeof call?.params?.cmd === "string"
          ? call.params.cmd
          : "";
    return renderBox("COMMAND", [visibleCommand(command)]);
  }

  if (call?.toolName === "remove_resource") {
    const details = approvalDetailsForCall(call);
    const uri = details.find((entry) => entry.label === "Target URI")?.value ?? "<unresolved resource>";
    const flags = details
      .filter((entry) => entry.label !== "Target URI")
      .map((entry) => `${entry.label.toLowerCase()}=${entry.value}`)
      .join(" · ");
    return renderBox("REMOVE RESOURCE", flags ? [uri, flags] : [uri]);
  }

  if (decision?.kind === "filesystem" || String(call?.capability ?? "").startsWith("fs.")) {
    const targets = Array.isArray(decision?.askTargets) && decision.askTargets.length > 0
      ? decision.askTargets.map((target) => `${target.operation}: ${target.path}`)
      : (call?.paths ?? []).map((path) => `${call?.operation ?? "access"}: ${path}`);
    return renderBox("FILESYSTEM REQUEST", [targets.join("\n") || "<unresolved filesystem target>"]);
  }

  const toolName = sanitizeScalar(call?.toolName ?? "unknown tool", 120) ?? "unknown tool";
  const lines = [toolName];
  const operation = sanitizeScalar(call?.operation, 80);
  const capability = sanitizeScalar(call?.capability, 80);
  if (operation && operation !== toolName) {
    lines.push(capability && capability !== "tool" ? `${capability} / ${operation}` : `operation: ${operation}`);
  } else if (capability && capability !== "tool") {
    lines.push(`capability: ${capability}`);
  }
  if (Array.isArray(call?.paths) && call.paths.length > 0) {
    lines.push(`target: ${call.paths.join(", ")}`);
  }
  return renderBox("TOOL REQUEST", lines);
}

function permanentText(call, decision, canAlways) {
  if (canAlways) {
    if (decision?.kind === "filesystem") {
      return "Permanent: available → exact operation + target(s) for this agent";
    }
    return "Permanent: available → this tool + capability for this agent; params may change";
  }
  if (decision?.allowAlways && !call?.agentId) {
    return "Permanent: unavailable because agent identity is missing";
  }
  return "Permanent: disabled";
}

export function formatApprovalDescription(call, decision, options = {}) {
  const canAlways = options.canAlways === true;
  const action = actionForCall(call, decision);
  const rule = sanitizeScalar(decision?.ruleId ?? "<default>", 64) ?? "<default>";
  const agent = sanitizeScalar(call?.agentId ?? "unknown", 40) ?? "unknown";
  const metadata = `Policy: ${rule} · Agent: ${agent}`;
  const permanent = permanentText(call, decision, canAlways);
  return clamp([action, metadata, permanent].join("\n"), DESCRIPTION_MAX_CHARS);
}
