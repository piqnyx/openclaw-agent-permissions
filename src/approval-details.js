const TOOL_APPROVAL_FIELDS = Object.freeze({
  remove_resource: Object.freeze([
    Object.freeze({ param: "uri", label: "Target URI", maxChars: 280 }),
    Object.freeze({ param: "recursive", label: "Recursive", maxChars: 32 }),
    Object.freeze({ param: "wait", label: "Wait", maxChars: 32 }),
  ]),
});

function sanitizeScalar(value, maxChars) {
  let text;
  if (typeof value === "string") text = value;
  else if (typeof value === "boolean") text = value ? "true" : "false";
  else if (typeof value === "number" && Number.isFinite(value)) text = String(value);
  else return null;

  const normalized = text.replace(/[\u0000-\u001f\u007f]+/gu, " ").replace(/\s+/gu, " ").trim();
  if (!normalized) return null;
  if (normalized.length <= maxChars) return normalized;
  return `${normalized.slice(0, Math.max(0, maxChars - 1))}…`;
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
