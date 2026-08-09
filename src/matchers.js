const REGEX_FLAGS = /^[imsu]*$/;
const MAX_REGEX_LENGTH = 2048;

function assertOnlyKeys(object, allowed, where) {
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) throw new Error(`${where}.${key}: unknown field`);
  }
}

export function globToRegExp(glob) {
  let out = "^";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") {
          i++;
          out += "(?:.*/)?";
        } else {
          out += ".*";
        }
      } else {
        out += "[^/]*";
      }
      continue;
    }
    if (c === "?") {
      out += "[^/]";
      continue;
    }
    out += c.replace(/[\\^$+.()|{}\[\]]/g, "\\$&");
  }
  out += "$";
  return new RegExp(out, "u");
}

export function validateMatcher(matcher, where = "matcher") {
  if (typeof matcher === "string") {
    if (!matcher) throw new Error(`${where}: matcher string must not be empty`);
    return;
  }
  if (!matcher || typeof matcher !== "object" || Array.isArray(matcher)) {
    throw new Error(`${where}: matcher must be string or object`);
  }
  assertOnlyKeys(matcher, new Set(["exact", "glob", "regex", "flags"]), where);
  const keys = ["exact", "glob", "regex"].filter((k) => Object.hasOwn(matcher, k));
  if (keys.length !== 1) throw new Error(`${where}: exactly one of exact/glob/regex is required`);
  const key = keys[0];
  if (typeof matcher[key] !== "string" || !matcher[key]) throw new Error(`${where}.${key}: must be a non-empty string`);
  if (key === "regex") {
    if (matcher.regex.length > MAX_REGEX_LENGTH) throw new Error(`${where}.regex: too long`);
    const flags = matcher.flags ?? "u";
    if (typeof flags !== "string" || !REGEX_FLAGS.test(flags)) throw new Error(`${where}.flags: only i/m/s/u are allowed`);
    new RegExp(matcher.regex, flags.includes("u") ? flags : `${flags}u`);
  } else if (Object.hasOwn(matcher, "flags")) {
    throw new Error(`${where}.flags: only valid with regex`);
  }
}

export function matchValue(matcher, value) {
  if (typeof value !== "string") return false;
  if (typeof matcher === "string") return globToRegExp(matcher).test(value);
  if (Object.hasOwn(matcher, "exact")) return value === matcher.exact;
  if (Object.hasOwn(matcher, "glob")) return globToRegExp(matcher.glob).test(value);
  if (Object.hasOwn(matcher, "regex")) {
    const flags = matcher.flags ?? "u";
    return new RegExp(matcher.regex, flags.includes("u") ? flags : `${flags}u`).test(value);
  }
  return false;
}

export function matchAny(matchers, value) {
  const list = Array.isArray(matchers) ? matchers : [matchers];
  return list.some((matcher) => matchValue(matcher, value));
}
