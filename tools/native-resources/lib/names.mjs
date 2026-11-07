// Catalog keys as native names. Two keys that come out as the same name are an error, never a
// silent overwrite.

const SWIFT_KEYWORDS = new Set(
  ('associatedtype class deinit enum extension fileprivate func import init inout internal let open operator private ' +
    'precedencegroup protocol public rethrows static struct subscript typealias var break case catch continue default ' +
    'defer do else fallthrough for guard if in repeat return throw switch where while Any as await false is nil self ' +
    'Self super throws true try Type Protocol').split(' '),
);

const KOTLIN_KEYWORDS = new Set(
  'as break class continue do else false for fun if in interface is null object package return super this throw true try typealias typeof val var when while'.split(' '),
);

const JAVA_KEYWORDS = new Set(
  ('abstract assert boolean break byte case catch char class const continue default do double else enum extends final ' +
    'finally float for goto if implements import instanceof int interface long native new package private protected public ' +
    'return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null').split(' '),
);

/**
 * One key segment as an identifier: `-x` → `X` (`onepassword-1pux` → `onepassword1pux`), a
 * leading digit moves behind an underscore (`2fas` → `_2fas`), anything else not allowed → `_`.
 */
export function identifier(segment) {
  let id = segment.replace(/-+([a-zA-Z0-9])/g, (_, c) => c.toUpperCase()).replace(/[^a-zA-Z0-9_]/g, '_');
  if (/^[0-9]/.test(id)) id = `_${id}`;
  return id;
}

/** An identifier Swift accepts in a declaration (keywords in backticks). */
export function swiftName(segment) {
  const id = identifier(segment);
  return SWIFT_KEYWORDS.has(id) ? `\`${id}\`` : id;
}

/** An identifier Kotlin accepts in a declaration (keywords in backticks). */
export function kotlinName(name) {
  const id = identifier(name);
  return KOTLIN_KEYWORDS.has(id) ? `\`${id}\`` : id;
}

/** A catalog key as an Android resource name: `common.back` → `common_back`, `a.b-c` → `a_b_c`. */
export function androidName(key) {
  const name = key.replace(/[^a-zA-Z0-9_]/g, '_');
  if (!/^[a-zA-Z_]/.test(name) || JAVA_KEYWORDS.has(name)) throw new Error(`${key}: "${name}" isn't a usable Android resource name`);
  return name;
}

/** Throws if two inputs map to the same name; returns the Map input → name. */
export function uniqueNames(inputs, toName, what) {
  const byName = new Map();
  const out = new Map();
  const clashes = [];
  for (const input of inputs) {
    const name = toName(input);
    const other = byName.get(name);
    if (other !== undefined) clashes.push(`"${other}" and "${input}" are both ${what} "${name}"`);
    else byName.set(name, input);
    out.set(input, name);
  }
  if (clashes.length) throw new Error(`Name collisions:\n  ${clashes.join('\n  ')}`);
  return out;
}
