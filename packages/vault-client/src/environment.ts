// Environments: `.env` files and environment variables kept in the vault. The Rust core has the
// same reader and writer for the CLI; this copy gives the web vault and the extension the same
// rules without a round trip to WASM. Keep the two in step.

import type { EnvironmentVariable } from './types';

/** The stages apps know by name, translate and colour. Any other valid name is a custom stage. */
export const KNOWN_STAGES = ['development', 'staging', 'production', 'testing', 'preview', 'local'] as const;

export type EnvironmentFormat = 'dotenv' | 'json' | 'shell' | 'powershell' | 'docker';

/** A problem in a `.env` file or a variable list. `line` is 1-based; 0 means the list, not a file. */
export class EnvironmentError extends Error {
  readonly message: string;
  readonly line: number;
  readonly key?: string;

  constructor(message: string, line = 0, key?: string) {
    const where = key ? (line ? `line ${line} (${key})` : key) : line ? `line ${line}` : undefined;
    super(where ? `${where}: ${message}` : message);
    this.message = where ? `${where}: ${message}` : message;
    this.line = line;
    this.key = key;
    this.name = 'EnvironmentError';
  }
}

/** Names are letters, digits and `_`, not starting with a digit. */
export function validEnvironmentKey(key: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(key);
}

function assertKey(key: string, line = 0): void {
  if (!validEnvironmentKey(key)) throw new EnvironmentError('names are letters, digits and _, and don\'t start with a digit', line, key);
}

/** A project identifier: 1-64 letters, digits, `-` and `_`. */
export function validProject(project: string): boolean {
  return /^[A-Za-z0-9_-]{1,64}$/.test(project);
}

/** A stage name: 1-32 letters, digits, `-` and `_`. */
export function validStage(stage: string): boolean {
  return /^[A-Za-z0-9_-]{1,32}$/.test(stage);
}

export function isProductionStage(stage: string | undefined): boolean {
  return stage !== undefined && ['production', 'prod'].includes(stage.toLowerCase());
}

export function validateEnvironment(details: { project?: string; stage?: string; variables: EnvironmentVariable[] }): void {
  if (details.project !== undefined && !validProject(details.project)) {
    throw new EnvironmentError('a project is up to 64 letters, digits, - and _, like shop-api');
  }
  if (details.stage !== undefined && !validStage(details.stage)) {
    throw new EnvironmentError('a stage is up to 32 letters, digits, - and _, like production');
  }
  const seen = new Set<string>();
  for (const variable of details.variables) {
    assertKey(variable.key);
    if (seen.has(variable.key)) throw new EnvironmentError('this name is already used', 0, variable.key);
    seen.add(variable.key);
  }
}

export interface ParsedVariable {
  key: string;
  value: string;
  line: number;
}

/** The value inside a double-quoted string (after its opening quote) and the text after it. */
function doubleQuoted(text: string): { value: string; rest: string } | undefined {
  let value = '';
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]!;
    if (char === '"') return { value, rest: text.slice(i + 1) };
    if (char === '\\') {
      const next = text[i + 1];
      if (next === undefined) return undefined;
      value += next === 'n' ? '\n' : next === 't' ? '\t' : next === 'r' ? '\r' : next;
      i += 1;
    } else {
      value += char;
    }
  }
  return undefined;
}

/** An unquoted value, without a ` #` comment after it. */
function unquoted(raw: string): string {
  let comment = -1;
  for (let i = 1; i < raw.length; i += 1) {
    if (raw[i] === '#' && (raw[i - 1] === ' ' || raw[i - 1] === '\t')) {
      comment = i;
      break;
    }
  }
  return (comment === -1 ? raw : raw.slice(0, comment)).trimEnd();
}

function trailing(rest: string, line: number, key: string): void {
  const text = rest.trim();
  if (text && !text.startsWith('#')) throw new EnvironmentError('unexpected text after the closing quote', line, key);
}

/**
 * Reads a `.env` file: `KEY=value` lines, `#` comments, an optional `export `, single-quoted values
 * (as written), double-quoted values (with `\n`, `\t`, `\r`, `\"` and `\\`, and real line breaks)
 * and unquoted values (a ` #` starts a comment). A name used twice is kept twice.
 */
export function parseDotenv(text: string): ParsedVariable[] {
  const lines = text.split(/\r?\n/);
  const variables: ParsedVariable[] = [];
  let index = 0;
  while (index < lines.length) {
    const line = index + 1;
    const trimmed = lines[index]!.trim();
    index += 1;
    if (!trimmed || trimmed.startsWith('#')) continue;
    const withoutExport = (trimmed.startsWith('export ') ? trimmed.slice(7) : trimmed).trimStart();
    const equals = withoutExport.indexOf('=');
    if (equals === -1) throw new EnvironmentError('expected KEY=value', line);
    const key = withoutExport.slice(0, equals).trim();
    if (!validEnvironmentKey(key)) throw new EnvironmentError("names are letters, digits and _, and don't start with a digit", line);
    const raw = withoutExport.slice(equals + 1).trim();
    let value: string;
    if (raw.startsWith("'")) {
      const end = raw.indexOf("'", 1);
      if (end === -1) throw new EnvironmentError("a quote isn't closed", line, key);
      trailing(raw.slice(end + 1), line, key);
      value = raw.slice(1, end);
    } else if (raw.startsWith('"')) {
      let rest = raw.slice(1);
      let combined = rest;
      let parsed = doubleQuoted(combined);
      while (!parsed) {
        if (index >= lines.length) throw new EnvironmentError("a quote isn't closed", line, key);
        rest = `${combined}\n${lines[index]!.replace(/\r$/, '')}`;
        combined = rest;
        index += 1;
        parsed = doubleQuoted(combined);
      }
      trailing(parsed.rest, line, key);
      value = parsed.value;
    } else {
      value = unquoted(raw);
    }
    variables.push({ key, value, line });
  }
  return variables;
}

/** A `.env` file as an environment's variables: concealed, in file order, each name once. */
export function variablesFromDotenv(text: string): EnvironmentVariable[] {
  const parsed = parseDotenv(text);
  const seen = new Set<string>();
  for (const variable of parsed) {
    if (seen.has(variable.key)) throw new EnvironmentError('this name is already used', variable.line, variable.key);
    seen.add(variable.key);
  }
  return parsed.map(({ key, value }) => ({ key, value, concealed: true }));
}

/** Adds or replaces variables by name, keeping existing order and the replaced variable's flag and note. */
export function mergeVariables(current: EnvironmentVariable[], next: EnvironmentVariable[]): EnvironmentVariable[] {
  const out = current.map((variable) => ({ ...variable }));
  for (const variable of next) {
    const existing = out.find((one) => one.key === variable.key);
    if (existing) existing.value = variable.value;
    else out.push({ ...variable });
  }
  return out;
}

/** The variables of several environments, later ones winning: shared set, then stage, then the rest. */
export function layerEnvironments(lists: readonly EnvironmentVariable[][]): EnvironmentVariable[] {
  const out: EnvironmentVariable[] = [];
  for (const list of lists) {
    for (const variable of list) {
      const at = out.findIndex((one) => one.key === variable.key);
      if (at === -1) out.push({ ...variable });
      else out[at] = { ...variable };
    }
  }
  return out;
}

export type EnvironmentDiffKind = 'onlyInFirst' | 'onlyInSecond' | 'different';

export function diffEnvironments(first: readonly EnvironmentVariable[], second: readonly EnvironmentVariable[]): { key: string; kind: EnvironmentDiffKind }[] {
  const find = (list: readonly EnvironmentVariable[], key: string) => list.find((one) => one.key === key);
  const out: { key: string; kind: EnvironmentDiffKind }[] = [];
  for (const variable of first) {
    const other = find(second, variable.key);
    if (!other) out.push({ key: variable.key, kind: 'onlyInFirst' });
    else if (other.value !== variable.value) out.push({ key: variable.key, kind: 'different' });
  }
  for (const variable of second) if (!find(first, variable.key)) out.push({ key: variable.key, kind: 'onlyInSecond' });
  return out;
}

/** A value as a dotenv file writes it: bare when that reads back the same, else quoted. */
function dotenvValue(value: string): string {
  if (/^[A-Za-z0-9_\-./:@%+,=^~]*$/.test(value)) return value;
  if (!value.includes("'") && !value.includes('\n') && !value.includes('\r')) return `'${value}'`;
  let out = '"';
  for (const char of value) {
    if (char === '\\') out += '\\\\';
    else if (char === '"') out += '\\"';
    else if (char === '\r') out += '\\r';
    else if (char === '\t') out += '\\t';
    else out += char;
  }
  return `${out}"`;
}

/** Writes variables in the chosen format. Docker has no quoting, so a line break can't be written. */
export function writeEnvironment(variables: readonly Pick<EnvironmentVariable, 'key' | 'value'>[], format: EnvironmentFormat): string {
  for (const { key } of variables) assertKey(key);
  if (format === 'json') {
    if (variables.length === 0) return '{}\n';
    return `{\n${variables.map(({ key, value }) => `  ${JSON.stringify(key)}: ${JSON.stringify(value)}`).join(',\n')}\n}\n`;
  }
  if (variables.length === 0) return '';
  return variables
    .map(({ key, value }) => {
      switch (format) {
        case 'dotenv':
          return `${key}=${dotenvValue(value)}`;
        case 'shell':
          return `export ${key}='${value.replaceAll("'", "'\\''")}'`;
        case 'powershell':
          return `$env:${key} = '${value.replaceAll("'", "''")}'`;
        case 'docker':
          if (value.includes('\n') || value.includes('\r')) {
            throw new EnvironmentError('Docker\'s env file format can\'t hold a value with a line break: use dotenv or run the command with `octapass run`', 0, key);
          }
          return `${key}=${value}`;
      }
    })
    .join('\n')
    .concat('\n');
}
