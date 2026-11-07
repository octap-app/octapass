// What must stay true of the package: both languages complete, nothing that activates by itself,
// no way to read a secret, and the client free of `vscode`.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = join(__dirname, '..');
const text = (path: string) => readFileSync(join(root, path), 'utf8');
const json = (path: string) => JSON.parse(text(path)) as Record<string, unknown>;
const sources = readdirSync(join(root, 'src')).map((file) => ({ file, source: text(join('src', file)) }));

function placeholders(strings: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(strings).map(([key, value]) => [key, (String(value).match(/\{\d+\}|\(command:[^)]*\)/g) ?? []).join()]),
  );
}

describe('strings', () => {
  const used = sources.flatMap(({ source }) =>
    [...source.matchAll(/l10n\.t\(\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")/g)].map((match) =>
      (match[1] ?? match[2])!.replace(/\\(.)/g, '$1'),
    ),
  );

  it('finds the strings in the code', () => {
    expect(used.length).toBeGreaterThan(15);
  });

  it('has every l10n.t string in both bundles, and no leftovers', () => {
    const english = Object.keys(json('l10n/bundle.l10n.json')).sort();
    expect(english).toEqual([...new Set(used)].sort());
    expect(Object.keys(json('l10n/bundle.l10n.ar.json')).sort()).toEqual(english);
  });

  it('has the same keys and placeholders in both package.nls files', () => {
    const english = json('package.nls.json');
    const arabic = json('package.nls.ar.json');
    expect(Object.keys(arabic).sort()).toEqual(Object.keys(english).sort());
    expect(placeholders(arabic)).toEqual(placeholders(english));
  });

  it('keeps the placeholders of the bundles', () => {
    expect(placeholders(json('l10n/bundle.l10n.ar.json'))).toEqual(placeholders(json('l10n/bundle.l10n.json')));
  });

  it('defines every %key% of the manifest', () => {
    const keys = [...text('package.json').matchAll(/"%([\w.]+)%"/g)].map((match) => match[1]!);
    const english = json('package.nls.json');
    expect(keys.length).toBeGreaterThan(5);
    for (const key of keys) {
      expect(english).toHaveProperty([key]);
    }
  });
});

describe('the manifest', () => {
  const manifest = json('package.json') as {
    activationEvents: string[];
    contributes: { configuration: { properties: Record<string, { scope: string }> } };
  };

  it('declares no activation of its own', () => {
    expect(manifest.activationEvents).toEqual([]);
  });

  it('keeps the CLI path out of reach of workspace settings', () => {
    expect(manifest.contributes.configuration.properties['octapass.cliPath']?.scope).toBe('machine');
  });
});

describe('the code', () => {
  it('never reads a secret value', () => {
    for (const { file, source } of sources) {
      expect(`${file}: ${source.includes('/v1/read')}`).toBe(`${file}: false`);
    }
  });

  it('keeps the tested modules free of vscode', () => {
    for (const { file, source } of sources.filter(({ file }) => ['connect.ts', 'references.ts', 'run.ts'].includes(file))) {
      expect(`${file}: ${/from 'vscode'/.test(source)}`).toBe(`${file}: false`);
    }
  });

  it('makes no network call but the one in the client', () => {
    for (const { file, source } of sources.filter(({ file }) => file !== 'connect.ts')) {
      expect(`${file}: ${/node:(https?|net|tls)'|\bfetch\(/.test(source)}`).toBe(`${file}: false`);
    }
  });

  it('stays out of the editor proxy patch on http.request', () => {
    const client = sources.find(({ file }) => file === 'connect.ts')!.source;
    expect(client).toContain('new http.ClientRequest(');
    expect(/http\.(request|get)\(/.test(client)).toBe(false);
  });

  it('keeps the token only in SecretStorage', () => {
    for (const { file, source } of sources) {
      expect(`${file}: ${/(globalState|workspaceState)\.update\([^)]*token/i.test(source)}`).toBe(`${file}: false`);
    }
  });
});
