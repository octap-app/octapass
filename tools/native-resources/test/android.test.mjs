// The real catalogs through the Android toolchain: aapt2 must accept both strings.xml files and
// read back every format string unchanged, and Java's Formatter (what getString/getQuantityString
// use) must turn them into what the web vault shows. Skipped without the Android SDK or a JDK.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadCatalogs } from '../lib/catalogs.mjs';
import { FSI, PDI, buildMessages, expectations, mergeCatalogs, toFormat } from '../lib/messages.mjs';
import { androidName } from '../lib/names.mjs';
import { androidSpecifier, stringsXml } from '../lib/strings.mjs';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const { web, phone } = await loadCatalogs(ROOT);
const messages = buildMessages(mergeCatalogs(web, phone));
const dir = mkdtempSync(join(tmpdir(), 'native-resources-android-'));
after(() => rmSync(dir, { recursive: true, force: true }));

const sdk = process.env.ANDROID_HOME;
const latest = (path, has) => (existsSync(path) ? readdirSync(path).filter((v) => existsSync(join(path, v, has))).sort().at(-1) : undefined);
const buildTools = sdk && latest(join(sdk, 'build-tools'), 'aapt2');
const platform = sdk && latest(join(sdk, 'platforms'), 'android.jar');
const hasJava = spawnSync('java', ['-version']).status === 0;

/** Every value aapt2 linked: `name|locale` → string, `name|locale|quantity` → plural item. */
function dumpValues(dump) {
  const values = new Map();
  let name;
  let locale;
  for (const line of dump.split('\n')) {
    let m = /^\s+resource 0x[0-9a-f]+ (?:string|plurals)\/(\S+)$/.exec(line);
    if (m) {
      name = m[1];
      continue;
    }
    m = /^\s+\((\w*)\) "(.*)"$/.exec(line);
    if (m) {
      values.set(`${name}|${m[1] || 'en'}`, m[2]);
      continue;
    }
    m = /^\s+\((\w*)\) \(plurals\)/.exec(line);
    if (m) {
      locale = m[1] || 'en';
      continue;
    }
    m = /^\s+(zero|one|two|few|many|other)="(.*)"$/.exec(line);
    if (m) values.set(`${name}|${locale}|${m[1]}`, m[2]);
  }
  return values;
}

test('aapt2 links both strings.xml files and reads back every format string', { skip: !(buildTools && platform) && 'no Android SDK' }, () => {
  for (const [folder, locale] of [
    ['values', 'en'],
    ['values-ar', 'ar'],
  ]) {
    mkdirSync(join(dir, 'res', folder), { recursive: true });
    writeFileSync(join(dir, 'res', folder, 'strings.xml'), stringsXml(messages, locale));
  }
  writeFileSync(join(dir, 'AndroidManifest.xml'), '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="app.octap.check" />');
  const aapt2 = join(sdk, 'build-tools', buildTools, 'aapt2');
  execFileSync(aapt2, ['compile', '--dir', join(dir, 'res'), '-o', join(dir, 'res.zip')]);
  execFileSync(aapt2, ['link', '-I', join(sdk, 'platforms', platform, 'android.jar'), '--manifest', join(dir, 'AndroidManifest.xml'), '-o', join(dir, 'out.apk'), join(dir, 'res.zip')]);
  const values = dumpValues(execFileSync(aapt2, ['dump', 'resources', join(dir, 'out.apk')], { encoding: 'utf8', maxBuffer: 64 << 20 }));

  let checked = 0;
  for (const message of messages) {
    const name = androidName(message.key);
    for (const [locale, text] of Object.entries(message.text)) {
      const forms = message.plural ? Object.entries(text) : [[undefined, text]];
      for (const [quantity, form] of forms) {
        const id = quantity ? `${name}|${locale}|${quantity}` : `${name}|${locale}`;
        assert.equal(values.get(id), toFormat(form, message.args, androidSpecifier), id);
        checked++;
      }
    }
  }
  assert.ok(checked > 2000, `checked ${checked}`);
});

test("Java's Formatter shows what the web vault shows", { skip: !hasJava && 'no JDK' }, () => {
  const byKey = new Map(messages.map((m) => [m.key, m]));
  const lines = [];
  for (const c of expectations(messages)) {
    const message = byKey.get(c.key);
    const text = message.text[c.locale];
    const count = c.args[message.args.findIndex((a) => a.name === 'count')];
    const form = message.plural ? (text[new Intl.PluralRules(c.locale).select(count)] ?? text.other) : text;
    // getString without arguments returns the text as is; only formatted strings go through Formatter.
    if (message.args.length === 0) continue;
    const format = toFormat(form, message.args, androidSpecifier);
    const args = c.args.map((v, i) => `${message.args[i].kind === 'int' ? 'i' : 's'}:${encodeURIComponent(String(v))}`);
    // Android doesn't isolate inserted text by itself (an app uses BidiFormatter), so compare without.
    const expected = c.expected.replaceAll(FSI, '').replaceAll(PDI, '');
    lines.push([c.key, encodeURIComponent(expected), encodeURIComponent(format), ...args].join('\t'));
  }
  writeFileSync(join(dir, 'cases.tsv'), `${lines.join('\n')}\n`);
  writeFileSync(
    join(dir, 'Check.java'),
    `import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class Check {
    static String d(String s) { return URLDecoder.decode(s, StandardCharsets.UTF_8); }
    public static void main(String[] a) throws Exception {
        int bad = 0, n = 0;
        for (String line : Files.readAllLines(Path.of(a[0]))) {
            if (line.isEmpty()) continue;
            String[] f = line.split("\\t");
            Object[] args = new Object[f.length - 3];
            for (int i = 3; i < f.length; i++) args[i - 3] = f[i].startsWith("i:") ? (Object) Long.parseLong(d(f[i].substring(2))) : d(f[i].substring(2));
            String shown = String.format(Locale.ROOT, d(f[2]), args);
            n++;
            if (!shown.equals(d(f[1]))) { bad++; System.out.println(f[0] + ": " + shown + " != " + d(f[1])); }
        }
        System.out.println(n + " formatted, " + bad + " differ");
        System.exit(bad == 0 ? 0 : 1);
    }
}
`,
  );
  const run = spawnSync('java', [join(dir, 'Check.java'), join(dir, 'cases.tsv')], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.match(run.stdout, /^\d{3,} formatted, 0 differ/m);
});
