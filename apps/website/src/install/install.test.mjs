// The install scripts the site serves: they download only from the configured GitHub repository,
// keep no placeholders, and the shell one parses.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { installScript } from './render.ts';

const read = (name) => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');

test('the scripts name the repository and the site, and nothing is left to fill in', () => {
  for (const name of ['install.sh', 'install.ps1']) {
    const script = installScript(read(name), 'https://github.com/octap-app/octapass', 'https://octap.app/');
    assert.ok(!script.includes('__OCTAPASS_'), `${name} has a placeholder left`);
    assert.ok(script.includes("'octap-app/octapass'") || script.includes('-octap-app/octapass}'), name);
    assert.ok(script.includes('https://octap.app/install.'), name);
    assert.ok(!script.includes('http://'), `${name} downloads over plain HTTP`);
  }
});

test('only a GitHub repository is accepted', () => {
  for (const url of ['https://example.com/a/b', 'http://github.com/a/b', 'https://github.com/a', 'https://github.com/a/b/c']) {
    assert.throws(() => installScript('x', url, 'https://octap.app'), url);
  }
  assert.ok(installScript('__OCTAPASS_REPO__', 'https://github.com/a/b.git', 's') === 'a/b');
});

test('the shell script parses', () => {
  const script = installScript(read('install.sh'), 'https://github.com/a/b', 'https://octap.app');
  execFileSync('sh', ['-n'], { input: script });
});
