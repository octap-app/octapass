// Every language has the same keys, the same list lengths and the same HTML tags as English.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const load = (name) => JSON.parse(readFileSync(new URL(`./${name}.json`, import.meta.url), 'utf8'));
const en = load('en');
const tags = (text) => (text.match(/<[^>]+>/g) ?? []).sort();

function compare(a, b, path) {
  if (Array.isArray(a)) {
    assert.ok(Array.isArray(b), `${path} should be a list`);
    assert.equal(b.length, a.length, `${path} has a different length`);
    a.forEach((item, i) => compare(item, b[i], `${path}[${i}]`));
  } else if (a && typeof a === 'object') {
    assert.deepEqual(Object.keys(b).sort(), Object.keys(a).sort(), `${path} has different keys`);
    for (const key of Object.keys(a)) compare(a[key], b[key], `${path}.${key}`);
  } else {
    assert.equal(typeof b, typeof a, `${path} has a different type`);
    assert.ok(String(b).trim(), `${path} is empty`);
    assert.deepEqual(tags(String(b)), tags(String(a)), `${path} has different tags`);
  }
}

test('Arabic has the same shape as English', () => compare(en, load('ar'), 'ar'));

test('locale-independent values match', () => {
  const ar = load('ar');
  en.platforms.items.forEach((item, i) => {
    assert.equal(ar.platforms.items[i].id, item.id);
    assert.equal(ar.platforms.items[i].icon, item.icon);
  });
  en.roadmap.phases.forEach((phase, i) => assert.equal(ar.roadmap.phases[i].step, phase.step));
  en.everything.items.forEach((item, i) => {
    assert.equal(ar.everything.items[i].icon, item.icon);
    assert.equal(ar.everything.items[i].group, item.group);
  });
  en.everything.groups.forEach((group, i) => assert.equal(ar.everything.groups[i].id, group.id));
});

test('placeholders survive translation', () => {
  const ar = load('ar');
  for (const key of ['getLabel', 'sourceLabel']) {
    assert.ok(en.platforms[key].includes('{name}'), `en.platforms.${key} needs {name}`);
    assert.ok(ar.platforms[key].includes('{name}'), `ar.platforms.${key} needs {name}`);
  }
});
