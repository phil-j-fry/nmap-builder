'use strict';
// R16 quoting/round trips, R18 raw-text-preserving removal (pure core functions).
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadCore, plain, errors, warns } = require('./helpers.cjs');
const { ctx, map, parse } = loadCore();

test('R16 quoteArg', async t => {
  const same = ['80', 'a.b/c:d,e=f+g@h%i-j_k', '-', '-100', 'T:80,U:161'];
  for (const v of same) await t.test('bare ' + v, () => assert.equal(ctx.quoteArg(v), v));
  const cases = [['', "''"], ['a b', "'a b'"], ["it's", "'it'\\''s'"], ['$R/x', "'$R/x'"], ['*', "'*'"], ['a;b', "'a;b'"], ['<host>', "'<host>'"], ['#x', "'#x'"]];
  for (const [v, want] of cases) await t.test('quoted ' + JSON.stringify(v), () => assert.equal(ctx.quoteArg(v), want));
});

const VALUES = ['80', 'my report.xml', "it's", 'a;b', '$R/x', '`id`', '$(id)', '-100', '-', '"q"', 'a\\b', 'tab\there', 'ünïcødé', '<host>', '*', '#x', 'a b  c', 'x|y', 'a&&b', '>out', 'new\nline'];

test('R16 buildOption round trips every catalog form', async t => {
  let checked = 0;
  for (const d of map.values()) {
    if (d.arg === 'none') {
      await t.test(d.key + ' (none)', () => assert.equal(ctx.buildOption(d.key, '', map), d.key));
      continue;
    }
    for (const v of VALUES) {
      // Skips: values that change which option is parsed. An attached value on -v/-d/-f style letters
      // (e.g. "-v" + "v" is "-vv", a different catalog form) is ambiguous by design; the test documents it.
      if (['-v', '-d'].includes(d.key) && !/^\d+$/.test(v)) continue;
      if (['-oH', '-O1'].includes(d.key)) continue; // rejected-by-release forms
      const frag = ctx.buildOption(d.key, v, map);
      const s = 'nmap ' + frag + ' 10.0.0.1', p = parse(s);
      const f = plain(p.flags)[0];
      const bad = errors(p).filter(c => ['missing-value', 'empty-value', 'unexpected-value', 'unknown-flag', 'unclosed-quote'].includes(c));
      const shell = warns(p).filter(c => c.startsWith('shell-') || c === 'smart-quote');
      if (!f || f.key !== d.key || f.val !== v || bad.length || shell.length)
        assert.fail(`${d.key} ${JSON.stringify(v)} → ${s}\n  got key=${f?.key} val=${JSON.stringify(f?.val)} errors=${bad} warnings=${shell}`);
      checked++;
    }
  }
  assert.ok(checked > 500, 'round-tripped ' + checked);
});

test('R16 attached optional values', async t => {
  await t.test('empty optional', () => assert.equal(ctx.buildOption('-PS', '', map), '-PS'));
  await t.test('short attached', () => assert.equal(ctx.buildOption('-PS', '22,443', map), '-PS22,443'));
  await t.test('long attached uses =', () => assert.equal(ctx.buildOption('--debug', '3', map), '--debug=3'));
  await t.test('required separate', () => assert.equal(ctx.buildOption('-p', '80,443', map), '-p 80,443'));
  await t.test('required dash value attaches', () => { assert.equal(ctx.buildOption('-p', '-100', map), '-p-100'); assert.equal(ctx.buildOption('--exclude-ports', '-100', map), '--exclude-ports=-100'); });
  await t.test('lone dash stays separate', () => assert.equal(ctx.buildOption('-oN', '-', map), '-oN -'));
});

const REMOVALS = [
  ['nmap -sS -oX "my report.xml" 10.0.0.1', i => i.key === '-sS', 'nmap -oX "my report.xml" 10.0.0.1'],
  ['nmap -sS -oX "my report.xml" 10.0.0.1', i => i.key === '-oX', 'nmap -sS 10.0.0.1'],
  ['nmap -sS -oX "my report.xml" 10.0.0.1', i => i.kind === 'target', 'nmap -sS -oX "my report.xml"'],
  ['nmap  -sS   10.0.0.1', i => i.key === '-sS', 'nmap   10.0.0.1'],
  ['nmap -sSU 10.0.0.1', i => i.key === '-sS', 'nmap -sU 10.0.0.1'],
  ['nmap -sSU 10.0.0.1', i => i.key === '-sU', 'nmap -sS 10.0.0.1'],
  ['nmap -sSUV 10.0.0.1', i => i.key === '-sU', 'nmap -sSV 10.0.0.1'],
  ['nmap -sSUV 10.0.0.1', i => i.key === '-sV', 'nmap -sSU 10.0.0.1'],
  ['nmap --script=default,safe -p80 x', i => i.key === '--script', 'nmap -p80 x'],
  ['nmap -sL -iL s.txt | grep -F x', i => i.kind === 'shell', 'nmap -sL -iL s.txt'],
  ['nmap -sS -- -weird', i => i.kind === 'target', 'nmap -sS --'],
  ['nmap --made-up 10.0.0.1', i => i.kind === 'unknown', 'nmap 10.0.0.1'],
  ['nmap\t-n\t10.0.0.1', i => i.key === '-n', 'nmap\t10.0.0.1'],
  ["nmap -oN 'a b' -sV <host>", i => i.kind === 'target', "nmap -oN 'a b' -sV"],
  ['nmap 10.0.0.1 #trailing note', i => i.kind === 'shell', 'nmap 10.0.0.1'],
  ['nmap -oN x > log 10.0.0.1', i => i.kind === 'shell', 'nmap -oN x 10.0.0.1'],
  ['nmap 10.0.0.1 2>&1 | tee x', i => i.kind === 'shell' && i.stop, 'nmap 10.0.0.1 2>&1'],
];

test('R18 removeItem', async t => {
  for (const [input, pick, want] of REMOVALS) await t.test(`${JSON.stringify(input)} → ${JSON.stringify(want)}`, () => {
    const p = parse(input), items = plain(p.items), idx = items.findIndex(pick);
    assert.ok(idx >= 0, 'item not found in ' + JSON.stringify(items.map(i => i.kind + ':' + (i.key || i.text))));
    const out = ctx.removeItem(input, p, idx);
    assert.equal(out, want);
    const removed = items[idx], after = plain(parse(out).items);
    if (removed.kind === 'flag') assert.ok(!after.some(i => i.key === removed.key), 'flag still present');
  });
  await t.test('does not mutate parse result', () => { const s = 'nmap -sS 10.0.0.1', p = parse(s), before = JSON.stringify(plain(p)); ctx.removeItem(s, p, 0); assert.equal(JSON.stringify(plain(p)), before); });
});
