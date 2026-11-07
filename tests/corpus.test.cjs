'use strict';
// R26: data-driven corpus. Add examples to tests/fixtures/*.json; no code changes needed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { loadCore, plain, codes, rules } = require('./helpers.cjs');
const { ctx, parse } = loadCore();

const KINDS = {
  valid: { errors: [], warnings: [] },
  placeholder: { errors: [], notesInclude: ['placeholder'] },
  fragment: { errors: ['no-target'] },
  broken: { minErrors: 1 },
  pipeline: { errors: [], warningsInclude: ['shell-operator'], hasShell: true },
};
const EXPECT_KEYS = new Set(['errors', 'warnings', 'notes', 'errorsInclude', 'warningsInclude', 'notesInclude', 'flags', 'targets', 'placeholders', 'scope', 'rules', 'minErrors', 'hasShell', 'shellText', 'files']);
const EXAMPLE_KEYS = new Set(['src', 'cmd', 'kind', 'category', 'title', 'expect', 'comment']);
const sorted = a => [...a].sort();

const dir = path.join(__dirname, 'fixtures');
const corpora = fs.readdirSync(dir).filter(f => f.endsWith('.json')).map(f => [f, JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'))]).filter(([, d]) => Array.isArray(d.examples));

test('R26 corpus fixtures exist', () => assert.ok(corpora.length > 0 && corpora.some(([f]) => f === 'ccsf-examples.json')));

for (const [file, data] of corpora) {
  test(`R26 ${file}`, async t => {
    const seen = new Set();
    for (const ex of data.examples) {
      await t.test(`${ex.src} [${ex.kind}]`, () => {
        for (const k of Object.keys(ex)) assert.ok(EXAMPLE_KEYS.has(k), `unknown example key "${k}"`);
        assert.ok(KINDS[ex.kind], `unknown kind "${ex.kind}"`);
        assert.equal(typeof ex.cmd, 'string');
        assert.ok(!seen.has(ex.cmd), 'duplicate cmd in corpus'); seen.add(ex.cmd);
        for (const k of Object.keys(ex.expect || {})) assert.ok(EXPECT_KEYS.has(k), `unknown expect key "${k}"`);
        if (ex.title !== undefined) assert.ok(typeof ex.title === 'string' && ex.title.trim() && ex.title.length <= 60, 'title must be 1-60 chars');
        if (['valid', 'placeholder'].includes(ex.kind)) assert.ok(ex.title, 'starter-set kinds (valid, placeholder) need a title (Phil, 2026-11-07)');
        const e = { ...KINDS[ex.kind], ...(ex.expect || {}) };
        const p = parse(ex.cmd), info = () => `\n  cmd: ${ex.cmd}\n  issues: ${JSON.stringify(plain(p.issues))}\n  warnings: ${JSON.stringify(plain(p.warnings))}\n  notes: ${JSON.stringify(plain(p.notes))}`;
        const E = codes(p, 'error'), W = codes(p, 'warn'), N = codes(p, 'note');
        if (e.errors) assert.deepEqual(sorted(E), sorted(e.errors), 'errors' + info());
        if (e.warnings) assert.deepEqual(sorted(W), sorted(e.warnings), 'warnings' + info());
        if (e.notes) assert.deepEqual(sorted(N), sorted(e.notes), 'notes' + info());
        for (const c of e.errorsInclude || []) assert.ok(E.includes(c), `missing error ${c}` + info());
        for (const c of e.warningsInclude || []) assert.ok(W.includes(c), `missing warning ${c}` + info());
        for (const c of e.notesInclude || []) assert.ok(N.includes(c), `missing note ${c}` + info());
        if (e.minErrors) assert.ok(E.length >= e.minErrors, 'expected errors' + info());
        if (e.rules) assert.deepEqual(rules(p), sorted(e.rules), 'rules' + info());
        if (e.flags) assert.deepEqual(plain(p.flags).map(f => f.key), e.flags, 'flags' + info());
        if (e.targets) assert.deepEqual(plain(p.targets), e.targets, 'targets' + info());
        if (e.placeholders) assert.deepEqual(plain(p.placeholders), e.placeholders, 'placeholders' + info());
        const items = plain(p.items) || [];
        if (e.hasShell) assert.ok(items.some(i => i.kind === 'shell'), 'expected a shell item' + info());
        if (e.shellText !== undefined) assert.equal(items.find(i => i.kind === 'shell')?.text, e.shellText);
        if (e.scope) assert.match(ctx.scope(p, new Map(Object.entries(e.files || {}))), new RegExp(e.scope));
      });
    }
  });
}
