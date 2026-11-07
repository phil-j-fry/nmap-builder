'use strict';
// R27: tools/extract-inventory.py builds the inventory from Nmap source.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path'), fs = require('node:fs');
const ROOT = path.join(__dirname, '..'), TOOL = path.join(ROOT, 'tools', 'extract-inventory.py');
const run = (...args) => spawnSync('python3', ['-I', TOOL, ...args], { encoding: 'utf8', cwd: ROOT });

test('R27 extract-inventory', async t => {
  await t.test('tool exists', () => assert.ok(fs.existsSync(TOOL)));
  await t.test('excerpt fixture', () => {
    const r = run(path.join(__dirname, 'fixtures', 'nmap-cc-excerpt.cc'));
    assert.equal(r.status, 0, r.stderr);
    const out = r.stdout;
    assert.match(out, /^nmap\.cc SHA256: [0-9a-f]{64}$/m);
    assert.match(out, /^Short options: 46b:d::s::V$/m);
    assert.match(out, /4 literal long-option registrations; 1 non-literal skipped\./);
    assert.deepEqual(out.split('Source registration → argument type\n')[1].trim().split('\n'), ['version no', 'datadir required', 'debug optional', 'script required']);
  });
  await t.test('missing file fails loudly', () => { const r = run('/nonexistent/nmap.cc'); assert.notEqual(r.status, 0); assert.match(r.stderr, /no such file/); });
  await t.test('--check against real source (NMAP_SRC)', { skip: !process.env.NMAP_SRC && 'set NMAP_SRC to nmap.cc or nmap-7.993.tar.bz2' }, () => {
    const r = run(process.env.NMAP_SRC, '--check');
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /OK: catalog\.txt and coverage\.txt match/);
  });
});
