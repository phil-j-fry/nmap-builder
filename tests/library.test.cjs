'use strict';
// Phase 2 pure functions: R29 (core.js), R31–R33, R35 (library.js).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const { loadCore, plain, errors, diags, read, ROOT } = require('./helpers.cjs');
const { parse } = loadCore();

const FIXTURE = read('tests/fixtures/ccsf-examples.json');
function loadLibrary() {
  const ctx = {};
  vm.createContext(ctx);
  if (!fs.existsSync(path.join(ROOT, 'library.js'))) return null;
  vm.runInContext('const STARTER_DATA=' + FIXTURE + ';\n' + read('core.js') + '\n' + read('library.js'), ctx, { filename: 'library.js' });
  for (const n of ['LIBRARY_KEY', 'LIBRARY_FORMAT', 'LIBRARY_VERSION', 'LIBRARY_LIMITS', 'STARTER_DATA'])
    try { ctx[n] = vm.runInContext(`typeof ${n}!=='undefined'?${n}:undefined`, ctx); } catch { /* absent */ }
  return ctx;
}
const L = loadLibrary();
const need = t => { assert.ok(L, 'library.js does not exist yet (R30)'); return L; };
const NOW = Date.UTC(2026, 10, 7, 12, 0, 0);
const memStorage = (init = {}) => { const m = new Map(Object.entries(init)); return { m, getItem: k => m.has(k) ? m.get(k) : null, setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) }; };
const entry = (name, cmd, tags = [], extra = {}) => { const r = need().makeEntry({ name, cmd, tags, source: null }, { now: NOW, id: extra.id }); assert.ok(r.ok, JSON.stringify(plain(r))); return plain(r.entry); };

test('R29 unitless time above Nmap limit', async t => {
  for (const s of ['--max-rtt-timeout 100', '--min-rtt-timeout 50', '--initial-rtt-timeout 60', '--scan-delay 500', '--max-scan-delay 100', '--host-timeout 10000'])
    await t.test('bad ' + s, () => { const p = parse(`nmap ${s} 10.0.0.1`), bv = diags(p, 'error').filter(d => d.code === 'bad-value'); assert.equal(bv.length, 1, JSON.stringify(plain(p.issues))); assert.match(bv[0].msg, /ms/); });
  for (const s of ['--max-rtt-timeout 49', '--max-rtt-timeout 100ms', '--max-rtt-timeout 100s', '--scan-delay 99', '--host-timeout 9999', '--host-timeout 30m', '--script-timeout 100000', '--stats-every 100000'])
    await t.test('ok ' + s, () => assert.ok(!errors(parse(`nmap ${s} 10.0.0.1`)).includes('bad-value'), s));
});

test('R31 constants and tags', async t => {
  await t.test('constants', () => { const l = need(); assert.equal(l.LIBRARY_KEY, 'nmap-builder.library.v1'); assert.equal(l.LIBRARY_FORMAT, 'nmap-builder-library'); assert.equal(l.LIBRARY_VERSION, 1); assert.deepEqual(plain(l.LIBRARY_LIMITS), { name: 100, cmd: 8000, tag: 32, tags: 10, entries: 1000, importBytes: 32000000 }); });
  await t.test('normalizeTags string', () => assert.deepEqual(plain(need().normalizeTags('AD, ot ics, OT-ICS, , x!')), ['ad', 'ot-ics']));
  await t.test('normalizeTags array and limits', () => {
    const l = need();
    assert.deepEqual(plain(l.normalizeTags(['Recon', 'recon', ' web  app '])), ['recon', 'web-app']);
    assert.equal(plain(l.normalizeTags(Array.from({ length: 15 }, (_, i) => 't' + i))).length, 10);
    assert.deepEqual(plain(l.normalizeTags(['a'.repeat(32), 'b'.repeat(33), '-x', '.y', '_z'])), ['a'.repeat(32)]);
    assert.deepEqual(plain(l.normalizeTags('')), []); assert.deepEqual(plain(l.normalizeTags(undefined)), []);
  });
});

test('R31 makeEntry / updateEntry', async t => {
  await t.test('valid entry', () => {
    const e = entry('  OT sweep  ', 'nmap -sT 10.0.0.1  ', 'ot, ICS');
    assert.equal(e.name, 'OT sweep'); assert.equal(e.cmd, 'nmap -sT 10.0.0.1  ', 'cmd kept exactly'); assert.deepEqual(e.tags, ['ot', 'ics']);
    assert.equal(e.created, new Date(NOW).toISOString()); assert.equal(e.updated, e.created); assert.equal(e.source, null); assert.equal(typeof e.id, 'string'); assert.ok(e.id);
    assert.deepEqual(Object.keys(e).sort(), ['cmd', 'created', 'id', 'name', 'source', 'tags', 'updated']);
  });
  await t.test('given id is kept', () => assert.equal(entry('a', 'nmap x', [], { id: 'fixed' }).id, 'fixed'));
  await t.test('invalid name', () => { for (const name of ['', '   ', 'x'.repeat(101), null, 5]) { const r = plain(need().makeEntry({ name, cmd: 'nmap x' }, { now: NOW })); assert.equal(r.ok, false); assert.equal(r.error, 'name'); } });
  await t.test('invalid cmd', () => { for (const cmd of ['', '  \n ', 'x'.repeat(8001), null, {}]) { const r = plain(need().makeEntry({ name: 'a', cmd }, { now: NOW })); assert.equal(r.ok, false); assert.equal(r.error, 'cmd'); } });
  await t.test('100 / 8000 limits inclusive', () => assert.ok(need().makeEntry({ name: 'n'.repeat(100), cmd: 'x'.repeat(8000) }, { now: NOW }).ok));
  await t.test('unique generated ids', () => { const ids = new Set(); for (let i = 0; i < 1000; i++) ids.add(need().makeEntry({ name: 'a', cmd: 'nmap x' }, { now: NOW }).entry.id); assert.equal(ids.size, 1000); });
  await t.test('updateEntry', () => {
    const e = entry('a', 'nmap x', ['t']), before = JSON.stringify(e);
    const r = plain(need().updateEntry(e, { cmd: 'nmap y', tags: 'u' }, NOW + 1000));
    assert.equal(r.ok, true); assert.equal(r.entry.id, e.id); assert.equal(r.entry.created, e.created); assert.equal(r.entry.updated, new Date(NOW + 1000).toISOString());
    assert.equal(r.entry.cmd, 'nmap y'); assert.deepEqual(r.entry.tags, ['u']); assert.equal(r.entry.name, 'a');
    assert.equal(JSON.stringify(e), before, 'input not mutated');
    assert.equal(plain(need().updateEntry(e, { name: '' }, NOW)).ok, false);
  });
});

test('R31 searchLibrary / allTags', async t => {
  const l = need();
  const mk = (name, cmd, tags, dt) => plain(l.makeEntry({ name, cmd, tags }, { now: NOW + dt, id: name })).entry;
  const es = [mk('OT find', 'nmap -sT -p 502 <host>', 'ot,ics', 1), mk('Web scan', 'nmap -p 80,443 <host>', 'web', 3), mk('AD smb', 'nmap --script smb-protocols -p 445 <host>', 'ad', 2)];
  await t.test('order newest first', () => assert.deepEqual(plain(l.searchLibrary(es, {})).map(e => e.name), ['Web scan', 'AD smb', 'OT find']));
  await t.test('terms AND, case-insensitive, across fields', () => { assert.deepEqual(plain(l.searchLibrary(es, { query: 'NMAP 445' })).map(e => e.name), ['AD smb']); assert.deepEqual(plain(l.searchLibrary(es, { query: 'ics' })).map(e => e.name), ['OT find']); assert.deepEqual(plain(l.searchLibrary(es, { query: 'scan web' })).map(e => e.name), ['Web scan']); });
  await t.test('tag filter', () => assert.deepEqual(plain(l.searchLibrary(es, { tag: 'ad' })).map(e => e.name), ['AD smb']));
  await t.test('tag filter is exact', () => assert.deepEqual(plain(l.searchLibrary(es, { tag: 'i' })), []));
  await t.test('allTags', () => assert.deepEqual(plain(l.allTags(es)), ['ad', 'ics', 'ot', 'web']));
  await t.test('ties sorted by name', () => { const a = mk('b', 'nmap x', '', 0), b = mk('a', 'nmap y', '', 0); assert.deepEqual(plain(l.searchLibrary([a, b], {})).map(e => e.name), ['a', 'b']); });
});

test('R32 readLibrary / writeLibrary', async t => {
  const l = need();
  await t.test('round trip', () => { const st = memStorage(), es = [entry('a', 'nmap x', 'q')]; assert.equal(l.writeLibrary(st, es), true); const r = plain(l.readLibrary(st)); assert.equal(r.status, 'ok'); assert.deepEqual(r.entries, es); assert.equal(r.dropped, 0); assert.equal(JSON.parse(st.m.get(l.LIBRARY_KEY)).format, 'nmap-builder-library'); });
  await t.test('empty', () => assert.equal(plain(l.readLibrary(memStorage())).status, 'empty'));
  await t.test('unavailable: null', () => { const r = plain(l.readLibrary(null)); assert.equal(r.status, 'unavailable'); assert.deepEqual(r.entries, []); });
  await t.test('unavailable: throws', () => { const st = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('SecurityError'); } }; assert.equal(plain(l.readLibrary(st)).status, 'unavailable'); assert.equal(l.writeLibrary(st, []), false); });
  await t.test('quota → false, no throw', () => { const st = { getItem: () => null, setItem() { const e = new Error('q'); e.name = 'QuotaExceededError'; throw e; } }; assert.equal(l.writeLibrary(st, [entry('a', 'nmap x')]), false); });
  for (const raw of ['{not json', '[]', '{"format":"other","version":1,"entries":[]}', '{"format":"nmap-builder-library","version":1,"entries":"x"}', 'null'])
    await t.test('corrupt ' + raw, () => { const st = memStorage({ [l.LIBRARY_KEY]: raw }); const r = plain(l.readLibrary(st)); assert.equal(r.status, 'corrupt'); assert.deepEqual(r.entries, []); assert.equal(st.m.get(l.LIBRARY_KEY + '.backup'), raw, 'backup of raw value'); assert.equal(st.m.get(l.LIBRARY_KEY), raw, 'original not overwritten by read'); });
  await t.test('invalid entries dropped', () => { const good = entry('a', 'nmap x'); const st = memStorage({ [l.LIBRARY_KEY]: JSON.stringify({ format: 'nmap-builder-library', version: 1, entries: [good, { name: '', cmd: 'x' }, 7] }) }); const r = plain(l.readLibrary(st)); assert.equal(r.status, 'ok'); assert.equal(r.entries.length, 1); assert.equal(r.dropped, 2); });
});

test('R33 export / parse / merge', async t => {
  const l = need();
  await t.test('export shape', () => {
    const es = [entry('a', 'nmap x', 'q')], txt = l.exportLibrary(es, NOW), doc = JSON.parse(txt);
    assert.deepEqual(Object.keys(doc), ['format', 'version', 'exported', 'entries']);
    assert.equal(doc.format, 'nmap-builder-library'); assert.equal(doc.version, 1); assert.equal(doc.exported, new Date(NOW).toISOString());
    assert.deepEqual(doc.entries, es); assert.match(txt, /\n  "format"/, '2-space indent');
  });
  await t.test('export → parse round trip', () => { const es = [entry('a', 'nmap -oX "r.xml" <host>', 'x,y'), entry('b', "nmap '$(id)'")]; const r = plain(l.parseLibraryFile(l.exportLibrary(es, NOW))); assert.equal(r.ok, true); assert.deepEqual(r.entries, es); assert.equal(r.dropped, 0); });
  const bad = {
    'too big': 'x'.repeat(32000001), 'not json': '{', 'array': '[]', 'wrong format': '{"format":"x","version":1,"entries":[]}',
    'version 0': '{"format":"nmap-builder-library","version":0,"entries":[]}', 'version "1"': '{"format":"nmap-builder-library","version":"1","entries":[]}',
    'entries object': '{"format":"nmap-builder-library","version":1,"entries":{}}',
    'too many': JSON.stringify({ format: 'nmap-builder-library', version: 1, entries: Array.from({ length: 1001 }, (_, i) => ({ id: 'e' + i, name: 'n', cmd: 'nmap x', tags: [] })) }),
  };
  for (const [k, txt] of Object.entries(bad)) await t.test('reject ' + k, () => { const r = plain(l.parseLibraryFile(txt)); assert.equal(r.ok, false); assert.ok(r.errors.length && typeof r.errors[0] === 'string' && r.errors[0].length > 5); });
  await t.test('newer version message', () => assert.match(plain(l.parseLibraryFile('{"format":"nmap-builder-library","version":2,"entries":[]}')).errors[0], /newer/i));
  await t.test('unknown fields ignored, bad entries dropped, dates repaired', () => {
    const r = plain(l.parseLibraryFile(JSON.stringify({ format: 'nmap-builder-library', version: 1, extra: 1, entries: [{ id: 'a', name: 'ok', cmd: 'nmap x', tags: 'A,b', created: 'yesterday', updated: '2026-01-02T03:04:05.000Z', evil: '<script>' }, { name: 'no cmd' }, null, 'str'] })));
    assert.equal(r.ok, true); assert.equal(r.entries.length, 1); assert.equal(r.dropped, 3);
    const e = r.entries[0]; assert.deepEqual(Object.keys(e).sort(), ['cmd', 'created', 'id', 'name', 'source', 'tags', 'updated']); assert.deepEqual(e.tags, ['a', 'b']);
    assert.equal(e.updated, '2026-01-02T03:04:05.000Z'); assert.ok(!Number.isNaN(Date.parse(e.created)));
  });
  await t.test('prototype pollution', () => {
    const txt = '{"format":"nmap-builder-library","version":1,"__proto__":{"polluted":1},"entries":[{"id":"a","name":"n","cmd":"nmap x","tags":[],"__proto__":{"polluted":2},"constructor":{"prototype":{"polluted":3}}}]}';
    const r = plain(l.parseLibraryFile(txt)); assert.equal(r.ok, true); assert.equal(({}).polluted, undefined); assert.equal(vm.runInContext('({}).polluted', l), undefined); assert.equal(r.entries[0].polluted, undefined);
  });
  await t.test('content is data, never executed', () => { const r = plain(l.parseLibraryFile(JSON.stringify({ format: 'nmap-builder-library', version: 1, entries: [{ id: 'x', name: '<img src=x onerror=alert(1)>', cmd: 'nmap $(rm -rf /)', tags: [] }] }))); assert.equal(r.entries[0].cmd, 'nmap $(rm -rf /)'); assert.equal(r.entries[0].name, '<img src=x onerror=alert(1)>'); });
  await t.test('merge skips duplicates, regenerates colliding ids, never modifies existing', () => {
    const a = entry('a', 'nmap x', 'q,r', { id: 'id1' }), b = entry('b', 'nmap y', '', { id: 'id2' }), before = JSON.stringify([a, b]);
    const dup = { ...a, id: 'other', tags: ['r', 'q'] }, collide = entry('c', 'nmap z', '', { id: 'id1' }), fresh = entry('d', 'nmap w', '', { id: 'id9' });
    const r = plain(l.mergeLibrary([a, b], [dup, collide, fresh], NOW));
    assert.equal(r.added, 2); assert.equal(r.skipped, 1); assert.equal(r.entries.length, 4);
    assert.equal(JSON.stringify(r.entries.slice(0, 2)), before);
    const ids = r.entries.map(e => e.id); assert.equal(new Set(ids).size, 4); assert.ok(ids.includes('id9'));
    assert.equal(r.entries.find(e => e.name === 'c').cmd, 'nmap z');
  });
});

test('R35 starterEntries', async t => {
  const l = need(), data = JSON.parse(FIXTURE), st = plain(l.starterEntries(l.STARTER_DATA));
  const want = data.examples.filter(e => ['valid', 'placeholder'].includes(e.kind));
  await t.test('count and kinds', () => { assert.equal(st.length, want.length); assert.equal(st.length, 63); assert.ok(st.every(e => ['valid', 'placeholder'].includes(e.kind))); });
  await t.test('excludes broken, fragment, pipeline', () => { for (const e of data.examples.filter(e => !['valid', 'placeholder'].includes(e.kind))) assert.ok(!st.some(s => s.src === e.src), e.src); });
  await t.test('fields', () => {
    const s = st.find(e => e.src === 'archive/AD/README.md:27');
    assert.deepEqual(s, { id: 'ccsf:archive/AD/README.md:27', name: 'archive/AD/README.md:27', cmd: 'nmap --script smb2-security-mode -p 445 <TARGET_IP>', src: 'archive/AD/README.md:27', category: 'Active Directory', kind: 'placeholder', tags: ['ccsf', 'active-directory'], source: 'ccsf:archive/AD/README.md:27', readOnly: true });
  });
  await t.test('unique ids, every src kept', () => { assert.equal(new Set(st.map(e => e.id)).size, st.length); assert.ok(st.every(e => /:\d+$/.test(e.src))); });
  await t.test('title and default category', () => { const s = plain(l.starterEntries({ examples: [{ src: 'x.md:1', cmd: 'nmap 10.0.0.1', kind: 'valid', title: 'Hello' }] })); assert.equal(s[0].name, 'Hello'); assert.equal(s[0].category, 'Other'); assert.deepEqual(s[0].tags, ['ccsf', 'other']); });
  await t.test('origin', () => assert.deepEqual(plain(l.starterOrigin(l.STARTER_DATA)), { repo: data.source, commit: data.commit }));
});

// ---- Phase 2 review round 1 (Gadfly) ----
test('R29a decimal unitless values', async t => {
  for (const s of ['--max-rtt-timeout 60.5', '--scan-delay 100.0', '--host-timeout 10000.5']) await t.test('bad ' + s, () => assert.equal(diags(parse(`nmap ${s} 10.0.0.1`), 'error').filter(d => d.code === 'bad-value').length, 1));
  for (const s of ['--max-rtt-timeout 49.9', '--scan-delay .5', '--max-rtt-timeout 60.5ms']) await t.test('ok ' + s, () => assert.ok(!errors(parse(`nmap ${s} 10.0.0.1`)).includes('bad-value')));
});

test('R32a backups are never overwritten', async t => {
  const l = need(), K = () => l.LIBRARY_KEY;
  await t.test('first corruption uses .backup and reports the key', () => { const st = memStorage({ [K()]: 'junk1' }); const r = plain(l.readLibrary(st)); assert.equal(r.status, 'corrupt'); assert.equal(r.backupKey, K() + '.backup'); assert.equal(st.m.get(r.backupKey), 'junk1'); });
  await t.test('an existing different backup is kept; a new key is used', () => {
    const st = memStorage({ [K()]: 'junk2', [K() + '.backup']: 'older real data' });
    const r = plain(l.readLibrary(st));
    assert.equal(st.m.get(K() + '.backup'), 'older real data', 'older backup must survive');
    assert.ok(r.backupKey && r.backupKey !== K() + '.backup' && r.backupKey.startsWith(K() + '.backup'), String(r.backupKey));
    assert.equal(st.m.get(r.backupKey), 'junk2');
  });
  await t.test('same raw already backed up: reuse, no new key', () => { const st = memStorage({ [K()]: 'junk3', [K() + '.backup']: 'junk3' }); const r = plain(l.readLibrary(st)); assert.equal(r.backupKey, K() + '.backup'); assert.equal([...st.m.keys()].filter(k => k.startsWith(K() + '.backup')).length, 1); });
  await t.test('backup write fails → backupKey null', () => { const m = new Map([[K(), 'junk4']]); const st = { getItem: k => m.has(k) ? m.get(k) : null, setItem() { throw new Error('quota'); } }; assert.equal(plain(l.readLibrary(st)).backupKey, null); });
  await t.test('ok/empty/unavailable report backupKey null', () => { assert.equal(plain(l.readLibrary(memStorage())).backupKey, null); assert.equal(plain(l.readLibrary(null)).backupKey, null); });
});

test('R31a ids are unique and bounded; source is bounded', async t => {
  const l = need(), doc = entries => JSON.stringify({ format: 'nmap-builder-library', version: 1, entries });
  const base = { name: 'n', cmd: 'nmap x', tags: [] };
  await t.test('duplicate ids in a stored library are made unique', () => {
    const st = memStorage({ [l.LIBRARY_KEY]: doc([{ ...base, id: 'same', name: 'a' }, { ...base, id: 'same', name: 'b' }]) });
    const r = plain(l.readLibrary(st)); assert.equal(r.entries.length, 2); assert.equal(new Set(r.entries.map(e => e.id)).size, 2); assert.equal(r.entries[0].id, 'same', 'first keeps its id');
  });
  await t.test('duplicate ids in an import file are made unique', () => { const r = plain(l.parseLibraryFile(doc([{ ...base, id: 'd', name: 'a' }, { ...base, id: 'd', name: 'b' }]))); assert.equal(new Set(r.entries.map(e => e.id)).size, 2); });
  await t.test('oversized or odd ids are regenerated', () => {
    const r = plain(l.parseLibraryFile(doc([{ ...base, id: 'x'.repeat(65) }, { ...base, id: 'has space', name: 'b' }, { ...base, id: 'ok:id_1.2-3', name: 'c' }])));
    assert.ok(r.entries[0].id.length <= 64); assert.notEqual(r.entries[0].id, 'x'.repeat(65)); assert.notEqual(r.entries[1].id, 'has space'); assert.equal(r.entries[2].id, 'ok:id_1.2-3');
    for (const e of r.entries) assert.match(e.id, /^[A-Za-z0-9:._-]{1,64}$/);
  });
  await t.test('oversized source becomes null', () => { const r = plain(l.parseLibraryFile(doc([{ ...base, source: 's'.repeat(301) }, { ...base, name: 'b', source: 'ccsf:a.md:1' }]))); assert.equal(r.entries[0].source, null); assert.equal(r.entries[1].source, 'ccsf:a.md:1'); });
});

// ---- Plumb Phase 2 review ----
test('Plumb P2-1: entry cap on every write path; own storage always readable', async t => {
  const l = need();
  const many = (n, p) => Array.from({ length: n }, (_, i) => entry(p + i, 'nmap 10.0.' + (i % 250) + '.' + p.length, '', { id: p + i }));
  await t.test('merge stops at the cap and reports rejected', () => {
    const r = plain(l.mergeLibrary(many(600, 'a'), many(401, 'b'), NOW));
    assert.equal(r.entries.length, 1000); assert.equal(r.added, 400); assert.equal(r.rejected, 1); assert.equal(r.skipped, 0);
  });
  await t.test('merge reports rejected 0 normally', () => assert.equal(plain(l.mergeLibrary([], many(3, 'c'), NOW)).rejected, 0));
  await t.test('write then read 1000 is ok', () => { const st = memStorage(); const es = plain(l.mergeLibrary(many(600, 'a'), many(401, 'b'), NOW)).entries; assert.equal(l.writeLibrary(st, es), true); const r = plain(l.readLibrary(st)); assert.equal(r.status, 'ok'); assert.equal(r.entries.length, 1000); });
  await t.test('a stored library over the cap (older build) is still read, not corrupt', () => {
    const st = memStorage({ [l.LIBRARY_KEY]: JSON.stringify({ format: 'nmap-builder-library', version: 1, entries: many(1200, 'z') }) });
    const r = plain(l.readLibrary(st)); assert.equal(r.status, 'ok'); assert.equal(r.entries.length, 1200);
  });
  await t.test('own full-size export re-imports (Plumb P2-3)', () => {
    const big = Array.from({ length: 1000 }, (_, i) => entry('n' + i, 'nmap ' + 'x'.repeat(7990) + i, '', { id: 'big' + i }));
    const txt = l.exportLibrary(big, NOW); assert.ok(txt.length > 8000000);
    const r = plain(l.parseLibraryFile(txt)); assert.equal(r.ok, true, r.errors && r.errors[0]); assert.equal(r.entries.length, 1000);
  });
  await t.test('size message says bytes or characters accurately', () => assert.match(plain(l.parseLibraryFile('x'.repeat(32000001))).errors[0], /characters|bytes/));
});
