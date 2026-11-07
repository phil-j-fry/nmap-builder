'use strict';
// Phase 2 UI: R30, R32–R36 against view.html + core.js + library.js + ui.js, assembled like build.py.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { read, ROOT } = require('./helpers.cjs');
const { makeWindow, Event } = require('./dom-shim.cjs');

const KEY = 'nmap-builder.library.v1';
const OT = 'nmap -sT -n -p 102,502,2404,4840,20000,44818 --max-rate 10 --max-retries 1 -iL ot-ranges.txt --excludefile exclude.txt -oA $R/ot-find';
const FIXTURE = read('tests/fixtures/ccsf-examples.json');
const HAS_LIB = fs.existsSync(path.join(ROOT, 'library.js'));
const wait = ms => new Promise(r => setTimeout(r, ms));
// Never hand DOM nodes to assert.equal/deepEqual: a failure diff would inspect the whole tree.
const describe = el => el ? `${el.localName}.${el.className}` : String(el);

function load({ hash = '', storage, clipboard, fixture = FIXTURE } = {}) {
  const bundle = 'const CATALOG=' + JSON.stringify(read('catalog.txt')) + ';\nconst STARTER_DATA=' + fixture + ';\n' + read('core.js') + '\n' + (HAS_LIB ? read('library.js') : '') + '\n' + read('ui.js');
  const w = makeWindow({ hash, html: read('view.html'), scripts: [[bundle, 'bundle.js']], storage, clipboard });
  const d = w.document, $ = s => d.querySelector(s), $$ = s => d.querySelectorAll(s);
  const need = s => { const el = $(s); assert.ok(el, 'missing element ' + s); return el; };
  const fire = (el, type) => el.dispatchEvent(new Event(type, { bubbles: true }));
  const setField = (s, v) => { const el = need(s); el.value = v; fire(el, 'input'); fire(el, 'change'); };
  const type = v => setField('.cmd', v);
  const text = s => ($(s)?.textContent || '').trim();
  const rows = () => $$('.lib-list .lib-entry');
  const row = name => rows().find(r => r.querySelector('.lib-entry-name')?.textContent === name);
  const save = (name, tags = '') => { setField('.lib-name', name); setField('.lib-tags', tags); need('.lib-save').click(); };
  const stored = () => { const raw = w._store.get(KEY); return raw ? JSON.parse(raw) : null; };
  const starterRow = src => $$('.starter-list .starter-entry').find(r => r.getAttribute('data-src') === src);
  return { w, d, $, $$, need, fire, setField, type, text, rows, row, save, stored, starterRow };
}

test('R30 build embeds library and starter data', async t => {
  await t.test('library.js exists', () => assert.ok(HAS_LIB, 'create library.js'));
  await t.test('index.html contains library.js and STARTER_DATA', () => {
    const idx = read('index.html');
    assert.ok(HAS_LIB && idx.includes(read('library.js')), 'index.html lacks current library.js; run python3 build.py');
    assert.ok(idx.includes('const STARTER_DATA='), 'STARTER_DATA not embedded');
    assert.ok(idx.includes(JSON.parse(FIXTURE).commit), 'fixture commit not embedded');
  });
  await t.test('bundle order', () => {
    const idx = read('index.html'), pos = ['const CATALOG=', 'const STARTER_DATA=', read('core.js').slice(0, 80), HAS_LIB ? read('library.js').slice(0, 80) : '\u0000', read('ui.js').slice(0, 80)].map(s => idx.indexOf(s));
    assert.ok(pos.every(p => p >= 0) && pos.every((p, i) => i === 0 || p > pos[i - 1]), 'order: CATALOG, STARTER_DATA, core.js, library.js, ui.js');
  });
  await t.test('library.js is safe', () => { const s = HAS_LIB ? read('library.js') : ''; for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'fetch(', 'XMLHttpRequest', 'window.openai']) assert.ok(!s.includes(bad), 'library.js contains ' + bad); });
});

test('R34 save, list, search, filter', async t => {
  const u = load();
  await t.test('panel and controls exist', () => { for (const s of ['details.library', '.lib-name', '.lib-tags', '.lib-save', '.lib-new', '.lib-search', '.lib-tag', '.lib-list', '.lib-export', '.lib-import', '.lib-msg']) u.need(s); assert.equal(u.$('.lib-msg').getAttribute('role'), 'status'); assert.equal(u.$('.lib-import').getAttribute('type'), 'file'); assert.match(u.$('.lib-import').getAttribute('accept') || '', /json/); });
  await t.test('save current command', () => {
    u.type('nmap -sS 10.0.0.1'); u.save('First', 'Recon, quick');
    const r = u.row('First'); assert.ok(r, 'row for saved entry');
    assert.equal(r.querySelector('code').textContent, 'nmap -sS 10.0.0.1');
    assert.match(r.querySelector('.lib-entry-tags').textContent, /recon/); assert.match(r.querySelector('.lib-entry-tags').textContent, /quick/);
    assert.ok(r.getAttribute('data-id'));
    const doc = u.stored(); assert.equal(doc.format, 'nmap-builder-library'); assert.equal(doc.entries.length, 1); assert.equal(doc.entries[0].cmd, 'nmap -sS 10.0.0.1');
  });
  await t.test('missing name does not save', () => { const n = u.rows().length; u.setField('.lib-name', ''); const before = u.$('.lib-name')._reportValidityCalls; u.need('.lib-save').click(); assert.equal(u.rows().length, n); assert.ok(u.$('.lib-name')._reportValidityCalls > before, 'reportValidity on .lib-name'); });
  await t.test('empty command does not save', () => { const n = u.rows().length; u.type('   '); u.save('Blank'); assert.equal(u.rows().length, n); assert.ok(u.text('.lib-msg').length > 0); });
  await t.test('commands with errors can be saved', () => { u.type('nmap --made-up 10.0.0.1'); u.save('Broken one'); assert.ok(u.row('Broken one')); assert.match(u.row('Broken one').querySelector('.lib-status').textContent, /1 problem/); });
  await t.test('status texts', () => {
    u.type('nmap -sV <host>'); u.save('Placeholder one');
    assert.match(u.row('Placeholder one').querySelector('.lib-status').textContent, /Fill in placeholders/);
    assert.match(u.row('First').querySelector('.lib-status').textContent, /Parses cleanly/);
  });
  await t.test('newest first', () => assert.equal(u.rows()[0].querySelector('.lib-entry-name').textContent, 'Placeholder one'));
  await t.test('search filters live', () => { u.setField('.lib-search', 'made-up'); assert.deepEqual(u.rows().map(r => r.querySelector('.lib-entry-name').textContent), ['Broken one']); u.setField('.lib-search', ''); assert.equal(u.rows().length, 3); });
  await t.test('tag filter', () => {
    const opts = u.$$('.lib-tag option').map(o => o.value); assert.ok(opts.includes('recon') && opts.includes('quick') && opts[0] === '', JSON.stringify(opts));
    u.setField('.lib-tag', 'recon'); assert.deepEqual(u.rows().map(r => r.querySelector('.lib-entry-name').textContent), ['First']); u.setField('.lib-tag', '');
  });
  await t.test('buttons are native with names in aria-label', () => { for (const r of u.rows()) for (const s of ['.lib-open', '.lib-copy', '.lib-delete']) { const b = r.querySelector(s); assert.ok(b && b.localName === 'button' && b.getAttribute('type') === 'button', s); assert.ok((b.getAttribute('aria-label') || '').includes(r.querySelector('.lib-entry-name').textContent), s + ' aria-label'); } });
  await t.test('names render as text', () => { u.type('nmap 10.0.0.1'); u.save('<img src=x onerror=alert(1)>'); assert.ok(u.row('<img src=x onerror=alert(1)>')); assert.ok(!u.d.created.includes('img')); });
});

test('R34 open, edit, new, copy, delete', async t => {
  const u = load();
  u.type('nmap -sS 10.0.0.1'); u.save('Edit me', 'a');
  const id = u.row('Edit me').getAttribute('data-id');
  await t.test('open loads command and fields', async () => {
    u.type('nmap -sU 10.0.0.2'); u.setField('.lib-name', ''); u.row('Edit me').querySelector('.lib-open').click();
    assert.equal(u.$('.cmd').value, 'nmap -sS 10.0.0.1'); assert.equal(u.$('.lib-name').value, 'Edit me'); assert.match(u.$('.lib-tags').value, /a/);
    assert.equal(u.$$('.breakdown .token').length, 2, 'breakdown refreshed');
    await wait(350); assert.equal(decodeURIComponent(u.w.location.hash), '#cmd=nmap -sS 10.0.0.1', 'hash updated via replaceState');
  });
  await t.test('save after open updates in place', () => {
    u.type('nmap -sS -p 80 10.0.0.1'); u.need('.lib-save').click();
    assert.equal(u.rows().length, 1); assert.equal(u.rows()[0].getAttribute('data-id'), id); assert.equal(u.rows()[0].querySelector('code').textContent, 'nmap -sS -p 80 10.0.0.1');
    const e = u.stored().entries[0]; assert.equal(e.id, id); assert.ok(e.updated >= e.created);
  });
  await t.test('new clears editing state', () => { u.need('.lib-new').click(); assert.equal(u.$('.lib-name').value, ''); assert.equal(u.$('.lib-tags').value, ''); u.save('Second'); assert.equal(u.rows().length, 2); });
  await t.test('copy uses clipboard', async () => { u.row('Edit me').querySelector('.lib-copy').click(); await wait(10); assert.deepEqual(u.w.navigator.clipboard.written.slice(-1), ['nmap -sS -p 80 10.0.0.1']); });
  await t.test('delete needs confirm', () => {
    const b = u.row('Second').querySelector('.lib-delete'); b.click();
    assert.ok(u.row('Second'), 'first click must not delete'); assert.match(u.row('Second').querySelector('.lib-delete').textContent, /Confirm delete/);
    u.row('Second').querySelector('.lib-delete').click();
    assert.ok(!u.row('Second'), 'entry still listed'); assert.equal(u.stored().entries.length, 1);
  });
  await t.test('re-render cancels pending confirm', () => { u.row('Edit me').querySelector('.lib-delete').click(); u.setField('.lib-search', 'x'); u.setField('.lib-search', ''); assert.ok(!/Confirm/.test(u.row('Edit me').querySelector('.lib-delete').textContent)); });
  await t.test('deleting the edited entry clears editing', () => {
    u.row('Edit me').querySelector('.lib-open').click();
    u.row('Edit me').querySelector('.lib-delete').click(); u.row('Edit me').querySelector('.lib-delete').click();
    assert.equal(u.rows().length, 0); u.save('After delete'); assert.equal(u.rows().length, 1); assert.notEqual(u.rows()[0].getAttribute('data-id'), id);
  });
  await t.test('window.confirm not used', () => { assert.ok(!(HAS_LIB && read('library.js').includes('confirm(')) && !read('ui.js').includes('confirm(')); });
  await t.test('clipboard failure message', async () => {
    for (const clipboard of ['reject', 'missing']) {
      const v = load({ clipboard }); v.type('nmap 10.0.0.1'); v.save('C'); v.row('C').querySelector('.lib-copy').click(); await wait(10);
      assert.match(v.text('.lib-msg'), /copy/i, clipboard);
    }
  });
});

test('R32 storage resilience in the UI', async t => {
  await t.test('blocked storage: boots, Phase 1 works, library in memory', () => {
    const u = load({ storage: { mode: 'throw' } });
    assert.equal(u.$('.cmd').value, OT); assert.match(u.text('.scope'), /unknown until the named lists/);
    assert.match(u.text('.lib-msg'), /storage is unavailable/i); assert.match(u.text('.lib-msg'), /export/i);
    u.type('nmap -sS 10.0.0.1'); u.save('Mem'); assert.ok(u.row('Mem'), 'works in memory');
  });
  await t.test('quota errors: saved in memory, message shown', () => { const u = load({ storage: { mode: 'quota' } }); u.type('nmap 10.0.0.1'); u.save('Q'); assert.ok(u.row('Q')); assert.match(u.text('.lib-msg'), /storage is unavailable|could not be saved/i); });
  await t.test('loads stored library on boot', () => {
    const store = new Map([[KEY, JSON.stringify({ format: 'nmap-builder-library', version: 1, exported: '2026-11-07T00:00:00.000Z', entries: [{ id: 'k1', name: 'Kept', cmd: 'nmap -sn 10.0.0.0/24', tags: ['x'], source: null, created: '2026-11-07T00:00:00.000Z', updated: '2026-11-07T00:00:00.000Z' }] })]]);
    const u = load({ storage: { store } }); assert.ok(u.row('Kept')); assert.equal(u.$('.cmd').value, OT, 'library never changes .cmd on load');
  });
  await t.test('corrupt library: backed up, message, not overwritten until backup exists', () => {
    const store = new Map([[KEY, '{garbage']]);
    const u = load({ storage: { store } });
    assert.match(u.text('.lib-msg'), /could not be read/i); assert.equal(store.get(KEY + '.backup'), '{garbage');
    u.type('nmap 10.0.0.1'); u.save('New'); assert.equal(store.get(KEY + '.backup'), '{garbage'); assert.equal(JSON.parse(store.get(KEY)).entries.length, 1);
  });
  await t.test('storage event reloads', () => {
    const store = new Map(), u = load({ storage: { store } });
    store.set(KEY, JSON.stringify({ format: 'nmap-builder-library', version: 1, exported: 'x', entries: [{ id: 'o1', name: 'From other tab', cmd: 'nmap 10.0.0.9', tags: [], source: null, created: '2026-11-07T00:00:00.000Z', updated: '2026-11-07T00:00:00.000Z' }] }));
    const ev = new Event('storage'); ev.key = KEY; u.w.dispatchEvent(ev);
    assert.ok(u.row('From other tab'));
  });
});

test('R33 export and import in the UI', async t => {
  const u = load();
  u.type('nmap -sS 10.0.0.1'); u.save('One', 'a');
  await t.test('export downloads JSON', () => {
    u.need('.lib-export').click();
    const dl = u.w.downloads.at(-1); assert.ok(dl, 'no download triggered'); assert.match(dl.name, /^nmap-library-\d{4}-\d{2}-\d{2}\.json$/);
    assert.ok(dl.blob, 'download href must be an object URL for a Blob'); const doc = JSON.parse(dl.blob._text);
    assert.equal(doc.format, 'nmap-builder-library'); assert.equal(doc.version, 1); assert.equal(doc.entries[0].name, 'One');
  });
  const importText = async txt => { const inp = u.need('.lib-import'); inp.files = [new u.w.File([txt], 'lib.json', { type: 'application/json' })]; u.fire(inp, 'change'); await wait(30); };
  await t.test('import merges and reports', async () => {
    const doc = { format: 'nmap-builder-library', version: 1, exported: 'x', entries: [{ id: 'z1', name: 'Imported', cmd: 'nmap -sV <host>', tags: ['b'] }, { id: 'z2', name: 'One', cmd: 'nmap -sS 10.0.0.1', tags: ['a'] }, { id: 'z3', name: '' }] };
    await importText(JSON.stringify(doc));
    assert.ok(u.row('Imported')); assert.equal(u.rows().length, 2);
    assert.match(u.text('.lib-msg'), /Imported 1/); assert.match(u.text('.lib-msg'), /skipped 1/i); assert.match(u.text('.lib-msg'), /1 invalid/i);
    assert.equal(u.stored().entries.length, 2);
  });
  await t.test('invalid file leaves library unchanged', async () => { await importText('{"format":"nope"}'); assert.equal(u.rows().length, 2); assert.ok(u.text('.lib-msg').length > 0); assert.equal(u.stored().entries.length, 2); });
  await t.test('imported markup renders as text', async () => { await importText(JSON.stringify({ format: 'nmap-builder-library', version: 1, entries: [{ id: 'x', name: '<script>alert(1)</script>', cmd: 'nmap <img src=x onerror=alert(1)>', tags: [] }] })); assert.ok(u.row('<script>alert(1)</script>')); assert.ok(!u.d.created.includes('img') && !u.d.created.includes('script')); assert.equal(u.w.alerts || 0, 0); });
});

test('R35 starter set UI', async t => {
  const u = load();
  const data = JSON.parse(FIXTURE), want = data.examples.filter(e => ['valid', 'placeholder'].includes(e.kind));
  await t.test('panel lists every starter command with attribution', () => {
    u.need('details.starter');
    const rs = u.$$('.starter-list .starter-entry'); assert.equal(rs.length, want.length);
    for (const e of want) { const r = u.starterRow(e.src); assert.ok(r, e.src); assert.equal(r.querySelector('.starter-src').textContent, e.src); assert.equal(r.querySelector('code').textContent, e.cmd); assert.equal(r.querySelector('.starter-category-label').textContent, e.category); }
    assert.ok(u.text('details.starter').includes(data.commit.slice(0, 7)), 'short commit shown'); assert.ok(u.text('details.starter').includes(data.source), 'repo shown');
  });
  await t.test('broken / fragment / pipeline excluded', () => { for (const e of data.examples.filter(e => !['valid', 'placeholder'].includes(e.kind))) assert.ok(!u.starterRow(e.src), e.src); });
  await t.test('placeholder rows labeled', () => { const r = u.starterRow('archive/AD/README.md:27'); assert.match(r.querySelector('.starter-kind').textContent, /fill this in/i); assert.match(r.querySelector('.lib-status').textContent, /Fill in placeholders/); });
  await t.test('category filter', () => {
    const cats = u.$$('.starter-category option').map(o => o.value); assert.equal(cats[0], ''); assert.deepEqual(cats.slice(1), [...new Set(want.map(e => e.category))].sort());
    u.setField('.starter-category', 'OT / ICS'); const rs = u.$$('.starter-list .starter-entry'); assert.equal(rs.length, want.filter(e => e.category === 'OT / ICS').length); assert.ok(rs.every(r => r.querySelector('.starter-category-label').textContent === 'OT / ICS'));
    u.setField('.starter-category', ''); assert.equal(u.$$('.starter-list .starter-entry').length, want.length);
  });
  await t.test('read-only: no delete/edit controls, never stored', () => { for (const r of u.$$('.starter-list .starter-entry')) assert.ok(!r.querySelector('.lib-delete') && !r.querySelector('.lib-open')); assert.equal(u.stored(), null); });
  await t.test('open loads command, not editing', async () => {
    u.starterRow('playbooks/recon/RECON-GUIDE.md:108').querySelector('.starter-open').click();
    assert.equal(u.$('.cmd').value, 'nmap -sL -n -iL scope.txt --excludefile exclude.txt'); assert.equal(u.$('.lib-name').value, 'playbooks/recon/RECON-GUIDE.md:108');
    await wait(350); assert.equal(u.w.location.hash, '#cmd=' + encodeURIComponent('nmap -sL -n -iL scope.txt --excludefile exclude.txt'));
    u.need('.lib-save').click(); assert.equal(u.rows().length, 1, 'save after starter open creates a user copy'); assert.ok(u.starterRow('playbooks/recon/RECON-GUIDE.md:108'), 'starter row untouched');
  });
  await t.test('copy to my library, then duplicate skipped', () => {
    const v = load(), r = () => v.starterRow('archive/ICS/Readme.md:10');
    r().querySelector('.starter-save').click();
    const e = v.stored().entries; assert.equal(e.length, 1); assert.equal(e[0].source, 'ccsf:archive/ICS/Readme.md:10'); assert.equal(e[0].name, 'archive/ICS/Readme.md:10'); assert.deepEqual(e[0].tags, ['ccsf', 'ot-ics']); assert.equal(e[0].cmd, 'nmap -Pn -sU -p47808 --script bacnet-info <target>');
    r().querySelector('.starter-save').click(); assert.equal(v.stored().entries.length, 1); assert.match(v.text('.lib-msg'), /already/i);
  });
});

test('R36 coexistence with Phase 1', async t => {
  await t.test('hash wins on load, library untouched', () => {
    const store = new Map([[KEY, JSON.stringify({ format: 'nmap-builder-library', version: 1, exported: 'x', entries: [{ id: 'k', name: 'K', cmd: 'nmap -sn 10.0.0.0/24', tags: [], source: null, created: '2026-11-07T00:00:00.000Z', updated: '2026-11-07T00:00:00.000Z' }] })]]);
    const u = load({ hash: '#cmd=' + encodeURIComponent('nmap -sU 10.0.0.3'), storage: { store } });
    assert.equal(u.$('.cmd').value, 'nmap -sU 10.0.0.3'); assert.ok(u.row('K'));
  });
  await t.test('library data never in hash', async () => { const u = load(); u.type('nmap 10.0.0.1'); u.save('SecretName', 'secrettag'); await wait(350); const h = decodeURIComponent(u.w.location.hash); assert.ok(!h.includes('SecretName') && !h.includes('secrettag')); assert.ok(!u.w.history.calls.some(c => decodeURIComponent(c[1]).includes('SecretName'))); });
  await t.test('narrow widths: no fixed widths over 320px; rows wrap', () => {
    const css = (read('view.html').match(/<style>([\s\S]*?)<\/style>/) || [])[1] || '';
    for (const m of css.matchAll(/(?:^|[;{\s])(min-width|width)\s*:\s*(\d+)px/g)) assert.ok(+m[2] <= 320, `${m[1]}:${m[2]}px`);
    const root = /#scan-desk\{[^}]*overflow-wrap:\s*anywhere/.test(css);
    for (const sel of ['.lib-list', '.starter-list', '.lib-editing']) assert.ok(root || new RegExp(sel.replace('.', '\\.') + '[^{]*\\{[^}]*overflow-wrap:\\s*anywhere').test(css), sel + ' needs overflow-wrap:anywhere');
  });
});

// ---- Phase 2 review round 1 (Gadfly) ----
test('R33a import checks file size before reading', async () => {
  const u = load(); u.type('nmap 10.0.0.1'); u.save('Keep');
  let read = false;
  const huge = { name: 'huge.json', size: 5e9, type: 'application/json', text() { read = true; return Promise.resolve('{}'); } };
  const inp = u.need('.lib-import'); inp.files = [huge]; u.fire(inp, 'change'); await wait(30);
  assert.equal(read, false, 'file.text() must not be called for a file over importBytes');
  assert.match(u.text('.lib-msg'), /larger/i); assert.equal(u.rows().length, 1);
});

test('R32a corrupt library with an older backup', () => {
  const store = new Map([[KEY, 'junk-now'], [KEY + '.backup', 'older real data']]);
  const u = load({ storage: { store } });
  const keys = [...store.keys()].filter(k => k.startsWith(KEY + '.backup'));
  assert.equal(store.get(KEY + '.backup'), 'older real data');
  const fresh = keys.find(k => store.get(k) === 'junk-now'); assert.ok(fresh, 'current raw value backed up under a new key');
  assert.ok(u.text('.lib-msg').includes(fresh), 'message names the backup key');
  u.type('nmap 10.0.0.1'); u.save('New'); assert.equal(JSON.parse(store.get(KEY)).entries.length, 1);
  assert.equal(store.get(KEY + '.backup'), 'older real data'); assert.equal(store.get(fresh), 'junk-now');
});

// ---- Plumb Phase 2 review ----
const fullStore = n => new Map([[KEY, JSON.stringify({ format: 'nmap-builder-library', version: 1, exported: 'x', entries: Array.from({ length: n }, (_, i) => ({ id: 'f' + i, name: 'F' + i, cmd: 'nmap 10.0.0.' + (i % 250), tags: [], source: null, created: '2026-11-07T00:00:00.000Z', updated: '2026-11-07T00:00:00.000Z' })) })]]);
test('Plumb P2-1: the UI refuses to grow past 1000 entries', async t => {
  await t.test('save refused when full', () => { const store = fullStore(1000), u = load({ storage: { store } }); u.type('nmap -sS 10.0.0.1'); u.save('One too many'); assert.equal(JSON.parse(store.get(KEY)).entries.length, 1000); assert.ok(!u.row('One too many')); assert.match(u.text('.lib-msg'), /full/i); });
  await t.test('editing still works when full', () => { const store = fullStore(1000), u = load({ storage: { store } }); u.setField('.lib-search', 'F7'); u.row('F7').querySelector('.lib-open').click(); u.type('nmap -sU 10.0.0.7'); u.need('.lib-save').click(); const es = JSON.parse(store.get(KEY)).entries; assert.equal(es.length, 1000); assert.equal(es.find(e => e.id === 'f7').cmd, 'nmap -sU 10.0.0.7'); });
  await t.test('starter copy refused when full', () => { const store = fullStore(1000), u = load({ storage: { store } }); u.starterRow('archive/ICS/Readme.md:10').querySelector('.starter-save').click(); assert.equal(JSON.parse(store.get(KEY)).entries.length, 1000); assert.match(u.text('.lib-msg'), /full/i); });
  await t.test('import reports entries not added', async () => {
    const store = fullStore(999), u = load({ storage: { store } });
    const doc = { format: 'nmap-builder-library', version: 1, entries: [{ id: 'n1', name: 'New1', cmd: 'nmap 1.1.1.1', tags: [] }, { id: 'n2', name: 'New2', cmd: 'nmap 1.1.1.2', tags: [] }] };
    const inp = u.need('.lib-import'); inp.files = [new u.w.File([JSON.stringify(doc)], 'a.json')]; u.fire(inp, 'change'); await wait(30);
    assert.equal(JSON.parse(store.get(KEY)).entries.length, 1000); assert.match(u.text('.lib-msg'), /1 not added/i); assert.match(u.text('.lib-msg'), /full/i);
  });
  await t.test('reload after reaching the cap is not corrupt', () => { const store = fullStore(1000), u = load({ storage: { store } }); assert.ok(!/could not be read/i.test(u.text('.lib-msg'))); assert.equal(u.rows().length, 1000); });
});

test('Plumb P2-2: file input fits 320px', () => {
  const css = (read('view.html').match(/<style>([\s\S]*?)<\/style>/) || [])[1] || '';
  const rule = sel => [...css.matchAll(/([^{}]+)\{([^}]*)\}/g)].filter(m => m[1].split(',').some(x => x.trim() === sel)).map(m => m[2]).join(';');
  assert.match(rule('#scan-desk input[type=file]'), /width:\s*100%/); assert.match(rule('#scan-desk input[type=file]'), /min-width:\s*0/);
  assert.match(rule('#scan-desk label'), /min-width:\s*0/);
});

test('Plumb P2-3: export over the import limit warns', () => {
  const store = new Map([[KEY, JSON.stringify({ format: 'nmap-builder-library', version: 1, exported: 'x', entries: Array.from({ length: 1000 }, (_, i) => ({ id: 'w' + i, name: 'W' + i, cmd: 'nmap ' + '\u0001'.repeat(7990), tags: [], source: null, created: '2026-11-07T00:00:00.000Z', updated: '2026-11-07T00:00:00.000Z' })) })]]);
  const u = load({ storage: { store } }); u.need('.lib-export').click();
  const dl = u.w.downloads.at(-1); assert.ok(dl && dl.blob && dl.blob.size > 32000000, 'download still happens');
  assert.match(u.text('.lib-msg'), /import limit/i);
});

test('Plumb P2-4: starter copy with an invalid entry does not throw', () => {
  const data = JSON.parse(FIXTURE); data.examples = [{ src: 'long.md:1', cmd: 'nmap 10.0.0.1', kind: 'valid', category: 'Recon', title: 'T'.repeat(150) }];
  const u = load({ fixture: JSON.stringify(data) });
  const r = u.$$('.starter-list .starter-entry')[0]; assert.ok(r, 'starter row rendered');
  r.querySelector('.starter-save').click();
  assert.ok(u.text('.lib-msg').length > 0, 'explains why'); assert.equal(u.rows().length, 0);
});

test('Plumb P2-5: editing indicator and hashchange', async t => {
  const u = load(); u.type('nmap -sS 10.0.0.1'); u.save('A');
  await t.test('indicator empty when not editing', () => { u.need('.lib-editing'); assert.equal(u.text('.lib-editing'), ''); });
  await t.test('indicator shows name while editing', () => { u.row('A').querySelector('.lib-open').click(); assert.equal(u.text('.lib-editing'), 'Editing: A'); });
  await t.test('new #cmd= link ends editing', async () => {
    u.w.location.hash = '#cmd=' + encodeURIComponent('nmap -sU 10.9.9.9'); await wait(30);
    assert.equal(u.$('.cmd').value, 'nmap -sU 10.9.9.9'); assert.equal(u.text('.lib-editing'), '');
    assert.ok(!/Editing "A"/.test(u.text('.lib-msg')), 'stale editing message');
    u.setField('.lib-name', 'B'); u.need('.lib-save').click();
    assert.equal(u.rows().length, 2, 'save after a new link creates a new entry'); assert.equal(u.row('A').querySelector('code').textContent, 'nmap -sS 10.0.0.1');
  });
  await t.test('New clears indicator', () => { u.row('A').querySelector('.lib-open').click(); u.need('.lib-new').click(); assert.equal(u.text('.lib-editing'), ''); });
});
