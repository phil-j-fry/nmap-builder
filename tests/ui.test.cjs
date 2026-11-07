'use strict';
// R17, R19–R25 against the real view.html + core.js + ui.js, assembled the way build.py does.
const test = require('node:test');
const assert = require('node:assert/strict');
const { read, loadCore } = require('./helpers.cjs');
const { makeWindow, Event, KeyboardEvent } = require('./dom-shim.cjs');
const { ctx: core } = loadCore();

const OT = 'nmap -sT -n -p 102,502,2404,4840,20000,44818 --max-rate 10 --max-retries 1 -iL ot-ranges.txt --excludefile exclude.txt -oA $R/ot-find';
// Never pass DOM nodes to assert.equal: failure diffs would inspect the whole tree.
const describe = el => el ? `${el.localName}.${el.className} [${el.getAttribute('aria-label') || ''}]` : String(el);
const wait = ms => new Promise(r => setTimeout(r, ms));

function load(hash = '') {
  const w = makeWindow({ hash, html: read('view.html'), scripts: [['const CATALOG=' + JSON.stringify(read('catalog.txt')) + ';\n' + read('core.js') + '\n' + read('ui.js'), 'bundle.js']] });
  const d = w.document, $ = s => d.querySelector(s), $$ = s => d.querySelectorAll(s);
  const type = text => { const c = $('.cmd'); c.value = text; c.dispatchEvent(new Event('input', { bubbles: true })); c.dispatchEvent(new Event('change', { bubbles: true })); };
  const rows = () => $$('.breakdown .token');
  const choose = key => { const s = $('.search'); s.value = ''; s.dispatchEvent(new Event('input', { bubbles: true })); const c = $('.choice'); c.value = key; assert.equal(c.value, key, 'option ' + key + ' not in .choice'); c.dispatchEvent(new Event('change', { bubbles: true })); c.dispatchEvent(new Event('input', { bubbles: true })); };
  const enter = el => { const ev = new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }); el.dispatchEvent(ev); return ev; };
  const setField = (el, v) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); };
  const text = s => ($(s)?.textContent || '').trim();
  return { w, d, $, $$, type, rows, choose, enter, setField, text };
}

test('UI boots and shows the OT example by default', () => {
  const u = load();
  assert.equal(u.$('.cmd').value, OT);
  assert.match(u.text('.scope'), /unknown until the named lists are supplied/);
});

test('R19 breakdown in source order', async t => {
  const u = load();
  u.type('nmap -sS <host> --made-up 10.0.0.1 | grep x');
  const rs = u.rows();
  await t.test('kinds', () => assert.deepEqual(rs.map(r => r.getAttribute('data-kind')), ['flag', 'target', 'unknown', 'target', 'shell']));
  await t.test('code text', () => assert.deepEqual(rs.map(r => r.querySelector('code')?.textContent), ['-sS', '<host>', '--made-up', '10.0.0.1', '| grep x']));
  await t.test('placeholder row', () => { assert.ok(rs[1].classList.contains('placeholder')); assert.match(rs[1].textContent, /fill this in/i); assert.ok(!rs[3].classList.contains('placeholder')); });
  await t.test('unknown row', () => assert.match(rs[2].textContent, /Not in the pinned catalog/));
  await t.test('shell row', () => { assert.match(rs[4].textContent, /Shell syntax/); assert.match(rs[4].textContent, /not part of the Nmap command/); });
  await t.test('remove buttons', () => { for (const r of rs) { const b = r.querySelector('button'); assert.ok(b, 'button'); assert.equal(b.textContent.trim(), 'Remove'); assert.match(b.getAttribute('aria-label') || '', /^Remove \S/); } });
  await t.test('grouped flags one row each', () => { u.type('nmap -sSU 10.0.0.1'); assert.deepEqual(u.rows().map(r => r.querySelector('code').textContent), ['-sS', '-sU', '10.0.0.1']); });
  await t.test('values rendered as text, not markup', () => { u.type(`nmap -oX '<img src=x onerror=alert(1)>' 10.0.0.1`); assert.match(u.rows()[0].querySelector('code').textContent, /<img src=x onerror=alert\(1\)>/); assert.ok(!u.d.created.includes('img')); });
});

test('R18 Remove button uses raw-text removal', async t => {
  const u = load();
  await t.test('grouped -sSU', () => { u.type('nmap -sSU 10.0.0.1'); u.rows()[0].querySelector('button').click(); assert.equal(u.$('.cmd').value, 'nmap -sU 10.0.0.1'); });
  await t.test('quoted value kept', () => { u.type('nmap -sS -oX "my report.xml" 10.0.0.1'); u.rows()[0].querySelector('button').click(); assert.equal(u.$('.cmd').value, 'nmap -oX "my report.xml" 10.0.0.1'); });
  await t.test('target removable', () => { u.type('nmap -sS 10.0.0.1 10.0.0.2'); u.rows()[1].querySelector('button').click(); assert.equal(u.$('.cmd').value, 'nmap -sS 10.0.0.2'); });
  await t.test('shell removable', () => { u.type('nmap -sL -iL s.txt | grep -F x'); u.rows().at(-1).querySelector('button').click(); assert.equal(u.$('.cmd').value, 'nmap -sL -iL s.txt'); });
});

test('R20 keyboard', async t => {
  const u = load();
  await t.test('controls are native', () => {
    const native = new Set(['button', 'input', 'select', 'textarea', 'summary', 'a', 'option']);
    for (const el of u.$$('*')) {
      if (el.getAttribute('role') === 'button' && !native.has(el.localName)) assert.fail('role=button on ' + el.localName);
      if (el.hasAttribute('tabindex') && +el.getAttribute('tabindex') >= 0 && !native.has(el.localName)) assert.fail('tabindex on ' + el.localName);
      if (typeof el.onclick === 'function' && !native.has(el.localName)) assert.fail('onclick on ' + el.localName + '.' + el.className);
    }
  });
  await t.test('Enter in .value adds option', () => {
    u.type('nmap 10.0.0.1'); u.choose('-p'); u.setField(u.$('.value'), '80');
    const ev = u.enter(u.$('.value'));
    assert.equal(u.$('.cmd').value, 'nmap 10.0.0.1 -p 80'); assert.ok(ev.defaultPrevented, 'preventDefault');
  });
  await t.test('Enter in .target adds target', () => {
    u.type('nmap -sS'); u.setField(u.$('.target'), '10.0.0.9');
    const ev = u.enter(u.$('.target'));
    assert.equal(u.$('.cmd').value, 'nmap -sS 10.0.0.9'); assert.ok(ev.defaultPrevented);
  });
  await t.test('focus moves to same-index Remove after removal', () => {
    u.type('nmap -sS -sV 10.0.0.1'); const b = u.rows()[0].querySelector('button'); b.focus(); b.click();
    assert.ok(u.d.activeElement === u.rows()[0].querySelector('button'), 'focus is on ' + describe(u.d.activeElement));
    assert.match(u.d.activeElement.getAttribute('aria-label'), /-sV/);
  });
  await t.test('focus moves to previous Remove when last row removed', () => {
    u.type('nmap -sS 10.0.0.1'); const b = u.rows()[1].querySelector('button'); b.focus(); b.click();
    assert.ok(u.d.activeElement === u.rows()[0].querySelector('button'), 'focus is on ' + describe(u.d.activeElement));
  });
  await t.test('focus moves to .cmd when nothing is left', () => {
    u.type('nmap 10.0.0.1'); const b = u.rows()[0].querySelector('button'); b.focus(); b.click();
    assert.equal(u.$('.cmd').value, 'nmap'); assert.ok(u.d.activeElement === u.$('.cmd'), 'focus is on ' + describe(u.d.activeElement));
  });
});

test('R17 builder appends safely', async t => {
  const u = load();
  const addOpt = (key, v = '') => { u.choose(key); u.setField(u.$('.value'), v); u.$('.add').click(); };
  const addTarget = v => { u.setField(u.$('.target'), v); u.$('.addtarget').click(); };
  await t.test('empty command gets nmap prefix', () => { u.type(''); addOpt('-sS'); assert.equal(u.$('.cmd').value, 'nmap -sS'); });
  await t.test('whitespace command gets nmap prefix', () => { u.type('   '); addTarget('10.0.0.1'); assert.equal(u.$('.cmd').value, 'nmap 10.0.0.1'); });
  await t.test('inserted before shell segment', () => { u.type('nmap 10.0.0.1 | grep x'); addOpt('-p', '80'); assert.equal(u.$('.cmd').value, 'nmap 10.0.0.1 -p 80 | grep x'); });
  await t.test('appended after a mid-command redirect', () => { u.type('nmap -oN x > log 10.0.0.1'); addOpt('-sS'); assert.equal(u.$('.cmd').value, 'nmap -oN x > log 10.0.0.1 -sS'); });
  await t.test('inserted before the stopping operator, not a redirect', () => { u.type('nmap 10.0.0.1 2>&1 | tee x'); addOpt('-sS'); assert.equal(u.$('.cmd').value, 'nmap 10.0.0.1 2>&1 -sS | tee x'); });
  await t.test('inserted before comment', () => { u.type('nmap 10.0.0.1 #note'); addTarget('10.0.0.2'); assert.equal(u.$('.cmd').value, 'nmap 10.0.0.1 10.0.0.2 #note'); });
  await t.test('value is quoted', () => { u.type('nmap 10.0.0.1'); addOpt('-oX', 'my report.xml'); assert.equal(u.$('.cmd').value, "nmap 10.0.0.1 -oX 'my report.xml'"); });
  await t.test('unclosed quote refuses', () => { u.type('nmap -oX "a 10.0.0.1'); addOpt('-sS'); assert.equal(u.$('.cmd').value, 'nmap -oX "a 10.0.0.1'); assert.ok(u.text('.builder-msg').length > 0); });
  await t.test('targets split on whitespace', () => { u.type('nmap -sS'); addTarget('10.0.0.1  10.0.0.2'); assert.equal(u.$('.cmd').value, 'nmap -sS 10.0.0.1 10.0.0.2'); });
  await t.test('spaced placeholder stays one target', () => { u.type('nmap -sS'); addTarget('<brittle ports>'); const p = core.parse(u.$('.cmd').value, core.registry(read('catalog.txt'))); assert.deepEqual(JSON.parse(JSON.stringify(p.targets)), ['<brittle ports>']); });
  await t.test('shell text in target is quoted', () => { u.type('nmap -sS'); addTarget('$(id)'); assert.equal(u.$('.cmd').value, "nmap -sS '$(id)'"); });
  await t.test('dash target rejected', () => { u.type('nmap -sS'); addTarget('-iL /etc/passwd'); assert.equal(u.$('.cmd').value, 'nmap -sS'); assert.match(u.text('.builder-msg'), /-/); });
  await t.test('required value missing', () => { u.type('nmap 10.0.0.1'); u.choose('-p'); u.setField(u.$('.value'), ''); const before = u.$('.value')._reportValidityCalls; u.$('.add').click(); assert.equal(u.$('.cmd').value, 'nmap 10.0.0.1'); assert.ok(u.$('.value')._reportValidityCalls > before, 'reportValidity called'); });
  await t.test('shell-only command still gets nmap prefix', () => { u.type('; ls'); addOpt('-sS'); assert.equal(u.$('.cmd').value, 'nmap -sS ; ls'); });
  await t.test('builder message clears on success', () => { u.type('nmap -sS'); addTarget('-x'); assert.ok(u.text('.builder-msg')); addTarget('10.0.0.1'); assert.equal(u.text('.builder-msg'), ''); });
});

test('R21 validation failures are visible', async t => {
  const u = load();
  await t.test('alert role', () => assert.equal(u.$('.problem').getAttribute('role'), 'alert'));
  await t.test('error state', () => { u.type('nmap --made-up 10.0.0.1'); assert.ok(u.text('.problem').length > 0); assert.equal(u.text('.scope'), ''); assert.match(u.text('.prose'), /^Partial interpretation/); });
  await t.test('clean state', () => { u.type('nmap -sS 10.0.0.1'); assert.equal(u.text('.problem'), ''); assert.equal(u.text('.warnings'), ''); assert.match(u.text('.scope'), /^1 distinct IPv4 address/); });
  await t.test('warnings and notes shown', () => { u.type('nmap -sV <host> | grep x'); assert.equal(u.text('.problem'), ''); assert.match(u.text('.warnings'), /fill this in/i); assert.match(u.text('.warnings'), /\|/); });
  await t.test('every error message rendered', () => { u.type('nmap -T9 -sS -sT 10.0.0.999'); const p = core.parse(u.$('.cmd').value, core.registry(read('catalog.txt'))); for (const m of p.issues) assert.ok(u.text('.problem').includes(m), 'missing ' + m); });
});

test('R22 list handling', async t => {
  const u = load();
  const box = name => u.$(`.filebox [data-list="${name}"]`);
  const apply = (name, v) => { const b = box(name); assert.ok(b, 'no list box for ' + name); u.setField(b.querySelector('textarea'), v); [...b.querySelectorAll('button')].find(x => /Apply list/.test(x.textContent)).click(); };
  await t.test('boxes for OT lists', () => { u.type(OT); assert.ok(box('ot-ranges.txt')); assert.ok(box('exclude.txt')); assert.match(box('ot-ranges.txt').textContent, /ot-ranges\.txt/); });
  await t.test('apply both lists counts', () => { apply('ot-ranges.txt', '10.10.10.0/24'); apply('exclude.txt', '10.10.10.1'); assert.match(u.text('.scope'), /^255 distinct/); });
  await t.test('empty applied exclusion', () => { apply('exclude.txt', ''); assert.match(u.text('.scope'), /^256 distinct/); });
  await t.test('edit after apply returns to unknown', () => { const ta = box('exclude.txt').querySelector('textarea'); u.setField(ta, '10.10.10.2'); assert.match(u.text('.scope'), /unknown/); });
  await t.test('list contents never in hash', async () => { apply('exclude.txt', '10.99.99.99'); await wait(350); assert.ok(!decodeURIComponent(u.w.location.hash).includes('10.99.99.99')); assert.ok(!u.w.history.calls.some(c => decodeURIComponent(c[1]).includes('10.99.99.99'))); });
  await t.test('stdin label', () => { u.type('nmap -sn -iL -'); assert.match(box('-').textContent, /standard input/i); });
  await t.test('no box for placeholder name', () => { u.type('nmap -sn -iL <targets>'); assert.equal(u.$$('.filebox textarea').length, 0); });
  await t.test('one box per distinct name', () => { u.type('nmap -iL a.txt --excludefile a.txt'); assert.equal(u.$$('.filebox [data-list]').length, 1); });
});

test('R23 URL hash persistence', async t => {
  await t.test('loads command from hash', () => { const u = load(core.encodeHash('nmap -sS 10.0.0.1')); assert.equal(u.$('.cmd').value, 'nmap -sS 10.0.0.1'); assert.equal(u.rows().length, 2); });
  await t.test('empty cmd in hash loads empty', () => { const u = load('#cmd='); assert.equal(u.$('.cmd').value, ''); });
  await t.test('malformed hash falls back to default', () => { const u = load('#cmd=%E0%A4%A'); assert.equal(u.$('.cmd').value, OT); });
  await t.test('typing updates hash via replaceState', async () => {
    const u = load(); u.type('nmap -sU 10.0.0.5'); await wait(350);
    assert.equal(u.w.location.hash, core.encodeHash('nmap -sU 10.0.0.5'));
    assert.ok(u.w.history.calls.some(c => c[0] === 'replace')); assert.ok(!u.w.history.calls.some(c => c[0] === 'push'), 'pushState must not be used');
  });
  await t.test('builder and remove update hash', async () => { const u = load(); u.type('nmap -sS 10.0.0.1'); u.rows()[0].querySelector('button').click(); await wait(350); assert.equal(u.w.location.hash, core.encodeHash('nmap 10.0.0.1')); });
  await t.test('over-long command is not written to the hash', async () => { const u = load(); u.type('nmap 10.0.0.1 ' + '-v '.repeat(3000)); await wait(350); assert.ok(!u.w.history.calls.some(c => c[1].length > 9000), 'hash over 8000 chars written'); assert.match(u.text('.warnings'), /too long to save in the link/i); });
  await t.test('hashchange loads new command', async () => { const u = load(); u.w.location.hash = core.encodeHash('nmap -sV 10.0.0.7').slice(1); await wait(50); assert.equal(u.$('.cmd').value, 'nmap -sV 10.0.0.7'); assert.equal(u.rows().length, 2); });
  await t.test('XSS payload renders literally', () => {
    const u = load('#cmd=' + encodeURIComponent('nmap <img src=x onerror=alert(1)> --script "<script>alert(1)</script>"'));
    assert.ok(!u.d.created.includes('img') && !u.d.created.includes('script'));
    assert.ok(u.$$('.breakdown code').some(c => c.textContent.includes('<img')));
    assert.equal(u.w.alerts || 0, 0);
  });
});

test('Plumb review: search ranking and live regions', async t => {
  const u = load();
  const search = q => { const s = u.$('.search'); s.value = q; s.dispatchEvent(new Event('input', { bubbles: true })); return u.$$('.choice option').map(o => o.value); };
  await t.test('exact key first', () => { assert.equal(search('-p')[0], '-p'); assert.equal(search('--script')[0], '--script'); assert.equal(search('-sS')[0], '-sS'); });
  await t.test('key prefix before description match', () => { const r = search('-p'), firstDesc = r.findIndex(k => !k.toLowerCase().startsWith('-p')); assert.ok(firstDesc < 0 || r.slice(firstDesc).every(k => !k.toLowerCase().startsWith('-p')), 'prefix matches must come before description-only matches'); });
  await t.test('case-insensitive key match still finds -PS', () => assert.ok(search('-ps').includes('-PS')));
  await t.test('.problem is not inside an aria-live region', () => { assert.equal(u.$('.problem').getAttribute('role'), 'alert'); assert.ok(u.$('.problem').parentNode.closest('[aria-live]') === null, 'alert inside aria-live is announced twice'); });
  await t.test('.prose and .scope are announced', () => { for (const s of ['.prose', '.scope']) assert.ok(u.$(s).closest('[aria-live]'), s + ' needs an aria-live region'); });
});

test('R24 no dead widget code or unsafe DOM', async t => {
  const files = ['ui.js', 'core.js', 'view.html', 'index.html'];
  for (const f of files) await t.test(f, () => {
    const s = read(f);
    for (const bad of ['window.openai', 'openai:', 'setWidgetState', 'widgetState', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'fetch(', 'XMLHttpRequest'])
      assert.ok(!s.includes(bad), `${f} contains ${bad}`);
  });
  await t.test('index.html is fresh', () => { const idx = read('index.html'); assert.ok(idx.includes(read('core.js')), 'index.html lacks current core.js; run python3 build.py'); assert.ok(idx.includes(read('ui.js')), 'index.html lacks current ui.js; run python3 build.py'); assert.ok(idx.includes(read('view.html')), 'index.html lacks current view.html'); });
});

test('R25 narrow-width CSS', async t => {
  const css = (read('view.html').match(/<style>([\s\S]*?)<\/style>/) || [])[1] || '';
  await t.test('has max-width media query', () => assert.match(css, /@media\s*\(\s*max-width\s*:/));
  await t.test('no fixed width over 320px', () => { for (const m of css.matchAll(/(?:^|[;{\s])(min-width|width)\s*:\s*(\d+)px/g)) assert.ok(+m[2] <= 320, `${m[1]}:${m[2]}px`); });
  await t.test('tokens wrap', () => assert.match(css, /\.token\{[^}]*overflow-wrap:\s*anywhere/));
  await t.test('result, filebox and builder messages wrap long words (Plumb review)', () => {
    const root = /#scan-desk\{[^}]*overflow-wrap:\s*anywhere/.test(css);
    for (const sel of ['.result', '.filebox', '.builder-msg'])
      assert.ok(root || new RegExp('#scan-desk ' + sel.replace('.', '\\.') + '[^{]*\\{[^}]*overflow-wrap:\\s*anywhere').test(css) || new RegExp('[,\\s]#scan-desk ' + sel.replace('.', '\\.') + '\\s*[,{][^}]*overflow-wrap:\\s*anywhere').test(css), sel + ' (or #scan-desk) needs overflow-wrap:anywhere');
  });
  await t.test('textarea full width', () => assert.match(css, /textarea\{[^}]*width:\s*100%/));
});
