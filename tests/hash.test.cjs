'use strict';
// R23 pure URL-hash helpers.
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadCore } = require('./helpers.cjs');
const { ctx } = loadCore();

test('R23 encodeHash/decodeHash', async t => {
  const cmds = ['nmap -sS 10.0.0.1', '', 'nmap -oX "my report.xml" #frag & a=b %41 + ünï 🙂', 'nmap 10.0.0.1\nline2', "nmap '<img src=x onerror=alert(1)>'", 'x'.repeat(8000)];
  for (const c of cmds) await t.test('round trip ' + JSON.stringify(c.slice(0, 40)), () => {
    const h = ctx.encodeHash(c);
    assert.equal(h, '#cmd=' + encodeURIComponent(c));
    assert.equal(ctx.decodeHash(h), c);
    assert.equal(ctx.decodeHash(h.slice(1)), c, 'accepts no leading #');
  });
  await t.test('absent → null', () => { for (const h of ['', '#', '#other=1', '#cmdx=1', 'cm=1']) assert.equal(ctx.decodeHash(h), null, h); });
  await t.test('empty cmd → empty string', () => assert.equal(ctx.decodeHash('#cmd='), ''));
  await t.test('among other params', () => assert.equal(ctx.decodeHash('#v=2&cmd=nmap%20x&z=1'), 'nmap x'));
  await t.test('malformed percent → null', () => { for (const h of ['#cmd=%E0%A4%A', '#cmd=%', '#cmd=%zz']) assert.equal(ctx.decodeHash(h), null, h); });
  await t.test('plus is literal', () => assert.equal(ctx.decodeHash('#cmd=a+b'), 'a+b'));
  await t.test('over 8000 chars → null', () => assert.equal(ctx.decodeHash(ctx.encodeHash('x'.repeat(8001))), null));
  await t.test('undefined/null input → null', () => { assert.equal(ctx.decodeHash(undefined), null); assert.equal(ctx.decodeHash(null), null); });
});
