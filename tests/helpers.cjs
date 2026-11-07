'use strict';
// Shared loader: evaluates core.js in a fresh VM context, exactly as build.py concatenates it.
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const ROOT = path.join(__dirname, '..');
const read = n => fs.readFileSync(path.join(ROOT, n), 'utf8');

function loadCore() {
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(read('core.js'), ctx, { filename: 'core.js' });
  // Top-level `const` declarations are not context properties; expose them explicitly.
  for (const name of ['CHECKED_FLAGS']) {
    try { ctx[name] = vm.runInContext(`typeof ${name}!=='undefined'?${name}:undefined`, ctx); } catch { /* absent */ }
  }
  const map = ctx.registry(read('catalog.txt'));
  const parse = s => ctx.parse(s, map);
  return { ctx, map, parse };
}

// VM-realm arrays fail deepStrictEqual prototype checks; normalize through JSON.
const plain = x => x === undefined ? undefined : JSON.parse(JSON.stringify(x));
const diags = (p, level) => plain(p.diagnostics || []).filter(d => !level || d.level === level);
const codes = (p, level) => diags(p, level).map(d => d.code);
const errors = p => codes(p, 'error');
const warns = p => codes(p, 'warn');
const notes = p => codes(p, 'note');
const rules = p => diags(p, 'error').filter(d => d.code === 'conflict').map(d => d.rule).sort();
const kinds = p => plain(p.items || []).map(i => i.kind);

module.exports = { plain, ROOT, read, loadCore, diags, codes, errors, warns, notes, rules, kinds };
