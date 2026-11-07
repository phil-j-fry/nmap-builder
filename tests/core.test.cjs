'use strict';
// R1–R15: parser contract, shell safety, placeholders, targets, scope, values, conflicts.
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadCore, plain, errors, warns, notes, rules, kinds, diags, read } = require('./helpers.cjs');
const { ctx, map, parse } = loadCore();
const T = p => plain(p.targets);
const scope = (cmd, files = {}) => ctx.scope(parse(cmd), new Map(Object.entries(files)));
const count = (cmd, files) => { const s = scope(cmd, files); const m = /^([\d,]+) distinct IPv4 address(?:es)? in scope after exclusions \(before discovery\)\.$/.exec(s); assert.ok(m, `expected a count for ${cmd}, got ${JSON.stringify(s)}`); return Number(m[1].replaceAll(',', '')); };
const OT = 'nmap -sT -n -p 102,502,2404,4840,20000,44818 --max-rate 10 --max-retries 1 -iL ot-ranges.txt --excludefile exclude.txt -oA $R/ot-find';

test('R1 result contract', async t => {
  const inputs = ['', '   ', 'nmap', OT, 'nmap -oN x > log 10.0.0.1 2>&1 | tee y', 'nmap -sSU <host> --made-up 10.0.0.1 | grep x', 'nmap "unclosed', 'nmap -oX "a b" 10.0.0.1'];
  for (const s of inputs) await t.test(JSON.stringify(s), () => {
    const p = parse(s);
    for (const f of ['flags', 'targets', 'items', 'diagnostics', 'issues', 'warnings', 'notes', 'placeholders']) assert.ok(Array.isArray(plain(p[f])), `missing array field ${f}`);
    const items = plain(p.items);
    for (let i = 1; i < items.length; i++) assert.ok(items[i].start >= items[i - 1].start, 'items sorted by start');
    for (const it of items) {
      assert.ok(['flag', 'unknown', 'target', 'shell'].includes(it.kind), 'kind ' + it.kind);
      assert.equal(it.text, s.slice(it.start, it.end), 'item text equals source slice');
      if (it.kind === 'shell') assert.equal(typeof it.stop, 'boolean', 'shell items carry stop');
    }
    for (const d of diags(p)) { assert.ok(['error', 'warn', 'note'].includes(d.level)); assert.equal(typeof d.code, 'string'); assert.equal(typeof d.msg, 'string'); }
    assert.deepEqual(plain(p.issues), diags(p, 'error').map(d => d.msg));
    assert.deepEqual(plain(p.warnings), diags(p, 'warn').map(d => d.msg));
    assert.deepEqual(plain(p.notes), diags(p, 'note').map(d => d.msg));
  });
  await t.test('empty input has no diagnostics', () => { assert.deepEqual(diags(parse('')), []); assert.deepEqual(diags(parse(' \n\t ')), []); });
  await t.test('grouped scan items share span', () => {
    const it = plain(parse('nmap -sSU 10.0.0.1').items).filter(i => i.kind === 'flag');
    assert.deepEqual(it.map(i => i.key), ['-sS', '-sU']);
    assert.equal(it[0].start, it[1].start); assert.equal(it[0].end, it[1].end);
  });
  await t.test('target items carry placeholder flag', () => {
    const it = plain(parse('nmap <host> 10.0.0.1').items).filter(i => i.kind === 'target');
    assert.deepEqual(it.map(i => i.placeholder), [true, false]);
  });
});

test('R2 program name', async t => {
  const ok = ['nmap', 'NMAP', 'Nmap', 'nmap.exe', 'NMAP.EXE', '/usr/bin/nmap', './nmap', '/opt/nmap-7.993/bin/nmap', "'C:\\Program Files (x86)\\Nmap\\nmap.exe'", 'sudo nmap'];
  for (const prog of ok) await t.test('accept ' + prog, () => {
    const p = parse(prog + ' -sS 10.0.0.1');
    assert.ok(!errors(p).includes('program'), JSON.stringify(plain(p.issues)));
    assert.deepEqual(plain(p.flags).map(f => f.key), ['-sS']); assert.deepEqual(T(p), ['10.0.0.1']);
  });
  const bad = ['nmapx', 'nmap2', '/usr/bin/nmap-foo', 'notnmap', 'nmap.exe.bak', '/usr/bin/', 'sudo', 'sudo -u root nmap', 'doas nmap', 'FOO=1 nmap', '; nmap', '"nmap "', '\u2013sS'];
  for (const prog of bad) await t.test('reject ' + prog, () => {
    const p = parse(prog + ' 10.0.0.1');
    assert.equal(errors(p).filter(c => c === 'program').length, 1, JSON.stringify(plain(p.issues)));
  });
});

test('R3 lexing', async t => {
  await t.test('quotes join', () => { const p = parse(`nmap -oX "a b" 'c d'x 10.0.0.1`); assert.equal(p.flags[0].val, 'a b'); assert.deepEqual(T(p), ['c dx', '10.0.0.1']); });
  await t.test('unclosed quote', () => assert.ok(errors(parse('nmap -oX "a b 10.0.0.1')).includes('unclosed-quote')));
  await t.test('trailing escape', () => assert.ok(errors(parse('nmap 10.0.0.1 \\')).includes('trailing-escape')));
  await t.test('line continuation', () => { const p = parse('nmap -sS \\\n 10.0.0.1'); assert.deepEqual(diags(p), []); assert.deepEqual(T(p), ['10.0.0.1']); });
  for (const dash of ['\u2010', '\u2011', '\u2012', '\u2013', '\u2014', '\u2015', '\u2212']) await t.test('dash lookalike U+' + dash.codePointAt(0).toString(16), () => {
    const p = parse(`nmap ${dash}sS 10.0.0.1`);
    assert.ok(errors(p).includes('dash-lookalike'));
    assert.deepEqual(T(p), ['10.0.0.1']);
    assert.match(diags(p, 'error').find(d => d.code === 'dash-lookalike').msg, new RegExp(dash + 'sS'));
  });
  await t.test('smart quotes warn', () => { const p = parse('nmap --script=\u201cdefault\u201d 10.0.0.1'); assert.ok(warns(p).includes('smart-quote')); assert.equal(p.flags[0].val, '\u201cdefault\u201d'); });
  await t.test('quoted smart quotes do not warn', () => assert.ok(!warns(parse("nmap --script='\u201cx\u201d' 10.0.0.1")).includes('smart-quote')));
});

test('R4 shell operators stop parsing (Decisions round 2)', async t => {
  await t.test('; rm -rf /', () => {
    const s = 'nmap 10.0.0.1; rm -rf /', p = parse(s);
    assert.deepEqual(T(p), ['10.0.0.1']);
    assert.deepEqual(kinds(p), ['target', 'shell']);
    const sh = plain(p.items).at(-1);
    assert.equal(sh.text, '; rm -rf /'); assert.equal(sh.stop, true);
    assert.deepEqual(warns(p), ['shell-operator']); assert.deepEqual(errors(p), []);
    assert.match(diags(p, 'warn')[0].msg, /;/);
  });
  for (const op of ['|', '||', '&', '&&', '|&', '(', ')']) await t.test('stop operator ' + op, () => {
    for (const s of [`nmap -sS 10.0.0.1 ${op} evil -x`, `nmap -sS 10.0.0.1${op}evil -x`]) {
      const p = parse(s);
      assert.deepEqual(T(p), ['10.0.0.1'], s);
      assert.equal(warns(p).filter(c => c === 'shell-operator').length, 1, s);
      assert.ok(!kinds(p).includes('unknown'), s + ' must not parse -x');
      assert.equal(kinds(p).at(-1), 'shell');
      assert.equal(kinds(p).filter(k => k === 'shell').length, 1);
    }
  });
  await t.test('background &', () => { const p = parse('nmap -sS 10.0.0.1 &'); assert.deepEqual(T(p), ['10.0.0.1']); assert.ok(warns(p).includes('shell-operator')); });
  await t.test('value never taken from shell segment', () => assert.ok(errors(parse('nmap -oN | tee x 10.0.0.1')).includes('missing-value')));
  for (const s of ["nmap 'a;b' 10.0.0.1", 'nmap "a|b" 10.0.0.1', 'nmap a\\;b 10.0.0.1', "nmap 'x > y' 10.0.0.1", 'nmap "a&&b" 10.0.0.1', 'nmap a\\>b 10.0.0.1'])
    await t.test('literal: ' + s, () => { const p = parse(s); assert.deepEqual(warns(p), []); assert.equal(T(p).length, 2); });
  await t.test('literal values keep text', () => assert.deepEqual(T(parse("nmap 'a;b' a\\;b")), ['a;b', 'a;b']));
});

test('R4r redirects are skipped and parsing continues (Decisions round 2)', async t => {
  const cases = [
    // [command, targets, flag keys, shell item texts]
    ['nmap -oN x > log 10.0.0.1', ['10.0.0.1'], ['-oN'], ['> log']],
    ['nmap -oN x >log 10.0.0.1', ['10.0.0.1'], ['-oN'], ['>log']],
    ['nmap 10.0.0.1 >> all.txt -sS', ['10.0.0.1'], ['-sS'], ['>> all.txt']],
    ['nmap 10.0.0.1 2>/dev/null -sS', ['10.0.0.1'], ['-sS'], ['2>/dev/null']],
    ['nmap 10.0.0.1 2> err.txt -sS', ['10.0.0.1'], ['-sS'], ['2> err.txt']],
    ['nmap 10.0.0.1 &>/dev/null -sS', ['10.0.0.1'], ['-sS'], ['&>/dev/null']],
    ['nmap 10.0.0.1 >| out -sS', ['10.0.0.1'], ['-sS'], ['>| out']],
    ['nmap -iL - < hosts.txt -sn', [], ['-iL', '-sn'], ['< hosts.txt']],
    ["nmap 10.0.0.1 > 'my log.txt' -sS", ['10.0.0.1'], ['-sS'], ["> 'my log.txt'"]],
    ['nmap 10.0.0.1 > a 2> b 10.0.0.2', ['10.0.0.1', '10.0.0.2'], [], ['> a', '2> b']],
    ['nmap 10.0.0.1>out', ['10.0.0.1'], [], ['>out']],
  ];
  for (const [s, targets, flags, shells] of cases) await t.test(s, () => {
    const p = parse(s), items = plain(p.items);
    assert.deepEqual(T(p), targets, 'targets');
    assert.deepEqual(plain(p.flags).map(f => f.key), flags, 'flags');
    const sh = items.filter(i => i.kind === 'shell');
    assert.deepEqual(sh.map(i => i.text), shells, 'shell items');
    assert.ok(sh.every(i => i.stop === false), 'redirect items have stop:false');
    assert.ok(warns(p).includes('shell-redirect'), JSON.stringify(plain(p.warnings)));
    assert.ok(!warns(p).includes('shell-operator'));
    assert.deepEqual(errors(p), [], JSON.stringify(plain(p.issues)));
  });
  await t.test('2>&1 then pipe', () => {
    const p = parse('nmap 10.0.0.1 2>&1 | tee x');
    assert.deepEqual(plain(p.items).filter(i => i.kind === 'shell').map(i => [i.text, i.stop]), [['2>&1', false], ['| tee x', true]]);
    assert.ok(warns(p).includes('shell-redirect')); assert.ok(warns(p).includes('shell-operator'));
    assert.deepEqual(T(p), ['10.0.0.1']);
  });
  await t.test('redirect target never becomes a value', () => { const p = parse('nmap -oN > log 10.0.0.1'); assert.ok(errors(p).includes('missing-value')); assert.deepEqual(T(p), ['10.0.0.1']); });
  await t.test('redirect with no filename', () => { const p = parse('nmap 10.0.0.1 >'); assert.ok(warns(p).includes('shell-redirect')); assert.deepEqual(T(p), ['10.0.0.1']); assert.equal(plain(p.items).at(-1).text, '>'); });
  await t.test('placeholder beats redirect', () => { const p = parse('nmap -p <ports> <host>'); assert.deepEqual(warns(p), []); assert.deepEqual(T(p), ['<host>']); });
  await t.test('message mentions redirect', () => assert.match(diags(parse('nmap 10.0.0.1 > log'), 'warn').find(d => d.code === 'shell-redirect').msg, /redirect/i));
});

test('R4n line breaks are joined with a warning (Decisions round 2)', async t => {
  await t.test('two lines', () => {
    const p = parse('nmap -sS\n10.0.0.1');
    assert.deepEqual(T(p), ['10.0.0.1']); assert.deepEqual(plain(p.flags).map(f => f.key), ['-sS']);
    assert.deepEqual(errors(p), []); assert.deepEqual(warns(p), ['line-break']);
    assert.match(p.warnings[0], /line break treated as a space/i); assert.match(p.warnings[0], /separate commands/i);
    assert.ok(!kinds(p).includes('shell'));
  });
  await t.test('one warning for many lines', () => assert.equal(warns(parse('nmap\n-sS\n-n\n10.0.0.1')).filter(c => c === 'line-break').length, 1));
  await t.test('CRLF', () => { const p = parse('nmap -sS\r\n10.0.0.1'); assert.deepEqual(T(p), ['10.0.0.1']); assert.deepEqual(errors(p), []); });
  await t.test('leading and trailing newlines are plain whitespace', () => { for (const s of ['\nnmap 10.0.0.1', 'nmap 10.0.0.1\n', '\n\nnmap 10.0.0.1\n\n']) assert.deepEqual(diags(parse(s)), [], JSON.stringify(s)); });
  await t.test('backslash continuation does not warn', () => assert.deepEqual(diags(parse('nmap -sS \\\n10.0.0.1')), []));
  await t.test('quoted newline is literal', () => { const p = parse("nmap -oN 'a\nb' 10.0.0.1"); assert.ok(!warns(p).includes('line-break')); assert.equal(p.flags[0].val, 'a\nb'); });
  await t.test('comment ends at its line', () => {
    const p = parse('nmap 10.0.0.1 # first host\n-sS 10.0.0.2');
    assert.deepEqual(T(p), ['10.0.0.1', '10.0.0.2']); assert.deepEqual(plain(p.flags).map(f => f.key), ['-sS']);
    assert.ok(warns(p).includes('shell-comment')); assert.ok(warns(p).includes('line-break'));
    assert.equal(plain(p.items).find(i => i.kind === 'shell').text, '# first host');
  });
});

test('R5 command substitution', async t => {
  for (const s of ['nmap 10.0.0.$(echo 1)', 'nmap $(cat t)', 'nmap "$(cat t)"', 'nmap `cat t`', 'nmap "x`id`"', 'nmap -sS "$(cat t)"']) await t.test(s, () => {
    const p = parse(s);
    assert.ok(warns(p).includes('shell-substitution'), JSON.stringify(plain(p.warnings)));
    assert.deepEqual(T(p), []);
    assert.ok(errors(p).includes('no-target'));
    assert.equal(kinds(p).at(-1), 'shell');
  });
  await t.test('substitution word is whole shell item', () => { const s = 'nmap -sS 10.0.0.$(echo 1) 10.0.0.2'; const p = parse(s); assert.equal(plain(p.items).at(-1).text, '10.0.0.$(echo 1) 10.0.0.2'); });
  await t.test('single quotes are literal', () => { const p = parse("nmap -sS '$(id)' 10.0.0.1"); assert.deepEqual(warns(p), []); assert.deepEqual(T(p), ['$(id)', '10.0.0.1']); });
  await t.test('escaped backtick is literal', () => assert.ok(!warns(parse('nmap a\\`b 10.0.0.1')).includes('shell-substitution')));
});

test('R6 variable expansion', async t => {
  await t.test('OT example', () => {
    const p = parse(OT);
    assert.equal(p.flags.length, 8); assert.deepEqual(errors(p), []);
    assert.equal(p.flags.at(-1).val, '$R/ot-find');
    assert.deepEqual(warns(p), ['shell-variable']);
    assert.match(p.warnings[0], /\$R/);
  });
  await t.test('${NAME} and double quotes', () => { for (const s of ['nmap ${HOST}', 'nmap "$HOST"']) { const p = parse(s); assert.ok(warns(p).includes('shell-variable'), s); assert.equal(T(p).length, 1); } });
  for (const s of ["nmap -oA '$R/x' 10.0.0.1", 'nmap -oA \\$R/x 10.0.0.1', 'nmap -oA a$ 10.0.0.1']) await t.test('no warning ' + s, () => assert.deepEqual(warns(parse(s)), []));
});

test('R7 comments', async t => {
  await t.test('trailing comment', () => { const p = parse('nmap 10.0.0.1 #note -sS'); assert.deepEqual(T(p), ['10.0.0.1']); assert.ok(warns(p).includes('shell-comment')); assert.equal(p.flags.length, 0); assert.equal(kinds(p).at(-1), 'shell'); });
  await t.test('hash inside word', () => { const p = parse('nmap host#1'); assert.deepEqual(T(p), ['host#1']); assert.deepEqual(warns(p), []); });
});

test('R8 placeholders', async t => {
  await t.test('corpus line with spaced placeholder', () => {
    const p = parse('nmap -n -sC -sV <host> -oA svc --excludefile exclude.txt --exclude-ports <brittle ports>');
    assert.deepEqual(errors(p), []); assert.deepEqual(warns(p), []);
    assert.deepEqual(plain(p.placeholders), ['<host>', '<brittle ports>']);
    assert.deepEqual(T(p), ['<host>']);
    assert.equal(plain(p.flags).find(f => f.key === '--exclude-ports').val, '<brittle ports>');
    assert.equal(notes(p).filter(c => c === 'placeholder').length, 2);
    for (const m of plain(p.notes)) assert.match(m, /fill this in/i);
    assert.match(p.notes[1], /<brittle ports>/);
  });
  await t.test('embedded in value', () => { const p = parse('nmap -sT -Pn -p <HMI_WEB_PORT>,5900 --max-rate 10 <host>'); assert.deepEqual(errors(p), []); assert.deepEqual(plain(p.placeholders), ['<HMI_WEB_PORT>', '<host>']); });
  await t.test('embedded in word', () => { const p = parse('nmap --resume <name>.nmap'); assert.deepEqual(errors(p), []); assert.deepEqual(plain(p.placeholders), ['<name>']); });
  await t.test('duplicates noted once', () => { const p = parse('nmap -oA full-<host> <host>'); assert.deepEqual(plain(p.placeholders), ['<host>']); assert.equal(notes(p).length, 1); });
  await t.test('quoted placeholder still recognized', () => assert.deepEqual(plain(parse("nmap '<host>'").placeholders), ['<host>']));
  await t.test('placeholder value skips value checks', () => { for (const s of ['nmap -p <ports> <host>', 'nmap -T <speed> <host>', 'nmap --top-ports <n> <host>']) assert.ok(!errors(parse(s)).includes('bad-value'), s); });
  for (const s of ['nmap 10.0.0.1 < a.txt', 'nmap 10.0.0.1 <a.txt', 'nmap 10.0.0.1 <1abc>', 'nmap 10.0.0.1 <host >', 'nmap 10.0.0.1 <>']) await t.test('not a placeholder: ' + s, () => {
    const p = parse(s);
    assert.deepEqual(plain(p.placeholders), []);
    assert.ok(warns(p).includes('shell-redirect'), JSON.stringify(plain(p.warnings)));
    assert.deepEqual(T(p), ['10.0.0.1']);
  });
  await t.test('64 char limit', () => { assert.equal(plain(parse('nmap <' + 'a'.repeat(64) + '>').placeholders).length, 1); assert.equal(plain(parse('nmap <' + 'a'.repeat(65) + '>').placeholders).length, 0); });
});

test('R9 target sanity', async t => {
  for (const s of ['nmap 1091,2222 10.0.0.1', 'nmap 10.0.0.1 80,', 'nmap 10.0.0.999', 'nmap 10.0.0.50-1', 'nmap 10.0.0.1/33', 'nmap 10..0.1', 'nmap 10.0.0.0/24 10.0.0.1-300']) await t.test('bad ' + s, () => {
    const p = parse(s); assert.ok(errors(p).includes('bad-target'), JSON.stringify(plain(p.issues)));
    assert.equal(ctx.scope(p, new Map()), '');
  });
  await t.test('port list message', () => assert.match(diags(parse('nmap 1091,2222 10.0.0.1'), 'error').find(d => d.code === 'bad-target').msg, /port list/i));
  await t.test('fine targets', () => assert.deepEqual(errors(parse('nmap example.com ::1 10.1 scanme.nmap.org 10.0.0.1-5 10.0.*.1')).filter(c => c === 'bad-target'), []));
});

test('R10 IPv4 counting', async t => {
  const cases = [
    ['nmap 192.168.1.1-50', 50], ['nmap 192.168.1.*', 256], ['nmap 10.0.*.1', 256], ['nmap 10.0.0.1,3,5', 3],
    ['nmap 192.168.1.-5', 6], ['nmap 192.168.1.250-', 6], ['nmap 192.168.1-2.1-2', 4], ['nmap 10.0.0.1-10 10.0.0.5-20', 20],
    ['nmap 10.0.0.1-10 --exclude 10.0.0.1-3,10.0.0.10', 6], ['nmap 10.0.1-2.0/24', 512], ['nmap 10.0.0.1', 1],
    ['nmap 10.0.0.0/24 10.0.0.128/25', 256], ['nmap -sn 0.0.0.0/0 --exclude 0.0.0.0/1', 2147483648],
  ];
  for (const [cmd, n] of cases) await t.test(cmd, () => assert.equal(count(cmd), n));
  const heavy = [["nmap '*.*.*.*'", 4294967296], ["nmap '*.*.*.1' --exclude 10.0.0.0/8", 16711680], ['nmap 0-255.0-255.0-255.0-255 0.0.0.0/0', 4294967296], ["nmap '*.*.1-254.1-254' --exclude '10.*.*.*'", 255 * 256 * 254 * 254]];
  for (const [cmd, n] of heavy) await t.test('fast: ' + cmd, () => { const t0 = Date.now(); assert.equal(count(cmd), n); assert.ok(Date.now() - t0 < 2000, 'took ' + (Date.now() - t0) + 'ms'); });
  await t.test('singular grammar', () => assert.equal(scope('nmap 10.0.0.1'), '1 distinct IPv4 address in scope after exclusions (before discovery).'));
  await t.test('exclude list file with ranges', () => assert.equal(count('nmap 10.0.0.0/24 --excludefile e', { e: '10.0.0.1-10\n10.0.0.*' }), 0));
});

test('R11 scope precedence and lists', async t => {
  await t.test('errors hide scope', () => assert.equal(scope('nmap --made-up 10.0.0.1'), ''));
  await t.test('-iR', () => assert.match(scope('nmap -iR 5'), /Random targets/));
  await t.test('placeholder target', () => assert.match(scope('nmap -sV <host>'), /until placeholders are filled in/));
  await t.test('placeholder list name', () => assert.match(scope('nmap -iL <targets> -sn'), /until placeholders are filled in/));
  await t.test('missing list', () => assert.match(scope(OT), /unknown until the named lists are supplied/));
  await t.test('hostname symbolic', () => assert.match(scope('nmap example.com 10.0.0.1'), /Scope retained as entered/));
  await t.test('IPv6 symbolic', () => assert.match(scope('nmap -6 ::1'), /Scope retained as entered/));
  await t.test('applied list with hostname symbolic', () => assert.match(scope('nmap -iL a', { a: 'example.com' }), /Scope retained as entered/));
  await t.test('empty exclude applied', () => assert.equal(count('nmap -iL a --excludefile b', { a: '10.0.0.0/30', b: '' }), 4));
  await t.test('missing exclude unknown', () => assert.match(scope('nmap -iL a --excludefile b', { a: '10.0.0.0/30' }), /unknown/));
  await t.test('empty include applied', () => assert.equal(count('nmap -iL a', { a: '' }), 0));
  await t.test('CRLF, blanks, comments', () => assert.equal(count('nmap -iL a', { a: '# header\r\n10.0.0.1\r\n\r\n10.0.0.2 # two\r\n  \r\n10.0.0.3' }), 3));
  await t.test('same file both roles', () => assert.equal(count('nmap -iL a --excludefile a', { a: '10.0.0.0/24' }), 0));
  await t.test('stdin list', () => { assert.match(scope('nmap -iL -'), /unknown/); assert.equal(count('nmap -iL -', { '-': '10.0.0.1 10.0.0.2' }), 2); });
  await t.test('warnings keep count', () => assert.equal(scope('nmap 10.0.0.1 | grep x'), '1 distinct IPv4 address in scope after exclusions (before discovery).'));
});

const VALUES = {
  '-T': [['0', '5', '3', 'paranoid', 'Sneaky', 'POLITE', 'normal', 'aggressive', 'insane'], ['9', '6', '-1', '4.5', 'fast']],
  '-p': [['22', '1-1024', '-', '-100', '60000-', 'U:53,T:21-25,80', 'http,https', 'http*', 'ht?p', '0', '65535', '[1-1024]', 'T:80,U:161', 'S:1-10', 'P:6', '*'], ['99999', '65536', '100-1', '80,,443', '80,', 'HTTP', 'X:80', '1-2-3', 'abc!', '[80']],
  '--exclude-ports': [['80,443', 'T:9100'], ['70000']],
  '--top-ports': [['1', '100', '65535'], ['0', 'abc', '1.5', '65536']],
  '--port-ratio': [['0', '0.5', '0.999'], ['1', '1.5', 'x']],
  '--version-intensity': [['0', '9', '5'], ['10', 'a']],
  '--max-retries': [['0', '1', '10'], ['x', '1.5']],
  '--min-rate': [['1', '0.5', '100'], ['0', 'abc', 'Infinity']],
  '--max-rate': [['10', '300'], ['0', 'abc', 'Infinity']],
  '--host-timeout': [['30m', '0', '100ms', '1.5h', '30'], ['abc', '5x', '1.2.3']],
  '--scan-delay': [['1s', '0', '500ms'], ['abc', '5x']],
  '--max-scan-delay': [['10s'], ['x']],
  '--min-rtt-timeout': [['100ms', '0'], ['fast']],
  '--max-rtt-timeout': [['100ms', '5ms'], ['4ms', 'x']],
  '--initial-rtt-timeout': [['1ms', '1s'], ['0', 'x']],
  '--script-timeout': [['30s'], ['x']],
  '--stats-every': [['10s'], ['x']],
  '--min-hostgroup': [['1', '64'], ['0', 'x']],
  '--max-hostgroup': [['1', '64'], ['0', 'x']],
  '--min-parallelism': [['1'], ['0', 'x']],
  '--max-parallelism': [['1', '10'], ['0', 'x', '1-p80,102,443,502,1089,']],
  '-M': [['1'], ['0']],
  '--max-os-tries': [['1', '50'], ['0', '51']],
  '--ttl': [['0', '64', '255'], ['256', 'x']],
  '--mtu': [['8', '16', '1496'], ['0', '12', 'x']],
  '--data-length': [['0', '25', '65400'], ['65401', 'x']],
  '-iR': [['0', '100'], ['x']],
  '-g': [['53', '0', '65535'], ['70000', 'x']],
  '--source-port': [['53'], ['70000']],
  '-oA': [['out', 'dir/base'], []],
};
// Negative numbers would be read as a separate option by the parser; test them in attached/equals form.
const NEG = { '-T': '-T-1', '--top-ports': '--top-ports=-5', '--port-ratio': '--port-ratio=-0.1', '--version-intensity': '--version-intensity=-1', '--max-retries': '--max-retries=-1', '--min-rate': '--min-rate=-5', '--ttl': '--ttl=-1', '--data-length': '--data-length=-1', '-iR': '-iR-1', '--host-timeout': '--host-timeout=-1s' };
const canonical = { '-M': '--max-parallelism', '--source-port': '-g', '--timing': '-T' };

test('R12 value checks', async t => {
  const q = v => (/^[\w./:,=*?\[\]-]+$/.test(v) ? v : "'" + v + "'");
  for (const [key, [good, bad]] of Object.entries(VALUES)) {
    // Short options use the attached form so values such as '-100' or '-' are not read as a new option.
    const form = v => (key.startsWith('--') ? key + '=' + q(v) : key + q(v));
    for (const v of good) await t.test(`${key} ${v} ok`, () => { const p = parse('nmap ' + form(v) + ' 10.0.0.1'); assert.ok(!errors(p).includes('bad-value'), JSON.stringify(plain(p.issues))); });
    for (const v of bad) await t.test(`${key} ${v} bad`, () => {
      const p = parse('nmap ' + (key.startsWith('--') ? key + '=' + q(v) : key + q(v)) + ' 10.0.0.1');
      const bv = diags(p, 'error').filter(d => d.code === 'bad-value');
      assert.equal(bv.length, 1, JSON.stringify(plain(p.issues)));
      const want = map.get(key).key;
      assert.ok([want, canonical[key]].includes(bv[0].key), `key ${bv[0].key}`);
    });
  }
  for (const [key, s] of Object.entries(NEG)) await t.test('negative ' + s, () => assert.ok(errors(parse('nmap ' + s + ' 10.0.0.1')).includes('bad-value'), s));
  await t.test('-oA - rejected', () => assert.ok(errors(parse('nmap -oA - 10.0.0.1')).includes('bad-value')));
  await t.test('-oN - allowed', () => assert.deepEqual(errors(parse('nmap -oN - 10.0.0.1')), []));
  await t.test('--timing long form', () => { assert.ok(errors(parse('nmap --timing 9 10.0.0.1')).includes('bad-value')); assert.deepEqual(errors(parse('nmap --timing insane 10.0.0.1')), []); });
  await t.test('-T with separate argument', () => assert.deepEqual(errors(parse('nmap -T 4 10.0.0.1')), []));
  await t.test('-v / -d levels', () => { assert.deepEqual(errors(parse('nmap -v3 -d2 10.0.0.1')), []); for (const s of ['nmap -vx 10.0.0.1', 'nmap -dz 10.0.0.1']) assert.ok(errors(parse(s)).length > 0, s); });
  await t.test('legacy checks are bad-value', () => { assert.ok(errors(parse('nmap --max-rate 0 10.0.0.1')).includes('bad-value')); assert.ok(errors(parse('nmap --max-retries x 10.0.0.1')).includes('bad-value')); });
});

test('R13 checked flags documented', async t => {
  const checked = plain(ctx.CHECKED_FLAGS);
  await t.test('CHECKED_FLAGS exported', () => assert.ok(Array.isArray(checked) && checked.length > 0));
  await t.test('matches R12 table', () => {
    const want = new Set(Object.keys(VALUES).map(k => map.get(k).key)); want.add('-v'); want.add('-d'); want.add('--timing');
    const got = new Set(checked.map(k => map.get(k)?.key ?? k));
    for (const k of want) assert.ok(got.has(k) || got.has(map.get(k)?.key), 'CHECKED_FLAGS missing ' + k);
  });
  await t.test('README lists every checked key', () => {
    const readme = read('README.md'); assert.match(readme, /Checked values/i);
    for (const k of checked) assert.ok(readme.includes(k), 'README missing ' + k);
  });
});

const CONFLICTS = {
  'tcp-scan-types': [['-sS -sT', '-sST', '-sA -sI zombie', '-sF -b ftp.example.com', '-sSUT'], ['-sS -sS', '-sSU', '-sT -sU']],
  'ipproto-alone': [['-sO -sU', '-sO -sS'], ['-sO']],
  'noportscan-with-scan': [['-sn -sS', '-sL -sU', '-sP -sT'], ['-sn -Pn']],
  'ports-without-portscan': [['-sn -p 80', '-sL -F'], []],
  'os-without-portscan': [['-sn -O'], ['-sS -O']],
  'fast-and-ports': [['-F -p 80'], ['-F', '-p 80 --top-ports 10']],
  'duplicate-ports': [['-p 80 -p 443', '--exclude-ports 1 --exclude-ports 2'], []],
  'duplicate-ping-ports': [['-PS22 -PS80', '-PA -PB', '-PU53 -PU161', '-PY -PY', '-PO -PO1'], ['-PS22 -PA80']],
  'duplicate-output': [['-oN a -o b', '-oA x -oX y', '-oG a -m b', '-oG a -oM b', '-oA x -oA y', '-oX a -oX b'], ['-oN a -oX b -oG c', '-oA x -oS y']],
  'duplicate-input': [['-iL a -i b', '-iL a -iL b'], []],
  'both-families': [['-4 -6'], ['-4', '-6 ::1']],
  'rate-order': [['--min-rate 100 --max-rate 10'], ['--min-rate 10 --max-rate 100', '--min-rate 10 --max-rate 10']],
  'parallelism-order': [['--min-parallelism 10 --max-parallelism 2', '--min-parallelism 10 -M 2'], ['--min-parallelism 2 -M 10']],
  'hostgroup-order': [['--min-hostgroup 10 --max-hostgroup 2'], ['--min-hostgroup 2 --max-hostgroup 10']],
  'defeat-rst': [['-sT --defeat-rst-ratelimit'], ['-sS --defeat-rst-ratelimit', '--open --defeat-rst-ratelimit']],
  'defeat-icmp': [['-sS --defeat-icmp-ratelimit'], ['-sU --defeat-icmp-ratelimit']],
};
test('R14 conflicts', async t => {
  for (const [rule, [yes, no]] of Object.entries(CONFLICTS)) {
    for (const flags of yes) await t.test(`${rule}: ${flags}`, () => { const p = parse(`nmap ${flags} 10.0.0.1`); assert.deepEqual(rules(p), [rule], JSON.stringify(plain(p.issues))); });
    for (const flags of no) await t.test(`not ${rule}: ${flags}`, () => { const p = parse(`nmap ${flags} ${flags.includes('-6') ? '::1' : '10.0.0.1'}`); assert.deepEqual(rules(p), [], JSON.stringify(plain(p.issues))); });
  }
  for (const s of ['nmap -6 10.0.0.1', 'nmap -4 ::1', 'nmap -6 10.0.0.0/24', 'nmap -6 10.0.0.1-5', 'nmap -6 ::1 --exclude 10.0.0.1']) await t.test('ip-family: ' + s, () => assert.deepEqual(rules(parse(s)), ['ip-family']));
  await t.test('-6 IPv4 hides scope', () => assert.equal(scope('nmap -6 10.0.0.1'), ''));
  await t.test('-6 hostname ok', () => assert.deepEqual(rules(parse('nmap -6 example.com')), []));
  await t.test('resume-alone', () => { assert.deepEqual(rules(parse('nmap --resume x.nmap -sS')), ['resume-alone']); assert.deepEqual(rules(parse('nmap --resume x.nmap 10.0.0.1')), ['resume-alone']); assert.deepEqual(errors(parse('nmap --resume x.nmap')), []); });
  await t.test('ipv6 without -6 warns', () => { const p = parse('nmap ::1'); assert.ok(warns(p).includes('ipv6-needs-6')); assert.ok(!warns(parse('nmap -6 ::1')).includes('ipv6-needs-6')); });
});

test('R15 no-effect warnings', async t => {
  const yes = ['--version-all', '--version-light', '--version-intensity 5', '--version-trace', '--allports', '--osscan-guess', '--fuzzy', '--osscan-limit', '--max-os-tries 2', '--script-args a=1', '--script-args-file f', '--script-trace', '--script-timeout 5s'];
  for (const f of yes) await t.test('warns ' + f, () => { const p = parse(`nmap ${f} 10.0.0.1`); assert.ok(diags(p, 'warn').some(d => d.code === 'no-effect'), JSON.stringify(plain(p.warnings))); });
  for (const s of ['nmap -sV --version-all 10.0.0.1', 'nmap -A --osscan-guess 10.0.0.1', 'nmap -O --max-os-tries 2 10.0.0.1', 'nmap --script x --script-args a=1 10.0.0.1', 'nmap -sC --script-trace 10.0.0.1', 'nmap -A --version-light 10.0.0.1'])
    await t.test('silent ' + s, () => assert.ok(!warns(parse(s)).includes('no-effect')));
  await t.test('carries key', () => assert.equal(diags(parse('nmap --version-all 10.0.0.1'), 'warn').find(d => d.code === 'no-effect').key, '--version-all'));
});

// ---- Review round 1 additions (Gadfly, 2026-11-07) ----
test('R3a Unicode spaces are not word separators', async t => {
  for (const [s, cp] of [['nmap -sS 10.0.0.1', 'a0'], ['nmap -sS 10.0.0.1', 'a0'], ['nmap -sS 10.0.0.1​', '200b'], ['nmap -p 80 443 10.0.0.1', '2009'], ['nmap -sS ﻿10.0.0.1', 'feff'], ['nmap -sS　 10.0.0.1', '3000']])
    await t.test('U+' + cp, () => {
      const p = parse(s);
      assert.ok(errors(p).includes('unicode-space'), JSON.stringify(plain(p.issues)));
      assert.match(diags(p, 'error').find(d => d.code === 'unicode-space').msg, new RegExp('U\\+' + cp.toUpperCase().padStart(4, '0')));
    });
  await t.test('NBSP glues words like sh does', () => { const p = parse('nmap -sS 10.0.0.1'); assert.deepEqual(T(p), []); });
  await t.test('quoted NBSP is literal and not an error', () => { const p = parse("nmap -oN 'a b' 10.0.0.1"); assert.ok(!errors(p).includes('unicode-space')); assert.equal(p.flags[0].val, 'a b'); });
  await t.test('tabs and spaces still separate', () => assert.deepEqual(T(parse('nmap\t-sS \t10.0.0.1')), ['10.0.0.1']));
});

test('R3b single-dash long option with =', async t => {
  await t.test('-oN=x', () => { const p = parse('nmap -oN=x 10.0.0.1'); assert.equal(p.flags[0].key, '-oN'); assert.equal(p.flags[0].val, 'x'); });
  await t.test('-script=default', () => { const p = parse('nmap -script=default 10.0.0.1'); assert.equal(p.flags[0].key, '--script'); assert.equal(p.flags[0].val, 'default'); });
  await t.test('-max-rate=10', () => { const p = parse('nmap -max-rate=10 10.0.0.1'); assert.equal(p.flags[0].key, '--max-rate'); assert.equal(p.flags[0].val, '10'); assert.deepEqual(errors(p), []); });
});

test('R6a special parameters and ${...} forms', async t => {
  for (const [s, name] of [['nmap $1', '$1'], ['nmap "$@"', '$@'], ['nmap $*', '$*'], ['nmap $#', '$#'], ['nmap $?', '$?'], ['nmap $$', '$$'], ['nmap $!', '$!'], ['nmap ${HOST:-10.0.0.1}', 'HOST'], ['nmap ${#X}', 'X'], ['nmap -oA "${OUT}/x" 10.0.0.1', 'OUT']])
    await t.test(s, () => {
      const p = parse(s), w = diags(p, 'warn').filter(d => d.code === 'shell-variable');
      assert.equal(w.length, 1, JSON.stringify(plain(p.warnings)));
      assert.ok(w[0].msg.includes(name), `message should name ${name}: ${w[0].msg}`);
    });
  for (const s of ["nmap '$1' 10.0.0.1", 'nmap \\$1 10.0.0.1', 'nmap a$ 10.0.0.1', 'nmap $ 10.0.0.1']) await t.test('no warning ' + s, () => assert.ok(!warns(parse(s)).includes('shell-variable')));
});

test('R12a Nmap-accepted spellings', async t => {
  for (const s of ['nmap -p "80, 443" 10.0.0.1', 'nmap -p "80 ,443" 10.0.0.1', "nmap -p 'U:53, T:80' 10.0.0.1", 'nmap --host-timeout .5s 10.0.0.1', 'nmap --scan-delay 0.5 10.0.0.1'])
    await t.test('valid ' + s, () => assert.ok(!errors(parse(s)).includes('bad-value'), JSON.stringify(plain(parse(s).issues))));
  for (const s of ['nmap -p "80,, 443" 10.0.0.1', 'nmap -p " " 10.0.0.1', 'nmap --host-timeout . 10.0.0.1', 'nmap --host-timeout 5. 10.0.0.1'])
    await t.test('invalid ' + s, () => assert.ok(errors(parse(s)).includes('bad-value')));
});

test('R4h here-documents and placeholder redirect targets (review 2)', async t => {
  await t.test('<<EOF body is not parsed', () => {
    const p = parse('nmap -sn -iL - <<EOF\n10.0.0.1\nEOF');
    assert.deepEqual(T(p), []); assert.deepEqual(plain(p.flags).map(f => f.key), ['-sn', '-iL']);
    const sh = plain(p.items).filter(i => i.kind === 'shell');
    assert.equal(sh.length, 1); assert.equal(sh[0].stop, true); assert.equal(sh[0].text, '<<EOF\n10.0.0.1\nEOF');
    assert.ok(warns(p).includes('shell-redirect')); assert.deepEqual(errors(p), []);
    assert.match(diags(p, 'warn').find(d => d.code === 'shell-redirect').msg, /here-document/i);
  });
  await t.test('<<- also stops', () => { const p = parse("nmap -iL - <<-'END'\n\t10.0.0.1\nEND"); assert.deepEqual(T(p), []); assert.equal(plain(p.items).at(-1).stop, true); });
  await t.test('<<< here-string is a skipped redirect', () => { const p = parse("nmap -iL - <<< '10.0.0.1' -sn"); assert.deepEqual(T(p), []); assert.deepEqual(plain(p.flags).map(f => f.key), ['-iL', '-sn']); assert.equal(plain(p.items).find(i => i.kind === 'shell').text, "<<< '10.0.0.1'"); });
  await t.test('placeholder as redirect filename', () => {
    const p = parse('nmap -sS 10.0.0.1 > <outfile> -n');
    assert.deepEqual(T(p), ['10.0.0.1']); assert.deepEqual(plain(p.flags).map(f => f.key), ['-sS', '-n']);
    assert.equal(plain(p.items).find(i => i.kind === 'shell').text, '> <outfile>');
    assert.deepEqual(plain(p.placeholders), ['<outfile>']);
  });
});

test('R6b unclosed ${ (Plumb review)', async t => {
  for (const s of ['nmap ${X x', 'nmap 10.0.0.1 ${HOST', 'nmap "${X" 10.0.0.1']) await t.test(s, () => { const p = parse(s); assert.ok(errors(p).includes('unclosed-expansion'), JSON.stringify(plain(p.issues))); });
  await t.test('closed forms unaffected', () => assert.ok(!errors(parse('nmap ${X} 10.0.0.1')).includes('unclosed-expansion')));
  await t.test('single-quoted is literal', () => assert.ok(!errors(parse("nmap '${X' 10.0.0.1")).includes('unclosed-expansion')));
});
