// Nmap command parser, builder helpers and IPv4 scope math. Pure functions only: no DOM, no I/O.
// Requirement IDs (R1–R23) refer to REQUIREMENTS.md.

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

function registry(text) {
  const map = new Map();
  let group = '';
  for (const line of text.trim().split(/\r?\n/)) {
    if (line.startsWith('# ')) { group = line.slice(2); continue; }
    const [forms, desc] = line.split('|');
    for (const form of forms.split(' ')) {
      const key = form.replace(/[@?]$/, '');
      const arg = form.endsWith('@') ? 'required' : form.endsWith('?') ? 'attached' : 'none';
      map.set(key, { key, group, desc, arg });
    }
  }
  return map;
}

// ---------------------------------------------------------------------------
// Lexer (POSIX sh word rules, R3–R8)
// ---------------------------------------------------------------------------

// A placeholder: <content>, content 1–64 chars, starts with a letter or _, no trailing space (R8).
const PLACEHOLDER_SRC = '<[A-Za-z_](?:[A-Za-z0-9_ .:/,+-]{0,62}[A-Za-z0-9_.:/,+-])?>';
const PLACEHOLDER_AT = new RegExp('^' + PLACEHOLDER_SRC);
const PLACEHOLDER_ALL = () => new RegExp(PLACEHOLDER_SRC, 'g');
const hasPlaceholder = s => typeof s === 'string' && PLACEHOLDER_ALL().test(s);

const DASH_LOOKALIKE = /^[\u2010-\u2015\u2212]/;
const SMART_QUOTES = '\u201c\u201d\u2018\u2019';
// Unicode spaces that sh does not treat as word separators (R3a).
const UNICODE_SPACE = /[\u00a0\u1680\u2000-\u200b\u202f\u205f\u3000\ufeff]/;
const isBlank = c => c === ' ' || c === '\t' || c === '\r';
const META = ';|&<>()';
// Operators that end the Nmap command (R4). Longest first.
const STOP_OPS = ['||', '|&', '&&', '|', '&', ';', '(', ')'];
// Redirects are skipped with their filename, and parsing continues (R4, Decisions round 2). Longest first.
const REDIRECT_OPS = ['&>>', '&>', '>>', '>|', '>&', '<<', '<>', '<&', '>', '<'];

// Returns {
//   words:  [{v, start, end, afterRedirect}]  shell words in source order,
//   shells: [{start, end, stop, code}]       shell items (redirects, comments, stopping operators, substitutions),
//   diags }
function lex(text) {
  const words = [], shells = [], diags = [], seenDiag = new Set();
  const n = text.length;
  let i = 0, stopped = false, afterRedirect = false;

  const once = (key, d) => { if (!seenDiag.has(key)) { seenDiag.add(key); diags.push(d); } };
  const warnOnce = (code, msg) => once(code, { level: 'warn', code, msg });
  const restIsBlank = pos => !text.slice(pos).trim();
  const trimmedEnd = start => Math.max(text.trimEnd().length, start + 1);
  const startsOp = (ops, pos) => ops.find(op => text.startsWith(op, pos));

  const stopHere = (start, code, msg) => {
    shells.push({ start, end: trimmedEnd(start), stop: true, code });
    warnOnce(code, msg);
    stopped = true;
  };

  // R6, R6a: $NAME, ${…}, and the special parameters warn but stay literal.
  const variableAt = pos => {
    const rest = text.slice(pos + 1);
    let label = null, m;
    if ((m = /^\{#?([A-Za-z_]\w*|[0-9@*#?$!-])?[^}]*\}/.exec(rest))) label = m[1] ? '$' + m[1] : '${' + rest.slice(1, rest.indexOf('}')) + '}';
    else if ((m = /^[A-Za-z_]\w*/.exec(rest))) label = '$' + m[0];
    else if ((m = /^[0-9@*#?$!-]/.exec(rest))) label = '$' + m[0];
    if (!label) return;
    once('var:' + label, { level: 'warn', code: 'shell-variable', msg: `${label} is a shell variable or parameter. It is kept literally here; a real shell would replace it with its value before Nmap runs.` });
  };

  const substitution = start => stopHere(start, 'shell-substitution',
    'Command substitution ($(…) or backticks): a real shell would run another command and paste its output here. That word and everything after it are not interpreted.');

  // Read one word starting at i. Returns {v, start, end}, or null when a substitution stopped parsing.
  function readWord() {
    const start = i;
    let v = '';
    while (i < n) {
      const c = text[i];
      if (isBlank(c) || c === '\n') break;
      if (c === '\\') {
        const next = text[i + 1];
        if (next === undefined) {
          diags.push({ level: 'error', code: 'trailing-escape', msg: 'The command ends with a backslash, so the shell would wait for more input.' });
          i++;
          break;
        }
        if (next !== '\n') v += next; // backslash-newline is a line continuation
        i += 2;
        continue;
      }
      if (c === "'") {
        const close = text.indexOf("'", i + 1);
        if (close < 0) { v += text.slice(i + 1); i = n; unclosed(); break; }
        v += text.slice(i + 1, close);
        i = close + 1;
        continue;
      }
      if (c === '"') {
        i++;
        let closed = false;
        while (i < n) {
          const d = text[i];
          if (d === '"') { closed = true; i++; break; }
          if (d === '\\' && '"\\$`\n'.includes(text[i + 1] ?? '\0')) {
            if (text[i + 1] !== '\n') v += text[i + 1];
            i += 2;
            continue;
          }
          if (d === '`' || (d === '$' && text[i + 1] === '(')) { substitution(start); return null; }
          if (d === '$') variableAt(i);
          v += d;
          i++;
        }
        if (!closed) { unclosed(); break; }
        continue;
      }
      if (c === '`' || (c === '$' && text[i + 1] === '(')) { substitution(start); return null; }
      if (c === '$') variableAt(i);
      if (c === '<') {
        const m = PLACEHOLDER_AT.exec(text.slice(i));
        if (m) { v += m[0]; i += m[0].length; continue; }
      }
      if (META.includes(c)) break;
      if (UNICODE_SPACE.test(c)) {
        const cp = 'U+' + c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
        once('space:' + cp, { level: 'error', code: 'unicode-space', msg: `A non-standard space (${cp}) is inside a word. The shell does not split words on it, so the words around it run together; retype it as a normal space. This usually comes from copying a command off a web page.` });
      }
      if (SMART_QUOTES.includes(c)) warnOnce('smart-quote', `Typographic quote ${c} found. The shell treats it as an ordinary character, not as a quote; use straight quotes (' or ").`);
      v += c;
      i++;
    }
    return { v, start, end: i };
  }
  function unclosed() { diags.push({ level: 'error', code: 'unclosed-quote', msg: 'A quote is not closed, so the shell would wait for more input.' }); }

  while (i < n && !stopped) {
    const c = text[i];
    if (isBlank(c)) { i++; continue; }
    if (c === '\\' && text[i + 1] === '\n') { i += 2; continue; }

    if (c === '\n') {
      if ((words.length || shells.length) && !restIsBlank(i))
        warnOnce('line-break', 'Line break treated as a space; a real shell would run separate commands, one per line.');
      i++;
      continue;
    }

    if (c === '#') {
      // R7: a comment runs to the end of its line; parsing continues on the next line.
      const nl = text.indexOf('\n', i), lineEnd = nl < 0 ? n : nl;
      const stop = restIsBlank(lineEnd);
      shells.push({ start: i, end: i + text.slice(i, lineEnd).trimEnd().length, stop, code: 'shell-comment' });
      warnOnce('shell-comment', 'Shell comment (#): a real shell ignores the rest of the line, so it is not part of the Nmap command.');
      i = lineEnd;
      if (stop) stopped = true;
      continue;
    }

    const isPlaceholder = c === '<' && PLACEHOLDER_AT.test(text.slice(i));
    const redirect = !isPlaceholder && startsOp(REDIRECT_OPS, i);
    if (redirect) {
      let start = i;
      // A file-descriptor number directly before the operator belongs to it (2>/dev/null).
      const last = words.at(-1);
      if (last && last.end === i && c !== '&' && /^\d+$/.test(text.slice(last.start, last.end))) { words.pop(); start = last.start; }
      i += redirect.length;
      let end = i, j = i;
      while (j < n && isBlank(text[j])) j++;
      if (j < n && text[j] !== '\n' && !META.includes(text[j]) && text[j] !== '#') {
        i = j;
        const file = readWord();
        if (file) end = file.end;
      }
      shells.push({ start, end, stop: false, code: 'shell-redirect' });
      warnOnce('shell-redirect', `Redirect ${redirect}: a real shell would redirect input or output there. The operator and its filename are skipped, and the rest of the command is still read.`);
      afterRedirect = true;
      continue;
    }

    const op = !isPlaceholder && startsOp(STOP_OPS, i);
    if (op) {
      stopHere(i, 'shell-operator', `Shell operator ${op} ends the Nmap command here. A real shell would run the rest as a separate step; it is shown as shell syntax and not interpreted.`);
      break;
    }

    const w = readWord();
    if (!w) break;
    w.afterRedirect = afterRedirect;
    afterRedirect = false;
    words.push(w);
  }
  // A substitution inside a redirect filename is pushed before its redirect; keep source order.
  shells.sort((a, b) => a.start - b.start);
  return { words, shells, diags };
}

// ---------------------------------------------------------------------------
// IPv4 target specs (Nmap parse_ipv4_ranges, R9–R10)
// ---------------------------------------------------------------------------

// One octet: '*' or a comma list of N, N-M, -M, N-, '-'. Returns a Uint8Array(256) membership mask or null.
function octetSet(spec) {
  const set = new Uint8Array(256);
  if (spec === '*') return set.fill(1);
  if (spec === '') return null;
  for (const part of spec.split(',')) {
    const m = /^(\d{0,3})(?:(-)(\d{0,3}))?$/.exec(part);
    if (!m || part === '') return null;
    const lo = m[1] === '' ? 0 : +m[1];
    const hi = m[2] ? (m[3] === '' ? 255 : +m[3]) : lo;
    if (lo > hi || hi > 255) return null;
    set.fill(1, lo, hi + 1);
  }
  return set;
}

// Four-octet spec with optional /bits (applied per octet, like apply_ipv4_netmask_bits).
// Returns [Uint8Array x4] or null.
function parseIPv4(term) {
  const m = /^([^/]*)(?:\/(\d{1,2}))?$/.exec(term);
  if (!m) return null;
  const parts = m[1].split('.');
  if (parts.length !== 4) return null;
  const sets = parts.map(octetSet);
  if (sets.includes(null)) return null;
  const bits = m[2] === undefined ? 32 : +m[2];
  if (bits > 32) return null;
  for (let k = 0; k < 4; k++) {
    const hostBits = Math.min(8, Math.max(0, 32 - bits - 8 * (3 - k)));
    if (!hostBits) continue;
    const mask = (1 << hostBits) - 1, out = new Uint8Array(256);
    for (let v = 0; v < 256; v++) if (sets[k][v]) out.fill(1, v & ~mask, (v | mask) + 1);
    sets[k] = out;
  }
  return sets;
}

// Looks like a dotted-quad spec, so a parse failure is a typo rather than a hostname.
const looksIPv4 = t => /^[\d*,-]*(?:\.[\d*,-]*){3}(?:\/.*)?$/.test(t);
const isIPv4 = t => looksIPv4(t) && !!parseIPv4(t);
const isIPv6 = t => /^[0-9a-f:.]+(?:%[\w.-]+)?(?:\/\d{1,3})?$/i.test(t) && (t.match(/:/g) || []).length >= 2;

// |∪inc − ∪exc| for per-octet product sets, by recursive partition over octets.
// Never enumerates addresses, so 0.0.0.0/0 and *.*.*.* are cheap.
function countIPv4(inc, exc) {
  const size = s => { let c = 0; for (let v = 0; v < 256; v++) c += s[v]; return c; };
  function rec(A, B, d) {
    if (!A.length) return 0;
    if (d === 4) return B.length ? 0 : 1;
    if (!B.length && A.length === 1) { let p = 1; for (let k = d; k < 4; k++) p *= size(A[0][k]); return p; }
    const all = A.concat(B), groups = new Map();
    for (let v = 0; v < 256; v++) {
      let key = '';
      for (let j = 0; j < all.length; j++) if (all[j][d][v]) key += j + ',';
      if (key) groups.set(key, (groups.get(key) || 0) + 1);
    }
    let total = 0;
    for (const [key, count] of groups) {
      const idx = key.slice(0, -1).split(',').map(Number);
      const a = idx.filter(j => j < A.length).map(j => all[j]);
      if (!a.length) continue;
      const b = idx.filter(j => j >= A.length).map(j => all[j]);
      total += count * rec(a, b, d + 1);
    }
    return total;
  }
  return rec(inc, exc, 0);
}

// ---------------------------------------------------------------------------
// Value checks (R12, R13)
// ---------------------------------------------------------------------------

const INT = /^\d+$/;
const intIn = (lo, hi) => v => INT.test(v) && +v >= lo && +v <= hi;
const timeMs = v => {
  const m = /^(\d+(?:\.\d+)?|\.\d+)(ms|s|m|h)?$/.exec(v); // strtod-style: 5, 0.5, .5 (not '.' or '5.')
  return m ? +m[1] * { ms: 1, s: 1000, m: 60000, h: 3600000 }[m[2] || 's'] : null;
};
const timeAtLeast = minMs => v => { const ms = timeMs(v); return ms !== null && ms >= minMs; };
const TIMING_NAMES = ['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'];

function validPortList(v) {
  // Split on top-level commas; commas inside [...] belong to the group.
  const items = [];
  let depth = 0, cur = '';
  for (const c of v) {
    if (c === '[') depth++;
    if (c === ']') depth--;
    if (c === ',' && depth === 0) { items.push(cur); cur = ''; continue; }
    cur += c;
  }
  items.push(cur);
  const port = s => INT.test(s) && +s <= 65535;
  const single = s => {
    if (s === '-') return true;
    const m = /^(\d*)-(\d*)$/.exec(s);
    if (m) {
      if ((m[1] && !port(m[1])) || (m[2] && !port(m[2]))) return false;
      return !m[1] || !m[2] || +m[1] <= +m[2];
    }
    if (INT.test(s)) return port(s);
    return /^[a-z*?][a-z0-9*?_.+-]*$/.test(s); // service name pattern
  };
  // Nmap skips spaces around list items (scan_lists.cc getpts).
  return items.every(raw => {
    const s = raw.trim().replace(/^[TUSP]:\s*/, '');
    if (s.startsWith('[')) return s.endsWith(']') && s.length > 2 && validPortList(s.slice(1, -1));
    return s !== '' && single(s);
  });
}

// key → [isValid(value), hint]. Bounds from Nmap 7.993 (nmap.cc, NmapOps.cc).
const VALUE_RULES = {
  '-T': [v => /^[0-5]$/.test(v) || TIMING_NAMES.includes(v.toLowerCase()), 'use 0–5 or a template name (paranoid, sneaky, polite, normal, aggressive, insane).'],
  '-p': [validPortList, 'use a comma list of ports 0–65535, ranges (N-M, -M, N-), lowercase service names, optional T:/U:/S:/P: prefixes, or - for all ports.'],
  '--top-ports': [intIn(1, 65535), 'use a whole number from 1 to 65535.'],
  '--port-ratio': [v => /^(\d+(\.\d*)?|\.\d+)$/.test(v) && +v < 1, 'use a decimal from 0 up to (not including) 1.'],
  '--version-intensity': [intIn(0, 9), 'use a whole number from 0 to 9.'],
  '--max-retries': [v => INT.test(v), 'use a whole number of retries (0 or more).'],
  '--min-rate': [v => /^[\d.eE+]+$/.test(v) && Number.isFinite(+v) && +v > 0, 'use a positive number of packets per second.'],
  '--host-timeout': [timeAtLeast(0), 'use a time such as 30s, 500ms, 5m or 1h.'],
  '--max-rtt-timeout': [timeAtLeast(5), 'use a time of at least 5ms, such as 100ms.'],
  '--initial-rtt-timeout': [timeAtLeast(1), 'use a time of at least 1ms, such as 1s.'],
  '--min-hostgroup': [intIn(1, Infinity), 'use a whole number of at least 1.'],
  '--max-os-tries': [intIn(1, 50), 'use a whole number from 1 to 50.'],
  '--ttl': [intIn(0, 255), 'use a whole number from 0 to 255.'],
  '--mtu': [v => INT.test(v) && +v > 0 && +v % 8 === 0, 'use a positive multiple of 8.'],
  '--data-length': [intIn(0, 65400), 'use a whole number from 0 to 65400.'],
  '-iR': [v => INT.test(v), 'use a whole number (0 means no limit).'],
  '-g': [intIn(0, 65535), 'use a port number from 0 to 65535.'],
  '-v': [v => /^(\d+|v+)$/.test(v), 'attach a number (-v2) or repeat the letter (-vv).'],
  '-d': [v => /^(\d+|d+)$/.test(v), 'attach a number (-d2) or repeat the letter (-dd).'],
  '-oA': [v => v !== '-', 'Nmap cannot write multiple output types to standard output (-).'],
};
// Flags checked with another flag's rule.
const SAME_RULE = {
  '--timing': '-T', '--exclude-ports': '-p', '--max-rate': '--min-rate',
  '--scan-delay': '--host-timeout', '--max-scan-delay': '--host-timeout', '--min-rtt-timeout': '--host-timeout',
  '--script-timeout': '--host-timeout', '--stats-every': '--host-timeout',
  '--max-hostgroup': '--min-hostgroup', '--min-parallelism': '--min-hostgroup', '--max-parallelism': '--min-hostgroup', '-M': '--min-hostgroup',
  '--source-port': '-g',
};
// Every flag whose value is checked (R13). README.md "Checked values" lists the same keys.
const CHECKED_FLAGS = [...Object.keys(VALUE_RULES), ...Object.keys(SAME_RULE)];

function checkValue(key, val) {
  const rule = VALUE_RULES[SAME_RULE[key] || key];
  if (!rule || val === null || val === '' || hasPlaceholder(val)) return null;
  return rule[0](val) ? null : `${key} ${val}: ${rule[1]}`;
}

// ---------------------------------------------------------------------------
// Parser (R1–R15)
// ---------------------------------------------------------------------------

const NO_TARGET_NEEDED = ['-iL', '-i', '-iR', '--resume', '--script-help', '--script-updatedb', '-V', '--version', '-h', '--help', '--iflist', '--route-dst'];
const GROUPED_SCAN = /^-s[ACTFMLNOSUVWXnPYZR]{2,}$/;

function isProgram(word) {
  const base = word.split(/[/\\]/).pop().toLowerCase();
  return base === 'nmap' || base === 'nmap.exe';
}

// Resolve one option word to {key, val} (val null when nothing is attached), or null if unknown.
function resolveOption(x, map) {
  let key = x, val = null;
  const eq = x.indexOf('=');
  if (x.startsWith('--') && eq > 0) { key = x.slice(0, eq); val = x.slice(eq + 1); }
  // getopt_long_only: a single-dash long option also takes =value (-oN=x, -script=default).
  else if (eq > 1) {
    const name = x.slice(0, eq);
    const long = map.has('-' + name) ? '-' + name : /^-(?:o[ANGMSHX]|i[LR]|sI|ff|vv|rH)$/.test(name) && map.has(name) ? name : null;
    if (long) return { key: long, val: x.slice(eq + 1) };
  }
  if (!map.has(key) && /^--(?:o[ANGMSHX]|i[LR]|sI|ff|vv|rH)$/.test(key)) key = key.slice(1);
  if (!map.has(key) && /^-[a-z][\w-]+$/.test(key) && map.has('-' + key)) key = '-' + key;
  if (map.has(key)) return { key, val };
  // Attached short argument: the longest short key that takes an argument and prefixes the word.
  const k = [...map.keys()]
    .filter(k => !k.startsWith('--') && x.startsWith(k) && x !== k && map.get(k).arg !== 'none')
    .sort((a, b) => b.length - a.length)[0];
  return k ? { key: k, val: x.slice(k.length) } : null;
}

function parse(text, map) {
  const res = { flags: [], targets: [], items: [], diagnostics: [], issues: [], warnings: [], notes: [], placeholders: [] };
  if (!text.trim()) return res;
  const D = res.diagnostics;
  const err = (code, msg, extra) => D.push({ level: 'error', code, msg, ...extra });
  const warn = (code, msg, extra) => D.push({ level: 'warn', code, msg, ...extra });
  const slice = (s, e) => text.slice(s, e);

  const { words, shells, diags } = lex(text);
  D.push(...diags);

  // Program name (R2).
  let i = 0;
  if (words[0]?.v === 'sudo') i++;
  const prog = words[i];
  if (!prog || !isProgram(prog.v)) err('program', 'Start with nmap (or sudo nmap)' + (prog ? `; this command starts with ${prog.v}.` : '.'));
  if (prog) i++;
  const body = words.slice(i);

  // Options and targets.
  const addFlag = (key, val, start, end) => {
    res.flags.push({ key, val, def: map.get(key), start, end });
    res.items.push({ kind: 'flag', key, val, start, end, text: slice(start, end) });
  };
  const addUnknown = (t, x) => res.items.push({ kind: 'unknown', key: x, val: null, start: t.start, end: t.end, text: slice(t.start, t.end) });
  let ended = false;
  for (let j = 0; j < body.length; j++) {
    const t = body[j], x = t.v;
    if (DASH_LOOKALIKE.test(x)) {
      err('dash-lookalike', `${x} starts with a typographic dash, not '-'. Nmap rejects it ("Unparseable option"); retype the dash.`);
      addUnknown(t, x);
      continue;
    }
    if (!ended && x === '--') { ended = true; continue; }
    if (ended || !x.startsWith('-') || x === '-') {
      const ph = hasPlaceholder(x);
      res.targets.push(x);
      res.items.push({ kind: 'target', val: x, placeholder: ph, start: t.start, end: t.end, text: slice(t.start, t.end) });
      if (!ph) checkTarget(x);
      continue;
    }
    if (!map.has(x) && GROUPED_SCAN.test(x)) {
      for (const ch of x.slice(2)) addFlag('-s' + ch, null, t.start, t.end);
      continue;
    }
    const r = resolveOption(x, map);
    if (!r) {
      err('unknown-flag', `Unrecognized: ${x}. Its arguments and target scope are not verified.`, { key: x });
      res.flags.push({ key: x, val: null, def: undefined, start: t.start, end: t.end });
      addUnknown(t, x);
      continue;
    }
    let { key, val } = r, end = t.end;
    const def = map.get(key);
    if (def.arg === 'required' && val === null) {
      const next = body[j + 1];
      if (next && !next.afterRedirect && (!next.v.startsWith('-') || next.v === '-' || (key === '--script-args' && next.v.includes('=')))) { val = next.v; end = next.end; j++; }
      else err('missing-value', `${key} needs a value.`, { key });
    }
    if (val === '' && def.arg === 'required') err('empty-value', `${key} has an empty value.`, { key });
    if (def.arg === 'none' && val !== null) err('unexpected-value', `${key} does not take a value.`, { key });
    if (key === '-oH' || key === '-O1') err('unsupported', `${key} is rejected by this Nmap release.`, { key });
    const bad = checkValue(key, val);
    if (bad) err('bad-value', bad, { key });
    addFlag(key, val, t.start, end);
  }
  for (const sh of shells) res.items.push({ kind: 'shell', stop: sh.stop, start: sh.start, end: sh.end, text: slice(sh.start, sh.end) });
  res.items.sort((a, b) => a.start - b.start);

  // Placeholders (R8): every word after the program, in source order.
  for (const w of body) for (const m of w.v.matchAll(PLACEHOLDER_ALL())) if (!res.placeholders.includes(m[0])) res.placeholders.push(m[0]);

  checkCombinations();

  if (!res.targets.length && !res.flags.some(f => f.def && NO_TARGET_NEEDED.includes(f.key))) err('no-target', 'No target supplied.');

  for (const ph of res.placeholders) D.push({ level: 'note', code: 'placeholder', msg: `${ph} is a placeholder: fill this in with a real value before running.` });

  res.issues = D.filter(d => d.level === 'error').map(d => d.msg);
  res.warnings = D.filter(d => d.level === 'warn').map(d => d.msg);
  res.notes = D.filter(d => d.level === 'note').map(d => d.msg);
  return res;

  // R9.
  function checkTarget(x) {
    if ((/^[\d,]+$/.test(x) && x.includes(',')) || x.endsWith(','))
      err('bad-target', `${x} looks like part of a port list, not a target. Check for a space inside a -p list.`);
    else if (looksIPv4(x) && !parseIPv4(x))
      err('bad-target', `${x} is not a valid IPv4 address, range or CIDR (octets 0–255, ranges low-high, prefix /0–/32).`);
  }

  // R14 conflicts and R15 no-effect warnings.
  function checkCombinations() {
    const keys = res.flags.filter(f => f.def).map(f => f.key);
    const count = (...ks) => keys.filter(k => ks.includes(k)).length;
    const has = (...ks) => count(...ks) > 0;
    const num = k => Number(res.flags.find(f => f.key === k)?.val);
    const conflict = (rule, msg) => err('conflict', msg, { rule });

    const TCP = ['-sA', '-b', '-sT', '-sF', '-sI', '-sM', '-sN', '-sS', '-sW', '-sX'];
    const SCANS = [...TCP, '-sU', '-sY', '-sZ', '-sO'];
    const tcpTypes = [...new Set(keys.filter(k => TCP.includes(k)))];
    if (tcpTypes.length > 1) conflict('tcp-scan-types', `Only one TCP scan type can be used at a time (${tcpTypes.join(', ')}).`);
    if (has('-sO') && has(...TCP, '-sU', '-sY', '-sZ')) conflict('ipproto-alone', 'The IP protocol scan (-sO) cannot be combined with TCP, UDP or SCTP scan types.');
    if (has('-sL', '-sn', '-sP') && has(...SCANS)) conflict('noportscan-with-scan', 'A list scan (-sL) or ping scan (-sn) cannot be combined with a port scan type.');
    if (has('-p', '-F') && has('-sn', '-sP', '-sL')) conflict('ports-without-portscan', 'Port selection (-p or -F) is refused with -sn or -sL, which skip the port scan.');
    if (has('-O', '-O2') && has('-sn', '-sP')) conflict('os-without-portscan', 'OS detection (-O) needs a port scan, so it cannot be combined with -sn.');
    if (has('-F') && has('-p')) conflict('fast-and-ports', 'Fast mode (-F) and an explicit port list (-p) cannot both be used.');
    if (count('-p') > 1 || count('--exclude-ports') > 1) conflict('duplicate-ports', 'Ports can be given only once; combine them into one comma list.');
    if (count('-PS') > 1 || count('-PA', '-PB', '-PT') > 1 || count('-PU') > 1 || count('-PY') > 1 || count('-PO') > 1)
      conflict('duplicate-ping-ports', 'A discovery probe type can be given only once; combine its ports into one list.');
    const all3 = count('-oA');
    if (count('-oN', '-o') + all3 > 1 || count('-oG', '-oM', '-m') + all3 > 1 || count('-oX') + all3 > 1 || count('-oS') > 1)
      conflict('duplicate-output', 'The same output format is requested more than once (-oA already includes normal, XML and grepable output).');
    if (count('-iL', '-i') > 1) conflict('duplicate-input', 'Only one input list (-iL) can be given.');

    const both = has('-4') && has('-6');
    if (both) conflict('both-families', 'Choose either IPv4 (-4) or IPv6 (-6), not both.');
    else {
      const excludes = res.flags.filter(f => f.key === '--exclude' && f.val).flatMap(f => f.val.split(','));
      if (has('-6') && (res.targets.some(isIPv4) || excludes.some(isIPv4))) conflict('ip-family', '-6 selects IPv6, but an IPv4 address, range or CIDR is given.');
      else if (has('-4') && res.targets.some(isIPv6)) conflict('ip-family', '-4 selects IPv4, but an IPv6 address is given.');
    }
    if (!has('-6') && res.targets.some(isIPv6)) warn('ipv6-needs-6', 'IPv6 targets need -6; without it Nmap scans as IPv4.');

    if (has('--min-rate', '--max-rate') && num('--min-rate') > num('--max-rate')) conflict('rate-order', '--min-rate is higher than --max-rate.');
    const maxPar = has('--max-parallelism') ? num('--max-parallelism') : num('-M');
    if (has('--min-parallelism') && num('--min-parallelism') > maxPar) conflict('parallelism-order', '--min-parallelism is higher than --max-parallelism.');
    if (has('--min-hostgroup') && num('--min-hostgroup') > num('--max-hostgroup')) conflict('hostgroup-order', '--min-hostgroup is higher than --max-hostgroup.');
    if (has('--resume') && (res.flags.length > 1 || res.targets.length)) conflict('resume-alone', '--resume must be used alone: the saved log supplies the targets and options.');
    if (has('--defeat-rst-ratelimit') && !has('-sS', '--open')) conflict('defeat-rst', '--defeat-rst-ratelimit works only with a SYN scan (-sS) or --open.');
    if (has('--defeat-icmp-ratelimit') && !has('-sU')) conflict('defeat-icmp', '--defeat-icmp-ratelimit works only with a UDP scan (-sU).');

    const noEffect = (ks, needs, what) => { for (const k of ks) if (has(k) && !has(...needs)) warn('no-effect', `${k} has no effect without ${what}.`, { key: k }); };
    noEffect(['--version-intensity', '--version-light', '--version-all', '--version-trace', '--allports'], ['-sV', '-sR', '-A'], 'service detection (-sV or -A)');
    noEffect(['--osscan-limit', '--osscan-guess', '--fuzzy', '--max-os-tries'], ['-O', '-O2', '-A'], 'OS detection (-O or -A)');
    noEffect(['--script-args', '--script-args-file', '--script-trace', '--script-timeout'], ['--script', '-sC', '-A'], 'scripts (--script, -sC or -A)');
  }
}

// ---------------------------------------------------------------------------
// Scope (R10, R11)
// ---------------------------------------------------------------------------

function scope(p, files) {
  if (p.issues.length) return '';
  const lists = p.flags.filter(f => ['-iL', '-i', '--excludefile'].includes(f.key) && f.val !== null);
  const excludes = p.flags.filter(f => f.key === '--exclude' && f.val);
  if (p.flags.some(f => f.key === '-iR')) return 'Random targets are selected at run time.';
  if (p.targets.some(hasPlaceholder) || [...lists, ...excludes].some(f => hasPlaceholder(f.val)))
    return 'Scope unknown until placeholders are filled in.';
  if (lists.some(f => !files.has(f.val))) return 'Scope unknown until the named lists are supplied.';

  const inc = [...p.targets], exc = [];
  for (const f of lists) {
    const terms = files.get(f.val).replace(/#[^\r\n]*/g, ' ').split(/\s+/).filter(Boolean);
    (f.key === '--excludefile' ? exc : inc).push(...terms);
  }
  for (const f of excludes) exc.push(...f.val.split(',').filter(Boolean));
  if (!inc.length && !lists.some(f => f.key !== '--excludefile')) return '';
  const A = inc.map(parseIPv4), B = exc.map(parseIPv4);
  if ([...A, ...B].includes(null)) return 'Scope retained as entered. Exact counting supports IPv4 addresses, octet ranges, wildcards and CIDRs only.';
  const n = countIPv4(A, B);
  return n.toLocaleString('en-US') + ' distinct IPv4 address' + (n === 1 ? '' : 'es') + ' in scope after exclusions (before discovery).';
}

// ---------------------------------------------------------------------------
// Builder helpers (R16, R18)
// ---------------------------------------------------------------------------

function quoteArg(v) {
  if (/^[A-Za-z0-9_./:,=+@%-]+$/.test(v)) return v;
  return "'" + v.replaceAll("'", "'\\''") + "'";
}

function buildOption(key, value, map) {
  const d = map.get(key), v = value ?? '';
  if (!d || d.arg === 'none') return key;
  const attached = () => key + (key.startsWith('--') ? '=' : '') + quoteArg(v);
  if (d.arg === 'attached') return v === '' ? key : attached();
  return v.startsWith('-') && v !== '-' ? attached() : key + ' ' + quoteArg(v);
}

// Remove items[index] from the raw text, leaving every other byte unchanged.
function removeItem(text, p, index) {
  const it = p.items[index];
  if (!it) return text;
  if (it.kind === 'flag') {
    const peers = p.items.filter(x => x.kind === 'flag' && x.start === it.start && x.end === it.end);
    if (peers.length > 1) {
      const letters = peers.filter(x => x !== it).map(x => x.key.slice(2)).join('');
      return text.slice(0, it.start) + '-s' + letters + text.slice(it.end);
    }
  }
  let start = it.start;
  while (start > 0 && /\s/.test(text[start - 1])) start--;
  return text.slice(0, start) + text.slice(it.end);
}

// ---------------------------------------------------------------------------
// URL hash (R23)
// ---------------------------------------------------------------------------

function encodeHash(cmd) { return '#cmd=' + encodeURIComponent(cmd); }

function decodeHash(h) {
  if (typeof h !== 'string') return null;
  const pair = h.replace(/^#/, '').split('&').find(s => s.startsWith('cmd='));
  if (pair === undefined) return null;
  try {
    const v = decodeURIComponent(pair.slice(4));
    return v.length > 8000 ? null : v;
  } catch { return null; }
}
