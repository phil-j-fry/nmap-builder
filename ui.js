(() => {
// Browser UI. Text-only DOM insertion throughout (R24); command text never executes.
const root = document.getElementById('scan-desk');
const $ = s => root.querySelector(s);
const map = registry(CATALOG);
const files = new Map();
const cmd = $('.cmd');
let fileKey = '', hashTimer = 0;
const MAX_HASH = 8000; // decodeHash rejects longer commands (R23)

const el = (tag, props = {}, ...kids) => { const e = document.createElement(tag); Object.assign(e, props); e.append(...kids); return e; };
const opt = (v, t = v) => new Option(t, v);
const set = (s, t) => { $(s).textContent = t; };
const lines = (s, msgs) => $(s).replaceChildren(...msgs.map(m => el('p', { textContent: m })));

// ---- Builder controls (R16, R17) ----
$('.category').append(opt('', 'All categories'), ...[...new Set([...map.values()].map(x => x.group))].map(x => opt(x)));

function choose() {
  const d = map.get($('.choice').value);
  set('.hint', d?.desc || 'No matching flags.');
  $('.valuebox').hidden = !d || d.arg === 'none';
  $('.value').required = d?.arg === 'required';
  $('.value').placeholder = d?.arg === 'attached' ? 'Optional, attached' : 'Required';
  $('.add').disabled = !d;
}

function filter() {
  const q = $('.search').value.toLowerCase(), cat = $('.category').value;
  const matches = [...map.values()].filter(d => (!cat || d.group === cat) && (d.key + ' ' + d.desc).toLowerCase().includes(q));
  $('.choice').replaceChildren(...matches.map(d => opt(d.key, d.key + ' · ' + d.desc)));
  choose();
}

// Insert a fragment before the stopping shell item; redirects stay in place (R17).
// Returns false when the command can't take it.
function insert(fragment) {
  const text = cmd.value, p = parse(text, map);
  if (p.diagnostics.some(d => d.code === 'unclosed-quote' || d.code === 'trailing-escape')) {
    set('.builder-msg', 'Close the open quote or remove the trailing backslash in the command first; otherwise the addition would land inside it.');
    return false;
  }
  const stop = p.items.find(it => it.kind === 'shell' && it.stop);
  const head = text.slice(0, stop ? stop.start : text.length).trimEnd() || 'nmap';
  cmd.value = head + ' ' + fragment + (stop ? ' ' + stop.text : '');
  set('.builder-msg', '');
  changed();
  return true;
}

function addOption() {
  const d = map.get($('.choice').value), field = $('.value'), v = field.value.trim();
  if (!d) return;
  if (d.arg === 'required' && !v) { field.reportValidity(); return; }
  if (insert(buildOption(d.key, d.arg === 'none' ? '' : v, map))) field.value = '';
}

// Split on whitespace, keeping <spaced placeholders> whole.
const TARGET_WORDS = new RegExp('(?:' + PLACEHOLDER_SRC + '|[^\\s<]+|<)+', 'g');
function addTarget() {
  const field = $('.target'), words = field.value.match(TARGET_WORDS) || [];
  if (!words.length) return;
  const dash = words.find(w => w.startsWith('-'));
  if (dash) { set('.builder-msg', `${dash} starts with "-", so Nmap would read it as an option, not a target.`); return; }
  if (insert(words.map(quoteArg).join(' '))) field.value = '';
}

const onEnter = fn => e => { if (e.key === 'Enter') { e.preventDefault(); fn(); } };
$('.search').addEventListener('input', filter);
$('.category').addEventListener('change', filter);
$('.choice').addEventListener('change', choose);
$('.add').addEventListener('click', addOption);
$('.addtarget').addEventListener('click', addTarget);
$('.value').addEventListener('keydown', onEnter(addOption));
$('.target').addEventListener('keydown', onEnter(addTarget));

// ---- Explanation ----
function interpret(p) {
  const get = k => p.flags.find(a => a.key === k), any = (...ks) => ks.some(get), v = k => get(k)?.val;
  const out = [];
  if (any('--resume')) return 'Resume the scan recorded in ' + v('--resume') + '. Its targets and earlier options depend on the saved log.';
  if (any('-h', '--help', '--iflist', '--version', '-V', '--script-updatedb', '--script-help', '--route-dst', '--thc'))
    return p.flags.filter(a => a.def).map(a => a.def.desc + (a.val ? ' (' + a.val + ')' : '')).join(' ');
  if (!p.flags.length && !p.targets.length) return 'Enter a command to see its meaning.';
  if (p.targets.length) out.push('Target ' + p.targets.join(', ') + '.');
  if (any('-iL', '-i')) out.push('Read targets from ' + (v('-iL') || v('-i')) + '.');
  if (get('--excludefile')) out.push('Leave out addresses listed in ' + v('--excludefile') + '.');
  if (get('--exclude')) out.push('Exclude ' + v('--exclude') + '.');
  const skipDiscovery = any('-Pn', '-PN', '-P0', '-PD');
  if (any('-sL')) out.push('List matching targets without sending probes to those targets.');
  else if (any('-sn', '-sP')) out.push(skipDiscovery ? 'Treat targets as up and skip the port scan.' : 'Look for responsive hosts without running a port scan.');
  else {
    out.push(skipDiscovery ? 'Treat each target as online for scanning.' : 'First discover responsive hosts.');
    const methods = p.flags.filter(a => a.def?.group === 'Scan methods' && a.key !== '--scanflags');
    out.push(methods.length ? methods.map(a => a.def.desc).join(' ') : 'Use the default port scan: normally TCP SYN with raw-packet privileges, otherwise TCP connect.');
    if (get('-p')) { const value = v('-p'); out.push(value === '-' ? 'Select ports 1 through 65535.' : 'Use the port or protocol selection ' + (value || '(missing)') + '.'); }
    else if (!any('--top-ports', '--port-ratio', '-F', '-sO')) out.push('Normally check the 1,000 most common ports of each scanned transport protocol.');
  }
  if (get('-n')) out.push('Do not look up names for IP addresses.');
  if (get('--max-rate')) out.push('Limit discovery and port-probe sending to an average of ' + v('--max-rate') + ' per second across the scan.');
  if (get('--max-retries')) out.push('Allow at most ' + v('--max-retries') + ' retransmission(s) per unanswered port-scan probe.');
  if (get('-oA')) out.push('Request ' + ['.nmap', '.xml', '.gnmap'].map(x => v('-oA') + x).join(', ') + '.');
  if (any('-sV', '-sR') && !get('-A')) out.push('Probe services to try to identify their software and versions.');
  if (get('-A')) out.push(get('-A').def.desc);
  if (p.issues.length) out.unshift('Partial interpretation: see the problems below.');
  return out.join(' ');
}

// ---- Named lists (R22) ----
function fileUI(p) {
  const names = [...new Set(p.flags.filter(a => ['-i', '-iL', '--excludefile'].includes(a.key) && a.val && !hasPlaceholder(a.val)).map(a => a.val))];
  const key = JSON.stringify(names);
  if (key === fileKey) return;
  fileKey = key;
  const box = $('.filebox');
  box.replaceChildren();
  if (!names.length) return;
  const panel = el('details', { open: true }, el('summary', { textContent: 'Calculate scope from list contents' }));
  for (const name of names) {
    const area = el('textarea', { maxLength: 32000, value: files.get(name) || '', placeholder: 'Paste IPv4 addresses, ranges or CIDRs; # starts a comment.' });
    const apply = el('button', { type: 'button', textContent: 'Apply list' });
    const label = el('label', { textContent: name === '-' ? 'standard input (-)' : name }, area);
    const wrap = el('div', {}, label, apply);
    wrap.setAttribute('data-list', name);
    apply.addEventListener('click', () => { files.set(name, area.value); refresh(); });
    area.addEventListener('input', () => { files.delete(name); refresh(); });
    panel.append(wrap);
  }
  box.append(panel);
}

// ---- Breakdown (R18–R20) ----
const KIND_TEXT = {
  unknown: 'Not in the pinned catalog. Its arguments and target scope are not verified.',
  shell: 'Shell syntax: not part of the Nmap command. A real shell would act on it; it is not interpreted here.',
};
const display = it => it.kind === 'flag' ? it.key + (it.val !== null ? ' ' + it.val : '') : it.kind === 'unknown' ? it.key : it.kind === 'target' ? it.val : it.text;

function breakdown(p) {
  const rows = p.items.map((it, index) => {
    const shown = display(it);
    let desc = KIND_TEXT[it.kind];
    if (it.kind === 'flag') desc = map.get(it.key)?.desc || '';
    if (it.kind === 'target') desc = it.placeholder ? 'Placeholder target: fill this in with a real address or hostname before running.' : 'Target.';
    const rm = el('button', { type: 'button', textContent: 'Remove' });
    rm.setAttribute('aria-label', 'Remove ' + shown);
    rm.addEventListener('click', () => remove(p, index));
    const row = el('div', { className: 'token' + (it.placeholder ? ' placeholder' : '') }, el('code', { textContent: shown }), el('span', { textContent: desc }), rm);
    row.setAttribute('data-kind', it.kind);
    return row;
  });
  $('.breakdown').replaceChildren(...rows);
}

function remove(p, index) {
  cmd.value = removeItem(cmd.value, p, index);
  changed();
  const buttons = $('.breakdown').querySelectorAll('.token button');
  (buttons[index] || buttons[index - 1] || cmd).focus();
}

// ---- Refresh and URL hash (R21, R23) ----
function refresh() {
  const p = parse(cmd.value, map);
  fileUI(p);
  set('.prose', interpret(p));
  set('.scope', p.issues.length ? '' : scope(p, files));
  lines('.problem', p.issues);
  const tooLong = cmd.value.length > MAX_HASH ? [`This command is too long to save in the link (over ${MAX_HASH} characters), so the URL keeps the previous command.`] : [];
  lines('.warnings', [...p.warnings, ...p.notes, ...tooLong]);
  breakdown(p);
}

function changed() {
  refresh();
  clearTimeout(hashTimer);
  if (cmd.value.length <= MAX_HASH) hashTimer = setTimeout(() => history.replaceState(null, '', encodeHash(cmd.value)), 150);
}

function loadHash() {
  const v = decodeHash(location.hash);
  if (v !== null && v !== cmd.value) { cmd.value = v; refresh(); }
}

cmd.addEventListener('input', changed);
window.addEventListener('hashchange', loadHash);
set('.coverage', map.size + ' named forms, including aliases and retired switches, checked against the literal long-option table and short-option string of Nmap 7.993. ' +
  'Values are checked only for these flags (README "Checked values"): ' + CHECKED_FLAGS.join(' ') + '. Script-specific keys, undocumented abbreviations and shell syntax are outside this inventory.');
const initial = decodeHash(location.hash);
if (initial !== null) cmd.value = initial;
filter();
refresh();
})();
