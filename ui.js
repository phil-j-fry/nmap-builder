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
  const raw = $('.search').value.trim(), q = raw.toLowerCase(), cat = $('.category').value;
  // Rank: exact key (same case, then any case), key prefix, then other matches; stable within each rank.
  const rank = d => { const k = d.key.toLowerCase(); return d.key === raw ? 0 : k === q ? 1 : k.startsWith(q) ? 2 : 3; };
  const matches = [...map.values()]
    .filter(d => (!cat || d.group === cat) && (d.key + ' ' + d.desc).toLowerCase().includes(q))
    .map((d, i) => [rank(d), i, d]).sort((a, b) => a[0] - b[0] || a[1] - b[1]).map(x => x[2]);
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
  if (v !== null && v !== cmd.value) {
    cmd.value = v;
    refresh();
    // A command from a new link is not the entry being edited (Plumb P2-5).
    if (editingId) { setEditing(null); libMsg('Loaded a command from the link. Save creates a new entry.'); }
  }
}

// ---- Saved-command library (R32–R34) ----
// Storage may be blocked (getter throws) or full (setItem throws); the library then works in memory.
const storage = (() => { try { return window.localStorage; } catch { return null; } })();
let library = [], editingId = null, draftSource = null, storageOk = true, pendingDelete = null;
const libMsg = t => set('.lib-msg', t);
const UNAVAILABLE = 'Browser storage is unavailable, so saved commands last only for this session. Use Export to keep a copy.';
const plural = (n, word) => n + ' ' + word + (n === 1 ? '' : 's');
const fullMsg = () => `The library is full (${LIBRARY_LIMITS.entries} saved commands). Delete some, or export and start a new library, before adding more.`;

// Which saved entry Save updates (null: Save creates a new entry). Shown next to Save.
function setEditing(entry) {
  editingId = entry ? entry.id : null;
  draftSource = entry ? entry.source : null;
  set('.lib-editing', entry ? 'Editing: ' + entry.name : '');
}

function commandStatus(text) {
  const p = parse(text, map);
  if (p.issues.length) return plural(p.issues.length, 'problem');
  if (p.notes.length) return 'Fill in placeholders';
  return 'Parses cleanly' + (p.warnings.length ? ' (' + plural(p.warnings.length, 'warning') + ')' : '');
}

function persist() {
  if (storageOk && writeLibrary(storage, library)) return true;
  libMsg(storageOk ? 'This change could not be saved: browser storage is full or blocked. It is kept for this session; use Export to keep a copy.' : UNAVAILABLE);
  return false;
}

function button(className, text, name, onClick) {
  const b = el('button', { type: 'button', className, textContent: text });
  b.setAttribute('aria-label', text + ' ' + name);
  b.addEventListener('click', onClick);
  return b;
}

function openCommand(text) {
  cmd.value = text;
  changed(); // explanation, breakdown and hash update as for typing
}

function renderLibrary() {
  pendingDelete = null; // any re-render cancels a pending delete confirmation
  const tagSel = $('.lib-tag'), current = tagSel.value, tags = allTags(library);
  tagSel.replaceChildren(opt('', 'All tags'), ...tags.map(t => opt(t)));
  tagSel.value = tags.includes(current) ? current : '';
  const shown = searchLibrary(library, { query: $('.lib-search').value, tag: tagSel.value });
  $('.lib-list').replaceChildren(...shown.map(libraryRow));
  if (!shown.length) $('.lib-list').append(el('p', { className: 'note', textContent: library.length ? 'No saved commands match.' : 'No saved commands yet.' }));
}

function libraryRow(e) {
  const del = button('lib-delete', 'Delete', e.name, () => removeEntry(e, del));
  const row = el('div', { className: 'lib-entry' },
    el('div', { className: 'lib-entry-name', textContent: e.name }),
    el('code', { textContent: e.cmd }),
    el('div', { className: 'lib-meta' },
      el('span', { className: 'lib-entry-tags', textContent: e.tags.length ? 'Tags: ' + e.tags.join(', ') : 'No tags' }),
      el('span', { className: 'lib-status', textContent: commandStatus(e.cmd) })),
    el('div', { className: 'lib-actions' },
      button('lib-open', 'Open', e.name, () => {
        openCommand(e.cmd);
        $('.lib-name').value = e.name;
        $('.lib-tags').value = e.tags.join(', ');
        setEditing(e);
        libMsg(`Editing "${e.name}". Save updates it; New starts a separate entry.`);
      }),
      button('lib-copy', 'Copy', e.name, () => copyText(e.cmd)),
      del));
  row.setAttribute('data-id', e.id);
  return row;
}

function copyText(text) {
  const clip = navigator.clipboard;
  if (!clip || typeof clip.writeText !== 'function') { libMsg('Clipboard access is not available here; select the command and copy it manually.'); return; }
  clip.writeText(text).then(() => libMsg('Command copied.'), () => libMsg('Copying was blocked; select the command and copy it manually.'));
}

function removeEntry(e, b) {
  if (pendingDelete && pendingDelete.id === e.id) {
    library = library.filter(x => x.id !== e.id);
    if (editingId === e.id) setEditing(null);
    const saved = persist();
    renderLibrary();
    if (saved) libMsg(`Deleted "${e.name}".`);
    return;
  }
  if (pendingDelete) { pendingDelete.button.textContent = 'Delete'; pendingDelete.button.setAttribute('aria-label', 'Delete ' + pendingDelete.name); }
  pendingDelete = { id: e.id, name: e.name, button: b };
  b.textContent = 'Confirm delete';
  b.setAttribute('aria-label', 'Confirm delete ' + e.name);
}

function saveCurrent() {
  const nameEl = $('.lib-name'), name = nameEl.value, tags = $('.lib-tags').value;
  if (!name.trim()) { nameEl.reportValidity(); return; }
  if (!cmd.value.trim()) { libMsg('There is no command to save yet: type or build one first.'); return; }
  const editing = editingId && library.find(x => x.id === editingId);
  if (!editing && library.length >= LIBRARY_LIMITS.entries) { libMsg(fullMsg()); return; }
  const r = editing
    ? updateEntry(editing, { name, cmd: cmd.value, tags, source: draftSource }, Date.now())
    : makeEntry({ name, cmd: cmd.value, tags, source: draftSource }, { now: Date.now() });
  if (!r.ok) {
    if (r.error === 'name') nameEl.reportValidity();
    libMsg(r.error === 'name' ? `Names can be 1–${LIBRARY_LIMITS.name} characters.` : `Commands can be up to ${LIBRARY_LIMITS.cmd} characters.`);
    return;
  }
  library = editing ? library.map(x => (x.id === editing.id ? r.entry : x)) : [...library, r.entry];
  if (editing) setEditing(r.entry); else draftSource = null;
  const saved = persist();
  renderLibrary();
  if (saved) libMsg(editing ? `Updated "${r.entry.name}".` : `Saved "${r.entry.name}".`);
}

function newEntry() {
  $('.lib-name').value = '';
  $('.lib-tags').value = '';
  setEditing(null);
  libMsg('');
}

function exportFile() {
  const blob = new Blob([exportLibrary(library, Date.now())], { type: 'application/json' });
  const url = URL.createObjectURL(blob), tooBig = blob.size > LIBRARY_LIMITS.importBytes;
  const a = el('a', { href: url, download: `nmap-library-${new Date().toISOString().slice(0, 10)}.json` });
  root.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  libMsg(`Exported ${plural(library.length, 'saved command')}.` + (tooBig ? ` The file is over the import limit (${LIBRARY_LIMITS.importBytes.toLocaleString('en-US')} bytes), so this workbook cannot import it back in one piece.` : ''));
}

async function importFile() {
  const input = $('.lib-import'), file = input.files && input.files[0];
  if (!file) return;
  if (typeof file.size === 'number' && file.size > LIBRARY_LIMITS.importBytes) { // never load a huge file (R33a)
    input.value = '';
    libMsg(`Import failed: the file is larger than ${LIBRARY_LIMITS.importBytes.toLocaleString('en-US')} bytes.`);
    return;
  }
  let text;
  try { text = await file.text(); } catch { libMsg('The file could not be read.'); input.value = ''; return; }
  input.value = '';
  const r = parseLibraryFile(text);
  if (!r.ok) { libMsg('Import failed: ' + r.errors[0]); return; }
  const m = mergeLibrary(library, r.entries, Date.now());
  library = m.entries;
  const saved = persist();
  renderLibrary();
  if (saved) libMsg(`Imported ${m.added}; skipped ${m.skipped} already in the library; ${r.dropped} invalid.` + (m.rejected ? ` ${m.rejected} not added: library full (${LIBRARY_LIMITS.entries} saved commands).` : ''));
}

function loadLibrary() {
  const r = readLibrary(storage);
  library = r.entries;
  if (r.status === 'unavailable') { storageOk = false; libMsg(UNAVAILABLE); }
  else if (r.status === 'corrupt') {
    // Never overwrite an unreadable library unless its backup copy is verified (R32a).
    storageOk = !!r.backupKey;
    libMsg('The saved library could not be read' + (r.backupKey
      ? `, so its contents were kept in browser storage under ${r.backupKey} and a new library starts empty.`
      : ', and no backup copy could be made, so changes stay in this session only and the stored data is left untouched. Use Export to keep a copy.'));
  } else if (r.dropped) libMsg(`${plural(r.dropped, 'saved entry')} could not be read and ${r.dropped === 1 ? 'was' : 'were'} skipped.`);
  renderLibrary();
}


// ---- CCSF starter set (R35): read-only, never stored ----
let starters = [];

function renderStarterOrigin() {
  const { repo, commit } = starterOrigin(STARTER_DATA), box = $('.starter-origin');
  const source = /^https:\/\//.test(repo || '') ? el('a', { href: repo, textContent: repo }) : el('span', { textContent: repo || 'an unknown source' });
  box.replaceChildren('Real commands from ', source, ` at commit ${String(commit || '').slice(0, 7)}. Each one keeps its source file:line. Copy one to your library to edit it.`);
  const cats = [...new Set(starters.map(s => s.category))].sort();
  $('.starter-category').replaceChildren(opt('', 'All categories'), ...cats.map(c => opt(c)));
}

function renderStarters() {
  const cat = $('.starter-category').value;
  $('.starter-list').replaceChildren(...starters.filter(s => !cat || s.category === cat).map(starterRow));
}

function starterRow(s) {
  const row = el('div', { className: 'starter-entry' },
    ...(s.name !== s.src ? [el('div', { className: 'lib-entry-name', textContent: s.name })] : []),
    el('code', { textContent: s.cmd }),
    el('div', { className: 'lib-meta' },
      el('span', { className: 'starter-src', textContent: s.src }),
      el('span', { className: 'starter-category-label', textContent: s.category }),
      el('span', { className: 'starter-kind', textContent: s.kind === 'placeholder' ? 'Has placeholders: fill this in before running' : 'Complete command' }),
      el('span', { className: 'lib-status', textContent: commandStatus(s.cmd) })),
    el('div', { className: 'lib-actions' },
      button('starter-open', 'Open', s.name, () => {
        openCommand(s.cmd);
        $('.lib-name').value = s.name;
        $('.lib-tags').value = s.tags.join(', ');
        setEditing(null); // saving creates a user copy
        draftSource = s.source;
        libMsg('Starter command opened. Save creates your own copy.');
      }),
      button('starter-save', 'Copy to my library', s.name, () => {
        const r = makeEntry({ name: s.name, cmd: s.cmd, tags: s.tags, source: s.source }, { now: Date.now() });
        if (!r.ok) { libMsg(`This starter command cannot be copied: its ${r.error === 'name' ? `name is not 1–${LIBRARY_LIMITS.name} characters` : 'command is empty or too long'}.`); return; }
        const m = mergeLibrary(library, [r.entry], Date.now());
        if (m.rejected) { libMsg(fullMsg()); return; }
        if (!m.added) { libMsg(`"${r.entry.name}" is already in your library.`); return; }
        library = m.entries;
        const saved = persist();
        renderLibrary();
        if (saved) libMsg(`Copied "${s.name}" to your library.`);
      })));
  row.setAttribute('data-src', s.src);
  return row;
}

// The library needs library.js and STARTER_DATA (bundled by build.py). Without them the page still works as the Phase 1 parser.
function initLibrary() {
  if (typeof readLibrary !== 'function' || typeof STARTER_DATA === 'undefined') {
    for (const s of ['details.library', 'details.starter']) { const d = $(s); if (d) d.hidden = true; }
    return;
  }
  $('.lib-save').addEventListener('click', saveCurrent);
  $('.lib-new').addEventListener('click', newEntry);
  for (const s of ['.lib-search', '.lib-tag']) for (const type of ['input', 'change']) $(s).addEventListener(type, renderLibrary);
  $('.lib-export').addEventListener('click', exportFile);
  $('.lib-import').addEventListener('change', importFile);
  window.addEventListener('storage', ev => {
    if (ev.key !== LIBRARY_KEY && ev.key !== null) return;
    const r = readLibrary(storage);
    if (r.status === 'ok' || r.status === 'empty') { library = r.entries; renderLibrary(); }
  });
  $('.starter-category').addEventListener('change', renderStarters);
  $('.starter-category').addEventListener('input', renderStarters);
  starters = starterEntries(STARTER_DATA);
  loadLibrary();
  renderStarterOrigin();
  renderStarters();
}

// ---- Boot ----
cmd.addEventListener('input', changed);
window.addEventListener('hashchange', loadHash);
set('.coverage', map.size + ' named forms, including aliases and retired switches, checked against the literal long-option table and short-option string of Nmap 7.993. ' +
  'Values are checked only for these flags (README "Checked values"): ' + CHECKED_FLAGS.join(' ') + '. Script-specific keys, undocumented abbreviations and shell syntax are outside this inventory.');
const initial = decodeHash(location.hash);
if (initial !== null) cmd.value = initial;
filter();
refresh();
initLibrary();
})();
