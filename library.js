// Saved-command library and CCSF starter set (R31–R33, R35). Pure functions only: no DOM.
// Storage is passed in (localStorage-like); every access is guarded so blocked or full storage never throws.

const LIBRARY_KEY = 'nmap-builder.library.v1';
const LIBRARY_FORMAT = 'nmap-builder-library';
const LIBRARY_VERSION = 1;
const LIBRARY_LIMITS = { name: 100, cmd: 8000, tag: 32, tags: 10, entries: 1000, importBytes: 32000000 };

const TAG_RE = /^[a-z0-9][a-z0-9_.-]{0,31}$/;
const ID_RE = /^[A-Za-z0-9:._-]{1,64}$/;
const MAX_SOURCE = 300;
const BACKUP_KEYS = () => [LIBRARY_KEY + '.backup', ...Array.from({ length: 9 }, (_, i) => LIBRARY_KEY + '.backup-' + (i + 2))];
let librarySeq = 0;

const isoTime = now => new Date(now).toISOString();
const newEntryId = now => 'e' + Math.floor(now).toString(36) + '-' + (++librarySeq).toString(36) + '-' + Math.random().toString(36).slice(2, 8);
const ownField = (obj, k) => (Object.prototype.hasOwnProperty.call(obj, k) ? obj[k] : undefined);
const validName = n => typeof n === 'string' && n.trim().length >= 1 && n.trim().length <= LIBRARY_LIMITS.name;
const validCmd = c => typeof c === 'string' && c.length <= LIBRARY_LIMITS.cmd && c.trim() !== '';
const validTime = t => typeof t === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(t) && !Number.isNaN(Date.parse(t));

// Comma-separated string or array → lowercase, dash-joined, validated, deduplicated tags (max 10).
function normalizeTags(x) {
  const list = Array.isArray(x) ? x : typeof x === 'string' ? x.split(',') : [];
  const out = [];
  for (const t of list) {
    if (typeof t !== 'string') continue;
    const tag = t.trim().toLowerCase().replace(/\s+/g, '-');
    if (TAG_RE.test(tag) && !out.includes(tag)) out.push(tag);
    if (out.length === LIBRARY_LIMITS.tags) break;
  }
  return out;
}

function makeEntry({ name, cmd, tags, source } = {}, { now = Date.now(), id } = {}) {
  if (!validName(name)) return { ok: false, error: 'name' };
  if (!validCmd(cmd)) return { ok: false, error: 'cmd' };
  const t = isoTime(now);
  return {
    ok: true,
    entry: {
      id: typeof id === 'string' && ID_RE.test(id) ? id : newEntryId(now),
      name: name.trim(), cmd, tags: normalizeTags(tags),
      source: typeof source === 'string' && source.length <= MAX_SOURCE ? source : null,
      created: t, updated: t,
    },
  };
}

function updateEntry(entry, changes = {}, now = Date.now()) {
  const pick = k => (changes[k] !== undefined ? changes[k] : entry[k]);
  const r = makeEntry({ name: pick('name'), cmd: pick('cmd'), tags: pick('tags'), source: pick('source') }, { now, id: entry.id });
  if (!r.ok) return r;
  r.entry.created = entry.created;
  return r;
}

function searchLibrary(entries, { query = '', tag = '' } = {}) {
  const terms = String(query || '').toLowerCase().split(/\s+/).filter(Boolean);
  return entries
    .filter(e => !tag || e.tags.includes(tag))
    .filter(e => {
      const hay = [e.name, e.cmd, e.tags.join(' '), e.source || ''].join('\n').toLowerCase();
      return terms.every(t => hay.includes(t));
    })
    .sort((a, b) => (a.updated < b.updated ? 1 : a.updated > b.updated ? -1 : a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

function allTags(entries) { return [...new Set(entries.flatMap(e => e.tags))].sort(); }

// One stored or imported entry → a clean R31 entry, or null. Reads own fields only.
function sanitizeEntry(raw, now) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = makeEntry({ name: ownField(raw, 'name'), cmd: ownField(raw, 'cmd'), tags: ownField(raw, 'tags'), source: ownField(raw, 'source') }, { now, id: ownField(raw, 'id') });
  if (!r.ok) return null;
  const created = ownField(raw, 'created'), updated = ownField(raw, 'updated');
  if (validTime(created)) r.entry.created = created;
  if (validTime(updated)) r.entry.updated = updated;
  return r.entry;
}

function exportLibrary(entries, now = Date.now()) {
  const clean = entries.map(e => ({ id: e.id, name: e.name, cmd: e.cmd, tags: e.tags, source: e.source ?? null, created: e.created, updated: e.updated }));
  return JSON.stringify({ format: LIBRARY_FORMAT, version: LIBRARY_VERSION, exported: isoTime(now), entries: clean }, null, 2);
}

// Validate a library document (already-read text). Content is only ever treated as data.
// maxChars and maxEntries are 0 for the app's own storage, which is always read in full (Plumb P2-1).
function parseLibraryDoc(text, now, maxChars, maxEntries) {
  const fail = msg => ({ ok: false, entries: [], errors: [msg], dropped: 0 });
  if (typeof text !== 'string') return fail('The file could not be read as text.');
  if (maxChars && text.length > maxChars) return fail(`The file is longer than ${maxChars.toLocaleString('en-US')} characters.`);
  let doc;
  try { doc = JSON.parse(text); } catch (e) { return fail('The file is not valid JSON: ' + e.message); }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return fail('The file is not a saved-command library (expected a JSON object).');
  if (ownField(doc, 'format') !== LIBRARY_FORMAT) return fail(`The file is not an ${LIBRARY_FORMAT} file.`);
  const version = ownField(doc, 'version');
  if (version !== LIBRARY_VERSION) {
    return fail(Number.isInteger(version) && version > LIBRARY_VERSION
      ? `The file is from a newer version of the workbook (library version ${version}); update the workbook to import it.`
      : 'The file has an unsupported library version.');
  }
  const list = ownField(doc, 'entries');
  if (!Array.isArray(list)) return fail('The file has no list of entries.');
  if (maxEntries && list.length > maxEntries) return fail(`The file has more than ${maxEntries} entries.`);
  const entries = [], ids = new Set();
  let dropped = 0;
  for (const raw of list) {
    const e = sanitizeEntry(raw, now);
    if (!e) { dropped++; continue; }
    if (ids.has(e.id)) e.id = newEntryId(now); // ids are unique within a library; the first keeps its id
    ids.add(e.id);
    entries.push(e);
  }
  return { ok: true, entries, errors: [], dropped };
}

function parseLibraryFile(text) { return parseLibraryDoc(text, Date.now(), LIBRARY_LIMITS.importBytes, LIBRARY_LIMITS.entries); }

function readLibrary(storage) {
  const none = (status, backupKey = null) => ({ entries: [], status, dropped: 0, backupKey });
  if (!storage) return none('unavailable');
  let raw;
  try { raw = storage.getItem(LIBRARY_KEY); } catch { return none('unavailable'); }
  if (raw === null || raw === undefined) return none('empty');
  const r = parseLibraryDoc(raw, Date.now(), 0, 0);
  if (!r.ok) return none('corrupt', backupRaw(storage, raw));
  return { entries: r.entries, status: 'ok', dropped: r.dropped, backupKey: null };
}

// Copy an unreadable stored value to a backup key without overwriting a different existing backup.
// Returns the key where the value is verified stored (read back equal), or null.
function backupRaw(storage, raw) {
  for (const key of BACKUP_KEYS()) {
    let current;
    try { current = storage.getItem(key); } catch { return null; }
    if (current === raw) return key;
    if (current !== null && current !== undefined) continue;
    try { storage.setItem(key, raw); return storage.getItem(key) === raw ? key : null; } catch { return null; }
  }
  return null;
}

function writeLibrary(storage, entries) {
  if (!storage) return false;
  try { storage.setItem(LIBRARY_KEY, exportLibrary(entries, Date.now())); return true; } catch { return false; }
}

const entrySignature = e => JSON.stringify([e.name, e.cmd, [...e.tags].sort()]);

// Append incoming entries; skip exact duplicates (name, cmd, sorted tags); never modify existing ones.
// Stops adding at LIBRARY_LIMITS.entries; entries left out for that reason are counted in `rejected`.
function mergeLibrary(existing, incoming, now = Date.now()) {
  const sigs = new Set(existing.map(entrySignature)), ids = new Set(existing.map(e => e.id));
  const entries = [...existing];
  let added = 0, skipped = 0, rejected = 0;
  for (const e of incoming) {
    const sig = entrySignature(e);
    if (sigs.has(sig)) { skipped++; continue; }
    if (entries.length >= LIBRARY_LIMITS.entries) { rejected++; continue; }
    const id = ids.has(e.id) ? newEntryId(now) : e.id;
    entries.push({ ...e, id });
    sigs.add(sig); ids.add(id); added++;
  }
  return { entries, added, skipped, rejected };
}

// Starter set (R35): read-only entries for the valid and placeholder corpus examples.
const STARTER_KINDS = ['valid', 'placeholder'];
const categoryTag = c => c.toLowerCase().replace(/[^a-z0-9_.]+/g, '-').replace(/^-+|-+$/g, '');

function starterEntries(data) {
  const out = [], seen = new Set();
  for (const ex of (data && Array.isArray(data.examples)) ? data.examples : []) {
    if (!STARTER_KINDS.includes(ex.kind) || typeof ex.cmd !== 'string' || typeof ex.src !== 'string') continue;
    const id = 'ccsf:' + ex.src;
    if (seen.has(id)) continue;
    seen.add(id);
    const category = ex.category || 'Other';
    out.push({ id, name: ex.title || ex.src, cmd: ex.cmd, src: ex.src, category, kind: ex.kind, tags: normalizeTags(['ccsf', categoryTag(category)]), source: id, readOnly: true });
  }
  return out;
}

function starterOrigin(data) { return { repo: data?.source, commit: data?.commit }; }
