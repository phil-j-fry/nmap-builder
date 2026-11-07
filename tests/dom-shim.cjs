'use strict';
// Minimal DOM for UI tests, Node built-ins only. It is intentionally strict:
// innerHTML/outerHTML/insertAdjacentHTML/document.write throw (R24: text-only DOM insertion).
const vm = require('node:vm');

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const RAW = new Set(['style', 'script', 'textarea', 'title']);
const BOOL_PROPS = ['hidden', 'disabled', 'required', 'open', 'readOnly', 'multiple', 'checked', 'autofocus'];
const STR_PROPS = ['id', 'placeholder', 'type', 'name', 'title', 'role', 'href', 'rel', 'lang', 'for', 'autocomplete', 'inputMode', 'spellcheck', 'download', 'accept', 'target'];
const UNSAFE = () => { throw new Error('Unsafe DOM API used (R24): text-only insertion is required'); };
const decode = s => s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi, (m, e) => {
  const l = e.toLowerCase();
  if (l[0] === '#') return String.fromCodePoint(l[1] === 'x' ? parseInt(l.slice(2), 16) : parseInt(l.slice(1), 10));
  return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }[l];
});

class Event {
  constructor(type, init = {}) { this.type = type; this.bubbles = !!init.bubbles; this.cancelable = !!init.cancelable; this.defaultPrevented = false; this.target = null; this.currentTarget = null; this._stop = false; Object.assign(this, init.detail !== undefined ? { detail: init.detail } : {}); }
  preventDefault() { if (this.cancelable) this.defaultPrevented = true; }
  stopPropagation() { this._stop = true; }
  stopImmediatePropagation() { this._stop = true; this._stopNow = true; }
}
class KeyboardEvent extends Event { constructor(type, init = {}) { super(type, init); this.key = init.key || ''; this.code = init.code || ''; this.shiftKey = !!init.shiftKey; this.ctrlKey = !!init.ctrlKey; this.metaKey = !!init.metaKey; this.altKey = !!init.altKey; this.isComposing = false; } }
class CustomEvent extends Event { constructor(type, init = {}) { super(type, init); this.detail = init.detail; } }

class EventTargetish {
  constructor() { this._listeners = {}; }
  addEventListener(type, fn, opts) { (this._listeners[type] ||= []).push({ fn, once: !!(opts && opts.once) }); }
  removeEventListener(type, fn) { this._listeners[type] = (this._listeners[type] || []).filter(l => l.fn !== fn); }
  _fire(ev) {
    ev.currentTarget = this;
    const prop = this['on' + ev.type];
    if (typeof prop === 'function') prop.call(this, ev);
    for (const l of [...(this._listeners[ev.type] || [])]) {
      if (ev._stopNow) break;
      if (l.once) this.removeEventListener(ev.type, l.fn);
      l.fn.call(this, ev);
    }
  }
}

class Node extends EventTargetish {
  constructor(doc) { super(); this.ownerDocument = doc; this.parentNode = null; this.childNodes = []; }
  get parentElement() { return this.parentNode instanceof Element ? this.parentNode : null; }
  get firstChild() { return this.childNodes[0] || null; }
  get lastChild() { return this.childNodes.at(-1) || null; }
  get nextSibling() { const p = this.parentNode; return p ? p.childNodes[p.childNodes.indexOf(this) + 1] || null : null; }
  get previousSibling() { const p = this.parentNode; return p ? p.childNodes[p.childNodes.indexOf(this) - 1] || null : null; }
  get textContent() { return this.childNodes.map(c => c.textContent).join(''); }
  set textContent(v) { this.replaceChildren(); const s = String(v ?? ''); if (s) this.appendChild(this.ownerDocument.createTextNode(s)); }
  _norm(nodes) { const out = []; for (const n of nodes) { if (n instanceof DocumentFragment) out.push(...n.childNodes.slice()); else if (n instanceof Node) out.push(n); else out.push(this.ownerDocument.createTextNode(String(n))); } return out; }
  _detach(n) { if (n.parentNode) { const a = n.parentNode.childNodes; a.splice(a.indexOf(n), 1); n.parentNode = null; } }
  insertBefore(n, ref) { for (const c of this._norm([n])) { if (c.contains && c.contains(this)) throw new Error('HierarchyRequestError'); this._detach(c); const i = ref ? this.childNodes.indexOf(ref) : -1; if (i < 0) this.childNodes.push(c); else this.childNodes.splice(i, 0, c); c.parentNode = this; } return n; }
  appendChild(n) { return this.insertBefore(n, null); }
  removeChild(n) { this._detach(n); return n; }
  append(...ns) { for (const n of this._norm(ns)) this.appendChild(n); }
  prepend(...ns) { const f = this.firstChild; for (const n of this._norm(ns)) this.insertBefore(n, f); }
  replaceChildren(...ns) { for (const c of this.childNodes.slice()) this._detach(c); this.append(...ns); }
  remove() { const doc = this.ownerDocument; if (doc && doc._active && (doc._active === this || (this.contains && this.contains(doc._active)))) doc._active = null; this._detach(this); }
  before(...ns) { const p = this.parentNode; for (const n of this._norm(ns)) p.insertBefore(n, this); }
  after(...ns) { const p = this.parentNode, nx = this.nextSibling; for (const n of this._norm(ns)) p.insertBefore(n, nx); }
  replaceWith(...ns) { this.before(...ns); this.remove(); }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  get isConnected() { let x = this; while (x.parentNode) x = x.parentNode; return x === this.ownerDocument; }
  dispatchEvent(ev) {
    ev.target = this; const path = []; for (let x = this; x; x = x.parentNode) path.push(x);
    if (this.isConnected) path.push(this.ownerDocument.defaultView);
    for (const n of ev.bubbles ? path : [this]) { if (!n) continue; n._fire(ev); if (ev._stop) break; }
    return !ev.defaultPrevented;
  }
}
class Text extends Node { constructor(doc, data) { super(doc); this.nodeType = 3; this.nodeName = '#text'; this.data = data; } get textContent() { return this.data; } set textContent(v) { this.data = String(v); } cloneNode() { return new Text(this.ownerDocument, this.data); } }
class DocumentFragment extends Node { constructor(doc) { super(doc); this.nodeType = 11; } }

class ClassList {
  constructor(el) { this.el = el; }
  _get() { return (this.el.getAttribute('class') || '').split(/\s+/).filter(Boolean); }
  _set(a) { this.el.setAttribute('class', a.join(' ')); }
  contains(c) { return this._get().includes(c); }
  add(...cs) { const a = this._get(); for (const c of cs) if (!a.includes(c)) a.push(c); this._set(a); }
  remove(...cs) { this._set(this._get().filter(c => !cs.includes(c))); }
  toggle(c, force) { const has = this.contains(c), want = force === undefined ? !has : !!force; if (want && !has) this.add(c); if (!want && has) this.remove(c); return want; }
  get length() { return this._get().length; }
  [Symbol.iterator]() { return this._get()[Symbol.iterator](); }
}

class Element extends Node {
  constructor(doc, tag) {
    super(doc); this.nodeType = 1; this.localName = tag.toLowerCase(); this.tagName = this.nodeName = tag.toUpperCase();
    this._attrs = new Map(); this._value = null; this._dirty = false; this._selected = undefined; this.style = new Proxy({ setProperty() {}, removeProperty() {} }, { set: () => true });
    this.validationMessage = ''; this._reportValidityCalls = 0;
    this.classList = new ClassList(this);
    this.dataset = new Proxy({}, {
      get: (_, k) => typeof k === 'string' ? this.getAttribute('data-' + k.replace(/[A-Z]/g, m => '-' + m.toLowerCase())) ?? undefined : undefined,
      set: (_, k, v) => { this.setAttribute('data-' + String(k).replace(/[A-Z]/g, m => '-' + m.toLowerCase()), v); return true; },
    });
  }
  get children() { return this.childNodes.filter(c => c instanceof Element); }
  get firstElementChild() { return this.children[0] || null; }
  get lastElementChild() { return this.children.at(-1) || null; }
  get childElementCount() { return this.children.length; }
  get nextElementSibling() { let n = this.nextSibling; while (n && !(n instanceof Element)) n = n.nextSibling; return n; }
  get previousElementSibling() { let n = this.previousSibling; while (n && !(n instanceof Element)) n = n.previousSibling; return n; }
  getAttribute(n) { n = n.toLowerCase(); return this._attrs.has(n) ? this._attrs.get(n) : null; }
  setAttribute(n, v) { n = String(n).toLowerCase(); if (/^on/.test(n)) throw new Error('Inline event-handler attributes are not allowed: ' + n); this._attrs.set(n, String(v)); }
  hasAttribute(n) { return this._attrs.has(n.toLowerCase()); }
  removeAttribute(n) { this._attrs.delete(n.toLowerCase()); }
  toggleAttribute(n, f) { const h = this.hasAttribute(n), w = f === undefined ? !h : !!f; if (w) this.setAttribute(n, ''); else this.removeAttribute(n); return w; }
  getAttributeNames() { return [...this._attrs.keys()]; }
  get className() { return this.getAttribute('class') || ''; } set className(v) { this.setAttribute('class', v); }
  get htmlFor() { return this.getAttribute('for') || ''; } set htmlFor(v) { this.setAttribute('for', v); }
  get tabIndex() { const t = this.getAttribute('tabindex'); return t === null ? (['button', 'input', 'select', 'textarea', 'a', 'summary'].includes(this.localName) ? 0 : -1) : +t; } set tabIndex(v) { this.setAttribute('tabindex', v); }
  get maxLength() { const v = this.getAttribute('maxlength'); return v === null ? -1 : +v; } set maxLength(v) { this.setAttribute('maxlength', v); }
  get rows() { return +(this.getAttribute('rows') || 2); } set rows(v) { this.setAttribute('rows', v); }
  get innerHTML() { return UNSAFE(); } set innerHTML(v) { UNSAFE(); }
  get outerHTML() { return UNSAFE(); } set outerHTML(v) { UNSAFE(); }
  insertAdjacentHTML() { UNSAFE(); }
  get innerText() { return this.textContent; } set innerText(v) { this.textContent = v; }
  // form values
  get value() {
    if (this.localName === 'select') { const o = this.selectedOptions[0]; return o ? o.value : ''; }
    if (this.localName === 'option') return this.getAttribute('value') ?? this.textContent;
    if (this.localName === 'textarea') return this._dirty ? this._value : this.textContent;
    if (this.localName === 'input') return this._dirty ? this._value : (this.getAttribute('value') ?? '');
    return this.getAttribute('value') ?? '';
  }
  set value(v) {
    v = String(v ?? '');
    if (this.localName === 'select') { for (const o of this.options) o._selected = false; const o = this.options.find(o => o.value === v); if (o) o._selected = true; else this._noneSelected = true; if (o) this._noneSelected = false; return; }
    if (this.localName === 'option') { this.setAttribute('value', v); return; }
    if (this.localName === 'textarea' || this.localName === 'input') { const ml = this.maxLength; this._value = ml >= 0 && this.localName === 'input' ? v.slice(0, ml) : v; this._dirty = true; this.selectionStart = this.selectionEnd = this._value.length; return; }
    this.setAttribute('value', v);
  }
  get defaultValue() { return this.localName === 'textarea' ? this.textContent : this.getAttribute('value') ?? ''; }
  get options() { return this.localName === 'select' ? this.querySelectorAll('option') : undefined; }
  get selectedOptions() {
    const os = this.options; if (!os.length || this._noneSelected) return [];
    const sel = os.filter(o => o._selected === true);
    if (sel.length) return [sel.at(-1)];
    const def = os.filter(o => o._selected === undefined && o.hasAttribute('selected'));
    return [def.at(-1) || os[0]];
  }
  get selectedIndex() { return this.localName === 'select' ? this.options.indexOf(this.selectedOptions[0]) : undefined; }
  set selectedIndex(i) { if (this.localName !== 'select') return; for (const o of this.options) o._selected = false; this._noneSelected = i < 0; if (i >= 0 && this.options[i]) this.options[i]._selected = true; }
  get selected() { return this.parentSelect()?.selectedOptions[0] === this; }
  set selected(b) { const s = this.parentSelect(); if (s && b) { for (const o of s.options) o._selected = false; s._noneSelected = false; } this._selected = !!b; }
  parentSelect() { let x = this.parentNode; while (x && x.localName !== 'select') x = x.parentNode; return x; }
  get text() { return this.textContent; } set text(v) { this.textContent = v; }
  get labels() { return []; }
  get form() { return this.closest('form'); }
  // validity
  checkValidity() { if (this.validationMessage) return false; if (this.required && !this.disabled && ['input', 'textarea', 'select'].includes(this.localName) && !this.value) return false; return true; }
  reportValidity() { this._reportValidityCalls++; return this.checkValidity(); }
  setCustomValidity(m) { this.validationMessage = String(m || ''); }
  get validity() { return { valid: this.checkValidity(), valueMissing: this.required && !this.value }; }
  // focus
  focus() { if (this.disabled || !this.isConnected) return; const d = this.ownerDocument, prev = d._active; if (prev === this) return; d._active = this; if (prev) prev.dispatchEvent(new Event('blur')); this.dispatchEvent(new Event('focus')); }
  blur() { const d = this.ownerDocument; if (d._active === this) { d._active = null; this.dispatchEvent(new Event('blur')); } }
  click() {
    if (this.disabled) return;
    const ev = new Event('click', { bubbles: true, cancelable: true }); this.dispatchEvent(ev);
    if (!ev.defaultPrevented && this.localName === 'summary' && this.parentNode?.localName === 'details') this.parentNode.open = !this.parentNode.open;
    if (!ev.defaultPrevented && this.localName === 'a' && this.hasAttribute('download')) {
      const w = this.ownerDocument.defaultView, href = this.getAttribute('href') || '';
      w.downloads.push({ name: this.getAttribute('download'), href, blob: w._objectURLs.get(href) });
    }
  }
  select() {} setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; }
  scrollIntoView() {} getBoundingClientRect() { return { x: 0, y: 0, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 }; }
  getClientRects() { return []; }
  cloneNode(deep) { const c = this.ownerDocument.createElement(this.localName); for (const [k, v] of this._attrs) c._attrs.set(k, v); if (deep) for (const ch of this.childNodes) c.appendChild(ch.cloneNode(true)); return c; }
  // selectors
  matches(sel) { return parseSelectorList(sel).some(chain => matchChain(this, chain)); }
  closest(sel) { for (let x = this; x instanceof Element; x = x.parentNode) if (x.matches(sel)) return x; return null; }
  querySelectorAll(sel) { const chains = parseSelectorList(sel), out = []; walk(this, el => { if (el !== this && chains.some(ch => matchChain(el, ch))) out.push(el); }); return out; }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  getElementsByTagName(t) { return this.querySelectorAll(t); }
  getElementsByClassName(c) { return this.querySelectorAll('.' + c.trim().split(/\s+/).join('.')); }
}
for (const p of BOOL_PROPS) Object.defineProperty(Element.prototype, p, { get() { return this.hasAttribute(p.toLowerCase()); }, set(v) { this.toggleAttribute(p.toLowerCase(), !!v); if (p === 'open') this.dispatchEvent(new Event('toggle')); }, configurable: true });
for (const p of STR_PROPS) Object.defineProperty(Element.prototype, p, { get() { return this.getAttribute(p.toLowerCase()) ?? ''; }, set(v) { this.setAttribute(p.toLowerCase(), v); }, configurable: true });

function walk(root, fn) { for (const c of root.childNodes) if (c instanceof Element) { fn(c); walk(c, fn); } }

// Selector subset: compound simple selectors (tag, #id, .class, [attr], [attr=v], [attr^=v], [attr*=v], :not(simple)),
// descendant and child combinators, comma lists.
function parseSelectorList(sel) { return splitTop(sel, ',').map(s => parseChain(s.trim())); }
function splitTop(s, ch) { const out = []; let depth = 0, q = '', cur = ''; for (const c of s) { if (q) { if (c === q) q = ''; cur += c; continue; } if (c === '"' || c === "'") { q = c; cur += c; continue; } if (c === '[' || c === '(') depth++; if (c === ']' || c === ')') depth--; if (c === ch && !depth) { out.push(cur); cur = ''; continue; } cur += c; } out.push(cur); return out; }
function parseChain(s) {
  const parts = []; let comb = ' ', i = 0;
  const toks = s.replace(/\s*>\s*/g, ' > ').trim().match(/(?:[^\s"'\[\]()]+|\[[^\]]*\]|\([^)]*\)|"[^"]*"|'[^']*')+|>/g) || [];
  for (const t of toks) { if (t === '>') { comb = '>'; continue; } parts.push({ comb, simple: parseCompound(t) }); comb = ' '; i++; }
  return parts;
}
function parseCompound(t) {
  const out = []; const re = /([a-zA-Z][\w-]*|\*)|#([\w-]+)|\.([\w-]+)|\[([\w-]+)(?:([\^*$|~]?=)("[^"]*"|'[^']*'|[^\]]*))?\]|:not\(([^)]*)\)|:([\w-]+)/g;
  for (const m of t.matchAll(re)) {
    if (m[1]) out.push(el => m[1] === '*' || el.localName === m[1].toLowerCase());
    else if (m[2]) { const id = m[2]; out.push(el => el.getAttribute('id') === id); }
    else if (m[3]) { const c = m[3]; out.push(el => el.classList.contains(c)); }
    else if (m[4]) { const a = m[4], op = m[5], v = m[6] ? m[6].replace(/^["']|["']$/g, '') : null; out.push(el => { const x = el.getAttribute(a); if (x === null) return false; if (!op) return true; return op === '=' ? x === v : op === '^=' ? x.startsWith(v) : op === '*=' ? x.includes(v) : op === '$=' ? x.endsWith(v) : op === '~=' ? x.split(/\s+/).includes(v) : x === v || x.startsWith(v + '-'); }); }
    else if (m[7]) { const inner = parseCompound(m[7]); out.push(el => !inner.every(f => f(el))); }
    else if (m[8]) { const ps = m[8]; out.push(el => ps === 'first-child' ? el.parentNode?.children?.[0] === el : ps === 'last-child' ? el.parentNode?.children?.at(-1) === el : ps === 'checked' ? el.checked || el.selected : ps === 'disabled' ? el.disabled : ps === 'focus' ? el.ownerDocument._active === el : false); }
  }
  return out;
}
function matchChain(el, chain, idx = chain.length - 1) {
  if (!chain[idx].simple.every(f => f(el))) return false;
  if (idx === 0) return true;
  const comb = chain[idx].comb;
  if (comb === '>') { const p = el.parentNode; return p instanceof Element && matchChain(p, chain, idx - 1); }
  for (let p = el.parentNode; p instanceof Element; p = p.parentNode) if (matchChain(p, chain, idx - 1)) return true;
  return false;
}

class Document extends Node {
  constructor() {
    super(null); this.ownerDocument = this; this.nodeType = 9; this._active = null; this.created = [];
    this.documentElement = this.createElement('html'); this.appendChild(this.documentElement);
    this.head = this.createElement('head'); this.body = this.createElement('body'); this.documentElement.append(this.head, this.body);
    this.readyState = 'complete';
  }
  createElement(t) { const e = new Element(this, t); this.created.push(e.localName); return e; }
  createElementNS(_, t) { return this.createElement(t); }
  createTextNode(s) { return new Text(this, String(s)); }
  createDocumentFragment() { return new DocumentFragment(this); }
  get activeElement() { return this._active && this._active.isConnected ? this._active : this.body; }
  getElementById(id) { return this.querySelector('#' + id); }
  querySelectorAll(s) { return Element.prototype.querySelectorAll.call(this, s); }
  querySelector(s) { return this.querySelectorAll(s)[0] || null; }
  getElementsByTagName(t) { return this.querySelectorAll(t); }
  getElementsByClassName(c) { return Element.prototype.getElementsByClassName.call(this, c); }
  write() { UNSAFE(); } writeln() { UNSAFE(); }
  get textContent() { return null; }
}
Object.defineProperty(Document.prototype, 'defaultView', { get() { return this._window; } });

function parseHTML(html, doc, parent) {
  const stack = [parent]; let i = 0;
  const top = () => stack.at(-1);
  while (i < html.length) {
    if (html.startsWith('<!--', i)) { const e = html.indexOf('-->', i); i = e < 0 ? html.length : e + 3; continue; }
    if (html.startsWith('<!', i)) { i = html.indexOf('>', i) + 1; continue; }
    if (html[i] === '<' && html[i + 1] === '/') {
      const e = html.indexOf('>', i), name = html.slice(i + 2, e).trim().toLowerCase(); i = e + 1;
      const idx = stack.map(n => n.localName).lastIndexOf(name);
      if (idx <= 0) throw new Error(`view.html: unmatched </${name}>`);
      stack.length = idx; continue;
    }
    if (html[i] === '<' && /[a-zA-Z]/.test(html[i + 1] || '')) {
      const m = /^<([a-zA-Z][\w-]*)((?:\s+[^\s=>\/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>/.exec(html.slice(i));
      if (!m) throw new Error('view.html: bad tag near ' + JSON.stringify(html.slice(i, i + 40)));
      const el = doc.createElement(m[1]); doc.created.pop();
      const are = /([^\s=>\/]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?/g; let a;
      while ((a = are.exec(m[2]))) { const n = a[1].toLowerCase(); if (/^on/.test(n)) throw new Error('view.html: inline handler attribute ' + n); el._attrs.set(n, a[2] === undefined ? '' : decode(a[2].replace(/^["']|["']$/g, ''))); }
      top().appendChild(el); i += m[0].length;
      const tag = el.localName;
      if (RAW.has(tag)) { const close = html.toLowerCase().indexOf('</' + tag, i); const body = html.slice(i, close); if (body) el.appendChild(doc.createTextNode(tag === 'textarea' || tag === 'title' ? decode(body) : body)); i = html.indexOf('>', close) + 1; continue; }
      if (!VOID.has(tag) && !m[3]) stack.push(el);
      continue;
    }
    const n = html.indexOf('<', i + 1), end = n < 0 ? html.length : n;
    top().appendChild(doc.createTextNode(decode(html.slice(i, end)))); i = end;
  }
}

// options.storage: undefined (fresh in-memory), { mode: 'throw' } (access throws, like blocked storage),
//   { mode: 'quota' } (setItem throws QuotaExceededError), { store: Map } (shared/prefilled backing map).
// options.clipboard: undefined (records writes), 'reject' (writeText rejects), 'missing' (no navigator.clipboard).
function makeWindow({ hash = '', html, scripts, storage: storageOpt = {}, clipboard: clipOpt }) {
  const doc = new Document();
  const win = new EventTargetish();
  doc._window = win;
  const history = { calls: [], replaceState(s, t, url) { this.calls.push(['replace', String(url)]); setURL(url, false); }, pushState(s, t, url) { this.calls.push(['push', String(url)]); setURL(url, false); }, back() {}, state: null, length: 1 };
  const location = { _hash: '', pathname: '/index.html', search: '', origin: 'file://', protocol: 'file:', host: '',
    get hash() { return this._hash; }, set hash(v) { v = String(v); if (v && v[0] !== '#') v = '#' + v; if (v === '#') v = ''; const old = this._hash; this._hash = v; if (old !== v) setTimeout(() => win.dispatchEvent(new Event('hashchange')), 0); },
    get href() { return 'file:///index.html' + this.search + this._hash; }, set href(v) { setURL(v, true); }, assign(v) { setURL(v, true); }, replace(v) { setURL(v, true); }, reload() {} };
  function setURL(url, fire) { url = String(url ?? ''); const h = url.indexOf('#'); const nh = h >= 0 ? url.slice(h) : ''; if (fire) location.hash = nh; else location._hash = nh === '#' ? '' : nh; }
  location._hash = hash && hash[0] !== '#' ? '#' + hash : hash;
  const store = storageOpt.store || new Map();
  const storage = { getItem: k => store.has(k) ? store.get(k) : null, setItem: (k, v) => { if (storageOpt.mode === 'quota') { const e = new Error('QuotaExceededError'); e.name = 'QuotaExceededError'; throw e; } store.set(k, String(v)); }, removeItem: k => store.delete(k), clear: () => store.clear(), get length() { return store.size; }, key: i => [...store.keys()][i] ?? null };
  const downloads = [], objectURLs = new Map();
  class Blob { constructor(parts = [], opts = {}) { this._text = parts.map(String).join(''); this.type = opts.type || ''; this.size = this._text.length; } text() { return Promise.resolve(this._text); } }
  class File extends Blob { constructor(parts, name, opts) { super(parts, opts); this.name = name; } }
  const URLx = Object.assign(function (...a) { return new URL(...a); }, URL, {
    createObjectURL: b => { const u = 'blob:shim/' + (objectURLs.size + 1); objectURLs.set(u, b); return u; },
    revokeObjectURL: u => { objectURLs.delete(u); },
  });
  const clipboard = { written: [], writeText(t) { if (clipOpt === 'reject') return Promise.reject(new Error('denied')); this.written.push(t); return Promise.resolve(); } };
  win.dispatchEvent = ev => { ev.target ||= win; win._fire(ev); return !ev.defaultPrevented; };
  function Option(text = '', value, defSel, sel) { const o = doc.createElement('option'); o.textContent = text; if (value !== undefined) o.setAttribute('value', value); if (defSel) o.setAttribute('selected', ''); if (sel) o._selected = true; return o; }
  Object.assign(win, {
    document: doc, location, history, Option, Event, KeyboardEvent, CustomEvent, InputEvent: Event, FocusEvent: Event,
    Node, Element, HTMLElement: Element, Text, DocumentFragment,
    navigator: clipOpt === 'missing' ? { userAgent: 'dom-shim' } : { userAgent: 'dom-shim', clipboard },
    downloads, Blob, File, FileReader: undefined,
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
    requestAnimationFrame: f => setTimeout(() => f(Date.now()), 0), cancelAnimationFrame: clearTimeout,
    matchMedia: q => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => new Proxy({}, { get: () => '' }),
    console, URL: URLx, URLSearchParams, encodeURIComponent, decodeURIComponent, JSON, Math, Date, Map, Set, Promise, Intl,
    innerWidth: 375, innerHeight: 800, devicePixelRatio: 1,
    alert: () => { win.alerts = (win.alerts || 0) + 1; }, confirm: () => false, prompt: () => null,
    fetch: () => { throw new Error('fetch is not allowed (offline, nothing is fetched)'); },
    XMLHttpRequest: function () { throw new Error('XMLHttpRequest is not allowed'); },
  });
  for (const name of ['localStorage', 'sessionStorage'])
    Object.defineProperty(win, name, { configurable: true, enumerable: true, get() { if (storageOpt.mode === 'throw') { const e = new Error('SecurityError: The operation is insecure.'); e.name = 'SecurityError'; throw e; } return storage; } });
  win._store = store; win._objectURLs = objectURLs;
  win.window = win.self = win.globalThis = win.top = win.parent = win;
  parseHTML(html, doc, doc.body);
  const ctx = vm.createContext(win);
  for (const [code, filename] of scripts) vm.runInContext(code, ctx, { filename });
  return win;
}

module.exports = { makeWindow, Event, KeyboardEvent };
