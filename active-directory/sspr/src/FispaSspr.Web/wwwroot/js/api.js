'use strict';
// Client dell'API FispaSSPR (contratto in api/openapi.yaml). Nessuna dipendenza esterna.
const Api = {
  session: null,

  async refresh() {
    const r = await fetch('/api/v1/session', { credentials: 'same-origin' });
    Api.session = await r.json();
    return Api.session;
  },

  async windowsLogin() {
    const r = await fetch('/api/v1/session/windows', { credentials: 'include' });
    if (!r.ok) return null;
    Api.session = await r.json();
    return Api.session;
  },

  async call(method, url, body) {
    if (!Api.session) await Api.refresh();
    const opt = { method, credentials: 'same-origin', headers: { 'X-CSRF-Token': Api.session.csrfToken } };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    const r = await fetch('/api/v1' + url, opt);
    if (r.status === 204) return null;
    const ct = r.headers.get('Content-Type') || '';
    const data = ct.includes('json') ? await r.json() : null;
    if (!r.ok) {
      const err = new Error((data && data.title) || ('Errore ' + r.status));
      err.status = r.status;
      err.errors = (data && data.errors) || [];
      err.retryAfter = r.headers.get('Retry-After');
      if (r.status === 403 && data && /Sessione scaduta/.test(data.title)) await Api.refresh();
      throw err;
    }
    return data;
  },

  get: (u) => Api.call('GET', u),
  post: (u, b) => Api.call('POST', u, b === undefined ? {} : b),
  put: (u, b) => Api.call('PUT', u, b),
  del: (u) => Api.call('DELETE', u),
};

// ---- helper DOM (niente innerHTML con dati utente: solo textContent)
const $ = (s, root) => (root || document).querySelector(s);
const $$ = (s, root) => Array.from((root || document).querySelectorAll(s));

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v;
    else if (k === 'onclick') e.addEventListener('click', v);
    else if (v !== null && v !== undefined && v !== false) e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}

function show(id) {
  $$('[data-view]').forEach(v => v.classList.toggle('hidden', v.id !== id));
  $$('.msg').forEach(m => { if (!m.dataset.keep) m.remove(); });
  const first = $('#' + id + ' input:not([type=hidden])');
  if (first) setTimeout(() => first.focus(), 30);
}

function message(container, kind, text, list) {
  const box = el('div', { class: 'msg ' + kind }, text);
  if (list && list.length) box.append(el('ul', null, list.map(x => el('li', null, x))));
  const c = typeof container === 'string' ? $(container) : container;
  $$('.msg', c).forEach(m => m.remove());
  c.prepend(box);
  return box;
}

function errorText(e) {
  if (e.status === 429 && e.retryAfter) return e.message + ' (attendere circa ' + Math.ceil(e.retryAfter / 60) + ' minuti)';
  return e.message;
}

// Inserisce lo SVG del QR code generato dal server (solo elementi SVG, senza script)
function setQr(container, svgText) {
  const doc = new DOMParser().parseFromString(svgText, 'image/svg+xml');
  const svg = doc.documentElement;
  if (svg.nodeName.toLowerCase() !== 'svg' || svg.querySelector('script, foreignObject')) return;
  container.replaceChildren(document.importNode(svg, true));
}

function busy(button, on) {
  if (!button) return;
  button.disabled = on;
  if (on) { button.dataset.label = button.textContent; button.textContent = 'Attendere...'; }
  else if (button.dataset.label) button.textContent = button.dataset.label;
}

async function guarded(button, container, fn) {
  busy(button, true);
  try { return await fn(); }
  catch (e) { message(container, 'err', errorText(e), e.errors); return undefined; }
  finally { busy(button, false); }
}

function applyBranding(s) {
  const b = (s && s.branding) || {};
  if (b.companyName) { $$('.company').forEach(x => x.textContent = b.companyName); document.title = b.companyName + ' - ' + document.title; }
  if (b.logoUrl && $('#logo')) { $('#logo').src = b.logoUrl; $('#logo').classList.remove('hidden'); }
  if (b.helpdeskContact) $$('.helpdesk').forEach(x => x.textContent = b.helpdeskContact);
}
