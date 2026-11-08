'use strict';
// Client dell'API FispaSSPR (contratto in api/openapi.yaml), testi e aspetto dal server. Nessuna dipendenza esterna.
const Api = {
  session: null,
  ui: { texts: {}, branding: {}, features: {}, languages: [] },
  lang: null,             // lingua scelta (inviata in X-Lang); null = decide il server (Accept-Language)

  async loadUi() {
    try {
      const r = await fetch('/api/v1/ui' + (Api.lang ? '?lang=' + encodeURIComponent(Api.lang) : ''), { credentials: 'same-origin', headers: Api.langHeaders() });
      if (r.ok) Api.ui = await r.json();
    } catch (e) { /* testi predefiniti nell'HTML */ }
    if (Api.ui.language) document.documentElement.lang = Api.ui.language;
    return Api.ui;
  },

  langHeaders() { return Api.lang ? { 'X-Lang': Api.lang } : {}; },

  // lingua: scelta salvata, poi quella del browser, purche' attiva nel portale
  initLang() {
    let saved = null;
    try { saved = localStorage.getItem('sspr.lang'); } catch (e) { /* storage non disponibile */ }
    if (saved && /^[a-z]{2}$/.test(saved)) Api.lang = saved;
  },

  async setLang(l) {
    if (!/^[a-z]{2}$/.test(l)) return;
    Api.lang = l;
    try { localStorage.setItem('sspr.lang', l); } catch (e) { /* storage non disponibile */ }
    await Api.loadUi();
  },

  async refresh() {
    const r = await fetch('/api/v1/session', { credentials: 'same-origin', headers: Api.langHeaders() });
    Api.session = await r.json();
    return Api.session;
  },

  async windowsLogin(panel) {
    const r = await fetch('/api/v1/session/windows' + (panel ? '?panel=' + panel : ''), { credentials: 'include', headers: Api.langHeaders() });
    if (!r.ok) return null;
    Api.session = await r.json();
    return Api.session;
  },

  async call(method, url, body) {
    if (!Api.session) await Api.refresh();
    const opt = { method, credentials: 'same-origin', headers: Object.assign({ 'X-CSRF-Token': Api.session.csrfToken }, Api.langHeaders()) };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    const r = await fetch('/api/v1' + url, opt);
    if (r.status === 204) return null;
    const ct = r.headers.get('Content-Type') || '';
    const data = ct.includes('json') ? await r.json() : null;
    if (!r.ok) {
      const err = new Error((data && data.title) || ('Errore ' + r.status));
      err.status = r.status;
      err.code = data && data.code;
      err.errors = (data && data.errors) || [];
      err.retryAfter = r.headers.get('Retry-After');
      if (err.code === 'err.sessionExpired') await Api.refresh();
      throw err;
    }
    return data;
  },

  get: (u) => Api.call('GET', u),
  post: (u, b) => Api.call('POST', u, b === undefined ? {} : b),
  put: (u, b) => Api.call('PUT', u, b),
  del: (u) => Api.call('DELETE', u),
};

// ---- testi: chiave del catalogo -> testo (personalizzabile dal pannello), con segnaposto {nome}
function T(key, vars) {
  let t = (Api.ui.texts && Api.ui.texts[key]) || key;
  const all = Object.assign({ company: companyName(), helpdesk: (Api.ui.branding && Api.ui.branding.helpdeskContact) || '' }, vars || {});
  return t.replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (m, n) => (n in all ? String(all[n]) : m));
}

function companyName() {
  const b = Api.ui.branding || {};
  return b.companyName || (Api.ui.texts && Api.ui.texts['ui.headerTitle']) || '';
}

// Applica i testi agli elementi con data-t (contenuto), data-tp (placeholder), data-ta (aria-label)
function applyTexts(root) {
  $$('[data-t]', root).forEach(e => { e.textContent = T(e.dataset.t); });
  $$('[data-tp]', root).forEach(e => { e.placeholder = T(e.dataset.tp); });
  $$('[data-ta]', root).forEach(e => { e.setAttribute('aria-label', T(e.dataset.ta)); });
}

// ---- helper DOM (niente innerHTML con dati utente o testi personalizzati: solo textContent)
const $ = (s, root) => (root || document).querySelector(s);
const $$ = (s, root) => Array.from((root || document).querySelectorAll(s));

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v;
    else if (k === 'onclick') e.addEventListener('click', v);
    else if (k === 'onchange') e.addEventListener('change', v);
    else if (k === 'oninput') e.addEventListener('input', v);
    else if (v !== null && v !== undefined && v !== false) e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
}

function show(id) {
  $$('[data-view]').forEach(v => v.classList.toggle('hidden', v.id !== id));
  $$('.msg').forEach(m => { if (!m.dataset.keep) m.remove(); });
  const first = $('#' + id + ' input:not([type=hidden]):not([disabled])');
  if (first) setTimeout(() => first.focus(), 30);
  window.scrollTo(0, 0);
}

function message(container, kind, text, list) {
  const box = el('div', { class: 'msg ' + kind, role: kind === 'err' ? 'alert' : 'status' }, text);
  if (list && list.length) box.append(el('ul', null, list.map(x => el('li', null, x))));
  const c = typeof container === 'string' ? $(container) : container;
  $$(':scope > .msg', c).forEach(m => m.remove());
  c.prepend(box);
  return box;
}

function errorText(e) {
  if (e.status === 429 && e.retryAfter) return e.message + ' ' + T('err.rateLimitWait', { minutes: Math.max(1, Math.ceil(e.retryAfter / 60)) });
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
  if (on) { button.dataset.label = button.textContent; button.textContent = T('ui.wait'); }
  else if (button.dataset.label) button.textContent = button.dataset.label;
}

async function guarded(button, container, fn) {
  busy(button, true);
  try { return await fn(); }
  catch (e) { message(container, 'err', errorText(e), e.errors); return undefined; }
  finally { busy(button, false); }
}

// Selettore della lingua nell'intestazione (solo con piu' lingue attive)
const LANG_NAMES = { it: 'Italiano', en: 'English', de: 'Deutsch', fr: 'Francais', es: 'Espanol' };
function renderLangPicker(onChange) {
  const host = $('#lang');
  if (!host) return;
  const langs = Api.ui.languages || [];
  if (langs.length < 2) { host.replaceChildren(); host.classList.add('hidden'); return; }
  const sel = el('select', { 'aria-label': T('ui.language'), onchange: async (e) => { await Api.setLang(e.target.value); if (onChange) onChange(); } },
    langs.map(l => el('option', { value: l }, LANG_NAMES[l] || l.toUpperCase())));
  sel.value = Api.ui.language || langs[0];
  host.replaceChildren(sel);
  host.classList.remove('hidden');
}

// Aspetto: titolo, logo, icona, avviso, piede pagina, collegamento alla guida
function applyBranding(suffix) {
  const b = Api.ui.branding || {};
  const name = companyName();
  const title = b.portalTitle || T('ui.pageTitle');
  document.title = (name ? name + ' - ' : '') + title + (suffix ? ' - ' + suffix : '');
  $$('.company').forEach(x => { x.textContent = (b.showCompanyName === false) ? '' : name; });
  $$('.portal-title').forEach(x => { x.textContent = b.portalTitle || ''; x.classList.toggle('hidden', !b.portalTitle); });
  $$('.tagline').forEach(x => { x.textContent = b.tagline || ''; x.classList.toggle('hidden', !b.tagline); });
  const logo = $('#logo');
  if (logo) { if (b.logoUrl) { logo.src = b.logoUrl; logo.alt = name; logo.classList.remove('hidden'); } else logo.classList.add('hidden'); }
  const theme = $('#theme');
  if (theme && b.themeVersion) theme.href = '/theme.css?v=' + encodeURIComponent(b.themeVersion);
  if (b.faviconUrl) {
    let ico = $('link[rel=icon]');
    if (!ico) { ico = el('link', { rel: 'icon' }); document.head.append(ico); }
    ico.href = b.faviconUrl;
  }
  const ann = $('#announcement');
  if (ann) {
    ann.className = 'announcement ' + ((b.announcement && b.announcement.level) || 'info');
    ann.textContent = b.announcement ? b.announcement.text : '';
    ann.classList.toggle('hidden', !b.announcement);
  }
  const footer = $('#footer');
  if (footer) {
    footer.replaceChildren(el('span', null, T('ui.footer')));
    if (b.helpUrl && /^https?:\/\//i.test(b.helpUrl)) footer.append(' - ', el('a', { href: b.helpUrl, target: '_blank', rel: 'noopener noreferrer' }, T('ui.helpLink')));
  }
  document.body.classList.remove('loading');
}
