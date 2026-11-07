'use strict';
// Pannello amministrazione: autenticazione Windows + secondo fattore TOTP, poi cruscotto, utenti, audit, stato e configurazione completa.
let current = null;      // utente aperto nel dettaglio
let perms = {};          // permessi dell'operatore (dal servizio)
let cfg = null;          // configurazione in modifica
let catalog = [];        // catalogo dei testi
let dirty = false;
let setTab = 'general';

document.addEventListener('DOMContentLoaded', async () => {
  await Api.loadUi();
  applyBranding('Amministrazione');
  await Api.refresh();
  const s = await Api.windowsLogin('admin').catch(() => null);
  if (!s || !(s.isAdmin || s.isHelpdesk)) { show('v-denied'); return; }
  $('#who').textContent = (s.displayName || s.userName) + (s.isAdmin ? ' (Admin)' : ' (Helpdesk)');
  $$('.admin-only').forEach(x => x.classList.toggle('hidden', !s.isAdmin));
  $('#f-2fa').addEventListener('submit', verify2fa);
  $$('#main-tabs button').forEach(b => b.addEventListener('click', () => tab(b.dataset.tab)));
  $('#f-search').addEventListener('submit', search);
  $('#f-audit').addEventListener('submit', (e) => { e.preventDefault(); loadAudit(); });
  $('#btn-save').addEventListener('click', saveSettings);
  $('#btn-reload').addEventListener('click', () => { if (!dirty || confirm('Annullare le modifiche non salvate?')) loadSettings(); });
  window.addEventListener('beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
  await startSecondFactor();
});

async function startSecondFactor() {
  const st = await Api.get('/admin/2fa');
  perms = st.can || {};
  if (st.verified) return enter();
  if (!st.enrolled) {
    const r = await Api.post('/admin/2fa/setup');
    setQr($('#f2-qr'), r.qrCodeSvg);
    $('#f2-key').textContent = r.manualKey.replace(/(.{4})/g, '$1 ').trim();
    $('#f2-setup').classList.remove('hidden');
  }
  $('#f2-code').value = '';
  show('v-2fa');
}

async function verify2fa(ev) {
  ev.preventDefault();
  const r = await guarded(ev.submitter, '#v-2fa', () => Api.post('/admin/2fa/verify', { code: $('#f2-code').value }));
  if (r && r.verified) { perms = r.can || {}; enter(); }
}

function enter() { show('v-panel'); tab('t-dash'); }

// Errori del pannello: se scade il secondo fattore si torna alla verifica
async function adm(button, container, fn) {
  busy(button, true);
  try { return await fn(); }
  catch (e) {
    if (e.code === 'admin.2fa') { await startSecondFactor(); message('#v-2fa', 'info', e.message); return undefined; }
    message(container, 'err', errorText(e), e.errors);
    return undefined;
  } finally { busy(button, false); }
}

function tab(id) {
  if (id !== 't-settings' && dirty && !confirm('Ci sono modifiche non salvate nella configurazione. Uscire comunque?')) return;
  if (id !== 't-settings') dirty = false;
  $$('#main-tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === id));
  $$('.tab').forEach(t => t.classList.toggle('hidden', t.id !== id));
  if (id === 't-dash') loadDash();
  if (id === 't-audit') loadAudit();
  if (id === 't-health') loadHealth();
  if (id === 't-settings') loadSettings();
}

const fmt = (d) => d ? new Date(d).toLocaleString('it-IT') : '';

async function loadDash() {
  const d = await adm(null, '#t-dash', () => Api.get('/admin/dashboard'));
  if (!d) return;
  const pct = d.usersInScope ? Math.round(d.usersEnrolled * 100 / d.usersInScope) : 0;
  const k = (v, l) => el('div', { class: 'kpi' }, el('b', null, v), l);
  $('#kpis').replaceChildren(
    k(`${d.usersEnrolled} / ${d.usersInScope}`, `Utenti registrati (${pct}%)`),
    k(d.resetsLast30Days, 'Reset negli ultimi 30 giorni'),
    k(d.changesLast30Days, 'Cambi password (30 giorni)'),
    k(d.unlocksLast30Days, 'Sblocchi (30 giorni)'),
    k(d.blockedAttemptsLast24h, 'Tentativi bloccati o falliti (24 ore)'));
}

// ------------------------------------------------------------------ utenti
async function search(ev) {
  ev.preventDefault();
  const list = await adm(ev.submitter, '#t-users .card', () => Api.get('/admin/users?q=' + encodeURIComponent($('#q').value)));
  if (!list) return;
  $('#user-detail').classList.add('hidden');
  $('#users').replaceChildren(...list.map(u => el('tr', { class: 'click', onclick: () => detail(u.sid) },
    el('td', null, u.userName), el('td', null, u.displayName || ''),
    el('td', null, statusBadges(u)),
    el('td', null, u.manageable ? (u.enrollment && u.enrollment.enrolled ? el('span', { class: 'badge ok' }, 'registrato') : el('span', { class: 'badge warn' }, 'non registrato')) : el('span', { class: 'badge' }, 'non gestibile')))));
  if (!list.length) $('#users').replaceChildren(el('tr', null, el('td', { colspan: '4' }, 'Nessun utente trovato nelle OU abilitate.')));
}

function statusBadges(u) {
  const b = [];
  if (!u.enabled) b.push(el('span', { class: 'badge err' }, 'disabilitato'));
  if (u.lockedOut) b.push(el('span', { class: 'badge err' }, 'bloccato'));
  if (u.enabled && !u.lockedOut) b.push(el('span', { class: 'badge ok' }, 'attivo'));
  return b;
}

async function detail(sid) {
  const u = await adm(null, '#t-users .card', () => Api.get('/admin/users/' + encodeURIComponent(sid)));
  if (!u) return;
  current = u;
  $('#ud-title').textContent = `${u.displayName || u.userName} (${u.userName})`;
  const info = [el('p', null, statusBadges(u))];
  if (!u.manageable) info.push(el('p', { class: 'msg info', 'data-keep': '1' }, 'Account non gestibile dal portale: ' + u.notManageableReason));
  else if (u.enrollment) {
    info.push(el('p', null, u.enrollment.enrolled ? 'Metodi registrati:' : `Non registrato (servono ${u.enrollment.minimumMethods} metodi).`));
    info.push(el('ul', null, u.enrollment.methods.map(m => el('li', null, `${T('method.' + m.method)}: ${m.destinationMasked} - ${fmt(m.verifiedAt)}`))));
  }
  $('#ud-info').replaceChildren(...info);
  const actions = [];
  if (u.manageable) {
    if (perms.unlock) actions.push(el('button', { class: 'btn', onclick: (e) => act(e, 'unlock', 'Account sbloccato.') }, 'Sblocca'));
    if (perms.clearEnrollment) actions.push(el('button', { class: 'btn secondary', onclick: (e) => act(e, 'enrollment/clear', "Metodi azzerati: l'utente dovrà registrarsi di nuovo.", true) }, 'Azzera i metodi'));
    if (perms.invite) actions.push(el('button', { class: 'btn secondary', onclick: (e) => act(e, 'invite', 'Invito inviato.', false, true) }, 'Invita a registrarsi'));
    if (perms.temporaryReset) actions.push(el('button', { class: 'btn danger', onclick: tempReset }, 'Reset con password temporanea'));
  }
  $('#ud-actions').replaceChildren(...actions);
  $('#ud-reason').value = '';
  $('#ud-events').replaceChildren(...u.lastEvents.map(e => el('tr', null, el('td', null, fmt(e.time)), el('td', null, e.eventId), el('td', null, e.message))));
  $('#user-detail').classList.remove('hidden');
}

async function act(ev, path, okText, confirmIt, noReason) {
  if (confirmIt && !confirm('Confermi?')) return;
  const body = noReason ? {} : { reason: $('#ud-reason').value };
  const ok = await adm(ev.target, '#user-detail', async () => { await Api.post(`/admin/users/${encodeURIComponent(current.sid)}/${path}`, body); return true; });
  if (ok) { await detail(current.sid); message('#user-detail', 'ok', okText); }
}

async function tempReset(ev) {
  if (!confirm("Reimpostare la password con una temporanea? L'utente dovrà cambiarla al primo accesso.")) return;
  const r = await adm(ev.target, '#user-detail', () => Api.post(`/admin/users/${encodeURIComponent(current.sid)}/reset`, { reason: $('#ud-reason').value }));
  if (!r) return;
  const box = message('#user-detail', 'ok', 'Password temporanea (mostrata una sola volta, comunicarla di persona o al telefono): ');
  box.append(el('code', { class: 'key' }, r.temporaryPassword));
}

// ------------------------------------------------------------------ audit e stato
function auditQuery() {
  const p = new URLSearchParams();
  if ($('#a-from').value) p.set('from', new Date($('#a-from').value + 'T00:00:00').toISOString());
  if ($('#a-to').value) p.set('to', new Date($('#a-to').value + 'T23:59:59').toISOString());
  if ($('#a-user').value) p.set('user', $('#a-user').value);
  if ($('#a-ev').value) p.set('eventId', $('#a-ev').value);
  return p;
}

async function loadAudit() {
  const p = auditQuery();
  const rows = await adm(null, '#t-audit .card', () => Api.get('/admin/audit?' + p.toString()));
  p.set('format', 'csv');
  $('#a-csv').href = '/api/v1/admin/audit?' + p.toString();
  if (!rows) return;
  $('#audit').replaceChildren(...rows.slice(0, 500).map(r => el('tr', null,
    el('td', null, fmt(r.time)), el('td', null, r.eventId), el('td', null, r.outcome), el('td', null, r.targetUser || ''),
    el('td', null, r.actor || ''), el('td', null, r.clientIp || ''), el('td', null, r.message))));
}

async function loadHealth() {
  const h = await adm(null, '#t-health .card', () => Api.get('/admin/health'));
  if (!h) return;
  const labels = { version: 'Versione', server: 'Server', domainController: 'Domain controller', certificate: 'Certificato', masterKey: 'Chiave master', smtp: 'SMTP', sms: 'Gateway SMS' };
  $('#health').replaceChildren(...Object.entries(labels).map(([k, l]) => el('tr', null, el('th', null, l),
    el('td', null, el('span', { class: /^ERRORE|IN SCADENZA/.test(h[k] || '') ? 'badge err' : '' }, h[k] || '')))));
}

// ------------------------------------------------------------------ configurazione: modello dei campi
// tipi: text, int, bool, select, area, code, color, list (una voce per riga), secret
const bool = (path, label, help) => ({ path, type: 'bool', label, help });
const int = (path, label, help, min, max) => ({ path, type: 'int', label, help, min, max });
const text = (path, label, help) => ({ path, type: 'text', label, help });
const SECTIONS = [
  { id: 'general', title: 'Generale', groups: [
    { title: 'Azienda e portale', fields: [
      text('general.companyName', 'Nome azienda', "Nell'intestazione, nei messaggi e nelle notifiche ({company})."),
      text('branding.portalTitle', 'Titolo del portale', "Accanto al nome azienda e nel titolo della pagina."),
      text('branding.tagline', 'Sottotitolo', 'Frase sotto il titolo della pagina iniziale.'),
      text('general.portalUrl', 'Indirizzo del portale', 'URL https usato negli inviti e nelle notifiche ({portalUrl}).'),
      text('general.helpdeskContact', 'Contatto help desk', 'Telefono, email o interno mostrati agli utenti ({helpdesk}).'),
      text('branding.helpUrl', 'Collegamento alla guida', 'URL di una guida interna, mostrato nel piè di pagina.'),
      text('general.defaultCountryCode', 'Prefisso internazionale predefinito', 'Per i numeri inseriti senza prefisso (es. 39).'),
    ] },
    { title: 'Avviso in evidenza', fields: [
      bool('branding.announcement.enabled', 'Mostra un avviso in tutte le pagine del portale'),
      { path: 'branding.announcement.level', type: 'select', label: 'Tipo', options: [['info', 'Informazione'], ['warn', 'Attenzione'], ['err', 'Importante']] },
      { path: 'branding.announcement.text', type: 'area', label: 'Testo', help: 'Es. manutenzione programmata, nuove regole sulle password.' },
    ] },
  ] },
  { id: 'look', title: 'Aspetto', custom: renderLook },
  { id: 'texts', title: 'Testi', custom: renderTexts },
  { id: 'notify', title: 'Notifiche', custom: renderNotifications },
  { id: 'features', title: 'Funzioni', groups: [
    { title: 'Portale utenti', fields: [
      bool('features.resetEnabled', 'Reset della password dimenticata'),
      bool('features.unlockEnabled', "Sblocco dell'account"),
      bool('features.changeEnabled', 'Cambio della password conosciuta'),
      bool('features.enrollmentEnabled', 'Registrazione dei metodi da parte degli utenti', "Se disattivata i metodi si possono solo usare: la registrazione la gestisce l'help desk."),
      bool('features.allowMethodRemoval', 'Gli utenti possono rimuovere i propri metodi'),
      bool('features.showPasswordRequirements', 'Verifica dal vivo della nuova password'),
    ] },
    { title: 'Accesso', fields: [
      bool('features.windowsLoginEnabled', 'Accesso con autenticazione Windows (PC del dominio)'),
      bool('features.passwordLoginEnabled', 'Accesso con nome utente e password (es. da VPN)'),
      bool('features.firstEnrollmentRequiresWindowsLogin', 'Prima registrazione solo da PC aziendale', "Chi ruba solo la password non può registrare i propri metodi da remoto."),
      bool('features.stepUpForEnrollmentChanges', 'Conferma con un metodo esistente per modificare i metodi', 'Consigliato: impedisce di sostituire i metodi con la sola password.'),
    ] },
    { title: 'Reset', fields: [
      bool('features.resetUnlocksAccount', "Il reset sblocca anche l'account"),
      bool('features.resetForcesChangeAtNextLogon', 'Dopo il reset obbliga a cambiare la password al primo accesso'),
      bool('features.backgroundCodeDelivery', 'Invio dei codici di reset in background', 'Tempi di risposta costanti: non rivela quali account esistono.'),
    ] },
    { title: 'Pannello', fields: [
      bool('features.helpdeskCanUnlock', "L'help desk può sbloccare gli account"),
      bool('features.helpdeskCanClearEnrollment', "L'help desk può azzerare i metodi"),
      bool('features.helpdeskCanInvite', "L'help desk può inviare gli inviti"),
      bool('features.adminCanTemporaryReset', 'Gli amministratori possono impostare una password temporanea'),
    ] },
  ] },
  { id: 'verify', title: 'Verifica e password', groups: [
    { title: 'Metodi di verifica', fields: [
      bool('verification.totpEnabled', 'App di autenticazione (TOTP)'),
      bool('verification.smsEnabled', 'SMS'),
      bool('verification.emailEnabled', 'Email personale'),
      int('verification.minimumEnrolledMethods', 'Metodi minimi da registrare', '', 1, 3),
      int('verification.resetVerifications', 'Verifiche richieste per il reset', 'Metodi diversi; 2 consigliato.', 1, 3),
      int('verification.unlockVerifications', 'Verifiche richieste per lo sblocco', '', 1, 3),
      bool('verification.changeRequiresVerification', 'Il cambio password richiede la conferma con un metodo'),
      int('verification.codeLifetimeMinutes', 'Validità dei codici SMS/email (minuti)', '', 1, 30),
      int('verification.codeMaxAttempts', 'Tentativi per codice', '', 1, 10),
      int('verification.totpWindowSteps', 'Tolleranza TOTP (intervalli di 30 s)', "0 = solo il codice corrente; 1 = consigliato.", 0, 3),
      int('verification.flowSessionMinutes', 'Durata massima di un reset (minuti)', '', 3, 60),
      text('verification.totpIssuer', "Nome mostrato nell'app di autenticazione", 'Vuoto = nome azienda.'),
    ] },
    { title: 'Password', fields: [
      int('passwords.minLength', 'Lunghezza minima del portale', 'Si applica il maggiore tra questo valore e quello di dominio/PSO.', 8, 128),
      { path: 'passwords.bannedWords', type: 'list', label: 'Parole vietate', help: 'Una per riga (nome azienda, prodotti, città...). Confronto senza maiuscole.' },
      { path: 'passwords.breachedCheck', type: 'select', label: 'Password compromesse', options: [['OnlineKAnonymity', 'Online (HIBP, k-anonymity: escono solo 5 caratteri dell\'hash)'], ['OfflineList', 'Lista locale'], ['Off', 'Nessun controllo']] },
      text('passwords.offlineListPath', 'File della lista locale', 'Percorso sul server, una password o hash SHA-1 per riga.'),
      bool('passwords.blockWhenBreachCheckUnavailable', 'Rifiuta la password se il controllo non è disponibile'),
    ] },
  ] },
  { id: 'security', title: 'Sicurezza', groups: [
    { title: 'Limiti dei tentativi', fields: [
      int('rateLimits.perUserPerHour', 'Richieste per utente all\'ora', '', 1, 100),
      int('rateLimits.perIpPerHour', 'Richieste per indirizzo IP all\'ora', '', 1, 10000),
      int('rateLimits.globalPerMinute', 'Richieste totali al minuto', '', 1, 10000),
      int('rateLimits.codesPerUserPerHour', 'Codici inviati per utente all\'ora', '', 1, 50),
    ] },
    { title: 'Sessioni', fields: [
      int('sessions.userIdleMinutes', 'Inattività massima della sessione utente (minuti)', '', 2, 240),
      int('sessions.userAbsoluteMinutes', 'Durata massima della sessione utente (minuti)', '', 5, 1440),
      int('sessions.stepUpMinutes', "Validità della conferma d'identità (minuti)", '', 1, 30),
      int('sessions.minResponseMilliseconds', 'Tempo minimo di risposta di login e reset (ms)', 'Rende indistinguibili account esistenti e inesistenti.', 200, 5000),
      int('admin.sessionMinutes', 'Durata della sessione del pannello (minuti)', 'Poi si ripete il secondo fattore.', 5, 480),
      int('admin.maxSecondFactorFailuresPerHour', 'Codici errati del pannello per operatore all\'ora', '', 3, 20),
      int('audit.retentionMonths', "Conservazione dell'audit (mesi)", '', 1, 120),
    ] },
  ] },
  { id: 'channels', title: 'Email e SMS', custom: renderChannels },
  { id: 'directory', title: 'Directory', groups: [
    { title: 'Active Directory', fields: [
      text('directory.domainController', 'Domain controller', 'Vuoto = individuato automaticamente.'),
      { path: 'directory.allowedOus', type: 'list', label: 'OU abilitate', help: "Distinguished name, una per riga. Il gMSA ha le deleghe solo su quelle scelte nell'installazione." },
      { path: 'directory.excludedGroupSids', type: 'list', label: 'SID dei gruppi esclusi', help: 'Uno per riga. Gli account privilegiati sono sempre esclusi.' },
    ] },
  ] },
  { id: 'advanced', title: 'Avanzate', custom: renderAdvanced },
];

// ------------------------------------------------------------------ configurazione: lettura/scrittura per percorso
function getPath(o, p) { return p.split('.').reduce((a, k) => (a == null ? undefined : a[k]), o); }
function setPath(o, p, v) {
  const keys = p.split('.');
  let a = o;
  for (const k of keys.slice(0, -1)) { if (a[k] == null || typeof a[k] !== 'object') a[k] = {}; a = a[k]; }
  a[keys[keys.length - 1]] = v;
  markDirty();
}
function markDirty() { dirty = true; $('#dirty').textContent = 'Modifiche non salvate'; }

function field(def) {
  const id = 'f-' + def.path.replace(/\./g, '-');
  const v = getPath(cfg, def.path);
  let input;
  const help = def.help ? el('div', { class: 'help' }, def.help) : null;
  switch (def.type) {
    case 'bool':
      input = el('input', { type: 'checkbox', id, onchange: (e) => setPath(cfg, def.path, e.target.checked) });
      input.checked = !!v;
      return el('div', { class: 'field check' }, el('label', { for: id }, input, def.label), help);
    case 'int':
      input = el('input', { type: 'number', id, min: def.min, max: def.max, oninput: (e) => setPath(cfg, def.path, e.target.value === '' ? 0 : parseInt(e.target.value, 10)) });
      input.value = v ?? '';
      break;
    case 'select':
      input = el('select', { id, onchange: (e) => setPath(cfg, def.path, e.target.value) }, def.options.map(([val, l]) => el('option', { value: val }, l)));
      input.value = v ?? def.options[0][0];
      break;
    case 'area': case 'code':
      input = el('textarea', { id, class: def.type === 'code' ? 'code' : 'small', spellcheck: def.type === 'code' ? 'false' : 'true', oninput: (e) => setPath(cfg, def.path, e.target.value) });
      input.value = v ?? '';
      break;
    case 'list':
      input = el('textarea', { id, class: 'small', spellcheck: 'false', oninput: (e) => setPath(cfg, def.path, e.target.value.split('\n').map(x => x.trim()).filter(Boolean)) });
      input.value = (v || []).join('\n');
      break;
    case 'color': {
      const txt = el('input', { id, maxlength: '7', oninput: (e) => { if (/^#[0-9a-f]{6}$/i.test(e.target.value)) { pick.value = e.target.value; setPath(cfg, def.path, e.target.value); } } });
      const pick = el('input', { type: 'color', oninput: (e) => { txt.value = e.target.value; setPath(cfg, def.path, e.target.value); } });
      txt.value = v || ''; pick.value = /^#[0-9a-f]{6}$/i.test(v || '') ? v : '#000000';
      return el('div', { class: 'field' }, el('label', { for: id }, def.label), el('div', { class: 'row' }, el('div', null, txt), pick), help);
    }
    case 'secret':
      input = el('input', { type: 'password', id, autocomplete: 'new-password', placeholder: v ? 'Impostata: lasciare vuoto per non cambiarla' : 'Non impostata', oninput: (e) => { secrets[def.secret] = e.target.value || null; markDirty(); } });
      break;
    default:
      input = el('input', { id, oninput: (e) => setPath(cfg, def.path, e.target.value) });
      input.value = v ?? '';
  }
  return el('div', { class: 'field' }, el('label', { for: id }, def.label), input, help);
}

const secrets = { smtp: null, sms: null };

function renderGroups(groups) {
  return groups.map(g => el('div', { class: 'sub' }, el('h3', null, g.title), el('div', { class: 'grid2' }, g.fields.map(field))));
}

async function loadSettings() {
  const s = await adm(null, '#t-settings .card', () => Api.get('/admin/settings'));
  const t = await adm(null, '#t-settings .card', () => Api.get('/admin/texts'));
  if (!s || !t) return;
  cfg = s; catalog = t;
  cfg.branding.texts = cfg.branding.texts || {};
  secrets.smtp = null; secrets.sms = null;
  dirty = false; $('#dirty').textContent = '';
  $('#set-tabs').replaceChildren(...SECTIONS.map(x => el('button', { 'data-s': x.id, onclick: () => { setTab = x.id; renderSection(); } }, x.title)));
  renderSection();
}

function renderSection() {
  const sec = SECTIONS.find(x => x.id === setTab) || SECTIONS[0];
  $$('#set-tabs button').forEach(b => b.classList.toggle('active', b.dataset.s === sec.id));
  const body = $('#set-body');
  body.replaceChildren(...(sec.custom ? sec.custom() : renderGroups(sec.groups)));
}

async function saveSettings(ev) {
  const body = { settings: cfg, smtpPassword: secrets.smtp, smsPassword: secrets.sms };
  const ok = await adm(ev.target, '#t-settings .card', async () => { await Api.put('/admin/settings', body); return true; });
  if (ok) {
    dirty = false;
    await Api.loadUi(); applyBranding('Amministrazione');
    await loadSettings();
    message('#t-settings .card', 'ok', 'Configurazione salvata: attiva subito, senza riavvio.');
  }
}

// ------------------------------------------------------------------ aspetto: file, colori, CSS
function renderLook() {
  const assets = [['logo', 'Logo', "PNG, SVG, JPEG o WEBP, max 1 MB. Nell'intestazione di portale e pannello."],
    ['favicon', 'Icona della scheda', 'PNG, ICO o SVG quadrato (es. 64x64).'],
    ['background', 'Immagine di sfondo', 'Opzionale; meglio leggera e poco contrastata.']];
  const fileField = ([name, label, help]) => {
    const file = cfg.branding[name + 'File'];
    const preview = file ? el('img', { src: '/branding/' + name + '?t=' + Date.now(), alt: label }) : el('span', { class: 'muted' }, 'Nessun file');
    const input = el('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp,image/gif,image/svg+xml,image/x-icon,.ico', onchange: (e) => upload(e, name) });
    return el('div', { class: 'asset' }, preview, el('div', null, el('b', null, label), el('div', { class: 'help' }, help), input,
      file ? el('button', { class: 'btn secondary small', onclick: (e) => removeAsset(e, name) }, 'Rimuovi') : null));
  };
  const colors = [['primaryColor', 'Colore principale (pulsanti, collegamenti)'], ['primaryDarkColor', 'Colore principale scuro'], ['backgroundColor', 'Sfondo della pagina'],
    ['cardColor', 'Sfondo dei riquadri'], ['textColor', 'Testo'], ['mutedColor', 'Testo secondario'], ['headerColor', 'Sfondo intestazione'],
    ['headerTextColor', 'Testo intestazione'], ['successColor', 'Esito positivo'], ['errorColor', 'Errori']];
  return [
    el('div', { class: 'sub' }, el('h3', null, 'Immagini'), el('p', { class: 'muted' }, 'Le immagini si salvano subito al caricamento. Gli SVG con script o riferimenti esterni vengono rifiutati.'), assets.map(fileField)),
    el('div', { class: 'sub' }, el('h3', null, 'Intestazione e forme'), el('div', { class: 'grid2' },
      field(bool('branding.showCompanyNameInHeader', "Mostra il nome azienda accanto al logo")),
      field(int('branding.logoHeight', 'Altezza del logo (px)', '', 16, 160)),
      field(int('branding.cornerRadius', 'Arrotondamento dei riquadri (px)', '0 = angoli vivi.', 0, 30)),
      field(text('branding.fontFamily', 'Carattere', 'Elenco CSS, es. "Segoe UI", Arial, sans-serif. Solo caratteri installati sui PC.')))),
    el('div', { class: 'sub' }, el('h3', null, 'Colori'), el('div', { class: 'grid2' }, colors.map(([k, l]) => field({ path: 'branding.' + k, type: 'color', label: l })))),
    el('div', { class: 'sub' }, el('h3', null, 'CSS personalizzato'),
      el('p', { class: 'muted' }, 'Per ritocchi avanzati (es. .choice b{font-size:18px}). @import, URL esterni e script non sono ammessi.'),
      field({ path: 'branding.customCss', type: 'code', label: 'Regole CSS' })),
    el('button', { class: 'btn secondary', onclick: () => { cfg.branding = Object.assign(cfg.branding, defaultsLook()); markDirty(); renderSection(); } }, 'Ripristina colori e forme predefiniti'),
  ];
}

function defaultsLook() {
  return { primaryColor: '#1d4ed8', primaryDarkColor: '#1e40af', backgroundColor: '#f4f6f9', cardColor: '#ffffff', textColor: '#1a202c', mutedColor: '#64748b',
    headerColor: '#ffffff', headerTextColor: '#1a202c', successColor: '#15803d', errorColor: '#b91c1c', fontFamily: '"Segoe UI", system-ui, -apple-system, Arial, sans-serif',
    cornerRadius: 10, logoHeight: 36, customCss: '' };
}

async function upload(ev, name) {
  const f = ev.target.files[0];
  if (!f) return;
  if (f.size > 1024 * 1024) { message('#t-settings .card', 'err', 'File troppo grande (massimo 1 MB).'); return; }
  const buf = new Uint8Array(await f.arrayBuffer());
  let bin = '';
  for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
  const ok = await adm(null, '#t-settings .card', async () => { await Api.post('/admin/branding/' + name, { dataBase64: btoa(bin) }); return true; });
  if (ok) { await refreshAfterAsset(); message('#t-settings .card', 'ok', 'Immagine caricata.'); }
}

async function removeAsset(ev, name) {
  if (!confirm('Rimuovere questa immagine?')) return;
  const ok = await adm(ev.target, '#t-settings .card', async () => { await Api.del('/admin/branding/' + name); return true; });
  if (ok) { await refreshAfterAsset(); message('#t-settings .card', 'ok', 'Immagine rimossa.'); }
}

async function refreshAfterAsset() {
  const s = await Api.get('/admin/settings');
  ['logoFile', 'faviconFile', 'backgroundFile'].forEach(k => { cfg.branding[k] = s.branding[k]; });
  await Api.loadUi(); applyBranding('Amministrazione');
  renderSection();
}

// ------------------------------------------------------------------ testi e notifiche (catalogo)
function textEditor(item, rows) {
  const custom = cfg.branding.texts[item.key];
  const area = el('textarea', { class: 'small', rows: String(rows || 2), placeholder: item.defaultText,
    oninput: (e) => { const v = e.target.value; if (v && v !== item.defaultText) cfg.branding.texts[item.key] = v; else delete cfg.branding.texts[item.key]; box.classList.toggle('custom', !!cfg.branding.texts[item.key]); markDirty(); } });
  area.value = custom || '';
  const reset = el('button', { class: 'btn secondary small', onclick: () => { delete cfg.branding.texts[item.key]; area.value = ''; box.classList.remove('custom'); markDirty(); } }, 'Predefinito');
  const box = el('div', { class: 'text-row' + (custom ? ' custom' : '') },
    el('div', { class: 'row' }, el('div', null, el('div', { class: 'key' }, item.key), item.description ? el('div', { class: 'help' }, item.description) : null), reset),
    el('div', { class: 'help' }, 'Predefinito: ' + item.defaultText), area);
  return box;
}

function renderTexts() {
  const groups = [...new Set(catalog.filter(x => !x.key.startsWith('notify.')).map(x => x.group))];
  const q = el('input', { placeholder: 'Cerca nei testi (chiave o contenuto)' });
  const g = el('select', null, el('option', { value: '' }, 'Tutte le sezioni'), groups.map(x => el('option', { value: x }, x)));
  const onlyCustom = el('input', { type: 'checkbox', id: 'only-custom' });
  const list = el('div');
  const draw = () => {
    const term = q.value.toLowerCase();
    const items = catalog.filter(x => !x.key.startsWith('notify.') && (!g.value || x.group === g.value)
      && (!onlyCustom.checked || cfg.branding.texts[x.key])
      && (!term || x.key.toLowerCase().includes(term) || x.defaultText.toLowerCase().includes(term) || (cfg.branding.texts[x.key] || '').toLowerCase().includes(term)));
    list.replaceChildren(...items.slice(0, 200).map(x => textEditor(x)));
    if (!items.length) list.append(el('p', { class: 'muted' }, 'Nessun testo.'));
  };
  q.addEventListener('input', draw); g.addEventListener('change', draw); onlyCustom.addEventListener('change', draw);
  draw();
  return [el('p', { class: 'muted' }, 'Ogni testo del portale e dei messaggi di errore si può riscrivere. Lasciare vuoto per usare il predefinito. Segnaposto disponibili ovunque: {company}, {helpdesk}, {portalUrl}; gli altri sono indicati sotto la chiave. Solo testo semplice, niente HTML.'),
    el('div', { class: 'row' }, el('div', null, q), el('div', null, g), el('div', { class: 'field check' }, el('label', { for: 'only-custom' }, onlyCustom, 'Solo personalizzati'))), list];
}

function renderNotifications() {
  const events = [['code', 'Codice di verifica', null], ['methodAdded', 'Metodo aggiunto', 'methodAdded'], ['methodRemoved', 'Metodo rimosso', 'methodRemoved'],
    ['passwordChanged', 'Password cambiata', 'passwordChanged'], ['passwordReset', 'Password reimpostata', 'passwordReset'], ['accountUnlocked', 'Account sbloccato', 'accountUnlocked'],
    ['adminUnlock', "Sblocco dall'help desk", 'adminUnlock'], ['adminClearEnrollment', "Metodi azzerati dall'help desk", 'adminClearEnrollment'],
    ['adminTemporaryReset', 'Password temporanea dal pannello', 'adminTemporaryReset'], ['invite', 'Invito a registrarsi', null]];
  const byKey = Object.fromEntries(catalog.map(x => [x.key, x]));
  const out = [
    el('div', { class: 'sub' }, el('h3', null, 'Canali delle notifiche'), el('div', { class: 'grid2' },
      field(bool('notifications.viaPersonalEmail', 'Email personale registrata')),
      field(bool('notifications.viaSms', 'SMS al cellulare registrato')),
      field(bool('notifications.viaCorporateEmail', 'Email aziendale (attributo mail di AD)')))),
    el('p', { class: 'muted' }, 'Segnaposto: {company}, {helpdesk}, {portalUrl}, {user}, {displayName}, {time}, {method}; per il codice {code}, {minutes}, {purpose}. Testo semplice.'),
  ];
  for (const [key, title, flag] of events) {
    const parts = ['subject', 'body', 'sms'].map(p => byKey[`notify.${key}.${p}`]).filter(Boolean);
    out.push(el('div', { class: 'sub' }, el('h3', null, title),
      flag ? field(bool('notifications.' + flag, 'Invia questa notifica')) : el('p', { class: 'muted' }, key === 'code' ? 'Sempre inviato quando serve un codice.' : "Inviato quando l'operatore lo richiede."),
      parts.map(p => textEditor(p, p.key.endsWith('.body') ? 5 : 2))));
  }
  const purposes = catalog.filter(x => x.key.startsWith('notify.purpose.'));
  out.push(el('div', { class: 'sub' }, el('h3', null, 'Scopo del codice ({purpose})'), purposes.map(p => textEditor(p))));
  return out;
}

// ------------------------------------------------------------------ email e SMS
function renderChannels() {
  const test = (channel, label, type) => {
    const input = el('input', { type, placeholder: label });
    const btn = el('button', { class: 'btn secondary small', onclick: async (e) => {
      if (dirty) { message('#t-settings .card', 'info', 'Salvare prima la configurazione: il test usa le impostazioni salvate.'); return; }
      const ok = await adm(e.target, '#t-settings .card', async () => { await Api.post('/admin/test/' + channel, { destination: input.value }); return true; });
      if (ok) message('#t-settings .card', 'ok', 'Messaggio di prova inviato.');
    } }, 'Invia prova');
    return el('div', { class: 'row' }, el('div', null, input), btn);
  };
  return [
    ...renderGroups([{ title: 'Email (SMTP)', fields: [
      text('smtp.host', 'Server SMTP', 'Relay interno o servizio di posta.'),
      int('smtp.port', 'Porta', '25 o 587 con STARTTLS.', 1, 65535),
      bool('smtp.useStartTls', 'STARTTLS'),
      text('smtp.from', 'Mittente', 'Es. password@contoso.local'),
      text('smtp.userName', 'Utente', 'Vuoto = relay anonimo.'),
      { path: 'smtp.passwordEnvelope', type: 'secret', secret: 'smtp', label: 'Password' },
    ] }]),
    test('email', 'Email di prova', 'email'),
    ...renderGroups([{ title: 'SMS', fields: [
      { path: 'sms.provider', type: 'select', label: 'Provider', options: [['AndroidGatewayLocal', 'SMS Gateway for Android (locale, gratuito)'], ['GenericHttp', 'HTTP generico'], ['None', 'Nessuno']] },
      text('sms.endpoint', 'URL di invio', 'Es. http://192.168.1.50:8080/message'),
      text('sms.userName', 'Utente', "Dall'app o dal provider."),
      { path: 'sms.passwordEnvelope', type: 'secret', secret: 'sms', label: 'Password' },
      text('sms.senderName', 'Mittente (se supportato)', ''),
      { path: 'sms.genericBodyTemplate', type: 'code', label: 'Corpo JSON (solo HTTP generico)', help: 'Segnaposto {to} e {text}, es. {"to":"{to}","text":"{text}"}' },
    ] }]),
    test('sms', 'Cellulare di prova (+39...)', 'tel'),
  ];
}

// ------------------------------------------------------------------ avanzate: JSON, esporta, importa
function renderAdvanced() {
  const area = el('textarea', { class: 'code', spellcheck: 'false' });
  area.value = JSON.stringify(cfg, null, 2);
  const apply = el('button', { class: 'btn secondary', onclick: () => {
    try { const v = JSON.parse(area.value); keepManaged(v); cfg = v; markDirty(); message('#t-settings .card', 'ok', 'JSON applicato al modulo: controllare e salvare.'); }
    catch (e) { message('#t-settings .card', 'err', 'JSON non valido: ' + e.message); }
  } }, 'Applica il JSON');
  const exp = el('button', { class: 'btn secondary', onclick: () => {
    const copy = JSON.parse(JSON.stringify(cfg));
    if (copy.smtp) copy.smtp.passwordEnvelope = null;
    if (copy.sms) copy.sms.passwordEnvelope = null;
    const blob = new Blob([JSON.stringify(copy, null, 2)], { type: 'application/json' });
    const a = el('a', { href: URL.createObjectURL(blob), download: 'fispasspr-config.json' });
    document.body.append(a); a.click(); a.remove();
  } }, 'Esporta (senza password)');
  const imp = el('input', { type: 'file', accept: '.json,application/json', onchange: async (e) => {
    const f = e.target.files[0]; if (!f) return;
    try { const v = JSON.parse(await f.text()); keepManaged(v); cfg = v; markDirty(); renderSection(); message('#t-settings .card', 'ok', 'Configurazione importata nel modulo: controllare e salvare. Password SMTP/SMS e immagini non sono incluse.'); }
    catch (err) { message('#t-settings .card', 'err', 'File non valido: ' + err.message); }
  } });
  return [el('p', { class: 'muted' }, "Configurazione completa. Porta, certificato, account del servizio, gruppi degli operatori e obbligo del secondo fattore si cambiano solo dall'installer: qui vengono ignorati. Esporta/Importa per riusare la stessa configurazione (testi, colori, funzioni) su un altro ambiente."),
    el('div', null, exp, el('label', null, 'Importa da file'), imp), area, apply];
}

// valori gestiti dal servizio: non si sovrascrivono importando
function keepManaged(v) {
  v.hosting = cfg.hosting; v.configVersion = cfg.configVersion;
  v.branding = v.branding || {};
  v.branding.logoFile = cfg.branding.logoFile; v.branding.faviconFile = cfg.branding.faviconFile; v.branding.backgroundFile = cfg.branding.backgroundFile;
  v.branding.texts = v.branding.texts || {};
  v.smtp = v.smtp || {}; v.sms = v.sms || {};
  v.smtp.passwordEnvelope = cfg.smtp.passwordEnvelope; v.sms.passwordEnvelope = cfg.sms.passwordEnvelope;
}
