'use strict';
// Pannello amministrazione: autenticazione Windows + secondo fattore TOTP, poi cruscotto, utenti, audit, stato, configurazione.
let current = null;

document.addEventListener('DOMContentLoaded', async () => {
  applyBranding(await Api.refresh());
  const s = await Api.windowsLogin().catch(() => null);
  if (!s || !(s.isAdmin || s.isHelpdesk)) { show('v-denied'); return; }
  $('#who').textContent = (s.displayName || s.userName) + (s.isAdmin ? ' (Admin)' : ' (Helpdesk)');
  $$('.admin-only').forEach(x => x.classList.toggle('hidden', !s.isAdmin));
  $('#f-2fa').addEventListener('submit', verify2fa);
  $$('nav.tabs button').forEach(b => b.addEventListener('click', () => tab(b.dataset.tab)));
  $('#f-search').addEventListener('submit', search);
  $('#f-audit').addEventListener('submit', (e) => { e.preventDefault(); loadAudit(); });
  $('#btn-save').addEventListener('click', saveSettings);
  $('#btn-test-mail').addEventListener('click', (e) => testChannel(e, 'email', $('#test-mail').value));
  $('#btn-test-sms').addEventListener('click', (e) => testChannel(e, 'sms', $('#test-sms').value));
  const st = await Api.get('/admin/2fa');
  if (st.verified) return enter();
  if (!st.enrolled) {
    const r = await Api.post('/admin/2fa/setup');
    setQr($('#f2-qr'), r.qrCodeSvg);
    $('#f2-key').textContent = r.manualKey.replace(/(.{4})/g, '$1 ').trim();
    $('#f2-setup').classList.remove('hidden');
  }
  show('v-2fa');
});

async function verify2fa(ev) {
  ev.preventDefault();
  const r = await guarded(ev.submitter, '#v-2fa', () => Api.post('/admin/2fa/verify', { code: $('#f2-code').value }));
  if (r && r.verified) enter();
}

function enter() { show('v-panel'); tab('t-dash'); }

function tab(id) {
  $$('nav.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === id));
  $$('.tab').forEach(t => t.classList.toggle('hidden', t.id !== id));
  if (id === 't-dash') loadDash();
  if (id === 't-audit') loadAudit();
  if (id === 't-health') loadHealth();
  if (id === 't-settings') loadSettings();
}

const fmt = (d) => d ? new Date(d).toLocaleString('it-IT') : '';

async function loadDash() {
  const d = await guarded(null, '#t-dash', () => Api.get('/admin/dashboard'));
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
  const list = await guarded(ev.submitter, '#t-users .card', () => Api.get('/admin/users?q=' + encodeURIComponent($('#q').value)));
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
  const u = await guarded(null, '#t-users .card', () => Api.get('/admin/users/' + encodeURIComponent(sid)));
  if (!u) return;
  current = u;
  $('#ud-title').textContent = `${u.displayName || u.userName} (${u.userName})`;
  const info = [el('p', null, statusBadges(u))];
  if (!u.manageable) info.push(el('p', { class: 'msg info', 'data-keep': '1' }, 'Account non gestibile dal portale: ' + u.notManageableReason));
  else if (u.enrollment) {
    info.push(el('p', null, u.enrollment.enrolled ? 'Metodi registrati:' : `Non registrato (servono ${u.enrollment.minimumMethods} metodi).`));
    info.push(el('ul', null, u.enrollment.methods.map(m => el('li', null, `${m.method}: ${m.destinationMasked} - ${fmt(m.verifiedAt)}`))));
  }
  $('#ud-info').replaceChildren(...info);
  const isAdmin = Api.session.isAdmin;
  const actions = [];
  if (u.manageable) {
    actions.push(el('button', { class: 'btn', onclick: (e) => act(e, 'unlock', 'Account sbloccato.') }, 'Sblocca'));
    actions.push(el('button', { class: 'btn secondary', onclick: (e) => act(e, 'enrollment/clear', 'Metodi azzerati: l\'utente dovra\' registrarsi di nuovo.', true) }, 'Azzera i metodi'));
    actions.push(el('button', { class: 'btn secondary', onclick: (e) => act(e, 'invite', 'Invito inviato.', false, true) }, 'Invita a registrarsi'));
    if (isAdmin) actions.push(el('button', { class: 'btn danger', onclick: tempReset }, 'Reset con password temporanea'));
  }
  $('#ud-actions').replaceChildren(...actions);
  $('#ud-reason').value = '';
  $('#ud-events').replaceChildren(...u.lastEvents.map(e => el('tr', null, el('td', null, fmt(e.time)), el('td', null, e.eventId), el('td', null, e.message))));
  $('#user-detail').classList.remove('hidden');
}

async function act(ev, path, okText, confirmIt, noReason) {
  if (confirmIt && !confirm('Confermi?')) return;
  const body = noReason ? {} : { reason: $('#ud-reason').value };
  const ok = await guarded(ev.target, '#user-detail', async () => { await Api.post(`/admin/users/${encodeURIComponent(current.sid)}/${path}`, body); return true; });
  if (ok) { await detail(current.sid); message('#user-detail', 'ok', okText); }
}

async function tempReset(ev) {
  if (!confirm("Reimpostare la password con una temporanea? L'utente dovra' cambiarla al primo accesso.")) return;
  const r = await guarded(ev.target, '#user-detail', () => Api.post(`/admin/users/${encodeURIComponent(current.sid)}/reset`, { reason: $('#ud-reason').value }));
  if (!r) return;
  const box = message('#user-detail', 'ok', 'Password temporanea (mostrata una sola volta, comunicarla di persona o al telefono): ');
  box.append(el('code', { class: 'key' }, r.temporaryPassword));
}

// ------------------------------------------------------------------ audit, stato, configurazione
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
  const rows = await guarded(null, '#t-audit .card', () => Api.get('/admin/audit?' + p.toString()));
  p.set('format', 'csv');
  $('#a-csv').href = '/api/v1/admin/audit?' + p.toString();
  if (!rows) return;
  $('#audit').replaceChildren(...rows.slice(0, 500).map(r => el('tr', null,
    el('td', null, fmt(r.time || r.Time)), el('td', null, r.eventId ?? r.EventId),
    el('td', null, r.outcome ?? r.Outcome), el('td', null, r.targetUser ?? r.TargetUser ?? ''),
    el('td', null, r.actor ?? r.Actor ?? ''), el('td', null, r.clientIp ?? r.ClientIp ?? ''), el('td', null, r.message ?? r.Message))));
}

async function loadHealth() {
  const h = await guarded(null, '#t-health .card', () => Api.get('/admin/health'));
  if (!h) return;
  const labels = { version: 'Versione', server: 'Server', domainController: 'Domain controller', certificate: 'Certificato', masterKey: 'Chiave master', smtp: 'SMTP', sms: 'Gateway SMS' };
  $('#health').replaceChildren(...Object.entries(labels).map(([k, l]) => el('tr', null, el('th', null, l),
    el('td', null, el('span', { class: /^ERRORE|IN SCADENZA/.test(h[k] || '') ? 'badge err' : '' }, h[k] || '')))));
}

async function testChannel(ev, channel, destination) {
  const ok = await guarded(ev.target, '#t-health .card', async () => { await Api.post('/admin/test/' + channel, { destination }); return true; });
  if (ok) message('#t-health .card', 'ok', 'Messaggio di prova inviato.');
}

async function loadSettings() {
  const s = await guarded(null, '#t-settings .card', () => Api.get('/admin/settings'));
  if (s) $('#settings').value = JSON.stringify(s, null, 2);
}

async function saveSettings(ev) {
  let settings;
  try { settings = JSON.parse($('#settings').value); }
  catch (e) { message('#t-settings .card', 'err', 'JSON non valido: ' + e.message); return; }
  const body = { settings, smtpPassword: $('#smtp-pwd').value || null, smsPassword: $('#sms-pwd').value || null };
  const ok = await guarded(ev.target, '#t-settings .card', async () => { await Api.put('/admin/settings', body); return true; });
  if (ok) { $('#smtp-pwd').value = ''; $('#sms-pwd').value = ''; message('#t-settings .card', 'ok', 'Configurazione salvata.'); loadSettings(); }
}
