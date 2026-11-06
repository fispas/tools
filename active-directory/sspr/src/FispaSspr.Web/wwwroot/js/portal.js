'use strict';
// Portale utente: registrazione dei metodi, cambio password, reset e sblocco.
const State = { flow: null, purpose: null, destMethod: null, destChallenge: null, changeChallenge: null, checkTimer: null };
const LABELS = { totp: "App di autenticazione", sms: "SMS al cellulare", email: "Email personale" };

document.addEventListener('DOMContentLoaded', async () => {
  const s = await Api.refresh();
  applyBranding(s);
  updateWho();
  $$('[data-go]').forEach(b => b.addEventListener('click', () => go(b.dataset.go)));
  $('#btn-win').addEventListener('click', windowsLogin);
  $('#f-login').addEventListener('submit', login);
  $('#btn-logout').addEventListener('click', logout);
  $('#f-totp').addEventListener('submit', totpConfirm);
  $('#f-dest').addEventListener('submit', destStart);
  $('#f-dest-code').addEventListener('submit', destConfirm);
  $('#f-change').addEventListener('submit', changePassword);
  $('#c-send').addEventListener('click', changeSend);
  $('#c-method').addEventListener('change', changeMethodChanged);
  $('#f-start').addEventListener('submit', flowStart);
  $('#f-flow-code').addEventListener('submit', flowVerify);
  $('#f-newpwd').addEventListener('submit', flowComplete);
  $('#btn-unlock').addEventListener('click', flowComplete);
  liveCheck('#c-new', '#c-req', () => null);
  liveCheck('#n-new', '#n-req', () => State.flow && State.flow.flowId);
  show('v-home');
});

function updateWho() {
  const s = Api.session;
  $('#who').textContent = s && s.authenticated ? (s.displayName || s.userName) : '';
}

async function go(where) {
  if (where === 'home') { State.flow = null; show('v-home'); return; }
  if (where === 'reset' || where === 'unlock') {
    State.purpose = where;
    $('#start-title').textContent = where === 'reset' ? 'Reimposta la password' : "Sblocca l'account";
    $('#s-user').value = '';
    show('v-start');
    return;
  }
  if (where === 'account') {
    if (!Api.session.authenticated) {
      const s = await Api.windowsLogin().catch(() => null);
      if (!s || !s.authenticated) { show('v-login'); return; }
      updateWho();
    }
    await loadAccount();
  }
}

// ------------------------------------------------------------------ accesso
async function windowsLogin(ev) {
  const s = await guarded(ev.target, '#v-login', () => Api.windowsLogin());
  if (s && s.authenticated) { updateWho(); await loadAccount(); }
  else if (s !== undefined) message('#v-login', 'err', "Accesso con Windows non disponibile da questo PC: usa nome utente e password.");
}

async function login(ev) {
  ev.preventDefault();
  const btn = ev.submitter;
  const s = await guarded(btn, '#v-login', () => Api.post('/session/login', { userName: $('#l-user').value, password: $('#l-pwd').value }));
  $('#l-pwd').value = '';
  if (s) { Api.session = s; updateWho(); await loadAccount(); }
}

async function logout() {
  await Api.post('/session/logout').catch(() => null);
  await Api.refresh();
  updateWho();
  show('v-home');
}

// ------------------------------------------------------------------ metodi registrati
async function loadAccount() {
  const s = Api.session;
  if (s.manageable === false) {
    show('v-done');
    $('#done-title').textContent = 'Account non gestibile dal portale';
    $('#done-text').textContent = "Per motivi di sicurezza questo account (amministrativo, di servizio o fuori dagli ambiti abilitati) non puo' usare il portale. Contatta l'help desk.";
    return;
  }
  let st;
  try { st = await Api.get('/enrollment'); }
  catch (e) { show('v-login'); message('#v-login', 'err', errorText(e)); return; }
  renderEnrollment(st);
  show('v-account');
}

function renderEnrollment(st) {
  State.enrollment = st;
  $('#enroll-info').textContent = st.enrolled
    ? `Sei registrato con ${st.methods.length} metodi. Potrai usarli per reimpostare la password o sbloccare l'account.`
    : `Registra almeno ${st.minimumMethods} metodi: ti serviranno per reimpostare la password o sbloccare l'account senza chiamare l'help desk.`;
  const box = $('#methods');
  box.replaceChildren(...st.methods.map(m => el('div', { class: 'method' },
    el('div', null, el('div', { class: 'name' }, LABELS[m.method]), el('div', { class: 'muted' }, m.destinationMasked)),
    el('button', { class: 'btn secondary small', onclick: () => removeMethod(m.method) }, 'Rimuovi'))));
  if (!st.methods.length) box.append(el('p', { class: 'muted' }, 'Nessun metodo registrato.'));
  const add = $('#add-methods');
  const registered = st.methods.map(m => m.method);
  add.replaceChildren(...st.availableMethods.map(m => el('button', { class: 'btn', onclick: () => addMethod(m) },
    (registered.includes(m) ? 'Sostituisci: ' : 'Aggiungi: ') + LABELS[m])));
  // verifica per il cambio password
  const sel = $('#c-method');
  sel.replaceChildren(...st.methods.map(m => el('option', { value: m.method }, LABELS[m.method] + ' ' + (m.method === 'totp' ? '' : m.destinationMasked))));
  $('#c-verify').classList.toggle('hidden', st.methods.length === 0);
  changeMethodChanged();
}

async function removeMethod(m) {
  if (!confirm('Rimuovere il metodo "' + LABELS[m] + '"?')) return;
  const st = await guarded(null, '#v-account .card', () => Api.del('/enrollment/' + m));
  if (st) { renderEnrollment(st); message('#v-account .card', 'ok', 'Metodo rimosso.'); }
}

async function addMethod(m) {
  if (m === 'totp') {
    const r = await guarded(null, '#v-account .card', () => Api.post('/enrollment/totp/start'));
    if (!r) return;
    setQr($('#totp-qr'), r.qrCodeSvg);
    $('#totp-key').textContent = r.manualKey.replace(/(.{4})/g, '$1 ').trim();
    $('#t-code').value = '';
    show('v-totp');
    return;
  }
  State.destMethod = m;
  $('#dest-title').textContent = m === 'sms' ? 'Cellulare per gli SMS' : 'Email personale';
  $('#dest-label').textContent = m === 'sms' ? 'Numero di cellulare (es. 333 1234567)' : 'Indirizzo email personale (non quello aziendale)';
  $('#d-value').type = m === 'sms' ? 'tel' : 'email';
  $('#d-value').value = '';
  $('#f-dest').classList.remove('hidden');
  $('#f-dest-code').classList.add('hidden');
  show('v-dest');
}

async function totpConfirm(ev) {
  ev.preventDefault();
  const st = await guarded(ev.submitter, '#v-totp', () => Api.post('/enrollment/totp/confirm', { code: $('#t-code').value }));
  if (st) { renderEnrollment(st); show('v-account'); message('#v-account .card', 'ok', 'App di autenticazione registrata.'); }
}

async function destStart(ev) {
  ev.preventDefault();
  const r = await guarded(ev.submitter, '#v-dest', () => Api.post('/enrollment/' + State.destMethod + '/start', { destination: $('#d-value').value }));
  if (!r) return;
  State.destChallenge = r.challengeId;
  $('#dest-sent').textContent = 'Abbiamo inviato un codice a ' + r.destinationMasked + '.';
  $('#d-code').value = '';
  $('#f-dest').classList.add('hidden');
  $('#f-dest-code').classList.remove('hidden');
  $('#d-code').focus();
}

async function destConfirm(ev) {
  ev.preventDefault();
  const st = await guarded(ev.submitter, '#v-dest', () => Api.post('/enrollment/' + State.destMethod + '/confirm', { challengeId: State.destChallenge, code: $('#d-code').value }));
  if (st) { renderEnrollment(st); show('v-account'); message('#v-account .card', 'ok', 'Metodo registrato.'); }
}

// ------------------------------------------------------------------ cambio password
function changeMethodChanged() {
  const m = $('#c-method').value;
  $('#c-send').classList.toggle('hidden', !m || m === 'totp');
  State.changeChallenge = m === 'totp' ? 'totp' : null;
}

async function changeSend(ev) {
  const r = await guarded(ev.target, '#f-change', () => Api.post('/password/change/challenge', { method: $('#c-method').value }));
  if (r) { State.changeChallenge = r.challengeId; message('#f-change', 'info', 'Codice inviato a ' + r.destinationMasked + '.'); }
}

async function changePassword(ev) {
  ev.preventDefault();
  if ($('#c-new').value !== $('#c-new2').value) { message('#f-change', 'err', 'Le due password non coincidono.'); return; }
  const needsVerify = !$('#c-verify').classList.contains('hidden');
  const body = { currentPassword: $('#c-cur').value, newPassword: $('#c-new').value };
  if (needsVerify) body.verification = { challengeId: State.changeChallenge, code: $('#c-code').value };
  const ok = await guarded(ev.submitter, '#f-change', async () => { await Api.post('/password/change', body); return true; });
  if (ok) {
    ['#c-cur', '#c-new', '#c-new2', '#c-code'].forEach(s => $(s).value = '');
    show('v-done');
    $('#done-title').textContent = 'Password cambiata';
    $('#done-text').textContent = 'Usa la nuova password da subito. Sugli altri dispositivi (telefono, posta) aggiornala quando richiesto.';
  }
}

// ------------------------------------------------------------------ verifica dal vivo della nuova password
function liveCheck(input, list, flowId) {
  $(input).addEventListener('input', () => {
    clearTimeout(State.checkTimer);
    const value = $(input).value;
    if (!value) { $(list).replaceChildren(); return; }
    State.checkTimer = setTimeout(async () => {
      try {
        const r = await Api.post('/password/check', { password: value, flowId: flowId() });
        const items = [el('li', { class: value.length >= r.minLength ? 'okk' : 'bad' }, `Almeno ${r.minLength} caratteri`)];
        r.errors.filter(e => !/caratteri\.$/.test(e) || !/almeno/.test(e)).forEach(e => items.push(el('li', { class: 'bad' }, e)));
        if (r.valid) items.push(el('li', { class: 'okk' }, 'Password valida'));
        $(list).replaceChildren(...items);
      } catch (e) { /* la verifica completa avviene comunque all'invio */ }
    }, 450);
  });
}

// ------------------------------------------------------------------ reset e sblocco
async function flowStart(ev) {
  ev.preventDefault();
  const f = await guarded(ev.submitter, '#v-start', () => Api.post('/reset/start', { userName: $('#s-user').value, purpose: State.purpose }));
  if (f) { State.flow = f; renderFlow(); show('v-flow'); }
}

function renderFlow() {
  const f = State.flow;
  $('#flow-progress').textContent = `Verifiche completate: ${f.verificationsDone} di ${f.verificationsRequired}. Scegli come ricevere il codice.`;
  const box = $('#flow-methods');
  box.replaceChildren(...f.methods.map(m => el('div', { class: 'method' },
    el('div', null, el('div', { class: 'name' }, LABELS[m.method]), el('div', { class: 'muted' }, m.destinationMasked)),
    m.used ? el('span', { class: 'badge ok' }, 'verificato')
      : el('button', { class: 'btn small', onclick: (e) => flowChallenge(e, m.methodId) }, m.method === 'totp' ? 'Usa' : 'Invia codice'))));
  const ch = f.currentChallenge;
  $('#f-flow-code').classList.toggle('hidden', !ch);
  if (ch) {
    const m = f.methods.find(x => x.destinationMasked === ch.destinationMasked);
    $('#flow-sent').textContent = m && m.method === 'totp' ? "Inserisci il codice mostrato dall'app di autenticazione." : 'Codice inviato a ' + ch.destinationMasked + '.';
    $('#fl-code').value = '';
    setTimeout(() => $('#fl-code').focus(), 30);
  }
}

async function flowChallenge(ev, methodId) {
  const f = await guarded(ev.target, '#v-flow', () => Api.post(`/reset/${State.flow.flowId}/challenge`, { methodId }));
  if (f) { State.flow = f; renderFlow(); }
}

async function flowVerify(ev) {
  ev.preventDefault();
  let f;
  try { busy(ev.submitter, true); f = await Api.post(`/reset/${State.flow.flowId}/verify`, { code: $('#fl-code').value }); }
  catch (e) {
    message('#v-flow', 'err', errorText(e));
    if (/ricominciare/.test(e.message)) { State.flow = null; setTimeout(() => go('home'), 2500); }
    return;
  } finally { busy(ev.submitter, false); }
  State.flow = f;
  if (f.readyToComplete) {
    if (State.purpose === 'reset') { ['#n-new', '#n-new2'].forEach(s => $(s).value = ''); $('#n-req').replaceChildren(); show('v-newpwd'); }
    else show('v-unlock');
  } else { renderFlow(); message('#v-flow', 'ok', 'Verifica riuscita. Completa la verifica successiva.'); }
}

async function flowComplete(ev) {
  if (ev.preventDefault) ev.preventDefault();
  const btn = ev.submitter || ev.target;
  let body = {};
  if (State.purpose === 'reset') {
    if ($('#n-new').value !== $('#n-new2').value) { message('#v-newpwd', 'err', 'Le due password non coincidono.'); return; }
    body = { newPassword: $('#n-new').value };
  }
  const view = State.purpose === 'reset' ? '#v-newpwd' : '#v-unlock';
  const ok = await guarded(btn, view, async () => { await Api.post(`/reset/${State.flow.flowId}/complete`, body); return true; });
  if (!ok) return;
  ['#n-new', '#n-new2'].forEach(s => $(s).value = '');
  State.flow = null;
  show('v-done');
  $('#done-title').textContent = State.purpose === 'reset' ? 'Password reimpostata' : 'Account sbloccato';
  $('#done-text').textContent = State.purpose === 'reset'
    ? 'Ora puoi accedere con la nuova password. Su telefono e posta aggiornala quando richiesto.'
    : 'Ora puoi accedere di nuovo con la tua password.';
}
