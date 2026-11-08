'use strict';
// Portale utente: registrazione dei metodi, conferma d'identita', cambio password, reset e sblocco.
const State = { flow: null, purpose: null, destMethod: null, destChallenge: null, checkTimer: null, enrollment: null, retry: null, retryView: null, stepChallenge: null };
const M = (m) => T('method.' + m);
const F = () => Api.ui.features || {};

function applyUi() {
  applyTexts();
  applyBranding();
  applyFeatures();
  $('#flow-nocode').textContent = T('flow.noCode');
  renderLangPicker(() => { applyUi(); updateWho(Api.session); });
}

document.addEventListener('DOMContentLoaded', async () => {
  Api.initLang();
  await Api.loadUi();
  applyUi();
  const s = await Api.refresh();
  updateWho(s);
  $$('[data-go]').forEach(b => b.addEventListener('click', () => go(b.dataset.go)));
  $('#btn-win').addEventListener('click', windowsLogin);
  $('#f-login').addEventListener('submit', login);
  $('#btn-logout').addEventListener('click', logout);
  $('#f-totp').addEventListener('submit', totpConfirm);
  $('#f-dest').addEventListener('submit', destStart);
  $('#f-dest-code').addEventListener('submit', destConfirm);
  $('#f-change').addEventListener('submit', changePassword);
  $('#f-stepup').addEventListener('submit', stepUpVerify);
  $('#su-send').addEventListener('click', stepUpSend);
  $('#su-method').addEventListener('change', stepUpMethodChanged);
  $('#su-cancel').addEventListener('click', () => { State.retry = null; show(State.retryView || 'v-account'); });
  $('#f-start').addEventListener('submit', flowStart);
  $('#f-flow-code').addEventListener('submit', flowVerify);
  $('#f-newpwd').addEventListener('submit', flowComplete);
  $('#btn-unlock').addEventListener('click', flowComplete);
  if (F().showPasswordRequirements !== false) {
    liveCheck('#c-new', '#c-req', () => null);
    liveCheck('#n-new', '#n-req', () => State.flow && State.flow.flowId);
  }
  show('v-home');
});

// Funzioni disattivate in configurazione: nascoste (il servizio le rifiuta comunque)
function applyFeatures() {
  const f = F();
  const on = {
    reset: f.reset !== false, unlock: f.unlock !== false,
    account: (f.change !== false || f.enrollment !== false) && (f.windowsLogin !== false || f.passwordLogin !== false),
    windowsLogin: f.windowsLogin !== false, passwordLogin: f.passwordLogin !== false,
  };
  $$('[data-feature]').forEach(e => e.classList.toggle('hidden', !on[e.dataset.feature]));
  $('#card-change').classList.toggle('hidden', f.change === false);
}

function updateWho(s) {
  s = s || Api.session;
  $('#who').textContent = s && s.authenticated ? (s.displayName || s.userName) : '';
}

async function go(where) {
  if (where === 'home') { State.flow = null; show('v-home'); return; }
  if (where === 'reset' || where === 'unlock') {
    State.purpose = where;
    $('#start-title').textContent = T(where === 'reset' ? 'start.reset.title' : 'start.unlock.title');
    $('#s-user').value = '';
    show('v-start');
    return;
  }
  if (where === 'account') {
    if (!Api.session.authenticated) {
      const s = F().windowsLogin !== false ? await Api.windowsLogin().catch(() => null) : null;
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
  else if (s !== undefined) message('#v-login', 'err', T('login.windowsUnavailable'));
}

async function login(ev) {
  ev.preventDefault();
  const s = await guarded(ev.submitter, '#v-login', () => Api.post('/session/login', { userName: $('#l-user').value, password: $('#l-pwd').value }));
  $('#l-pwd').value = '';
  if (s) { Api.session = s; updateWho(); await loadAccount(); }
}

async function logout() {
  const s = await Api.post('/session/logout').catch(() => null);
  if (s) Api.session = s; else await Api.refresh();
  State.enrollment = null;
  updateWho();
  show('v-home');
}

// ------------------------------------------------------------------ conferma d'identita' (step-up)
// Azione protetta: se il servizio chiede la conferma con un metodo registrato, la si ottiene e si ripete l'azione.
async function protectedAction(button, container, view, fn) {
  busy(button, true);
  try { return await fn(); }
  catch (e) {
    if (e.code === 'err.stepUpRequired') { State.retry = fn; State.retryView = view; openStepUp(); return undefined; }
    if (e.code === 'err.windowsRequired') { message(container, 'err', e.message); return undefined; }
    message(container, 'err', errorText(e), e.errors);
    return undefined;
  } finally { busy(button, false); }
}

function openStepUp() {
  const st = State.enrollment;
  const sel = $('#su-method');
  const methods = (st ? st.methods : []).filter(m => !st.availableMethods.length || st.availableMethods.includes(m.method) || m.method === 'totp');
  sel.replaceChildren(...methods.map(m => el('option', { value: m.method }, M(m.method) + (m.method === 'totp' ? '' : ' ' + m.destinationMasked))));
  $('#su-code').value = '';
  $('#su-sent').textContent = '';
  State.stepChallenge = null;
  stepUpMethodChanged();
  show('v-stepup');
}

function stepUpMethodChanged() {
  const m = $('#su-method').value;
  $('#su-send').classList.toggle('hidden', !m || m === 'totp');
  if (m === 'totp') { State.stepChallenge = null; $('#su-sent').textContent = T('stepup.totpHint'); stepUpTotp(); }
  else $('#su-sent').textContent = '';
}

async function stepUpTotp() {
  try { const r = await Api.post('/stepup/challenge', { method: 'totp' }); State.stepChallenge = r.challengeId; }
  catch (e) { message('#v-stepup', 'err', errorText(e)); }
}

async function stepUpSend(ev) {
  const r = await guarded(ev.target, '#v-stepup', () => Api.post('/stepup/challenge', { method: $('#su-method').value }));
  if (r) { State.stepChallenge = r.challengeId; $('#su-sent').textContent = T('stepup.sent', { destination: r.destinationMasked }); $('#su-code').focus(); }
}

async function stepUpVerify(ev) {
  ev.preventDefault();
  if (!State.stepChallenge) { message('#v-stepup', 'err', T('err.codeRequestNew')); return; }
  const st = await guarded(ev.submitter, '#v-stepup', () => Api.post('/stepup/verify', { challengeId: State.stepChallenge, code: $('#su-code').value }));
  if (!st) return;
  State.enrollment = st;
  const fn = State.retry;
  State.retry = null;
  show(State.retryView || 'v-account');
  if (fn) {
    try { await fn(); }
    catch (e) { message('#' + (State.retryView || 'v-account'), 'err', errorText(e), e.errors); }
  } else message('#card-methods', 'ok', T('stepup.done'));
}

// ------------------------------------------------------------------ metodi registrati
async function loadAccount() {
  const s = Api.session;
  if (s.manageable === false) {
    done(T('account.notManageable.title'), T('account.notManageable.text'));
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
  $('#enroll-info').textContent = st.enrolled ? T('enroll.enrolled', { count: st.methods.length }) : T('enroll.notEnrolled', { min: st.minimumMethods });
  const box = $('#methods');
  box.replaceChildren(...st.methods.map(m => el('div', { class: 'method' },
    el('div', null, el('div', { class: 'name' }, M(m.method)), el('div', { class: 'muted' }, m.method === 'totp' ? '' : m.destinationMasked)),
    st.canRemove ? el('button', { class: 'btn secondary small', onclick: (e) => removeMethod(e, m.method) }, T('enroll.remove')) : null)));
  if (!st.methods.length) box.append(el('p', { class: 'muted' }, T('enroll.none')));
  const add = $('#add-methods');
  const registered = st.methods.map(m => m.method);
  if (st.firstEnrollmentBlocked) add.replaceChildren(el('div', { class: 'msg info', 'data-keep': '1' }, T('err.windowsRequired')));
  else if (!st.availableMethods.length && !st.methods.length) add.replaceChildren(el('p', { class: 'muted' }, T('enroll.disabled')));
  else add.replaceChildren(...st.availableMethods.map(m => el('button', { class: 'btn', onclick: (e) => addMethod(e, m) },
    T(registered.includes(m) ? 'enroll.replace' : 'enroll.add', { method: M(m) }))));
  $('#card-change').classList.toggle('hidden', st.changeEnabled === false);
}

async function removeMethod(ev, m) {
  if (!confirm(T('enroll.removeConfirm', { method: M(m) }))) return;
  const st = await protectedAction(ev.target, '#card-methods', 'v-account', async () => {
    const r = await Api.del('/enrollment/' + m);
    renderEnrollment(r); message('#card-methods', 'ok', T('enroll.removed'));
    return r;
  });
  return st;
}

async function addMethod(ev, m) {
  if (m === 'totp') {
    await protectedAction(ev.target, '#card-methods', 'v-account', async () => {
      const r = await Api.post('/enrollment/totp/start');
      setQr($('#totp-qr'), r.qrCodeSvg);
      $('#totp-key').textContent = r.manualKey.replace(/(.{4})/g, '$1 ').trim();
      $('#t-code').value = '';
      show('v-totp');
      return r;
    });
    return;
  }
  State.destMethod = m;
  $('#dest-title').textContent = T(m === 'sms' ? 'dest.sms.title' : 'dest.email.title');
  $('#dest-label').textContent = T(m === 'sms' ? 'dest.sms.label' : 'dest.email.label');
  $('#d-value').type = m === 'sms' ? 'tel' : 'email';
  $('#d-value').autocomplete = m === 'sms' ? 'tel' : 'email';
  $('#d-value').value = '';
  $('#f-dest').classList.remove('hidden');
  $('#f-dest-code').classList.add('hidden');
  show('v-dest');
}

async function totpConfirm(ev) {
  ev.preventDefault();
  const st = await protectedAction(ev.submitter, '#v-totp', 'v-totp', () => Api.post('/enrollment/totp/confirm', { code: $('#t-code').value }));
  if (st) { renderEnrollment(st); show('v-account'); message('#card-methods', 'ok', T('enroll.totpAdded')); }
}

async function destStart(ev) {
  ev.preventDefault();
  const value = $('#d-value').value;
  await protectedAction(ev.submitter, '#v-dest', 'v-dest', async () => {
    const r = await Api.post('/enrollment/' + State.destMethod + '/start', { destination: value });
    State.destChallenge = r.challengeId;
    $('#dest-sent').textContent = T('dest.sent', { destination: r.destinationMasked });
    $('#d-code').value = '';
    $('#f-dest').classList.add('hidden');
    $('#f-dest-code').classList.remove('hidden');
    $('#d-code').focus();
    return r;
  });
}

async function destConfirm(ev) {
  ev.preventDefault();
  const st = await protectedAction(ev.submitter, '#v-dest', 'v-dest', () => Api.post('/enrollment/' + State.destMethod + '/confirm', { challengeId: State.destChallenge, code: $('#d-code').value }));
  if (st) { renderEnrollment(st); show('v-account'); message('#card-methods', 'ok', T('enroll.added')); }
}

// ------------------------------------------------------------------ cambio password
async function changePassword(ev) {
  ev.preventDefault();
  if ($('#c-new').value !== $('#c-new2').value) { message('#f-change', 'err', T('change.mismatch')); return; }
  const body = { currentPassword: $('#c-cur').value, newPassword: $('#c-new').value };
  const ok = await protectedAction(ev.submitter, '#f-change', 'v-account', async () => {
    await Api.post('/password/change', body);
    ['#c-cur', '#c-new', '#c-new2'].forEach(s => $(s).value = '');
    $('#c-req').replaceChildren();
    done(T('change.done.title'), T('change.done.text'));
    return true;
  });
  return ok;
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
        const items = [el('li', { class: value.length >= r.minLength ? 'okk' : 'bad' }, T('pwd.minLength', { min: r.minLength }))];
        // la lunghezza minima ha gia' la sua riga: gli altri requisiti mancanti nella lingua dell'utente
        (r.errors || []).forEach((e, i) => { if ((r.codes || [])[i] !== 'pwd.err.minLength') items.push(el('li', { class: 'bad' }, e)); });
        if (r.valid) items.push(el('li', { class: 'okk' }, T('pwd.valid')));
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
  $('#flow-progress').textContent = T('flow.progress', { done: f.verificationsDone, required: f.verificationsRequired });
  const box = $('#flow-methods');
  box.replaceChildren(...f.methods.map(m => el('div', { class: 'method' },
    el('div', null, el('div', { class: 'name' }, M(m.method)), el('div', { class: 'muted' }, m.method === 'totp' ? '' : m.destinationMasked)),
    m.used ? el('span', { class: 'badge ok' }, T('flow.verified'))
      : el('button', { class: 'btn small', onclick: (e) => flowChallenge(e, m.methodId) }, T(m.method === 'totp' ? 'flow.use' : 'flow.send')))));
  const ch = f.currentChallenge;
  $('#f-flow-code').classList.toggle('hidden', !ch);
  if (ch) {
    $('#flow-sent').textContent = ch.method === 'totp' ? T('flow.totpHint') : T('flow.sent', { destination: ch.destinationMasked });
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
    if (e.code === 'err.tooManyCodes' || e.code === 'err.flowExpired' || e.code === 'err.verifyBlocked') { State.flow = null; setTimeout(() => go('home'), 4000); }
    return;
  } finally { busy(ev.submitter, false); }
  State.flow = f;
  if (f.readyToComplete) {
    if (State.purpose === 'reset') { ['#n-new', '#n-new2'].forEach(s => $(s).value = ''); $('#n-req').replaceChildren(); show('v-newpwd'); }
    else show('v-unlock');
  } else { renderFlow(); message('#v-flow', 'ok', T('flow.next')); }
}

async function flowComplete(ev) {
  if (ev.preventDefault) ev.preventDefault();
  const btn = ev.submitter || ev.target;
  let body = {};
  if (State.purpose === 'reset') {
    if ($('#n-new').value !== $('#n-new2').value) { message('#v-newpwd', 'err', T('change.mismatch')); return; }
    body = { newPassword: $('#n-new').value };
  }
  const view = State.purpose === 'reset' ? '#v-newpwd' : '#v-unlock';
  const ok = await guarded(btn, view, async () => { await Api.post(`/reset/${State.flow.flowId}/complete`, body); return true; });
  if (!ok) return;
  ['#n-new', '#n-new2'].forEach(s => $(s).value = '');
  State.flow = null;
  if (State.purpose === 'reset') done(T('done.reset.title'), T('done.reset.text'));
  else done(T('done.unlock.title'), T('done.unlock.text'));
}

function done(title, text) {
  $('#done-title').textContent = title;
  $('#done-text').textContent = text;
  show('v-done');
}
