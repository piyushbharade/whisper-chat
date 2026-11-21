// Whisper – disappearing-message chat (front-end demo, no backend)
// Accounts and contacts are saved in this browser's localStorage. Passwords are only
// lightly hashed for the demo – a real app must hash and verify them on a server.

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hueOf = str => { let h = 0; for (const c of str) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };
const nowTime = () => new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
const RING = 50.27; // circumference of r=8 ring
const socket = io();

/* ---------- End-to-End Encryption (AES-GCM via Web Crypto API) ---------- */
const e2ee = (() => {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const fromB64 = str => Uint8Array.from(atob(str), c => c.charCodeAt(0));

  async function getRoomKey(u1, u2) {
    const seed = [u1.toLowerCase(), u2.toLowerCase()].sort().join('::whisper-e2ee::');
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(seed));
    return crypto.subtle.importKey('raw', hashBuf, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  return {
    async encrypt(plainText, u1, u2) {
      if (!plainText) return '';
      const key = await getRoomKey(u1, u2);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plainText));
      return `enc:${toB64(iv)}:${toB64(cipher)}`;
    },
    async decrypt(payload, u1, u2) {
      if (!payload || !payload.startsWith('enc:')) return payload || '';
      try {
        const [, ivB64, cipherB64] = payload.split(':');
        const key = await getRoomKey(u1, u2);
        const plainBuf = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: fromB64(ivB64) },
          key,
          fromB64(cipherB64)
        );
        return dec.decode(plainBuf);
      } catch {
        return '[Encrypted message]';
      }
    }
  };
})();

let authToken = sessionStorage.getItem('whisper.jwt') || '';
function setAuthToken(t) {
  authToken = t || '';
  if (t) sessionStorage.setItem('whisper.jwt', t);
  else sessionStorage.removeItem('whisper.jwt');
}

async function api(url, method = 'GET', body = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

socket.on('receive_message', async (msg) => {
  if (!state.loggedIn || msg.sender.toLowerCase() === state.user.toLowerCase()) return;
  const chatId = msg.sender.toLowerCase();
  if (!state.chats[chatId]) {
    state.chats[chatId] = makeChat({ id: chatId, name: chatId, status: 'online', sub: 'Teammate', retention: msg.life || 10, note: '', muted: false });
  }
  const c = state.chats[chatId];
  const plainText = await e2ee.decrypt(msg.text, state.user, chatId);
  const m = {
    id: msg._id, from: chatId, text: plainText, time: nowTime(),
    life: msg.life, attach: msg.attach,
    expiresAt: msg.expiresAt ? new Date(msg.expiresAt).getTime() : null
  };
  c.messages.push(m);
  c.stat.recv++;
  if (chatId === state.activeId && state.tab === 'chats') {
    $('#feed').insertAdjacentHTML('beforeend', msgHTML(m, c));
    if (m.expiresAt) updateMsgEl($('#m-' + m.id), m);
    $('#feed').scrollTop = $('#feed').scrollHeight;
  }
  if (state.settings.sound && !c.muted) beep();
  renderList();
});
socket.on('policy_updated', (pol) => {
  if (!pol) return;
  store.set('whisper.policy', pol);
  if (state.loggedIn) applyPolicyUi();
});

socket.on('chat_vanished', ({ scope, u1, u2 }) => {
  if (!state.loggedIn) return;
  if (scope === 'all') {
    Object.values(state.chats).forEach(c => { c.messages.forEach(freeMsg); c.messages = []; });
    renderList(); renderFeed();
    toast('All conversations vanished across devices');
  } else if (scope === 'room') {
    const peer = u1 === state.user ? u2 : (u2 === state.user ? u1 : null);
    if (peer && state.chats[peer]) {
      state.chats[peer].messages.forEach(freeMsg);
      state.chats[peer].messages = [];
      renderList();
      if (state.activeId === peer) renderFeed();
    }
  }
});

/* ---------- storage (localStorage with in-memory fallback) ---------- */
const mem = {};
const store = {
  get(k, d) {
    if (k in mem) return mem[k];
    try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; }
  },
  set(k, v) { mem[k] = v; try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } },
  del(k) { delete mem[k]; try { localStorage.removeItem(k); } catch { /* ignore */ } }
};
function hash(s) { // demo-only string hash, NOT secure
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); h1 = Math.imul(h1 ^ c, 2654435761); h2 = Math.imul(h2 ^ c, 1597334677); }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}

let accounts = store.get('whisper.accounts', null);
if (!accounts) {
  accounts = { rasmalai: { username: 'rasmalai', name: 'Rasmalai', email: 'rasmalai@example.com', companyId: 'WH-1001', pw: hash('supersecret') } };
  store.set('whisper.accounts', accounts);
}
// accounts saved by an older version have no company ID yet
if (Object.values(accounts).some(a => !a.companyId)) {
  Object.values(accounts).forEach(a => { if (!a.companyId) a.companyId = a.username === 'rasmalai' ? 'WH-1001' : 'WH-0000'; });
  store.set('whisper.accounts', accounts);
}
// Admin accounts. Change the default admin password before using this for real.
let admins = store.get('whisper.admins', null);
if (!admins) {
  const old = store.get('whisper.admin', null); // single admin saved by the previous version
  admins = { admin: { username: 'admin', name: 'Admin', adminId: 'ADM-1001', email: 'admin@whisper.app', pw: hash('admin@123'), ...(old || {}) } };
  store.set('whisper.admins', admins);
}
const saveAdmins = () => store.set('whisper.admins', admins);
// admins saved by an older version have no admin ID yet
if (Object.values(admins).some(a => !a.adminId)) {
  Object.values(admins).forEach((a, i) => { if (!a.adminId) a.adminId = a.username === 'admin' ? 'ADM-1001' : `ADM-${1002 + i}`; });
  saveAdmins();
}
const findAdmin = id => {
  const k = id.trim().toLowerCase();
  return admins[normUser(k)] || Object.values(admins).find(a => a.email.toLowerCase() === k) || null;
};
const saveAccounts = () => store.set('whisper.accounts', accounts);
const normUser = s => s.trim().toLowerCase().replace(/\s+/g, '_');
const findAccount = id => {
  const k = id.trim().toLowerCase();
  return accounts[normUser(k)] || Object.values(accounts).find(a => a.email.toLowerCase() === k) || null;
};

/* ---------- state ---------- */
const DEFAULT_SETTINGS = { theme: 'light', accent: 'teal', defaultLife: 10, typing: true, autoReply: false, blur: false, sound: false };
const ACCENTS = { teal: ['#0f766e', '#14958a'], indigo: ['#4338ca', '#6366f1'], rose: ['#be123c', '#e11d48'], plum: ['#7e22ce', '#9333ea'], ocean: ['#0369a1', '#0ea5e9'] };
const SEED_CONTACTS = [
  { id: 'bhumi',  name: 'Bhumi',  status: 'online', sub: 'Disappearing mode on', retention: 10, note: 'Design lead. Replies fast.', muted: false },
  { id: 'vikram', name: 'Vikram', status: 'online', sub: 'Around for a chat',    retention: 30, note: 'Weekend trek planner.',     muted: false },
  { id: 'arjun',  name: 'Arjun',  status: 'idle',   sub: 'Playing Valorant',     retention: 5,  note: 'Gaming buddy.',             muted: false }
];
const BOT_CONTACT = { id: 'whisper-bot', name: 'Whisper Bot', status: 'online', sub: 'Your guide to Whisper', retention: 30, note: 'Ask me anything about timers.', muted: false };

const state = {
  user: null, me: {}, settings: { ...DEFAULT_SETTINGS },
  tab: 'chats', activeId: null, seq: 0,
  chats: {}, log: [], infoId: null, lifeTarget: null, reset: null
};

const REPLIES = [
  'Received loud and clear! Timer is synced ⏱️',
  'This disappearing-chat interface looks great.',
  'Zero footprint once the countdown ends.',
  'Got it. Ready for the next message.',
  'Ha, that one will be gone in a moment 👀'
];
const EMOJIS = ['😊', '😂', '🔥', '✨', '👍', '🎉', '🤫', '💬'];

/* ---------- helpers ---------- */
function avatar(name, url, cls = '') {
  const img = url ? `<img src="${esc(url)}" alt="" onerror="this.remove()">` : '';
  return `<span class="av ${cls}" style="--h:${hueOf(name)}">${esc(name.charAt(0).toUpperCase())}${img}</span>`;
}
const activeChat = () => state.chats[state.activeId];
function fmtLife(s) {
  if (!s) return 'Off';
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${s % 60 ? ' ' + (s % 60) + 's' : ''}`;
  return `${Math.floor(s / 3600)}h${Math.floor((s % 3600) / 60) ? ' ' + Math.floor((s % 3600) / 60) + 'm' : ''}`;
}
const fmtLong = s => !s ? 'permanently' : s === 1 ? '1 second' : s < 60 ? `${s} seconds` : `${fmtLife(s)}`;

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

function beep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.type = 'sine'; o.frequency.value = 660; g.gain.value = 0.04;
    o.connect(g); g.connect(ctx.destination); o.start();
    g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.25);
    o.stop(ctx.currentTime + 0.26);
  } catch { /* audio unavailable */ }
}

function persist() {
  if (!state.user) return;
  const { bio, avatarUrl, banner } = state.me;
  const payload = {
    name: state.me.name, bio, avatarUrl, banner,
    settings: state.settings,
    contacts: Object.values(state.chats).map(({ id, name, status, sub, retention, note, muted }) => ({ id, name, status, sub, retention, note, muted }))
  };
  store.set('whisper.data.' + state.user, payload);
  api(`/api/users/${state.user}/sync`, 'PUT', payload).catch(() => {});
}

/* ---------- theme ---------- */
function applyTheme() {
  const s = state.settings;
  const dark = s.theme === 'dark' || (s.theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  const [a, b] = ACCENTS[s.accent] || ACCENTS.teal;
  document.documentElement.style.setProperty('--accent', a);
  document.documentElement.style.setProperty('--accent-2', b);
  $('#feed').classList.toggle('blur', !!s.blur);
}

/* ---------- auth views ---------- */
function showAuth(name) {
  document.body.classList.add('auth-mode');            // auth pages are always plain white
  document.documentElement.dataset.theme = 'light';
  $$('.auth').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
  $$('.form-error').forEach(e => e.textContent = '');
  const first = $(`#view-${name} input:not([type=checkbox])`);
  if (first && window.innerWidth > 820) first.focus();
}
$$('[data-auth]').forEach(a => a.addEventListener('click', e => {
  e.preventDefault();
  if (a.dataset.auth === 'login') { setForgotStep(1); }
  showAuth(a.dataset.auth);
}));
$('#register-link').addEventListener('click', e => { e.preventDefault(); showAuth('register'); });
$('#forgot-link').addEventListener('click', e => {
  e.preventDefault();
  setForgotStep(1);
  $('#forgot-id').value = $('#username-input').value.trim();
  showAuth('forgot');
});
$$('[data-toggle-pw]').forEach(b => b.addEventListener('click', () => {
  const inp = b.parentElement.querySelector('input');
  const show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  b.classList.toggle('on', show);
  b.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
}));

/* --- password strength --- */
function strengthOf(pw) {
  if (pw.length < 8) return pw ? 1 : 0;
  let n = 1;
  if (pw.length >= 12) n++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) n++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) n++;
  return Math.min(n, 4);
}
const STRENGTH_LABELS = ['Use 8+ characters', 'Too weak', 'Okay', 'Good', 'Strong'];
$('#reg-password').addEventListener('input', e => {
  const lv = strengthOf(e.target.value);
  $('#reg-strength').dataset.level = lv;
  $('#reg-strength-label').textContent = STRENGTH_LABELS[lv];
});

function mergeTeammates(userObj, teammates = []) {
  const existing = userObj.contacts || [];
  const map = new Map(existing.map(c => [c.id, c]));
  teammates.forEach(t => {
    if (!map.has(t.username)) {
      map.set(t.username, {
        id: t.username,
        name: t.name,
        status: 'online',
        sub: `${userObj.companyId} teammate`,
        retention: userObj.settings?.defaultLife ?? 10,
        note: t.bio || '',
        muted: false
      });
    }
  });
  return [...map.values()];
}

/* --- sign in --- */
$('#login-form').addEventListener('submit', async e => {
  e.preventDefault();
  const id = $('#username-input').value.trim(), pw = $('#password-input').value, cid = $('#company-input').value.trim();
  const err = $('#login-error');
  if (!id || !pw || !cid) { err.textContent = 'Enter your username or email, password and company ID.'; return; }
  try {
    const data = await api('/api/auth/login', 'POST', { id, password: pw, companyId: cid });
    setAuthToken(data.token);
    accounts[data.user.username] = data.user;
    store.set('whisper.data.' + data.user.username, {
      me: { bio: data.user.bio, avatarUrl: data.user.avatarUrl, banner: data.user.banner },
      settings: data.user.settings,
      contacts: mergeTeammates(data.user, data.teammates)
    });
    err.textContent = '';
    $('#company-input').value = '';
    enterApp(data.user.username);
  } catch (ex) {
    err.textContent = ex.message;
  }
});

/* --- create account --- */
$('#register-form').addEventListener('submit', async e => {
  e.preventDefault();
  const name = $('#reg-name').value.trim(), uname = normUser($('#reg-username').value);
  const email = $('#reg-email').value.trim(), pw = $('#reg-password').value, pw2 = $('#reg-confirm').value;
  const company = $('#reg-company').value.trim().toUpperCase();
  const err = $('#reg-error');
  const fail = m => { err.textContent = m; };
  if (!name) return fail('Add a display name.');
  if (!/^[a-z0-9_]{3,20}$/.test(uname)) return fail('Usernames use 3–20 letters, numbers or underscores.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail('Enter a valid email address.');
  if (!/^[A-Z0-9-]{3,20}$/.test(company)) return fail('Enter your employee company ID (3–20 letters, numbers or dashes).');
  if (pw.length < 8) return fail('Password needs at least 8 characters.');
  if (pw !== pw2) return fail('The two passwords don\'t match.');
  if (!$('#reg-terms').checked) return fail('Tick the box to confirm you understand.');
  try {
    const data = await api('/api/auth/register', 'POST', { name, username: uname, email, companyId: company, password: pw });
    setAuthToken(data.token);
    accounts[uname] = data.user;
    store.set('whisper.data.' + uname, {
      me: { bio: data.user.bio, avatarUrl: data.user.avatarUrl, banner: data.user.banner },
      settings: data.user.settings,
      contacts: mergeTeammates(data.user, data.teammates)
    });
    e.target.reset();
    $('#reg-strength').dataset.level = 0; $('#reg-strength-label').textContent = STRENGTH_LABELS[0];
    $('#password-input').value = '';
    enterApp(uname);
    toast(`Welcome to Whisper, ${name}!`);
  } catch (ex) {
    fail(ex.message);
  }
});

/* --- admin login, account creation + dashboard --- */
let adminSession = null;
let adminRole = 'company_admin';
let adminCompanyId = '';
let liveAudit = [];

$('#admin-form').addEventListener('submit', async e => {
  e.preventDefault();
  const id = $('#admin-username').value.trim().toLowerCase();
  const aid = $('#admin-id').value.trim();
  const cid = $('#admin-company').value.trim();
  const pw = $('#admin-pw').value;
  const err = $('#admin-error');
  if (!id || !aid || !cid || !pw) { err.textContent = 'Enter your username, admin ID, company ID and password.'; return; }
  try {
    const data = await api('/api/admin/login', 'POST', { username: id, adminId: aid, companyId: cid, password: pw });
    setAuthToken(data.token);
    admins[data.admin.username] = data.admin;
    adminSession = data.admin.username;
    adminRole = data.admin.role;
    adminCompanyId = data.admin.companyId;
    err.textContent = '';
    e.target.reset();
    await openAdminPanel();
  } catch (ex) {
    err.textContent = ex.message;
  }
});

/* --- admin dashboard --- */
const POLICY_DEFAULT = { allowSignup: true, allowUploads: true, allowViewOnce: true, maxMB: 10 };
const getPolicy = () => ({ ...POLICY_DEFAULT, ...store.get('whisper.policy', {}) });
const fmtDate = ts => ts ? new Date(ts).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
const fmtDT = ts => new Date(ts).toLocaleString([], { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' });

let adTab = 'overview', empEdit = null, rpUser = null;

async function syncAdminData() {
  try {
    const data = await api('/api/admin/dashboard');
    accounts = {};
    data.employees.forEach(u => {
      accounts[u.username] = u;
      store.set('whisper.data.' + u.username, { contacts: u.contacts || [] });
    });
    admins = {};
    data.admins.forEach(a => { admins[a.username] = a; });
    if (data.policy) {
      store.set('whisper.policy', data.policy);
      liveAudit = data.policy.audit || [];
    }
  } catch (ex) {
    console.error('Admin sync error:', ex.message);
  }
}

async function openAdminPanel() {
  adTab = 'overview';
  await syncAdminData();
  renderAdmin();
  showAuth('adminpanel');
}

$$('[data-ad]').forEach(b => b.addEventListener('click', async () => {
  adTab = b.dataset.ad;
  await syncAdminData();
  renderAdmin();
}));

function renderAdmin() {
  const me = admins[adminSession];
  const isSuper = adminRole === 'whisper_admin';
  const roleLabel = isSuper ? 'Whisper Super Admin' : `Company Admin · ${adminCompanyId}`;
  $('#ad-who').textContent = me ? `${me.name} · ${me.adminId} (${roleLabel})` : '';
  // Only Whisper Super Admin sees global policy tab & + Add Admin button
  const polTab = document.querySelector('[data-ad="policy"]');
  if (polTab) polTab.hidden = !isSuper;
  const addAdminBtn = $('#ad-add-admin');
  if (addAdminBtn) addAdminBtn.hidden = !isSuper;

  $$('[data-ad]').forEach(b => b.classList.toggle('on', b.dataset.ad === adTab));
  ['overview', 'employees', 'admins', 'policy'].forEach(t => $('#ad-' + t).hidden = t !== adTab);
  if (adTab === 'overview') renderAdOverview();
  if (adTab === 'employees') renderAdEmployees();
  if (adTab === 'admins') renderAdAdmins();
  if (adTab === 'policy' && isSuper) renderAdPolicy();
}

function renderAdOverview() {
  const list = Object.values(accounts);
  const active = list.filter(a => !a.disabled).length;
  const byCo = {};
  list.forEach(a => { byCo[a.companyId] = (byCo[a.companyId] || 0) + 1; });
  const contacts = list.reduce((n, a) => n + (a.contacts?.length || 0), 0);
  const tile = (n, label, cls) => `<div class="tile ${cls}"><b>${n}</b><span>${label}</span></div>`;
  $('#ad-tiles').innerHTML = tile(list.length, 'Employees', 't1') + tile(active, 'Active', 't2') + tile(list.length - active, 'Suspended', 't3')
    + tile(Object.keys(admins).length, 'Admins', 't4') + tile(Object.keys(byCo).length, 'Company IDs', 't2') + tile(contacts, 'Contacts added', 't1');
  const max = Math.max(1, ...Object.values(byCo));
  $('#ad-companies').innerHTML = Object.entries(byCo).sort((a, b) => b[1] - a[1]).map(([id, n]) =>
    `<div class="crow" style="--h:${hueOf(id)}"><span class="cname">${esc(id)}</span><span class="ctrack"><i style="width:${n / max * 100}%"></i></span><span class="cval">${n}</span></div>`).join('')
    || '<p class="no-results">No employees yet.</p>';
  const log = liveAudit.slice(0, 10);
  $('#ad-activity').innerHTML = log.length
    ? log.map(l => `<li><span class="vdot"></span><span><b>${esc(l.by)}</b> ${esc(l.text)}</span><small>${fmtDT(l.t)}</small></li>`).join('')
    : '<li class="vempty">Changes you make will show up here.</li>';
}

function renderAdEmployees() {
  const q = $('#ad-search').value.trim().toLowerCase();
  const all = Object.values(accounts);
  const list = all.filter(a => [a.name, a.username, a.email, a.companyId].join(' ').toLowerCase().includes(q));
  $('#ad-emp-count').textContent = `${all.length} ${all.length === 1 ? 'employee' : 'employees'}${q ? ` · ${list.length} shown` : ''}`;
  $('#ad-emp-list').innerHTML = list.map(a => {
    const n = a.contacts?.length || 0;
    return `<div class="a-row ${a.disabled ? 'off' : ''}">
      <span class="av-wrap">${avatar(a.name, '')}</span>
      <span class="row-text"><b>${esc(a.name)} <span class="pill ${a.disabled ? 'bad' : 'ok'}">${a.disabled ? 'Suspended' : 'Active'}</span></b><small>@${esc(a.username)} · ${esc(a.email)} · joined ${fmtDate(a.createdAt)} · ${n} ${n === 1 ? 'contact' : 'contacts'}</small></span>
      <span class="cid">${esc(a.companyId)}</span>
      <span class="a-actions">
        <button class="btn ghost sm" data-emp="edit" data-u="${esc(a.username)}">Edit</button>
        <button class="btn ghost sm" data-emp="reset" data-u="${esc(a.username)}">Reset password</button>
        <button class="btn ghost sm" data-emp="toggle" data-u="${esc(a.username)}">${a.disabled ? 'Reactivate' : 'Suspend'}</button>
        <button class="btn danger sm" data-emp="del" data-u="${esc(a.username)}">Remove</button>
      </span></div>`;
  }).join('') || `<p class="no-results">${all.length ? 'No employees match your search.' : 'No employees yet. Add the first one.'}</p>`;
}
$('#ad-search').addEventListener('input', renderAdEmployees);

function openEmpForm(username) {
  empEdit = username || null;
  const a = username ? accounts[username] : null;
  const isSuper = adminRole === 'whisper_admin';
  $('#emp-form').reset();
  $('#emp-error').textContent = '';
  $('#emp-title').textContent = a ? 'Edit employee' : 'Add employee';
  $('#emp-save').textContent = a ? 'Save changes' : 'Add employee';
  $('#emp-pw-row').hidden = !!a;
  $('#emp-username').disabled = !!a;
  $('#emp-company').disabled = !isSuper;
  if (!isSuper) $('#emp-company').value = adminCompanyId;
  if (a) { $('#emp-name').value = a.name; $('#emp-username').value = a.username; $('#emp-email').value = a.email; $('#emp-company').value = a.companyId; }
  openOverlay('emp-overlay');
}
$('#ad-add-emp').addEventListener('click', () => openEmpForm());

$('#emp-form').addEventListener('submit', async e => {
  e.preventDefault();
  const name = $('#emp-name').value.trim(), email = $('#emp-email').value.trim();
  const company = (adminRole === 'whisper_admin' ? $('#emp-company').value : adminCompanyId).trim().toUpperCase();
  const err = $('#emp-error'), fail = m => { err.textContent = m; };
  const uname = empEdit || normUser($('#emp-username').value);
  const by = admins[adminSession]?.name || 'Admin';
  if (!name) return fail('Add the employee\'s full name.');
  if (!empEdit && !/^[a-z0-9_]{3,20}$/.test(uname)) return fail('Usernames use 3–20 letters, numbers or underscores.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail('Enter a valid email address.');
  if (!/^[A-Z0-9-]{3,20}$/.test(company)) return fail('Company ID uses 3–20 letters, numbers or dashes.');

  try {
    if (empEdit) {
      await api(`/api/admin/employees/${uname}`, 'PATCH', { name, email, companyId: company, by, auditText: `updated ${name} (@${uname})` });
      toast('Employee updated');
    } else {
      const pw = $('#emp-pw').value;
      if (pw.length < 8) return fail('Temporary password needs at least 8 characters.');
      await api('/api/admin/employees', 'POST', { name, username: uname, email, companyId: company, password: pw, by });
      toast(`${name} added to ${company}.`);
    }
    closeOverlay('emp-overlay');
    await syncAdminData();
    renderAdmin();
  } catch (ex) {
    fail(ex.message);
  }
});

$('#ad-emp-list').addEventListener('click', async e => {
  const b = e.target.closest('[data-emp]');
  if (!b) return;
  const u = b.dataset.u, a = accounts[u];
  const by = admins[adminSession]?.name || 'Admin';
  if (!a) return;
  if (b.dataset.emp === 'edit') openEmpForm(u);
  if (b.dataset.emp === 'reset') {
    rpUser = u;
    $('#rp-sub').textContent = `Set a new password for ${a.name} (@${u}).`;
    $('#rp-form').reset(); $('#rp-error').textContent = '';
    openOverlay('rp-overlay');
  }
  if (b.dataset.emp === 'toggle') {
    const nextState = !a.disabled;
    await api(`/api/admin/employees/${u}`, 'PATCH', {
      disabled: nextState, by,
      auditText: `${nextState ? 'suspended' : 'reactivated'} ${a.name} (@${u})`
    });
    toast(`${a.name} ${nextState ? 'suspended. They can\'t sign in.' : 'reactivated'}`);
    await syncAdminData();
    renderAdmin();
  }
  if (b.dataset.emp === 'del') {
    if (!confirm(`Remove ${a.name} (@${u})? Their profile and contacts will be deleted.`)) return;
    await api(`/api/admin/employees/${u}?by=${encodeURIComponent(by)}`, 'DELETE');
    toast(`${a.name} removed`);
    await syncAdminData();
    renderAdmin();
  }
});

$('#rp-form').addEventListener('submit', async e => {
  e.preventDefault();
  const pw = $('#rp-pw').value, a = accounts[rpUser];
  const by = admins[adminSession]?.name || 'Admin';
  if (!a) return;
  if (pw.length < 8) { $('#rp-error').textContent = 'Password needs at least 8 characters.'; return; }
  await api(`/api/admin/employees/${a.username}`, 'PATCH', {
    newPassword: pw, by,
    auditText: `reset the password for ${a.name} (@${a.username})`
  });
  closeOverlay('rp-overlay');
  toast(`Password reset for ${a.name}`);
  await syncAdminData();
  renderAdmin();
});

function renderAdAdmins() {
  const list = Object.values(admins);
  const isSuper = adminRole === 'whisper_admin';
  $('#ad-admin-count').textContent = `${list.length} ${list.length === 1 ? 'admin' : 'admins'}`;
  $('#ad-admin-list').innerHTML = list.map(a => {
    const badge = a.companyId === 'WHISPER-HQ' ? '<span class="pill ok">Whisper Admin</span>' : `<span class="pill">${esc(a.companyId)} Admin</span>`;
    const delBtn = (isSuper && a.username !== adminSession)
      ? `<button class="btn danger sm" data-del-admin="${esc(a.username)}">Remove</button>` : '';
    return `<div class="a-row">
      <span class="av-wrap">${avatar(a.name, '')}</span>
      <span class="row-text"><b>${esc(a.name)} ${badge}${a.username === adminSession ? ' <span class="pill ok">You</span>' : ''}</b><small>@${esc(a.username)} · ${esc(a.email)}</small></span>
      <span class="cid">${esc(a.adminId)}</span>
      <span class="a-actions">${delBtn}</span></div>`;
  }).join('');
}

$('#ad-add-admin')?.addEventListener('click', () => {
  $('#addadmin-form').reset();
  $('#aa-error').textContent = '';
  openOverlay('addadmin-overlay');
});

$('#addadmin-form')?.addEventListener('submit', async e => {
  e.preventDefault();
  const err = $('#aa-error'), fail = m => { err.textContent = m; };
  const name = $('#aa-name').value.trim();
  const uname = normUser($('#aa-username').value);
  const email = $('#aa-email').value.trim();
  const aid = $('#aa-aid').value.trim().toUpperCase();
  const cid = $('#aa-cid').value.trim().toUpperCase();
  const pw = $('#aa-pw').value;
  if (!name) return fail('Enter a display name.');
  if (!/^[a-z0-9_]{3,20}$/.test(uname)) return fail('Username uses 3–20 letters, numbers or underscores.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail('Enter a valid email address.');
  if (!/^[A-Z0-9-]{3,20}$/.test(aid) || !/^[A-Z0-9-]{3,20}$/.test(cid)) return fail('Admin ID and Company ID use 3–20 letters, numbers or dashes.');
  if (pw.length < 8) return fail('Password needs at least 8 characters.');

  try {
    await api('/api/admin/create-admin', 'POST', { name, username: uname, email, adminId: aid, companyId: cid, password: pw });
    closeOverlay('addadmin-overlay');
    toast(`Created ${cid === 'WHISPER-HQ' ? 'Whisper Super Admin' : cid + ' Admin'} @${uname}`);
    await syncAdminData();
    renderAdmin();
  } catch (ex) {
    fail(ex.message);
  }
});

$('#ad-admin-list').addEventListener('click', async e => {
  const b = e.target.closest('[data-del-admin]');
  if (!b) return;
  const u = b.dataset.delAdmin;
  if (!confirm(`Remove admin @${u}?`)) return;
  try {
    await api(`/api/admin/admins/${u}`, 'DELETE');
    toast(`Removed admin @${u}`);
    await syncAdminData();
    renderAdmin();
  } catch (ex) {
    toast(ex.message);
  }
});

$('#ad-pw-form').addEventListener('submit', async e => {
  e.preventDefault();
  const err = $('#ad-pw-error');
  const cur = $('#ad-cur').value, n1 = $('#ad-new').value, n2 = $('#ad-new2').value;
  if (n1.length < 8) { err.textContent = 'New password needs at least 8 characters.'; return; }
  if (n1 !== n2) { err.textContent = 'The two new passwords don\'t match.'; return; }
  try {
    await api('/api/admin/password', 'PATCH', { currentPassword: cur, newPassword: n1 });
    e.target.reset(); err.textContent = '';
    toast('Password updated');
    await syncAdminData();
  } catch (ex) {
    err.textContent = ex.message;
  }
});

function renderAdPolicy() {
  const p = getPolicy();
  $('#pol-signup').checked = p.allowSignup; $('#pol-uploads').checked = p.allowUploads;
  $('#pol-once').checked = p.allowViewOnce; $('#pol-max').value = String(p.maxMB);
}

async function setPolicy(k, v, label) {
  const by = admins[adminSession]?.name || 'Admin';
  await api('/api/admin/policy', 'PATCH', { key: k, value: v, by, label });
  store.set('whisper.policy', { ...getPolicy(), [k]: v });
  toast('Policy saved');
}
$('#pol-signup').addEventListener('change', e => setPolicy('allowSignup', e.target.checked, `${e.target.checked ? 'turned on' : 'turned off'} employee sign-ups`));
$('#pol-uploads').addEventListener('change', e => setPolicy('allowUploads', e.target.checked, `${e.target.checked ? 'allowed' : 'blocked'} file and image sharing`));
$('#pol-once').addEventListener('change', e => setPolicy('allowViewOnce', e.target.checked, `${e.target.checked ? 'allowed' : 'blocked'} view-once photos`));
$('#pol-max').addEventListener('change', e => setPolicy('maxMB', parseInt(e.target.value, 10), `set the maximum upload size to ${e.target.value} MB`));
$('#admin-logout').addEventListener('click', () => { adminSession = null; setAuthToken(''); showAuth('admin'); });

/* --- forgot password --- */
function setForgotStep(n) {
  $$('.fstep').forEach(s => s.hidden = Number(s.dataset.step) !== n);
  $$('#forgot-steps i').forEach((d, i) => d.classList.toggle('on', i < n));
  $('.back-row').hidden = n === 3;
  if (n === 1) { state.reset = null; $('#forgot-form-2').reset(); }
}
function sendResetCode(acc) {
  state.reset = { username: acc.username, code: String(Math.floor(100000 + Math.random() * 900000)), at: Date.now() };
  $('#demo-code-val').textContent = state.reset.code;
  const [u, d] = acc.email.split('@');
  $('#forgot-sub-2').textContent = `We sent a 6-digit code to ${u.slice(0, 2)}${'•'.repeat(Math.max(2, u.length - 2))}@${d}.`;
}
$('#forgot-form-1').addEventListener('submit', e => {
  e.preventDefault();
  const id = $('#forgot-id').value.trim(), err = $('#forgot-error-1');
  if (!id) { err.textContent = 'Enter your username or email.'; return; }
  const acc = findAccount(id);
  if (!acc) { err.textContent = 'No account matches that username or email.'; return; }
  err.textContent = '';
  sendResetCode(acc);
  setForgotStep(2);
  $('#forgot-code').focus();
});
$('#resend-code').addEventListener('click', e => {
  e.preventDefault();
  if (!state.reset) return;
  sendResetCode(accounts[state.reset.username]);
  toast('A new code is on its way');
});
$('#forgot-form-2').addEventListener('submit', e => {
  e.preventDefault();
  const err = $('#forgot-error-2'), pw = $('#forgot-pw').value, pw2 = $('#forgot-pw2').value;
  const fail = m => { err.textContent = m; };
  if (!state.reset) return fail('Start again from the first step.');
  if ($('#forgot-code').value.trim() !== state.reset.code) return fail('That code isn\'t right. Check it and try again.');
  if (Date.now() - state.reset.at > 10 * 60 * 1000) return fail('That code has expired. Send a new one.');
  if (pw.length < 8) return fail('Password needs at least 8 characters.');
  if (pw !== pw2) return fail('The two passwords don\'t match.');
  accounts[state.reset.username].pw = hash(pw);
  saveAccounts();
  $('#username-input').value = state.reset.username;
  $('#password-input').value = '';
  state.reset = null;
  setForgotStep(3);
});

/* ---------- rendering ---------- */
function renderList() {
  const q = $('#search-input').value.trim().toLowerCase();
  const rows = Object.values(state.chats).filter(c => c.name.toLowerCase().includes(q));
  $('#chat-list').innerHTML = rows.map(c => {
    const last = c.messages[c.messages.length - 1];
    const prev = last ? (last.from === 'me' ? 'You: ' : '') + (last.text || (last.attach ? (last.attach.kind === 'image' ? '📷 Photo' : '📎 ' + last.attach.name) : '')) : c.sub;
    return `<button class="chat-row ${c.id === state.activeId ? 'active' : ''}" data-id="${c.id}">
      <span class="av-wrap">${avatar(c.name, '')}<i class="dot ${c.status}"></i></span>
      <span class="row-text"><b>${esc(c.name)}${c.muted ? ' 🔕' : ''}</b><small>${esc(prev)}</small></span>
      <span class="row-timer">${c.retention ? fmtLife(c.retention) : '∞'}</span>
    </button>`;
  }).join('') || `<p class="no-results">${Object.keys(state.chats).length ? 'No conversations found' : 'No contacts yet. Tap the + above to add one.'}</p>`;
}

function renderHeader() {
  const c = activeChat();
  $('#chat-none').hidden = !!c;
  $('#chat-view').hidden = !c;
  if (!c) return;
  $('#head-avatar').innerHTML = avatar(c.name, '') + `<i class="dot ${c.status}"></i>`;
  $('#head-name').textContent = c.name;
  $('#head-status').textContent = c.typing ? 'typing…' : c.sub;
  $('#head-status').classList.toggle('typing', c.typing);
  $('#timer-badge').textContent = fmtLife(c.retention);
  $('#msg-input').placeholder = c.retention
    ? `Message ${c.name} · vanishes in ${fmtLife(c.retention)}`
    : `Message ${c.name}`;
  $('#notice').innerHTML = c.retention
    ? `<b>Disappearing on for ${esc(c.name)}.</b> New messages vanish <b>${fmtLong(c.retention)}</b> after they're sent.`
    : `<b>Timer off for ${esc(c.name)}.</b> Messages in this chat are kept permanently.`;
  $('#notice').classList.toggle('off', !c.retention);
}

function renderMe() {
  const m = state.me;
  $('#me-avatar').innerHTML = avatar(m.name, m.avatarUrl);
  $('#me-name').textContent = m.name;
  $('#me-handle').textContent = '@' + m.username;
}

const fmtSize = b => b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB';
function attHTML(a) {
  if (a.kind === 'image') {
    return a.once
      ? `<button type="button" class="att-once"><span class="eye">👁</span><span><b>Photo · view once</b><small>Tap to open. It disappears after.</small></span></button>`
      : `<img class="att-img" src="${esc(a.url)}" alt="${esc(a.name)}">`;
  }
  const ext = (a.name.includes('.') ? a.name.split('.').pop() : 'file').slice(0, 4).toUpperCase();
  return `<a class="att-file" href="${esc(a.url)}" download="${esc(a.name)}"><span class="ficon">${esc(ext)}</span><span class="fmeta"><b>${esc(a.name)}</b><small>${fmtSize(a.size)} · tap to save</small></span></a>`;
}
const freeMsg = m => { if (m.attach?.url?.startsWith('blob:')) URL.revokeObjectURL(m.attach.url); };

function msgHTML(m, c) {
  const mine = m.from === 'me';
  const ttl = m.expiresAt
    ? `<span class="ttl"><svg class="ring" viewBox="0 0 20 20"><circle class="trk" cx="10" cy="10" r="8"/><circle class="prg" cx="10" cy="10" r="8"/></svg><b>${fmtLife(Math.max(0, Math.ceil((m.expiresAt - Date.now()) / 1000)))}</b></span>`
    : '<span class="ttl perm">kept</span>';
  return `<div class="msg ${mine ? 'mine' : 'theirs'}" id="m-${m.id}">
    ${mine ? '' : avatar(c.name, '', 'sm')}
    <div class="bubble">
      ${m.attach ? attHTML(m.attach) : ''}
      ${m.text ? `<p>${esc(m.text)}</p>` : ''}
      <div class="meta"><span>${m.time}</span>${ttl}</div>
      ${m.expiresAt ? '<div class="bar"><i></i></div>' : ''}
    </div>
  </div>`;
}

function updateMsgEl(el, m) {
  const rem = Math.max(0, m.expiresAt - Date.now());
  const frac = rem / (m.life * 1000);
  const b = $('.ttl b', el), prg = $('.prg', el), bar = $('.bar i', el);
  if (b) b.textContent = fmtLife(Math.ceil(rem / 1000));
  if (prg) prg.style.strokeDashoffset = RING * (1 - frac);
  if (bar) bar.style.width = frac * 100 + '%';
}

function renderFeed() {
  const c = activeChat();
  const feed = $('#feed');
  if (!c) { feed.innerHTML = ''; return; }
  feed.innerHTML = `<div class="empty"><div class="empty-ic">✨</div><b>Nothing here (anymore)</b><p>Messages with ${esc(c.name)} vanish ${c.retention ? 'after ' + fmtLong(c.retention) : 'never – the timer is off'}. Say something!</p></div>`
    + c.messages.map(m => msgHTML(m, c)).join('');
  c.messages.forEach(m => { if (m.expiresAt) updateMsgEl($('#m-' + m.id), m); });
  feed.scrollTop = feed.scrollHeight;
}

function renderContacts() {
  const q = $('#contact-search').value.trim().toLowerCase();
  const all = Object.values(state.chats);
  const list = all.filter(c => c.name.toLowerCase().includes(q));
  $('#contact-count').textContent = `${all.length} ${all.length === 1 ? 'person' : 'people'}`;
  const cards = list.map(c => `<article class="c-card" style="--h:${hueOf(c.name)}">
    <div class="c-top"><span class="av-wrap">${avatar(c.name, '')}<i class="dot ${c.status}"></i></span>
      <div class="c-id"><b>${esc(c.name)}</b><small>${esc(c.sub)}</small></div></div>
    <p class="c-note">${esc(c.note || 'No note yet.')}</p>
    <button class="life-chip" data-act="life" data-id="${c.id}" title="Change lifespan"><svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2M9 2h6"/></svg>${c.retention ? 'Vanishes after ' + fmtLife(c.retention) : 'Timer off'}</button>
    <div class="c-actions">
      <button class="btn primary sm" data-act="msg" data-id="${c.id}">Message</button>
      <button class="btn ghost sm" data-act="info" data-id="${c.id}">Info</button>
    </div></article>`).join('');
  const addTile = q ? '' : `<button class="c-card c-add" data-open="contact-overlay"><span class="plus">+</span><b>Add contact</b><small>Give each person their own lifespan</small></button>`;
  $('#contact-grid').innerHTML = cards + addTile || '<p class="no-results">No contacts match your search.</p>';
  if (q && !list.length) $('#contact-grid').innerHTML = '<p class="no-results">No contacts match your search.</p>';
}

function renderInsights() {
  const chats = Object.values(state.chats);
  const sum = k => chats.reduce((n, c) => n + c.stat[k], 0);
  const live = chats.reduce((n, c) => n + c.messages.length, 0);
  $('#insight-sub').textContent = live
    ? `${live} ${live === 1 ? 'message is' : 'messages are'} visible right now.`
    : 'Nothing is stored right now. That\'s the point.';
  const tile = (n, label, cls) => `<div class="tile ${cls}"><b>${n}</b><span>${label}</span></div>`;
  $('#tiles').innerHTML = tile(sum('sent'), 'Sent', 't1') + tile(sum('recv'), 'Received', 't2') + tile(sum('gone'), 'Vanished', 't3') + tile(live, 'Still visible', 't4');

  const sorted = [...chats].sort((a, b) => (a.retention || 1e9) - (b.retention || 1e9));
  const maxLog = Math.log(Math.max(...chats.map(c => c.retention || 0), 60) + 1);
  $('#life-chart').innerHTML = sorted.map(c => {
    const w = c.retention ? Math.max(6, Math.log(c.retention + 1) / maxLog * 100) : 100;
    return `<div class="crow" style="--h:${hueOf(c.name)}"><span class="cname">${esc(c.name)}</span>
      <span class="ctrack"><i class="${c.retention ? '' : 'perm'}" style="width:${w}%"></i></span><span class="cval">${c.retention ? fmtLife(c.retention) : '∞'}</span></div>`;
  }).join('') || '<p class="no-results">Add a contact to see lifespans.</p>';

  const maxAct = Math.max(1, ...chats.map(c => c.stat.sent + c.stat.recv));
  $('#act-chart').innerHTML = chats.map(c => `<div class="crow" style="--h:${hueOf(c.name)}"><span class="cname">${esc(c.name)}</span>
      <span class="ctrack stack"><i class="s" style="width:${c.stat.sent / maxAct * 100}%"></i><i class="r" style="width:${c.stat.recv / maxAct * 100}%"></i></span>
      <span class="cval">${c.stat.sent + c.stat.recv}</span></div>`).join('') || '<p class="no-results">No activity yet.</p>';

  $('#vanish-log').innerHTML = state.log.length
    ? state.log.map(l => `<li><span class="vdot"></span><span><b>${esc(l.name)}</b> · ${l.once ? 'a view-once photo was opened and vanished' : 'a message vanished after ' + fmtLife(l.life)}</span><small>${l.time}</small></li>`).join('')
    : '<li class="vempty">Send a message and watch it appear here when it vanishes.</li>';
}

function renderSettings() {
  const s = state.settings;
  $$('[data-theme-opt]').forEach(b => { const on = b.dataset.themeOpt === s.theme; b.classList.toggle('on', on); b.setAttribute('aria-checked', on); });
  $$('[data-accent]').forEach(b => b.classList.toggle('on', b.dataset.accent === s.accent));
  $('#set-default-life').value = String(s.defaultLife);
  $('#set-blur').checked = s.blur; $('#set-typing').checked = s.typing;
  $('#set-reply').checked = s.autoReply; $('#set-sound').checked = s.sound;
}

function renderAll() { renderMe(); renderList(); renderHeader(); renderFeed(); renderContacts(); }

/* ---------- messaging ---------- */
function makeChat(c) {
  return { ...c, messages: [], typing: false, stat: { sent: 0, recv: 0, gone: 0 } };
}

function addMessage(chatId, from, text, opts = {}) {
  const c = state.chats[chatId];
  if (!c) return;
  const m = {
    id: ++state.seq, from, text, time: nowTime(),
    life: opts.life ?? c.retention,
    attach: opts.attach || null
  };
  m.expiresAt = m.life ? Date.now() + m.life * 1000 : null;
  c.messages.push(m);
  if (from === 'me') {
  e2ee.encrypt(text, state.user, chatId).then(encryptedText => {
    socket.emit('send_message', {
      sender: state.user,
      recipient: chatId,
      text: encryptedText,
      life: m.life,
      attach: m.attach
    });
  });
}
  c.stat[from === 'me' ? 'sent' : 'recv']++;
  if (chatId === state.activeId && state.tab === 'chats') {
    const feed = $('#feed');
    feed.insertAdjacentHTML('beforeend', msgHTML(m, c));
    if (m.expiresAt) updateMsgEl($('#m-' + m.id), m);
    feed.scrollTop = feed.scrollHeight;
  }
  if (from !== 'me' && state.settings.sound && !c.muted) beep();
  renderList();
  if (state.tab === 'insights') renderInsights();
}

function botReply(chatId, greeting) {
  if (chatId !== 'whisper-bot') return;
  const c = state.chats[chatId];
  if (!c || !state.settings.autoReply) return;
  const showTyping = state.settings.typing;
  if (showTyping) { c.typing = true; if (chatId === state.activeId) renderHeader(); }
  setTimeout(() => {
    c.typing = false;
    if (!state.loggedIn || !state.chats[chatId]) return;
    addMessage(chatId, chatId, greeting || REPLIES[Math.floor(Math.random() * REPLIES.length)]);
    if (chatId === state.activeId) renderHeader();
  }, 900 + Math.random() * 600);
}

$('#composer').addEventListener('submit', e => {
  e.preventDefault();
  const input = $('#msg-input');
  const text = input.value.trim();
  if (!text || !activeChat()) return;
  addMessage(state.activeId, 'me', text);
  input.value = '';
  botReply(state.activeId);
});

$('#emoji-btn').addEventListener('click', () => {
  const input = $('#msg-input');
  input.value += EMOJIS[Math.floor(Math.random() * EMOJIS.length)];
  input.focus();
});

/* Single ticker drives every countdown, ring, bar and the vanish animation */
function tick() {
  if (!state.loggedIn) return;
  const now = Date.now();
  let changed = false;
  for (const c of Object.values(state.chats)) {
    for (const m of c.messages.slice()) {
      if (!m.expiresAt) continue;
      const el = document.getElementById('m-' + m.id);
      if (m.expiresAt - now <= 0) {
        c.messages = c.messages.filter(x => x !== m);
        freeMsg(m);
        c.stat.gone++;
        state.log.unshift({ name: c.name, life: m.life, time: nowTime() });
        state.log.length = Math.min(state.log.length, 30);
        changed = true;
        if (el && c.id === state.activeId) {
          el.style.height = el.offsetHeight + 'px';
          void el.offsetHeight;
          el.classList.add('gone');
          setTimeout(() => el.remove(), 650);
        } else if (el) el.remove();
      } else if (el && c.id === state.activeId) {
        updateMsgEl(el, m);
      }
    }
  }
  if (changed) { renderList(); if (state.tab === 'insights') renderInsights(); }
}
setInterval(tick, 200);

/* ---------- navigation ---------- */
function switchTab(tab) {
  state.tab = tab;
  const app = $('#app');
  app.dataset.tab = tab;
  if (tab !== 'chats') app.classList.remove('chat-open');
  $$('.rail-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  ['contacts', 'insights', 'settings'].forEach(t => $('#pane-' + t).hidden = t !== tab);
  if (tab === 'contacts') renderContacts();
  if (tab === 'insights') renderInsights();
  if (tab === 'settings') renderSettings();
  if (tab === 'chats') { renderHeader(); renderFeed(); }
}
$$('.rail-btn').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));

function selectChat(id) {
  state.activeId = id;
  switchTab('chats');
  $('#app').classList.add('chat-open');
  renderList(); renderHeader(); renderFeed();
  socket.emit('join_chat', { me: state.user, peer: id });
  api(`/api/messages/${state.user}/${id}`).then(async msgs => {
    const c = state.chats[id];
    if (!c) return;
    c.messages = await Promise.all(msgs.map(async m => ({
      id: m._id,
      from: m.sender === state.user ? 'me' : m.sender,
      text: await e2ee.decrypt(m.text, state.user, id),
      time: new Date(m.createdAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }),
      life: m.life,
      attach: m.attach,
      expiresAt: m.expiresAt ? new Date(m.expiresAt).getTime() : null
    })));
    if (state.activeId === id) renderFeed();
  }).catch(() => {});
}
$('#chat-list').addEventListener('click', e => {
  const row = e.target.closest('.chat-row');
  if (row) selectChat(row.dataset.id);
});
$('#back-btn').addEventListener('click', () => $('#app').classList.remove('chat-open'));
$('#search-input').addEventListener('input', renderList);
$('#contact-search').addEventListener('input', renderContacts);
$$('[data-demo]').forEach(b => b.addEventListener('click', () => toast(b.dataset.demo)));

$('#contact-grid').addEventListener('click', e => {
  const b = e.target.closest('[data-act]');
  if (!b) return;
  const id = b.dataset.id;
  if (b.dataset.act === 'msg') selectChat(id);
  if (b.dataset.act === 'info') openInfo(id);
  if (b.dataset.act === 'life') openTimeline(id);
});

/* ---------- overlays ---------- */
const openOverlay  = id => $('#' + id).classList.add('open');
const closeOverlay = id => $('#' + id).classList.remove('open');
$$('[data-close]').forEach(b => b.addEventListener('click', () => closeOverlay(b.dataset.close)));
$$('[data-open]').forEach(b => b.addEventListener('click', () => b.dataset.open === 'contact-overlay' ? openAddContact() : openOverlay(b.dataset.open)));
// Contact cards are re-rendered, so delegate opens from anywhere in the document too
document.addEventListener('click', e => {
  const b = e.target.closest('.c-add');
  if (b) openAddContact();
});
$$('.overlay').forEach(o => o.addEventListener('mousedown', e => { if (e.target === o) o.classList.remove('open'); }));
document.addEventListener('keydown', e => { if (e.key === 'Escape') $$('.overlay.open').forEach(o => o.classList.remove('open')); });

/* ---------- lifespan chooser (per contact) ---------- */
const PRESETS = ['5', '10', '30', '60', '300', '0'];
function syncOptSelection() { $$('.opt').forEach(o => o.classList.toggle('sel', $('input', o).checked)); }

function openTimeline(id) {
  const c = state.chats[id || state.activeId];
  if (!c) return;
  state.lifeTarget = c.id;
  const v = String(c.retention);
  const isPreset = PRESETS.includes(v);
  $$('input[name=life]').forEach(r => r.checked = isPreset ? r.value === v : r.value === 'custom');
  $('#life-custom').value = isPreset ? 20 : c.retention;
  $('#life-all').checked = false;
  $('#tl-sub').textContent = `Set how long new messages with ${c.name} stay visible. Other contacts keep their own lifespan.`;
  syncOptSelection();
  openOverlay('timeline-overlay');
}
$('#btn-open-timeline').addEventListener('click', () => openTimeline());
$$('input[name=life]').forEach(r => r.addEventListener('change', syncOptSelection));
$('#life-custom').addEventListener('focus', () => { $('input[name=life][value=custom]').checked = true; syncOptSelection(); });

$('#save-timeline').addEventListener('click', () => {
  const c = state.chats[state.lifeTarget];
  if (!c) return;
  const pick = $('input[name=life]:checked').value;
  let v;
  if (pick === 'custom') {
    v = Math.round(Number($('#life-custom').value));
    if (!(v >= 1 && v <= 86400)) { toast('Enter a custom lifespan between 1 and 86,400 seconds'); return; }
  } else v = parseInt(pick, 10);
  const all = $('#life-all').checked;
  if (all) Object.values(state.chats).forEach(x => x.retention = v);
  else c.retention = v;
  persist();
  renderList(); renderHeader(); renderContacts();
  if (state.tab === 'insights') renderInsights();
  refreshInfoLife();
  closeOverlay('timeline-overlay');
  toast(all ? `All chats now ${v ? 'vanish after ' + fmtLife(v) : 'keep messages'}`
            : v ? `${c.name}'s messages will vanish after ${fmtLife(v)}` : `Timer turned off for ${c.name}`);
});

/* ---------- add contact ---------- */
function updateAcPreview() {
  const n = $('#ac-name').value.trim() || 'New contact';
  $('#ac-preview').innerHTML = `<span class="av-wrap">${avatar(n, '')}</span><span class="row-text"><b>${esc(n)}</b><small>${esc($('#ac-sub').value.trim() || 'New contact')}</small></span>`;
}
function openAddContact() {
  $('#contact-form').reset();
  $('#ac-life').value = String(state.settings.defaultLife);
  $('#ac-error').textContent = '';
  updateAcPreview();
  openOverlay('contact-overlay');
  if (window.innerWidth > 820) setTimeout(() => $('#ac-name').focus(), 50);
}
['ac-name', 'ac-sub'].forEach(id => $('#' + id).addEventListener('input', updateAcPreview));

$('#contact-form').addEventListener('submit', e => {
  e.preventDefault();
  const name = $('#ac-name').value.trim(), err = $('#ac-error');
  if (!name) { err.textContent = 'Enter a name for your contact.'; return; }
  if (Object.values(state.chats).some(c => c.name.toLowerCase() === name.toLowerCase())) { err.textContent = `You already have a contact named ${name}.`; return; }
  let id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'contact';
  while (state.chats[id]) id += '-' + Math.floor(Math.random() * 90 + 10);
  state.chats[id] = makeChat({ id, name, status: 'online', sub: $('#ac-sub').value.trim() || 'New contact', retention: parseInt($('#ac-life').value, 10), note: '', muted: false });
  persist();
  closeOverlay('contact-overlay');
  selectChat(id);
  toast(`${name} added`);
  botReply(id, `Hi ${state.me.name}! Thanks for adding me 👋`);
});

/* ---------- contact info drawer ---------- */
function openInfo(id) {
  const c = state.chats[id || state.activeId];
  if (!c) return;
  state.infoId = c.id;
  $('#ci-banner').style.background = `linear-gradient(120deg, hsl(${hueOf(c.name)} 65% 55%), hsl(${(hueOf(c.name) + 40) % 360} 65% 42%))`;
  $('#ci-avatar').innerHTML = avatar(c.name, '');
  $('#ci-name').textContent = c.name;
  $('#ci-status').textContent = c.status === 'online' ? 'Online now' : c.status === 'idle' ? 'Idle' : 'Offline';
  $('#ci-edit-name').value = c.name;
  $('#ci-edit-note').value = c.note || '';
  $('#ci-mute').checked = !!c.muted;
  refreshInfoLife();
  openOverlay('info-overlay');
}
function refreshInfoLife() {
  const c = state.chats[state.infoId];
  if (c) $('#ci-life-btn').innerHTML = `<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2M9 2h6"/></svg>${c.retention ? 'Vanishes after ' + fmtLife(c.retention) : 'Timer off'} · change`;
}
$('#open-info').addEventListener('click', () => openInfo());
$('#ci-life-btn').addEventListener('click', () => openTimeline(state.infoId));
$('#ci-save').addEventListener('click', () => {
  const c = state.chats[state.infoId];
  if (!c) return;
  const name = $('#ci-edit-name').value.trim();
  if (name && name.toLowerCase() !== c.name.toLowerCase() && Object.values(state.chats).some(x => x !== c && x.name.toLowerCase() === name.toLowerCase())) { toast(`You already have a contact named ${name}`); return; }
  if (name) c.name = name;
  c.note = $('#ci-edit-note').value.trim();
  c.muted = $('#ci-mute').checked;
  persist(); renderAll();
  closeOverlay('info-overlay');
  toast('Contact updated');
});
$('#ci-clear').addEventListener('click', () => {
  const c = state.chats[state.infoId];
  if (!c || !c.messages.length) { toast('This chat is already empty'); return; }
  c.stat.gone += c.messages.length;
  api(`/api/messages/room/${state.user}/${c.id}`, 'DELETE').catch(() => {});
  c.messages.forEach(freeMsg);
  c.messages = [];
  renderList(); renderFeed();
  closeOverlay('info-overlay');
  toast(`Chat with ${c.name} cleared`);
});
$('#ci-remove').addEventListener('click', () => {
  const c = state.chats[state.infoId];
  if (!c || !confirm(`Remove ${c.name}? Their chat will be erased.`)) return;
  c.messages.forEach(freeMsg);
  delete state.chats[c.id];
  if (state.activeId === c.id) { state.activeId = Object.keys(state.chats)[0] || null; $('#app').classList.remove('chat-open'); }
  persist(); renderAll();
  if (state.tab === 'insights') renderInsights();
  closeOverlay('info-overlay');
  toast(`${c.name} removed`);
});

/* ---------- profile drawer ---------- */
function renderPreview() {
  const name = $('#edit-name').value.trim() || state.me.name;
  $('#pv-name').textContent = name;
  $('#pv-handle').textContent = '@' + state.me.username;
  $('#pv-bio').textContent = $('#edit-bio').value.trim() || 'No bio yet.';
  $('#pv-banner').style.background = `linear-gradient(120deg, ${$('#edit-banner').value}, ${$('#edit-banner').value}99)`;
  $('#pv-avatar').innerHTML = avatar(name, $('#edit-avatar').value.trim());
}
['edit-name', 'edit-bio', 'edit-avatar', 'edit-banner'].forEach(id => $('#' + id).addEventListener('input', renderPreview));

function openProfile() {
  $('#edit-name').value = state.me.name;
  $('#edit-bio').value = state.me.bio;
  $('#edit-avatar').value = state.me.avatarUrl;
  $('#edit-banner').value = state.me.banner;
  renderPreview();
  openOverlay('profile-overlay');
}
$('#open-profile-btn').addEventListener('click', openProfile);

$('#save-profile').addEventListener('click', () => {
  const name = $('#edit-name').value.trim();
  if (name) { state.me.name = name; accounts[state.user].name = name; saveAccounts(); }
  state.me.bio = $('#edit-bio').value.trim();
  state.me.avatarUrl = $('#edit-avatar').value.trim();
  state.me.banner = $('#edit-banner').value;
  persist(); renderMe();
  closeOverlay('profile-overlay');
  toast('Profile updated');
});

/* ---------- attachments: files, images, timers, view-once ---------- */
const UP_TIMERS = [['def', 'Chat default'], [15, '15 sec'], [20, '20 sec'], [30, '30 sec'], [60, '1 min'], [120, '2 min'], [300, '5 min'], ['custom', 'Custom']];
let pending = null; // { file, kind, url }
let upTimer = 'def';

const attachMenu = $('#attach-menu');
$('#attach-btn').addEventListener('click', e => {
  e.stopPropagation();
  if (!getPolicy().allowUploads) { toast('File and image sharing is turned off by your company admin'); return; }
  attachMenu.classList.toggle('open');
});
function applyPolicyUi() {
  const p = getPolicy();
  $('#attach-btn').classList.toggle('off', !p.allowUploads);
  $('#attach-btn').title = p.allowUploads ? 'Attach a file or image' : 'File sharing is turned off by your admin';
  $('#pick-file small').textContent = `PDF, docs, zip… up to ${p.maxMB} MB`;
  $('#pick-image small').textContent = p.allowViewOnce ? `Up to ${p.maxMB} MB · can be view-once` : `Up to ${p.maxMB} MB`;
}
document.addEventListener('click', () => attachMenu.classList.remove('open'));
$('#pick-image').addEventListener('click', () => $('#image-input').click());
$('#pick-file').addEventListener('click', () => $('#file-input').click());
['image-input', 'file-input'].forEach(id => $('#' + id).addEventListener('change', e => {
  const f = e.target.files[0];
  e.target.value = '';
  if (f) startUpload(f);
}));

function renderUpTimers() {
  const c = activeChat();
  $('#up-timers').innerHTML = UP_TIMERS.map(([v, label]) => {
    const text = v === 'def' ? `${label} (${c.retention ? fmtLife(c.retention) : 'permanent'})` : label;
    return `<button type="button" class="chip ${String(v) === String(upTimer) ? 'on' : ''}" data-t="${v}" role="radio" aria-checked="${String(v) === String(upTimer)}">${text}</button>`;
  }).join('');
  $('#up-custom-row').hidden = upTimer !== 'custom';
}
$('#up-timers').addEventListener('click', e => {
  const b = e.target.closest('[data-t]');
  if (!b) return;
  upTimer = b.dataset.t;
  renderUpTimers();
  if (upTimer === 'custom') $('#up-custom').focus();
});

function startUpload(file) {
  if (!activeChat()) { toast('Open a chat first'); return; }
  const pol = getPolicy();
  if (!pol.allowUploads) { toast('File and image sharing is turned off by your company admin'); return; }
  if (file.size > pol.maxMB * 1024 * 1024) { toast(`That file is ${fmtSize(file.size)}. The limit is ${pol.maxMB} MB.`); return; }
  if (pending) URL.revokeObjectURL(pending.url);
  const kind = file.type.startsWith('image/') ? 'image' : 'file';
  pending = { file, kind, url: URL.createObjectURL(file) };
  upTimer = 'def';
  $('#up-caption').value = '';
  $('#up-once').checked = false;
  $('#up-once-row').hidden = kind !== 'image' || !pol.allowViewOnce;
  $('#up-title').textContent = kind === 'image' ? 'Send photo' : 'Send file';
  $('#up-sub').textContent = `To ${activeChat().name}. Choose how long it stays visible.`;
  const ext = (file.name.includes('.') ? file.name.split('.').pop() : 'file').slice(0, 4).toUpperCase();
  $('#up-preview').innerHTML = kind === 'image'
    ? `<img src="${esc(pending.url)}" alt=""><span class="up-meta"><b>${esc(file.name)}</b><small>${fmtSize(file.size)}</small></span>`
    : `<span class="ficon lg">${esc(ext)}</span><span class="up-meta"><b>${esc(file.name)}</b><small>${fmtSize(file.size)}</small></span>`;
  renderUpTimers();
  openOverlay('upload-overlay');
}

$('#up-send').addEventListener('click', async () => {
  const c = activeChat();
  if (!pending || !c) return;
  let life;
  if (upTimer === 'def') life = c.retention;
  else if (upTimer === 'custom') {
    life = Math.round(Number($('#up-custom').value));
    if (!(life >= 1 && life <= 86400)) { toast('Enter a custom timer between 1 and 86,400 seconds'); return; }
  } else life = Number(upTimer);

  const { file, kind, url } = pending;
  const once = kind === 'image' && $('#up-once').checked;
  const caption = $('#up-caption').value.trim();
  const btn = $('#up-send');
  btn.disabled = true;
  btn.textContent = 'Sending…';

  try {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch('/api/upload', {
      method: 'POST',
      headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
      body: fd
    });
    const uploaded = await res.json();
    if (!res.ok) throw new Error(uploaded.error || 'Upload failed');

    URL.revokeObjectURL(url);
    pending = null;
    closeOverlay('upload-overlay');
    addMessage(c.id, 'me', caption, {
      life,
      attach: { kind: uploaded.kind, url: uploaded.url, name: uploaded.name, size: uploaded.size, once }
    });
    toast(`${kind === 'image' ? 'Photo' : 'File'} sent · ${life ? 'vanishes after ' + fmtLife(life) : 'kept permanently'}${once ? ' · view once' : ''}`);
  } catch (ex) {
    toast(ex.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send';
  }
});

/* image viewer; view-once photos are destroyed when closed */
let viewing = null;
function findMsgEl(el) {
  const row = el.closest('.msg');
  const id = row && row.id.slice(2);
  return { row, m: activeChat()?.messages.find(x => String(x.id) === String(id)) };
}
$('#feed').addEventListener('click', e => {
  const img = e.target.closest('.att-img'), once = e.target.closest('.att-once');
  if (!img && !once) return;
  const { m } = findMsgEl(e.target);
  if (!m) return;
  viewing = { chatId: state.activeId, id: m.id, once: !!once };
  $('#viewer-img').src = m.attach.url;
  $('#viewer-note').textContent = once ? 'View once. This photo disappears when you close it.' : m.attach.name;
  $('#viewer').hidden = false;
});
function closeViewer() {
  if (!viewing) return;
  const { chatId, id, once } = viewing;
  viewing = null;
  $('#viewer').hidden = true;
  $('#viewer-img').removeAttribute('src');
  if (!once) return;

  // Notify backend to delete the file & purge message across all clients
  if (typeof id === 'string') {
    api(`/api/messages/${id}/view-once`, 'DELETE').catch(() => {});
  }

  const c = state.chats[chatId];
  const m = c?.messages.find(x => String(x.id) === String(id));
  if (!m) return;
  c.messages = c.messages.filter(x => x !== m);
  freeMsg(m);
  c.stat.gone++;
  state.log.unshift({ name: c.name, life: 0, time: nowTime(), once: true });
  const el = document.getElementById('m-' + id);
  if (el) { el.style.height = el.offsetHeight + 'px'; void el.offsetHeight; el.classList.add('gone'); setTimeout(() => el.remove(), 650); }
  renderList();
  toast('Photo opened once and gone');
}
$('#viewer-close').addEventListener('click', closeViewer);
$('#viewer').addEventListener('click', e => { if (e.target.id === 'viewer') closeViewer(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeViewer(); });

/* ---------- settings page ---------- */
function setSetting(k, v) { state.settings[k] = v; persist(); applyTheme(); renderSettings(); }
$('#theme-seg').addEventListener('click', e => { const b = e.target.closest('[data-theme-opt]'); if (b) setSetting('theme', b.dataset.themeOpt); });
$('#accent-swatches').addEventListener('click', e => { const b = e.target.closest('[data-accent]'); if (b) setSetting('accent', b.dataset.accent); });
$('#set-default-life').addEventListener('change', e => { setSetting('defaultLife', parseInt(e.target.value, 10)); toast('New contacts will start with this lifespan'); });
$('#set-blur').addEventListener('change', e => setSetting('blur', e.target.checked));
$('#set-typing').addEventListener('change', e => setSetting('typing', e.target.checked));
$('#set-reply').addEventListener('change', e => setSetting('autoReply', e.target.checked));
$('#set-sound').addEventListener('change', e => { setSetting('sound', e.target.checked); if (e.target.checked) beep(); });
matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', () => { if (state.settings.theme === 'system') applyTheme(); });

$('#vanish-all').addEventListener('click', async () => {
  const n = Object.values(state.chats).reduce((t, c) => t + c.messages.length, 0);
  if (!n) { toast('Nothing to vanish. All your chats are already empty'); return; }
  if (!confirm(`Erase ${n} visible ${n === 1 ? 'message' : 'messages'} in every chat for both you and your recipients?`)) return;
  await api(`/api/messages/user/${state.user}`, 'DELETE').catch(() => {});
  Object.values(state.chats).forEach(c => { c.stat.gone += c.messages.length; c.messages.forEach(freeMsg); c.messages = []; });
  renderList(); renderFeed();
  toast('Poof. Every chat is empty across all devices');
});
$('#delete-account').addEventListener('click', () => {
  if (!confirm('Delete your account and contacts from this browser? This can\'t be undone.')) return;
  const u = state.user;
  delete accounts[u]; saveAccounts(); store.del('whisper.data.' + u);
  state.user = null; // so logout() doesn't re-save the deleted profile
  logout(true);
  $('#username-input').value = ''; 
  toast('Account deleted');
});

/* ---------- login / logout ---------- */
function seedMessages() {
  const t = (id, text) => { if (state.chats[id]) addMessage(id, id, text); };
  t('bhumi', `Hey ${state.me.name}, check out this self-destruct mechanism!`);
  t('bhumi', 'Tap the stopwatch at the top to change the message lifespan.');
  t('vikram', 'This chat keeps messages for 30 seconds, longer than Bhumi\'s.');
  t('arjun', 'Gaming later? This message won\'t last long 😄');
  t('whisper-bot', `Welcome, ${state.me.name}! Every contact has its own lifespan.`);
  t('whisper-bot', 'Tap the stopwatch above to set this chat\'s timer. Add more people from the + button.');
  Object.values(state.chats).forEach(c => c.stat = { sent: 0, recv: 0, gone: 0 });
}

function enterApp(username) {
  const acc = accounts[username];
  const data = store.get('whisper.data.' + username, null);
  state.user = username;
  state.loggedIn = true;
  socket.emit('register_user', username);
  state.seq = 0; state.log = [];
  state.me = {
    username, name: acc.name, email: acc.email,
    bio: data?.me?.bio ?? (username === 'rasmalai' ? 'Software engineer · keeping conversations light and ephemeral ✨' : 'New to Whisper ✨'),
    avatarUrl: data?.me?.avatarUrl ?? '',
    banner: data?.me?.banner ?? '#0f766e'
  };
  state.settings = { ...DEFAULT_SETTINGS, ...(data?.settings || {}) };
  const contacts = data?.contacts ?? (username === 'rasmalai' ? SEED_CONTACTS : [{ ...BOT_CONTACT, retention: state.settings.defaultLife }]);
  state.chats = {};
  contacts.forEach(c => { state.chats[c.id] = makeChat(c); });
  state.activeId = contacts[0]?.id || null;
  document.body.classList.remove('auth-mode');
  applyTheme();
  api('/api/policy').then(pol => {
  if (pol) { store.set('whisper.policy', pol); applyPolicyUi(); }
  }).catch(() => {});
  applyPolicyUi();

  $$('.auth').forEach(v => v.classList.remove('active'));
  $('#app').hidden = false;
  $('#app').classList.remove('chat-open');
  //seedMessages();
  switchTab('chats');
  renderAll();
  persist();
}

function logout(skipConfirm) {
  if (skipConfirm !== true && !confirm('Are you sure you want to log out?')) return;
  persist();
  state.loggedIn = false; state.user = null;
  $$('.overlay.open').forEach(o => o.classList.remove('open'));
  $('#app').hidden = true;
  $('#password-input').value = '';
  showAuth('login');
}
$('#logout-btn').addEventListener('click', () => logout());
$('#logout-btn-2').addEventListener('click', () => logout());

showAuth('login');
