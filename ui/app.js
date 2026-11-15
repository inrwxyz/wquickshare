// Quick Share for Windows - UI controller (vanilla JS, Tauri v2)
'use strict';

/* ---------- Tauri bridge ---------- */
const invoke = (cmd, args = {}) => {
  const t = window.__TAURI__;
  if (t && t.core && typeof t.core.invoke === 'function') return t.core.invoke(cmd, args);
  return Promise.reject(new Error('Tauri API not available'));
};

function listen(name, fn) {
  const go = () => {
    const t = window.__TAURI__;
    if (t && t.event && typeof t.event.listen === 'function') {
      const r = t.event.listen(name, fn);
      if (r && r.catch) r.catch(e => console.warn('listen failed', name, e));
    } else setTimeout(go, 80);
  };
  go();
}

/* ---------- Helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const icon = n => `<svg class="ic"><use href="#i-${n}"/></svg>`;
const errText = e => (typeof e === 'string' ? e : (e && e.message) || 'Something went wrong');

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(n >= 100 ? 0 : 1)} ${u[i]}`;
}
function fmtEta(s) {
  if (!isFinite(s) || s <= 0) return '';
  s = Math.round(s);
  if (s < 60) return `${s} s left`;
  const m = Math.floor(s / 60);
  return `${m} min ${s % 60} s left`;
}
const baseName = p => String(p).split(/[\\/]/).filter(Boolean).pop() || String(p);
const extOf = n => { const m = /\.([a-z0-9]+)$/i.exec(n || ''); return m ? m[1].toLowerCase() : ''; };
function kindOf(name) {
  const e = extOf(name);
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'heic', 'heif', 'svg'].includes(e)) return 'Image';
  if (['mp4', 'mkv', 'mov', 'avi', 'webm', '3gp'].includes(e)) return 'Video';
  if (['mp3', 'wav', 'flac', 'aac', 'm4a', 'ogg', 'opus'].includes(e)) return 'Audio';
  if (['pdf', 'doc', 'docx', 'txt', 'xls', 'xlsx', 'ppt', 'pptx', 'csv'].includes(e)) return 'Document';
  return 'File';
}
const fileIcon = name => (kindOf(name) === 'Image' ? 'image' : 'file');
function devIcon(t) { return t === 1 ? 'phone' : t === 2 ? 'tablet' : t === 3 ? 'laptop' : 'phone'; }
function devLabel(t) { return t === 1 ? 'Phone' : t === 2 ? 'Tablet' : t === 3 ? 'Computer' : 'Device'; }

/* ---------- State ---------- */
const S = {
  status: null,
  files: [],
  devices: new Map(),
  vis: 'everyone',
  visTimer: null,
  collapsed: false,
  modal: null,            // 'offer' | 'rx' | 'received' | 'tx'
  offer: null,
  offerResponded: false,
  rx: { device: '', names: [] },
  tx: { name: '', pin: '', stage: 'connecting' },
  sendActive: false,
  prog: { pct: 0, mbps: 0, idx: 1, total: 1, name: '', start: 0, startPct: 0 },
  lastOffer: null,
};

/* ---------- Toast ---------- */
let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 3500);
}

/* ---------- Status ---------- */
async function refreshStatus() {
  try {
    const st = await invoke('get_status');
    S.status = st || {};
    $('#deviceName').textContent = st.device_name || 'Quick Share';
    $('#setName').textContent = st.device_name || '-';
    $('#setDir').textContent = st.downloads_dir || st.save_dir || '-';
    if (!S.visTimer) {
      S.vis = st.running === false ? 'none' : (S.vis === 'none' ? 'everyone' : S.vis);
      renderVis();
    }
  } catch (e) { console.warn('get_status failed', e); }
}

/* ---------- Visibility ---------- */
const VIS_LABEL = { none: 'No one', everyone: 'Everyone', temp: 'Everyone (10 min)' };
const VIS_SUB = {
  none: 'No one can share with you',
  everyone: 'Anyone nearby can share with you',
  temp: 'Anyone nearby can share with you for 10 minutes',
};
function renderVis() {
  $('#visLabel').textContent = VIS_LABEL[S.vis];
  $('#setVis').textContent = VIS_SUB[S.vis];
  $$('#visMenu .menu-item').forEach(b => {
    const on = b.dataset.vis === S.vis;
    b.classList.toggle('on', on);
    b.setAttribute('aria-checked', on);
  });
  $$('#setVisOptions .opt').forEach(b => b.classList.toggle('on', b.dataset.vis === S.vis));
  const ic = $('.pill-ic use');
  ic.setAttribute('href', S.vis === 'none' ? '#i-eye-off' : '#i-group');
}
async function setVisibility(mode) {
  clearTimeout(S.visTimer);
  S.visTimer = null;
  S.vis = mode;
  renderVis();
  try {
    if (mode === 'none') await invoke('stop_server');
    else await invoke('start_server');
  } catch (e) { toast(errText(e)); }
  if (mode === 'temp') S.visTimer = setTimeout(() => setVisibility('none'), 10 * 60 * 1000);
}
function toggleMenu(open) {
  const m = $('#visMenu');
  const show = open ?? m.hidden;
  m.hidden = !show;
  $('#visBtn').setAttribute('aria-expanded', show);
}
$('#visBtn').addEventListener('click', e => { e.stopPropagation(); toggleMenu(); });
$('#visMenu').addEventListener('click', e => {
  const b = e.target.closest('.menu-item');
  if (!b) return;
  toggleMenu(false);
  setVisibility(b.dataset.vis);
});
document.addEventListener('click', e => { if (!e.target.closest('.vis-wrap')) toggleMenu(false); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') toggleMenu(false); });

/* ---------- Home: idle / send ---------- */
function renderHome() {
  const has = S.files.length > 0;
  $('#idle').hidden = has;
  $('#send').hidden = !has;
  if (!has) return;

  const n = S.files.length;
  $('#filesSummary').textContent = `Sharing ${n} ${n === 1 ? 'file' : 'files'}`;
  const tiles = $('#fileTiles');
  tiles.hidden = S.collapsed;
  $('#btnCollapse use').setAttribute('href', S.collapsed ? '#i-down' : '#i-up');
  $('#btnCollapse').setAttribute('aria-expanded', !S.collapsed);
  tiles.innerHTML = S.files.map(p => {
    const nm = baseName(p);
    return `<div class="tile" title="${esc(nm)}"><div class="tile-box">${icon(fileIcon(nm))}</div><span class="tile-name">${esc(nm)}</span></div>`;
  }).join('');
  renderDevices();
}

function renderDevices() {
  const list = [...S.devices.values()];
  $('#searching').hidden = list.length > 0;
  $('#found').hidden = list.length === 0;
  $('#deviceGrid').innerHTML = list.map((d, i) => {
    const t = d.dev_type ?? d.device_type ?? 0;
    return `<button class="device" type="button" data-i="${i}">
      <div class="device-ic">${icon(devIcon(t))}</div>
      <div class="device-name-t">${esc(d.name)}</div>
      <div class="device-type">${devLabel(t)}</div>
    </button>`;
  }).join('');
}
$('#deviceGrid').addEventListener('click', e => {
  const b = e.target.closest('.device');
  if (!b) return;
  const dev = [...S.devices.values()][Number(b.dataset.i)];
  if (dev) startSend(dev);
});

async function startScan() { try { await invoke('start_scan'); } catch (e) { toast(errText(e)); } }
async function stopScan() { try { await invoke('stop_scan'); } catch (_) {} }

function addFiles(paths) {
  paths = (paths || []).filter(Boolean);
  if (!paths.length) return;
  const had = S.files.length > 0;
  for (const p of paths) if (!S.files.includes(p)) S.files.push(p);
  renderHome();
  if (!had) startScan();
}
function clearFiles() {
  S.files = [];
  S.devices.clear();
  renderHome();
  stopScan();
}

async function pickFiles() {
  try { addFiles(await invoke('pick_files')); } catch (e) { toast(errText(e)); }
}
async function pickFolder() {
  try { const p = await invoke('pick_folder'); if (p) addFiles([p]); } catch (e) { toast(errText(e)); }
}
$('#btnSelect').addEventListener('click', pickFiles);
$('#btnSelectFolder').addEventListener('click', pickFolder);
$('#btnAdd').addEventListener('click', pickFiles);
$('#btnClear').addEventListener('click', clearFiles);
$('#btnCollapse').addEventListener('click', () => { S.collapsed = !S.collapsed; renderHome(); });

/* Drag & drop (Tauri v2 window events) */
listen('tauri://drag-enter', () => { if (!S.modal && $('#view-home').hidden === false) $('#idle').classList.add('over'); });
listen('tauri://drag-over', () => { if (!S.modal) $('#idle').classList.add('over'); });
listen('tauri://drag-leave', () => $('#idle').classList.remove('over'));
listen('tauri://drag-drop', e => {
  $('#idle').classList.remove('over');
  if (S.modal) return;
  const paths = e.payload && e.payload.paths;
  if (paths && paths.length) addFiles(paths);
});

/* ---------- Dialog plumbing ---------- */
function setDialog(html) {
  $('#dialog').innerHTML = html;
  $('#backdrop').hidden = false;
  const f = $('#dialog .btn.primary') || $('#dialog .btn');
  if (f) f.focus();
}
function closeModal() {
  S.modal = null;
  $('#backdrop').hidden = true;
  $('#dialog').innerHTML = '';
}
$('#dialog').addEventListener('click', e => {
  const b = e.target.closest('[data-act]');
  if (!b || b.disabled) return;
  const act = b.dataset.act;
  if (act === 'accept') respond(true);
  else if (act === 'decline') respond(false);
  else if (act === 'cancel') cancelTransfer(b);
  else if (act === 'close') closeModal();
  else if (act === 'open') { invoke('open_downloads').catch(() => {}); closeModal(); }
  else if (act === 'done') { closeModal(); clearFiles(); }
});

function resetProg() {
  S.prog = { pct: 0, mbps: 0, idx: 1, total: 1, name: '', start: Date.now(), startPct: 0 };
}
function progressHtml(title, wait) {
  return `
    ${title ? `<h2 style="margin-top:0">${esc(title)}</h2>` : ''}
    <div class="bar ${wait ? 'wait' : ''}" id="pBar"><i id="pFill"></i></div>
    <div class="stats"><span class="pct" id="pPct">0%</span><span id="pSpeed"></span><span id="pEta"></span></div>
    <p class="cur-file" id="pFile"></p>
    <div class="actions"><button class="btn ghost" data-act="cancel" type="button">Cancel</button></div>`;
}
function updateProgressUI() {
  const p = S.prog;
  const fill = $('#pFill');
  if (!fill) return;
  $('#pBar').classList.remove('wait');
  fill.style.marginLeft = '0';
  fill.style.width = `${p.pct}%`;
  $('#pPct').textContent = `${Math.round(p.pct)}%`;
  $('#pSpeed').textContent = p.mbps > 0 ? `${p.mbps.toFixed(1)} MB/s` : '';
  let eta = p.eta;
  if (eta == null) {
    const el = (Date.now() - p.start) / 1000;
    const done = p.pct - p.startPct;
    eta = done > 1 && el > 1 ? (el * (100 - p.pct)) / done : NaN;
  }
  $('#pEta').textContent = fmtEta(eta);
  const cnt = p.total > 1 ? `File ${p.idx} of ${p.total}` : '';
  $('#pFile').textContent = [p.name, cnt].filter(Boolean).join('  -  ');
}

/* ---------- Receive: offer ---------- */
function offerSummary(o) {
  const files = o.files || [];
  const count = o.count || files.length || 1;
  if (count === 1) {
    const nm = files[0] ? files[0].name : '';
    return `${kindOf(nm)} (${fmtBytes(o.total)})`;
  }
  return `${count} files (${fmtBytes(o.total)})`;
}
function showOffer(o) {
  S.offer = o;
  S.lastOffer = o;
  S.offerResponded = false;
  S.modal = 'offer';
  const files = o.files || [];
  const rows = files.slice(0, 6).map(f => `
    <div class="frow"><div class="tile-box">${icon(fileIcon(f.name))}</div>
      <div class="frow-t"><b>${esc(f.name)}</b><span>${fmtBytes(f.size)}</span></div></div>`).join('');
  const more = (o.more || 0) > 0 ? `<div class="frow-t"><span>and ${o.more} more</span></div>` : '';
  const single = (o.count || files.length) <= 1;
  const first = files[0] ? files[0].name : '';
  const box = single
    ? `<div class="frow"><div class="tile-box">${icon(fileIcon(first))}</div>
         <div class="frow-t"><b>${esc(kindOf(first))} file</b><span class="pin">PIN: ${esc(o.pin || '----')}</span></div></div>`
    : `${rows}${more}<div class="frow-t"><span class="pin">PIN: ${esc(o.pin || '----')}</span></div>`;
  setDialog(`
    <div class="dh"><div class="avatar">${icon('phone')}</div>
      <div class="dh-t"><b>${esc(o.device || 'Nearby device')}</b><span>${esc(offerSummary(o))}</span></div></div>
    <h2>Accept request?</h2>
    <div class="filebox">${box}</div>
    <div class="actions"><button class="btn primary" data-act="accept" type="button">Accept</button>
      <button class="btn ghost" data-act="decline" type="button">Decline</button></div>`);
}
async function respond(accept) {
  S.offerResponded = true;
  try { await invoke('respond_offer', { accept }); } catch (e) { toast(errText(e)); }
  if (!accept) closeModal();
  else {
    S.rx = { device: S.offer ? S.offer.device : '', names: [] };
    showRx();
  }
}
function showRx() {
  S.modal = 'rx';
  resetProg();
  const o = S.offer || {};
  setDialog(`
    <div class="dh"><div class="avatar">${icon('phone')}</div>
      <div class="dh-t"><b>${esc(o.device || S.rx.device || 'Nearby device')}</b><span>${esc(o.count ? offerSummary(o) : 'Receiving')}</span></div></div>
    <h2>Receiving</h2>
    ${progressHtml('', true)}`);
}

/* ---------- Receive: finished ---------- */
function showReceived() {
  S.modal = 'received';
  const o = S.lastOffer || {};
  const names = S.rx.names.length ? S.rx.names : (o.files || []).map(f => f.name);
  const sizes = {};
  (o.files || []).forEach(f => { sizes[f.name] = f.size; });
  const rows = names.slice(0, 6).map(n => `
    <div class="frow"><div class="tile-box">${icon(fileIcon(n))}</div>
      <div class="frow-t"><b>${esc(n)}</b>${sizes[n] != null ? `<span>${fmtBytes(sizes[n])}</span>` : ''}</div></div>`).join('');
  const extra = names.length > 6 ? `<div class="frow-t"><span>and ${names.length - 6} more</span></div>` : '';
  setDialog(`
    <div class="dh"><div class="avatar ok">${icon('check')}</div>
      <div class="dh-t"><b>${esc(o.device || S.rx.device || 'Nearby device')}</b><span>${esc(o.total != null ? offerSummary(o) : 'Files received')}</span></div></div>
    <h2>Received</h2>
    <div class="filebox">${rows || '<div class="frow-t"><span>Saved to your downloads folder</span></div>'}${extra}</div>
    <div class="actions"><button class="btn primary" data-act="open" type="button">Open</button>
      <button class="btn ghost" data-act="close" type="button">Close</button></div>`);
}

/* ---------- Send ---------- */
async function startSend(dev) {
  if (S.sendActive) return;
  S.sendActive = true;
  S.tx = { name: dev.name, pin: '', stage: 'connecting' };
  showTx();
  try {
    await invoke('send_files', {
      name: dev.name,
      ip: dev.ip,
      port: Number(dev.port),
      devType: dev.dev_type ?? dev.device_type ?? 0,
      instance: dev.instance || '',
      paths: S.files,
    });
  } catch (e) {
    if (S.sendActive) { S.sendActive = false; closeModal(); toast(errText(e)); }
  }
}
function showTx() {
  S.modal = 'tx';
  resetProg();
  const t = S.tx;
  const title = t.stage === 'connecting' ? 'Connecting…'
    : t.stage === 'waiting' ? `Waiting for ${t.name} to accept…`
    : 'Sending…';
  const pin = t.pin ? `<p class="pin-big">PIN: <b>${esc(t.pin)}</b></p>` : '';
  setDialog(`
    <div class="dh"><div class="avatar">${icon('phone')}</div>
      <div class="dh-t"><b>${esc(t.name)}</b><span>${S.files.length} ${S.files.length === 1 ? 'file' : 'files'}</span></div></div>
    <div style="height:18px"></div>
    ${progressHtml(title, t.stage !== 'sending')}${pin}`);
  if (t.stage === 'sending') updateProgressUI();
}
function showSent() {
  S.modal = 'tx';
  setDialog(`
    <div class="dh"><div class="avatar ok">${icon('check')}</div>
      <div class="dh-t"><b>${esc(S.tx.name)}</b><span>${S.files.length} ${S.files.length === 1 ? 'file' : 'files'}</span></div></div>
    <h2>Sent</h2>
    <div class="actions"><button class="btn primary" data-act="done" type="button">Done</button></div>`);
}
function cancelTransfer(btn) {
  btn.disabled = true;
  btn.textContent = 'Cancelling…';
  invoke('control_transfer', { cmd: 'c' }).catch(e => toast(errText(e)));
}

/* ---------- Engine events ---------- */
function onProgress(d) {
  const p = S.prog;
  const pct = Number(d.pct ?? d.percent ?? 0);
  if (p.start === 0 || pct < p.pct) { p.start = Date.now(); p.startPct = pct; }
  p.pct = pct;
  p.mbps = Number(d.mbps ?? d.speed_mbps ?? 0);
  p.idx = d.file_index || p.idx;
  p.total = d.files || d.file_count || p.total;
  if (d.name) p.name = d.name;
  p.eta = d.eta_secs != null ? Number(d.eta_secs) : null;

  if (d.dir === 'tx') {
    if (!S.sendActive) return;
    if (S.tx.stage !== 'sending') { S.tx.stage = 'sending'; showTx(); }
    updateProgressUI();
  } else {
    if (S.modal !== 'rx') { if (!S.offer && !S.lastOffer) S.offer = {}; showRx(); }
    updateProgressUI();
  }
}

let lastRaw = '', lastAt = 0;
function handleEvent(ev) {
  let d = ev.payload;
  if (typeof d === 'string') { try { d = JSON.parse(d); } catch (_) { return; } }
  if (!d || !d.type) return;

  // The backend emits to several targets; drop exact duplicates that arrive back to back.
  const raw = JSON.stringify(d), now = Date.now();
  if (d.type !== 'progress' && raw === lastRaw && now - lastAt < 60) return;
  lastRaw = raw; lastAt = now;

  switch (d.type) {
    case 'offer':
      showOffer(d);
      break;

    case 'offer_closed':
      if (S.modal === 'offer' && !S.offerResponded) { closeModal(); toast('Request expired'); }
      break;

    case 'rx_accepted':
    case 'rx_resumed':
      S.rx = { device: d.device || (S.offer && S.offer.device) || '', names: [] };
      if (S.modal !== 'rx') showRx();
      break;

    case 'file_done':
      if (d.name) S.rx.names.push(d.name);
      break;

    case 'progress':
      onProgress(d);
      break;

    case 'rx_session_end':
      if (d.cancelled === true) { closeModal(); toast('Transfer cancelled'); }
      else if (d.ok === true) showReceived();
      else { closeModal(); toast('Transfer failed'); }
      break;

    case 'rx_interrupted':
      closeModal();
      toast('Transfer interrupted');
      break;

    case 'device': {
      const key = d.instance || d.key || `${d.ip}:${d.port}`;
      S.devices.set(key, d);
      if (S.files.length) renderDevices();
      break;
    }
    case 'device_gone':
    case 'device_lost': {
      for (const [k, v] of S.devices) {
        if ((d.key && v.key === d.key) || (d.instance && v.instance === d.instance) || k === d.key) S.devices.delete(k);
      }
      if (S.files.length) renderDevices();
      break;
    }

    case 'send_pin':
      if (!S.sendActive) break;
      S.tx.pin = d.pin || '';
      S.tx.stage = 'waiting';
      showTx();
      break;

    case 'send_waiting':
      if (!S.sendActive) break;
      S.tx.stage = 'waiting';
      showTx();
      break;

    case 'send_accepted':
      if (!S.sendActive) break;
      S.tx.stage = 'sending';
      showTx();
      break;

    case 'send_finished':
      if (!S.sendActive) break;
      S.sendActive = false;
      if (d.cancelled) { closeModal(); toast('Transfer cancelled or declined'); }
      else showSent();
      break;

    case 'stopped':
      if (S.vis !== 'none') { S.vis = 'none'; renderVis(); }
      break;

    default:
      break;
  }
}

listen('qs-event', handleEvent);

/* Optional: per-event names from the original IPC contract (adapters -> same handlers) */
listen('rx_offer', ev => {
  const p = ev.payload || {};
  handleEvent({ payload: { type: 'offer', device: p.device_name, count: p.file_count, total: p.total_bytes, pin: p.pin, files: p.files || [] } });
});
listen('rx_progress', ev => onProgress({ ...(ev.payload || {}), dir: 'rx' }));
listen('tx_progress', ev => onProgress({ ...(ev.payload || {}), dir: 'tx' }));
listen('rx_session_end', ev => handleEvent({ payload: { type: 'rx_session_end', ...(ev.payload || {}) } }));
listen('device_found', ev => handleEvent({ payload: { type: 'device', ...(ev.payload || {}) } }));
listen('device_lost', ev => handleEvent({ payload: { type: 'device_lost', ...(ev.payload || {}) } }));

/* ---------- Settings ---------- */
function showView(name) {
  $('#view-home').hidden = name !== 'home';
  $('#view-settings').hidden = name !== 'settings';
  if (name === 'settings') refreshStatus();
}
$('#btnSettings').addEventListener('click', () => showView('settings'));
$('#btnBack').addEventListener('click', () => showView('home'));
$('#rowVis').addEventListener('click', () => {
  const o = $('#setVisOptions');
  o.hidden = !o.hidden;
  $('#rowVis').setAttribute('aria-expanded', !o.hidden);
});
$('#setVisOptions').addEventListener('click', e => {
  const b = e.target.closest('.opt');
  if (b) setVisibility(b.dataset.vis);
});
$('#rowFolder').addEventListener('click', () => invoke('open_downloads').catch(e => toast(errText(e))));
$('#rowAbout').addEventListener('click', () => {
  const o = $('#aboutBody');
  o.hidden = !o.hidden;
  $('#rowAbout').setAttribute('aria-expanded', !o.hidden);
});

// Start-up toggle: remembered locally only (no backend command exists for it yet)
try { $('#swStartup').checked = localStorage.getItem('qs.startup') === '1'; } catch (_) {}
$('#swStartup').addEventListener('change', e => {
  try { localStorage.setItem('qs.startup', e.target.checked ? '1' : '0'); } catch (_) {}
});

/* ---------- Init ---------- */
window.addEventListener('DOMContentLoaded', async () => {
  renderVis();
  renderHome();
  await refreshStatus();
  try {
    const app = window.__TAURI__ && window.__TAURI__.app;
    if (app && app.getVersion) $('#setVersion').textContent = `Version ${await app.getVersion()}`;
  } catch (_) {}
});
