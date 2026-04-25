/**
 * SecureSyscall OS — script.js  v2.1
 * All API calls, WebSocket management, DOM updates, tab routing,
 * chart rendering, analytics, and UX enhancements.
 */

"use strict";

// ── Config ────────────────────────────────────────────────────────────────────
const BASE   = `${location.protocol}//${location.host}`;
const WS_URL = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/live`;

// ── Category metadata ─────────────────────────────────────────────────────────
const CAT_META = {
  io:      { icon: '💾', color: 'var(--c-io)',      label: 'I/O' },
  fs:      { icon: '📁', color: 'var(--c-fs)',      label: 'Filesystem' },
  memory:  { icon: '🔶', color: 'var(--c-memory)',  label: 'Memory' },
  process: { icon: '⚙️',  color: 'var(--c-process)', label: 'Process' },
  network: { icon: '🌐', color: 'var(--c-network)', label: 'Network' },
  signal:  { icon: '📡', color: 'var(--c-signal)',  label: 'Signal' },
  debug:   { icon: '🐛', color: 'var(--c-debug)',   label: 'Debug' },
  device:  { icon: '🔌', color: 'var(--c-device)',  label: 'Device' },
  system:  { icon: '🖥️',  color: 'var(--c-system)',  label: 'System' },
};

const SEV_ICON = { low: '🟢', medium: '🟡', high: '🟠', critical: '🔴' };

// ── State ─────────────────────────────────────────────────────────────────────
let feedCount    = 0;
let syscallCache = [];
let ws           = null;
let wsRetries    = 0;
let uptimeBase   = 0;
let rateChart    = null;
let rateData     = new Array(60).fill(0);  // rolling 60-point series
let threatCount  = 0;

// ── Utility ───────────────────────────────────────────────────────────────────
async function apiFetch(path, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body !== null) opts.body = JSON.stringify(body);
  try {
    const r = await fetch(BASE + path, opts);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    console.warn('[API]', path, e.message);
    return null;
  }
}

function fmt(n) {
  return typeof n === 'number' ? n.toLocaleString() : (n ?? '—');
}

function shortTime(iso) {
  return iso ? iso.slice(11, 19) : '—';
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function catPill(cat) {
  const m = CAT_META[cat] || { icon: '?', label: cat };
  return `<span class="cat-pill ${cat}">${m.icon} ${m.label}</span>`;
}

function modeBadge(mode) {
  return `<span class="badge badge-${mode}">${mode}</span>`;
}

function riskBar(score) {
  const col = score > 70 ? 'var(--m-blocked)'
    : score > 40 ? 'var(--m-audited)'
    : 'var(--m-allowed)';
  const pct = Math.min(100, score);
  return `<div class="risk-wrap">
    <div class="risk-bar"><div class="risk-fill" style="width:${pct}%;background:${col}"></div></div>
    <span class="risk-val" style="color:${col}">${score}</span>
  </div>`;
}

// ── Tab routing ───────────────────────────────────────────────────────────────
function showTab(name, btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const el = document.getElementById('tab-' + name);
  if (el) el.classList.add('active');
  if (btn) btn.classList.add('active');
  // Lazy-load tab data
  const loaders = {
    policies:  loadPolicies,
    syscalls:  loadSyscalls,
    audit:     loadAudit,
    threats:   () => loadThreats(''),
    analytics: loadAnalytics,
    processes: refreshProcesses,
  };
  if (loaders[name]) loaders[name]();
}
window.showTab = showTab;

// ── Status / KPIs ─────────────────────────────────────────────────────────────
async function refreshStatus() {
  const s = await apiFetch('/api/status');
  if (!s) return;

  setText('stat-total',    fmt(s.total_syscalls));
  setText('stat-blocked',  fmt(s.blocked_calls));
  setText('stat-policies', fmt(s.active_policies));
  setText('stat-threat',   fmt(s.threat_score));
  setText('stat-rate',     fmt(s.avg_rate_per_sec));
  setText('stat-ws',       fmt(s.ws_connections));
  setText('stat-level',    (s.security_level || '—').toUpperCase());

  uptimeBase = s.uptime_seconds || uptimeBase;

  const badge = document.getElementById('sec-badge');
  if (badge) {
    badge.textContent = (s.security_level || 'unknown').toUpperCase();
    badge.className   = `sec-badge ${s.security_level}`;
  }
}

// Uptime clock (incremented locally every second)
function renderUptime() {
  const s  = uptimeBase;
  const hh = String(Math.floor(s / 3600)).padStart(2, '0');
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const ss = String(s % 60).padStart(2, '0');
  setText('uptime-txt', `${hh}:${mm}:${ss}`);
}

// ── Analytics ─────────────────────────────────────────────────────────────────
async function loadAnalytics() {
  const data = await apiFetch('/api/analytics');
  if (!data) return;

  setText('an-block-rate', data.block_rate_pct + '%');
  setText('an-total',      fmt(data.total));
  setText('an-blocked',    fmt(data.blocked));

  // Rate chart
  if (data.rate_window && data.rate_window.length) {
    rateData = data.rate_window;
    drawRateChart();
  }

  // Per-category table
  const tb = document.getElementById('analytics-tbody');
  if (!tb) return;
  const cats = data.categories || {};
  const TREND = ['📈', '📉', '➡️'];
  tb.innerHTML = Object.entries(cats).map(([cat, v]) => {
    const m   = CAT_META[cat] || { icon: '?', color: '#fff' };
    const blk = v.blocked || 0;
    const tot = v.total   || 0;
    const pct = tot > 0 ? ((blk / tot) * 100).toFixed(1) : '0.0';
    const trend = TREND[Math.floor(Math.random() * 3)]; // cosmetic
    return `<tr>
      <td>${catPill(cat)}</td>
      <td style="color:${m.color}">${fmt(tot)}</td>
      <td style="color:var(--m-blocked)">${fmt(blk)}</td>
      <td>${riskBar(parseFloat(pct))}</td>
      <td>${trend}</td>
    </tr>`;
  }).join('');
}

function drawRateChart() {
  const canvas = document.getElementById('rate-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 400;
  const H = canvas.height || 120;
  canvas.width = W;

  const max  = Math.max(...rateData, 1);
  const step = W / Math.max(rateData.length - 1, 1);

  ctx.clearRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = 'rgba(26,37,53,0.8)';
  ctx.lineWidth   = 1;
  for (let i = 0; i <= 4; i++) {
    const y = (H / 4) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(W, y);
    ctx.stroke();
  }

  // Area fill
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, 'rgba(0,212,255,0.3)');
  grad.addColorStop(1, 'rgba(0,212,255,0.02)');
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.moveTo(0, H);
  rateData.forEach((v, i) => {
    const x = i * step;
    const y = H - (v / max) * (H - 8);
    i === 0 ? ctx.lineTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.lineTo((rateData.length - 1) * step, H);
  ctx.closePath();
  ctx.fill();

  // Line
  ctx.strokeStyle = 'var(--accent, #00d4ff)';
  ctx.lineWidth   = 2;
  ctx.lineJoin    = 'round';
  ctx.beginPath();
  rateData.forEach((v, i) => {
    const x = i * step;
    const y = H - (v / max) * (H - 8);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
}

// ── Processes ─────────────────────────────────────────────────────────────────
async function refreshProcesses() {
  const procs = await apiFetch('/api/processes');
  if (!procs) return;
  const tb = document.getElementById('proc-body');
  if (!tb) return;

  tb.innerHTML = procs.map(p => {
    const col = p.risk > 70 ? 'var(--m-blocked)'
      : p.risk > 40 ? 'var(--m-audited)'
      : 'var(--m-allowed)';
    return `<tr>
      <td class="muted">${p.pid}</td>
      <td style="color:var(--accent);font-weight:600">${p.name}</td>
      <td>${p.user}</td>
      <td>
        <span class="proc-status ${p.status}"></span>
        <span class="muted" style="font-size:9px;margin-left:4px">${p.status}</span>
      </td>
      <td>${p.syscalls_per_sec}</td>
      <td>${riskBar(p.risk)}</td>
      <td>
        <button class="btn-sm" style="color:var(--m-blocked)"
          onclick="killProcess(${p.pid})">⊗ Kill</button>
      </td>
    </tr>`;
  }).join('');
}
window.refreshProcesses = refreshProcesses;

async function killProcess(pid) {
  if (!confirm(`Sandbox-kill PID ${pid}?`)) return;
  const r = await apiFetch(`/api/processes/${pid}`, 'DELETE');
  if (r) {
    refreshProcesses();
    loadThreats('');
  }
}
window.killProcess = killProcess;

// ── Category stats (dashboard) ────────────────────────────────────────────────
async function refreshCategoryStats() {
  const scs = await apiFetch('/api/syscalls');
  if (!scs) return;
  syscallCache = scs;

  const cats = {};
  scs.forEach(s => {
    const c = s.category;
    if (!cats[c]) cats[c] = { total: 0, blocked: 0 };
    cats[c].total   += s.count;
    cats[c].blocked += s.blocked;
  });

  const el = document.getElementById('cat-stats');
  if (!el) return;
  el.innerHTML = Object.entries(cats).map(([cat, v]) => {
    const m = CAT_META[cat] || { icon: '?', color: '#fff' };
    return `<div class="cat-stat">
      <div class="cat-stat-val" style="color:${m.color}">${m.icon} ${fmt(v.total)}</div>
      <div class="cat-stat-lbl">${cat}</div>
      <div class="cat-stat-blk">▼ ${fmt(v.blocked)}</div>
    </div>`;
  }).join('');
}

// ── Policies ──────────────────────────────────────────────────────────────────
async function loadPolicies() {
  const policies = await apiFetch('/api/policies');
  if (!policies) return;

  const active = policies.filter(p => p.enabled).length;
  setText('pol-active-count', `${active} / ${policies.length} enabled`);

  const tb = document.getElementById('pol-body');
  if (!tb) return;
  tb.innerHTML = policies.map((p, i) => {
    const m = CAT_META[p.category] || { icon: '?' };
    return `<tr>
      <td class="muted" style="font-size:9px">${String(i + 1).padStart(2, '0')}</td>
      <td style="font-weight:600">${m.icon} ${p.name}</td>
      <td>${catPill(p.category)}</td>
      <td class="muted" style="font-size:10px">${p.description}</td>
      <td>
        <label class="toggle">
          <input type="checkbox" ${p.enabled ? 'checked' : ''}
            onchange="togglePolicy(${i}, this.checked)">
          <span class="slider"></span>
        </label>
      </td>
    </tr>`;
  }).join('');
}

async function togglePolicy(i, val) {
  await apiFetch(`/api/policies/${i}`, 'PUT', { enabled: val });
  refreshStatus();
  loadPolicies();
}
window.togglePolicy = togglePolicy;

// ── Syscalls ──────────────────────────────────────────────────────────────────
async function loadSyscalls() {
  const data = await apiFetch('/api/syscalls');
  if (!data) return;
  syscallCache = data;
  renderSyscalls(data);
}

function renderSyscalls(data) {
  const tb = document.getElementById('sc-body');
  if (!tb) return;
  tb.innerHTML = data.map(s => {
    const m = CAT_META[s.category] || { icon: '?', color: '#fff' };
    return `<tr>
      <td style="color:${m.color};font-weight:600">${m.icon} ${s.name}</td>
      <td>${catPill(s.category)}</td>
      <td>${modeBadge(s.mode)}</td>
      <td class="muted">${fmt(s.count)}</td>
      <td style="color:${s.blocked > 0 ? 'var(--m-blocked)' : 'var(--text-muted)'}">${fmt(s.blocked)}</td>
      <td>
        <select class="mode-sel" onchange="setSyscallMode('${s.name}', this.value)">
          ${['allowed','audited','sandboxed','blocked'].map(md =>
            `<option value="${md}" ${s.mode === md ? 'selected' : ''}>${md}</option>`
          ).join('')}
        </select>
      </td>
      <td>
        <button class="btn-sm" onclick="resetSyscall('${s.name}')" title="Reset counters">↺</button>
      </td>
    </tr>`;
  }).join('');
}

window.filterSyscalls = function () {
  const q   = (document.getElementById('sc-search')?.value || '').toLowerCase();
  const cat = document.getElementById('cat-filter')?.value || '';
  renderSyscalls(syscallCache.filter(s =>
    (!cat || s.category === cat) &&
    (s.name.includes(q) || s.category.includes(q) || s.mode.includes(q))
  ));
};

window.setSyscallMode = async function (name, mode) {
  await apiFetch(`/api/syscalls/${name}`, 'PUT', { mode });
  loadSyscalls();
};

window.resetSyscall = async function (name) {
  await apiFetch(`/api/syscalls/${name}/reset`, 'POST');
  loadSyscalls();
};

// ── Audit ─────────────────────────────────────────────────────────────────────
async function loadAudit() {
  const cat         = document.getElementById('audit-cat')?.value || '';
  const blockedOnly = document.getElementById('audit-blocked-only')?.checked || false;

  let url = '/api/audit?limit=120';
  if (cat)         url += `&category=${cat}`;
  if (blockedOnly) url += `&blocked_only=true`;

  const log = await apiFetch(url);
  if (!log) return;

  const tb = document.getElementById('audit-body');
  if (!tb) return;
  tb.innerHTML = log.map(e => {
    const m = CAT_META[e.category] || { icon: '?' };
    const flags = [
      e.priv_esc  ? '<span class="badge badge-critical" title="Privilege escalation">PRIV-ESC</span>' : '',
      e.rate_flag ? '<span class="badge badge-high"     title="Rate limit triggered">RATE</span>'    : '',
    ].filter(Boolean).join(' ');
    return `<tr>
      <td class="muted" style="font-size:9px">${shortTime(e.time)}</td>
      <td style="color:var(--accent);font-weight:600">${m.icon} ${e.syscall}</td>
      <td>${catPill(e.category)}</td>
      <td>${e.process}</td>
      <td class="muted">${e.pid}</td>
      <td>${modeBadge(e.blocked ? 'blocked' : 'allowed')}</td>
      <td>${flags || '—'}</td>
      <td class="muted" style="font-size:9px;max-width:110px;overflow:hidden;text-overflow:ellipsis">${e.args || '—'}</td>
    </tr>`;
  }).join('');
}
window.loadAudit = loadAudit;

// ── Threats ───────────────────────────────────────────────────────────────────
async function loadThreats(severity = '') {
  let url = '/api/threats?limit=80';
  if (severity) url += `&severity=${severity}`;

  const threats = await apiFetch(url);
  const el = document.getElementById('threat-list');
  if (!el) return;

  if (!threats || !threats.length) {
    el.innerHTML = '<p class="muted" style="padding:14px;font-size:11px">No threat alerts recorded.</p>';
    return;
  }

  // Update badge
  threatCount = threats.length;
  const badge = document.getElementById('threat-badge');
  if (badge) {
    badge.textContent = threatCount > 99 ? '99+' : threatCount;
    badge.style.display = threatCount > 0 ? 'inline-block' : 'none';
  }

  el.innerHTML = threats.map(t => {
    const m = CAT_META[t.category] || { icon: '⚠️' };
    const extras = [
      t.priv_esc  ? '<span class="badge badge-critical">PRIV-ESC</span>' : '',
      t.rate_flag ? '<span class="badge badge-high">RATE-LIMIT</span>'   : '',
    ].filter(Boolean).join(' ');
    return `<div class="threat-item ${t.severity}">
      <div class="threat-icon">${SEV_ICON[t.severity] || '⚠️'}</div>
      <div class="threat-body">
        <div class="threat-msg">
          <span class="badge badge-${t.severity}">${t.severity.toUpperCase()}</span>
          ${extras}
          <span style="margin-left:8px">${t.message}</span>
        </div>
        <div class="threat-meta">
          <span>${m.icon} ${t.category}</span>
          <span>syscall: <strong>${t.syscall}</strong></span>
          <span>${shortTime(t.time)} UTC</span>
        </div>
      </div>
    </div>`;
  }).join('');
}
window.loadThreats = loadThreats;

async function clearThreats() {
  if (!confirm('Clear all threat alerts?')) return;
  await apiFetch('/api/threats', 'DELETE');
  loadThreats('');
}
window.clearThreats = clearThreats;

// ── Sandbox ───────────────────────────────────────────────────────────────────
window.runSandbox = async function () {
  const inp = document.getElementById('cmd-input');
  const out  = document.getElementById('sandbox-out');
  if (!inp || !out) return;
  const cmd = inp.value.trim();
  if (!cmd) return;

  out.innerHTML = '<span class="muted">⏳ Evaluating against active policies…</span>';

  const res = await apiFetch('/api/sandbox/run', 'POST', { command: cmd });
  if (!res) {
    out.innerHTML = '<span style="color:var(--m-blocked)">❌ Error contacting backend.</span>';
    return;
  }

  const isBlock = res.decision === 'BLOCK';
  const cls     = isBlock ? 'verdict-block' : 'verdict-allow';
  const icon    = isBlock ? '✗' : '✓';

  out.innerHTML = `
    <div class="${cls}" style="font-size:22px;font-weight:700;margin-bottom:14px;
         font-family:var(--font-display);letter-spacing:2px">
      ${icon} ${res.decision}
    </div>
    <div style="display:grid;grid-template-columns:110px 1fr;gap:8px 12px;font-size:11px;
         align-items:start">
      <span class="muted">Command</span>
      <span style="color:var(--text-primary);font-weight:600">${res.command}</span>
      <span class="muted">Reason</span>
      <span>${res.reason}</span>
      <span class="muted">Risk Score</span>
      <span>${riskBar(res.risk_score)}</span>
      <span class="muted">Category</span>
      <span>${res.cmd_parsed || '—'}</span>
      <span class="muted">Timestamp</span>
      <span class="muted" style="font-size:9px">${shortTime(res.timestamp)} UTC</span>
      ${res.blocked_syscalls?.length ? `
        <span class="muted">Blocked<br>Syscalls</span>
        <span>${res.blocked_syscalls.map(s =>
          `<span class="badge badge-blocked" style="margin:2px 2px 0 0">${s}</span>`
        ).join('')}</span>` : ''}
    </div>`;
};

window.quickTest = function (cmd) {
  const inp = document.getElementById('cmd-input');
  if (inp) inp.value = cmd;
  window.runSandbox();
};

// ── Security level ────────────────────────────────────────────────────────────
window.setSecLevel = async function (level) {
  await apiFetch('/api/security-level', 'PUT', { level });
  await refreshStatus();
  // Reload syscalls in case modes changed
  if (document.getElementById('tab-syscalls')?.classList.contains('active')) {
    loadSyscalls();
  }
};

// ── WebSocket live feed ───────────────────────────────────────────────────────
function connectWS() {
  try {
    ws = new WebSocket(WS_URL);
  } catch (e) {
    scheduleReconnect();
    return;
  }

  const dot = document.getElementById('ws-dot');
  const lbl = document.getElementById('ws-lbl');

  ws.onopen = () => {
    wsRetries = 0;
    if (dot) { dot.className = 'ws-dot on'; }
    if (lbl)   lbl.textContent = 'LIVE';
    // Ping keepalive every 25s
    ws._pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping');
    }, 25000);
  };

  ws.onmessage = (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }

    if (msg.type === 'pong' || msg.type === 'heartbeat') return;

    if (msg.type === 'snapshot') {
      // Initial snapshot — sync local caches
      if (msg.data?.syscalls) syscallCache = msg.data.syscalls;
      return;
    }

    if (msg.type !== 'syscall_event') return;

    const ev = msg.data;
    feedCount++;
    const fc = document.getElementById('feed-count');
    if (fc) fc.textContent = fmt(feedCount) + ' events';

    // Update rolling rate chart data
    rateData.shift();
    rateData.push(feedCount % 10);  // cosmetic tick

    const feed = document.getElementById('live-feed');
    if (!feed) return;

    const m   = CAT_META[ev.category] || { icon: '?', color: 'var(--text-primary)' };
    const row = document.createElement('div');
    row.className = `feed-row ${ev.blocked ? 'blocked' : ev.mode}`;

    const flags = [
      ev.priv_esc  ? '<span class="badge badge-critical" style="font-size:8px">PE</span>' : '',
      ev.rate_flag ? '<span class="badge badge-high"     style="font-size:8px">RL</span>' : '',
    ].filter(Boolean).join('');

    row.innerHTML = `
      <span class="feed-time">${shortTime(ev.time)}</span>
      <span class="feed-call" style="color:${m.color}">${m.icon} ${ev.syscall}</span>
      <span class="feed-proc">${ev.process}</span>
      <span class="feed-pid muted">${ev.pid}</span>
      <span>${flags}${ev.blocked
        ? '<span class="badge badge-blocked">BLOCKED</span>'
        : `<span class="badge badge-${ev.mode}">${ev.mode.slice(0, 3).toUpperCase()}</span>`
      }</span>`;

    feed.prepend(row);
    // Cap feed at 120 visible rows
    while (feed.children.length > 120) feed.lastChild.remove();

    // Auto-update threat badge if on threats tab
    if (ev.blocked && (ev.priv_esc || ev.rate_flag)) {
      threatCount++;
      const badge = document.getElementById('threat-badge');
      if (badge) {
        badge.textContent = threatCount > 99 ? '99+' : threatCount;
        badge.style.display = 'inline-block';
      }
    }
  };

  ws.onclose = () => {
    clearInterval(ws._pingInterval);
    if (dot) { dot.className = 'ws-dot off'; }
    if (lbl) lbl.textContent = 'OFFLINE';
    scheduleReconnect();
  };

  ws.onerror = () => ws.close();
}

function scheduleReconnect() {
  const delay = Math.min(30000, 1000 * Math.pow(1.5, wsRetries++));
  setTimeout(connectWS, delay);
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function init() {
  await refreshStatus();
  await refreshCategoryStats();
  await refreshProcesses();
  connectWS();

  // Uptime ticker
  setInterval(() => {
    uptimeBase++;
    renderUptime();
  }, 1000);

  // Analytics chart resize
  window.addEventListener('resize', () => {
    if (document.getElementById('tab-analytics')?.classList.contains('active')) {
      drawRateChart();
    }
  });

  // Periodic background polls
  setInterval(refreshStatus,        5000);
  setInterval(refreshCategoryStats, 12000);
  setInterval(refreshProcesses,     15000);
  setInterval(() => {
    if (document.getElementById('tab-analytics')?.classList.contains('active')) {
      loadAnalytics();
    }
  }, 8000);
}

document.addEventListener('DOMContentLoaded', init);