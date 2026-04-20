const API = window.location.protocol === 'file:' || window.location.port === '5000' ? 'http://127.0.0.1:8000' : '';
const WS = window.location.protocol === 'https:' ? 'wss' : 'ws';
const PANELS = ['dashboard', 'live-log', 'processes', 'threats', 'policy', 'syscalls', 'sandbox', 'audit'];
const state = {
  logEntries: [],
  policies: [],
  syscalls: [],
  audit: [],
  threats: null,
  currentSyscallFilter: 'all',
  ws: null
};

const fallback = {
  status: {
    syscall_rate: 1416,
    blocked_total: 47,
    active_policies: 18,
    threat_score: 42,
    security_level: 'enforcing',
    categories: { file: 38, net: 24, proc: 19, mem: 12, ipc: 7 }
  },
  log: [
    { time: '14:03:52', pid: '4421', call: 'ptrace()', args: 'PTRACE_ATTACH, target=PID:1882, addr=0x0', action: 'blocked', cat: 'proc' },
    { time: '14:03:48', pid: '3302', call: 'execve()', args: '/usr/bin/curl, ["curl","http://10.0.0.1/backdoor"]', action: 'sandboxed', cat: 'proc' },
    { time: '14:03:41', pid: '2110', call: 'mprotect()', args: 'addr=0x7fff2000, len=4096, PROT_EXEC|PROT_WRITE', action: 'blocked', cat: 'mem' },
    { time: '14:03:39', pid: '1882', call: 'open()', args: '/etc/shadow, O_RDONLY', action: 'blocked', cat: 'file' },
    { time: '14:03:33', pid: '892', call: 'read()', args: 'fd=3, buf=0x55a12f, count=4096', action: 'allowed', cat: 'file' },
    { time: '14:03:31', pid: '1102', call: 'connect()', args: 'sockfd=5, addr=192.168.1.1:443', action: 'audited', cat: 'net' },
    { time: '14:03:28', pid: '3302', call: 'mmap()', args: 'addr=NULL, len=65536, PROT_READ|PROT_WRITE', action: 'sandboxed', cat: 'mem' }
  ],
  processes: [
    { name: 'nginx', pid: '892', rate: 82, count: 24100, risk: 'low' },
    { name: 'sshd', pid: '1882', rate: 15, count: 4420, risk: 'medium' },
    { name: 'python3', pid: '3302', rate: 68, count: 19800, risk: 'high' },
    { name: 'systemd', pid: '1', rate: 20, count: 6100, risk: 'low' },
    { name: 'unknown', pid: '4421', rate: 44, count: 1200, risk: 'high' },
    { name: 'gcc', pid: '2110', rate: 30, count: 8800, risk: 'medium' },
    { name: 'curl', pid: '1102', rate: 11, count: 3100, risk: 'medium' },
    { name: 'bash', pid: '445', rate: 7, count: 2200, risk: 'low' }
  ],
  policies: [
    { name: 'Deny ptrace from unprivileged processes', desc: 'Prevents process injection', level: 'CRITICAL', on: true },
    { name: 'Block writable executable memory', desc: 'Stops W+X page mappings', level: 'CRITICAL', on: true },
    { name: 'Restrict sensitive file reads', desc: 'Protects passwd and shadow paths', level: 'HIGH', on: true },
    { name: 'Audit network socket activity', desc: 'Records outbound network attempts', level: 'MEDIUM', on: true },
    { name: 'Sandbox risky process execution', desc: 'Runs execve activity in a jail', level: 'HIGH', on: true },
    { name: 'Gate filesystem mounts', desc: 'Requires privileged mount capability', level: 'HIGH', on: true },
    { name: 'Rate limit fork storms', desc: 'Detects fork bomb patterns', level: 'MEDIUM', on: true },
    { name: 'Deny raw socket creation', desc: 'Blocks packet crafting', level: 'MEDIUM', on: false },
    { name: 'Audit privilege changes', desc: 'Tracks setuid and setgid calls', level: 'MEDIUM', on: true },
    { name: 'Block process memory writes', desc: 'Protects direct memory interfaces', level: 'HIGH', on: true }
  ],
  syscalls: [
    { num: 0, name: 'read', cat: 'file', status: 'allowed' },
    { num: 1, name: 'write', cat: 'file', status: 'allowed' },
    { num: 2, name: 'open', cat: 'file', status: 'audited' },
    { num: 3, name: 'close', cat: 'file', status: 'allowed' },
    { num: 9, name: 'mmap', cat: 'mem', status: 'sandboxed' },
    { num: 10, name: 'mprotect', cat: 'mem', status: 'blocked' },
    { num: 39, name: 'getpid', cat: 'proc', status: 'allowed' },
    { num: 41, name: 'socket', cat: 'net', status: 'audited' },
    { num: 42, name: 'connect', cat: 'net', status: 'audited' },
    { num: 56, name: 'clone', cat: 'proc', status: 'sandboxed' },
    { num: 57, name: 'fork', cat: 'proc', status: 'sandboxed' },
    { num: 59, name: 'execve', cat: 'proc', status: 'sandboxed' },
    { num: 62, name: 'kill', cat: 'proc', status: 'audited' },
    { num: 101, name: 'ptrace', cat: 'proc', status: 'blocked' },
    { num: 105, name: 'setuid', cat: 'proc', status: 'audited' },
    { num: 165, name: 'mount', cat: 'file', status: 'blocked' },
    { num: 257, name: 'openat', cat: 'file', status: 'audited' }
  ]
};

fallback.audit = [
  { ts: '14:03:52.411', pid: '4421', call: 'ptrace()', policy: 'P-01 ptrace deny', decision: 'BLOCKED', hash: 'a3f9c2' },
  { ts: '14:03:48.203', pid: '3302', call: 'execve()', policy: 'P-05 sandbox exec', decision: 'SANDBOXED', hash: 'b7e1d4' },
  { ts: '14:03:47.891', pid: '1882', call: 'open()', policy: 'P-03 sensitive file gate', decision: 'BLOCKED', hash: 'c1a8f3' },
  { ts: '14:03:46.502', pid: '2110', call: 'mprotect()', policy: 'P-02 memory execute deny', decision: 'BLOCKED', hash: 'd5c2b1' },
  { ts: '14:03:45.200', pid: '772', call: 'socket()', policy: 'P-09 network audit', decision: 'AUDITED', hash: 'e8f3a7' }
];

fallback.threats = {
  critical: 1,
  high: 3,
  medium: 2,
  resolved: 11,
  score: 42,
  items: fallback.audit
};

function $(id) {
  return document.getElementById(id);
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed: ${response.status}`);
  }
  return response.json();
}

function switchPanel(id, evt) {
  PANELS.forEach(panel => $(`panel-${panel}`)?.classList.remove('active'));
  $(`panel-${id}`)?.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
  if (evt?.currentTarget) evt.currentTarget.classList.add('active');
}

function updateClock() {
  const el = $('live-clock');
  if (el) el.textContent = new Date().toLocaleString();
}

function setText(id, value) {
  const el = $(id);
  if (el) el.textContent = value;
}

const actLabels = Array.from({ length: 20 }, (_, i) => `${60 - i * 3}s`).reverse();
const actData = Array.from({ length: 20 }, () => Math.floor(900 + Math.random() * 600));
let actChart;

function initChart() {
  const canvas = $('actChart');
  if (!canvas || !window.Chart) return;
  actChart = new Chart(canvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: actLabels,
      datasets: [{
        data: actData,
        borderColor: '#1D9E75',
        borderWidth: 1.5,
        pointRadius: 0,
        fill: true,
        backgroundColor: 'rgba(29,158,117,0.08)',
        tension: 0.35
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: { x: { display: false }, y: { display: false, min: 0 } },
      animation: false
    }
  });
}

function updateChart(rate) {
  if (!actChart) return;
  actChart.data.datasets[0].data.shift();
  actChart.data.datasets[0].data.push(rate || Math.floor(900 + Math.random() * 600));
  actChart.update('none');
}

function statusColor(status) {
  return status === 'allowed' ? 'var(--accent)' : status === 'blocked' ? 'var(--danger)' : status === 'sandboxed' ? 'var(--warn)' : 'var(--info)';
}

function riskClass(risk) {
  return risk === 'high' ? 'blocked' : risk === 'medium' ? 'sandboxed' : 'allowed';
}

function renderLog(entries = state.logEntries) {
  const body = $('logBody');
  if (!body) return;
  body.innerHTML = entries.map(entry => `
    <div class="log-row padded-row">
      <div class="log-time">${esc(entry.time)}</div>
      <div class="log-pid">PID:${esc(entry.pid)}</div>
      <div class="log-call">${esc(entry.call)}</div>
      <div class="log-args">${esc(entry.args)}</div>
      <span class="tag ${esc(entry.action)}">${esc(entry.action).toUpperCase()}</span>
    </div>
  `).join('');
  setText('logCount', entries.length);
  setText('logBadge', state.logEntries.length);
}

function filterLog() {
  const action = $('filterAction')?.value || 'all';
  const cat = $('filterCat')?.value || 'all';
  let entries = state.logEntries;
  if (action !== 'all') entries = entries.filter(entry => entry.action === action);
  if (cat !== 'all') entries = entries.filter(entry => entry.cat === cat);
  renderLog(entries);
}

function renderProcesses(processes) {
  const el = $('procList');
  if (!el) return;
  el.innerHTML = processes.map(process => `
    <div class="proc-row">
      <div class="proc-name">${esc(process.name)}</div>
      <div class="proc-pid">${esc(process.pid)}</div>
      <div class="bar-cell">
        <div class="mini-bar"><div class="mini-fill" style="width:${Number(process.rate) || 0}%; background:${statusColor(riskClass(process.risk))};"></div></div>
      </div>
      <div class="proc-calls">${Number(process.count || 0).toLocaleString()}</div>
      <div class="risk-cell"><span class="tag ${riskClass(process.risk)}">${esc(process.risk).toUpperCase()}</span></div>
    </div>
  `).join('');
}

function renderPolicies() {
  const el = $('policyList');
  if (!el) return;
  el.innerHTML = state.policies.map((policy, index) => `
    <div class="policy-row">
      <label class="toggle">
        <input type="checkbox" ${policy.on ? 'checked' : ''} onchange="setPolicy(${index}, this.checked)">
        <span class="slider-t"></span>
      </label>
      <div class="policy-text">
        <div class="policy-name">${esc(policy.name)}</div>
        <div class="policy-desc">${esc(policy.desc)}</div>
      </div>
      <div class="policy-level">${esc(policy.level)}</div>
    </div>
  `).join('');
}

async function setPolicy(index, enabled) {
  state.policies[index].on = enabled;
  renderPolicies();
  await api(`/api/policies/${index}`, {
    method: 'PUT',
    body: JSON.stringify({ enabled })
  });
  refreshStatus();
}

function renderSyscalls(filter = state.currentSyscallFilter) {
  state.currentSyscallFilter = filter;
  const el = $('syscallGrid');
  if (!el) return;
  const list = filter === 'all' ? state.syscalls : state.syscalls.filter(syscall => syscall.cat === filter);
  el.innerHTML = list.map(syscall => `
    <div class="syscall-chip ${esc(syscall.status)}-s" onclick="toggleSyscall('${esc(syscall.name)}')" title="NR: ${esc(syscall.num)} | Category: ${esc(syscall.cat)}">
      <div class="sc-name">${esc(syscall.name)}()</div>
      <div class="sc-num">NR ${esc(syscall.num)} | ${esc(syscall.cat)}</div>
      <div class="sc-status" style="color:${statusColor(syscall.status)}">${esc(syscall.status)}</div>
    </div>
  `).join('');
}

function filterSyscalls(value) {
  renderSyscalls(value);
}

async function toggleSyscall(name) {
  const order = ['allowed', 'audited', 'sandboxed', 'blocked'];
  const syscall = state.syscalls.find(item => item.name === name);
  if (!syscall) return;
  syscall.status = order[(order.indexOf(syscall.status) + 1) % order.length];
  renderSyscalls();
  await api(`/api/syscalls/${encodeURIComponent(name)}`, {
    method: 'PUT',
    body: JSON.stringify({ status: syscall.status })
  });
}

function renderAudit() {
  const el = $('auditBody');
  if (!el) return;
  el.innerHTML = state.audit.map(entry => `
    <div class="audit-row">
      <span class="audit-ts">${esc(entry.ts)}</span>
      <span class="audit-pid">PID:${esc(entry.pid)}</span>
      <span class="audit-call">${esc(entry.call)}</span>
      <span class="audit-policy">${esc(entry.policy)}</span>
      <span class="tag ${esc(entry.decision).toLowerCase()}">${esc(entry.decision)}</span>
      <span class="audit-hash">${esc(entry.hash)}</span>
    </div>
  `).join('');
}

function renderThreats(data) {
  if (!data) return;
  setText('threatCritical', data.critical);
  setText('threatHigh', data.high);
  setText('threatMedium', data.medium);
  setText('threatResolved', data.resolved);
  const el = $('threatList');
  if (!el) return;
  const items = data.items || [];
  el.innerHTML = items.length ? items.map(entry => {
    const severity = entry.decision === 'BLOCKED' ? 'high' : 'med';
    const width = entry.decision === 'BLOCKED' ? 92 : 66;
    return `
      <div class="threat-item">
        <div class="threat-icon ${severity}">${entry.decision === 'BLOCKED' ? '!' : 'i'}</div>
        <div>
          <div class="threat-title">${esc(entry.call)} policy decision</div>
          <div class="threat-desc">${esc(entry.policy)} returned ${esc(entry.decision)} for PID ${esc(entry.pid)}.</div>
          <div class="severity-bar">
            <span class="severity-label ${severity}">${esc(entry.decision)}</span>
            <div class="sev-fill"><div class="sev-inner ${severity}" style="width:${width}%;"></div></div>
          </div>
          <div class="threat-time">Detected ${esc(entry.ts)}</div>
        </div>
      </div>
    `;
  }).join('') : '<div class="empty-state">No active threats detected.</div>';
}

function renderCategories(categories = {}) {
  const labels = { file: 'File I/O', net: 'Network', proc: 'Process', mem: 'Memory', ipc: 'IPC' };
  const colors = { file: 'var(--info)', net: 'var(--accent)', proc: 'var(--warn)', mem: '#7F77DD', ipc: 'var(--danger)' };
  const el = $('categoryBars');
  if (!el) return;
  el.innerHTML = Object.entries(labels).map(([key, label]) => {
    const value = categories[key] ?? 0;
    return `
      <div>
        <div class="bar-label"><span>${label}</span><span>${value}%</span></div>
        <div class="mini-bar"><div class="mini-fill" style="width:${value}%; background:${colors[key]};"></div></div>
      </div>
    `;
  }).join('');
}

function renderRecentHighRisk() {
  const el = $('recentRisk');
  if (!el) return;
  const entries = state.logEntries.filter(entry => entry.action !== 'allowed').slice(0, 5);
  el.innerHTML = entries.map(entry => `
    <div class="log-row">
      <div class="log-time">${esc(entry.time)}</div>
      <div class="log-pid">PID:${esc(entry.pid)}</div>
      <div class="log-call">${esc(entry.call)}</div>
      <div class="log-args">${esc(entry.args)}</div>
      <span class="tag ${esc(entry.action)}">${esc(entry.action).toUpperCase()}</span>
    </div>
  `).join('');
}

async function runSandbox() {
  const cmd = $('cmdInput')?.value?.trim() || '';
  const profile = $('sandboxProfile')?.value || 'minimal';
  const timeout = Number($('sandboxTimeout')?.value || 5);
  const box = $('termBox');
  if (!box || !cmd) return;
  box.innerHTML = '<div class="t-line"><span class="t-info">Running inside sandbox...</span></div>';
  try {
    const result = await api('/api/sandbox/run', {
      method: 'POST',
      body: JSON.stringify({ command: cmd, profile, timeout })
    });
    box.innerHTML = '';
    result.lines.forEach((line, index) => {
      setTimeout(() => {
        const row = document.createElement('div');
        row.className = 't-line';
        row.innerHTML = `<span class="${esc(line.cls)}">${esc(line.text)}</span>`;
        box.appendChild(row);
        box.scrollTop = box.scrollHeight;
      }, index * 130);
    });
    refreshAudit();
    refreshStatus();
  } catch (error) {
    box.innerHTML = `<div class="t-line"><span class="t-err">${esc(error.message)}</span></div>`;
  }
}

async function refreshStatus() {
  let status;
  try {
    status = await api('/api/status');
  } catch (error) {
    status = fallback.status;
  }
  setText('s-rate', Number(status.syscall_rate).toLocaleString());
  setText('s-blocked', status.blocked_total);
  setText('s-policies', status.active_policies);
  setText('s-threat', status.threat_score);
  renderCategories(status.categories);
  updateChart(status.syscall_rate);
  document.querySelectorAll('input[name="seclevel"]').forEach(input => {
    input.checked = input.value === status.security_level;
  });
}

async function refreshLog() {
  try {
    state.logEntries = await api('/api/log?limit=120');
  } catch (error) {
    state.logEntries = fallback.log;
  }
  filterLog();
  renderRecentHighRisk();
}

async function refreshProcesses() {
  try {
    renderProcesses(await api('/api/processes'));
  } catch (error) {
    renderProcesses(fallback.processes);
  }
}

async function refreshPolicies() {
  try {
    state.policies = await api('/api/policies');
  } catch (error) {
    state.policies = fallback.policies;
  }
  renderPolicies();
}

async function refreshSyscalls() {
  try {
    state.syscalls = await api('/api/syscalls');
  } catch (error) {
    state.syscalls = fallback.syscalls;
  }
  renderSyscalls();
}

async function refreshAudit() {
  try {
    state.audit = await api('/api/audit?limit=80');
  } catch (error) {
    state.audit = fallback.audit;
  }
  renderAudit();
}

async function refreshThreats() {
  try {
    state.threats = await api('/api/threats');
  } catch (error) {
    state.threats = fallback.threats;
  }
  renderThreats(state.threats);
}

async function setSecurityLevel(level) {
  await api('/api/security-level', {
    method: 'PUT',
    body: JSON.stringify({ level })
  });
  refreshStatus();
}

function connectLiveStream() {
  const target = window.location.protocol === 'file:' || window.location.port === '5000' ? 'ws://127.0.0.1:8000/ws/live' : `${WS}://${window.location.host}/ws/live`;
  state.ws = new WebSocket(target);
  state.ws.onmessage = event => {
    const payload = JSON.parse(event.data);
    if (payload.type !== 'syscall_events') return;
    state.logEntries = [...payload.events, ...state.logEntries].slice(0, 140);
    setText('s-rate', Number(payload.stats.rate).toLocaleString());
    setText('s-blocked', payload.stats.blocked);
    setText('s-threat', payload.stats.threat_score);
    renderCategories(payload.stats.categories);
    filterLog();
    renderRecentHighRisk();
    updateChart(payload.stats.rate);
  };
  state.ws.onerror = () => state.ws.close();
  state.ws.onclose = () => setTimeout(connectLiveStream, 3000);
}

async function init() {
  updateClock();
  initChart();
  await Promise.all([
    refreshStatus(),
    refreshLog(),
    refreshProcesses(),
    refreshPolicies(),
    refreshSyscalls(),
    refreshAudit(),
    refreshThreats()
  ]);
  connectLiveStream();
  setInterval(updateClock, 1000);
  setInterval(refreshStatus, 2500);
  setInterval(refreshProcesses, 3500);
  setInterval(refreshAudit, 5000);
  setInterval(refreshThreats, 5000);
  document.querySelectorAll('input[name="seclevel"]').forEach(input => {
    input.addEventListener('change', event => setSecurityLevel(event.target.value));
  });
}

window.addEventListener('load', init);
