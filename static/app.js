// ── State ─────────────────────────────────────────────────────────────────────
let sessionId     = localStorage.getItem('cybrix_session') || null;
let currentFilter = 'ALL';
let allEvents     = [];
let knownIds      = new Set();
let isStreaming   = false;
let threatCount   = 0;

// ── Persist session ───────────────────────────────────────────────────────────
function saveSession(id) {
  sessionId = id;
  if (id) localStorage.setItem('cybrix_session', id);
}

// ── Persist chat ──────────────────────────────────────────────────────────────
function saveChatToStorage() {
  const msgs = document.getElementById('chat-messages');
  if (msgs) localStorage.setItem('cybrix_chat', msgs.innerHTML);
}

function loadChatFromStorage() {
  const saved = localStorage.getItem('cybrix_chat');
  const msgs  = document.getElementById('chat-messages');
  if (saved && msgs) {
    msgs.innerHTML = saved;
    msgs.scrollTop = msgs.scrollHeight;
  }
}

// ── Markdown Renderer ─────────────────────────────────────────────────────────
function renderMD(text) {
  return text
    .replace(/```[a-z]*([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/^#{1,3} (.+)$/gm, '<strong>$1</strong>')
    .replace(/\r?\n/g, '<br>');
}

// ── Token Counter ─────────────────────────────────────────────────────────────
const tokenStats = {
  input:  parseInt(localStorage.getItem('cybrix_tokens_input')  || '0'),
  output: parseInt(localStorage.getItem('cybrix_tokens_output') || '0')
};
function updateTokenDisplay(inputT, outputT) {
  tokenStats.input  += inputT  || 0;
  tokenStats.output += outputT || 0;
  localStorage.setItem('cybrix_tokens_input',  tokenStats.input);
  localStorage.setItem('cybrix_tokens_output', tokenStats.output);
  const cost = ((tokenStats.input * 2 + tokenStats.output * 8) / 1_000_000).toFixed(5);
  const el = document.getElementById('token-counter');
  if (el) el.textContent = `TOKENS: ${tokenStats.input + tokenStats.output} | COST: $${cost} / $10.00`;
}
document.addEventListener('DOMContentLoaded', () => updateTokenDisplay(0, 0));

// ── Clock ─────────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString('en-US', {hour12: false});
}
setInterval(updateClock, 1000);
updateClock();

// ── Filters ───────────────────────────────────────────────────────────────────
function setFilter(f) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  renderEvents();
}

// ── Render Events ─────────────────────────────────────────────────────────────
function severityClass(s) { return `sev-${s}`; }

function formatTime(ts) {
  try { return new Date(ts).toLocaleTimeString('en-US', {hour12: false}); }
  catch { return ts; }
}

function renderEvents() {
  const list        = document.getElementById('events-list');
  const searchInput = document.getElementById('event-search');
  const searchTerm  = searchInput ? searchInput.value.toLowerCase().trim() : '';

  let filtered = currentFilter === 'ALL'
    ? allEvents
    : allEvents.filter(e => e.severity === currentFilter);

  // Apply search filter
  if (searchTerm) {
    filtered = filtered.filter(e =>
      (e.description  || '').toLowerCase().includes(searchTerm) ||
      (e.source_ip    || '').toLowerCase().includes(searchTerm) ||
      (e.event_type   || '').toLowerCase().includes(searchTerm) ||
      (e.source       || '').toLowerCase().includes(searchTerm) ||
      (e.dest_ip      || '').toLowerCase().includes(searchTerm)
    );
  }

  if (filtered.length === 0) {
    list.innerHTML = `<div class="no-events">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>
      </svg>
      ${currentFilter === 'ALL' ? 'AWAITING EVENTS...' : 'NO ' + currentFilter + ' EVENTS'}
    </div>`;
    return;
  }

  list.innerHTML = filtered.map((ev, i) => `
    <div class="event-row ${i === 0 ? 'new-event' : ''}" onclick="askAboutEvent('${ev.id}')">
      <span class="ev-time">${formatTime(ev.timestamp)}</span>
      <span class="ev-sev ${severityClass(ev.severity)}">${ev.severity}</span>
      <span class="ev-type">${ev.event_type}</span>
      <span class="ev-desc" title="${ev.description}">${ev.description}</span>
      <span class="ev-src">${ev.source || ''}</span>
    </div>
  `).join('');
}

// ── Poll Events ───────────────────────────────────────────────────────────────
async function pollEvents() {
  try {
    const res  = await fetch('/api/events?limit=200');
    const data = await res.json();

    let hasNew = false;
    for (const ev of data.events) {
      if (!knownIds.has(ev.id)) { knownIds.add(ev.id); hasNew = true; }
    }
    if (hasNew) { allEvents = data.events; renderEvents(); }

    const s = data.stats;
    document.getElementById('stat-total').textContent    = data.total;
    document.getElementById('stat-critical').textContent = s.critical;
    document.getElementById('stat-high').textContent     = s.high;
    document.getElementById('stat-medium').textContent   = s.medium;
    document.getElementById('stat-ips').textContent      = s.unique_ips;
  } catch(e) { console.error('Poll error:', e); }
}

// ── Poll Source Status ────────────────────────────────────────────────────────
async function pollStatus() {
  try {
    const res  = await fetch('/api/status');
    const data = await res.json();
    // Only update pills that exist in the DOM (static Ubuntu pills)
    for (const [name, status] of Object.entries(data)) {
      const el = document.getElementById(`src-${name}`);
      if (!el) continue; // skip removed pills (cisco, fortigate, syslog_rx)
      el.className = `source-pill ${status.connected ? 'connected' : 'disconnected'}`;
    }
  } catch(e) {}
}

// ── Poll Devices ──────────────────────────────────────────────────────────────
let lastDevicesHash = '';

async function pollDevices() {
  try {
    const res  = await fetch('/api/devices');
    const data = await res.json();
    const container = document.getElementById('dynamic-device-pills');
    if (!container) return;

    // Show all non-ubuntu devices as dynamic pills
    const networkDevices = data.devices.filter(d => d.id !== 'ubuntu-main');

    // Only rebuild if something changed — prevents flicker
    const newHash = JSON.stringify(networkDevices.map(d => d.id + d.connected));
    if (newHash === lastDevicesHash) return;
    lastDevicesHash = newHash;

    container.innerHTML = '';
    // Also fetch source_status for fortigate syslog state
    let sourceStatus = {};
    try {
      const sr = await fetch('/api/status');
      sourceStatus = await sr.json();
    } catch(e) {}

    networkDevices.forEach(d => {
      // For Fortigate: use syslog status not SSH status
      let isConnected = d.connected;
      if (d.type === 'fortigate') {
        isConnected = sourceStatus.fortigate?.connected || d.connected;
      }
      const pill = document.createElement('div');
      pill.className = 'source-pill ' + (isConnected ? 'connected' : 'disconnected');
      pill.title = d.host + ' — ' + (isConnected ? 'Connected (syslog active)' : (d.error || 'Disconnected'));

      const dot = document.createElement('div');
      dot.className = 'source-dot';
      pill.appendChild(dot);

      const label = document.createTextNode(d.name.toUpperCase());
      pill.appendChild(label);

      // X button with real event listener
      const xBtn = document.createElement('span');
      xBtn.className = 'remove-device-btn';
      xBtn.textContent = ' ✕';
      xBtn.title = 'Remove device';
      xBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        removeDevice(d.id);
      });
      pill.appendChild(xBtn);
      container.appendChild(pill);
    });
  } catch(e) {}
}

async function removeDevice(deviceId) {
  if (!confirm(`Remove device ${deviceId}?`)) return;
  try {
    const res  = await fetch(`/api/devices/${deviceId}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.status === 'removed') {
      pollDevices();
    }
  } catch(e) { console.error('Remove device error:', e); }
}

// ── Alert History ────────────────────────────────────────────────────────────
const alertHistory = [];

function addToAlertHistory(item) {
  alertHistory.unshift({
    ...item.alert,
    timestamp: item.timestamp,
    id: item.id,
  });
  // Keep max 50 alerts in history
  if (alertHistory.length > 50) alertHistory.pop();
}

function toggleAlertsModal() {
  const modal = document.getElementById('alerts-modal');
  if (modal.style.display === 'none') {
    modal.style.display = 'flex';
    renderAlertHistory();
  } else {
    modal.style.display = 'none';
  }
}

function closeAlertsModalOutside(e) {
  if (e.target.id === 'alerts-modal') toggleAlertsModal();
}

function renderAlertHistory() {
  const list = document.getElementById('alerts-history-list');
  if (alertHistory.length === 0) {
    list.innerHTML = `<div style="color:var(--text2);font-family:var(--font-mono);font-size:11px;text-align:center;padding:20px;">No alerts yet</div>`;
    return;
  }
  const sevColors = { CRITICAL: '#ff1744', HIGH: '#ff6d00', MEDIUM: '#ffd600' };

  list.innerHTML = '';
  alertHistory.forEach((alert, idx) => {
    const div = document.createElement('div');
    div.className = 'managed-ip-row';
    div.id = `hist-${idx}`;
    div.style.borderLeft = `3px solid ${sevColors[alert.severity] || '#546e7a'}`;
    div.style.position = 'relative';

    // Check if this IP was already remediated (even if popup was dismissed)
    if (!alert._remediated && remediatedIPs[alert.ip]) {
      alert._remediated = remediatedIPs[alert.ip];
    }
    // Get remediation buttons based on device source
    const remButtons = getRemediationButtons(alert);

    div.innerHTML = `
      <div class="managed-ip-info" style="flex:1;">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
          <span style="font-family:var(--font-head);font-size:11px;color:${sevColors[alert.severity] || '#546e7a'};letter-spacing:1px;">
            ⚠ ${(alert.type || '').replace(/_/g,' ')}
          </span>
          <span style="font-family:var(--font-mono);font-size:9px;color:var(--text2);">
            ${alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : ''}
          </span>
        </div>
        <div class="managed-ip-addr">🎯 ${alert.ip}</div>
        <div style="font-family:var(--font-body);font-size:12px;color:var(--text);margin-top:3px;">${alert.detail || ''}</div>
        <div style="font-family:var(--font-mono);font-size:9px;color:var(--orange);margin-top:4px;">KILL CHAIN: ${alert.kill_chain || 'Unknown'}</div>
        <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;align-items:center;">
          <button class="threat-action-btn" 
            onclick="navigator.clipboard.writeText('${(alert.action||'').replace(/'/g,"\'")}').then(()=>this.textContent='✅ COPIED')"
            style="font-size:9px;">COPY CMD</button>
          ${alert._remediated
            ? `<span style="font-family:var(--font-mono);font-size:10px;color:#00e676;background:rgba(0,230,118,0.1);border:1px solid #00e676;padding:2px 8px;border-radius:2px;">✅ ${alert._remediated}</span>`
            : remButtons
          }
          <button class="threat-action-btn" onclick="removeFromHistory(${idx})"
            style="font-size:9px;color:var(--text2);border-color:var(--border);margin-left:auto;">✕ DISMISS</button>
        </div>
        <div class="remediate-status" style="display:none;font-size:10px;margin-top:4px;font-family:var(--font-mono);"></div>
      </div>
    `;
    list.appendChild(div);
  });
}

// Track remediated IPs globally — persists even after popup dismissed
const remediatedIPs = {};

function markAlertRemediated(ip, action) {
  remediatedIPs[ip] = action;
  // Mark all history alerts for this IP
  alertHistory.forEach(alert => {
    if (alert.ip === ip) {
      alert._remediated = action;
    }
  });
  // Re-render if panel is open
  const modal = document.getElementById('alerts-modal');
  if (modal && modal.style.display !== 'none') {
    renderAlertHistory();
  }
}

function removeFromHistory(idx) {
  alertHistory.splice(idx, 1);
  threatCount = Math.max(0, threatCount - 1);
  const badge = document.getElementById('threat-badge');
  if (threatCount === 0) {
    badge.style.display = 'none';
  } else {
    badge.textContent = threatCount;
  }
  renderAlertHistory();
}

function clearAlertHistory() {
  alertHistory.length = 0;
  threatCount = 0;
  const badge = document.getElementById('threat-badge');
  badge.style.display = 'none';
  renderAlertHistory();
}

// ── Poll Threat Alerts ────────────────────────────────────────────────────────
let lastAlertTimestamp = '';

async function pollAlerts() {
  try {
    const url  = lastAlertTimestamp
      ? `/api/alerts/pending?since=${encodeURIComponent(lastAlertTimestamp)}`
      : '/api/alerts/pending';
    const res  = await fetch(url);
    const data = await res.json();
    for (const item of data.alerts) {
      showThreatPopup(item);
      // Track the latest timestamp we've seen
      if (!lastAlertTimestamp || item.timestamp > lastAlertTimestamp) {
        lastAlertTimestamp = item.timestamp;
      }
    }
  } catch(e) {}
}

// ── Active alert cards ────────────────────────────────────────────────────────
const activeCards = {};
const seenAlertIds = new Set(JSON.parse(localStorage.getItem('cybrix_seen_alerts') || '[]'));

function markAlertSeen(alertId) {
  seenAlertIds.add(alertId);
  // Keep only last 100 seen IDs to prevent unbounded growth
  const arr = Array.from(seenAlertIds).slice(-100);
  localStorage.setItem('cybrix_seen_alerts', JSON.stringify(arr));
}

function hasSeenAlert(alertId) {
  return seenAlertIds.has(alertId);
}

// ── Remediation Buttons — device aware ───────────────────────────────────────
function getRemediationButtons(alert) {
  const ip = alert.ip;
  const isFortigate = alert.device_source === 'fortigate' || (alert.detail && alert.detail.includes('Fortigate'));
  const isCisco     = alert.device_source === 'cisco'     || (alert.detail && alert.detail.includes('Cisco'));

  if (isFortigate) {
    // Fortigate: auto-block via paramiko SSH
    const devId = alert.device_id || 'fortigate-main';
    return `
      <button class="threat-action-btn remediate-btn" onclick="autoRemediateDevice('${ip}', 'block', '${devId}', this)">⚡ BLOCK</button>
    `;
  } else if (isCisco) {
    const devId = alert.device_id || 'ubuntu-main';
    return `
      <button class="threat-action-btn remediate-btn" onclick="autoRemediateDevice('${ip}', 'block', '${devId}', this)">⚡ BLOCK</button>
    `;
  } else {
    // Linux/Ubuntu: full auto-remediation
    return `
      <button class="threat-action-btn remediate-btn" onclick="autoRemediate('${ip}', 'block', this)">⚡ BLOCK</button>
      <button class="threat-action-btn ratelimit-btn" onclick="autoRemediate('${ip}', 'ratelimit', this)">⏱ RATE-LIMIT</button>
    `;
  }
}

// ── Show Threat Popup ─────────────────────────────────────────────────────────
function showThreatPopup(item) {
  const { alert } = item;
  const key      = alert.live_counter_key || `${alert.type}_${alert.ip}`;
  const alertId  = item.id || key;

  // Always add to history regardless of dedup
  addToAlertHistory(item);

  // Don't show duplicate popup if already seen
  if (activeCards[key]) return;
  if (hasSeenAlert(alertId)) return;
  markAlertSeen(alertId);

  threatCount++;
  const badge = document.getElementById('threat-badge');
  badge.style.display = 'inline-flex';
  badge.style.cursor  = 'pointer';
  badge.textContent   = threatCount;

  const popup = document.getElementById('alert-popup');
  const card  = document.createElement('div');
  card.className = 'threat-card';
  card.id = `card-${key}`;
  card.innerHTML = `
    <div class="threat-card-header">
      <div class="threat-type">⚠ ${alert.type.replace(/_/g,' ')}</div>
      <div class="threat-sev">${alert.severity}</div>
    </div>
    <div class="threat-ip">🎯 ${alert.ip}</div>
    <div class="threat-detail" id="detail-${key}">${alert.detail}</div>
    <div class="threat-kill-chain">KILL CHAIN: ${alert.kill_chain}</div>
    <div style="display:flex;gap:8px;margin-top:8px;align-items:center;flex-wrap:wrap;">
      <button class="threat-action-btn" onclick="copyCommand('${alert.action}')">COPY CMD</button>
      ${getRemediationButtons(alert)}
      <button class="threat-action-btn" onclick="dismissCard('${key}')">DISMISS</button>
    </div>
    <div class="remediate-status" id="rem-${key}" style="display:none"></div>
  `;

  popup.appendChild(card);
  activeCards[key] = card;
}

function dismissCard(key) {
  const card = activeCards[key];
  if (card) {
    card.style.opacity = '0';
    card.style.transform = 'translateX(20px)';
    card.style.transition = 'all 0.3s';
    setTimeout(() => { card.remove(); delete activeCards[key]; }, 300);
  }
}

// ── AUTO-REMEDIATION ──────────────────────────────────────────────────────────
async function autoRemediateDevice(ip, mode, deviceId, btn) {
  // Same as autoRemediate but with explicit device ID
  btn.disabled = true;
  btn.textContent = '⏳ BLOCKING...';
  btn.style.opacity = '0.6';
  try {
    const res  = await fetch('/api/remediate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ip, device_id: deviceId, mode, hitcount: getRateLimitSetting() })
    });
    const data = await res.json();
    const card      = btn.closest('.threat-card') || btn.closest('.managed-ip-row');
    const statusDiv = card ? card.querySelector('.remediate-status') : null;
    if (data.success) {
      btn.textContent = '✅ BLOCKED';
      btn.style.background = 'rgba(0,230,118,0.15)';
      btn.style.borderColor = '#00e676';
      btn.style.color = '#00e676';
      if (statusDiv) { statusDiv.style.display = 'block'; statusDiv.style.color = '#00e676'; statusDiv.textContent = '✅ ' + data.message; }
      addMessage('assistant', '⚡ AUTO-REMEDIATION EXECUTED\n\nIP **' + ip + '** blocked on ' + deviceId + '.\nCommand: ' + data.command);
      saveChatToStorage();
      pollManagedIPs();
      markAlertRemediated(ip, 'BLOCKED');
    } else {
      btn.textContent = '❌ FAILED';
      btn.style.opacity = '1';
      btn.disabled = false;
      if (statusDiv) { statusDiv.style.display = 'block'; statusDiv.style.color = '#ff1744'; statusDiv.textContent = '❌ ' + data.message; }
    }
  } catch(e) {
    btn.textContent = '❌ ERROR';
    btn.disabled = false;
  }
}

async function autoRemediate(ip, mode, btn) {
  const deviceId = 'ubuntu-main';
  const isBlock  = mode === 'block';

  btn.disabled = true;
  btn.textContent = isBlock ? '⏳ BLOCKING...' : '⏳ LIMITING...';
  btn.style.opacity = '0.6';

  try {
    const res  = await fetch('/api/remediate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ip, device_id: deviceId, mode, hitcount: getRateLimitSetting() })
    });
    const data = await res.json();

    const card = btn.closest('.threat-card') || btn.closest('.managed-ip-row');
    const statusDiv = card ? card.querySelector('.remediate-status') : null;

    if (data.success) {
      btn.textContent = '✅ BLOCKED';
      btn.style.background = 'rgba(0,230,118,0.15)';
      btn.style.borderColor = '#00e676';
      btn.style.color = '#00e676';
      if (statusDiv) {
        statusDiv.style.display = 'block';
        statusDiv.style.color = '#00e676';
        statusDiv.textContent = `✅ ${data.message}`;
      }
      // Add to chat as confirmation
      addMessage('assistant', `⚡ AUTO-REMEDIATION EXECUTED\n\nIP **${ip}** has been automatically blocked.\nCommand: \`${data.command}\`\nDevice: ${deviceId}`);
      saveChatToStorage();
    } else {
      btn.textContent = '❌ FAILED';
      btn.style.opacity = '1';
      if (statusDiv) {
        statusDiv.style.display = 'block';
        statusDiv.style.color = '#ff1744';
        statusDiv.textContent = `❌ ${data.message}`;
      }
    }
  } catch(e) {
    btn.textContent = '❌ ERROR';
    console.error('Remediate error:', e);
  }
}

// ── Poll active alert counters ────────────────────────────────────────────────
async function pollActiveAlerts() {
  try {
    const res  = await fetch('/api/alerts/active');
    const data = await res.json();
    for (const [key, info] of Object.entries(data)) {
      const detailEl = document.getElementById(`detail-${key}`);
      if (detailEl) {
        detailEl.textContent = `${info.count} failed logins in 5 minutes from ${info.ip}`;
      }
    }
  } catch(e) {}
}

// ── Chat Functions ────────────────────────────────────────────────────────────
function addMessage(role, text) {
  const msgs = document.getElementById('chat-messages');
  const div  = document.createElement('div');
  div.className = `msg ${role}`;
  div.innerHTML = `
    <div class="msg-label">${role === 'user' ? 'ANALYST' : 'CYBRIX-AI'}</div>
    <div class="msg-bubble">${text}</div>
  `;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
  saveChatToStorage();
  return div;
}

function addAlertMessage(text) {
  const msgs = document.getElementById('chat-messages');
  const div  = document.createElement('div');
  div.className = 'msg alert-msg';
  div.innerHTML = `
    <div class="msg-label">⚠ AUTOMATED THREAT ALERT</div>
    <div class="msg-bubble">${text}</div>
  `;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function addTyping() {
  const msgs = document.getElementById('chat-messages');
  const div  = document.createElement('div');
  div.className = 'msg assistant';
  div.id = 'typing-indicator';
  div.innerHTML = `<div class="typing"><span></span><span></span><span></span></div>`;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
  return div;
}

// ── Command System ────────────────────────────────────────────────────────────
const COMMANDS = {
  '!help':        'Show all available commands',
  '!block':       '!block <ip> [device_id] — Block IP on device (default: ubuntu-main)',
  '!ratelimit':   '!ratelimit <ip> [limit] [device_id] — Rate limit SSH (Linux only, default 3/min)',
  '!unblock':     '!unblock <ip> — Remove block or rate limit from IP',
  '!updatelimit': '!updatelimit <ip> <new_limit> [device_id] — Change rate limit',
  '!status':      '!status <ip> — Show current rules for an IP',
  '!listblocked': '!listblocked — Show all managed IPs',
  '!listdevices': '!listdevices — Show all connected devices and their IDs',
  '!clearall':    '!clearall — Remove ALL SOC-X managed rules (use with caution)',
};

async function processCommand(input) {
  const parts  = input.trim().split(/\s+/);
  const cmd    = parts[0].toLowerCase();
  const args   = parts.slice(1);

  // Show help
  if (cmd === '!help') {
    const lines = [
      '📋 CYBRIX COMMAND REFERENCE',
      '─────────────────────────────',
      ...Object.entries(COMMANDS).map(([c, d]) => `<code>${c}</code> — ${d}`),
      '─────────────────────────────',
      '<strong>DEVICE IDs:</strong>',
      '<code>ubuntu-main</code> — Ubuntu server (iptables + ufw)',
      '<code>fortigate-main</code> — Fortigate firewall (address object)',
      '<code>cisco-X_X_X_X</code> — Cisco device (ACL CYBRIXBLOCKLIST)',
      '─────────────────────────────',
      '<strong>Examples:</strong>',
      '<code>!block 1.2.3.4</code> — block on Ubuntu (default)',
      '<code>!block 1.2.3.4 fortigate-main</code> — block on Fortigate',
      '<code>!block 1.2.3.4 cisco-10_0_0_1</code> — block on Cisco',
      '<code>!ratelimit 1.2.3.4 5</code> — max 5 SSH/min on Ubuntu',
      '<code>!unblock 1.2.3.4</code> — remove any rule for this IP',
      '<code>!updatelimit 1.2.3.4 10</code> — change rate limit to 10/min',
      '<code>!listblocked</code> — show all managed IPs',
      '<code>!listdevices</code> — show all connected devices',
      '<code>!status 1.2.3.4</code> — show rules for specific IP',
    ];
    appendCommandResult(lines.join('<br>'), 'info');
    return true;
  }

  // List blocked IPs
  if (cmd === '!listblocked') {
    try {
      const res  = await fetch('/api/managed_ips');
      const data = await res.json();
      const ips  = data.managed_ips;
      if (ips.length === 0) {
        appendCommandResult('No managed IPs.', 'info');
        return true;
      }
      const active   = ips.filter(i => i.active);
      const inactive = ips.filter(i => !i.active);
      const lines = [
        `📋 MANAGED IPs (${active.length} active, ${inactive.length} removed)`,
        '─────────────────────────────',
        ...active.map(i =>
          `${i.mode === 'block' ? '🔴' : '🟡'} <strong>${i.ip}</strong> — ${i.mode.toUpperCase()}${i.hitcount ? ` (${i.hitcount}/min)` : ''} on ${i.device_name} since ${new Date(i.timestamp).toLocaleTimeString()}`
        ),
        ...(inactive.length ? ['─────────────────────────────', ...inactive.map(i => `⚪ ${i.ip} — REMOVED`)] : []),
      ];
      appendCommandResult(lines.join('<br>'), 'info');
    } catch(e) {
      appendCommandResult('❌ Failed to fetch managed IPs: ' + e.message, 'error');
    }
    return true;
  }

  // List devices
  if (cmd === '!listdevices') {
    try {
      const res  = await fetch('/api/devices');
      const data = await res.json();
      if (data.devices.length === 0) {
        appendCommandResult('No devices registered.', 'info');
        return true;
      }
      const typeIcons = { cisco_ios: '🔵 Cisco IOS', fortigate: '🟠 Fortigate', linux: '🟢 Linux' };
      const lines = [
        '🖥️ CONNECTED DEVICES',
        '─────────────────────────────',
        ...data.devices.map(d =>
          `${d.connected ? '✅' : '❌'} <strong>${d.id}</strong> — ${typeIcons[d.type] || d.type} @ ${d.host} ${d.connected ? '(online)' : '(offline)'}`
        ),
        '─────────────────────────────',
        'Use device ID with <code>!block</code> to target specific device',
      ];
      appendCommandResult(lines.join('<br>'), 'info');
    } catch(e) {
      appendCommandResult('❌ Error: ' + e.message, 'error');
    }
    return true;
  }

  // Status of specific IP
  if (cmd === '!status') {
    const ip = args[0];
    if (!ip) { appendCommandResult('Usage: !status <ip>', 'error'); return true; }
    try {
      const res  = await fetch('/api/managed_ips');
      const data = await res.json();
      const entry = data.managed_ips.find(i => i.ip === ip);
      if (!entry) {
        appendCommandResult(`ℹ️ <strong>${ip}</strong> — No active rules managed by SOC-X.`, 'info');
        return true;
      }
      const lines = [
        `📊 STATUS: <strong>${ip}</strong>`,
        `Mode: ${entry.mode === 'block' ? '🔴 BLOCKED' : '🟡 RATE-LIMITED'}`,
        `Device: ${entry.device_name}`,
        `Applied: ${new Date(entry.timestamp).toLocaleTimeString()}`,
        entry.hitcount ? `Max connections: ${entry.hitcount}/min` : '',
        `Command: <code>${entry.command}</code>`,
        `Active: ${entry.active ? '✅ Yes' : '❌ Removed'}`,
      ].filter(Boolean);
      appendCommandResult(lines.join('<br>'), 'info');
    } catch(e) {
      appendCommandResult('❌ Error: ' + e.message, 'error');
    }
    return true;
  }

  // Block IP
  if (cmd === '!block') {
    const ip       = args[0];
    const deviceId = args[1] || 'ubuntu-main';
    if (!ip) { appendCommandResult('Usage: !block <ip> [device_id]<br>Example: <code>!block 1.2.3.4 fortigate-main</code>', 'error'); return true; }
    if (!isValidIP(ip)) { appendCommandResult(`❌ Invalid IP: ${ip}`, 'error'); return true; }

    // Show device-specific message
    const deviceMsgs = {
      'ubuntu-main':    'Ubuntu (iptables + ufw)',
      'fortigate-main': 'Fortigate (address object)',
    };
    const devLabel = deviceMsgs[deviceId] || deviceId;
    appendCommandResult(`⏳ Blocking <strong>${ip}</strong> on ${devLabel}...`, 'info');

    try {
      const res  = await fetch('/api/remediate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ip, device_id: deviceId, mode: 'block' })
      });
      const data = await res.json();
      if (data.success) {
        const deviceType = deviceId.includes('fortigate') ? 'Fortigate' :
                           deviceId.includes('cisco')     ? 'Cisco' : 'Linux';
        appendCommandResult(
          `✅ <strong>${ip}</strong> BLOCKED on ${devLabel}<br>` +
          `Device type: ${deviceType}<br>` +
          `<code>${data.command}</code>`,
          'success'
        );
        pollManagedIPs();
      } else {
        appendCommandResult(`❌ Block failed on ${devLabel}: ${data.message}`, 'error');
      }
    } catch(e) {
      appendCommandResult('❌ Error: ' + e.message, 'error');
    }
    return true;
  }

  // Rate limit IP
  if (cmd === '!ratelimit') {
    const ip       = args[0];
    const hitcount = parseInt(args[1]) || 3;
    const deviceId = args[2] || 'ubuntu-main';
    if (!ip) { appendCommandResult('Usage: !ratelimit <ip> [limit] [device_id]', 'error'); return true; }
    if (!isValidIP(ip)) { appendCommandResult(`❌ Invalid IP: ${ip}`, 'error'); return true; }
    appendCommandResult(`⏳ Rate-limiting <strong>${ip}</strong> to ${hitcount}/min on ${deviceId}...`, 'info');
    try {
      const res  = await fetch('/api/remediate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ip, device_id: deviceId, mode: 'ratelimit', hitcount })
      });
      const data = await res.json();
      if (data.success) {
        appendCommandResult(`✅ <strong>${ip}</strong> RATE-LIMITED to ${hitcount} connections/min on ${deviceId}<br><code>${data.command}</code>`, 'success');
        pollManagedIPs();
      } else {
        appendCommandResult(`❌ Rate-limit failed: ${data.message}`, 'error');
      }
    } catch(e) {
      appendCommandResult('❌ Error: ' + e.message, 'error');
    }
    return true;
  }

  // Unblock IP
  if (cmd === '!unblock') {
    const ip = args[0];
    if (!ip) { appendCommandResult('Usage: !unblock <ip>', 'error'); return true; }
    if (!isValidIP(ip)) { appendCommandResult(`❌ Invalid IP: ${ip}`, 'error'); return true; }
    appendCommandResult(`⏳ Removing rules for <strong>${ip}</strong>...`, 'info');
    try {
      const res  = await fetch(`/api/managed_ips/${ip}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        appendCommandResult(`✅ <strong>${ip}</strong> UNBLOCKED — all rules removed<br>${data.message}`, 'success');
        pollManagedIPs();
      } else {
        appendCommandResult(`❌ Unblock failed: ${data.error || data.message}`, 'error');
      }
    } catch(e) {
      appendCommandResult('❌ Error: ' + e.message, 'error');
    }
    return true;
  }

  // Update rate limit
  if (cmd === '!updatelimit') {
    const ip       = args[0];
    const hitcount = parseInt(args[1]);
    const deviceId = args[2] || 'ubuntu-main';
    if (!ip || !hitcount) { appendCommandResult('Usage: !updatelimit <ip> <new_limit> [device_id]', 'error'); return true; }
    if (!isValidIP(ip)) { appendCommandResult(`❌ Invalid IP: ${ip}`, 'error'); return true; }
    if (hitcount < 1 || hitcount > 100) { appendCommandResult('❌ Limit must be between 1 and 100', 'error'); return true; }
    appendCommandResult(`⏳ Updating rate limit for <strong>${ip}</strong> to ${hitcount}/min...`, 'info');
    try {
      // Remove old rule first
      await fetch(`/api/managed_ips/${ip}`, { method: 'DELETE' });
      // Apply new limit
      const res  = await fetch('/api/remediate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ip, device_id: deviceId, mode: 'ratelimit', hitcount })
      });
      const data = await res.json();
      if (data.success) {
        appendCommandResult(`✅ <strong>${ip}</strong> rate limit updated to ${hitcount}/min<br><code>${data.command}</code>`, 'success');
        pollManagedIPs();
      } else {
        appendCommandResult(`❌ Update failed: ${data.message}`, 'error');
      }
    } catch(e) {
      appendCommandResult('❌ Error: ' + e.message, 'error');
    }
    return true;
  }

  // Clear all SOC-X rules
  if (cmd === '!clearall') {
    appendCommandResult('⏳ Removing all SOC-X managed rules...', 'info');
    try {
      const res  = await fetch('/api/managed_ips');
      const data = await res.json();
      const active = data.managed_ips.filter(i => i.active);
      if (active.length === 0) {
        appendCommandResult('ℹ️ No active rules to remove.', 'info');
        return true;
      }
      let removed = 0;
      for (const entry of active) {
        const r = await fetch(`/api/managed_ips/${entry.ip}`, { method: 'DELETE' });
        const d = await r.json();
        if (d.success) removed++;
      }
      appendCommandResult(`✅ Removed ${removed}/${active.length} rules.`, 'success');
      pollManagedIPs();
    } catch(e) {
      appendCommandResult('❌ Error: ' + e.message, 'error');
    }
    return true;
  }

  return false; // not a command
}

function isValidIP(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
}

function appendCommandResult(html, type) {
  const msgs = document.getElementById('chat-messages');
  const div  = document.createElement('div');
  div.className = 'msg cmd-result';
  const colors = { success: '#00e676', error: '#ff1744', info: '#00e5ff' };
  div.innerHTML = `
    <div class="msg-label" style="color:${colors[type] || colors.info}">▶ CYBRIX CMD</div>
    <div class="msg-bubble cmd-bubble" style="border-color:${colors[type] || colors.info}20;background:#020c14;">${html}</div>
  `;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
  saveChatToStorage();
}

async function sendMessage() {
  const input = document.getElementById('chat-input');
  const msg   = input.value.trim();
  if (!msg || isStreaming) return;

  input.value = '';

  // Check if it's a command
  if (msg.startsWith('!')) {
    addMessage('user', msg);
    const handled = await processCommand(msg);
    if (handled) return;
    // Unknown command
    appendCommandResult(`❓ Unknown command: <code>${msg.split(' ')[0]}</code><br>Type <code>!help</code> to see all commands.`, 'error');
    return;
  }

  addMessage('user', msg);

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ message: msg, session_id: sessionId })
    });
    const data = await res.json();
    saveSession(data.session_id);
    await streamResponse();
  } catch(e) {
    addMessage('assistant', 'Error connecting to SOC AI: ' + e.message);
  }
}

async function streamResponse() {
  isStreaming = true;
  document.getElementById('send-btn').disabled = true;

  const typing = addTyping();
  const msgs   = document.getElementById('chat-messages');

  try {
    const res = await fetch(`/api/stream?session_id=${sessionId}`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();

    let aiDiv  = null;
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          const data = JSON.parse(line.slice(6));
          if (data.error) { typing.remove(); addMessage('assistant', 'Error: ' + data.error); break; }
          if (data.token) {
            if (!aiDiv) { typing.remove(); aiDiv = addMessage('assistant', ''); }
            const bubble = aiDiv.querySelector('.msg-bubble');
            bubble.dataset.raw = (bubble.dataset.raw || '') + data.token;
            bubble.innerHTML = renderMD(bubble.dataset.raw);
            msgs.scrollTop = msgs.scrollHeight;
          }
          if (data.done) {
            updateTokenDisplay(data.input_tokens, data.output_tokens);
            saveChatToStorage();
            break;
          }
        } catch(e) {}
      }
    }
  } catch(e) {
    typing.remove();
    addMessage('assistant', 'Stream error: ' + e.message);
  }

  isStreaming = false;
  document.getElementById('send-btn').disabled = false;
}

function askAboutEvent(id) {
  const ev = allEvents.find(e => e.id === id);
  if (!ev) return;
  const msg = `Analyze this event: [${ev.severity}] ${ev.event_type} from ${ev.source_ip} — ${ev.description}`;
  document.getElementById('chat-input').value = msg;
  sendMessage();
}

function handleKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

async function resetChat() {
  if (sessionId) {
    await fetch('/api/reset', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ session_id: sessionId })
    });
  }
  saveSession(null);
  localStorage.removeItem('cybrix_session');
  localStorage.removeItem('cybrix_chat');
  document.getElementById('chat-messages').innerHTML = `
    <div class="msg assistant">
      <div class="msg-label">CYBRIX-AI</div>
      <div class="msg-bubble">⚡ Chat reset. Token cost tracking continues.</div>
    </div>`;
  saveChatToStorage();
  threatCount = 0;
  document.getElementById('threat-badge').style.display = 'none';
}

function copyCommand(cmd) {
  navigator.clipboard.writeText(cmd).then(() => { alert('Command copied: ' + cmd); });
}

// ── Device Modal ──────────────────────────────────────────────────────────────
function toggleDeviceModal() {
  const modal = document.getElementById('device-modal');
  modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
  document.getElementById('add-device-result').style.display = 'none';
}

function closeModalOutside(e) {
  if (e.target.id === 'device-modal') toggleDeviceModal();
}

function updatePlaceholders() {
  const type = document.getElementById('dev-type').value;
  const hint = document.getElementById('dev-hint');
  const secretRow = document.getElementById('secret-row');
  const hints = {
    cisco_ios:  "Cisco IOS: SOC-X SSHes in and runs 'show logging' every 30s. Enter enable secret if required.",
    fortigate:  "Fortigate: Make sure syslog push is configured on the device (config log syslogd setting). Adding here registers credentials for auto-block functionality.",
    linux:      "Linux: SOC-X tails auth.log, ufw.log, syslog and kern.log via SSH in real-time.",
  };
  hint.textContent = hints[type] || '';
  secretRow.style.display = type === 'cisco_ios' ? 'flex' : 'none';
}

async function addDevice() {
  const type   = document.getElementById('dev-type').value;
  const name   = document.getElementById('dev-name').value.trim();
  const host   = document.getElementById('dev-host').value.trim();
  const user   = document.getElementById('dev-user').value.trim();
  const pass   = document.getElementById('dev-pass').value.trim();
  const secret = document.getElementById('dev-secret').value.trim();

  if (!host || !user || !pass) {
    showDeviceResult('❌ Host, username and password are required', false);
    return;
  }

  const btn = document.getElementById('add-dev-btn');
  btn.textContent = 'CONNECTING...';
  btn.disabled = true;

  try {
    const res  = await fetch('/api/devices', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ type, name, host, username: user, password: pass, secret })
    });
    const data = await res.json();

    if (data.status === 'ok') {
      showDeviceResult(`✅ ${data.message}`, true);
      setTimeout(() => { toggleDeviceModal(); pollDevices(); }, 1500);
    } else {
      showDeviceResult(`❌ ${data.error || 'Failed to add device'}`, false);
    }
  } catch(e) {
    showDeviceResult('❌ Connection error: ' + e.message, false);
  }

  btn.textContent = 'CONNECT DEVICE';
  btn.disabled = false;
}

function showDeviceResult(msg, success) {
  const el = document.getElementById('add-device-result');
  el.style.display = 'block';
  el.style.color = success ? '#00e676' : '#ff1744';
  el.textContent = msg;
}

// ── Rate Limit Setting (global, configurable from manage panel) ──────────────
function getRateLimitSetting() {
  return parseInt(localStorage.getItem('cybrix_ratelimit') || '3');
}
function setRateLimitSetting(val) {
  const n = Math.max(1, Math.min(20, parseInt(val) || 3));
  localStorage.setItem('cybrix_ratelimit', n);
  return n;
}

// ── IP Manager ───────────────────────────────────────────────────────────────
function toggleIPManager() {
  const modal = document.getElementById('ip-manager-modal');
  if (modal.style.display === 'none') {
    modal.style.display = 'flex';
    // Load saved rate limit setting
    const input = document.getElementById('rl-global-setting');
    if (input) input.value = getRateLimitSetting();
    refreshManagedIPs();
  } else {
    modal.style.display = 'none';
  }
}

function closeIPManagerOutside(e) {
  if (e.target.id === 'ip-manager-modal') toggleIPManager();
}

// ── IP Manager ───────────────────────────────────────────────────────────────
function toggleIPManager() {
  const modal = document.getElementById('ip-manager-modal');
  if (modal.style.display === 'none') {
    modal.style.display = 'flex';
    // Load saved rate limit setting
    const input = document.getElementById('rl-global-setting');
    if (input) input.value = getRateLimitSetting();
    refreshManagedIPs();
  } else {
    modal.style.display = 'none';
  }
}

function closeIPManagerOutside(e) {
  if (e.target.id === 'ip-manager-modal') toggleIPManager();
}

async function refreshManagedIPs() {
  try {
    const res  = await fetch('/api/managed_ips');
    const data = await res.json();
    const list = document.getElementById('managed-ip-list');
    const ips  = data.managed_ips;

    // Update count badge
    const active = ips.filter(i => i.active);
    const countEl = document.getElementById('managed-ip-count');
    if (active.length > 0) {
      countEl.style.display = 'inline';
      countEl.textContent = active.length;
    } else {
      countEl.style.display = 'none';
    }

    if (ips.length === 0) {
      list.innerHTML = `<div style="color:var(--text2);font-family:var(--font-mono);font-size:11px;text-align:center;padding:20px;">No managed IPs yet</div>`;
      return;
    }

    list.innerHTML = ips.map(entry => `
      <div class="managed-ip-row">
        <div class="managed-ip-info">
          <div class="managed-ip-addr">${entry.ip}</div>
          <div class="managed-ip-meta">
            <span class="managed-ip-mode ${entry.mode}">${entry.mode === 'block' ? '🔴 BLOCKED' : '🟡 RATE-LIMITED'}</span>
            <span class="managed-ip-device">${entry.device_name}</span>
            <span class="managed-ip-time">${new Date(entry.timestamp).toLocaleTimeString()}</span>
          </div>
          <div class="managed-ip-cmd">${entry.command}</div>
          ${entry.active && entry.mode === 'ratelimit' ? `
            <div style="display:flex;align-items:center;gap:8px;margin-top:6px;">
              <span style="font-family:var(--font-mono);font-size:10px;color:var(--text2);">MAX CONNECTIONS/60s:</span>
              <input type="number" min="1" max="20" value="${entry.hitcount || 3}"
                id="rl-${entry.ip.replace(/\./g,'_')}"
                style="width:44px;background:var(--panel);border:1px solid var(--yellow);color:var(--yellow);
                       font-family:var(--font-mono);font-size:11px;text-align:center;padding:2px 4px;border-radius:2px;outline:none;">
              <button class="threat-action-btn" onclick="updateRateLimit('${entry.ip}','${entry.device_id}',this)"
                style="color:var(--yellow);border-color:var(--yellow);padding:2px 8px;">
                APPLY
              </button>
            </div>
          ` : ''}
        </div>
        <div class="managed-ip-actions">
          <button class="threat-action-btn" onclick="unblockIP('${entry.ip}', this)" style="color:var(--green);border-color:var(--green)">UNBLOCK</button>
        </div>
      </div>
    `).join('');
  } catch(e) {
    console.error('Managed IPs error:', e);
  }
}

async function updateRateLimit(ip, deviceId, btn) {
  const safeIp = ip.replace(/\./g, '_');
  const input  = document.getElementById(`rl-${safeIp}`);
  const hitcount = Math.max(1, Math.min(20, parseInt(input?.value) || 3));

  btn.disabled = true;
  btn.textContent = '⏳...';

  try {
    // First unblock current rule, then re-apply with new hitcount
    await fetch(`/api/managed_ips/${ip}`, { method: 'DELETE' });
    const res  = await fetch('/api/remediate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ip, device_id: deviceId, mode: 'ratelimit', hitcount })
    });
    const data = await res.json();
    if (data.success) {
      btn.textContent = '✅ DONE';
      btn.style.color = 'var(--green)';
      btn.style.borderColor = 'var(--green)';
      setTimeout(() => refreshManagedIPs(), 800);
    } else {
      btn.textContent = '❌ FAIL';
      btn.disabled = false;
    }
  } catch(e) {
    btn.textContent = '❌ ERR';
    btn.disabled = false;
  }
}

async function unblockIP(ip, btn) {
  btn.disabled = true;
  btn.textContent = '⏳...';
  try {
    const res  = await fetch(`/api/managed_ips/${ip}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      btn.textContent = '✅ DONE';
      btn.style.color = 'var(--text2)';
      btn.style.borderColor = 'var(--border)';
      refreshManagedIPs();
    } else {
      btn.textContent = '❌ FAILED';
      btn.disabled = false;
    }
  } catch(e) {
    btn.textContent = '❌ ERROR';
    btn.disabled = false;
  }
}

// Poll managed IPs count badge every 10s
async function pollManagedIPs() {
  try {
    const res  = await fetch('/api/managed_ips');
    const data = await res.json();
    const active = data.managed_ips.filter(i => i.active);
    const countEl = document.getElementById('managed-ip-count');
    if (active.length > 0) {
      countEl.style.display = 'inline';
      countEl.textContent = active.length;
    } else {
      countEl.style.display = 'none';
    }
  } catch(e) {}
}

// ── Start Polling ─────────────────────────────────────────────────────────────
loadChatFromStorage();
pollEvents();
pollStatus();
pollDevices();

setInterval(pollEvents,       2000);
setInterval(pollStatus,       5000);
setInterval(pollAlerts,       3000);
setInterval(pollActiveAlerts, 2000);
setInterval(pollDevices,      8000);
setInterval(pollManagedIPs,   10000);