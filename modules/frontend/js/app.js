/**
 * app.js — Shared utilities: navigation, toasts, chatbot, API calls,
 *           scan history, risk card renderer, auto-refresh
 *
 * Depends on: js/env.js, js/auth.js, js/session.js (loaded before this file)
 */

/* ── Constants ────────────────────────────────────────────── */
const API_BASE = window.ENV_API_URL || '';

/* ── Page initializer ─────────────────────────────────────── */
function initPage(moduleName) {
  const user = requireAuth();
  if (!user) return;

  /* Populate nav user info */
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  set('nav-user-name',  user.name);
  set('nav-user-avatar', user.initials);
  set('dd-user-name',   user.name);
  set('dd-user-email',  user.email);

  /* Inject theme toggle into navbar */
  const navActions = document.querySelector('.navbar-actions');
  if (navActions && !document.getElementById('theme-toggle')) {
    const themeBtn       = document.createElement('button');
    themeBtn.id          = 'theme-toggle';
    themeBtn.className   = 'theme-toggle-btn';
    const currentTheme   = document.documentElement.getAttribute('data-theme') || 'dark';
    themeBtn.textContent = currentTheme === 'dark' ? 'Light' : 'Dark';
    themeBtn.title       = currentTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
    themeBtn.addEventListener('click', toggleTheme);
    navActions.insertBefore(themeBtn, navActions.firstChild);
  }

  /* User dropdown toggle */
  const userMenu = document.getElementById('user-menu');
  const dropdown = document.getElementById('user-dropdown');
  if (userMenu && dropdown) {
    userMenu.addEventListener('click', e => { e.stopPropagation(); dropdown.classList.toggle('open'); });
    document.addEventListener('click', () => dropdown.classList.remove('open'));
  }

  /* Logout */
  document.getElementById('logout-btn')?.addEventListener('click', logout);

  /* Session timer */
  if (typeof initSessionTimer === 'function') initSessionTimer();

  /* Chatbot */
  initChatbot(moduleName);

  /* Toast container */
  if (!document.getElementById('toast-container')) {
    const tc = document.createElement('div');
    tc.id = 'toast-container';
    document.body.appendChild(tc);
  }
}

/* ── Toast ────────────────────────────────────────────────── */
function showToast(msg, type = 'info', duration = 4000) {
  let tc = document.getElementById('toast-container');
  if (!tc) { tc = document.createElement('div'); tc.id = 'toast-container'; document.body.appendChild(tc); }
  const icons = { success: '[ok]', error: '[!]', warning: '[warn]', info: '[i]' };
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${icons[type] || '[i]'}</span><span>${msg}</span>`;
  tc.appendChild(t);
  setTimeout(() => {
    t.style.opacity   = '0';
    t.style.transform = 'translateX(110%)';
    t.style.transition = 'all .3s ease';
    setTimeout(() => t.remove(), 320);
  }, duration);
}

/* ── Rate limiter (client-side — defence in depth only) ───── */
function checkRateLimit(email) {
  const key  = `cs_rl_${btoa(email).slice(0, 12)}`;
  const data = JSON.parse(localStorage.getItem(key) || '{"fails":0,"lockedUntil":0}');
  if (data.lockedUntil > Date.now()) {
    const remaining = Math.ceil((data.lockedUntil - Date.now()) / 1000);
    throw new Error(`LOCKED:${remaining}`);
  }
  return data;
}

function recordLoginFailure(email) {
  const key  = `cs_rl_${btoa(email).slice(0, 12)}`;
  const data = JSON.parse(localStorage.getItem(key) || '{"fails":0,"lockedUntil":0}');
  data.fails++;
  const lockDurations = { 3: 60 * 1000, 5: 5 * 60 * 1000, 10: 30 * 60 * 1000 };
  const lockMs = Object.entries(lockDurations).reverse()
    .find(([n]) => data.fails >= parseInt(n))?.[1] || 0;
  if (lockMs) data.lockedUntil = Date.now() + lockMs;
  localStorage.setItem(key, JSON.stringify(data));
  return data.fails;
}

function clearLoginFailures(email) {
  localStorage.removeItem(`cs_rl_${btoa(email).slice(0, 12)}`);
}

/* ── API helpers ──────────────────────────────────────────── */
async function apiCall(path, method = 'GET', body = null) {
  if (!API_BASE) throw new Error('API is not configured. Set ENV_API_URL in your deployment environment.');
  const opts = {
    method,
    headers: {
      'Content-Type':  'application/json',
      'Authorization': getToken() || '',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(API_BASE + path, opts);
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

async function fetchRisks(module) {
  if (!API_BASE) throw new Error('API is not configured.');
  const res = await fetch(`${API_BASE}/risks?module=${module}`, {
    headers: { Authorization: getToken() || '' },
  });
  if (!res.ok) throw new Error(`Failed to fetch risks (${res.status})`);
  const data = await res.json();
  return Array.isArray(data) ? data : (data.risks || []);
}

async function triggerScan(module) {
  if (!API_BASE) throw new Error('API is not configured.');

  // Pick up cross-account role ARN stored when the user connected the account
  const conn        = getConnections(module);
  const roleArn     = conn?.aws?.roleArn || null;
  const scanPayload = roleArn ? { targetRoleArn: roleArn } : {};

  const res = await fetch(`${API_BASE}/scan-${module}`, {
    method:  'POST',
    headers: { Authorization: getToken() || '', 'Content-Type': 'application/json' },
    body:    JSON.stringify(scanPayload),
  });
  if (!res.ok) throw new Error(`Scan failed (${res.status})`);
  return res.json();
}


/* ── Scan History ─────────────────────────────────────────── */
const MAX_HISTORY = 30;

function recordScanToHistory(module, risks) {
  const key     = `cs_history_${module}`;
  const history = JSON.parse(localStorage.getItem(key) || '[]');
  history.unshift({
    timestamp: new Date().toISOString(),
    total:     risks.length,
    high:      risks.filter(r => r.riskPriority === 'High').length,
    medium:    risks.filter(r => r.riskPriority === 'Medium').length,
    low:       risks.filter(r => r.riskPriority === 'Low').length,
    risks:     risks.slice(0, 10),
    module,
  });
  if (history.length > MAX_HISTORY) history.splice(MAX_HISTORY);
  localStorage.setItem(key, JSON.stringify(history));
  return history[0];
}

function getModuleHistory(module, limit = 10) {
  return JSON.parse(localStorage.getItem(`cs_history_${module}`) || '[]').slice(0, limit);
}

function getAllHistory(limit = 30) {
  const modules = ['cloud-infra', 'devops', 'fullstack', 'data-eng', 'mobile'];
  const all = modules.flatMap(m => getModuleHistory(m, 20));
  return all.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, limit);
}

function getRiskTrend(module) {
  const history = getModuleHistory(module, 2);
  if (history.length < 2) return null;
  const diff = history[0].total - history[1].total;
  return { diff, direction: diff > 0 ? 'up' : diff < 0 ? 'down' : 'same' };
}

/* ── Auto-refresh (poll every N minutes) ──────────────────── */
const _refreshTimers = {};

function startAutoRefresh(module, onNewRisks, intervalMs = 5 * 60 * 1000) {
  stopAutoRefresh(module);
  _refreshTimers[module] = setInterval(async () => {
    try {
      const risks   = await fetchRisks(module);
      const history = getModuleHistory(module, 1);
      const prev    = history[0]?.total ?? null;

      if (prev !== null && risks.length > prev) {
        showToast(`${risks.length - prev} new risk(s) detected in ${formatModuleName(module)}`, 'warning', 8000);
        showNotificationBadge(module);
        if (typeof onNewRisks === 'function') onNewRisks(risks);
      }

      if (risks.filter(r => r.riskPriority === 'High').length > 0) {
        triggerSnsAlert(module, risks.filter(r => r.riskPriority === 'High'));
      }
    } catch { /* silent background refresh */ }
  }, intervalMs);
}

function stopAutoRefresh(module) {
  if (_refreshTimers[module]) {
    clearInterval(_refreshTimers[module]);
    delete _refreshTimers[module];
  }
}

function showNotificationBadge(module) {
  const moduleMap = {
    'cloud-infra': 'mod-cloud',
    'devops':      'mod-devops',
    'fullstack':   'mod-fullstack',
    'data-eng':    'mod-data',
    'mobile':      'mod-mobile',
  };
  const card = document.getElementById(moduleMap[module]);
  if (!card) return;
  const top = card.querySelector('.module-card-top');
  if (top && !top.querySelector('.notif-badge')) {
    const badge     = document.createElement('span');
    badge.className = 'notif-badge';
    badge.title     = 'New risks detected';
    top.style.position = 'relative';
    top.appendChild(badge);
  }
}

function formatModuleName(module) {
  const names = {
    'cloud-infra': 'Cloud Infrastructure',
    'devops':      'DevOps',
    'fullstack':   'Full-Stack',
    'data-eng':    'Data Engineering',
    'mobile':      'Mobile Backend',
  };
  return names[module] || module;
}

/* ── Chatbot ──────────────────────────────────────────────── */
let chatModule = 'cloud-infra';

const CHAT_CHIPS = [
  'Highest risk right now?',
  'How do I fix this?',
  'Compare priorities',
  'Best security practice?',
];

function initChatbot(module) {
  chatModule = module || 'cloud-infra';
  const fab   = document.getElementById('chatbot-fab');
  const panel = document.getElementById('chatbot-panel');
  const close = document.getElementById('chatbot-close');
  const input = document.getElementById('chatbot-input');
  const send  = document.getElementById('chatbot-send');
  if (!fab || !panel) return;

  /* Update header subtitle with live module name */
  const headerSub = panel.querySelector('.chatbot-header-sub');
  if (headerSub) headerSub.textContent = 'Online \u00b7 ' + formatModuleName(chatModule);

  /* Inject suggestion chips before the messages area if not already present */
  const msgs = document.getElementById('chatbot-messages');
  if (msgs && !panel.querySelector('.chatbot-chips')) {
    const chips = document.createElement('div');
    chips.className = 'chatbot-chips';
    chips.innerHTML = CHAT_CHIPS.map(c => `<button class="chatbot-chip">${c}</button>`).join('');
    panel.insertBefore(chips, msgs);
    chips.querySelectorAll('.chatbot-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        if (input) {
          input.value = btn.textContent;
          sendChat();   // auto-send immediately on chip click
        }
      });
    });
  }

  fab.addEventListener('click', () => { panel.classList.add('open'); fab.style.display = 'none'; input?.focus(); });
  close?.addEventListener('click', () => { panel.classList.remove('open'); fab.style.display = 'flex'; });
  send?.addEventListener('click', () => sendChat());
  input?.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } });

  appendBotMessage('Hi! I\'m CloudSentinel AI. Ask me about your detected risks, remediation steps, or what to prioritize first. Use the chips above for quick questions!');
}

async function sendChat() {
  const input = document.getElementById('chatbot-input');
  const q = input?.value.trim();
  if (!q) return;
  input.value = '';
  appendUserMessage(q);
  const typingId = appendTyping();
  try {
    if (!API_BASE) throw new Error('API not configured. Set ENV_API_URL in env.js.');
    const resp = await fetch(`${API_BASE}/chat`, {
      method:  'POST',
      headers: { Authorization: getToken() || '', 'Content-Type': 'application/json' },
      body:    JSON.stringify({ question: q, module: chatModule }),
    });
    if (!resp.ok) throw new Error(`Chat API error ${resp.status}`);
    const data = await resp.json();
    removeTyping(typingId);
    appendBotMessage(data.answer || 'No response from AI assistant.');
  } catch (err) {
    removeTyping(typingId);
    appendBotMessage('\u26a0\ufe0f ' + escHtml(err.message) + '. Please ensure the API is configured and reachable.');
  }
}

function appendUserMessage(text) {
  const msgs = document.getElementById('chatbot-messages');
  if (!msgs) return;
  msgs.insertAdjacentHTML('beforeend', `<div class="chat-msg user"><div class="chat-bubble">${escHtml(text)}</div></div>`);
  msgs.scrollTop = msgs.scrollHeight;
}

function appendBotMessage(text) {
  const msgs = document.getElementById('chatbot-messages');
  if (!msgs) return;
  // Render basic markdown: **bold**, `code`, line breaks, numbered lists
  const html = text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')  // escape HTML first
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')                    // **bold**
    .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.1);padding:1px 4px;border-radius:3px">$1</code>') // `code`
    .replace(/^(\d+\.\s)/gm, '<span style="color:var(--accent)">$1</span>')  // numbered list
    .replace(/\n/g, '<br>');                                              // newlines
  msgs.insertAdjacentHTML('beforeend', `<div class="chat-msg bot"><div class="chat-avatar">CS</div><div class="chat-bubble" style="white-space:normal;line-height:1.6">${html}</div></div>`);
  msgs.scrollTop = msgs.scrollHeight;
}

function appendTyping() {
  const msgs = document.getElementById('chatbot-messages');
  const id   = 'typing-' + Date.now();
  msgs?.insertAdjacentHTML('beforeend',
    `<div class="chat-msg bot" id="${id}"><div class="chat-avatar">CS</div><div class="chat-typing"><span></span><span></span><span></span></div></div>`);
  msgs && (msgs.scrollTop = msgs.scrollHeight);
  return id;
}

function removeTyping(id) { document.getElementById(id)?.remove(); }

/* ── Risk card renderer ───────────────────────────────────── */
function renderRiskCards(risks, containerId, filterPriority = 'All') {
  const container = document.getElementById(containerId);
  if (!container) return;
  const filtered = filterPriority === 'All' ? risks : risks.filter(r => r.riskPriority === filterPriority);
  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">[clear]</div>
        <div class="empty-state-title">${filterPriority === 'All' ? 'No risks detected' : `No ${filterPriority} priority risks`}</div>
        <div class="empty-state-desc">${filterPriority === 'All' ? 'Your environment looks clean.' : 'Try another filter.'}</div>
      </div>`;
    return;
  }
  container.innerHTML = filtered.map((r, i) => `
    <div class="risk-card priority-${r.riskPriority.toLowerCase()}" style="animation-delay:${i * 0.05}s">
      <div class="risk-card-header">
        <div>
          <div class="risk-card-title">${escHtml(r.riskType)}</div>
          <div class="risk-card-resource"><span class="text-muted">Resource:</span> ${escHtml(r.resource)} &mdash; <strong>${escHtml(r.resourceName)}</strong></div>
        </div>
        <span class="badge badge-${r.riskPriority.toLowerCase()} badge-dot">${r.riskPriority}</span>
      </div>
      <div class="risk-card-reason">${escHtml(r.riskReason)}</div>
      <div class="risk-card-footer">
        <button class="risk-expand-btn" onclick="toggleRiskDetail(this,'risk-detail-${containerId}-${i}')">View details &amp; remediation</button>
        <span class="text-xs text-dimmer">${escHtml(r.region || 'us-east-1')}</span>
      </div>
      <div class="risk-details" id="risk-detail-${containerId}-${i}">
        <div>
          <div class="risk-details-label">Remediation Steps</div>
          <div class="remediation-steps">
            ${(r.remediationSteps || []).map((s, j) => `<div class="remediation-step"><span class="step-num">${j + 1}</span><span>${escHtml(s)}</span></div>`).join('')}
          </div>
        </div>
        ${(r.alternativeSolutions || []).length ? `
          <div>
            <div class="risk-details-label">Alternative Solutions</div>
            <div class="remediation-steps">
              ${r.alternativeSolutions.map(s => `<div class="remediation-step"><span class="step-num" style="background:var(--purple-dim);color:var(--purple)">&#8226;</span><span>${escHtml(s)}</span></div>`).join('')}
            </div>
          </div>` : ''}
        <div class="ai-explanation-box">
          <span class="ai-icon">AI</span>
          <span>${r.aiExplanation ? escHtml(r.aiExplanation) : '<em>AI explanation generates on next scan cycle via Amazon Bedrock.</em>'}</span>
        </div>
      </div>
    </div>`).join('');
}

function toggleRiskDetail(btn, id) {
  const d = document.getElementById(id);
  if (!d) return;
  const open = d.classList.toggle('open');
  btn.textContent = open ? 'Hide details' : 'View details & remediation';
}

function updateStats(risks) {
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  set('stat-total',  risks.length);
  set('stat-high',   risks.filter(r => r.riskPriority === 'High').length);
  set('stat-medium', risks.filter(r => r.riskPriority === 'Medium').length);
  set('stat-low',    risks.filter(r => r.riskPriority === 'Low').length);
}

/* ── Connection helpers ───────────────────────────────────── */
function getConnections(module) { try { return JSON.parse(localStorage.getItem(`cs_conn_${module}`) || '{}'); } catch { return {}; } }
function setConnection(module, provider, data) { const c = getConnections(module); c[provider] = data; localStorage.setItem(`cs_conn_${module}`, JSON.stringify(c)); }
function removeConnection(module, provider) { const c = getConnections(module); delete c[provider]; localStorage.setItem(`cs_conn_${module}`, JSON.stringify(c)); }

/* ── SNS alert stub (implemented server-side in notification Lambda) */
async function triggerSnsAlert(module, highRisks) {
  if (!API_BASE) return;
  try {
    await fetch(`${API_BASE}/notify`, {
      method:  'POST',
      headers: { Authorization: getToken() || '', 'Content-Type': 'application/json' },
      body:    JSON.stringify({ module, highCount: highRisks.length }),
    });
  } catch { /* non-critical */ }
}

/* ── Utility ──────────────────────────────────────────────── */
function escHtml(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    if (btn) { btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = 'Copy', 1800); }
    showToast('Copied to clipboard', 'success');
  });
}
