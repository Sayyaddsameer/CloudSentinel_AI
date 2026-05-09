/**
 * session.js — Idle session timeout with configurable duration
 * Default: 30 minutes. Resets on any user interaction.
 * Injects countdown pill into navbar automatically.
 */

const SESSION_TIMEOUT_KEY = 'cs_session_timeout'; /* seconds */
const DEFAULT_TIMEOUT_S   = 1800; /* 30 minutes */

let _sessionInterval  = null;
let _sessionRemaining = DEFAULT_TIMEOUT_S;
let _pillEl           = null;
let _timerEl          = null;

/* ── Public API ───────────────────────────────────────────── */

function getSessionTimeout() {
  return parseInt(localStorage.getItem(SESSION_TIMEOUT_KEY) || DEFAULT_TIMEOUT_S, 10);
}

function setSessionTimeout(seconds) {
  localStorage.setItem(SESSION_TIMEOUT_KEY, seconds);
  resetIdleTimer();
  showToast(`Session timeout set to ${Math.round(seconds/60)} minutes`, 'success');
}

const LAST_ACTIVITY_KEY   = 'cs_last_activity';

function _savedRemaining() {
  const timeout  = getSessionTimeout();
  const lastAct  = parseInt(localStorage.getItem(LAST_ACTIVITY_KEY) || '0', 10);
  if (!lastAct) return timeout;
  const elapsed = Math.floor((Date.now() - lastAct) / 1000);
  return Math.max(0, timeout - elapsed);
}

function initSessionTimer() {
  _sessionRemaining = _savedRemaining();
  if (_sessionRemaining <= 0) { _doAutoLogout(); return; }
  _injectPill();
  _startInterval();
  _registerActivityListeners();
}

function resetIdleTimer() {
  localStorage.setItem(LAST_ACTIVITY_KEY, Date.now());
  _sessionRemaining = getSessionTimeout();
  _updatePillDisplay();
  _updatePillColor();
}

function extendSession() {
  document.getElementById('session-warn-modal')?.remove();
  resetIdleTimer();
  showToast('Session extended — timer reset.', 'success');
}

/* ── Internals ────────────────────────────────────────────── */

function _startInterval() {
  clearInterval(_sessionInterval);
  _sessionInterval = setInterval(() => {
    _sessionRemaining--;

    if (_sessionRemaining <= 0) {
      clearInterval(_sessionInterval);
      _doAutoLogout();
      return;
    }

    _updatePillDisplay();
    _updatePillColor();

    if (_sessionRemaining === 300) {
      showToast('Session expires in 5 minutes. Move your mouse to stay logged in.', 'warning', 7000);
    }
    if (_sessionRemaining === 60) {
      _showSessionWarnModal();
    }
  }, 1000);
}

function _registerActivityListeners() {
  const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click', 'wheel'];
  const throttled = _throttle(resetIdleTimer, 3000);
  events.forEach(ev => document.addEventListener(ev, throttled, { passive: true }));
}

function _throttle(fn, delay) {
  let last = 0;
  return function(...args) {
    const now = Date.now();
    if (now - last > delay) { last = now; fn.apply(this, args); }
  };
}

function _injectPill() {
  const navActions = document.querySelector('.navbar-actions');
  if (!navActions || document.getElementById('session-pill')) return;

  const pill = document.createElement('div');
  pill.id          = 'session-pill';
  pill.className   = 'session-pill';
  pill.title       = 'Session timeout — click to adjust';
  pill.innerHTML   = `<span style="color:var(--text-3);font-size:.85rem">⏱</span><span id="session-timer" class="session-label">—</span>`;
  pill.addEventListener('click', () => openSessionSettings());

  navActions.insertBefore(pill, navActions.firstChild);
  _pillEl  = pill;
  _timerEl = document.getElementById('session-timer');
  _updatePillDisplay();
}

function _updatePillDisplay() {
  if (!_timerEl) _timerEl = document.getElementById('session-timer');
  if (!_timerEl) return;
  const m = Math.floor(_sessionRemaining / 60);
  const s = _sessionRemaining % 60;
  _timerEl.textContent = `${m}:${s.toString().padStart(2, '0')}`;
}

function _updatePillColor() {
  if (!_pillEl) _pillEl = document.getElementById('session-pill');
  if (!_pillEl) return;
  if (_sessionRemaining <= 60) {
    _pillEl.className = 'session-pill danger';
    if (_timerEl) _timerEl.style.color = 'var(--high)';
  } else if (_sessionRemaining <= 300) {
    _pillEl.className = 'session-pill warn';
    if (_timerEl) _timerEl.style.color = 'var(--medium)';
  } else {
    _pillEl.className = 'session-pill';
    if (_timerEl) _timerEl.style.color = 'var(--text-2)';
  }
}

function _showSessionWarnModal() {
  if (document.getElementById('session-warn-modal')) return;
  document.body.insertAdjacentHTML('beforeend', `
    <div class="modal-overlay open" id="session-warn-modal" style="z-index:9999">
      <div class="modal" style="max-width:400px">
        <div class="modal-header">
          <div>
            <div class="modal-title" style="color:var(--medium)">⏱ Session Expiring</div>
            <div class="modal-subtitle">You'll be signed out in 60 seconds due to inactivity</div>
          </div>
        </div>
        <div class="modal-body">
          <div class="info-box warning-box">
            <span class="info-icon">[!]</span>
            <div>Any unsaved work or active connections will be preserved in your history. You can reconnect immediately after signing back in.</div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline" onclick="document.getElementById('session-warn-modal').remove(); _doAutoLogout();">Sign Out Now</button>
          <button class="btn btn-gradient" onclick="extendSession()">Stay Signed In</button>
        </div>
      </div>
    </div>`);
}

function _doAutoLogout() {
  try { clearSession(); } catch(e) {}
  localStorage.removeItem(LAST_ACTIVITY_KEY);
  window.location.href = 'index.html?reason=timeout';
}

function openSessionSettings() {
  /* Renders a quick-select timeout modal */
  if (document.getElementById('session-settings-modal')) {
    document.getElementById('session-settings-modal').classList.add('open');
    return;
  }
  const options = [
    { label: '15 minutes', val: 900  },
    { label: '30 minutes', val: 1800 },
    { label: '1 hour',     val: 3600 },
    { label: '2 hours',    val: 7200 },
    { label: '4 hours',    val: 14400},
    { label: '8 hours',    val: 28800},
  ];
  const current = getSessionTimeout();
  document.body.insertAdjacentHTML('beforeend', `
    <div class="modal-overlay open" id="session-settings-modal">
      <div class="modal" style="max-width:420px">
        <div class="modal-header">
          <div>
            <div class="modal-title">⏱ Session Timeout</div>
            <div class="modal-subtitle">Auto sign-out after this period of inactivity</div>
          </div>
          <span class="modal-close" onclick="document.getElementById('session-settings-modal').remove()">x</span>
        </div>
        <div class="modal-body">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem">
            ${options.map(o => `
              <button onclick="setSessionTimeout(${o.val}); document.getElementById('session-settings-modal').remove();"
                class="btn ${current===o.val ? 'btn-gradient' : 'btn-outline'}"
                style="justify-content:start;gap:.5rem">
                ${current===o.val ? '[active]' : ''} ${o.label}
              </button>`).join('')}
          </div>
          <div class="info-box mt-2">
            <span class="info-icon">ℹ️</span>
            <div>Any connected cloud module will remain connected — only your login session expires. You can reconnect without re-entering cloud credentials.</div>
          </div>
        </div>
      </div>
    </div>`);
}
