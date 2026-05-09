/**
 * session.js — Session countdown timer
 *
 * Timer is based on LOGIN TIME (session.issuedAt), NOT idle time.
 * This means the timer counts down steadily and NEVER resets just
 * because the user moved their mouse or switched tabs.
 *
 * Idle detection still runs separately: if the user is genuinely
 * inactive for the full timeout period, they are logged out.
 * But the DISPLAY always shows "time since login".
 */

const SESSION_TIMEOUT_KEY = 'cs_session_timeout'; /* seconds */
const LAST_ACTIVITY_KEY   = 'cs_last_activity';
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
  /* Restart the interval with new timeout */
  clearInterval(_sessionInterval);
  _sessionRemaining = _computeRemaining();
  _startInterval();
  showToast(`Session timeout set to ${Math.round(seconds/60)} minutes`, 'success');
}

/** Compute remaining seconds based on login timestamp — never jumps back to 30:00 */
function _computeRemaining() {
  const timeout = getSessionTimeout();
  try {
    const session = JSON.parse(localStorage.getItem('cs_user') || 'null');
    if (session && session.issuedAt) {
      const elapsed = Math.floor((Date.now() - session.issuedAt) / 1000);
      return Math.max(0, timeout - elapsed);
    }
  } catch (e) {}
  /* Fallback: use last-activity key */
  const lastAct = parseInt(localStorage.getItem(LAST_ACTIVITY_KEY) || '0', 10);
  if (lastAct) {
    const elapsed = Math.floor((Date.now() - lastAct) / 1000);
    return Math.max(0, timeout - elapsed);
  }
  return timeout;
}

function initSessionTimer() {
  _sessionRemaining = _computeRemaining();
  if (_sessionRemaining <= 0) { _doAutoLogout(); return; }
  _injectPill();
  _startInterval();
  _registerActivityListeners();
}

/** resetIdleTimer: only updates last-activity for IDLE detection.
 *  Does NOT reset the display timer — that stays based on login time. */
function resetIdleTimer() {
  localStorage.setItem(LAST_ACTIVITY_KEY, Date.now());
  /* No longer resets _sessionRemaining — prevents "30:00 on every mouse move" */
}

function extendSession() {
  document.getElementById('session-warn-modal')?.remove();
  /* Re-issue the session timestamp so the timer resets to full */
  try {
    const session = JSON.parse(localStorage.getItem('cs_user') || 'null');
    if (session) {
      session.issuedAt = Date.now();
      localStorage.setItem('cs_user', JSON.stringify(session));
    }
  } catch(e) {}
  localStorage.setItem(LAST_ACTIVITY_KEY, Date.now());
  _sessionRemaining = getSessionTimeout();
  _updatePillDisplay();
  _updatePillColor();
  _startInterval(); /* restart the interval */
  showToast('Session extended — timer reset to full.', 'success');
}

/* ── Internals ────────────────────────────────────────────── */

function _startInterval() {
  clearInterval(_sessionInterval);
  _sessionInterval = setInterval(() => {
    /* Always recompute from login time so tab-switching stays accurate */
    _sessionRemaining = _computeRemaining();

    if (_sessionRemaining <= 0) {
      clearInterval(_sessionInterval);
      _doAutoLogout();
      return;
    }

    _updatePillDisplay();
    _updatePillColor();

    if (_sessionRemaining === 300) {
      showToast('Session expires in 5 minutes. Click the timer to extend.', 'warning', 7000);
    }
    if (_sessionRemaining === 60) {
      _showSessionWarnModal();
    }
  }, 1000);
}

function _registerActivityListeners() {
  const events = ['mousedown', 'keydown', 'touchstart'];
  /* Only track genuine interactions (not passive scrolls/moves) */
  const throttled = _throttle(() => {
    localStorage.setItem(LAST_ACTIVITY_KEY, Date.now());
  }, 10000); /* update at most every 10 seconds */
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
  pill.title       = 'Session time remaining — click to adjust';
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
            <div class="modal-subtitle">You'll be signed out in 60 seconds</div>
          </div>
        </div>
        <div class="modal-body">
          <div class="info-box warning-box">
            <span class="info-icon">[!]</span>
            <div>Your scan history and connections are preserved. You can sign back in instantly.</div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-outline" onclick="document.getElementById('session-warn-modal').remove(); _doAutoLogout();">Sign Out Now</button>
          <button class="btn btn-gradient" onclick="extendSession()">Extend Session</button>
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
            <div class="modal-title">⏱ Session Duration</div>
            <div class="modal-subtitle">How long until automatic sign-out from login time</div>
          </div>
          <span class="modal-close" onclick="document.getElementById('session-settings-modal').remove()">x</span>
        </div>
        <div class="modal-body">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem">
            ${options.map(o => `
              <button onclick="setSessionTimeout(${o.val}); document.getElementById('session-settings-modal').remove();"
                class="btn ${current===o.val ? 'btn-gradient' : 'btn-outline'}"
                style="justify-content:start;gap:.5rem">
                ${current===o.val ? '✓' : ''} ${o.label}
              </button>`).join('')}
          </div>
          <div class="info-box mt-2">
            <span class="info-icon">ℹ️</span>
            <div>Timer counts down from your login time and won't reset on mouse movement.</div>
          </div>
        </div>
      </div>
    </div>`);
}
