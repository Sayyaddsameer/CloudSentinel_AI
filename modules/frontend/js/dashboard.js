/**
 * dashboard.js -- Dashboard module logic
 *
 * Fetches live risk data for all modules from the production API,
 * renders module cards with connection status and risk trends,
 * and populates the recent activity feed from local scan history.
 *
 * Depends on: js/env.js, js/auth.js, js/app.js, js/session.js
 */

const MODULE_KEYS = ['cloud-infra', 'devops', 'fullstack', 'data-eng', 'mobile'];

const BADGE_IDS = {
  'cloud-infra': 'badge-cloud',
  'devops':      'badge-devops',
  'fullstack':   'badge-fullstack',
  'data-eng':    'badge-data',
  'mobile':      'badge-mobile',
};

const COUNT_IDS = {
  'cloud-infra': 'risk-count-cloud',
  'devops':      'risk-count-devops',
  'fullstack':   'risk-count-fullstack',
  'data-eng':    'risk-count-data',
  'mobile':      'risk-count-mobile',
};

const TREND_IDS = {
  'cloud-infra': 'trend-cloud',
  'devops':      'trend-devops',
  'fullstack':   'trend-fullstack',
  'data-eng':    'trend-data',
  'mobile':      'trend-mobile',
};

const MOD_NAMES = {
  'cloud-infra': 'Cloud Infrastructure',
  'devops':      'DevOps',
  'fullstack':   'Full-Stack',
  'data-eng':    'Data Engineering',
  'mobile':      'Mobile Backend',
};

const MOD_ICONS = {
  'cloud-infra': '[cloud]',
  'devops':      '[devops]',
  'fullstack':   '[api]',
  'data-eng':    '[data]',
  'mobile':      '[mobile]',
};

/* ── Init ─────────────────────────────────────────────────── */
function initDashboard() {
  const user = requireAuth();
  if (!user) return;

  const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  set('nav-user-avatar', user.initials);
  set('nav-user-name',   user.name);
  set('dd-user-name',    user.name);
  set('dd-user-email',   user.email);
  set('welcome-avatar',  user.initials);

  document.getElementById('logout-btn')?.addEventListener('click', logout);

  /* User dropdown */
  const menu = document.getElementById('user-menu');
  const dd   = document.getElementById('user-dropdown');
  menu?.addEventListener('click', e => { e.stopPropagation(); dd.classList.toggle('open'); });
  document.addEventListener('click', () => dd?.classList.remove('open'));

  /* Theme toggle (dashboard page does not use initPage so inject manually) */
  const navActions = document.querySelector('.navbar-actions');
  if (navActions && !document.getElementById('theme-toggle')) {
    const btn        = document.createElement('button');
    btn.id           = 'theme-toggle';
    btn.className    = 'theme-toggle-btn';
    const th         = document.documentElement.getAttribute('data-theme') || 'dark';
    btn.textContent  = th === 'dark' ? 'Light' : 'Dark';
    btn.addEventListener('click', toggleTheme);
    navActions.insertBefore(btn, navActions.firstChild);
  }

  /* Session timer */
  if (typeof initSessionTimer === 'function') initSessionTimer();

  /* Welcome greeting */
  const hour  = new Date().getHours();
  const greet = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
  set('welcome-greeting', `${greet}, ${user.name.split(' ')[0]}`);

  /* Module cards */
  let totalRisks = 0, highCount = 0, connected = 0;

  MODULE_KEYS.forEach(mod => {
    const conns       = getConnections(mod);
    const isConnected = Object.keys(conns).length > 0;
    const badge       = document.getElementById(BADGE_IDS[mod]);

    if (isConnected) {
      connected++;
      if (badge) { badge.textContent = 'Connected'; badge.className = 'module-card-badge badge-connected'; }

      /* Load cached risk counts from history for offline-first display */
      const latestHistory = getModuleHistory(mod, 1)[0];
      if (latestHistory) {
        totalRisks += latestHistory.total;
        highCount  += latestHistory.high;
        const el = document.getElementById(COUNT_IDS[mod]);
        if (el) el.textContent = `${latestHistory.total} risk${latestHistory.total !== 1 ? 's' : ''}`;
      } else {
        const el = document.getElementById(COUNT_IDS[mod]);
        if (el) el.textContent = 'No scan yet';
      }

      /* Risk trend */
      const trend   = getRiskTrend(mod);
      const trendEl = document.getElementById(TREND_IDS[mod]);
      if (trendEl && trend) {
        const { diff, direction } = trend;
        const labels = { up: `+${diff} since last`, down: `-${Math.abs(diff)} since last`, same: 'No change' };
        trendEl.className   = `risk-trend ${direction}`;
        trendEl.textContent = labels[direction];
      }
    } else {
      const el = document.getElementById(COUNT_IDS[mod]);
      if (el) el.textContent = 'Connect to scan';
    }
  });

  set('ws-total',     connected ? totalRisks : '--');
  set('ws-high',      connected ? highCount  : '--');
  set('ws-connected', `${connected}/${MODULE_KEYS.length}`);

}

/* ── Start ────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', initDashboard);

/* ── Dashboard Chatbot with platform-level chips ─────────── */
const DASHBOARD_CHIPS = [
  'What does CloudSentinel do?',
  'Which module should I use first?',
  'How do I connect my AWS account?',
  'What risks can you detect?',
];

function initDashboardChatbot() {
  const fab   = document.getElementById('chatbot-fab');
  const panel = document.getElementById('chatbot-panel');
  const close = document.getElementById('chatbot-close');
  const input = document.getElementById('chatbot-input');
  const send  = document.getElementById('chatbot-send');
  if (!fab || !panel) return;

  /* Wire up open/close */
  fab.addEventListener('click',   () => { panel.classList.add('open');    fab.style.display = 'none'; input?.focus(); });
  close?.addEventListener('click',() => { panel.classList.remove('open'); fab.style.display = 'flex'; });
  send?.addEventListener('click', () => sendChat());
  input?.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } });

  /* Inject dashboard-specific chips */
  const msgs = document.getElementById('chatbot-messages');
  if (msgs && !panel.querySelector('.chatbot-chips')) {
    const chips = document.createElement('div');
    chips.className = 'chatbot-chips';
    chips.innerHTML = DASHBOARD_CHIPS.map(c => `<button class="chatbot-chip">${c}</button>`).join('');
    panel.insertBefore(chips, msgs);
    chips.querySelectorAll('.chatbot-chip').forEach(btn => {
      btn.addEventListener('click', () => {
        if (input) { input.value = btn.textContent; sendChat(); }
      });
    });
  }

  /* Set chatModule for sendChat() */
  window.chatModule = 'cloud-infra';

  /* Welcome greeting using \n not <br> so appendBotMessage renders correctly */
  appendBotMessage(
    "Hi! I\u2019m CloudSentinel AI. I can help you understand the platform and all 5 security modules.\n\n" +
    "Use the chips above for quick answers, or ask me anything about Cloud, DevOps, Full-Stack, Data Engineering, or Mobile security!"
  );
}

document.addEventListener('DOMContentLoaded', initDashboardChatbot);

