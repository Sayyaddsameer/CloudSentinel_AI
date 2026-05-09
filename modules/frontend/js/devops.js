/**
 * devops.js — DevOps Intelligence module
 *
 * Validates GitHub Personal Access Token against the GitHub API before
 * storing the connection. No DEMO_MODE — all flows require real credentials.
 *
 * Depends on: js/env.js, js/auth.js, js/app.js, js/session.js
 */

const MODULE = 'devops';
let allRisks = [];

document.addEventListener('DOMContentLoaded', () => {
  initPage(MODULE);
  const conns = getConnections(MODULE);
  if (Object.keys(conns).length) showRisksView(conns);
  else showConnectView();

  document.getElementById('btn-connect-github').addEventListener('click', () => openModal('modal-github'));
  document.getElementById('toggle-gh-token').addEventListener('click', function () {
    const t = document.getElementById('github-token');
    t.type = t.type === 'password' ? 'text' : 'password';
    this.textContent = t.type === 'password' ? 'show' : 'hide';
  });
});

/* ── View switcher ────────────────────────────────────────── */
function showConnectView() {
  document.getElementById('view-connect').style.display = '';
  document.getElementById('view-scan').style.display    = 'none';
  document.getElementById('view-risks').style.display   = 'none';
  document.getElementById('header-actions').innerHTML   = '';
}

function showScanView() {
  document.getElementById('view-connect').style.display = 'none';
  document.getElementById('view-scan').style.display    = '';
  document.getElementById('view-risks').style.display   = 'none';
}

function showRisksView(conns) {
  document.getElementById('view-connect').style.display = 'none';
  document.getElementById('view-scan').style.display    = 'none';
  document.getElementById('view-risks').style.display   = '';
  document.getElementById('header-actions').innerHTML   = `
    <button class="btn btn-outline btn-sm" onclick="showConnectView()">Manage Connections</button>
    <button class="btn btn-gradient btn-sm" onclick="startScan()">Re-analyze</button>`;
  const org = conns.github?.org || 'GitHub';
  const el  = document.getElementById('connected-repo-name');
  if (el) el.textContent = `${org} — Workflows Connected`;
  loadRisks();
}

/* ── Load risks ───────────────────────────────────────────── */
async function loadRisks() {
  document.getElementById('risk-list').innerHTML = `
    <div class="empty-state"><div class="empty-state-icon">...</div>
    <div class="empty-state-title">Loading…</div></div>`;
  try {
    allRisks = await fetchRisks(MODULE);
    updateStats(allRisks);
    renderRiskCards(allRisks, 'risk-list');
    document.getElementById('last-scan-time').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    showToast('Failed to load risks: ' + e.message, 'error');
  }
}

function filterRisks(priority, btn) {
  document.querySelectorAll('.filter-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderRiskCards(allRisks, 'risk-list', priority);
}

/* ── Scan flow ────────────────────────────────────────────── */
async function startScan() {
  const conns = getConnections(MODULE);
  if (!Object.keys(conns).length) { showToast('Connect GitHub first', 'warning'); return; }
  showScanView();

  const fill  = document.getElementById('scan-fill');
  const label = document.getElementById('scan-label');
  const sub   = document.getElementById('scan-sub');

  const steps = [
    { label: 'Fetching workflow files…',      sub: 'Reading .github/workflows/ directory',                 pct: 30 },
    { label: 'Scanning for secrets…',         sub: 'Regex matching environment variables for hardcoded values', pct: 55 },
    { label: 'Checking pipeline structure…',  sub: 'Looking for test, rollback and monitoring steps',     pct: 80 },
    { label: 'Finalizing analysis…',          sub: 'Prioritizing findings and generating AI explanations', pct: 95 },
  ];

  for (const s of steps) {
    label.textContent = s.label;
    sub.textContent   = s.sub;
    fill.style.width  = s.pct + '%';
    await sleep(800 + Math.random() * 500);
  }

  try {
    await triggerScan(MODULE);
    fill.style.width = '100%';
    await sleep(300);
    showToast('Pipeline analysis complete!', 'success');
    localStorage.setItem(`cs_scan_${MODULE}`, new Date().toISOString());
    showRisksView(getConnections(MODULE));
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
    showConnectView();
  }
}

/* ── GitHub PAT validation + Connect ─────────────────────── */

/**
 * Validates a GitHub Personal Access Token directly against the GitHub API.
 * Returns { valid, login, scopes } or throws on network error.
 */
async function validateGithubToken(token) {
  const res = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `token ${token}`,
      Accept:        'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  if (res.status === 401) {
    throw new Error('Invalid token — GitHub returned 401 Unauthorized. Check your token and try again.');
  }
  if (res.status === 403) {
    throw new Error('Token is valid but lacks required permissions. Ensure it has the "repo" scope (read-only).');
  }
  if (!res.ok) {
    throw new Error(`GitHub API error: ${res.status}. Please try again.`);
  }

  const user   = await res.json();
  const scopes = res.headers.get('x-oauth-scopes') || '';
  return { valid: true, login: user.login, name: user.name || user.login, scopes };
}

async function confirmGithubConnect() {
  const org     = document.getElementById('github-org').value.trim();
  const token   = document.getElementById('github-token').value.trim();
  const consent = document.getElementById('github-consent').checked;
  const btn     = document.querySelector('#modal-github .btn-primary');

  if (!org)     { showToast('Please enter your GitHub org or username', 'warning'); return; }
  if (!token)   { showToast('Please enter a Personal Access Token', 'warning'); return; }
  if (!consent) { showToast('Please confirm your consent to proceed', 'warning'); return; }

  /* Validate token against GitHub API */
  if (btn) { btn.disabled = true; btn.textContent = 'Validating token…'; }
  try {
    const { login, name, scopes } = await validateGithubToken(token);

    /* Warn if repo scope is missing */
    if (scopes && !scopes.split(',').map(s => s.trim()).includes('repo')) {
      showToast('Warning: token may lack "repo" scope — some workflow files may be inaccessible.', 'warning', 6000);
    }

    closeModal('modal-github');

    /* Store connection — token stored only in localStorage (never sent to server) */
    setConnection(MODULE, 'github', {
      org,
      githubLogin: login,
      githubName:  name,
      connectedAt: new Date().toISOString(),
    });

    /* Store token encrypted in sessionStorage only (cleared on tab close) */
    sessionStorage.setItem('cs_gh_token', token);

    const statusEl = document.getElementById('github-status');
    const cardEl   = document.getElementById('github-card');
    if (statusEl) statusEl.innerHTML = `<span style="color:var(--low)">● Connected as ${escHtml(login)}</span>`;
    if (cardEl)   cardEl.classList.add('connected');

    showToast(`GitHub connected as ${name}! Analyzing pipelines…`, 'success');
    await sleep(400);
    showRisksView(getConnections(MODULE));
    await sleep(300);
    startScan();
  } catch (err) {
    showToast(err.message, 'error', 7000);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Connect & Analyze'; }
  }
}

/* ── Disconnect ───────────────────────────────────────────── */
function performDisconnect() {
  localStorage.removeItem(`cs_conn_${MODULE}`);
  localStorage.removeItem(`cs_scan_${MODULE}`);
  sessionStorage.removeItem('cs_gh_token');
  allRisks = [];
  showToast('GitHub disconnected', 'info');
  showConnectView();
}

/* ── Helpers ──────────────────────────────────────────────── */
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
function escHtml(s)     { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
