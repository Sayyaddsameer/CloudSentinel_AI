/**
 * devops.js -- DevOps Intelligence module
 *
 * 2-step GitHub connect flow:
 *   Step 1: Enter org/username + PAT → validated against GitHub API
 *   Step 2: Auto-fetched repo list with checkboxes → user picks repos to scan
 *
 * Scan sends { repoList: [...], githubToken } to Lambda.
 * Lambda loops every repo, fetches .github/workflows/, scans each.
 * Zero hardcoding — every value comes from user input or live API.
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

  document.getElementById('btn-connect-github').addEventListener('click', () => {
    resetGhModal();
    openModal('modal-github');
  });

  document.getElementById('toggle-gh-token').addEventListener('click', function () {
    const t = document.getElementById('github-token');
    t.type = t.type === 'password' ? 'text' : 'password';
    this.textContent = t.type === 'password' ? 'show' : 'hide';
  });
});

/* ── View switcher ─────────────────────────────────────────── */
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

  const repos = conns.github?.repos || [];
  const el    = document.getElementById('connected-repo-name');
  if (el) el.textContent = repos.length
    ? `${repos.length} repo${repos.length > 1 ? 's' : ''} connected`
    : (conns.github?.org || 'GitHub') + ' — Workflows Connected';

  loadRisks();
}

/* ── Load risks ────────────────────────────────────────────── */
async function loadRisks() {
  document.getElementById('risk-list').innerHTML = `
    <div class="empty-state"><div class="empty-state-icon">...</div>
    <div class="empty-state-title">Loading…</div></div>`;
  try {
    allRisks = await fetchRisks(MODULE);
    updateStats(allRisks);
    renderRiskCards(allRisks, 'risk-list');
    document.getElementById('last-scan-time').textContent = new Date().toLocaleTimeString();
    recordScanToHistory(MODULE, allRisks);
  } catch (e) {
    showToast('Failed to load risks: ' + e.message, 'error');
  }
}

function filterRisks(priority, btn) {
  document.querySelectorAll('.filter-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderRiskCards(allRisks, 'risk-list', priority);
}

/* ── Scan flow ─────────────────────────────────────────────── */
async function startScan() {
  const conns = getConnections(MODULE);
  if (!Object.keys(conns).length) { showToast('Connect GitHub first', 'warning'); return; }

  const repos     = conns.github?.repos || [];
  const ghToken   = sessionStorage.getItem('cs_gh_token');

  if (!repos.length) { showToast('No repositories selected. Reconnect and choose at least one repo.', 'warning'); return; }
  if (!ghToken)       { showToast('Session expired — please reconnect GitHub.', 'warning'); showConnectView(); return; }

  showScanView();

  const fill  = document.getElementById('scan-fill');
  const label = document.getElementById('scan-label');
  const sub   = document.getElementById('scan-sub');

  const steps = [
    { label: 'Fetching workflow files…',     sub: `Reading .github/workflows/ for ${repos.length} repo(s)`,          pct: 25 },
    { label: 'Scanning for secrets…',        sub: 'Regex matching environment variables for hardcoded values',        pct: 50 },
    { label: 'Checking pipeline structure…', sub: 'Looking for test, rollback and monitoring steps',                  pct: 75 },
    { label: 'Finalizing analysis…',         sub: 'Prioritizing findings and generating AI explanations',             pct: 90 },
  ];

  for (const s of steps) {
    label.textContent = s.label;
    sub.textContent   = s.sub;
    fill.style.width  = s.pct + '%';
    await sleep(700 + Math.random() * 400);
  }

  try {
    // Send repo list + token directly in request body — Lambda loops all repos
    await triggerScan(MODULE, { repoList: repos, githubToken: ghToken });
    fill.style.width = '100%';
    label.textContent = 'Analysis complete! Loading results…';
    sub.textContent   = 'Waiting for risk records to be saved…';
    await sleep(2000);
    showToast(`Pipeline analysis complete across ${repos.length} repo(s)!`, 'success');
    localStorage.setItem(`cs_scan_${MODULE}`, new Date().toISOString());
    showRisksView(getConnections(MODULE));
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
    showConnectView();
  }
}

/* ── GitHub PAT validation ─────────────────────────────────── */
async function validateGithubToken(token) {
  const res = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `token ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (res.status === 401) throw new Error('Invalid token — GitHub returned 401. Check your token and try again.');
  if (res.status === 403) throw new Error('Token lacks required permissions. Ensure it has the "repo" scope.');
  if (!res.ok) throw new Error(`GitHub API error: ${res.status}`);
  const user   = await res.json();
  const scopes = res.headers.get('x-oauth-scopes') || '';
  return { login: user.login, name: user.name || user.login, scopes };
}

/* ── Fetch all repos for an org/user via GitHub API (handles pagination) ── */
async function fetchAllRepos(orgOrUser, token) {
  let repos = [];
  let page  = 1;

  // Try org first, fall back to user repos
  const endpoints = [
    `https://api.github.com/orgs/${encodeURIComponent(orgOrUser)}/repos`,
    `https://api.github.com/users/${encodeURIComponent(orgOrUser)}/repos`,
  ];

  for (const baseUrl of endpoints) {
    repos = [];
    page  = 1;
    let success = true;

    while (true) {
      const res = await fetch(`${baseUrl}?per_page=100&page=${page}&sort=pushed`, {
        headers: {
          Authorization: `token ${token}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      });

      if (!res.ok) { success = false; break; }

      const data = await res.json();
      if (!data.length) break;

      repos.push(...data.map(r => ({
        fullName:    r.full_name,           // "owner/repo"
        name:        r.name,
        private:     r.private,
        description: r.description || '',
        pushedAt:    r.pushed_at,
        hasWorkflows: true,                 // we'll assume yes; filter during scan if empty
      })));

      // Stop if last page
      const linkHeader = res.headers.get('link') || '';
      if (!linkHeader.includes('rel="next"')) break;
      page++;
    }

    if (success && repos.length) break; // Found repos — stop trying endpoints
  }

  return repos;
}

/* ── Modal step management ─────────────────────────────────── */
function resetGhModal() {
  document.getElementById('gh-step-1').style.display    = '';
  document.getElementById('gh-step-2').style.display    = 'none';
  document.getElementById('gh-btn-back').style.display  = 'none';
  document.getElementById('gh-btn-next').textContent    = 'Fetch Repositories →';
  document.getElementById('gh-btn-next').onclick        = ghNextStep;
  document.getElementById('gh-modal-subtitle').textContent = 'Enter your credentials to fetch repositories';
  document.getElementById('github-consent').checked     = false;
  document.getElementById('gh-repo-list').innerHTML     = '';
  document.getElementById('gh-repo-count').textContent  = '';
}

function ghGoBack() {
  document.getElementById('gh-step-1').style.display    = '';
  document.getElementById('gh-step-2').style.display    = 'none';
  document.getElementById('gh-btn-back').style.display  = 'none';
  document.getElementById('gh-btn-next').textContent    = 'Fetch Repositories →';
  document.getElementById('gh-btn-next').onclick        = ghNextStep;
  document.getElementById('gh-modal-subtitle').textContent = 'Enter your credentials to fetch repositories';
}

async function ghNextStep() {
  const org   = document.getElementById('github-org').value.trim();
  const token = document.getElementById('github-token').value.trim();
  const btn   = document.getElementById('gh-btn-next');

  if (!org)   { showToast('Please enter your GitHub org or username', 'warning'); return; }
  if (!token) { showToast('Please enter a Personal Access Token', 'warning'); return; }

  btn.disabled    = true;
  btn.textContent = 'Validating & fetching repos…';

  try {
    // 1. Validate token
    const { login, name, scopes } = await validateGithubToken(token);
    if (scopes && !scopes.split(',').map(s => s.trim()).includes('repo')) {
      showToast('Warning: token may lack "repo" scope — some repos may be inaccessible.', 'warning', 5000);
    }

    // 2. Fetch all repos
    btn.textContent = `Fetching repositories for ${org}…`;
    const repos = await fetchAllRepos(org, token);

    if (!repos.length) {
      showToast(`No repositories found for "${org}". Check the org/username and token scope.`, 'error', 7000);
      btn.disabled    = false;
      btn.textContent = 'Fetch Repositories →';
      return;
    }

    // 3. Render repo list
    renderRepoList(repos);

    // 4. Show step 2
    document.getElementById('gh-step-1').style.display    = 'none';
    document.getElementById('gh-step-2').style.display    = '';
    document.getElementById('gh-btn-back').style.display  = '';
    document.getElementById('gh-modal-subtitle').textContent = `Found ${repos.length} repo(s) for ${org}`;
    document.getElementById('gh-btn-next').textContent    = 'Connect & Analyze';
    document.getElementById('gh-btn-next').onclick        = () => confirmGithubConnect(org, token, login, name);

    // Store token in session only
    sessionStorage.setItem('cs_gh_token', token);

  } catch (err) {
    showToast(err.message, 'error', 7000);
  } finally {
    btn.disabled = false;
    if (btn.textContent !== 'Connect & Analyze') btn.textContent = 'Fetch Repositories →';
  }
}

function renderRepoList(repos) {
  const container = document.getElementById('gh-repo-list');
  container.innerHTML = repos.map(r => `
    <label style="display:flex;align-items:flex-start;gap:.6rem;padding:.5rem .4rem;border-radius:6px;cursor:pointer;transition:background .15s"
           onmouseover="this.style.background='var(--surface-2)'" onmouseout="this.style.background=''">
      <input type="checkbox" class="gh-repo-checkbox" value="${escHtml(r.fullName)}" checked
             style="margin-top:3px;flex-shrink:0" onchange="updateRepoCount()">
      <div style="min-width:0">
        <div style="font-weight:500;font-size:.875rem;color:var(--text)">${escHtml(r.name)}
          ${r.private ? '<span style="font-size:.7rem;background:var(--surface-3);color:var(--text-2);padding:1px 6px;border-radius:4px;margin-left:4px">private</span>' : ''}
        </div>
        ${r.description ? `<div style="font-size:.75rem;color:var(--text-2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escHtml(r.description)}</div>` : ''}
      </div>
    </label>
  `).join('');
  updateRepoCount();
}

function updateRepoCount() {
  const total    = document.querySelectorAll('.gh-repo-checkbox').length;
  const selected = document.querySelectorAll('.gh-repo-checkbox:checked').length;
  document.getElementById('gh-repo-count').textContent = `${selected} of ${total} repositories selected`;
}

function toggleAllRepos(checked) {
  document.querySelectorAll('.gh-repo-checkbox').forEach(cb => cb.checked = checked);
  updateRepoCount();
}

/* ── Connect & save ────────────────────────────────────────── */
async function confirmGithubConnect(org, token, login, name) {
  const consent = document.getElementById('github-consent').checked;
  if (!consent) { showToast('Please confirm your consent to proceed', 'warning'); return; }

  const selectedRepos = [...document.querySelectorAll('.gh-repo-checkbox:checked')].map(cb => cb.value);
  if (!selectedRepos.length) { showToast('Please select at least one repository', 'warning'); return; }

  closeModal('modal-github');

  // Store connection — PAT never goes to localStorage, only sessionStorage
  setConnection(MODULE, 'github', {
    org,
    repos:       selectedRepos,   // ["owner/repo1", "owner/repo2", ...]
    githubLogin: login,
    githubName:  name,
    connectedAt: new Date().toISOString(),
  });

  sessionStorage.setItem('cs_gh_token', token);

  const statusEl = document.getElementById('github-status');
  const cardEl   = document.getElementById('github-card');
  if (statusEl) statusEl.innerHTML = `<span style="color:var(--low)">&#9679; Connected as ${escHtml(login)} · ${selectedRepos.length} repo(s)</span>`;
  if (cardEl)   cardEl.classList.add('connected');

  showToast(`GitHub connected! Analyzing ${selectedRepos.length} repo(s)…`, 'success');
  await sleep(400);
  showRisksView(getConnections(MODULE));
  await sleep(300);
  startScan();
}

/* ── Disconnect ────────────────────────────────────────────── */
async function performDisconnect() {
  showToast('Disconnecting and purging risk data...', 'info', 3000);
  await callDisconnectApi(MODULE, 'all');
  localStorage.removeItem(`cs_conn_${MODULE}`);
  localStorage.removeItem(`cs_scan_${MODULE}`);
  sessionStorage.removeItem('cs_gh_token');
  allRisks = [];
  showToast('GitHub disconnected. Risk data purged.', 'success');
  showConnectView();
}

/* ── Helpers ───────────────────────────────────────────────── */
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
function escHtml(s)     { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
