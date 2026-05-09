/**
 * fullstack.js -- Full-Stack Application Intelligence module
 *
 * Depends on: js/env.js, js/auth.js, js/app.js, js/session.js
 */

const MODULE = 'fullstack';
let allRisks = [];

document.addEventListener('DOMContentLoaded', () => {
  initPage(MODULE);
  const conns = getConnections(MODULE);
  if (Object.keys(conns).length) showRisksView(conns);
  else showConnectView();
  document.getElementById('btn-connect-apigw').addEventListener('click', () => openModal('modal-apigw'));
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
    <button class="btn btn-outline btn-sm" onclick="showConnectView()">Manage</button>
    <button class="btn btn-gradient btn-sm" onclick="startScan()">Rescan</button>`;
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
  if (!Object.keys(conns).length) { showToast('Connect API Gateway first', 'warning'); return; }
  showScanView();

  const fill  = document.getElementById('scan-fill');
  const label = document.getElementById('scan-label');
  const sub   = document.getElementById('scan-sub');

  const steps = [
    { label: 'Discovering API endpoints…',  sub: 'Listing all resources and methods',                    pct: 25 },
    { label: 'Checking authentication…',    sub: 'Reviewing authorization on each endpoint',             pct: 50 },
    { label: 'Analyzing CloudWatch metrics…', sub: 'Checking 5XX rates and average latency',             pct: 75 },
    { label: 'Finalizing findings…',        sub: 'Prioritizing security and performance risks',          pct: 92 },
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
    showToast('API scan complete!', 'success');
    localStorage.setItem(`cs_scan_${MODULE}`, new Date().toISOString());
    showRisksView(getConnections(MODULE));
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
    showConnectView();
  }
}

/* ── Connect flow ─────────────────────────────────────────── */
async function confirmApigwConnect() {
  const url     = document.getElementById('api-url-input').value.trim();
  const consent = document.getElementById('apigw-consent').checked;

  if (!url) {
    showToast('Please enter your API Gateway invoke URL', 'warning');
    return;
  }
  if (!url.startsWith('https://')) {
    showToast('API URL must start with https://', 'warning');
    return;
  }
  if (!consent) {
    showToast('Please confirm your consent to proceed', 'warning');
    return;
  }

  closeModal('modal-apigw');
  setConnection(MODULE, 'apigw', { url, connectedAt: new Date().toISOString() });

  const statusEl = document.getElementById('apigw-status');
  if (statusEl) statusEl.innerHTML = `<span style="color:var(--low)">- Connected</span>`;

  showToast('API Gateway connected! Starting scan…', 'success');
  await sleep(400);
  showRisksView(getConnections(MODULE));
  await sleep(300);
  startScan();
}

/* ── Disconnect ───────────────────────────────────────────── */
async function performDisconnect() {
  showToast('Disconnecting and purging risk data...', 'info', 3000);
  await callDisconnectApi(MODULE, 'all');
  localStorage.removeItem(`cs_conn_${MODULE}`);
  localStorage.removeItem(`cs_scan_${MODULE}`);
  allRisks = [];
  showToast('Disconnected. Risk data purged.', 'success');
  showConnectView();
}

/* ── Helpers ──────────────────────────────────────────────── */
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
