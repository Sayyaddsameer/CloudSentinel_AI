/**
 * mobile.js -- Mobile Backend Intelligence module
 *
 * Connect flow (2 steps):
 *   Step 1: AWS Account ID + Region → builds CloudFormation scanner role ARN
 *   Step 2: Mobile API Base URL + latency threshold → for real-time HTTP testing
 *
 * Scan sends { targetRoleArn, scanRegion, apiBaseUrl, latencyThresholdMs }
 * Lambda does:
 *   - Cross-account scan: API GW auth, Cognito MFA/policy, Lambda health, IAM roles
 *   - Live HTTP calls to apiBaseUrl (latency 3 samples, rate-limit burst, auth check)
 *   - CloudWatch 4XX/5XX rates
 *
 * Depends on: js/env.js, js/auth.js, js/app.js, js/session.js
 */

const MODULE = 'mobile';
let allRisks = [];

document.addEventListener('DOMContentLoaded', () => {
  initPage(MODULE);

  // Pre-fill from cloud-infra connection if already done
  const cloudConn   = getConnections('cloud-infra');
  const savedRegion = cloudConn?.aws?.region || localStorage.getItem('cs_aws_region') || 'us-east-1';
  const regionEl    = document.getElementById('mobile-region');
  if (regionEl) regionEl.value = savedRegion;
  const acctEl = document.getElementById('mobile-account-id');
  if (acctEl && cloudConn?.aws?.accountId) acctEl.value = cloudConn.aws.accountId;

  const conns = getConnections(MODULE);
  if (Object.keys(conns).length) showRisksView(conns);
  else showConnectView();

  document.getElementById('btn-connect-mobile')?.addEventListener('click', () => {
    resetMobModal();
    // Skip Step 1 if global AWS is already connected
    const gAws = (() => { try { return JSON.parse(localStorage.getItem('cs_global_aws') || 'null'); } catch { return null; } })();
    openModal('modal-mobile');
    if (gAws) {
      document.getElementById('mobile-account-id').value = gAws.accountId;
      document.getElementById('mobile-region').value     = gAws.region;
      _mobShowStep2WithBanner(gAws);
    }
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
  if (!Object.keys(conns).length) { showToast('Connect AWS first', 'warning'); return; }
  showScanView();

  const fill  = document.getElementById('scan-fill');
  const label = document.getElementById('scan-label');
  const sub   = document.getElementById('scan-sub');

  const steps = [
    { label: 'Assuming scanner role…',         sub: 'Connecting to your AWS account via STS',                       pct: 12 },
    { label: 'Checking Cognito pools…',         sub: 'Scanning MFA enforcement and password policies',               pct: 28 },
    { label: 'Analyzing Lambda functions…',     sub: 'Checking error rates, timeouts and IAM role permissions',      pct: 44 },
    { label: 'Testing auth live…',              sub: 'Calling your API without credentials — expecting 401/403',     pct: 60 },
    { label: 'Measuring real latency…',         sub: 'Making 3 live HTTP requests and averaging response time',      pct: 76 },
    { label: 'Testing rate limiting…',          sub: 'Burst of 20 rapid requests — checking for HTTP 429',           pct: 90 },
    { label: 'Finalizing…',                     sub: 'Checking CloudWatch 4XX/5XX rates and API logging',            pct: 97 },
  ];

  for (const s of steps) {
    label.textContent = s.label;
    sub.textContent   = s.sub;
    fill.style.width  = s.pct + '%';
    await sleep(700 + Math.random() * 400);
  }

  try {
    const conn  = getConnections(MODULE);
    const extra = {
      apiBaseUrl:         conn?.['aws-mobile']?.apiBaseUrl || '',
      latencyThresholdMs: conn?.['aws-mobile']?.latencyThresholdMs || 1000,
    };
    await triggerScan(MODULE, extra);
    fill.style.width  = '100%';
    label.textContent = 'Analysis complete! Loading results…';
    sub.textContent   = 'Saving findings to dashboard…';
    await sleep(2000);
    showToast('Mobile backend scan complete!', 'success');
    localStorage.setItem(`cs_scan_${MODULE}`, new Date().toISOString());
    showRisksView(getConnections(MODULE));
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
    showConnectView();
  }
}

/* ── Modal 2-step flow ─────────────────────────────────────── */
function resetMobModal() {
  document.getElementById('mob-step-1').style.display   = '';
  document.getElementById('mob-step-2').style.display   = 'none';
  document.getElementById('mob-btn-back').style.display = 'none';
  document.getElementById('mob-btn-next').textContent   = 'Next →';
  document.getElementById('mob-btn-next').onclick       = mobNextStep;
  document.getElementById('mob-modal-sub').textContent  = 'Step 1 of 2 — AWS Account access';
  document.getElementById('mobile-consent').checked     = false;
  document.getElementById('mob-global-banner')?.remove();
}

function _mobShowStep2WithBanner(gAws) {
  document.getElementById('mob-step-1').style.display   = 'none';
  document.getElementById('mob-step-2').style.display   = '';
  document.getElementById('mob-btn-back').style.display = '';
  document.getElementById('mob-modal-sub').textContent  = 'Step 2 of 2 — API endpoint for live testing';
  document.getElementById('mob-btn-next').textContent   = 'Connect & Monitor';
  document.getElementById('mob-btn-next').onclick       = confirmMobileConnect;

  const step2 = document.getElementById('mob-step-2');
  if (!document.getElementById('mob-global-banner')) {
    const banner = document.createElement('div');
    banner.id = 'mob-global-banner';
    banner.className = 'info-box mb-3';
    banner.style.borderColor = 'var(--low)';
    banner.innerHTML = `<span class="info-icon">&#10003;</span><div>Using your globally connected AWS account &middot; <strong>${gAws.accountId}</strong> &middot; <strong>${gAws.region}</strong>. Enter your API URL and consent below.</div>`;
    step2.prepend(banner);
  }
}


function mobGoBack() {
  document.getElementById('mob-step-1').style.display   = '';
  document.getElementById('mob-step-2').style.display   = 'none';
  document.getElementById('mob-btn-back').style.display = 'none';
  document.getElementById('mob-btn-next').textContent   = 'Next →';
  document.getElementById('mob-btn-next').onclick       = mobNextStep;
  document.getElementById('mob-modal-sub').textContent  = 'Step 1 of 2 — AWS Account access';
}

function mobNextStep() {
  const accountId = document.getElementById('mobile-account-id').value.trim();
  if (!/^\d{12}$/.test(accountId)) {
    showToast('Account ID must be exactly 12 digits', 'warning'); return;
  }
  document.getElementById('mob-step-1').style.display   = 'none';
  document.getElementById('mob-step-2').style.display   = '';
  document.getElementById('mob-btn-back').style.display = '';
  document.getElementById('mob-modal-sub').textContent  = 'Step 2 of 2 — API endpoint for live testing';
  document.getElementById('mob-btn-next').textContent   = 'Connect & Monitor';
  document.getElementById('mob-btn-next').onclick       = confirmMobileConnect;
}

async function confirmMobileConnect() {
  const accountId  = document.getElementById('mobile-account-id').value.trim();
  const region     = document.getElementById('mobile-region').value;
  const apiBaseUrl = document.getElementById('mobile-api-url').value.trim();
  const threshold  = parseInt(document.getElementById('mobile-threshold').value || '1000', 10);
  const consent    = document.getElementById('mobile-consent').checked;

  if (!apiBaseUrl || !apiBaseUrl.startsWith('https://')) {
    showToast('Please enter a valid https:// API URL', 'warning'); return;
  }
  if (!consent) {
    showToast('Please confirm your consent to proceed', 'warning'); return;
  }

  const roleArn = `arn:aws:iam::${accountId}:role/cloudsentinel-scanner-role`;
  closeModal('modal-mobile');

  setConnection(MODULE, 'aws-mobile', {
    accountId,
    region,
    roleArn,
    apiBaseUrl,
    latencyThresholdMs: isNaN(threshold) ? 1000 : threshold,
    connectedAt: new Date().toISOString(),
  });
  localStorage.setItem('cs_aws_region', region);

  const statusEl = document.getElementById('mobile-aws-status');
  const cardEl   = document.getElementById('mobile-aws-card');
  if (statusEl) statusEl.innerHTML =
    `<span style="color:var(--low)">&#9679; Connected · ${accountId} · ${region}</span>`;
  if (cardEl) cardEl.classList.add('connected');

  showToast(`AWS connected! Scanning mobile backend in ${region}…`, 'success');
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
  allRisks = [];
  showToast('Mobile backend disconnected. Risk data purged.', 'success');
  showConnectView();
}

/* ── Helpers ───────────────────────────────────────────────── */
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
