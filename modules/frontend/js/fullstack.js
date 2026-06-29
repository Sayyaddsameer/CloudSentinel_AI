/**
 * fullstack.js -- Full-Stack Application Intelligence module
 *
 * Connect flow (2 steps):
 *   Step 1: AWS Account ID + Region → builds CloudFormation scanner role ARN
 *   Step 2: API Base URL + latency threshold → for real-time HTTP testing
 *
 * Scan sends { targetRoleArn, scanRegion, apiBaseUrl, latencyThresholdMs }
 * Lambda does:
 *   - Cross-account API GW config scan (auth, WAF, logging, throttle)
 *   - Live HTTP calls to apiBaseUrl (latency, rate-limit burst, auth test)
 *   - CloudWatch historical 5XX trends
 *
 * Depends on: js/env.js, js/auth.js, js/app.js, js/session.js
 */

const MODULE = 'fullstack';
let allRisks = [];

document.addEventListener('DOMContentLoaded', () => {
  initPage(MODULE);

  // Pre-fill from cloud-infra connection if already done
  const cloudConn = getConnections('cloud-infra');
  const savedRegion = cloudConn?.aws?.region || localStorage.getItem('cs_aws_region') || 'us-east-1';
  const regionEl = document.getElementById('fs-region');
  if (regionEl) regionEl.value = savedRegion;
  const acctEl = document.getElementById('fs-account-id');
  if (acctEl && cloudConn?.aws?.accountId) acctEl.value = cloudConn.aws.accountId;

  const conns = getConnections(MODULE);
  if (Object.keys(conns).length) showRisksView(conns);
  else showConnectView();

  document.getElementById('btn-connect-apigw').addEventListener('click', () => {
    resetFsModal();
    openModal('modal-apigw');
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
    <button class="btn btn-outline btn-sm" onclick="showConnectView()">Manage</button>
    <button class="btn btn-gradient btn-sm" onclick="startScan()">Rescan</button>`;
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
    { label: 'Assuming scanner role…',        sub: 'Connecting to your AWS account via STS',                  pct: 15 },
    { label: 'Reading API Gateway config…',   sub: 'Checking auth settings, WAF and logging per stage',       pct: 35 },
    { label: 'Testing authentication live…',  sub: 'Calling API without credentials — expecting 401/403',     pct: 55 },
    { label: 'Measuring real latency…',       sub: 'Making 3 live HTTP requests and averaging response time', pct: 72 },
    { label: 'Testing rate limiting…',        sub: 'Burst of 20 rapid requests — checking for 429',           pct: 88 },
    { label: 'Finalizing…',                   sub: 'Reading CloudWatch 5XX history and alarm gaps',            pct: 96 },
  ];

  for (const s of steps) {
    label.textContent = s.label;
    sub.textContent   = s.sub;
    fill.style.width  = s.pct + '%';
    await sleep(700 + Math.random() * 400);
  }

  try {
    const conn = getConnections(MODULE);
    const extra = {
      apiBaseUrl:         conn?.aws?.apiBaseUrl || '',
      latencyThresholdMs: conn?.aws?.latencyThresholdMs || 2000,
    };
    await triggerScan(MODULE, extra);
    fill.style.width = '100%';
    label.textContent = 'Scan complete! Loading results…';
    sub.textContent   = 'Saving findings to dashboard…';
    await sleep(2000);
    showToast('API scan complete!', 'success');
    localStorage.setItem(`cs_scan_${MODULE}`, new Date().toISOString());
    showRisksView(getConnections(MODULE));
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
    showConnectView();
  }
}

/* ── Modal 2-step flow ─────────────────────────────────────── */
function resetFsModal() {
  document.getElementById('fs-step-1').style.display   = '';
  document.getElementById('fs-step-2').style.display   = 'none';
  document.getElementById('fs-btn-back').style.display = 'none';
  document.getElementById('fs-btn-next').textContent   = 'Next →';
  document.getElementById('fs-btn-next').onclick       = fsNextStep;
  document.getElementById('fs-modal-sub').textContent  = 'Step 1 of 2 — AWS Account access';
  document.getElementById('apigw-consent').checked     = false;
}

function fsGoBack() {
  document.getElementById('fs-step-1').style.display   = '';
  document.getElementById('fs-step-2').style.display   = 'none';
  document.getElementById('fs-btn-back').style.display = 'none';
  document.getElementById('fs-btn-next').textContent   = 'Next →';
  document.getElementById('fs-btn-next').onclick       = fsNextStep;
  document.getElementById('fs-modal-sub').textContent  = 'Step 1 of 2 — AWS Account access';
}

function fsNextStep() {
  const accountId = document.getElementById('fs-account-id').value.trim();
  if (!/^\d{12}$/.test(accountId)) {
    showToast('Account ID must be exactly 12 digits', 'warning'); return;
  }
  // Proceed to step 2
  document.getElementById('fs-step-1').style.display   = 'none';
  document.getElementById('fs-step-2').style.display   = '';
  document.getElementById('fs-btn-back').style.display = '';
  document.getElementById('fs-modal-sub').textContent  = 'Step 2 of 2 — API endpoint for live testing';
  document.getElementById('fs-btn-next').textContent   = 'Connect & Scan';
  document.getElementById('fs-btn-next').onclick       = confirmApigwConnect;
}

async function confirmApigwConnect() {
  const accountId  = document.getElementById('fs-account-id').value.trim();
  const region     = document.getElementById('fs-region').value;
  const apiBaseUrl = document.getElementById('fs-api-url').value.trim();
  const threshold  = parseInt(document.getElementById('fs-threshold').value || '2000', 10);
  const consent    = document.getElementById('apigw-consent').checked;

  if (!apiBaseUrl || !apiBaseUrl.startsWith('https://')) {
    showToast('Please enter a valid https:// API URL', 'warning'); return;
  }
  if (!consent) {
    showToast('Please confirm your consent to proceed', 'warning'); return;
  }

  const roleArn = `arn:aws:iam::${accountId}:role/cloudsentinel-scanner-role`;
  closeModal('modal-apigw');

  // Store — targetRoleArn + scanRegion auto-included in every triggerScan()
  setConnection(MODULE, 'aws', {
    accountId,
    region,
    roleArn,
    apiBaseUrl,
    latencyThresholdMs: isNaN(threshold) ? 2000 : threshold,
    connectedAt: new Date().toISOString(),
  });
  localStorage.setItem('cs_aws_region', region);

  const statusEl = document.getElementById('apigw-status');
  if (statusEl) statusEl.innerHTML =
    `<span style="color:var(--low)">&#9679; Connected · ${accountId} · ${region}</span>`;

  showToast(`AWS connected! Scanning API Gateway in ${region}…`, 'success');
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
  showToast('Disconnected. Risk data purged.', 'success');
  showConnectView();
}

/* ── Helpers ───────────────────────────────────────────────── */
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
