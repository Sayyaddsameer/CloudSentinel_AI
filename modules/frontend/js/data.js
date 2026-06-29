/**
 * data.js -- Data Engineering Intelligence module
 *
 * Connect flow (2 steps):
 *   Step 1: AWS Account ID + Region (+ CloudFormation stack link)
 *           → skipped automatically if cs_global_aws already exists
 *   Step 2: Consent
 *
 * Scan sends { targetRoleArn, scanRegion } — Lambda assumes cross-account role
 * and scans: S3 (public access, encryption, versioning, logging),
 *            DynamoDB (encryption, PITR), Glue (job failures, bookmarks).
 *
 * Depends on: js/env.js, js/auth.js, js/app.js, js/session.js, js/global-connect.js
 */

const MODULE = 'data-eng';
let allRisks = [];

document.addEventListener('DOMContentLoaded', () => {
  initPage(MODULE);

  // Pre-fill from global AWS or cloud-infra
  const globalAws = getGlobalAws?.() || null;
  const cloudConn = getConnections('cloud-infra');
  const savedRegion = cloudConn?.aws?.region || globalAws?.region || localStorage.getItem('cs_aws_region') || 'us-east-1';
  const regionEl = document.getElementById('data-region');
  if (regionEl) regionEl.value = savedRegion;
  const acctEl = document.getElementById('data-account-id');
  if (acctEl && (cloudConn?.aws?.accountId || globalAws?.accountId))
    acctEl.value = cloudConn?.aws?.accountId || globalAws?.accountId;

  // Set CFN link from env.js if available
  const cfnLinkEl = document.getElementById('data-cfn-link');
  if (cfnLinkEl) {
    const tplUrl = typeof CFN_TEMPLATE_URL !== 'undefined' ? CFN_TEMPLATE_URL : '';
    if (tplUrl) {
      const base = 'https://console.aws.amazon.com/cloudformation/home#/stacks/create/review';
      cfnLinkEl.href = `${base}?templateURL=${encodeURIComponent(tplUrl)}&stackName=CloudSentinel-Scanner`;
    }
  }

  const conns = getConnections(MODULE);
  if (Object.keys(conns).length) showRisksView(conns);
  else showConnectView();

  document.getElementById('btn-connect-data').addEventListener('click', () => {
    resetDataModal();
    // Skip Step 1 if global AWS already connected
    openModal('modal-data');
    if (globalAws) {
      document.getElementById('data-account-id').value = globalAws.accountId;
      document.getElementById('data-region').value     = globalAws.region;
      _dataShowStep2WithBanner(globalAws);
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
    { label: 'Assuming scanner role…',       sub: 'Connecting to your AWS account via STS',              pct: 15 },
    { label: 'Scanning S3 buckets…',         sub: 'Checking public access, encryption and versioning',   pct: 35 },
    { label: 'Analyzing DynamoDB tables…',   sub: 'Checking encryption at rest and PITR backup status',  pct: 55 },
    { label: 'Auditing Glue ETL jobs…',      sub: 'Reviewing job failures, bookmarks and security config', pct: 75 },
    { label: 'Checking S3 access logging…',  sub: 'Verifying audit logs are enabled per bucket',         pct: 90 },
    { label: 'Finalizing…',                  sub: 'Saving findings to dashboard',                        pct: 97 },
  ];

  for (const s of steps) {
    label.textContent = s.label;
    sub.textContent   = s.sub;
    fill.style.width  = s.pct + '%';
    await sleep(800 + Math.random() * 400);
  }

  try {
    await triggerScan(MODULE);
    fill.style.width  = '100%';
    label.textContent = 'Scan complete! Loading results…';
    sub.textContent   = 'Saving findings to dashboard…';
    await sleep(2000);
    showToast('Data Engineering scan complete!', 'success');
    localStorage.setItem(`cs_scan_${MODULE}`, new Date().toISOString());
    showRisksView(getConnections(MODULE));
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
    showConnectView();
  }
}

/* ── Modal 2-step flow ─────────────────────────────────────── */
function resetDataModal() {
  document.getElementById('data-step-1').style.display   = '';
  document.getElementById('data-step-2').style.display   = 'none';
  document.getElementById('data-btn-back').style.display = 'none';
  document.getElementById('data-btn-next').textContent   = 'Next →';
  document.getElementById('data-btn-next').onclick       = dataNextStep;
  document.getElementById('data-modal-sub').textContent  = 'Step 1 of 2 — AWS Account access';
  document.getElementById('data-consent').checked        = false;
  document.getElementById('data-global-banner')?.remove();
}

function _dataShowStep2WithBanner(gAws) {
  document.getElementById('data-step-1').style.display   = 'none';
  document.getElementById('data-step-2').style.display   = '';
  document.getElementById('data-btn-back').style.display = '';
  document.getElementById('data-modal-sub').textContent  = 'Step 2 of 2 — Consent';
  document.getElementById('data-btn-next').textContent   = 'Connect & Scan';
  document.getElementById('data-btn-next').onclick       = confirmDataConnect;

  const step2 = document.getElementById('data-step-2');
  if (!document.getElementById('data-global-banner')) {
    const banner = document.createElement('div');
    banner.id = 'data-global-banner';
    banner.className = 'info-box mb-3';
    banner.style.borderColor = 'var(--low)';
    banner.innerHTML = `<span class="info-icon">&#10003;</span><div>Using your globally connected AWS account &middot; <strong>${gAws.accountId}</strong> &middot; <strong>${gAws.region}</strong>. Confirm consent below to scan your data services.</div>`;
    step2.prepend(banner);
  }
}

function dataGoBack() {
  document.getElementById('data-step-1').style.display   = '';
  document.getElementById('data-step-2').style.display   = 'none';
  document.getElementById('data-btn-back').style.display = 'none';
  document.getElementById('data-btn-next').textContent   = 'Next →';
  document.getElementById('data-btn-next').onclick       = dataNextStep;
  document.getElementById('data-modal-sub').textContent  = 'Step 1 of 2 — AWS Account access';
  document.getElementById('data-global-banner')?.remove();
}

function dataNextStep() {
  const accountId = document.getElementById('data-account-id').value.trim();
  if (!/^\d{12}$/.test(accountId)) {
    showToast('Account ID must be exactly 12 digits', 'warning'); return;
  }
  document.getElementById('data-step-1').style.display   = 'none';
  document.getElementById('data-step-2').style.display   = '';
  document.getElementById('data-btn-back').style.display = '';
  document.getElementById('data-modal-sub').textContent  = 'Step 2 of 2 — Consent';
  document.getElementById('data-btn-next').textContent   = 'Connect & Scan';
  document.getElementById('data-btn-next').onclick       = confirmDataConnect;
}

async function confirmDataConnect() {
  const accountId = document.getElementById('data-account-id').value.trim();
  const region    = document.getElementById('data-region').value;
  const consent   = document.getElementById('data-consent').checked;

  if (!consent) { showToast('Please confirm your consent', 'warning'); return; }

  const roleArn = `arn:aws:iam::${accountId}:role/cloudsentinel-scanner-role`;
  closeModal('modal-data');

  setConnection(MODULE, 'aws-data', {
    accountId,
    region,
    roleArn,
    connectedAt: new Date().toISOString(),
  });
  localStorage.setItem('cs_aws_region', region);

  const statusEl = document.getElementById('data-aws-status');
  const cardEl   = document.getElementById('data-aws-card');
  if (statusEl) statusEl.innerHTML =
    `<span style="color:var(--low)">&#9679; Connected · ${accountId} · ${region}</span>`;
  if (cardEl) cardEl.classList.add('connected');

  showToast(`AWS connected! Scanning data services in ${region}…`, 'success');
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
  showToast('Data Engineering disconnected. Risk data purged.', 'success');
  showConnectView();
}

/* ── Helpers ───────────────────────────────────────────────── */
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
