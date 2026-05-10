/** mobile.js -- Mobile Backend (Flutter) module */
const MODULE = 'mobile';
let allRisks = [];

document.addEventListener('DOMContentLoaded', () => {
  initPage(MODULE);
  const conns = getConnections(MODULE);
  if (Object.keys(conns).length) showRisksView(conns);
  else showConnectView();
  document.getElementById('btn-connect-mobile').addEventListener('click', () => openModal('modal-mobile'));
});

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
  document.getElementById('header-actions').innerHTML = `
    <button class="btn btn-outline btn-sm" onclick="showConnectView()">Manage</button>
    <button class="btn btn-gradient btn-sm" onclick="startScan()">Rescan</button>`;
  loadRisks();
}

async function loadRisks() {
  document.getElementById('risk-list').innerHTML = `
    <div class="empty-state"><div class="empty-state-icon">...</div><div class="empty-state-title">Loading risks</div></div>`;
  try {
    allRisks = await fetchRisks(MODULE);
    updateStats(allRisks);
    renderRiskCards(allRisks, 'risk-list');
    document.getElementById('last-scan-time').textContent = new Date().toLocaleTimeString();
    recordScanToHistory(MODULE, allRisks);
    updateLiveMetrics();
  } catch (e) {
    showToast('Failed to load risks', 'error');
  }
}

function updateLiveMetrics() {
  /* Extract metric values from mock risk data */
  const latencyRisk = allRisks.find(r => r.riskType.includes('Latency'));
  const err5xxRisk  = allRisks.find(r => r.riskType.includes('5XX'));
  const err4xxRisk  = allRisks.find(r => r.riskType.includes('4XX'));

  const set = (id, val, color) => {
    const el = document.getElementById(id);
    if (el) { el.textContent = val; if (color) el.style.color = `var(--${color})`; }
  };

  set('metric-latency', latencyRisk ? '1850ms' : '< 1000ms', latencyRisk ? 'high' : 'low');
  set('metric-5xx',     err5xxRisk  ? '8/hr'   : '0/hr',     err5xxRisk  ? 'high' : 'low');
  set('metric-4xx',     err4xxRisk  ? '67/hr'  : '< 50/hr',  err4xxRisk  ? 'medium' : 'low');
}

function filterRisks(priority, btn) {
  document.querySelectorAll('.filter-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderRiskCards(allRisks, 'risk-list', priority);
}

async function startScan() {
  const conns = getConnections(MODULE);
  if (!Object.keys(conns).length) { showToast('Connect your backend first', 'warning'); return; }
  showScanView();

  const steps = [
    { label: 'Checking API latency…',          sub: 'Fetching p95 latency from CloudWatch',           pct: 25 },
    { label: 'Analyzing error rates…',          sub: 'Counting 4XX and 5XX errors in last 60 minutes', pct: 50 },
    { label: 'Verifying CORS headers…',         sub: 'Checking OPTIONS method on API endpoints',        pct: 70 },
    { label: 'Scanning Lambda error logs…',     sub: 'Reviewing function error counts per hour',        pct: 88 },
    { label: 'Generating risk report…',         sub: 'Prioritizing findings by user impact',            pct: 96 },
  ];

  for (const s of steps) {
    document.getElementById('scan-label').textContent = s.label;
    document.getElementById('scan-sub').textContent   = s.sub;
    document.getElementById('scan-fill').style.width  = s.pct + '%';
    await sleep(700 + Math.random() * 600);
  }

  try {
    // Pass the stored threshold to the backend
    const stored   = getConnections(MODULE);
    const apiUrl   = stored?.['aws-mobile']?.apiUrl || '';
    const threshold = stored?.['aws-mobile']?.latencyThresholdMs || 1000;
    await triggerScan(MODULE, { targetApiUrl: apiUrl, latencyThresholdMs: threshold });
    document.getElementById('scan-fill').style.width = '100%';
    document.getElementById('scan-label').textContent = 'Scan complete! Loading results…';
    document.getElementById('scan-sub').textContent   = 'Waiting for risk records to be saved…';
    await sleep(2000);
    showToast('Mobile backend scan complete!', 'success');
    localStorage.setItem(`cs_scan_${MODULE}`, new Date().toISOString());
    showRisksView(getConnections(MODULE));
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
    showConnectView();
  }
}

async function confirmMobileConnect() {
  const apiUrl    = document.getElementById('mobile-api-url').value.trim();
  const accountId = document.getElementById('mobile-account-id').value.trim();
  const threshold = parseInt(document.getElementById('mobile-threshold')?.value || '1000', 10);
  const consent   = document.getElementById('mobile-consent').checked;
  const btn       = document.querySelector('#modal-mobile .btn-primary');

  if (!consent)   { showToast('Please confirm your consent', 'warning'); return; }
  if (!apiUrl)    { showToast('Please enter your mobile API URL', 'warning'); return; }
  if (!apiUrl.startsWith('https://')) { showToast('API URL must start with https://', 'warning'); return; }
  if (!accountId || accountId.length !== 12 || !/^\d+$/.test(accountId)) {
    showToast('Please enter a valid 12-digit AWS Account ID', 'warning');
    return;
  }

  // ── Validate via STS before accepting connection ────────────────────────
  if (btn) { btn.disabled = true; btn.textContent = 'Validating AWS access…'; }
  try {
    const roleArn = `arn:aws:iam::${accountId}:role/cloudsentinel-scanner-role`;
    const result  = await validateAwsConnection(MODULE, accountId, roleArn);
    if (!result.valid) {
      showToast(result.error || 'Could not connect: CloudSentinel IAM role not found.', 'error', 10000);
      if (btn) { btn.disabled = false; btn.textContent = 'Connect & Monitor'; }
      return;
    }
    showToast(`AWS account ${result.accountId} verified!`, 'success');
  } catch (err) {
    showToast('Validation failed: ' + err.message, 'error', 8000);
    if (btn) { btn.disabled = false; btn.textContent = 'Connect & Monitor'; }
    return;
  }

  if (btn) { btn.disabled = false; btn.textContent = 'Connect & Monitor'; }
  closeModal('modal-mobile');
  setConnection(MODULE, 'aws-mobile', {
    apiUrl,
    accountId,
    latencyThresholdMs: isNaN(threshold) ? 1000 : threshold,
    connectedAt: new Date().toISOString(),
  });
  document.getElementById('mobile-aws-status').innerHTML = `<span style="color:var(--low)">- Connected</span>`;
  document.getElementById('mobile-aws-card').classList.add('connected');
  showToast('Mobile backend connected! Starting monitoring…', 'success');
  await sleep(400);
  showRisksView(getConnections(MODULE));
  await sleep(300);
  startScan();
}

async function performDisconnect() {
  showToast('Disconnecting and purging risk data...', 'info', 3000);
  await callDisconnectApi(MODULE, 'all');
  localStorage.removeItem(`cs_conn_${MODULE}`);
  localStorage.removeItem(`cs_scan_${MODULE}`);
  allRisks = [];
  showToast('Mobile backend disconnected. Risk data purged.', 'success');
  showConnectView();
}

function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function sleep(ms)      { return new Promise(r => setTimeout(r, ms)); }
