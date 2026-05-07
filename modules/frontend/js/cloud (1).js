/**
 * cloud.js — Cloud Infrastructure module logic
 */

const MODULE = 'cloud-infra';
let allRisks      = [];
let selectedMethod = 'cfn';

/* ── Init ─────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initPage(MODULE);
  loadConnectionState();
});

/* ── Connection state ─────────────────────────────────────── */
function loadConnectionState() {
  const conns = getConnections(MODULE);
  const hasAws = conns.aws;
  const hasGcp = conns.gcp;

  if (hasAws || hasGcp) {
    showRisksView(conns);
  } else {
    showConnectView();
  }

  /* Button wiring */
  document.getElementById('btn-connect-aws').addEventListener('click', () => openModal('modal-aws'));
  document.getElementById('btn-connect-gcp').addEventListener('click', () => openModal('modal-gcp'));
  const disconnectBtn = document.getElementById('btn-disconnect');
  if (disconnectBtn) disconnectBtn.addEventListener('click', () => openModal('modal-disconnect'));

  const rescanBtn = document.getElementById('btn-rescan');
  if (rescanBtn) rescanBtn.addEventListener('click', startScan);
}

/* ── View switcher ────────────────────────────────────────── */
function showConnectView() {
  document.getElementById('view-connect').style.display = '';
  document.getElementById('view-scan').style.display    = 'none';
  document.getElementById('view-risks').style.display   = 'none';
  document.getElementById('header-actions').innerHTML   = '';

  /* Update provider card states */
  const conns = getConnections(MODULE);
  updateProviderCard('aws', !!conns.aws);
  updateProviderCard('gcp', !!conns.gcp);
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

  /* Header actions */
  document.getElementById('header-actions').innerHTML = `
    <button class="btn btn-outline btn-sm" onclick="showConnectView()">Manage Connections</button>
    <button class="btn btn-gradient btn-sm" onclick="startScan()">Rescan Now</button>`;

  /* Provider pills */
  const pills = document.getElementById('provider-pills');
  if (pills) {
    pills.innerHTML = Object.keys(conns).map(p => `
      <span style="display:inline-flex;align-items:center;gap:.4rem;padding:.3rem .75rem;border-radius:99px;background:var(--low-dim);color:var(--low);font-size:.78rem;font-weight:600">
        ${ p === 'aws' ? 'Amazon Web Services' : 'Google Cloud Platform' }
        <span style="color:var(--low)">[connected]</span>
      </span>`).join('');
  }

  /* Load risks */
  loadRisks();
}

function updateProviderCard(provider, connected) {
  const statusEl = document.getElementById(`${provider}-status`);
  const cardEl   = document.getElementById(`${provider}-card`);
  const btnEl    = document.getElementById(`btn-connect-${provider}`);

  if (!statusEl || !cardEl || !btnEl) return;

  if (connected) {
    statusEl.innerHTML = `<span style="color:var(--low)">● Connected</span>`;
    cardEl.classList.add('connected');
    btnEl.textContent = 'Reconnect';
    btnEl.className = 'btn btn-outline w-full';
  } else {
    statusEl.innerHTML = `<span style="color:var(--text-3)">● Not connected</span>`;
    cardEl.classList.remove('connected');
  }
}

/* ── Load risks ───────────────────────────────────────────── */
async function loadRisks() {
  document.getElementById('risk-list').innerHTML = `
    <div class="empty-state"><div class="empty-state-icon">...</div><div class="empty-state-title">Loading risks</div></div>`;

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
  if (!Object.keys(conns).length) {
    showToast('Connect at least one provider first', 'warning');
    return;
  }

  showScanView();
  const fill   = document.getElementById('scan-fill');
  const pct    = document.getElementById('scan-pct');
  const label  = document.getElementById('scan-label');
  const sub    = document.getElementById('scan-sub');

  const steps = [
    { label:'Checking S3 buckets…',          sub:'Verifying public access and encryption settings', pct:25 },
    { label:'Scanning security groups…',     sub:'Looking for open SSH/RDP ports to 0.0.0.0/0',    pct:50 },
    { label:'Reviewing IAM configuration…',  sub:'Checking account password policy',                pct:75 },
    { label:'Finalizing risk analysis…',     sub:'Saving detected risks and requesting AI explanations', pct:92 },
  ];

  for (const step of steps) {
    label.textContent = step.label;
    sub.textContent   = step.sub;
    fill.style.width  = step.pct + '%';
    pct.textContent   = step.pct + '%';
    await sleep(900 + Math.random() * 500);
  }

  try {
    await triggerScan(MODULE);
    fill.style.width = '100%';
    pct.textContent  = '100%';
    await sleep(400);
    showToast('Scan complete!', 'success');
    localStorage.setItem(`cs_scan_${MODULE}`, new Date().toISOString());
    showRisksView(getConnections(MODULE));
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
    showConnectView();
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ── Modal helpers ────────────────────────────────────────── */
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

/* AWS wizard */
function selectMethod(method) {
  selectedMethod = method;
  document.getElementById('method-cfn').style.borderColor = method==='cfn' ? 'var(--blue)' : 'var(--border)';
  document.getElementById('method-tf').style.borderColor  = method==='tf'  ? 'var(--blue)' : 'var(--border)';
}

function awsStep1() {
  ['aws-step-1','aws-step-2','aws-step-3'].forEach(id => document.getElementById(id).style.display='none');
  document.getElementById('aws-step-1').style.display='';
  setWizardStep(1);
}

function awsStep2() {
  ['aws-step-1','aws-step-2','aws-step-3'].forEach(id => document.getElementById(id).style.display='none');
  document.getElementById('aws-step-2').style.display='';
  setWizardStep(2);

  /* Build CloudFormation URL — values injected from env.js at deploy time */
  const TEMPLATE_URL = window.ENV_CFN_TEMPLATE_URL || '';
  const LAMBDA_ROLE  = window.ENV_LAMBDA_ROLE_ARN  || '';
  if (!TEMPLATE_URL) { showToast('CloudFormation template URL not configured.', 'error'); return; }
  const cfnParams = LAMBDA_ROLE
    ? `&param_CloudSentinelLambdaRoleArn=${encodeURIComponent(LAMBDA_ROLE)}&param_ExternalId=cloudsentinel`
    : '';
  const cfnUrl = `https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=${encodeURIComponent(TEMPLATE_URL)}&stackName=CloudSentinel-Scanner${cfnParams}`;
  document.getElementById('cfn-link').href = cfnUrl;
  document.getElementById('cfn-instructions').style.display = selectedMethod==='cfn' ? '' : 'none';
  document.getElementById('tf-instructions').style.display  = selectedMethod==='tf'  ? '' : 'none';
}

function awsStep3() {
  const accountId = document.getElementById('aws-account-id').value.trim();
  if (!accountId || accountId.length !== 12 || !/^\d+$/.test(accountId)) {
    showToast('Please enter your 12-digit AWS Account ID', 'warning');
    return;
  }
  ['aws-step-1','aws-step-2','aws-step-3'].forEach(id => document.getElementById(id).style.display='none');
  document.getElementById('aws-step-3').style.display='';
  setWizardStep(3);

  // Pre-fill expected Role ARN so user can verify
  const roleArnInput = document.getElementById('aws-role-arn');
  if (roleArnInput && !roleArnInput.value) {
    roleArnInput.value = `arn:aws:iam::${accountId}:role/cloudsentinel-scanner-role`;
  }

  const consentBox = document.getElementById('aws-consent');
  const confirmBtn = document.getElementById('btn-confirm-aws');
  if (consentBox && confirmBtn) {
    consentBox.addEventListener('change', () => { confirmBtn.disabled = !consentBox.checked; });
  }
}

function setWizardStep(n) {
  [1,2,3].forEach(i => {
    const el = document.getElementById(`ws-${i}`);
    el.className = 'wizard-step' + (i < n ? ' done' : i===n ? ' active' : '');
  });
}

async function confirmAwsConnect() {
  const accountId  = document.getElementById('aws-account-id').value.trim();
  const roleArnEl  = document.getElementById('aws-role-arn');
  const roleArn    = roleArnEl ? roleArnEl.value.trim() : `arn:aws:iam::${accountId}:role/cloudsentinel-scanner-role`;

  closeModal('modal-aws');
  setConnection(MODULE, 'aws', {
    accountId,
    roleArn,
    connectedAt:  new Date().toISOString(),
    method:       selectedMethod,
  });
  updateProviderCard('aws', true);
  showToast('AWS account connected! Starting first scan…', 'success');
  await sleep(500);
  showRisksView(getConnections(MODULE));
  await sleep(400);
  startScan();
}

async function confirmGcpConnect() {
  const projectId = document.getElementById('gcp-project-id').value.trim();
  const consent   = document.getElementById('gcp-consent').checked;
  const fileInput = document.getElementById('gcp-key-file');

  if (!projectId)   { showToast('Please enter your GCP Project ID', 'warning'); return; }
  if (!consent)     { showToast('Please confirm your consent', 'warning'); return; }
  if (!fileInput.files.length && !DEMO_MODE) { showToast('Please upload your service account JSON key', 'warning'); return; }

  closeModal('modal-gcp');
  setConnection(MODULE, 'gcp', { projectId, connectedAt: new Date().toISOString() });
  updateProviderCard('gcp', true);
  showToast('GCP project connected!', 'success');

  const conns = getConnections(MODULE);
  if (Object.keys(conns).length === 1) {
    /* First connection — go to scan */
    await sleep(400);
    showRisksView(conns);
    startScan();
  }
}

async function performDisconnect() {
  closeModal('modal-disconnect');
  localStorage.removeItem(`cs_conn_${MODULE}`);
  localStorage.removeItem(`cs_scan_${MODULE}`);
  allRisks = [];
  showToast('Access removed. CloudFormation stack can now be deleted from your AWS console.', 'info', 6000);
  await sleep(400);
  showConnectView();
}
