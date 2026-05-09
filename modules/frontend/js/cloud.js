/**
 * cloud.js -- Cloud Infrastructure module logic
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
    statusEl.innerHTML = `<span style="color:var(--low)">- Connected</span>`;
    cardEl.classList.add('connected');
    btnEl.textContent = 'Reconnect';
    btnEl.className = 'btn btn-outline w-full';
  } else {
    statusEl.innerHTML = `<span style="color:var(--text-3)">- Not connected</span>`;
    cardEl.classList.remove('connected');
  }
}

/* ── Load risks ─────────────────────────────────────────────── */
async function loadRisks() {
  document.getElementById('risk-list').innerHTML = `
    <div class="empty-state"><div class="empty-state-icon">...</div><div class="empty-state-title">Loading risks</div></div>`;

  try {
    allRisks = await fetchRisks(MODULE);
    updateStats(allRisks);
    renderRiskCards(allRisks, 'risk-list');
    document.getElementById('last-scan-time').textContent = new Date().toLocaleTimeString();

    /* Record to history and render scan history timeline */
    recordScanToHistory(MODULE, allRisks);
    renderScanHistory();
  } catch (e) {
    showToast('Failed to load risks: ' + e.message, 'error');
  }
}

/* ── Scan History Timeline ───────────────────────────────── */
function renderScanHistory() {
  const history = getModuleHistory(MODULE, 5);
  const section = document.getElementById('risk-history-section');
  const list    = document.getElementById('risk-history-list');
  const counter = document.getElementById('history-scan-count');
  if (!section || !list) return;
  if (history.length < 2) { section.style.display = 'none'; return; }

  section.style.display = '';
  if (counter) counter.textContent = `${history.length} scan${history.length > 1 ? 's' : ''} recorded`;

  const maxTotal = Math.max(...history.map(h => h.total), 1);

  list.innerHTML = history.map((h, i) => {
    const d   = new Date(h.timestamp);
    const lbl = i === 0 ? 'Latest' : d.toLocaleString('en-IN', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' });
    const highPct   = Math.round((h.high   / maxTotal) * 100);
    const medPct    = Math.round((h.medium / maxTotal) * 100);
    const lowPct    = Math.round((h.low    / maxTotal) * 100);
    const borderStyle = i === 0 ? 'border-color:var(--blue)' : '';
    return `
      <div class="risk-snapshot" style="${borderStyle}">
        <div class="risk-snapshot-date">${lbl}</div>
        <div class="risk-snapshot-bars">
          <div class="risk-bar-row"><div class="risk-bar-label">High</div><div class="risk-bar-track"><div class="risk-bar-fill high" style="width:${highPct}%"></div></div><div class="risk-bar-count">${h.high}</div></div>
          <div class="risk-bar-row"><div class="risk-bar-label">Med</div><div class="risk-bar-track"><div class="risk-bar-fill medium" style="width:${medPct}%"></div></div><div class="risk-bar-count">${h.medium}</div></div>
          <div class="risk-bar-row"><div class="risk-bar-label">Low</div><div class="risk-bar-track"><div class="risk-bar-fill low" style="width:${lowPct}%"></div></div><div class="risk-bar-count">${h.low}</div></div>
        </div>
        <div class="risk-snapshot-total">${h.total} total</div>
      </div>`;
  }).join('');
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

  /* Build CloudFormation URL -- values injected from env.js at deploy time */
  const TEMPLATE_URL = window.ENV_CFN_TEMPLATE_URL || '';
  const LAMBDA_ROLE  = window.ENV_LAMBDA_ROLE_ARN  || '';
  const REGION       = window.ENV_REGION            || 'us-east-1';
  if (!TEMPLATE_URL) { showToast('CloudFormation template URL not configured. Set ENV_CFN_TEMPLATE_URL in env.js.', 'error'); return; }
  const cfnParams = LAMBDA_ROLE
    ? `&param_CloudSentinelLambdaRoleArn=${encodeURIComponent(LAMBDA_ROLE)}&param_ExternalId=cloudsentinel`
    : '';
  const cfnUrl = `https://${REGION}.console.aws.amazon.com/cloudformation/home?region=${REGION}#/stacks/create/review?templateURL=${encodeURIComponent(TEMPLATE_URL)}&stackName=CloudSentinel-Scanner${cfnParams}`;
  document.getElementById('cfn-link').href = cfnUrl;

  /* Update CLI command snippet dynamically */
  const cliCmd = document.getElementById('cfn-cli-cmd');
  if (cliCmd) {
    cliCmd.textContent = `aws cloudformation create-stack \\\n  --stack-name CloudSentinel-Scanner \\\n  --template-url ${TEMPLATE_URL} \\\n  --capabilities CAPABILITY_NAMED_IAM \\\n  --region ${REGION}`;
  }

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

  if (!projectId) { showToast('Please enter your GCP Project ID', 'warning'); return; }
  if (!consent)   { showToast('Please confirm your consent', 'warning'); return; }
  if (!fileInput.files.length) { showToast('Please upload your service account JSON key', 'warning'); return; }

  closeModal('modal-gcp');
  setConnection(MODULE, 'gcp', { projectId, connectedAt: new Date().toISOString() });
  updateProviderCard('gcp', true);
  showToast('GCP project connected!', 'success');

  const conns = getConnections(MODULE);
  if (Object.keys(conns).length === 1) {
    /* First connection -- go to scan */
    await sleep(400);
    showRisksView(conns);
    startScan();
  }
}

async function performDisconnect() {
  closeModal('modal-disconnect');

  const conn = getConnections(MODULE);
  const hasAws = !!conn?.aws;
  const hasGcp = !!conn?.gcp;
  const provider = (hasAws && hasGcp) ? 'all' : hasAws ? 'aws' : hasGcp ? 'gcp' : 'all';

  showToast('Revoking access and cleaning up...', 'info', 4000);

  /* Call backend: delete CFN stack + GCP secret + DynamoDB risks */
  const result = await callDisconnectApi(MODULE, provider);

  /* Clear local state regardless of API result */
  localStorage.removeItem(`cs_conn_${MODULE}`);
  localStorage.removeItem(`cs_scan_${MODULE}`);
  allRisks = [];

  if (result) {
    const awsStatus = result.aws;
    const gcpStatus = result.gcp;

    if (awsStatus === 'delete_initiated') {
      showToast('AWS CloudFormation stack deletion initiated. The IAM role will be removed within minutes.', 'success', 8000);
    } else if (awsStatus === 'already_deleted') {
      showToast('AWS access already removed.', 'success');
    } else if (awsStatus === 'instructions') {
      const REGION = window.ENV_REGION || 'us-east-1';
      showToast(
        `Could not auto-delete stack. Run: aws cloudformation delete-stack --stack-name CloudSentinel-Scanner --region ${REGION}`,
        'warning', 12000
      );
    }

    if (gcpStatus === 'deleted') {
      showToast('GCP credentials removed from secure storage.', 'success', 4000);
    }

    if (result.risks_purged > 0) {
      showToast(`${result.risks_purged} risk records purged.`, 'info', 4000);
    }
  } else {
    showToast('Access removed locally. Backend cleanup may have failed - check your AWS account.', 'warning', 6000);
  }

  await sleep(400);
  showConnectView();
}
