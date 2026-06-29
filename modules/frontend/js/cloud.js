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
  document.getElementById('btn-connect-aws').addEventListener('click', () => {
    openModal('modal-aws');
    // If globally connected from dashboard, skip straight to Step 3 (consent)
    const gAws = getGlobalAws ? getGlobalAws() : null;
    if (gAws) {
      // Pre-fill account ID and region from global connection
      const acctEl = document.getElementById('aws-account-id');
      const regionEl = document.getElementById('aws-target-region');
      if (acctEl)   acctEl.value   = gAws.accountId;
      if (regionEl) regionEl.value = gAws.region;
      // Jump straight to consent step
      _cloudSkipToStep3(gAws);
    } else {
      awsStep1();
    }
  });

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

  /* Show "View Previous" button in header if previous data exists */
  const prev = getPreviousRisks(MODULE);
  if (prev) {
    document.getElementById('header-actions').innerHTML = `
      <button class="btn btn-outline btn-sm" id="btn-view-previous-header" onclick="showPreviousRisks()">View Previous Scan</button>`;
  } else {
    document.getElementById('header-actions').innerHTML = '';
  }

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

  /* Header actions — include "Previous" button if data exists */
  const prev = getPreviousRisks(MODULE);
  const prevBtn = prev
    ? `<button class="btn btn-outline btn-sm" onclick="showPreviousRisks()">Previous Scan</button>`
    : '';
  document.getElementById('header-actions').innerHTML = `
    ${prevBtn}
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
  /* Save current risks as "previous" before fetching new ones */
  if (allRisks.length > 0) {
    savePreviousRisks(MODULE, allRisks);
  }

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

    /* Update "Previous Scan" button visibility in header */
    refreshHeaderActions();
  } catch (e) {
    showToast('Failed to load risks: ' + e.message, 'error');
  }
}

/* ── Refresh header actions (updates Previous button visibility) ── */
function refreshHeaderActions() {
  const prev = getPreviousRisks(MODULE);
  const prevBtn = prev
    ? `<button class="btn btn-outline btn-sm" onclick="showPreviousRisks()">Previous Scan</button>`
    : '';
  document.getElementById('header-actions').innerHTML = `
    ${prevBtn}
    <button class="btn btn-outline btn-sm" onclick="showConnectView()">Manage Connections</button>
    <button class="btn btn-gradient btn-sm" onclick="startScan()">Rescan Now</button>`;
}

/* ── Previous Risks Viewer ───────────────────────────────── */
function showPreviousRisks() {
  const prev = getPreviousRisks(MODULE);
  if (!prev) { showToast('No previous scan data available', 'info'); return; }

  const section = document.getElementById('previous-risks-section');
  if (!section) return;

  section.style.display = '';
  document.getElementById('prev-scan-time').textContent = new Date(prev.timestamp).toLocaleString();
  document.getElementById('prev-stat-total').textContent = prev.total;
  document.getElementById('prev-stat-high').textContent = prev.high;
  document.getElementById('prev-stat-medium').textContent = prev.medium;
  document.getElementById('prev-stat-low').textContent = prev.low;
  renderRiskCards(prev.risks, 'previous-risk-list');

  /* Scroll into view */
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hidePreviousRisks() {
  const section = document.getElementById('previous-risks-section');
  if (section) section.style.display = 'none';
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

  /* Save current risks as "previous" before rescanning */
  if (allRisks.length > 0) {
    savePreviousRisks(MODULE, allRisks);
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
    label.textContent = 'Scan complete! Loading results…';
    sub.textContent   = 'Waiting for risk records to be saved…';
    await sleep(2000);   // give DynamoDB writes time to propagate
    showToast('Scan complete!', 'success');
    localStorage.setItem(`cs_scan_${MODULE}`, new Date().toISOString());

    /* Reset allRisks so loadRisks fetches fresh from API */
    allRisks = [];
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

function _cloudSkipToStep3(gAws) {
  ['aws-step-1','aws-step-2','aws-step-3'].forEach(id => document.getElementById(id).style.display='none');
  document.getElementById('aws-step-3').style.display='';
  setWizardStep(3);

  const roleArnInput = document.getElementById('aws-role-arn');
  if (roleArnInput) roleArnInput.value = gAws.roleArn;

  // Inject banner if not already there
  const step3 = document.getElementById('aws-step-3');
  if (step3 && !document.getElementById('cloud-global-banner')) {
    const banner = document.createElement('div');
    banner.id = 'cloud-global-banner';
    banner.className = 'info-box';
    banner.style.cssText = 'border-color:var(--low);margin-bottom:1rem';
    banner.innerHTML = `<span class="info-icon">&#10003;</span><div>Using your globally connected AWS account &middot; <strong>${gAws.accountId}</strong> &middot; <strong>${gAws.region}</strong>. Confirm consent below to start scanning.</div>`;
    step3.prepend(banner);
  }

  const consentBox = document.getElementById('aws-consent');
  const confirmBtn = document.getElementById('btn-confirm-aws');
  if (consentBox && confirmBtn) {
    confirmBtn.disabled = !consentBox.checked;
    consentBox.addEventListener('change', () => { confirmBtn.disabled = !consentBox.checked; });
  }
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

  /* Default the region picker to the client's last choice (or us-east-1) */
  const sel = document.getElementById('aws-target-region');
  if (sel) {
    const saved = localStorage.getItem('cs_aws_region');
    if (saved) sel.value = saved;
  }
  updateCfnLinks();

  document.getElementById('cfn-instructions').style.display = selectedMethod==='cfn' ? '' : 'none';
  document.getElementById('tf-instructions').style.display  = selectedMethod==='tf'  ? '' : 'none';
}

/* Build the CloudFormation deep-link + CLI snippet from the CLIENT-selected
 * region (not the platform's ENV_REGION). Re-runs whenever the region
 * dropdown changes, and remembers the choice for the disconnect step. */
function updateCfnLinks() {
  const TEMPLATE_URL  = window.ENV_CFN_TEMPLATE_URL  || '';
  const PLATFORM_ACCT = window.ENV_PLATFORM_ACCOUNT_ID || '871070087236';
  const LAMBDA_ROLE   = window.ENV_LAMBDA_ROLE_NAME    || 'cloudsentinel-lambda-role';
  const sel    = document.getElementById('aws-target-region');
  const REGION = (sel && sel.value) || window.ENV_REGION || 'us-east-1';
  localStorage.setItem('cs_aws_region', REGION);
  if (!TEMPLATE_URL) { showToast('CloudFormation template URL not configured. Set ENV_CFN_TEMPLATE_URL in env.js.', 'error'); return; }

  // Pre-fill all CFN parameters — user just clicks through without typing anything
  const cfnParams = [
    `param_CloudSentinelAccountId=${encodeURIComponent(PLATFORM_ACCT)}`,
    `param_CloudSentinelLambdaRoleName=${encodeURIComponent(LAMBDA_ROLE)}`,
    `param_ExternalId=cloudsentinel`,
  ].map(p => `&${p}`).join('');

  const cfnUrl = `https://${REGION}.console.aws.amazon.com/cloudformation/home?region=${REGION}#/stacks/create/review?templateURL=${encodeURIComponent(TEMPLATE_URL)}&stackName=CloudSentinel-Scanner${cfnParams}`;
  const link = document.getElementById('cfn-link');
  if (link) link.href = cfnUrl;

  const cliCmd = document.getElementById('cfn-cli-cmd');
  if (cliCmd) {
    cliCmd.textContent = `aws cloudformation create-stack \\\n  --stack-name CloudSentinel-Scanner \\\n  --template-url ${TEMPLATE_URL} \\\n  --capabilities CAPABILITY_NAMED_IAM \\\n  --parameters \\\n    ParameterKey=CloudSentinelAccountId,ParameterValue=<platform-account-id> \\\n    ParameterKey=CloudSentinelLambdaRoleName,ParameterValue=cloudsentinel-lambda-role \\\n    ParameterKey=ExternalId,ParameterValue=cloudsentinel \\\n  --region ${REGION}`;
  }

  const disc = document.getElementById('disconnect-cli-cmd');
  if (disc) {
    disc.textContent = `aws cloudformation delete-stack \\\n  --stack-name CloudSentinel-Scanner \\\n  --region ${REGION}`;
  }
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
  const confirmBtn = document.getElementById('btn-confirm-aws');

  // Basic client-side check — 12-digit AWS account ID
  if (!/^\d{12}$/.test(accountId)) {
    showToast('Please enter a valid 12-digit AWS account ID.', 'error', 6000);
    return;
  }

  if (confirmBtn) { confirmBtn.disabled = true; confirmBtn.textContent = 'Connecting…'; }
  closeModal('modal-aws');
  setConnection(MODULE, 'aws', {
    accountId,
    roleArn,
    connectedAt:  new Date().toISOString(),
    method:       selectedMethod,
  });
  updateProviderCard('aws', true);
  showToast('AWS account connected! Starting first scan…', 'success');

  /* Clear stale risk data so fresh scan results load cleanly */
  allRisks = [];

  /* Go directly to scan instead of showing stale risks first */
  await sleep(500);
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
  if (Object.keys(conns).length >= 1) {
    /* Clear stale data and go directly to scan */
    allRisks = [];
    await sleep(400);
    startScan();
  }
}

async function performDisconnect() {
  closeModal('modal-disconnect');

  /* ── Save current risks as "previous" BEFORE clearing ──────── */
  if (allRisks.length > 0) {
    savePreviousRisks(MODULE, allRisks);
  }

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

  /* Hide previous risks panel (user can re-open via button) */
  hidePreviousRisks();

  if (result) {
    const awsStatus = result.aws;
    const gcpStatus = result.gcp;

    if (awsStatus === 'delete_initiated') {
      showToast('AWS CloudFormation stack deletion initiated. The IAM role will be removed within minutes.', 'success', 8000);
    } else if (awsStatus === 'already_deleted') {
      showToast('AWS access already removed.', 'success');
    } else if (awsStatus === 'instructions') {
      const REGION = localStorage.getItem('cs_aws_region') || window.ENV_REGION || 'us-east-1';
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
