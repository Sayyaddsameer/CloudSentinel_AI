/**
 * global-connect.js — Dashboard-level AWS + GCP connection
 *
 * Stores one global AWS connection and one global GCP connection in localStorage.
 * All modules check these on load and skip their Step 1 if a global connection exists.
 *
 * localStorage keys:
 *   cs_global_aws  → { accountId, region, roleArn, connectedAt }
 *   cs_global_gcp  → { projectId, connectedAt }
 *
 * No values are hardcoded. roleArn is built from whatever accountId the user enters.
 */

/* ── Helpers ───────────────────────────────────────────────── */
function getGlobalAws() {
  try { return JSON.parse(localStorage.getItem('cs_global_aws') || 'null'); } catch { return null; }
}
function setGlobalAws(data) {
  localStorage.setItem('cs_global_aws', JSON.stringify(data));
  if (data?.region) localStorage.setItem('cs_aws_region', data.region);
}
function clearGlobalAws() {
  localStorage.removeItem('cs_global_aws');
}

function getGlobalGcp() {
  try { return JSON.parse(localStorage.getItem('cs_global_gcp') || 'null'); } catch { return null; }
}
function setGlobalGcp(data) {
  localStorage.setItem('cs_global_gcp', JSON.stringify(data));
}
function clearGlobalGcp() {
  localStorage.removeItem('cs_global_gcp');
}

/* ── Region options (shared, no hardcoding) ────────────────── */
const AWS_REGIONS = [
  ['us-east-1',      'US East (N. Virginia)'],
  ['us-east-2',      'US East (Ohio)'],
  ['us-west-1',      'US West (N. California)'],
  ['us-west-2',      'US West (Oregon)'],
  ['ap-south-1',     'Asia Pacific (Mumbai)'],
  ['ap-southeast-1', 'Asia Pacific (Singapore)'],
  ['ap-southeast-2', 'Asia Pacific (Sydney)'],
  ['ap-northeast-1', 'Asia Pacific (Tokyo)'],
  ['ap-northeast-2', 'Asia Pacific (Seoul)'],
  ['eu-west-1',      'Europe (Ireland)'],
  ['eu-west-2',      'Europe (London)'],
  ['eu-central-1',   'Europe (Frankfurt)'],
  ['eu-north-1',     'Europe (Stockholm)'],
  ['sa-east-1',      'South America (São Paulo)'],
  ['ca-central-1',   'Canada (Central)'],
];

function buildRegionOptions(selectedValue) {
  return AWS_REGIONS.map(([v, l]) =>
    `<option value="${v}" ${v === selectedValue ? 'selected' : ''}>${v} — ${l}</option>`
  ).join('');
}

/* ── Dashboard card renderer ───────────────────────────────── */
function renderGlobalConnectSection() {
  const container = document.getElementById('global-connect-section');
  if (!container) return;

  const aws = getGlobalAws();
  const gcp = getGlobalGcp();

  const awsCard = aws
    ? `<div class="provider-card connected" style="flex:1;min-width:220px">
         <div class="provider-logo">AWS</div>
         <div class="provider-name">Amazon Web Services</div>
         <div class="provider-status"><span style="color:var(--low)">&#9679; Connected</span></div>
         <div class="form-hint" style="margin:.25rem 0">${aws.accountId} &middot; ${aws.region}</div>
         <button class="btn btn-outline btn-sm w-full" onclick="disconnectGlobalAws()">Disconnect</button>
       </div>`
    : `<div class="provider-card" style="flex:1;min-width:220px">
         <div class="provider-logo">AWS</div>
         <div class="provider-name">Amazon Web Services</div>
         <div class="provider-desc">Connect once — reused by Cloud Infra, Fullstack, Mobile and Data Engineering modules.</div>
         <div class="provider-status"><span style="color:var(--text-3)">&#9679; Not connected</span></div>
         <button class="btn btn-primary w-full" onclick="openGlobalAwsModal()">Connect AWS</button>
       </div>`;

  const gcpCard = gcp
    ? `<div class="provider-card connected" style="flex:1;min-width:220px">
         <div class="provider-logo">GCP</div>
         <div class="provider-name">Google Cloud Platform</div>
         <div class="provider-status"><span style="color:var(--low)">&#9679; Connected</span></div>
         <div class="form-hint" style="margin:.25rem 0">${gcp.projectId}</div>
         <button class="btn btn-outline btn-sm w-full" onclick="disconnectGlobalGcp()">Disconnect</button>
       </div>`
    : `<div class="provider-card" style="flex:1;min-width:220px">
         <div class="provider-logo">GCP</div>
         <div class="provider-name">Google Cloud Platform</div>
         <div class="provider-desc">Connect once — reused by Cloud Infrastructure module for GCP scanning.</div>
         <div class="provider-status"><span style="color:var(--text-3)">&#9679; Not connected</span></div>
         <button class="btn btn-primary w-full" onclick="openGlobalGcpModal()">Connect GCP</button>
       </div>`;

  container.innerHTML = `
    <div class="card" style="margin-bottom:1.5rem">
      <div style="padding:1.25rem 1.5rem;border-bottom:1px solid var(--border)">
        <div class="card-title">Quick Connect</div>
        <div class="card-subtitle">Connect your cloud accounts once here — all modules reuse these credentials automatically</div>
      </div>
      <div style="padding:1.25rem 1.5rem;display:flex;gap:1rem;flex-wrap:wrap">
        ${awsCard}
        ${gcpCard}
      </div>
    </div>`;
}

/* ── Global AWS Modal ──────────────────────────────────────── */
function openGlobalAwsModal() {
  // Inject modal if not already present
  if (!document.getElementById('modal-global-aws')) {
    const el = document.createElement('div');
    el.innerHTML = _globalAwsModalHtml();
    document.body.appendChild(el.firstElementChild);
  }
  _resetGlobalAwsModal();
  document.getElementById('modal-global-aws').classList.add('open');
}

function _globalAwsModalHtml() {
  return `
<div class="modal-overlay" id="modal-global-aws">
  <div class="modal" style="max-width:560px">
    <div class="modal-header">
      <div>
        <div class="modal-title">Connect AWS Account</div>
        <div class="modal-subtitle" id="gaws-modal-sub">Step 1 of 2 — Deploy scanner role</div>
      </div>
      <span class="modal-close" onclick="_closeGlobalAwsModal()">X</span>
    </div>
    <div class="modal-body">
      <div id="gaws-step-1">
        <div class="info-box mb-3" style="border-color:var(--accent)">
          <span class="info-icon">&#9888;</span>
          <div>
            CloudSentinel needs a <strong>read-only IAM role</strong> in your AWS account.
            Deploy the scanner CloudFormation stack once — it creates the role automatically.
            All modules (Cloud Infra, Fullstack, Mobile, Data Engineering) will reuse it.
            <br><br>
            <strong>Already deployed it?</strong> Just enter your Account ID below.
          </div>
        </div>
        <div style="margin-bottom:1rem">
          <a id="gaws-cfn-link" href="#" target="_blank" class="btn btn-outline w-full" style="justify-content:center">
            &#9654; Deploy CloudSentinel Scanner Stack
          </a>
          <div class="form-hint" style="text-align:center;margin-top:.4rem">Opens AWS CloudFormation — takes ~30 seconds</div>
        </div>
        <div class="form-group">
          <label class="form-label">AWS Account ID</label>
          <input class="form-input" id="gaws-account-id" placeholder="{your 12-digit account ID}" maxlength="12" autocomplete="off">
          <span class="form-hint">Found in the AWS console — top-right account menu</span>
        </div>
        <div class="form-group">
          <label class="form-label">AWS Region (primary region for your resources)</label>
          <select class="form-input" id="gaws-region">${buildRegionOptions(localStorage.getItem('cs_aws_region') || 'us-east-1')}</select>
        </div>
      </div>
      <div id="gaws-step-2" style="display:none">
        <div class="info-box mb-3">
          <span class="info-icon">&#10003;</span>
          <div>
            CloudSentinel will use <strong>read-only</strong> access to scan your AWS resources.
            No data is modified. Access can be revoked anytime by deleting the CloudFormation stack.
          </div>
        </div>
        <div class="card" style="padding:.875rem 1rem;margin-bottom:1rem;background:var(--surface-2)">
          <div class="form-hint" style="margin:0">Account ID: <strong id="gaws-confirm-acct"></strong></div>
          <div class="form-hint" style="margin:.25rem 0 0">Region: <strong id="gaws-confirm-region"></strong></div>
          <div class="form-hint" style="margin:.25rem 0 0">Role ARN: <code id="gaws-confirm-arn" style="font-size:.75rem;word-break:break-all"></code></div>
        </div>
        <label class="checkbox-group">
          <input type="checkbox" id="gaws-consent">
          <span class="form-hint">I confirm the CloudSentinel scanner stack is deployed in my account and I authorize CloudSentinel to perform read-only scans.</span>
        </label>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" id="gaws-btn-back" style="display:none" onclick="_gawsGoBack()">&larr; Back</button>
      <button class="btn btn-outline" onclick="_closeGlobalAwsModal()">Cancel</button>
      <button class="btn btn-primary" id="gaws-btn-next" onclick="_gawsNextStep()">Next &rarr;</button>
    </div>
  </div>
</div>`;
}

function _resetGlobalAwsModal() {
  document.getElementById('gaws-step-1').style.display   = '';
  document.getElementById('gaws-step-2').style.display   = 'none';
  document.getElementById('gaws-btn-back').style.display = 'none';
  document.getElementById('gaws-btn-next').textContent   = 'Next →';
  document.getElementById('gaws-btn-next').onclick       = _gawsNextStep;
  document.getElementById('gaws-modal-sub').textContent  = 'Step 1 of 2 — Deploy scanner role';
  document.getElementById('gaws-consent').checked        = false;

  // Build CFN link from S3 template URL — no hardcoded account or region
  const cfnBase  = 'https://console.aws.amazon.com/cloudformation/home#/stacks/create/review';
  const tplUrl   = typeof CFN_TEMPLATE_URL !== 'undefined' ? CFN_TEMPLATE_URL
                 : (typeof window.ENV_CFN_TEMPLATE_URL !== 'undefined' ? window.ENV_CFN_TEMPLATE_URL : '');
  const cfnHref  = tplUrl
    ? `${cfnBase}?templateURL=${encodeURIComponent(tplUrl)}&stackName=CloudSentinel-Scanner`
    : cfnBase;
  document.getElementById('gaws-cfn-link').href = cfnHref;
}

function _closeGlobalAwsModal() {
  document.getElementById('modal-global-aws')?.classList.remove('open');
}

function _gawsGoBack() {
  document.getElementById('gaws-step-1').style.display   = '';
  document.getElementById('gaws-step-2').style.display   = 'none';
  document.getElementById('gaws-btn-back').style.display = 'none';
  document.getElementById('gaws-btn-next').textContent   = 'Next →';
  document.getElementById('gaws-btn-next').onclick       = _gawsNextStep;
  document.getElementById('gaws-modal-sub').textContent  = 'Step 1 of 2 — Deploy scanner role';
}

function _gawsNextStep() {
  const accountId = document.getElementById('gaws-account-id').value.trim();
  if (!/^\d{12}$/.test(accountId)) {
    if (typeof showToast === 'function') showToast('Account ID must be exactly 12 digits', 'warning');
    return;
  }
  const region  = document.getElementById('gaws-region').value;
  const roleArn = `arn:aws:iam::${accountId}:role/cloudsentinel-scanner-role`;

  document.getElementById('gaws-confirm-acct').textContent   = accountId;
  document.getElementById('gaws-confirm-region').textContent = region;
  document.getElementById('gaws-confirm-arn').textContent    = roleArn;

  document.getElementById('gaws-step-1').style.display   = 'none';
  document.getElementById('gaws-step-2').style.display   = '';
  document.getElementById('gaws-btn-back').style.display = '';
  document.getElementById('gaws-modal-sub').textContent  = 'Step 2 of 2 — Confirm access';
  document.getElementById('gaws-btn-next').textContent   = 'Connect AWS';
  document.getElementById('gaws-btn-next').onclick       = _gawsConfirm;
}

function _gawsConfirm() {
  const consent   = document.getElementById('gaws-consent').checked;
  if (!consent) {
    if (typeof showToast === 'function') showToast('Please confirm your consent', 'warning');
    return;
  }
  const accountId = document.getElementById('gaws-confirm-acct').textContent;
  const region    = document.getElementById('gaws-confirm-region').textContent;
  const roleArn   = document.getElementById('gaws-confirm-arn').textContent;

  setGlobalAws({ accountId, region, roleArn, connectedAt: new Date().toISOString() });
  _closeGlobalAwsModal();
  if (typeof showToast === 'function') showToast(`AWS account connected globally (${region})`, 'success');
  renderGlobalConnectSection();
}

function disconnectGlobalAws() {
  clearGlobalAws();
  if (typeof showToast === 'function') showToast('AWS global connection removed', 'info');
  renderGlobalConnectSection();
}

/* ── Global GCP Modal ──────────────────────────────────────── */
function openGlobalGcpModal() {
  if (!document.getElementById('modal-global-gcp')) {
    const el = document.createElement('div');
    el.innerHTML = _globalGcpModalHtml();
    document.body.appendChild(el.firstElementChild);
  }
  document.getElementById('modal-global-gcp').classList.add('open');
  document.getElementById('ggcp-project-id').value = '';
  document.getElementById('ggcp-key-filename').textContent = 'No file chosen';
  document.getElementById('ggcp-consent').checked = false;
  window._ggcpKeyContent = null;
}

function _globalGcpModalHtml() {
  return `
<div class="modal-overlay" id="modal-global-gcp">
  <div class="modal" style="max-width:520px">
    <div class="modal-header">
      <div><div class="modal-title">Connect GCP Project</div><div class="modal-subtitle">Upload a service account key with Viewer permissions</div></div>
      <span class="modal-close" onclick="_closeGlobalGcpModal()">X</span>
    </div>
    <div class="modal-body">
      <div class="info-box mb-3">
        <span class="info-icon">[lock]</span>
        <div>
          Create a GCP service account with the <strong>Viewer</strong> role, download the JSON key, and upload it here.
          <br><br>Steps:
          <ol style="margin:.5rem 0 0 1.2rem;padding:0;font-size:.8rem">
            <li>GCP Console &rarr; IAM &amp; Admin &rarr; Service Accounts &rarr; Create Service Account</li>
            <li>Assign the Viewer role (<code>roles/viewer</code>)</li>
            <li>Keys tab &rarr; Add Key &rarr; Create new key &rarr; JSON &rarr; Download</li>
            <li>Upload the JSON file below</li>
          </ol>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">GCP Project ID</label>
        <input class="form-input" id="ggcp-project-id" placeholder="{your-gcp-project-id}" autocomplete="off">
      </div>
      <div class="form-group">
        <label class="form-label">Service Account Key (JSON)</label>
        <label class="btn btn-outline" style="cursor:pointer;display:inline-flex;align-items:center;gap:.5rem">
          &#128206; Choose File
          <input type="file" accept=".json" style="display:none" onchange="_ggcpFileChange(this)">
        </label>
        <span class="form-hint" id="ggcp-key-filename" style="margin-left:.5rem">No file chosen</span>
      </div>
      <label class="checkbox-group">
        <input type="checkbox" id="ggcp-consent">
        <span class="form-hint">I authorize CloudSentinel to use this key for read-only GCP scanning. The key is handled in-memory only.</span>
      </label>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="_closeGlobalGcpModal()">Cancel</button>
      <button class="btn btn-primary" onclick="_ggcpConfirm()">Connect GCP</button>
    </div>
  </div>
</div>`;
}

function _ggcpFileChange(input) {
  const file = input.files[0];
  if (!file) return;
  document.getElementById('ggcp-key-filename').textContent = file.name;
  const reader = new FileReader();
  reader.onload = e => { window._ggcpKeyContent = e.target.result; };
  reader.readAsText(file);
}

function _closeGlobalGcpModal() {
  document.getElementById('modal-global-gcp')?.classList.remove('open');
}

function _ggcpConfirm() {
  const projectId = document.getElementById('ggcp-project-id').value.trim();
  const consent   = document.getElementById('ggcp-consent').checked;
  if (!projectId)           { if (typeof showToast === 'function') showToast('Enter your GCP Project ID', 'warning'); return; }
  if (!window._ggcpKeyContent) { if (typeof showToast === 'function') showToast('Please upload a service account JSON key', 'warning'); return; }
  if (!consent)             { if (typeof showToast === 'function') showToast('Please confirm your consent', 'warning'); return; }

  setGlobalGcp({ projectId, connectedAt: new Date().toISOString() });
  // Key content stored only in session — not persisted to localStorage
  window._gcpKeySession = window._ggcpKeyContent;
  _closeGlobalGcpModal();
  if (typeof showToast === 'function') showToast(`GCP project connected (${projectId})`, 'success');
  renderGlobalConnectSection();
}

function disconnectGlobalGcp() {
  clearGlobalGcp();
  window._gcpKeySession = null;
  if (typeof showToast === 'function') showToast('GCP global connection removed', 'info');
  renderGlobalConnectSection();
}

/* ── Auto-init on dashboard page ───────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  renderGlobalConnectSection();
});
