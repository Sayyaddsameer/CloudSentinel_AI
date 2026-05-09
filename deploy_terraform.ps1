#Requires -Version 5.1
<#
.SYNOPSIS
    CloudSentinel Terraform deployment wrapper for Windows PowerShell.

.DESCRIPTION
    Validates prerequisites, copies the tfvars example if not present,
    then runs terraform init, validate, and apply.

.PARAMETER Destroy
    Tear down all CloudSentinel resources. Requires typed confirmation.

.EXAMPLE
    .\deploy_terraform.ps1
    .\deploy_terraform.ps1 -Destroy
#>

param(
    [switch]$Destroy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TfDir      = Join-Path $ScriptDir "infrastructure\terraform"
$TfVars     = Join-Path $TfDir "terraform.tfvars"
$TfVarsEx   = Join-Path $TfDir "terraform.tfvars.example"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Log  { param([string]$Msg) Write-Host ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Msg) }
function Err  { param([string]$Msg) Write-Error $Msg; exit 1 }
function Hr   { Write-Host ("-" * 60) }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

Log "Checking prerequisites ..."

if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) { Err "terraform is not installed or not on PATH." }
if (-not (Get-Command aws      -ErrorAction SilentlyContinue)) { Err "aws CLI is not installed or not on PATH." }
if (-not (Get-Command python   -ErrorAction SilentlyContinue)) { Err "python is not installed or not on PATH." }

$TfVersion = (terraform version -json | python -c "import sys,json; print(json.load(sys.stdin)['terraform_version'])")
Log "Terraform version : $TfVersion"

$AwsAccount = aws sts get-caller-identity --query Account --output text 2>$null
if ($LASTEXITCODE -ne 0) {
    Err "AWS credentials are not configured. Run 'aws configure' or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY."
}
Log "AWS account       : $AwsAccount"

# ---------------------------------------------------------------------------
# tfvars check
# ---------------------------------------------------------------------------

if (-not (Test-Path $TfVars)) {
    Log "terraform.tfvars not found. Copying example ..."
    Copy-Item $TfVarsEx $TfVars
    Write-Host ""
    Log "ACTION REQUIRED: Edit '$TfVars' with your values, then re-run this script."
    exit 0
}

# ---------------------------------------------------------------------------
# Destroy path
# ---------------------------------------------------------------------------

if ($Destroy) {
    Log "DESTROY mode selected."
    $Confirm = Read-Host "  Type 'destroy' to confirm teardown of all CloudSentinel resources"
    if ($Confirm -ne "destroy") { Log "Destroy cancelled."; exit 0 }

    Set-Location $TfDir
    terraform init -reconfigure
    terraform destroy -var-file="$TfVars" -auto-approve
    Log "All resources destroyed."
    exit 0
}

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

Hr
Log "CloudSentinel Terraform Deployment"
Hr

Set-Location $TfDir

Log "Step 1/3 - terraform init"
terraform init -reconfigure
if ($LASTEXITCODE -ne 0) { Err "terraform init failed." }

Log "Step 2/3 - terraform validate"
terraform validate
if ($LASTEXITCODE -ne 0) { Err "terraform validate failed." }

Log "Step 3/3 - terraform apply"
terraform apply -var-file="$TfVars" -auto-approve
if ($LASTEXITCODE -ne 0) { Err "terraform apply failed." }

Hr
Log "Deployment complete. Outputs:"
Hr
terraform output
Hr
Log "ACTION REQUIRED: Confirm the SNS subscription email before alerts will be delivered."
