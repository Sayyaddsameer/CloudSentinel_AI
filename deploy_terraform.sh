#!/usr/bin/env bash
# deploy_terraform.sh — CloudSentinel Terraform deployment wrapper
# Usage: bash deploy_terraform.sh [--destroy]
# Requires: terraform >= 1.6, aws CLI, python3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/infrastructure/terraform"
TFVARS="${TF_DIR}/terraform.tfvars"
TFVARS_EXAMPLE="${TF_DIR}/terraform.tfvars.example"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf "[%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
err()  { log "ERROR: $*" >&2; exit 1; }
hr()   { printf '%0.s-' {1..60}; printf '\n'; }

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

log "Checking prerequisites ..."

command -v terraform >/dev/null 2>&1 || err "terraform is not installed or not on PATH."
command -v aws       >/dev/null 2>&1 || err "aws CLI is not installed or not on PATH."
command -v python3   >/dev/null 2>&1 || err "python3 is not installed or not on PATH."

TF_VERSION=$(terraform version -json | python3 -c "import sys,json; print(json.load(sys.stdin)['terraform_version'])")
log "Terraform version : ${TF_VERSION}"

AWS_IDENTITY=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null) \
  || err "AWS credentials are not configured. Run 'aws configure' or export AWS_* variables."
log "AWS account       : ${AWS_IDENTITY}"

# ---------------------------------------------------------------------------
# Variable file check
# ---------------------------------------------------------------------------

if [[ ! -f "${TFVARS}" ]]; then
  log "terraform.tfvars not found. Copying example file ..."
  cp "${TFVARS_EXAMPLE}" "${TFVARS}"
  printf "\n"
  log "ACTION REQUIRED: Edit '${TFVARS}' with your values, then re-run this script."
  exit 0
fi

# ---------------------------------------------------------------------------
# Destroy path
# ---------------------------------------------------------------------------

if [[ "${1:-}" == "--destroy" ]]; then
  log "DESTROY mode selected."
  read -r -p "  Type 'destroy' to confirm teardown of all CloudSentinel resources: " confirm
  [[ "${confirm}" == "destroy" ]] || err "Destroy cancelled."
  cd "${TF_DIR}"
  terraform init -reconfigure
  terraform destroy -var-file="${TFVARS}" -auto-approve
  log "All resources destroyed."
  exit 0
fi

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

hr
log "CloudSentinel Terraform Deployment"
hr

cd "${TF_DIR}"

log "Step 1/3 — terraform init"
terraform init -reconfigure

log "Step 2/3 — terraform validate"
terraform validate

log "Step 3/3 — terraform apply"
terraform apply -var-file="${TFVARS}" -auto-approve

hr
log "Deployment complete. Outputs:"
hr
terraform output
hr
log "ACTION REQUIRED: Confirm the SNS subscription email before alerts will be delivered."
