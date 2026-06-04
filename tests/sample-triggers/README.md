# Sample Test Triggers

These are files we use to intentionally create misconfigured AWS resources so we can test that each CloudSentinel module actually detects what it's supposed to detect. Run them, trigger a scan, check that the risks show up, then clean up.

**Important:** Always run the cleanup commands after testing. These files create real AWS resources that cost money if left running.

## File Index

| File | Module | What it tests |
|------|--------|---------------|
| `test-infra-insecure.yaml` | Cloud Infrastructure | Open security groups, no S3 encryption, admin IAM user |
| `bad-deploy.yml` | DevOps | Hardcoded secrets, no tests, no rollback |
| `good-deploy.yml` | DevOps | Clean pipeline (should show 0 risks) |
| `test-data-risks.tf` | Data Engineering | Unencrypted S3, PII-named buckets, DynamoDB SSE off |
| `run_mobile_test.py` | Mobile Backend | Cognito MFA off, wildcard IAM role, unauth API |

## Quick Start

### Test Cloud Infrastructure Module
```bash
aws cloudformation create-stack \
  --stack-name cs-test-insecure \
  --template-body file://test-infra-insecure.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```
Then go to `/cloud.html` → scan → expect **3+ High risks**

### Test DevOps Module
```bash
# Copy bad-deploy.yml to your repo
cp bad-deploy.yml /path/to/your/repo/.github/workflows/
cd /path/to/your/repo && git add .github/workflows/bad-deploy.yml
git commit -m "test: CloudSentinel DevOps scan trigger"
git push
```
Then go to `/devops.html` → scan → expect **2 High + 2 Medium risks**

### Test Data Engineering Module
```bash
terraform init && terraform apply -auto-approve -target=./test-data-risks.tf
```
Then go to `/data.html` → scan → expect **2 High + 2 Medium risks**

### Test Mobile Backend Module
```bash
python run_mobile_test.py
```
Then go to `/mobile.html` → scan → expect **2–3 High risks**

## Cleanup All
```bash
aws cloudformation delete-stack --stack-name cs-test-insecure
terraform destroy -auto-approve
python run_mobile_test.py --cleanup
git rm .github/workflows/bad-deploy.yml && git commit -m "remove test workflow" && git push
```
