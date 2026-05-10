# CloudSentinel AI

**Multi-Cloud Security Intelligence Platform — Powered by AWS Serverless and AI**

[![CI](https://github.com/Sayyaddsameer/CloudSentinel_AI/actions/workflows/ci.yml/badge.svg)](https://github.com/Sayyaddsameer/CloudSentinel_AI/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11-3776AB)
![AWS](https://img.shields.io/badge/AWS-Serverless-FF9900)
![API Gateway](https://img.shields.io/badge/API_Gateway-Cognito_JWT-orange)
![License](https://img.shields.io/badge/License-Academic-blue)

---

## Overview

CloudSentinel AI continuously scans AWS and GCP cloud environments for misconfigurations, IAM vulnerabilities, exposed resources, and compliance gaps. Instead of generic alerts, every detected risk comes with an AI-generated plain-English explanation and step-by-step remediation guide.

The platform covers five specialized domains: Cloud Infrastructure, DevOps pipelines, Full-Stack APIs, Data Engineering, and Mobile Backends. A built-in AI chatbot lets users query their specific detected risks in real time without leaving the dashboard.

**Key security properties:**
- All API endpoints protected by Cognito JWT authorizer (no public access)
- Cloud credentials never stored in frontend; GCP keys held in AWS Secrets Manager
- Cross-account scanning via read-only IAM roles deployed through CloudFormation
- Automated credential revocation on disconnect or session expiry

---

## Platform Modules

| Module | What It Scans | Key Detections |
|--------|---------------|----------------|
| Cloud Infrastructure | AWS S3, EC2, IAM, GCP GCS, GCP Firewall | Public buckets, open SSH/RDP ports, missing IAM password policy, GCP firewall/bucket exposure |
| DevOps Intelligence | GitHub Actions CI/CD workflows | Hardcoded secrets, missing test step, missing rollback, no post-deploy monitoring |
| Full-Stack Application | API Gateway, Lambda metrics | Unauthenticated endpoints, permissive CORS, missing rate limiting, high error rates |
| Data Engineering | DynamoDB, S3, Glue jobs | Unencrypted tables, public data buckets, repeated ETL job failures |
| Mobile Backend | Cognito, Lambda, API Routes | MFA disabled, weak password policy, over-permissioned Lambda roles, API auth gaps |

---

## Architecture

```
Browser (landing.html / dashboard / module pages)
  |-- Amazon Cognito (sign-up, sign-in, forgot password, JWT tokens — 30-min expiry)
  |-- Amazon API Gateway  [ALL routes require Cognito JWT — no NONE endpoints]
        |-- POST /validate-connection --> cloudsentinel-validate-connection
        |-- POST /scan-cloud-infra    --> cloudsentinel-cloud-scanner
        |-- POST /scan-devops         --> cloudsentinel-devops-analyzer
        |-- POST /scan-fullstack      --> cloudsentinel-fullstack-analyzer
        |-- POST /scan-data-eng       --> cloudsentinel-data-eng-analyzer
        |-- POST /scan-mobile         --> cloudsentinel-mobile-analyzer
        |-- GET  /risks               --> cloudsentinel-risk-reader
        |-- POST /chat                --> cloudsentinel-chatbot-handler
        |-- POST /disconnect          --> cloudsentinel-disconnect-handler

All scanners write risk records to:
  Amazon DynamoDB (cloudsentinel-risks)  [Point-In-Time Recovery enabled]
    |-- module-index GSI   (per-module queries)
    |-- priority-index GSI (High/Medium/Low filtering)
    |-- cloudsentinel-ai-explainer (EventBridge hourly) --> Amazon Bedrock (Claude 3 Haiku)
    |-- cloudsentinel-notification-handler              --> Amazon SNS --> Email alerts

GCP scanning (when GCP_SECRET_NAME is set):
  cloud-scanner --> AWS Secrets Manager (GCP service-account JSON)
    |-- Google Cloud Storage: scans bucket IAM policies for allUsers/allAuthenticatedUsers
    |-- GCP Compute Engine:   scans firewall rules for open SSH/RDP (0.0.0.0/0)

On disconnect or session expiry:
  cloudsentinel-disconnect-handler
    |-- Assumes cross-account scanner role --> cloudformation:DeleteStack
    |-- AWS Secrets Manager: ForceDeleteWithoutRecovery (GCP keys)
    |-- DynamoDB: batch delete all risk records for the module
```

Full architecture diagrams, sequence flows, and the risk data schema are in [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend hosting | AWS S3 Static Website / AWS Amplify |
| Authentication | Amazon Cognito (User Pools, JWT, Forgot Password flow) |
| API security | Amazon API Gateway + Cognito JWT Authorizer |
| Serverless compute | AWS Lambda (Python 3.11) |
| AI reasoning | Amazon Bedrock (Claude 3 Haiku) |
| Risk storage | Amazon DynamoDB (with GSIs) |
| Secrets management | AWS Secrets Manager (GCP credentials) |
| Cross-account access | AWS STS AssumeRole + CloudFormation (read-only scanner role) |
| Alert delivery | Amazon SNS |
| Artifact storage | Amazon S3 |
| Monitoring | Amazon CloudWatch |
| Scheduling | Amazon EventBridge |
| Infrastructure as Code | Terraform >= 1.6 |
| CI/CD | GitHub Actions |

---

## Repository Structure

```
CloudSentinel_AI/
|-- .github/
|   |-- workflows/ci.yml              # CI: unit tests (fail-fast) + Bandit + Terraform validate
|-- docs/
|   |-- cloud-infrastructure-and-ai/  # Architecture, AWS setup, research, specs
|   |-- devops-intelligence/
|   |-- frontend-portal/
|   |-- fullstack-intelligence/
|   |-- data-engineering-intelligence/
|   |-- mobile-backend-intelligence/
|-- infrastructure/
|   |-- cloudformation/               # Scanner IAM role (cross-account)
|   |-- iam/lambda_policy.json        # Lambda execution policy (least-privilege)
|   |-- terraform/                    # Full IaC: all AWS + Security Hub resources
|-- modules/
|   |-- cloud-infra/                  # Cloud Infrastructure + AI + GCP scan Lambdas
|   |-- devops/                       # DevOps Intelligence Lambda
|   |-- fullstack/                    # Full-Stack Intelligence Lambda
|   |-- data-eng/                     # Data Engineering Intelligence Lambda
|   |-- mobile/                       # Mobile Backend Intelligence Lambda
|   |-- frontend/                     # Frontend portal (HTML/CSS/JS)
|       |-- landing.html              # Public landing page (dark/light mode)
|       |-- index.html                # Sign in + forgot password flow
|       |-- signup.html               # Account registration
|       |-- dashboard.html            # Main dashboard with AI chatbot
|       |-- cloud.html / devops.html / fullstack.html / data.html / mobile.html
|       |-- terms.html / privacy.html # Legal pages
|       |-- js/env.js                 # Runtime config (API URL, Cognito IDs)
|       |-- js/auth.js                # Cognito auth (login, signup, forgot password)
|       |-- js/session.js             # Session timer (login-time based, auto-revoke)
|       |-- js/app.js                 # Shared utilities (API calls, disconnect API)
|-- shared/schemas/                   # Risk record JSON schema
|-- tests/                            # Unit tests for all 5 modules (pytest)
|   |-- conftest.py                   # Shared fixtures and sys.path setup
|-- pytest.ini                        # Pytest configuration
|-- deploy_console.py                 # Full deployment without Terraform
|-- ARCHITECTURE.md                   # Full architecture and design documentation
|-- DEPLOYMENT.md                     # Step-by-step deployment guide
|-- README.md
```

---

## Getting Started

**Prerequisites:** AWS account with CLI configured, Python 3.11, Git.

See [DEPLOYMENT.md](./DEPLOYMENT.md) for the complete guide.

**Quick deploy (no Terraform):**
```bash
git clone https://github.com/Sayyaddsameer/CloudSentinel_AI.git
cd CloudSentinel_AI
pip install boto3
python deploy_console.py
```

**Quick deploy (Terraform):**
```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# Fill in alert_email and environment
terraform init && terraform apply
```

**Access the platform:**
```
http://cloudsentinel-frontend-<account-id>.s3-website-us-east-1.amazonaws.com/landing.html
```

---

## Security Architecture

| Control | Implementation |
|---------|---------------|
| Authentication | Amazon Cognito User Pools — access tokens expire in **30 minutes** (enforced by Cognito, not client) |
| API Authorization | All 9 endpoints use `COGNITO_USER_POOLS` authorizer — API Gateway rejects any missing or expired token |
| Password Recovery | Cognito ForgotPassword + ConfirmForgotPassword (code sent to email) |
| Session Management | 30-min token expiry enforced **server-side** by Cognito + API Gateway; client timer matches |
| Credential Storage | GCP service account keys in AWS Secrets Manager only; never in frontend code or env vars |
| Cross-account Access | Read-only IAM role deployed via CloudFormation; STS AssumeRole scoped to `cloudsentinel-scanner-role` |
| Automated Revocation | On disconnect or session expiry: CFN stack deleted, GCP secret purged, DynamoDB risks cleared |
| DynamoDB Backup | Point-In-Time Recovery (PITR) enabled — any-second restore up to 35 days |

---

## Running Tests

```bash
# Install dependencies
pip install boto3 "moto[all]" pytest pytest-cov

# Run all unit tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=modules --cov-report=term-missing
```

The test suite covers all 5 Lambda modules with mocked AWS services (no real AWS credentials needed).

---

## Team

| Name | GitHub | Module |
|------|--------|--------|
| Sayyad Sameer | [@Sayyaddsameer](https://github.com/Sayyaddsameer) | Cloud Infrastructure, AI Layer, Platform Lead |
| Kantipudi Vivek Vardhan | [@vivekkantipudi](https://github.com/vivekkantipudi) | DevOps Intelligence |
| Janapareddy Dyns Gowrish | [@gowrishjanapareddy](https://github.com/gowrishjanapareddy) | Full-Stack Intelligence |
| Bikkavolu Srivallisa Sai Veerabhadra Ayyan | [@23P31A0506](https://github.com/23P31A0506) | Data Engineering Intelligence |
| Muramalla Ambica Sai Ram | [@AmbicaSairam](https://github.com/AmbicaSairam) | Mobile Backend Intelligence |
| Bogavalli Akash | [@Akashbogavalli69](https://github.com/Akashbogavalli69) | Frontend Portal |

---

## License

Developed as part of an academic engineering initiative at Aditya University.
All rights reserved by the contributing team members.
