# CloudSentinel AI — Architecture

> How we built it, why we made the decisions we did, and how everything connects.

---

## Table of Contents

- [Why we built this](#why-we-built-this)
- [What it does](#what-it-does)
- [System Architecture](#system-architecture)
- [Module Architectures](#module-architectures)
- [Step Functions Orchestration](#step-functions-orchestration)
- [AI Chatbot](#ai-chatbot)
- [Risk Data Model](#risk-data-model)
- [Risk Prioritization](#risk-prioritization)
- [Full System Workflow](#full-system-workflow)
- [Frontend Architecture](#frontend-architecture)
- [Security and Session Model](#security-and-session-model)
- [Module Summary](#module-summary)
- [Technologies Used](#technologies-used)
- [What we set out to achieve](#what-we-set-out-to-achieve)

---

## Why we built this

The biggest source of real cloud breaches is not sophisticated zero-day exploits. It is misconfigured infrastructure. S3 buckets left open, security groups with port 22 open to the world, CI/CD pipelines where someone committed an API key six months ago and it's still there. These are detectable. They just require someone to actually check.

The problem with existing tools is that they either cost too much for a student or small team to use, or they dump a wall of alerts without any explanation of why something matters. If you're a mobile developer who suddenly sees `DynamoDB table SSEDescription.Status = DISABLED` flagged as a risk — that means nothing to you unless someone explains what SSE is, why it matters for your table specifically, and what you need to click to fix it.

We wanted a tool that finds these issues AND explains them in plain language using AI, with actual remediation steps — not just a link to the AWS docs.

---

## What it does

Six of us built this over a semester, each owning one domain:

- **Sameer** — Cloud Infrastructure (AWS + GCP scanning, AI explainer, chatbot, platform)
- **Vivek** — DevOps Intelligence (GitHub Actions CI/CD pipeline analysis)
- **Gowrish** — Full-Stack Intelligence (API Gateway, throttling, error rates)
- **Ayyan** — Data Engineering (DynamoDB, S3 data buckets, Glue ETL jobs)
- **Ambica** — Mobile Backend (Cognito, Lambda, mobile API latency)
- **Akash** — Frontend Portal (dashboard, module pages, session management)

When you trigger a scan, all five scanners run simultaneously in parallel using AWS Step Functions. Instead of taking 10 minutes sequentially, it finishes in 2–3 minutes. Every detected risk gets stored in DynamoDB, then an AI explainer Lambda processes each one with Claude 3 Haiku to write a plain-English explanation and step-by-step fix. If anything Critical or High comes up, an SNS email goes out immediately.

---

## System Architecture

The platform has six layers: frontend, auth, API, compute, AI, and data.

```mermaid
flowchart TD
    User([User]) --> Portal

    subgraph Frontend Layer
        Portal[AWS Amplify\nWeb Portal]
        Portal --> Auth[Amazon Cognito\nAuthentication]
    end

    Auth --> APIGW[Amazon API Gateway\nREST API - /dev stage]

    subgraph Step Functions Orchestration
        SFN[CloudSentinelScanOrchestrator\nExpress Workflow]
    end

    subgraph Lambda Processing Layer
        APIGW --> CS[cloudsentinel-cloud-scanner]
        APIGW --> DA[cloudsentinel-devops-analyzer]
        APIGW --> FA[cloudsentinel-fullstack-analyzer]
        APIGW --> DEA[cloudsentinel-data-eng-analyzer]
        APIGW --> MA[cloudsentinel-mobile-analyzer]
        APIGW --> RR[cloudsentinel-risk-reader]
        APIGW --> CH[cloudsentinel-chatbot-handler]
        SFN --> CS
        SFN --> DA
        SFN --> FA
        SFN --> DEA
        SFN --> MA
    end

    subgraph Multi-Cloud Integration
        CS --> AWS_C[AWS Connector\nS3, EC2, IAM, Config, STS]
        CS --> GCP_C[GCP Connector\nGCS Buckets, Firewall Rules]
    end

    subgraph Domain Intelligence Engines
        DA --> DevOps_E[DevOps Engine\nCI/CD, Pipelines, Webhooks]
        FA --> FS_E[Full-Stack Engine\nAPI Gateway, CloudWatch]
        DEA --> DE_E[Data Engineering Engine\nS3, DynamoDB, Glue]
        MA --> MB_E[Mobile Backend Engine\nAPI Gateway, Lambda, CloudWatch]
    end

    AWS_C --> DDB
    GCP_C --> DDB
    DevOps_E --> DDB
    FS_E --> DDB
    DE_E --> DDB
    MB_E --> DDB

    subgraph AI Analysis Layer
        DDB[(Amazon DynamoDB\ncloudsentinel-risks)] --> AIX[cloudsentinel-ai-explainer]
        AIX --> Bedrock[Amazon Bedrock\nClaude 3 Haiku]
        AIX --> Comprehend[Amazon Comprehend\nRisk Classification]
        Bedrock --> AIX
        Comprehend --> AIX
        AIX --> DDB
        CH --> DDB
        CH --> Bedrock
    end

    subgraph Notification Layer
        AIX --> NH[cloudsentinel-notification-handler]
        NH --> SNS[Amazon SNS\ncloudsentinel-alerts]
        SNS --> Email[Email to account owner]
    end

    DDB --> S3[(Amazon S3\nArtifacts, Reports)]
    DDB --> RR
    RR --> Portal

    subgraph Observability
        EB[Amazon EventBridge\nHourly AI Explainer Trigger] --> AIX
        CW[Amazon CloudWatch\nLogs, Metrics, Alarms]
        XRay[AWS X-Ray\nEnd-to-end tracing]
    end

    style Portal fill:#1A9C3E,color:#fff
    style Auth fill:#D13212,color:#fff
    style APIGW fill:#8C4FFF,color:#fff
    style Bedrock fill:#FF9900,color:#000
    style DDB fill:#4053D6,color:#fff
    style EB fill:#E7157B,color:#fff
    style SNS fill:#D13212,color:#fff
    style SFN fill:#2196F3,color:#fff
```

---

## Module Architectures

### Cloud Infrastructure (Sameer)

This is the core scanner. It covers AWS and optionally GCP if a service account key is configured. Cross-account scanning works by assuming a read-only IAM role in the target account — the CloudFormation template in `infrastructure/cloudformation/` creates that role in the client's account.

```mermaid
flowchart LR
    Trigger([POST /scan-cloud]) --> Handler[lambda_handler]

    subgraph AWS Scans
        Handler --> S3[scan_s3_buckets\nPublic access, Encryption]
        Handler --> SG[scan_security_groups\nOpen SSH/RDP to 0.0.0.0/0]
        Handler --> IAM[scan_iam_password_policy\nStrength, Existence]
        Handler --> MFA[scan_root_mfa\nRoot account MFA]
        Handler --> Config[scan_aws_config_findings\nNon-compliant managed rules]
    end

    subgraph GCP Scans
        Handler --> GCP[scan_gcp_resources\nGCS public buckets, Firewall rules]
    end

    subgraph Cross-Account Scanning
        Handler --> STS[get_aws_clients\nAssume TARGET_ROLE_ARN if set]
        STS --> CrossAcct[Scan external AWS account]
    end

    S3 --> DDB[(DynamoDB)]
    SG --> DDB
    IAM --> DDB
    MFA --> DDB
    Config --> DDB
    GCP --> DDB
    CrossAcct --> DDB
```

---

### DevOps Intelligence (Vivek)

Vivek's module analyzes CI/CD pipeline configuration files — primarily GitHub Actions YAML. It supports two modes: manual (you POST the config) and webhook (GitHub pushes it on every commit). The webhook mode verifies the HMAC signature before processing, so we're not just accepting arbitrary payloads.

```mermaid
flowchart LR
    Trigger([POST /scan-devops\nor GitHub Webhook]) --> Handler[lambda_handler]

    subgraph Pipeline Analysis
        Handler --> Secrets[scan_for_secrets\nRegex: credentials, API keys, tokens]
        Handler --> Tests[scan_for_test_steps\nLooks for pytest, test in CI steps]
        Handler --> Rollback[scan_for_rollback\nLooks for rollback step in pipeline]
        Handler --> Monitor[scan_for_monitoring\nLooks for health check, CloudWatch]
    end

    Secrets --> Risk[build_risk]
    Tests --> Risk
    Rollback --> Risk
    Monitor --> Risk
    Risk --> DDB[(DynamoDB)]
```

---

### Full-Stack Intelligence (Gowrish)

Gowrish's module checks API Gateway configuration and CloudWatch metrics. The key thing it looks for is unauthenticated endpoints — any API method where `authorizationType == NONE` and `apiKeyRequired == false` is fully open to the internet.

He also agreed with Ambica on the latency threshold: web gets 2000ms, mobile gets 1000ms, based on Google's Core Web Vitals research.

```mermaid
flowchart LR
    Trigger([POST /scan-fullstack]) --> Handler[lambda_handler]

    subgraph API Gateway Analysis
        Handler --> Auth[scan_api_authentication\nauthorizationType per method]
        Handler --> Throttle[scan_api_throttling\nthrottlingBurstLimit per stage]
    end

    subgraph CloudWatch Analysis
        Handler --> Err5xx[scan_api_error_rates\n5XX errors - threshold 10/hr]
        Handler --> Latency[scan_api_latency\nAverage latency - threshold 2000ms]
    end

    Auth --> DDB[(DynamoDB)]
    Throttle --> DDB
    Err5xx --> DDB
    Latency --> DDB
```

---

### Data Engineering (Ayyan)

Ayyan's module focuses on protecting data. It uses bucket name analysis (not content inspection) to find potentially sensitive S3 buckets — this keeps the permissions minimal and avoids reading actual data. The threshold for Glue job failures is 2 in the last 5 runs, because a single failure is usually transient but repeated failures mean something is actually broken.

```mermaid
flowchart LR
    Trigger([POST /scan-data-eng]) --> Handler[lambda_handler]

    subgraph S3 Data Buckets
        Handler --> PubCheck[scan - public access block\nAll 4 settings enabled?]
        Handler --> EncCheck[scan - encryption\nSSE configured?]
        PubCheck --> SensCheck{sensitive\nbucket name?}
        EncCheck --> SensCheck
        SensCheck -->|yes| High[Priority = High]
        SensCheck -->|no| Med[Priority = Medium]
    end

    subgraph DynamoDB Tables
        Handler --> SSE[scan - SSEDescription.Status\nDISABLED = Medium risk]
    end

    subgraph Glue ETL
        Handler --> Glue[scan - last 5 job runs\n>= 2 FAILED = High risk]
    end

    High --> DDB[(DynamoDB)]
    Med --> DDB
    SSE --> DDB
    Glue --> DDB
```

---

### Mobile Backend (Ambica)

Ambica's module is similar to Gowrish's full-stack scanner but tuned for mobile clients. The 1000ms latency threshold comes from Firebase Performance Monitoring's recommendation. She also added CORS detection because Flutter Web apps running in a browser are subject to the same preflight rules as any other browser client.

The distinction between her error detection and Gowrish's: she looks at per-function Lambda errors, he looks at API Gateway 5XX. Together they catch more cases.

```mermaid
flowchart LR
    Trigger([POST /scan-mobile]) --> Handler[lambda_handler]

    subgraph API Metrics
        Handler --> Lat[scan_api_latency\np95 > 1000ms - High]
        Handler --> Err5[scan_error_rates 5XX\nSum > 10/hr - High]
        Handler --> Err4[scan_error_rates 4XX\nSum > 50/hr - Medium]
    end

    subgraph CORS
        Handler --> CORS[scan_cors_config\nOPTIONS method missing - Medium]
    end

    subgraph Lambda Health
        Handler --> LErr[scan_lambda_errors\nErrors > 5/hr per function - High]
    end

    Lat --> DDB[(DynamoDB)]
    Err5 --> DDB
    Err4 --> DDB
    CORS --> DDB
    LErr --> DDB
```

---

## Step Functions Orchestration

Running five scanners sequentially would take around 10 minutes. With Step Functions parallel execution it finishes in 2–3 minutes. Each scanner Lambda runs independently and writes to DynamoDB directly — failures in one don't stop the others.

```mermaid
flowchart TD
    Start([Scan Triggered]) --> Validate[ValidateInput\nNormalize request parameters]
    Validate --> Parallel[RunAllScanners\nParallel State]

    subgraph Parallel Execution
        Parallel --> C1[ScanCloudInfra]
        Parallel --> C2[ScanDevOps]
        Parallel --> C3[ScanFullStack]
        Parallel --> C4[ScanDataEng]
        Parallel --> C5[ScanMobile]
    end

    C1 --> AIX[RunAIExplainer\nAmazon Bedrock - Claude 3 Haiku]
    C2 --> AIX
    C3 --> AIX
    C4 --> AIX
    C5 --> AIX

    AIX --> Check{Critical or High\nrisks detected?}
    Check -->|yes| Notify[NotifyUser\nSNS email alert]
    Check -->|no| Done([ScanComplete])
    Notify --> Done

    style Parallel fill:#2196F3,color:#fff
    style AIX fill:#FF9900,color:#000
    style Notify fill:#D13212,color:#fff
```

Each Lambda state has exponential backoff retry (3 attempts, 2x multiplier). X-Ray tracing and CloudWatch logs are enabled on the state machine.

---

## AI Chatbot

The chatbot isn't a generic cloud assistant — it has context. When you ask a question, the chatbot Lambda pulls your top 20 most recent risks from DynamoDB and injects them as context into the Bedrock prompt. So when you ask "why is this risky?" it can answer based on the specific resources that were actually flagged in your environment.

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Chat Panel
    participant APIGW as API Gateway
    participant Lambda as chatbot-handler
    participant DDB as DynamoDB
    participant BR as Amazon Bedrock

    U->>FE: Types a question
    FE->>APIGW: POST /chat { question, module }
    APIGW->>Lambda: Invoke
    Lambda->>DDB: Fetch top 20 risks for module
    DDB-->>Lambda: Risk records
    Lambda->>BR: Claude 3 Haiku (question + risk context as prompt)
    BR-->>Lambda: Answer
    Lambda-->>APIGW: { answer }
    APIGW-->>FE: Response
    FE-->>U: Shown in chat panel

    Note over Lambda,BR: Example questions it handles:<br/>"Why is this risky?"<br/>"Which risk should I fix first?"<br/>"What's the safest way to fix this?"
```

---

## Risk Data Model

Every detected issue is stored as a structured record in DynamoDB.

```json
{
  "resourceId":           "cloud-infra-s3-my-bucket",
  "riskTimestamp":        "2025-06-01T10:30:00Z",
  "module":               "cloud-infra",
  "cloudProvider":        "AWS",
  "resource":             "S3 Bucket",
  "resourceName":         "my-bucket",
  "riskType":             "S3 Public Access Not Fully Blocked",
  "riskReason":           "One or more Block Public Access settings are disabled.",
  "riskPriority":         "High",
  "remediationSteps":     ["Enable all four Block Public Access settings", "Review bucket policy"],
  "alternativeSolutions": ["Use pre-signed URLs for sharing", "Serve via CloudFront with OAC"],
  "aiExplanation":        "filled by ai-explainer via Amazon Bedrock",
  "riskCategory":         "filled by Amazon Comprehend",
  "postureScore":         72,
  "status":               "OPEN",
  "notified":             false,
  "region":               "us-east-1"
}
```

### DynamoDB table design

```mermaid
flowchart TD
    T[(cloudsentinel-risks)] --> PK[Partition Key: resourceId]
    T --> SK[Sort Key: riskTimestamp]
    T --> GSI1[GSI: module-index\nPK: module, SK: riskTimestamp]
    T --> GSI2[GSI: priority-index\nPK: riskPriority, SK: riskTimestamp]

    GSI1 --> Q1[Module dashboard queries]
    GSI2 --> Q2[Priority-filtered summaries]
```

**Status values:** `OPEN`, `IN_PROGRESS`, `RESOLVED`
**Priority values:** `Critical`, `High`, `Medium`, `Low`
**Modules:** `cloud-infra`, `devops`, `fullstack`, `data-eng`, `mobile`

---

## Risk Prioritization

Sameer introduced a Security Posture Score (0–100) to give a single number that represents overall account health — useful for the paper and also easier to explain to a non-technical audience than a list of individual risk counts.

**Posture score formula:**
```
Score = 100 − (20 × Critical + 10 × High + 5 × Medium + 2 × Low)
Minimum: 0
```

Individual risks are classified based on:

```mermaid
flowchart TD
    Risk([Detected Issue]) --> Factors

    subgraph Evaluation Factors
        Factors --> E[Exposure Level\nIs it publicly accessible?]
        Factors --> I[Impact\nWhat data or system is at risk?]
        Factors --> L[Likelihood\nIs this commonly exploited?]
        Factors --> S[Sensitivity\nDoes it hold personal data?]
        Factors --> O[Operational importance\nIs this production?]
    end

    E --> Class[Risk Classification]
    I --> Class
    L --> Class
    S --> Class
    O --> Class

    Class --> Crit[Critical — fix immediately\nExamples: root MFA off, admin access keys exposed]
    Class --> H[High — fix soon\nExamples: public S3 bucket, open SSH port, unauthenticated API]
    Class --> M[Medium — address this sprint\nExamples: weak password policy, no encryption, missing rate limit]
    Class --> Lo[Low — good practice\nExamples: no bucket versioning, non-critical config gap]
```

---

## Full System Workflow

```mermaid
sequenceDiagram
    participant U as User
    participant P as Portal
    participant AG as API Gateway
    participant SFN as Step Functions
    participant Scan as Scan Lambda
    participant Cloud as AWS / GCP APIs
    participant AI as AI Explainer
    participant DDB as DynamoDB
    participant SNS as Amazon SNS

    U->>P: Sign in via Cognito
    U->>P: Connect module + give consent
    P->>AG: POST /scan-{module}
    AG->>SFN: StartExecution (all 5 scanners in parallel)
    SFN->>Scan: Invoke module Lambdas
    Scan->>Cloud: Fetch configuration data
    Cloud-->>Scan: Infrastructure metadata
    Scan->>Scan: Run detection checks
    Scan->>DDB: Write risk records (status: OPEN)

    Note over AI,DDB: After all scans finish
    AI->>DDB: Fetch risks without aiExplanation
    AI->>AI: Build prompt per risk
    AI->>AI: Call Amazon Bedrock (Claude 3 Haiku)
    AI->>DDB: Update aiExplanation field

    Note over SFN,SNS: If Critical or High risks found
    SFN->>SNS: Publish email alert
    SNS-->>U: Email with risk summary

    P->>AG: GET /risks?module=...
    AG->>DDB: Query module-index GSI
    DDB-->>P: Risk records with AI explanations displayed as cards
```

---

## Frontend Architecture

Akash built the frontend as plain HTML/CSS/JS — no framework. It supports dark and light mode (Akash's addition), a configurable session timer, and stores scan history locally in the browser. The AI chatbot panel is embedded on every module page, not just the main dashboard.

```mermaid
flowchart TD
    User([User]) --> Amplify[AWS Amplify\nStatic hosting]

    Amplify --> Login[index.html - Sign In]
    Amplify --> Signup[signup.html - Register]
    Amplify --> Dash[dashboard.html - Main Hub]
    Amplify --> Modules[Module Pages\ncloud, devops, fullstack, data, mobile]

    Login --> Cognito[Amazon Cognito\nInitiateAuth]
    Signup --> Cognito
    Cognito -->|JWT tokens| Dash

    Dash --> APIGW_R[GET /risks] --> RR[risk-reader Lambda]
    Dash --> APIGW_S[POST /scan-*] --> Scanner[module Lambda]
    Modules --> APIGW_C[POST /chat] --> CH[chatbot-handler Lambda]

    style Amplify fill:#1A9C3E,color:#fff
    style Cognito fill:#D13212,color:#fff
```

---

## Security and Session Model

We tried to get the security properties right — not just functional auth, but actually secure.

**Authentication:**
- Cognito User Pools with email-based sign-in
- JWT tokens (Access + ID) stored in memory; refresh token in localStorage
- 30-minute token expiry enforced server-side by Cognito AND API Gateway — not just a frontend timer

**Session management:**
- Idle timeout defaults to 30 minutes
- Activity events (mouse, keyboard, scroll) reset the timer
- Warning modal at 60 seconds remaining
- Users can adjust timeout between 15 minutes and 8 hours
- On expiry: frontend calls `/disconnect`, which revokes all cloud credentials

**Login security:**
- Client-side rate limiting: 3 failed attempts = 60-second lockout, 5 = 5 minutes, 10 = 30 minutes
- Failed attempt count shown after the second failure
- Email format validated before any API call

**Cloud connection security:**
- AWS: cross-account role deployed via CloudFormation — read-only, with an External ID to prevent confused deputy attacks
- GCP: service account JSON key stored in AWS Secrets Manager — never touches the frontend
- Disconnect: CloudFormation stack deleted, GCP secret force-purged, all DynamoDB risk records cleared

---

## Module Summary

| Module | Lambda | Owner | What it checks |
|--------|--------|-------|----------------|
| Cloud Infrastructure | `cloudsentinel-cloud-scanner` | Sameer | S3, EC2, IAM, root MFA, GCP buckets and firewalls |
| DevOps Intelligence | `cloudsentinel-devops-analyzer` | Vivek | Hardcoded secrets, missing tests, no rollback, no post-deploy monitoring |
| Full-Stack | `cloudsentinel-fullstack-analyzer` | Gowrish | Unauthenticated APIs, no throttling, 5XX error rate, high latency |
| Data Engineering | `cloudsentinel-data-eng-analyzer` | Ayyan | Sensitive public buckets, DynamoDB encryption off, Glue job failures |
| Mobile Backend | `cloudsentinel-mobile-analyzer` | Ambica | High latency, Lambda errors, CORS gaps, Cognito MFA |
| Frontend | AWS Amplify (static) | Akash | Dashboard, risk cards, chatbot, scan history, session timer |

---

## Technologies Used

### AWS Services

| Service | How we use it |
|---------|--------------|
| Amazon Bedrock (Claude 3 Haiku) | AI explanations + chatbot |
| Amazon Comprehend | Risk category classification |
| AWS Step Functions | Parallel scan coordination |
| Amazon SNS | Email alerts on Critical/High risks |
| AWS Amplify | Frontend hosting |
| Amazon Cognito | Auth, JWT tokens, forgot password |
| Amazon API Gateway | REST API, Cognito JWT authorizer on every route |
| AWS Lambda (Python 3.11) | All compute |
| Amazon DynamoDB | Risk records, GSI for module + priority queries |
| Amazon S3 | Artifacts, PDF reports |
| Amazon CloudWatch | Logs, metrics (scan timing, AI latency for paper) |
| AWS X-Ray | Request tracing |
| Amazon EventBridge | Hourly AI explainer trigger |
| AWS STS | Cross-account scanning |
| AWS Secrets Manager | GCP keys, webhook secrets |
| AWS Config | Non-compliant resource findings |
| AWS Security Hub | Compliance standards baseline |
| Terraform | Full infrastructure as code |
| GitHub Actions | CI: unit tests, Bandit, Terraform validate |

### Cloud coverage

| Cloud | Status |
|-------|--------|
| AWS | Full coverage across 5 domains |
| GCP | Cloud Storage + Compute Engine firewall scanning |
| Azure | Planned for v2 |

---

## What we set out to achieve

We wanted to build something we would actually use. Whether that's checking a bucket configuration before a deployment, figuring out why a Glue job stopped working, or asking the chatbot "is this actually dangerous or can I ignore it" — the platform should answer that faster and more clearly than going through the AWS console manually.

Specifically:

- A single portal covering all five domains without jumping between services
- AI explanations specific to the actual resource flagged, not generic documentation summaries
- Alerts that arrive fast enough to be actionable
- Remediation steps that tell you the exact setting or command, not just "fix your configuration"
- A chatbot that knows what's in your environment, not just what's in the AWS docs
- A quantitative posture score so you can see progress as you fix things

The combination of Step Functions parallel scanning, domain-specific detection, Bedrock explanations, Comprehend classification, posture scoring, and PDF reporting is what makes this more than a monitoring dashboard.
