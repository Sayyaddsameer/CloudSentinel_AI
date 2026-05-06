# CloudSentinel -- Architecture

> AI-Powered Multi-Cloud Engineering Risk Intelligence Platform

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Project Overview](#project-overview)
- [Objectives](#objectives)
- [System Architecture](#system-architecture)
- [Module Architectures](#module-architectures)
- [Step Functions Orchestration](#step-functions-orchestration)
- [AI Chatbot Architecture](#ai-chatbot-architecture)
- [Risk Intelligence Model](#risk-intelligence-model)
- [Risk Prioritization Logic](#risk-prioritization-logic)
- [System Workflow](#system-workflow)
- [Frontend Architecture](#frontend-architecture)
- [Session and Security Model](#session-and-security-model)
- [Platform Modules](#platform-modules)
- [Technologies and Services](#technologies-and-services)
- [Expected Outcomes](#expected-outcomes)

---

## Problem Statement

When you are running infrastructure across multiple cloud services, things go wrong quietly. S3 buckets get misconfigured. Security groups accumulate open ports. CI/CD pipelines grow hardcoded secrets over time. Data buckets lose their encryption settings after an update. These issues rarely announce themselves — they show up later, usually at the worst possible moment.

The harder problem is that existing monitoring tools generate a lot of noise but very little signal. You get an alert, you look at the resource, and you still do not know if it is actually dangerous or how urgent it is. If you are a backend developer and the alert is about a Glue job failure, you might not even know where to start.

We built CloudSentinel because we wanted a tool that not only finds these issues but explains them in language that any engineer can act on, regardless of which part of the stack they work in.

---

## Project Overview

CloudSentinel is a fully serverless platform running on AWS. Each of the five engineering domains has its own Lambda-based scanner. When a scan runs, AWS Step Functions coordinates all five scanners in parallel — what would take around 10 minutes running sequentially finishes in 2–3 minutes this way.

Detected risks get stored in DynamoDB. An AI explainer Lambda then picks up each risk record and calls Amazon Bedrock (Claude 3 Haiku) to write a plain-language explanation and remediation guide. Amazon Comprehend classifies the risk into a category. When High-priority risks are found, Amazon SNS sends an email alert to the account owner.

The frontend is a static web portal on AWS Amplify, authenticated through Amazon Cognito. Each module has its own dashboard page showing risk cards. There is also an AI chatbot on every module page that lets you ask questions about what was detected and get contextual answers back from the same Claude model.

---

## Objectives

- Detect infrastructure and operational risks across five engineering domains from a single platform
- Support multi-cloud scanning across AWS and GCP environments
- Generate AI-powered explanations for every detected risk using Amazon Bedrock
- Prioritize risks by severity so teams can focus on what matters most
- Deliver actionable remediation guidance with concrete steps and alternatives
- Send real-time email notifications when High-priority risks are detected
- Enable interactive troubleshooting through an AI assistant chatbot

---

## System Architecture

The platform is composed of six integrated layers: presentation, authentication, API, compute, AI analysis, and data.

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
        SNS --> Email[Email to user]
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

### Cloud Infrastructure Intelligence

**Module:** Cloud Infrastructure and AI Layer -- Lambda: `cloudsentinel-cloud-scanner`

```mermaid
flowchart LR
    Trigger([POST /scan-cloud]) --> Handler[lambda_handler]

    subgraph AWS Scans
        Handler --> S3[scan_s3_buckets\nPublic access, Encryption]
        Handler --> SG[scan_security_groups\nOpen SSH/RDP to 0.0.0.0/0]
        Handler --> IAM[scan_iam_password_policy\nStrength, Existence]
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
    Config --> DDB
    GCP --> DDB
    CrossAcct --> DDB
```

---

### DevOps Intelligence

**Module:** DevOps Intelligence -- Lambda: `cloudsentinel-devops-analyzer`

```mermaid
flowchart LR
    Trigger([POST /scan-devops\nor GitHub Webhook]) --> Handler[lambda_handler]

    subgraph Pipeline Analysis
        Handler --> Secrets[scan_environment_variables\nRegex: credentials, API keys, tokens]
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

### Full-Stack Application Intelligence

**Module:** Full-Stack Application Intelligence -- Lambda: `cloudsentinel-fullstack-analyzer`

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

### Data Engineering Intelligence

**Module:** Data Engineering Intelligence -- Lambda: `cloudsentinel-data-eng-analyzer`

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

### Mobile Backend Intelligence

**Module:** Mobile Backend Intelligence -- Lambda: `cloudsentinel-mobile-analyzer`

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

AWS Step Functions coordinates the full scan pipeline using an Express workflow. All five module scanners run in parallel, which reduces total scan time from ~10 minutes (sequential) to approximately 2-3 minutes.

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

    AIX --> Check{High risks\ndetected?}
    Check -->|yes| Notify[NotifyUser\nSNS email alert]
    Check -->|no| Done([ScanComplete])
    Notify --> Done

    style Parallel fill:#2196F3,color:#fff
    style AIX fill:#FF9900,color:#000
    style Notify fill:#D13212,color:#fff
```

Each Lambda state has exponential backoff retry (3 attempts, 2x multiplier). Failures in individual scanners are caught and do not stop the rest of the workflow. X-Ray tracing and CloudWatch logs are enabled on the state machine.

---

## AI Chatbot Architecture

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Chat Interface
    participant APIGW as API Gateway
    participant Lambda as chatbot-handler
    participant DDB as DynamoDB
    participant BR as Amazon Bedrock

    U->>FE: Asks question about a risk
    FE->>APIGW: POST /chat { question, module }
    APIGW->>Lambda: Invoke with payload
    Lambda->>DDB: Query top 20 risks for module
    DDB-->>Lambda: Risk records with context
    Lambda->>BR: InvokeModel - Claude 3 Haiku\n(question + risk context as prompt)
    BR-->>Lambda: AI-generated answer
    Lambda-->>APIGW: { answer }
    APIGW-->>FE: Response
    FE-->>U: Displayed in chat panel

    Note over Lambda,BR: Example queries handled:\n"Why is this resource risky?"\n"Which risk should I fix first?"\n"What secure alternatives exist?"
```

---

## Risk Intelligence Model

Every detected issue is stored as a structured risk record in DynamoDB.

```json
{
  "resourceId":           "cloud-infra-s3-bucket-my-bucket",
  "riskTimestamp":        "2024-01-15T10:30:00Z",
  "scanId":               "scan-uuid",
  "userId":               "user-uuid",
  "module":               "cloud-infra",
  "cloudProvider":        "AWS",
  "resource":             "S3 Bucket",
  "resourceName":         "my-bucket",
  "riskType":             "S3 Public Access Not Fully Blocked",
  "riskReason":           "One or more Block Public Access settings are disabled on this bucket.",
  "riskPriority":         "High",
  "remediationSteps":     ["Enable all four Block Public Access settings", "Review bucket policy"],
  "alternativeSolutions": ["Use pre-signed URLs", "Serve via CloudFront with OAC"],
  "aiExplanation":        "Filled by ai-explainer Lambda via Amazon Bedrock",
  "riskCategory":         "Filled by Amazon Comprehend",
  "status":               "OPEN",
  "notified":             false,
  "region":               "us-east-1"
}
```

### DynamoDB Table Structure

```mermaid
flowchart TD
    T[(cloudsentinel-risks\nTable)] --> PK[Partition Key: resourceId]
    T --> SK[Sort Key: riskTimestamp]
    T --> GSI1[GSI: module-index\nPK: module, SK: riskTimestamp]
    T --> GSI2[GSI: priority-index\nPK: riskPriority, SK: riskTimestamp]
    T --> GSI3[GSI: userId-module-index\nPK: userId, SK: module]

    GSI1 --> Q1[Module dashboard queries]
    GSI2 --> Q2[High-priority risk summary]
    GSI3 --> Q3[Notification handler queries\nby user and module]
```

**Status values:** `OPEN`, `IN_PROGRESS`, `RESOLVED`
**Priority values:** `High`, `Medium`, `Low`
**Module values:** `cloud-infra`, `devops`, `fullstack`, `data-eng`, `mobile`

---

## Risk Prioritization Logic

```mermaid
flowchart TD
    Risk([Detected Issue]) --> Factors

    subgraph Evaluation Factors
        Factors --> E[Exposure Level\nIs the resource publicly accessible?]
        Factors --> I[Impact Severity\nWhat data or system is affected?]
        Factors --> L[Likelihood of Exploitation\nIs this commonly exploited?]
        Factors --> S[Resource Sensitivity\nDoes it hold PII or critical data?]
        Factors --> O[Operational Importance\nIs this a production system?]
    end

    E --> Class[Risk Classification]
    I --> Class
    L --> Class
    S --> Class
    O --> Class

    Class --> H[High -- Immediate action required\nExamples: public S3 bucket, open SSH, no auth on API]
    Class --> M[Medium -- Address soon\nExamples: weak password policy, missing encryption, no rate limiting]
    Class --> Lo[Low -- Recommended improvement\nExamples: no bucket versioning, non-critical config gap]
```

---

## System Workflow

```mermaid
sequenceDiagram
    participant U as User
    participant P as Portal
    participant AG as API Gateway
    participant SFN as Step Functions
    participant Scan as Scan Lambda
    participant Cloud as Cloud APIs
    participant AI as AI Explainer
    participant DDB as DynamoDB
    participant SNS as Amazon SNS
    participant Chat as Chatbot

    U->>P: Login via Cognito
    U->>P: Connect module + give consent
    P->>AG: POST /scan-{module}
    AG->>SFN: StartExecution (all 5 scanners)
    SFN->>Scan: Invoke module Lambdas in parallel
    Scan->>Cloud: Collect configuration metadata
    Cloud-->>Scan: Infrastructure data
    Scan->>Scan: Risk detection engine runs
    Scan->>DDB: Write classified risk records (OPEN)

    Note over AI,DDB: Step Functions triggers AI after all scans complete
    AI->>DDB: Fetch OPEN risks without aiExplanation
    AI->>AI: Build prompt per risk
    AI->>AI: Invoke Amazon Bedrock
    AI->>DDB: Update aiExplanation field

    Note over SFN,SNS: If High risks detected
    SFN->>SNS: Publish email notification
    SNS-->>U: Email alert with risk summary

    P->>AG: GET /risks?module=...
    AG->>DDB: Query module-index GSI
    DDB-->>P: Risk records with AI explanations

    U->>Chat: Ask question about a risk
    Chat->>AG: POST /chat
    AG->>Chat: Invoke chatbot-handler
    Chat->>DDB: Fetch risk context
    Chat->>AI: Invoke Bedrock with question and context
    AI-->>Chat: AI answer
    Chat-->>U: Contextual response in chat panel
```

---

## Frontend Architecture

**Module:** Frontend Portal -- Hosting: AWS Amplify

```mermaid
flowchart TD
    User([User]) --> Amplify[AWS Amplify\nStatic hosting]

    Amplify --> Login[index.html - Login]
    Amplify --> Signup[signup.html - Registration]
    Amplify --> Dash[dashboard.html - Main Hub]
    Amplify --> History[history.html - Risk History]
    Amplify --> Modules[Module Pages\ncloud, devops, fullstack, data, mobile]

    Login --> Cognito[Amazon Cognito\nInitiateAuth API]
    Signup --> Cognito
    Cognito -->|AccessToken + IdToken| Dash

    Dash --> APIGW_R[GET /risks] --> RR[risk-reader Lambda]
    Dash --> APIGW_S[POST /scan-*] --> Scanner[module Lambda]
    Modules --> APIGW_C[POST /chat] --> CH[chatbot-handler Lambda]

    style Amplify fill:#1A9C3E,color:#fff
    style Cognito fill:#D13212,color:#fff
```

The frontend uses plain HTML, CSS, and JavaScript with no framework dependencies. It supports light and dark mode, a session idle timeout (30 minutes default, user-configurable), and stores scan history locally in the browser. The AI chatbot panel is embedded on every module page.

---

## Session and Security Model

The frontend implements a layered security approach:

**Authentication:**
- Amazon Cognito handles identity -- user pool with email-based sign-in
- JWT tokens (Access + ID) stored in memory, refresh token in localStorage
- Demo mode for local development -- any credentials are accepted when Cognito is not configured

**Session management:**
- Idle timeout defaults to 30 minutes
- Session countdown timer visible in navbar at all times
- Activity events (mouse, keyboard, scroll) reset the timer
- Warning modal appears at 60 seconds remaining
- Session settings let users extend to 15 minutes up to 8 hours
- Auto-logout redirects to login page with `reason=timeout` in URL

**Login security:**
- Client-side rate limiting: 3 failed attempts = 60 second lockout, 5 attempts = 5 minute lockout, 10 attempts = 30 minute lockout
- Attempt counter shown after the second failed attempt
- Live countdown timer during lockout period
- Email format validation before API call

**Cloud connection security:**
- AWS connections use CloudFormation or Terraform to deploy a read-only IAM role
- The role uses an External ID to prevent confused deputy attacks
- GCP connections use a service account JSON stored in AWS Secrets Manager
- Users explicitly consent before access is granted
- Disconnect option removes the cross-account role stack from the user's account

---

## Platform Modules

| Module | Lambda | Owner | Key Detections |
|--------|--------|-------|----------------|
| Cloud Infrastructure | `cloudsentinel-cloud-scanner` | Cloud Infrastructure and AI Layer | Public S3 buckets, open security groups, weak IAM, GCP firewall |
| DevOps Intelligence | `cloudsentinel-devops-analyzer` | DevOps Intelligence | Hardcoded secrets, missing tests, no rollback, no monitoring |
| Full-Stack Application | `cloudsentinel-fullstack-analyzer` | Full-Stack Intelligence | Unauthenticated APIs, no rate limiting, high 5XX, high latency |
| Data Engineering | `cloudsentinel-data-eng-analyzer` | Data Engineering Intelligence | Public data buckets, missing encryption, DynamoDB SSE off, Glue failures |
| Mobile Backend | `cloudsentinel-mobile-analyzer` | Mobile Backend Intelligence | High latency, error spikes, missing CORS, Lambda errors |
| Frontend Portal | AWS Amplify (static) | Frontend Portal | Dashboard, risk cards, AI chatbot, scan history, session management |

---

## Technologies and Services

### Cloud Platforms

| Platform | Status |
|----------|--------|
| Amazon Web Services (AWS) | Production |
| Google Cloud Platform (GCP) | Production (GCS + Firewall scanning) |
| Microsoft Azure | Planned for v2 |

### AWS Services

| Category | Service | Purpose |
|----------|---------|---------|
| AI / ML | Amazon Bedrock (Claude 3 Haiku) | Risk explanations, chatbot responses |
| AI / ML | Amazon Comprehend | Risk category classification |
| Orchestration | AWS Step Functions | Parallel scan coordination, AI trigger, SNS routing |
| Alerting | Amazon SNS | Email notifications on High risk detection |
| Hosting | AWS Amplify | Frontend portal |
| Authentication | Amazon Cognito | User identity and session management |
| API | Amazon API Gateway | Frontend to backend communication |
| Compute | AWS Lambda (Python 3.11) | Risk detection, AI processing, API handling |
| Database | Amazon DynamoDB | Structured risk record storage |
| Storage | Amazon S3 | Logs, reports, scan artifacts |
| Monitoring | Amazon CloudWatch | Metrics, logs, alarms |
| Tracing | AWS X-Ray | End-to-end request tracing |
| Events | Amazon EventBridge | Hourly AI explainer trigger, scan-complete events |
| Security | AWS IAM | Role-based access control |
| Security | AWS STS | Cross-account scanning credentials |
| Security | AWS Secrets Manager | GCP credentials, webhook secrets |
| Governance | AWS Config | Non-compliant resource detection |
| IaC | Terraform | Full infrastructure deployment |
| CI/CD | GitHub Actions | Automated testing and Bandit security scan |

---

## Expected Outcomes

The goal was to build something we would actually use ourselves. Whether that is checking an S3 bucket configuration before a deployment, verifying that a Glue job has not been silently failing, or asking the chatbot why a particular API endpoint was flagged — the platform should make that faster and clearer than looking it up manually.

More specifically, by the end of this project we wanted to have:

- A single portal where you can see risks across all five engineering domains without switching between services
- AI explanations that are specific to the detected issue, not just generic documentation summaries
- Email alerts that arrive quickly enough to be useful — not summaries delivered hours after the fact
- Remediation steps that are actionable and tell you the exact setting or command to run
- A chatbot that understands the context of your detected risks, not just generic cloud questions

The combination of Step Functions orchestration, domain-specific scanners, Bedrock explanations, Comprehend classification, and SNS alerts is what makes this more than just another monitoring dashboard.
