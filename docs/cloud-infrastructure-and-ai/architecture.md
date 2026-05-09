# Architecture Notes — Cloud Infra + AI Layer
## Sayyad Sameer

Wrote this out to make the overall system clear for the team. The cloud-infra module sits at the center — I own the shared infrastructure that everyone else connects to.

---

## How the whole system fits together

```mermaid
flowchart TD
    User([User]) --> Portal[AWS Amplify\nWeb Portal]
    Portal --> Cognito[Amazon Cognito\nAuth]
    Cognito --> APIGW[Amazon API Gateway]

    APIGW --> Scanner[Lambda\ncloud-scanner]
    APIGW --> AIExp[Lambda\nai-explainer]
    APIGW --> Chat[Lambda\nchatbot-handler]
    APIGW --> Reader[Lambda\nrisk-reader]
    APIGW --> DevOps[Lambda\ndevops-analyzer]
    APIGW --> FS[Lambda\nfullstack-analyzer]
    APIGW --> DE[Lambda\ndata-eng-analyzer]
    APIGW --> Mobile[Lambda\nmobile-analyzer]

    Scanner --> AWS_S3[S3 API]
    Scanner --> AWS_EC2[EC2 API]
    Scanner --> AWS_IAM[IAM API]

    Scanner --> DDB[(DynamoDB\ncloudsentinel-risks)]
    DevOps --> DDB
    FS --> DDB
    DE --> DDB
    Mobile --> DDB

    DDB --> AIExp
    AIExp --> Bedrock[Amazon Bedrock\nClaude 3 Haiku]
    Bedrock --> AIExp
    AIExp --> DDB

    Chat --> DDB
    Chat --> Bedrock

    Reader --> DDB
    Reader --> Portal

    style Bedrock fill:#FF9900,color:#000
    style DDB fill:#4053D6,color:#fff
    style APIGW fill:#8C4FFF,color:#fff
    style Cognito fill:#D13212,color:#fff
    style Portal fill:#1A9C3E,color:#fff
```

The idea is simple — every scan Lambda just reads from AWS APIs and writes to the same DynamoDB table. Then my ai-explainer Lambda goes through all the unprocessed risks and calls Bedrock to add the AI explanation. The frontend reads everything through the risk-reader Lambda.

---

## My module — cloud-scanner and the AI layer

```mermaid
flowchart LR
    Trigger([POST /scan-cloud]) --> Scanner

    subgraph cloud-scanner Lambda
        Scanner[lambda_handler] --> S3[scan_s3_buckets]
        Scanner --> SG[scan_security_groups]
        Scanner --> IAM[scan_iam_password_policy]
        S3 --> Risk[build_risk]
        SG --> Risk
        IAM --> Risk
        Risk --> Save[save to DynamoDB]
    end

    Save --> DDB[(DynamoDB)]

    DDB --> Trigger2([trigger ai-explainer])

    subgraph ai-explainer Lambda
        Fetch[fetch OPEN risks\nwith no aiExplanation] --> Prompt[build prompt]
        Prompt --> BR[Bedrock\nClaude 3 Haiku]
        BR --> Update[update aiExplanation\nin DynamoDB]
    end

    style DDB fill:#4053D6,color:#fff
    style BR fill:#FF9900,color:#000
```

---

## Chatbot flow — how it works

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend
    participant APIGW as API Gateway
    participant Lambda as chatbot-handler
    participant DDB as DynamoDB
    participant BR as Bedrock

    U->>FE: types a question
    FE->>APIGW: POST /chat { question, module }
    APIGW->>Lambda: invoke
    Lambda->>DDB: query risks by module (last 20)
    DDB-->>Lambda: risk records
    Lambda->>BR: InvokeModel with question + risk context
    BR-->>Lambda: AI answer
    Lambda-->>APIGW: { answer }
    APIGW-->>FE: response
    FE-->>U: show in chat bubble
```

I pass the top 20 risks as context to the model so it can answer questions specifically about the user's environment, not generic cloud security stuff.

---

## DynamoDB structure

```mermaid
flowchart TD
    PK[resourceId - Partition Key] --> T[(cloudsentinel-risks)]
    SK[riskTimestamp - Sort Key] --> T

    T --> GSI1[GSI: module-index]
    T --> GSI2[GSI: priority-index]
    T --> GSI3[GSI: userId-module-index]

    GSI1 --> Q1[query by module\nfor dashboard tabs]
    GSI2 --> Q2[query High risks first\nfor summary view]
    GSI3 --> Q3[notification-handler queries\nby userId and module]
```

Three GSIs now. The userId-module-index is new — notification-handler needs it to pull open High risks for a specific user after a scan finishes.

---

## Step Functions orchestration (added in v2)

I added a Step Functions Express workflow to coordinate the scans. Before this, if you triggered a scan on the frontend it went directly to the Lambda. The problem is that all five module Lambdas run one after another on the same invocation, which is slow. With Step Functions, all five run in parallel inside a Parallel state.

```mermaid
flowchart TD
    Trigger([API call]) --> SFN[CloudSentinelScanOrchestrator\nStep Functions Express Workflow]
    SFN --> Parallel[Parallel State\nall 5 scanners run at once]
    Parallel --> AIX[ai-explainer\nBedrock call]
    AIX --> Check{High risks?}
    Check -->|yes| NH[notification-handler\nSNS email]
    Check -->|no| Done([complete])
    NH --> Done
```

Scan time went from about 10 minutes down to 2-3 minutes in practice. Each scanner state has a retry block with exponential backoff so transient AWS API throttles don't break the whole run.

---

## SNS email notification flow

When a scan finds High-priority risks, the notification-handler Lambda sends an email via SNS. The email has an HTML table listing the risks, a count by priority, and a direct link to the module dashboard.

```mermaid
sequenceDiagram
    participant SFN as Step Functions
    participant NH as notification-handler
    participant DDB as DynamoDB
    participant SNS as Amazon SNS
    participant User as User Email

    SFN->>NH: invoke with scanId and userId
    NH->>DDB: query userId-module-index for OPEN High risks
    DDB-->>NH: list of risk records
    NH->>SNS: Publish HTML email
    SNS-->>User: email delivered
    NH->>DDB: mark risks as notified=true
```

The `notified=true` flag prevents the same risks from triggering another email on the next hourly EventBridge run. Threshold is configurable via Lambda env var — default is High only, can set to Medium or All.
