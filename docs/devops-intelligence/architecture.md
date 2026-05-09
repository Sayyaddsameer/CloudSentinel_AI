# Architecture — DevOps Intelligence
## Kantipudi Vivek Vardhan

Notes on how my module works. Drew these diagrams to explain the flow to myself and to have something ready for the demo.

---

## Module flow

```mermaid
flowchart TD
    APIGW[POST /scan-devops] --> Lambda

    subgraph Lambda: devops-analyzer
        H[lambda_handler] --> E[scan_environment_variables\nregex check for secrets]
        H --> T[scan_for_test_steps\nlook for pytest / test in steps]
        H --> R[scan_for_rollback\nlook for rollback keyword]
        H --> M[scan_for_monitoring\nlook for cloudwatch / health]

        E --> Build[build_risk record]
        T --> Build
        R --> Build
        M --> Build
        Build --> Save[save to DynamoDB]
    end

    Save --> DDB[(DynamoDB\ncloudsentinel-risks)]

    style DDB fill:#4053D6,color:#fff
```

---

## CI/CD pipeline I built for the team

```mermaid
flowchart LR
    Dev([anyone pushes code]) --> GH[GitHub]
    GH --> CI[GitHub Actions\n.github/workflows/ci.yml]

    subgraph CI Jobs
        CI --> Test[Job: test\npip install + pytest]
        Test --> Scan[Job: security\nbandit scan on modules/]
    end

    Test -->|pass| PR_OK[PR can be merged]
    Test -->|fail| PR_Block[PR blocked]
    Scan --> Report[bandit-report.txt artifact]

    style GH fill:#24292e,color:#fff
    style CI fill:#2088FF,color:#fff
```

I set it to `continue-on-error: true` on both jobs for now so a test failure doesn't completely block people. Once we stabilize, I'll make tests required before merge.

---

## How my risk detection logic decides priority

```mermaid
flowchart TD
    Start([pipeline config input]) --> S[check for secret patterns]
    S -->|AKIA... or password= found| R1[HIGH — Hardcoded Credentials]
    S -->|clean| T[check for test steps]
    T -->|no test / pytest in steps| R2[HIGH — No Automated Tests]
    T -->|tests exist| R[check for rollback]
    R -->|no rollback step| R3[MEDIUM — No Rollback Strategy]
    R -->|rollback exists| Mo[check for monitoring]
    Mo -->|no monitor / health| R4[MEDIUM — No Post-Deploy Monitoring]
    Mo -->|found| Clean([no risks])
```

---

## Sequence from frontend trigger to DynamoDB

```mermaid
sequenceDiagram
    participant FE as Frontend
    participant AG as API Gateway
    participant L as devops-analyzer
    participant D as DynamoDB

    FE->>AG: POST /scan-devops { pipeline_config }
    AG->>L: invoke Lambda
    L->>L: run all 4 scans
    L->>D: PutItem for each risk found
    D-->>L: OK
    L-->>AG: 200 { risksFound: N }
    AG-->>FE: response
```

---

## Step Functions integration

Sameer added the orchestration layer using AWS Step Functions. From my side, my Lambda now gets invoked as one of five parallel branches inside the workflow instead of being called directly. My Lambda code didn't change at all — the Step Functions state machine just calls it like any other Lambda invocation, passing the same payload.

The main benefit is that all five scanners run at the same time. Previously if someone triggered all five scans the wait was sequential. The workflow also handles retries at the state machine level, so my Lambda doesn't need to implement its own retry logic for transient failures.

I also own `infrastructure/terraform/step_functions.tf` with Sameer since I wrote the DevOps scanner state in the Parallel block.
