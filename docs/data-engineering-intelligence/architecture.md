# Architecture — Data Engineering Intelligence
## Bikkavolu Srivallisa Sai Veerabhadra Ayyan

My module scans three services: S3, DynamoDB, and Glue. Here's how it works.

---

## Overall flow

```mermaid
flowchart TD
    APIGW[POST /scan-data-eng] --> L

    subgraph Lambda: data-eng-analyzer
        L[lambda_handler] --> S3[scan_s3_data_buckets]
        L --> DB[scan_dynamodb_tables]
        L --> Glue[scan_glue_jobs]

        S3 --> Sensitive{sensitive bucket name?}
        Sensitive -->|yes| HP[priority = High]
        Sensitive -->|no| MP[priority = Medium]

        S3 --> PubCheck[check public access block]
        S3 --> EncCheck[check encryption]
        DB --> SSECheck[check SSEDescription.Status]
        Glue --> FailCheck[check last 5 job runs]

        HP --> Build[build risk]
        MP --> Build
        PubCheck --> Build
        EncCheck --> Build
        SSECheck --> Build
        FailCheck --> Build
        Build --> Save[save to DynamoDB]
    end

    style APIGW fill:#8C4FFF,color:#fff
```

---

## Sensitive name detection

This is one of the more interesting parts of my module. Instead of reading the contents of buckets (which would need data-level permissions and is way out of scope), I check if the bucket name contains words that suggest it holds sensitive data.

```mermaid
flowchart LR
    Name([bucket name]) --> Lower[.lower]
    Lower --> Check{contains any\nsensitive word?}

    Check -->|user, customer, patient,\npayment, financial, pii,\nmedical, ssn, credit,\npassword, private| High[is_sensitive = True → High priority]
    Check -->|none match| Med[is_sensitive = False → Medium priority]
```

---

## S3 check decision tree

```mermaid
flowchart TD
    B([S3 Bucket]) --> PAB{get_public_access_block\nraises exception?}
    PAB -->|NoSuchPublicAccessBlockConfiguration| R1[High or Medium:\nNo Public Access Block]
    PAB -->|exists| AllEnabled{all 4 flags = True?}
    AllEnabled -->|No| R2[High or Medium:\nPublic Access Not Fully Blocked]
    AllEnabled -->|Yes| Enc{get_bucket_encryption\nraises exception?}
    Enc -->|ServerSideEncryptionConfigurationNotFoundError| R3[High or Medium:\nEncryption Missing]
    Enc -->|configured| OK([bucket is fine])
```

Priority depends on `is_sensitive` — if True, it's High, otherwise Medium.

---

## Glue failure detection

```mermaid
sequenceDiagram
    participant L as data-eng-analyzer
    participant G as AWS Glue
    participant D as DynamoDB

    L->>G: get_jobs()
    G-->>L: job list

    loop each job
        L->>G: get_job_runs(jobName, MaxResults=5)
        G-->>L: last 5 run statuses

        alt FAILED count >= 2
            L->>D: PutItem — Repeated ETL Failures (High)
        end
    end
```

I check the last 5 runs because a single failure could be a fluke. Two or more failures in a row is a pattern worth raising.
