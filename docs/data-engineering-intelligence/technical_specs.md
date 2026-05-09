# Tech Specs — Data Engineering Module
## Bikkavolu Srivallisa Sai Veerabhadra Ayyan

Quick reference for my Lambda.

---

## Lambda: cloudsentinel-data-eng-analyzer

| | |
|-|-|
| Runtime | Python 3.11 |
| Handler | `data_eng_analyzer.lambda_handler` |
| Timeout | 120 sec |
| Memory | 256 MB |
| Trigger | POST /scan-data-eng |
| Env | `DYNAMODB_TABLE=cloudsentinel-risks` |

---

## Input / Output

Input: `{}` — scans everything using execution role

Output:
```json
{ "statusCode": 200, "body": "{\"message\": \"Data Engineering scan complete\", \"risksFound\": 4}" }
```

---

## AWS calls I make

| Service | Call | Purpose |
|---------|------|---------|
| S3 | `list_buckets()` | get all |
| S3 | `get_public_access_block(Bucket)` | public access check |
| S3 | `get_bucket_encryption(Bucket)` | encryption check |
| DynamoDB | `list_tables()` paginated | get all table names |
| DynamoDB | `describe_table(TableName)` | get SSEDescription.Status |
| Glue | `get_jobs()` | list ETL jobs |
| Glue | `get_job_runs(JobName, MaxResults=5)` | last 5 run results |

---

## Sensitive keyword list

```python
SENSITIVE_PATTERNS = [
    'user', 'customer', 'client', 'patient', 'payment',
    'financial', 'pii', 'medical', 'health', 'ssn',
    'credit', 'password', 'secret', 'private', 'personal'
]
# check: any(p in bucket_name.lower() for p in SENSITIVE_PATTERNS)
```

---

## Risk thresholds

| Check | Condition | Priority |
|-------|-----------|----------|
| S3 public access block missing | NoSuchPublicAccessBlockConfiguration | High if sensitive, Medium if not |
| S3 encryption missing | ServerSideEncryptionConfigurationNotFoundError | High if sensitive, Medium if not |
| DynamoDB SSE disabled | SSEDescription.Status = DISABLED | Medium |
| Glue failures | >= 2 FAILED in last 5 runs | High |

---

## Sample DynamoDB record (what I write)

```json
{
  "resourceId":    "data-s3-customer-records-public",
  "module":        "data-eng",
  "resource":      "Data Storage",
  "resourceName":  "customer-records",
  "riskType":      "Data Bucket Public Access Not Fully Blocked",
  "riskPriority":  "High",
  "status":        "OPEN"
}
```

---

## My unit tests

File: `tests/test_data_eng_analyzer.py`

| Test | Checks |
|------|--------|
| `test_sensitive_bucket_name_detected` | buckets with "user", "customer" → `is_sensitive=True` |
| `test_normal_bucket_not_sensitive` | "app-logs", "static-assets" → `is_sensitive=False` |
| `test_build_risk_module_field` | `risk['module'] == 'data-eng'` |

Run: `pytest tests/test_data_eng_analyzer.py -v`
