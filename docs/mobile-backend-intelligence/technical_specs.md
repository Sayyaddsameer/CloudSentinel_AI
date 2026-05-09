# Tech Specs — Mobile Backend Module
## Muramalla Ambica Sai Ram

Quick reference. Most of this mirrors Gowrish's setup but with mobile-specific thresholds.

---

## Lambda: cloudsentinel-mobile-analyzer

| | |
|-|-|
| Runtime | Python 3.11 |
| Handler | `mobile_analyzer.lambda_handler` |
| Timeout | 120 sec |
| Memory | 256 MB |
| Trigger | POST /scan-mobile |
| Env | `DYNAMODB_TABLE=cloudsentinel-risks` |

---

## Input / Output

Input: `{}` — scans CloudWatch, API Gateway, and Lambda functions automatically

Output:
```json
{ "statusCode": 200, "body": "{\"message\": \"Mobile Backend scan complete\", \"risksFound\": 3}" }
```

---

## Risk thresholds (mobile-specific)

| Check | Threshold | Priority | vs full-stack module |
|-------|-----------|----------|---------------------|
| API latency (p95) | > 1000ms | High | Full-stack uses 2000ms |
| 5XX error rate | > 10 in 1 hr | High | Same |
| 4XX error rate | > 50 in 1 hr | Medium | More lenient (token refresh normal) |
| Lambda errors | > 5 in 1 hr | High | Additional check not in full-stack |
| Missing CORS | OPTIONS method absent | Medium | Mobile-specific check |

---

## CloudWatch call for latency

```python
cloudwatch.get_metric_statistics(
    Namespace  = "AWS/ApiGateway",
    MetricName = "Latency",
    StartTime  = now - timedelta(hours=1),
    EndTime    = now,
    Period     = 3600,
    Statistics = ["Average"]
)
# flag if result > 1000ms
```

---

## Sample DynamoDB record

```json
{
  "resourceId":    "mobile-apigw-latency-cloudsentinel-api",
  "module":        "mobile",
  "resource":      "API Gateway",
  "resourceName":  "cloudsentinel-api",
  "riskType":      "High Mobile API Latency",
  "riskReason":    "Average latency 1450ms exceeds 1000ms mobile threshold",
  "riskPriority":  "High",
  "status":        "OPEN"
}
```

---

## Tests

File: `tests/test_mobile_analyzer.py`

| Test | Expected |
|------|----------|
| `test_latency_risk_mobile_threshold` | 1500ms → High risk |
| `test_latency_no_risk_below_threshold` | 800ms → no risk |
| `test_module_field_is_mobile` | `risk['module'] == 'mobile'` |

Run: `pytest tests/test_mobile_analyzer.py -v`
