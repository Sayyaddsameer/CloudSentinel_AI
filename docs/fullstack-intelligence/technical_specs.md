# Tech Specs — Full-Stack Module
## Janapareddy Dyns Gowrish

Notes on my Lambda function for quick reference.

---

## Lambda: cloudsentinel-fullstack-analyzer

| | |
|-|-|
| Runtime | Python 3.11 |
| Handler | `fullstack_analyzer.lambda_handler` |
| Timeout | 120 sec |
| Memory | 256 MB |
| Trigger | POST /scan-fullstack |
| Env | `DYNAMODB_TABLE=cloudsentinel-risks` |

---

## Input / Output

Input: empty `{}` — scans everything using the Lambda execution role

Output:
```json
{ "statusCode": 200, "body": "{\"message\": \"Full-Stack scan complete\", \"risksFound\": 2}" }
```

---

## What APIs I call

- `apigateway.get_rest_apis()` → list all REST APIs in account
- `apigateway.get_resources(restApiId)` → per API
- `apigateway.get_method(restApiId, resourceId, httpMethod)` → check `authorizationType`
- `apigateway.get_stages(restApiId)` → check `defaultRouteSettings.throttlingBurstLimit`
- `cloudwatch.get_metric_statistics(MetricName="5XXError", ...)` → sum over last 1 hour
- `cloudwatch.get_metric_statistics(MetricName="Latency", ...)` → average over last 1 hour

---

## Risk thresholds

| Check | Condition | Priority |
|-------|-----------|----------|
| Auth type | `authorizationType=NONE` and `apiKeyRequired=false` | High |
| Throttling | `throttlingBurstLimit` not set on stage | Medium |
| 5XX errors | sum > 10 in last hour | High |
| Latency | average > 2000ms in last hour | Medium |

My latency threshold is 2000ms. Ambica uses 1000ms for mobile — we agreed on this split.

---

## DynamoDB record I write for unauthenticated endpoint

```json
{
  "resourceId":    "apigw-test-api-GET-data",
  "module":        "fullstack",
  "resource":      "API Gateway",
  "resourceName":  "test-api GET /data",
  "riskType":      "Unauthenticated API Endpoint",
  "riskReason":    "Method has no authentication. Anyone with the URL can call this endpoint.",
  "riskPriority":  "High",
  "remediationSteps": [
    "Add Cognito User Pool authorizer to the method",
    "Or add AWS_IAM authorization"
  ],
  "status": "OPEN"
}
```

---

## Test I wrote

File: `tests/test_fullstack_analyzer.py`

Main checks:
- build_risk returns a dict with all required fields
- `module` field is always `"fullstack"`
- `riskPriority` is one of High/Medium/Low

Run: `pytest tests/test_fullstack_analyzer.py -v`
