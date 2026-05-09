# Tech Specs — DevOps Module
## Kantipudi Vivek Vardhan

Quick reference for my Lambda and the CI workflow.

---

## Lambda: cloudsentinel-devops-analyzer

| | |
|-|-|
| Runtime | Python 3.11 |
| Handler | `devops_analyzer.lambda_handler` |
| Timeout | 120 seconds |
| Memory | 256 MB |
| Trigger | POST /scan-devops |
| Env var | `DYNAMODB_TABLE=cloudsentinel-risks` |

---

## Input format

If someone calls the API they pass a pipeline config. But if they call with just `{}`, my function uses a built-in sample pipeline that's intentionally missing test and rollback steps — so there's always something to demo.

```json
{
  "repo_name": "CloudSentinel_AI",
  "pipeline_config": {
    "jobs": {
      "build": {
        "steps": [
          {"name": "install", "run": "pip install -r requirements.txt"},
          {"name": "deploy", "run": "aws lambda update-function-code..."}
        ]
      }
    }
  }
}
```

## Output

```json
{ "statusCode": 200, "body": "{\"message\": \"DevOps scan complete\", \"risksFound\": 2}" }
```

---

## Risk rules

| What I check | How | Priority |
|-------------|-----|----------|
| Secrets in env vars or step commands | Regex match | High |
| No test or pytest step | String search in step names/commands | High |
| No rollback step | String search | Medium |
| No monitor/health step | String search | Medium |

Secret regex patterns:
```python
PATTERNS = [
    r'(?i)(password|secret|token|api_key)\s*[:=]\s*["\']?\w{8,}',
    r'AKIA[0-9A-Z]{16}',
]
```

---

## DynamoDB record example (what I write)

```json
{
  "resourceId":    "devops-CloudSentinel_AI-no-tests",
  "riskTimestamp": "2024-01-15T10:30:00Z",
  "module":        "devops",
  "resource":      "CI/CD Pipeline",
  "resourceName":  "CloudSentinel_AI",
  "riskType":      "No Automated Tests in CI Pipeline",
  "riskReason":    "Pipeline has no test step — code is deployed untested",
  "riskPriority":  "High",
  "remediationSteps": ["Add pytest step before the deploy step", "Fail pipeline if tests don't pass"],
  "alternativeSolutions": ["Add GitHub Actions test matrix"],
  "aiExplanation": "",
  "status":        "OPEN",
  "region":        "us-east-1"
}
```

---

## CI Workflow (my responsibility)

File: `.github/workflows/ci.yml`

Runs on: push to `feature/**` or `develop`, PR to `main` or `develop`

Jobs:
1. `test` — installs dependencies, runs `pytest tests/ -v --tb=short`
2. `security` — runs `bandit -r modules/` after tests pass

Both set to `continue-on-error: true` for now so broken tests don't block everyone. Will tighten this before the final demo.

---

## Unit tests I wrote

File: `tests/test_devops_analyzer.py`

| Test | What it checks |
|------|---------------|
| `test_pipeline_with_no_tests` | Pipeline with only a deploy step → 1 High risk |
| `test_pipeline_with_tests_passes` | Pipeline with a pytest step → 0 risks |
| `test_no_rollback_flagged` | No rollback step → 1 Medium risk |

Run locally: `pytest tests/test_devops_analyzer.py -v`
