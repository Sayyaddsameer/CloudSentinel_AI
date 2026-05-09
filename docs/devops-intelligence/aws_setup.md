# AWS Setup — DevOps Module
## Kantipudi Vivek Vardhan

My setup notes for getting the devops-analyzer Lambda up and running. I need the base infrastructure from Sameer first before I can do any of this. Specifically need:
- The IAM role ARN (`cloudsentinel-lambda-role`)
- Confirmation that DynamoDB table exists

---

## Getting the code ready

First thing I did was write `devops_analyzer.py` inside `modules/devops/`. The logic checks CI pipeline configs for:
- hardcoded secrets/credentials
- missing test steps
- no rollback defined
- no monitoring/health check after deploy

Once the code is done, pack it:
```
cd modules/devops
pip install boto3 -t package/
copy devops_analyzer.py package\
cd package
Compress-Archive -Path * -DestinationPath ..\devops_analyzer.zip -Force
cd ..\..
```

---

## Option 1 — Console (no Terraform)

### Create the Lambda

1. Lambda > Create function > Author from scratch
2. Name it `cloudsentinel-devops-analyzer`
3. Python 3.11
4. Under Permissions — switch to "Use an existing role" → `cloudsentinel-lambda-role` (Sameer gives you the name)
5. Create function
6. Upload from > .zip > pick `devops_analyzer.zip` > Save
7. Configuration tab > Environment variables > Add `DYNAMODB_TABLE` = `cloudsentinel-risks`
8. General configuration > set Timeout to 2 min (default 3 seconds is way too short)

### Test it

I use a test event that simulates a minimal pipeline with no tests and no rollback:
```json
{
  "repo_name": "CloudSentinel_AI",
  "pipeline_config": {
    "jobs": {
      "build": {
        "steps": [
          {"name": "install", "run": "pip install -r requirements.txt"},
          {"name": "deploy", "run": "aws lambda update-function-code --function-name test"}
        ]
      }
    }
  }
}
```

Expected result: 2 risks detected (no tests + no rollback). Both appear in DynamoDB.

To verify in DynamoDB: Explore table items, filter `module = devops`.

### Hook into API Gateway

Sameer added `/scan-devops` as a resource in the API Gateway already. I just need to confirm the Lambda is connected:
1. API Gateway > cloudsentinel-api > /scan-devops > POST
2. Check Lambda Function field shows `cloudsentinel-devops-analyzer`
3. If I added it myself: POST method, Lambda Proxy integration, enter my Lambda name, Save

Then Actions > Deploy API > stage `dev`.

---

## Option 2 — Terraform

I created `infrastructure/terraform/devops_lambda.tf`. Sameer runs `main.tf` first (DynamoDB, IAM role, API Gateway) and then I run my specific file.

```hcl
data "archive_file" "devops_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/devops"
  output_path = "${path.module}/../../modules/devops/devops_analyzer.zip"
}

resource "aws_lambda_function" "devops_analyzer" {
  filename         = data.archive_file.devops_zip.output_path
  function_name    = "cloudsentinel-devops-analyzer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "devops_analyzer.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 256
  source_code_hash = data.archive_file.devops_zip.output_base64sha256
  environment {
    variables = { DYNAMODB_TABLE = aws_dynamodb_table.risks.name }
  }
  tags = { Project = "CloudSentinel", Module = "devops" }
}

resource "aws_api_gateway_resource" "scan_devops" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "scan-devops"
}

resource "aws_api_gateway_method" "devops_post" {
  rest_api_id   = aws_api_gateway_resource.scan_devops.rest_api_id
  resource_id   = aws_api_gateway_resource.scan_devops.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "devops_int" {
  rest_api_id             = aws_api_gateway_resource.scan_devops.rest_api_id
  resource_id             = aws_api_gateway_resource.scan_devops.id
  http_method             = aws_api_gateway_method.devops_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.devops_analyzer.invoke_arn
}

resource "aws_lambda_permission" "devops_apigw" {
  statement_id  = "AllowAPIGatewayDevops"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.devops_analyzer.function_name
  principal     = "apigateway.amazonaws.com"
}
```

Deploy:
```
cd infrastructure/terraform
terraform init
terraform plan -target=aws_lambda_function.devops_analyzer
terraform apply -target=aws_lambda_function.devops_analyzer
```

Quick check after:
```
aws lambda invoke --function-name cloudsentinel-devops-analyzer --payload "{}" --cli-binary-format raw-in-base64-out out.json --region us-east-1
type out.json
```

---

## CI Workflow

I'm also responsible for the GitHub Actions CI that runs for everyone's code. Created `.github/workflows/ci.yml`. It runs `pytest tests/ -v` on every push to a feature branch and every PR to develop. Also runs `bandit` for basic security scanning of the Python code.

View build results under the Actions tab on GitHub.
