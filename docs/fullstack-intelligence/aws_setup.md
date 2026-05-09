# AWS Setup — Full-Stack Module
## Janapareddy Dyns Gowrish

My notes for setting up the fullstack-analyzer Lambda. I need Sameer to deploy the base infra first. Once he shares the IAM role ARN and confirms API Gateway is up, I can do the rest on my own.

---

## Packaging

```
cd modules/fullstack
pip install boto3 -t package/
copy fullstack_analyzer.py package\
cd package
Compress-Archive -Path * -DestinationPath ..\fullstack_analyzer.zip -Force
cd ..\..
```

---

## Option 1 — Console

### Creating the Lambda

1. Lambda console > Create function > Author from scratch
2. `cloudsentinel-fullstack-analyzer`, Python 3.11
3. Use existing role: `cloudsentinel-lambda-role`
4. Upload `fullstack_analyzer.zip`
5. Add env var: `DYNAMODB_TABLE` = `cloudsentinel-risks`
6. Timeout: 2 min

### Testing

Empty `{}` body works — the Lambda scans API Gateway and CloudWatch automatically using the execution role. So all I need to do is hit Test and it runs.

To actually see risks being detected, I create a test API with no auth:
1. API Gateway > Create API > REST API
2. Name it `test-unprotected-api`
3. Add resource `/data` > GET method > Integration: Mock > Authorization: NONE
4. Deploy to a stage
5. Now run my Lambda — it should detect this unauthenticated endpoint and write a risk to DynamoDB

Check DynamoDB > cloudsentinel-risks > filter `module = fullstack` to see the result.

### Connect to API Gateway

1. cloudsentinel-api > / > Create resource `/scan-fullstack`
2. POST method > Lambda proxy > `cloudsentinel-fullstack-analyzer`
3. Save > OK on the permission popup
4. Deploy API > dev stage

---

## Option 2 — Terraform

File: `infrastructure/terraform/fullstack_lambda.tf`

```hcl
data "archive_file" "fullstack_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/fullstack"
  output_path = "${path.module}/../../modules/fullstack/fullstack_analyzer.zip"
}

resource "aws_lambda_function" "fullstack_analyzer" {
  filename         = data.archive_file.fullstack_zip.output_path
  function_name    = "cloudsentinel-fullstack-analyzer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "fullstack_analyzer.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 256
  source_code_hash = data.archive_file.fullstack_zip.output_base64sha256
  environment {
    variables = { DYNAMODB_TABLE = aws_dynamodb_table.risks.name }
  }
  tags = { Project = "CloudSentinel", Module = "fullstack" }
}

resource "aws_api_gateway_resource" "scan_fullstack" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "scan-fullstack"
}

resource "aws_api_gateway_method" "fullstack_post" {
  rest_api_id   = aws_api_gateway_resource.scan_fullstack.rest_api_id
  resource_id   = aws_api_gateway_resource.scan_fullstack.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "fullstack_int" {
  rest_api_id             = aws_api_gateway_resource.scan_fullstack.rest_api_id
  resource_id             = aws_api_gateway_resource.scan_fullstack.id
  http_method             = aws_api_gateway_method.fullstack_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.fullstack_analyzer.invoke_arn
}

resource "aws_lambda_permission" "fullstack_apigw" {
  statement_id  = "AllowAPIGatewayFullstack"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fullstack_analyzer.function_name
  principal     = "apigateway.amazonaws.com"
}
```

```
terraform plan -target=aws_lambda_function.fullstack_analyzer
terraform apply -target=aws_lambda_function.fullstack_analyzer
```
