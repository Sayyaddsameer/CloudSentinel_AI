# AWS Setup — Data Engineering Module
## Bikkavolu Srivallisa Sai Veerabhadra Ayyan

My setup for the data-eng-analyzer Lambda. Need from Sameer: IAM role ARN, confirmation DynamoDB table exists.

---

## Package and deploy

```
cd modules/data-eng
pip install boto3 -t package/
copy data_eng_analyzer.py package\
cd package
Compress-Archive -Path * -DestinationPath ..\data_eng_analyzer.zip -Force
cd ..\..
```

---

## Option 1 — Console

1. Lambda > Create function > Author from scratch
2. `cloudsentinel-data-eng-analyzer`, Python 3.11
3. Use existing role: `cloudsentinel-lambda-role`
4. Upload `data_eng_analyzer.zip`
5. Env var: `DYNAMODB_TABLE` = `cloudsentinel-risks`
6. Timeout: 2 min

### Test with a real misconfigured bucket

To see my scanner work, I create an intentionally insecure S3 bucket:
- Name: `test-customer-data-svbk` (use your own initials, include "customer" to trigger sensitve name detection)
- Uncheck Block all public access (acknowledge the warning)
- Leave encryption disabled
- Create

Then run the Lambda with the Test button. DynamoDB should show a High risk for that bucket. Delete the bucket after testing.

### Add to API Gateway

1. cloudsentinel-api > / > Create resource `/scan-data-eng`
2. POST method > Lambda proxy > `cloudsentinel-data-eng-analyzer`
3. Save > OK > Deploy API > dev

---

## Option 2 — Terraform

File: `infrastructure/terraform/data_eng_lambda.tf`

```hcl
data "archive_file" "data_eng_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/data-eng"
  output_path = "${path.module}/../../modules/data-eng/data_eng_analyzer.zip"
}

resource "aws_lambda_function" "data_eng_analyzer" {
  filename         = data.archive_file.data_eng_zip.output_path
  function_name    = "cloudsentinel-data-eng-analyzer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "data_eng_analyzer.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 256
  source_code_hash = data.archive_file.data_eng_zip.output_base64sha256
  environment {
    variables = { DYNAMODB_TABLE = aws_dynamodb_table.risks.name }
  }
  tags = { Project = "CloudSentinel", Module = "data-eng" }
}

resource "aws_api_gateway_resource" "scan_data_eng" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "scan-data-eng"
}

resource "aws_api_gateway_method" "data_eng_post" {
  rest_api_id   = aws_api_gateway_resource.scan_data_eng.rest_api_id
  resource_id   = aws_api_gateway_resource.scan_data_eng.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "data_eng_int" {
  rest_api_id             = aws_api_gateway_resource.scan_data_eng.rest_api_id
  resource_id             = aws_api_gateway_resource.scan_data_eng.id
  http_method             = aws_api_gateway_method.data_eng_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.data_eng_analyzer.invoke_arn
}

resource "aws_lambda_permission" "data_eng_apigw" {
  statement_id  = "AllowAPIGatewayDataEng"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.data_eng_analyzer.function_name
  principal     = "apigateway.amazonaws.com"
}
```

```
terraform plan -target=aws_lambda_function.data_eng_analyzer
terraform apply -target=aws_lambda_function.data_eng_analyzer
```
