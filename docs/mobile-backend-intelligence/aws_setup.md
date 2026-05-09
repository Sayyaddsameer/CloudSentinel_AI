# AWS Setup — Mobile Backend Module
## Muramalla Ambica Sai Ram

My notes for deploying the mobile-analyzer Lambda. Since I'm dealing with mobile-specific thresholds, my setup is similar to Gowrish's full-stack module but with different rules.

Need from Sameer: IAM role ARN, DynamoDB table confirmation.

---

## Package

```
cd modules/mobile
pip install boto3 -t package/
copy mobile_analyzer.py package\
cd package
Compress-Archive -Path * -DestinationPath ..\mobile_analyzer.zip -Force
cd ..\..
```

---

## Option 1 — Console

1. Lambda > Create function > Author from scratch
2. `cloudsentinel-mobile-analyzer`, Python 3.11
3. Use existing role: `cloudsentinel-lambda-role`
4. Upload `mobile_analyzer.zip`
5. Env var: `DYNAMODB_TABLE` = `cloudsentinel-risks`
6. Timeout: 2 min

### Test
Empty `{}` body. The Lambda scans CloudWatch and API Gateway automatically.

It may detect CORS issues on the cloudsentinel-api itself if OPTIONS method isn't configured on all resources — that's expected and is actually a real finding.

Check DynamoDB > filter `module = mobile` to see results.

### Add to API Gateway
1. cloudsentinel-api > / > Create resource `/scan-mobile`  
2. POST method > Lambda proxy > `cloudsentinel-mobile-analyzer`
3. Save > OK > Deploy API > dev

### Add a CloudWatch Alarm (optional but good for demo)
1. CloudWatch > Alarms > Create alarm
2. Metric: API Gateway > Latency for cloudsentinel-api
3. Statistic: p95, Period: 5 min
4. Threshold: Greater than 1000
5. Name: `cloudsentinel-mobile-high-latency`

---

## Option 2 — Terraform

File: `infrastructure/terraform/mobile_lambda.tf`

```hcl
data "archive_file" "mobile_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/mobile"
  output_path = "${path.module}/../../modules/mobile/mobile_analyzer.zip"
}

resource "aws_lambda_function" "mobile_analyzer" {
  filename         = data.archive_file.mobile_zip.output_path
  function_name    = "cloudsentinel-mobile-analyzer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "mobile_analyzer.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 256
  source_code_hash = data.archive_file.mobile_zip.output_base64sha256
  environment {
    variables = { DYNAMODB_TABLE = aws_dynamodb_table.risks.name }
  }
  tags = { Project = "CloudSentinel", Module = "mobile" }
}

resource "aws_api_gateway_resource" "scan_mobile" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "scan-mobile"
}

resource "aws_api_gateway_method" "mobile_post" {
  rest_api_id   = aws_api_gateway_resource.scan_mobile.rest_api_id
  resource_id   = aws_api_gateway_resource.scan_mobile.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "mobile_int" {
  rest_api_id             = aws_api_gateway_resource.scan_mobile.rest_api_id
  resource_id             = aws_api_gateway_resource.scan_mobile.id
  http_method             = aws_api_gateway_method.mobile_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.mobile_analyzer.invoke_arn
}

resource "aws_lambda_permission" "mobile_apigw" {
  statement_id  = "AllowAPIGatewayMobile"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.mobile_analyzer.function_name
  principal     = "apigateway.amazonaws.com"
}

resource "aws_cloudwatch_metric_alarm" "mobile_latency" {
  alarm_name          = "cloudsentinel-mobile-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Latency"
  namespace           = "AWS/ApiGateway"
  period              = 300
  statistic           = "p95"
  threshold           = 1000
  treat_missing_data  = "notBreaching"
  tags = { Project = "CloudSentinel", Module = "mobile" }
}
```

```
terraform plan -target=aws_lambda_function.mobile_analyzer
terraform apply -target=aws_lambda_function.mobile_analyzer
```
