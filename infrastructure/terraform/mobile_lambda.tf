# Mobile Backend module Lambda — Muramalla Ambica Sai Ram

data "archive_file" "mobile_zip" {
  type        = "zip"
  output_path = "${path.module}/../../modules/mobile/mobile_analyzer.zip"
  # scan_events is provided by the shared Lambda layer — do NOT bundle the shim
  source {
    content  = file("${path.module}/../../modules/mobile/mobile_analyzer.py")
    filename = "mobile_analyzer.py"
  }
}

resource "aws_lambda_function" "mobile_analyzer" {
  filename         = data.archive_file.mobile_zip.output_path
  function_name    = "${var.project}-mobile-analyzer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "mobile_analyzer.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 256
  source_code_hash = data.archive_file.mobile_zip.output_base64sha256
  layers           = [aws_lambda_layer_version.scan_events.arn]

  environment {
    variables = {
      DYNAMODB_TABLE         = aws_dynamodb_table.risks.name
      LATENCY_THRESHOLD_MS   = "1000"
      ERROR_5XX_THRESHOLD    = "10"
      ERROR_4XX_THRESHOLD    = "50"
      LAMBDA_ERROR_THRESHOLD = "5"
      LOOKBACK_HOURS         = "1"
    }
  }

  tags = { Project = var.project, Module = "mobile", Owner = "ambica" }
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
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "mobile_post" {
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
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}

resource "aws_cloudwatch_metric_alarm" "mobile_high_latency" {
  alarm_name          = "${var.project}-mobile-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Latency"
  namespace           = "AWS/ApiGateway"
  period              = 300
  extended_statistic  = "p95"
  threshold           = 1000
  treat_missing_data  = "notBreaching"
  alarm_description   = "p95 API latency exceeded mobile threshold of 1000ms"
  tags                = { Project = var.project, Module = "mobile" }
}
