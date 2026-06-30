# Full-Stack module Lambda — Janapareddy Dyns Gowrish

data "archive_file" "fullstack_zip" {
  type        = "zip"
  output_path = "${path.module}/../../modules/fullstack/fullstack_analyzer.zip"
  # scan_events is provided by the shared Lambda layer — do NOT bundle the shim
  source {
    content  = file("${path.module}/../../modules/fullstack/fullstack_analyzer.py")
    filename = "fullstack_analyzer.py"
  }
}

resource "aws_lambda_function" "fullstack_analyzer" {
  filename         = data.archive_file.fullstack_zip.output_path
  function_name    = "${var.project}-fullstack-analyzer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "fullstack_analyzer.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 256
  source_code_hash = data.archive_file.fullstack_zip.output_base64sha256
  layers           = [aws_lambda_layer_version.scan_events.arn]

  environment {
    variables = {
      DYNAMODB_TABLE            = aws_dynamodb_table.risks.name
      DDB_REGION                = var.aws_region
      LATENCY_THRESHOLD_MS      = "2000"
      ERROR_5XX_THRESHOLD       = "10"
      LOOKBACK_HOURS            = "1"
      STS_EXTERNAL_ID           = var.sts_external_id
      AI_EXPLAINER_FUNCTION_NAME = aws_lambda_function.ai_explainer.function_name
      AMPLIFY_DOMAIN            = var.amplify_domain
    }
  }

  tags = { Project = var.project, Module = "fullstack" }
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
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "fullstack_post" {
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
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}
