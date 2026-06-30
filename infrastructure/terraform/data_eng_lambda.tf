# Data Engineering module Lambda — Bikkavolu Srivallisa Sai Veerabhadra Ayyan

data "archive_file" "data_eng_zip" {
  type        = "zip"
  output_path = "${path.module}/../../modules/data-eng/data_eng_analyzer.zip"
  # scan_events is provided by the shared Lambda layer — do NOT bundle the shim
  source {
    content  = file("${path.module}/../../modules/data-eng/data_eng_analyzer.py")
    filename = "data_eng_analyzer.py"
  }
}

resource "aws_lambda_function" "data_eng_analyzer" {
  filename         = data.archive_file.data_eng_zip.output_path
  function_name    = "${var.project}-data-eng-analyzer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "data_eng_analyzer.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 256
  source_code_hash = data.archive_file.data_eng_zip.output_base64sha256
  layers           = [aws_lambda_layer_version.scan_events.arn]

  environment {
    variables = {
      DYNAMODB_TABLE             = aws_dynamodb_table.risks.name
      DDB_REGION                 = var.aws_region
      GLUE_FAIL_THRESHOLD        = "2"
      GLUE_RUNS_WINDOW           = "5"
      STS_EXTERNAL_ID            = var.sts_external_id
      AI_EXPLAINER_FUNCTION_NAME = aws_lambda_function.ai_explainer.function_name
      AMPLIFY_DOMAIN             = var.amplify_domain
    }
  }

  tags = { Project = var.project, Module = "data-eng", Owner = "srivallisa" }
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
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "data_eng_post" {
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
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}
