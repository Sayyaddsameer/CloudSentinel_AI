# Data Engineering module Lambda — Bikkavolu Srivallisa Sai Veerabhadra Ayyan

data "archive_file" "data_eng_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/data-eng"
  output_path = "${path.module}/../../modules/data-eng/data_eng_analyzer.zip"
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

  environment {
    variables = {
      DYNAMODB_TABLE      = aws_dynamodb_table.risks.name
      GLUE_FAIL_THRESHOLD = "2"
      GLUE_RUNS_WINDOW    = "5"
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
  authorization = "NONE"
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
