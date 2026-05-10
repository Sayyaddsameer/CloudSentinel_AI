# DevOps module Lambda — Kantipudi Vivek Vardhan

data "archive_file" "devops_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../modules/devops"
  output_path = "${path.module}/../../modules/devops/devops_analyzer.zip"
}

resource "aws_lambda_function" "devops_analyzer" {
  filename         = data.archive_file.devops_zip.output_path
  function_name    = "${var.project}-devops-analyzer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "devops_analyzer.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 256
  source_code_hash = data.archive_file.devops_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE      = aws_dynamodb_table.risks.name
      WEBHOOK_SECRET_ARN  = var.webhook_secret_arn
    }
  }

  tags = { Project = var.project, Module = "devops", Owner = "vivek" }
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
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "devops_post" {
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
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}
