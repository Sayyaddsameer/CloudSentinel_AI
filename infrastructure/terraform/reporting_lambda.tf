/*
 * reporting_lambda.tf — CloudSentinel AI PDF Report Generator
 *
 * Creates:
 *   - S3 bucket for storing generated PDF audit reports
 *   - Lambda layer for fpdf2 (pure-Python PDF library)
 *   - pdf-generator Lambda function
 *   - API Gateway route: POST /generate-report
 *   - IAM permissions: Lambda → S3 + DynamoDB
 *
 * The pdf_generator Lambda produces branded audit reports with:
 *   - Security Posture Score (0-100 weighted metric)
 *   - 4-severity metric cards (Critical/High/Medium/Low)
 *   - AI-generated remediation text from Amazon Bedrock
 *   - Risk distribution bar chart
 */

locals {
  pdf_src_hash = filemd5("../../modules/reporting/pdf_generator.py")
}

# ── S3 Bucket for PDF Reports ─────────────────────────────────────────────

resource "aws_s3_bucket" "reports" {
  bucket        = "cloudsentinel-reports-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Project   = "CloudSentinel"
    ManagedBy = "Terraform"
    Purpose   = "AuditReports"
  }
}

resource "aws_s3_bucket_public_access_block" "reports_block" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports_enc" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports_lifecycle" {
  bucket = aws_s3_bucket.reports.id
  rule {
    id     = "expire-old-reports"
    status = "Enabled"
    expiration { days = 90 }   # Auto-delete reports older than 90 days
  }
}

# ── fpdf2 Lambda Layer ────────────────────────────────────────────────────

resource "null_resource" "build_fpdf2_layer" {
  triggers = { always_run = timestamp() }

  provisioner "local-exec" {
    interpreter = ["PowerShell", "-Command"]
    command     = <<-EOT
      New-Item -ItemType Directory -Force -Path reporting-layer/python | Out-Null
      pip install fpdf2 --target reporting-layer/python --quiet
    EOT
    working_dir = "${path.module}"
  }
}

data "archive_file" "fpdf2_layer_zip" {
  type        = "zip"
  source_dir  = "${path.module}/reporting-layer"
  output_path = "${path.module}/reporting-layer.zip"
  depends_on  = [null_resource.build_fpdf2_layer]
}

resource "aws_lambda_layer_version" "fpdf2" {
  layer_name          = "cloudsentinel-fpdf2"
  filename            = data.archive_file.fpdf2_layer_zip.output_path
  source_code_hash    = data.archive_file.fpdf2_layer_zip.output_base64sha256
  compatible_runtimes = ["python3.11"]
  description         = "fpdf2 pure-Python PDF generation library for CloudSentinel reports"
}

# ── pdf-generator Lambda package ─────────────────────────────────────────

data "archive_file" "pdf_generator_zip" {
  type        = "zip"
  source_file = "../../modules/reporting/pdf_generator.py"
  output_path = "${path.module}/pdf_generator.zip"
}

# ── pdf-generator Lambda ──────────────────────────────────────────────────

resource "aws_lambda_function" "pdf_generator" {
  function_name    = "cloudsentinel-pdf-generator"
  role             = aws_iam_role.pdf_generator_role.arn
  runtime          = "python3.11"
  handler          = "pdf_generator.lambda_handler"
  filename         = data.archive_file.pdf_generator_zip.output_path
  source_code_hash = data.archive_file.pdf_generator_zip.output_base64sha256
  timeout          = 120   # fpdf2 render + S3 upload
  memory_size      = 512   # PDF generation benefits from extra memory
  layers           = [aws_lambda_layer_version.fpdf2.arn]

  environment {
    variables = {
      DYNAMODB_TABLE       = aws_dynamodb_table.risks.name
      REPORTS_BUCKET       = aws_s3_bucket.reports.bucket
      AWS_REGION           = var.aws_region
      PRESIGNED_URL_EXPIRY = "3600"
      AMPLIFY_DOMAIN       = "https://${aws_amplify_app.frontend.default_domain}"
    }
  }

  tags = {
    Project   = "CloudSentinel"
    ManagedBy = "Terraform"
  }
}

# ── IAM Role for pdf-generator ────────────────────────────────────────────

resource "aws_iam_role" "pdf_generator_role" {
  name = "cloudsentinel-pdf-generator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "pdf_generator_policy" {
  name = "cloudsentinel-pdf-generator-policy"
  role = aws_iam_role.pdf_generator_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Logs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "DynamoRead"
        Effect = "Allow"
        Action = ["dynamodb:Scan", "dynamodb:Query", "dynamodb:GetItem"]
        Resource = [
          aws_dynamodb_table.risks.arn,
          "${aws_dynamodb_table.risks.arn}/index/*"
        ]
      },
      {
        Sid    = "S3Reports"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.reports.arn}/*"
      }
    ]
  })
}

# ── API Gateway Route: POST /generate-report ──────────────────────────────

resource "aws_lambda_permission" "pdf_generator_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pdf_generator.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.cloudsentinel_api.execution_arn}/*/*"
}

resource "aws_api_gateway_resource" "generate_report" {
  rest_api_id = aws_api_gateway_rest_api.cloudsentinel_api.id
  parent_id   = aws_api_gateway_rest_api.cloudsentinel_api.root_resource_id
  path_part   = "generate-report"
}

resource "aws_api_gateway_method" "generate_report_post" {
  rest_api_id   = aws_api_gateway_rest_api.cloudsentinel_api.id
  resource_id   = aws_api_gateway_resource.generate_report.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "generate_report" {
  rest_api_id             = aws_api_gateway_rest_api.cloudsentinel_api.id
  resource_id             = aws_api_gateway_resource.generate_report.id
  http_method             = aws_api_gateway_method.generate_report_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.pdf_generator.invoke_arn
}

# ── Outputs ───────────────────────────────────────────────────────────────

output "reports_bucket" {
  description = "S3 bucket storing CloudSentinel PDF audit reports"
  value       = aws_s3_bucket.reports.bucket
}

output "pdf_generator_function" {
  description = "PDF generator Lambda function name"
  value       = aws_lambda_function.pdf_generator.function_name
}
