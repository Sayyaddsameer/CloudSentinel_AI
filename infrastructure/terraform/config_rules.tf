# AWS Config managed rules for cloud infrastructure compliance
# NOTE: Config recorder is NOT created here — AWS allows only 1 recorder per account/region.
# If the account already has a recorder (e.g. from another project), the rules below
# depend on it being enabled. The recorder resource is intentionally omitted to avoid
# the MaxNumberOfConfigurationRecordersExceededException limit error.

# IAM role for AWS Config service
resource "aws_iam_role" "config_role" {
  name = "${var.project}-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}
