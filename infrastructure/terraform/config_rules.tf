# AWS Config managed rules for cloud infrastructure compliance
#
# NOTE: AWS allows only 1 configuration recorder per account per region.
# This project does NOT create a recorder — it expects one to already exist
# (or for the account owner to enable it separately).
# The Config rules below work with any active recorder in the account.
#
# IAM role is still created so the recorder (if created manually) can use it.

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

# Managed Config rules — no depends_on on recorder so they deploy without conflict.
# AWS will evaluate these rules using whichever recorder is active in the account.
resource "aws_config_config_rule" "s3_public_read_prohibited" {
  name = "${var.project}-s3-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}

resource "aws_config_config_rule" "restricted_ssh" {
  name = "${var.project}-restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
}

resource "aws_config_config_rule" "iam_password_policy" {
  name = "${var.project}-iam-password-policy"
  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }
  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "false"
    RequireNumbers             = "true"
    MinimumPasswordLength      = "14"
    PasswordReusePrevention    = "5"
    MaxPasswordAge             = "90"
  })
}
