data "aws_caller_identity" "account" {}
data "aws_region" "current" {}

# KMS Key for cloudwatch encryption
resource "aws_kms_key" "cloudwatch" {
  description = "KMS Key for ${var.name} cloudwatch encryption"
  deletion_window_in_days = 30
  enable_key_rotation = true
  policy = data.aws_iam_policy_document.cloudwatch_kms_policy.json
}

# Policy to control who has access to the cloudwatch kms key
data "aws_iam_policy_document" "cloudwatch_kms_policy" {
  statement {
    sid = "EnableIAMPermissions"
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.account.account_id}:root"]
    }
    actions = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid = "EnableCloudWatchAccess"
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]
    condition {
      test = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = ["Testing"]
    }
    resources = ["*"]
  }
}

# The actual log group name
resource "aws_cloudwatch_log_group" "log_group" {
  name = var.name
  kms_key_id = aws_kms_key.cloudwatch.arn
  retention_in_days = var.retention_days

  tags = merge(var.tags, {
    environment     = var.environment
    service         = var.service
    system          = var.system
    classification  = var.classification
  })
  
  depends_on = [
    aws_kms_key.cloudwatch
  ]
}