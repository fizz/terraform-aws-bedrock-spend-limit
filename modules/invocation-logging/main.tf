# Bedrock model invocation logging for one Region, to CloudWatch Logs.
#
# Invocation logging is one setting per Region per account, and it covers every caller.
# An account has exactly one owner of it: if another stack already sets it, do not use
# this module there, and point the parent module at that stack's log group.
#
# Call once per Region, with a provider for that Region.

terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "log_group_name" {
  description = "Log group for the invocation records."
  type        = string
  default     = "/aws/bedrock/invocations"
}

variable "retention_days" {
  description = "How long CloudWatch keeps the records."
  type        = number
  default     = 365
}

variable "deliver_content" {
  description = "True logs the prompts and responses (text, image, embedding and video). False logs metadata only: caller, model and token counts, which is all the spend limit needs."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags for every resource that takes them."
  type        = map(string)
  default     = {}
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.id
}

resource "aws_kms_key" "logs" {
  description             = "Bedrock invocation logs in ${local.region}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministers"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsEncrypts"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:${var.log_group_name}"
          }
        }
      },
    ]
  })

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "invocations" {
  name              = var.log_group_name
  retention_in_days = var.retention_days
  kms_key_id        = aws_kms_key.logs.arn
  tags              = var.tags
}

resource "aws_iam_role" "logging" {
  # IAM is global. The Region in the name keeps one role per Region from colliding.
  name = "bedrock-invocation-logging-${local.region}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "logging" {
  name = "write-invocation-logs"
  role = aws_iam_role.logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.invocations.arn}:*"
    }]
  })
}

# Bedrock checks that it can write when the configuration is created, so the role's
# policy has to exist first.
resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    text_data_delivery_enabled      = var.deliver_content
    image_data_delivery_enabled     = var.deliver_content
    embedding_data_delivery_enabled = var.deliver_content
    video_data_delivery_enabled     = var.deliver_content

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.invocations.name
      role_arn       = aws_iam_role.logging.arn
    }
  }

  depends_on = [aws_iam_role_policy.logging]
}

output "log_group_name" {
  description = "The invocation log group."
  value       = aws_cloudwatch_log_group.invocations.name
}
