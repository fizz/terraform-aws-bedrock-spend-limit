output "policy_arn" {
  description = "ARN of the block policy. Attach it to every role the limit covers."
  value       = aws_iam_policy.blocks.arn
}

output "policy_name" {
  description = "Name of the block policy, for an Identity Center customer-managed policy attachment."
  value       = aws_iam_policy.blocks.name
}

output "topic_arn" {
  description = "SNS topic for warnings, blocks and unblocks."
  value       = aws_sns_topic.alerts.arn
}

output "overrides_parameter" {
  description = "SSM parameter that holds temporary limits. Edit it by hand; the next run reads it."
  value       = aws_ssm_parameter.overrides.name
}

output "document_name" {
  description = "The SSM Automation document. Start it by hand to check spend now."
  value       = aws_ssm_document.spend_limit.name
}
