# Bedrock spend limit per principal, without Lambda.
#
#   EventBridge rule (schedule) -> SSM Automation, aws:executeScript (spend_limit.py)
#     reads:  Bedrock invocation logs in each Region, through Logs Insights
#     writes: deny statements in one managed policy, as a new policy version
#     tells:  SNS, on warnings, blocks and unblocks; and SES, when var.email is set
#
# The managed policy does nothing until it is attached: to roles through
# attach_to_roles, or by name in an Identity Center permission set.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  # With pacing, the human limit changes month to month, so the script doubles it.
  paced              = var.monthly_budget_usd != null
  workload_limit_usd = var.workload_limit_usd != null ? tostring(var.workload_limit_usd) : local.paced ? "" : tostring(2 * var.human_limit_usd)

  log_group_arns = [
    for r in var.regions : "arn:${local.partition}:logs:${r}:${local.account_id}:log-group:${var.log_group_name}"
  ]

  automation_definition_arn = "arn:${local.partition}:ssm:${local.region}:${local.account_id}:automation-definition/${var.name}"

  # The bare address of var.email.from, which may carry a display name.
  emails       = var.email == null ? [] : [var.email]
  from_address = [for e in local.emails : regex("([^<>\\s]+@[^<>\\s]+)>?\\s*$", e.from)[0]]
}

# -----------------------------------------------------------------------------
# The block policy. The script owns its statements; Terraform owns its existence.
# -----------------------------------------------------------------------------
resource "aws_iam_policy" "blocks" {
  name        = var.name
  description = "Bedrock spend limit blocks. Written by the ${var.name} automation; do not edit."

  # A deny that matches no caller. The script replaces it with the real blocks.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "NoBlocks"
      Effect    = "Deny"
      Action    = "bedrock:InvokeModel"
      Resource  = "*"
      Condition = { StringEquals = { "aws:userid" = "no-principal-has-this-id" } }
    }]
  })

  tags = var.tags

  lifecycle {
    ignore_changes = [policy]
  }
}

resource "aws_iam_role_policy_attachment" "blocks" {
  for_each = toset(var.attach_to_roles)

  role       = each.value
  policy_arn = aws_iam_policy.blocks.arn
}

# -----------------------------------------------------------------------------
# Parameters: run state (the script owns it) and emergency overrides (people own it)
# -----------------------------------------------------------------------------
resource "aws_ssm_parameter" "state" {
  name        = "/${var.name}/state"
  description = "Spend limit state for the current period. Written by the automation."
  type        = "String"
  tier        = "Intelligent-Tiering"
  value       = "{}"
  tags        = var.tags

  lifecycle {
    ignore_changes = [value, tier]
  }
}

resource "aws_ssm_parameter" "overrides" {
  name        = "/${var.name}/overrides"
  description = "Temporary limits: {\"role:name\": {\"limit_usd\": 500, \"until\": \"2026-01-01T00:00:00Z\"}}. Edit by hand; read on every run."
  type        = "String"
  tier        = "Intelligent-Tiering"
  value       = "{}"
  tags        = var.tags

  lifecycle {
    ignore_changes = [value, tier]
  }
}

# -----------------------------------------------------------------------------
# Notifications
# -----------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name              = var.name
  kms_master_key_id = coalesce(var.kms_key_id, "alias/aws/sns")
  tags              = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# -----------------------------------------------------------------------------
# Automation
# -----------------------------------------------------------------------------
resource "aws_iam_role" "automation" {
  name = "${var.name}-automation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "automation" {
  name = "spend-limit"
  role = aws_iam_role.automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "QueryInvocationLogs"
        Effect   = "Allow"
        Action   = ["logs:StartQuery"]
        Resource = concat(local.log_group_arns, [for a in local.log_group_arns : "${a}:*"])
      },
      {
        Sid      = "ReadQueryResults"
        Effect   = "Allow"
        Action   = ["logs:GetQueryResults", "logs:StopQuery"]
        Resource = "*"
      },
      {
        Sid    = "WriteBlocks"
        Effect = "Allow"
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
        ]
        Resource = aws_iam_policy.blocks.arn
      },
      {
        Sid      = "Parameters"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = [aws_ssm_parameter.state.arn, aws_ssm_parameter.overrides.arn]
      },
      {
        Sid      = "Notify"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      ], [
      # SES checks the identity that matches the sender: the address, or its domain.
      for a in local.from_address : {
        Sid    = "Email"
        Effect = "Allow"
        Action = ["ses:SendEmail"]
        Resource = [
          "arn:${local.partition}:ses:${local.region}:${local.account_id}:identity/${a}",
          "arn:${local.partition}:ses:${local.region}:${local.account_id}:identity/${split("@", a)[1]}",
        ]
        Condition = { StringEquals = { "ses:FromAddress" = a } }
      }
    ])
  })
}

resource "aws_ssm_document" "spend_limit" {
  name            = var.name
  document_type   = "Automation"
  document_format = "JSON"
  tags            = var.tags

  content = jsonencode({
    schemaVersion = "0.3"
    description   = "Bedrock spend limit: warns and blocks principals past their limit for the ${var.period}."
    assumeRole    = "{{ AutomationAssumeRole }}"
    parameters = {
      AutomationAssumeRole = {
        type    = "String"
        default = aws_iam_role.automation.arn
      }
      DryRun = {
        type          = "String"
        default       = tostring(var.dry_run)
        allowedValues = ["true", "false"]
      }
    }
    mainSteps = [{
      name           = "CheckSpend"
      action         = "aws:executeScript"
      timeoutSeconds = 600
      inputs = {
        Runtime = "python3.11"
        Handler = "handler"
        Script  = file("${path.module}/spend_limit.py")
        InputPayload = {
          Name               = var.name
          Period             = var.period
          BlockMinutes       = tostring(var.block_minutes)
          HumanLimitUsd      = tostring(var.human_limit_usd)
          MonthlyBudgetUsd   = local.paced ? tostring(var.monthly_budget_usd) : ""
          HolidaysJson       = jsonencode(var.holidays)
          WorkloadLimitUsd   = local.workload_limit_usd
          LimitsJson         = jsonencode(var.limits)
          WarnAtJson         = jsonencode(var.warn_at)
          PricesJson         = jsonencode(var.prices)
          HumanPatternsJson  = jsonencode(var.human_role_patterns)
          ExemptPatternsJson = jsonencode(var.exempt_patterns)
          Regions            = join(",", var.regions)
          LogGroup           = var.log_group_name
          PolicyArn          = aws_iam_policy.blocks.arn
          StateParameter     = aws_ssm_parameter.state.name
          OverrideParameter  = aws_ssm_parameter.overrides.name
          TopicArn           = aws_sns_topic.alerts.arn
          EmailJson          = var.email == null ? "" : jsonencode(var.email)
          DryRun             = "{{ DryRun }}"
        }
      }
    }]
  })

  lifecycle {
    precondition {
      condition     = !local.paced || var.period == "day"
      error_message = "monthly_budget_usd paces spend as a daily limit, so it needs period = \"day\"."
    }
  }
}

# -----------------------------------------------------------------------------
# Schedule
# -----------------------------------------------------------------------------
resource "aws_iam_role" "schedule" {
  name = "${var.name}-schedule"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "schedule" {
  name = "start-automation"
  role = aws_iam_role.schedule.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "ssm:StartAutomationExecution"
        # Scoping to this document fails at runtime, with AccessDenied naming the document
        # ARN even when that exact ARN is granted. Region and account is the narrowest scope
        # that works. PassRole below still limits what a started document can do.
        Resource = "arn:${local.partition}:ssm:${local.region}:${local.account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.automation.arn
      },
    ]
  })
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = var.name
  description         = "Runs the ${var.name} Bedrock spend limit."
  schedule_expression = var.schedule_expression
  state               = var.enabled ? "ENABLED" : "DISABLED"
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "schedule" {
  rule     = aws_cloudwatch_event_rule.schedule.name
  arn      = "${local.automation_definition_arn}:$DEFAULT"
  role_arn = aws_iam_role.schedule.arn

  depends_on = [aws_ssm_document.spend_limit]
}
