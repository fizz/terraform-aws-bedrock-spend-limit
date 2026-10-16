# Plan-level checks with a mocked provider: no credentials, no account.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_region" {
    defaults = {
      id = "us-east-1"
    }
  }

  mock_resource "aws_iam_policy" {
    override_during = plan
    defaults = {
      arn = "arn:aws:iam::111122223333:policy/test"
    }
  }

  mock_resource "aws_iam_role" {
    override_during = plan
    defaults = {
      arn = "arn:aws:iam::111122223333:role/test"
    }
  }

  mock_resource "aws_sns_topic" {
    override_during = plan
    defaults = {
      arn = "arn:aws:sns:us-east-1:111122223333:test"
    }
  }

  mock_resource "aws_ssm_parameter" {
    override_during = plan
    defaults = {
      arn = "arn:aws:ssm:us-east-1:111122223333:parameter/test"
    }
  }
}

variables {
  name    = "test"
  regions = ["us-east-1", "us-west-2"]
  prices = {
    "claude-sonnet-5-5" = { input = 2.4, output = 12 }
    "default"           = { input = 12, output = 60 }
  }
}

run "workload_limit_defaults_to_twice_the_human_limit" {
  command = plan

  variables {
    human_limit_usd = 30
  }

  assert {
    condition     = jsondecode(aws_ssm_document.spend_limit.content).mainSteps[0].inputs.InputPayload.WorkloadLimitUsd == "60"
    error_message = "With no workload_limit_usd, workloads get twice the human limit."
  }
}

run "schedule_may_start_automations_in_its_region_and_account" {
  command = plan

  assert {
    condition     = jsondecode(aws_iam_role_policy.schedule.policy).Statement[0].Resource == "arn:aws:ssm:us-east-1:111122223333:*"
    error_message = "A document-scoped grant fails at runtime; the schedule needs the Region and account."
  }

  assert {
    condition     = jsondecode(aws_iam_role_policy.schedule.policy).Statement[1].Resource == "arn:aws:iam::111122223333:role/test"
    error_message = "The schedule may pass only the automation role."
  }

  assert {
    condition     = aws_cloudwatch_event_target.schedule.arn == "arn:aws:ssm:us-east-1:111122223333:automation-definition/test:$DEFAULT"
    error_message = "The schedule targets the automation-definition."
  }
}

run "automation_may_query_every_region" {
  command = plan

  assert {
    condition = alltrue([
      for r in ["us-east-1", "us-west-2"] : contains(
        jsondecode(aws_iam_role_policy.automation.policy).Statement[0].Resource,
        "arn:aws:logs:${r}:111122223333:log-group:/aws/bedrock/invocations"
      )
    ])
    error_message = "The automation needs StartQuery on the log group in each Region."
  }
}

run "block_policy_starts_with_a_deny_that_matches_no_one" {
  command = plan

  assert {
    condition     = jsondecode(aws_iam_policy.blocks.policy).Statement[0].Condition.StringEquals["aws:userid"] == "no-principal-has-this-id"
    error_message = "The first version of the block policy must not block anyone."
  }
}

run "govcloud_arns" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = { partition = "aws-us-gov" }
  }

  override_data {
    target = data.aws_region.current
    values = { id = "us-gov-east-1" }
  }

  variables {
    regions = ["us-gov-east-1", "us-gov-west-1"]
  }

  assert {
    condition     = jsondecode(aws_iam_role_policy.schedule.policy).Statement[0].Resource == "arn:aws-us-gov:ssm:us-gov-east-1:111122223333:*"
    error_message = "ARNs use the partition the account is in."
  }

  assert {
    condition = contains(
      jsondecode(aws_iam_role_policy.automation.policy).Statement[0].Resource,
      "arn:aws-us-gov:logs:us-gov-west-1:111122223333:log-group:/aws/bedrock/invocations"
    )
    error_message = "Log group ARNs use the partition the account is in."
  }
}

run "prices_need_a_default" {
  command = plan

  variables {
    prices = { "claude-sonnet-5-5" = { input = 2.4, output = 12 } }
  }

  expect_failures = [var.prices]
}

run "period_is_checked" {
  command = plan

  variables {
    period = "fortnight"
  }

  expect_failures = [var.period]
}

run "attach_to_roles" {
  command = plan

  variables {
    attach_to_roles = ["app", "worker"]
  }

  assert {
    condition     = length(aws_iam_role_policy_attachment.blocks) == 2
    error_message = "Each named role gets the block policy."
  }
}

run "pacing_passes_the_budget_and_holidays" {
  command = plan

  variables {
    monthly_budget_usd = 250
    holidays           = ["2026-10-12"]
  }

  assert {
    condition     = jsondecode(aws_ssm_document.spend_limit.content).mainSteps[0].inputs.InputPayload.MonthlyBudgetUsd == "250"
    error_message = "The script needs the monthly budget to pace it."
  }

  assert {
    condition     = jsondecode(jsondecode(aws_ssm_document.spend_limit.content).mainSteps[0].inputs.InputPayload.HolidaysJson) == ["2026-10-12"]
    error_message = "The script needs the holidays to count business days."
  }

  assert {
    condition     = jsondecode(aws_ssm_document.spend_limit.content).mainSteps[0].inputs.InputPayload.WorkloadLimitUsd == ""
    error_message = "With pacing and no workload_limit_usd, the script doubles the paced limit."
  }
}

run "pacing_needs_a_daily_period" {
  command = plan

  variables {
    monthly_budget_usd = 250
    period             = "month"
  }

  expect_failures = [aws_ssm_document.spend_limit]
}

run "holidays_are_dates" {
  command = plan

  variables {
    holidays = ["Oct 12"]
  }

  expect_failures = [var.holidays]
}
