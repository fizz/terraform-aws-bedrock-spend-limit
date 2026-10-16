# terraform-aws-bedrock-spend-limit

A spend limit on Amazon Bedrock for each person and each workload in an AWS account, enforced by IAM, with no Lambda.

Bedrock has token quotas per model and per account, and AWS Budgets reports cost a day late, for the whole account. Neither stops one person or one runaway job from spending the month's budget in an afternoon. This module prices every caller's tokens from the invocation logs every five minutes, emails a warning at 50% and 80% of their limit, and denies them Bedrock at 100% until the period ends.

## Usage

```hcl
module "bedrock_spend_limit" {
  source  = "fizz/bedrock-spend-limit/aws"
  version = "~> 0.1"

  name    = "bedrock-spend-limit"
  regions = ["us-east-1", "us-west-2"]

  period          = "day"
  human_limit_usd = 50 # workloads get twice this unless workload_limit_usd says otherwise

  alert_emails    = ["platform@example.com"]
  attach_to_roles = ["app-api", "batch-worker"]

  # USD per 1M tokens, keyed by text in the model ID. The longest matching key wins.
  prices = {
    "claude-sonnet-5-5" = { input = 2.40, output = 12.00, cache_read = 0.12, cache_write = 3.00 }
    "claude-haiku-5-5"  = { input = 0.12, output = 0.60, cache_read = 0.012, cache_write = 0.15 }
    "default"           = { input = 12.00, output = 60.00 } # the most expensive model you allow
  }
}
```

The limit reads Bedrock's model invocation logs in CloudWatch Logs. If an account has none, add them with the submodule, once per Region:

```hcl
module "bedrock_logging_east" {
  source          = "fizz/bedrock-spend-limit/aws//modules/invocation-logging"
  deliver_content = false # metadata only: caller, model and token counts, which is all the limit reads
}
```

## Who is limited, and how

| Caller | Counted as | Limited by | Blocked with |
|---|---|---|---|
| A session in a role matching `human_role_patterns` (default: Identity Center roles) | human, `user:<session>` | `human_limit_usd` | `aws:userid` ends in `:<session>` |
| Any other role | workload, `role:<role>` | `workload_limit_usd`, default twice the human limit | `aws:PrincipalArn` is the role |
| An IAM user | workload, `iam-user:<name>` | `workload_limit_usd` | `aws:PrincipalArn` is the user |

Workloads are keyed by role because their session names change with every pod and task. Humans are keyed by session because Identity Center sets the session name to the user name, and many users share one permission set's role.

`limits` sets a limit for a named principal, and `exempt_patterns` leaves callers out entirely.

**A monthly budget, paced by the day.** With `period = "day"`, `monthly_budget_usd` replaces `human_limit_usd` with the budget divided by the business days in the current month, recomputed each run. Nobody can spend the month in a week, and a month of working days spends the budget. Weekends and holidays get the same daily limit; they are only left out of the count. `holidays` takes the dates that are not business days, and `scripts/holidays.py` writes a country's public holidays as JSON:

```hcl
  period             = "day"
  monthly_budget_usd = 250 # $11.90 a day in October 2026: 22 weekdays, less Columbus Day
  holidays           = [for h in jsondecode(file("${path.module}/holidays.json")) : h.date]
```

`limits` and overrides stay daily amounts. A period of `month` with a plain limit is the other choice: one monthly total, which a person can spend in a day.

**Raising a limit in an emergency** needs no apply. Write the overrides parameter, and the next run reads it:

```sh
aws ssm put-parameter --overwrite --name /bedrock-spend-limit/overrides \
  --value '{"role:app-api": {"limit_usd": 500, "until": "2026-10-15T00:00:00Z"}}'
```

**Attaching the block policy** is how the limit reaches a principal. `attach_to_roles` does it for IAM roles. For an Identity Center permission set, attach the policy by name in the permission set (`aws_ssoadmin_customer_managed_policy_attachment` with `policy_name` output), so the reserved role in each account gets it.

## What is hard to get right

**Blocks must end on their own.** Each deny carries `aws:CurrentTime` as its expiry. If the schedule stops, or the automation breaks, nobody stays blocked past the end of the period.

**A deny in a policy stops sessions that already exist.** IAM evaluates the policy on every request, so a block also stops a session that was issued hours ago, and a Bedrock API key made from one. Removing a permission set assignment would not: the session keeps working until it expires.

**The block policy has one owner.** Terraform creates it and then ignores its content. The automation writes each change as a new policy version, and removes the oldest when IAM's limit of five versions is reached.

**The schedule cannot be scoped to its document.** EventBridge targets the automation-definition ARN, and a denied start names the `document/<name>` ARN, but granting exactly that ARN, or the automation-definition, still fails at runtime and in the IAM policy simulator. The narrowest grant that works is SSM in the Region and account. `iam:PassRole` limits the schedule to passing the automation role, so any other document it could start runs with the schedule role's own two permissions. A failed start is silent: EventBridge counts a FailedInvocation and nothing else, so watch that metric.

**Logs Insights rejects an aggregate named like a field.** `stats sum(i) as i` fails with "Ephemeral field is already defined". The query names its sums apart from its fields.

**The usage that caused a block must not cause the next one.** With a block shorter than the period, the spend that caused it is still in the window when it ends. The automation counts that principal from the end of the block.

**IAM takes seconds to apply a change everywhere.** For the first few seconds after a block, a request can still get through. The worst-case overspend is one schedule interval plus that.

**Prices are not in the log.** Invocation records carry token counts, not cost. Long-context and one-hour cache-write rates are higher than the standard rates and the log does not say which applied, so the module counts standard rates. An unlisted model is priced at the `default` entry; set it to the most expensive model you allow.

**Invocation logging is account-wide, per Region.** One setting covers every caller in the Region. Exactly one stack must own it: if another one already sets it, point this module at that log group and do not use the submodule.

**The Mantle endpoint is not counted yet.** Calls to `bedrock-mantle` (the OpenAI- and Anthropic-compatible endpoint) do not reach the invocation logs, so this version cannot price them. Its usage is in CloudWatch under `AWS/BedrockMantle`, per project and model, not per caller. Until per-principal projects are supported, do not grant `bedrock-mantle:CreateInference` to a principal this module limits. A block still denies Mantle inference along with `bedrock`.

## Testing

```sh
terraform test                                    # plan-level checks, mocked provider
python3 -I tests/test_spend_limit.py              # the script's pure functions
```
