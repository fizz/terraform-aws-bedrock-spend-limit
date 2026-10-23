variable "name" {
  description = "Name for the policy, automation document, roles, schedule, topic and parameters."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,64}$", var.name))
    error_message = "name must be 1 to 64 letters, digits, '_', '.' or '-'."
  }
}

variable "regions" {
  description = "Regions whose Bedrock invocation logs count toward the limit. The automation runs in the provider's Region and queries each of these."
  type        = list(string)

  validation {
    condition     = length(var.regions) > 0
    error_message = "regions needs at least one Region."
  }
}

variable "log_group_name" {
  description = "The Bedrock invocation log group, with the same name in every Region. Invocation logging must already deliver to CloudWatch Logs there; the invocation-logging submodule sets it up."
  type        = string
  default     = "/aws/bedrock/invocations"
}

variable "period" {
  description = "The spend window, in UTC: day, week (from Monday) or month."
  type        = string
  default     = "day"

  validation {
    condition     = contains(["day", "week", "month"], var.period)
    error_message = "period must be day, week or month."
  }
}

variable "human_limit_usd" {
  description = "Default spend per human per period, in USD."
  type        = number
  default     = 50
}

variable "monthly_budget_usd" {
  description = "Spend per human per calendar month, in USD, paced as a daily limit: the budget divided by the business days in the current month. Needs period = day, and replaces human_limit_usd. Null turns pacing off."
  type        = number
  default     = null

  validation {
    condition     = var.monthly_budget_usd == null || try(var.monthly_budget_usd > 0, false)
    error_message = "monthly_budget_usd must be greater than 0."
  }
}

variable "holidays" {
  description = "Dates (YYYY-MM-DD) that are not business days, for monthly_budget_usd. scripts/holidays.py writes a country's public holidays as JSON."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for d in var.holidays : can(regex("^\\d{4}-\\d{2}-\\d{2}$", d))])
    error_message = "Each holiday must be a date in YYYY-MM-DD form."
  }
}

variable "workload_limit_usd" {
  description = "Default spend per workload role or IAM user per period, in USD. Null means twice the human limit, the paced daily limit included."
  type        = number
  default     = null
}

variable "limits" {
  description = "Limits in USD for named principals, keyed user:<session name>, role:<role name> or iam-user:<user name>. These replace the defaults."
  type        = map(number)
  default     = {}
}

variable "warn_at" {
  description = "Fractions of the limit that send a warning, once per period."
  type        = list(number)
  default     = [0.5, 0.8]

  validation {
    condition     = alltrue([for f in var.warn_at : f > 0 && f < 1])
    error_message = "Each warn_at value must be between 0 and 1."
  }
}

variable "block_minutes" {
  description = "How long a block lasts. 0 blocks until the period ends."
  type        = number
  default     = 0
}

variable "human_role_patterns" {
  description = "Regular expressions on the role name. A session in a matching role is a human, limited by session name. Any other role is a workload, limited as a role."
  type        = list(string)
  default     = ["^AWSReservedSSO_"]
}

variable "exempt_patterns" {
  description = "Regular expressions on the caller ARN. A matching caller is never limited."
  type        = list(string)
  default     = []
}

variable "prices" {
  description = "USD per 1M tokens, keyed by text in the model ID: input, output, and optionally cache_read and cache_write. The longest matching key wins. The \"default\" entry prices every other model."
  type        = map(map(number))

  validation {
    condition     = contains(keys(var.prices), "default")
    error_message = "prices needs a \"default\" entry. Set it to your most expensive model so an unlisted model cannot slip past the limit."
  }

  validation {
    condition     = alltrue([for k, v in var.prices : contains(keys(v), "input") && contains(keys(v), "output")])
    error_message = "Every prices entry needs input and output."
  }
}

variable "attach_to_roles" {
  description = "Names of IAM roles to attach the block policy to. For an Identity Center permission set, attach the policy by name in the permission set instead."
  type        = list(string)
  default     = []
}

variable "schedule_expression" {
  description = "How often the check runs. The worst-case overspend is one interval of usage."
  type        = string
  default     = "rate(5 minutes)"
}

variable "enabled" {
  description = "False stops the schedule. Blocks already in place still end at their expiry."
  type        = bool
  default     = true
}

variable "dry_run" {
  description = "True reports what would change, and writes nothing."
  type        = bool
  default     = false
}

variable "alert_emails" {
  description = "Addresses that get warnings, blocks and unblocks through the SNS topic. Each address must confirm the subscription. For addresses that must not have to confirm anything, use email."
  type        = list(string)
  default     = []
}

variable "email" {
  description = <<-EOT
    Sends warnings, blocks and unblocks through SES too, from the automation's Region.
    Recipients confirm nothing. from is an address, with or without a display name
    ("Name <a@example.com>"), on an SES identity (the address or its domain) that can
    send to the recipients. exclude takes principal keys (user:<session>, role:<role>,
    iam-user:<name>) whose notes and spend are left out of these emails. A notice with
    no note left is not sent. The SNS topic still gets everything. Null sends no email.
  EOT
  type = object({
    from     = string
    to       = list(string)
    bcc      = optional(list(string), [])
    reply_to = optional(list(string), [])
    exclude  = optional(list(string), [])
  })
  default = null

  validation {
    condition     = var.email == null ? true : can(regex("([^<>\\s]+@[^<>\\s]+)>?\\s*$", var.email.from))
    error_message = "email.from must be an address, optionally as \"Name <address>\"."
  }

  validation {
    condition     = var.email == null ? true : length(var.email.to) + length(var.email.bcc) > 0
    error_message = "email needs at least one address in to or bcc."
  }
}

variable "kms_key_id" {
  description = "KMS key for the topic. Null uses the AWS-managed SNS key."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for every resource that takes them."
  type        = map(string)
  default     = {}
}
