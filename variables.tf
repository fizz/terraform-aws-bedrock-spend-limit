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

variable "workload_limit_usd" {
  description = "Default spend per workload role or IAM user per period, in USD. Null means twice the human limit."
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
  description = "Addresses that get warnings, blocks and unblocks. Each address must confirm the subscription."
  type        = list(string)
  default     = []
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
