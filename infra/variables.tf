variable "region" {
  type    = string
  default = "us-east-1"
}

variable "aws_profile" {
  type    = string
  default = "sarcastic-soul"
}

variable "table_prefix" {
  type    = string
  default = "th-"
}

variable "trusted_contact_email" {
  description = "Email for approval notices (SNS). Empty means no subscription."
  type        = string
  default     = ""
}

variable "global_daily_runs" {
  description = "Global cap on agent runs per day (R11)."
  type        = number
  default     = 1000
}

variable "local_dev_origin" {
  description = "Extra CORS origin for local web development."
  type        = string
  default     = "http://localhost:8000"
}

variable "conditional_policy_validation_mode" {
  description = "Cedar validation mode for the conditional permits (pay_bill, request_new_payee). Fall back to IGNORE_ALL_FINDINGS if the validator rejects them."
  type        = string
  default     = "FAIL_ON_ANY_FINDINGS"
}

variable "per_payment_max_inr" {
  description = "Cedar cap for pay_bill. Must match DEFAULT_LIMITS per_payment (R3)."
  type        = number
  default     = 10000
}

variable "new_payee_max_inr" {
  description = "Cedar cap for request_new_payee."
  type        = number
  default     = 50000
}
