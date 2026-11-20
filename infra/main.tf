data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

locals {
  account = data.aws_caller_identity.me.account_id
  region  = data.aws_region.current.region

  # The harness is created outside Terraform (infra/harness.py). Its ARN is
  # written to infra/harness.json; Terraform reads it so the chat Lambda keeps
  # the value on later applies.
  harness_json = try(jsondecode(file("${path.module}/harness.json")), {})
  harness_arn  = try(local.harness_json.harness_arn, "")

  # Harness names have no hyphens, ids look like trustedhand-<10 chars>.
  harness_arn_pattern = "arn:aws:bedrock-agentcore:${local.region}:${local.account}:harness/trustedhand-*"

  web_origin = "https://${aws_cloudfront_distribution.web.domain_name}"
}
