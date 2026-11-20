# AgentCore Policy engine, Gateway, target, Cedar policies, harness role.
# The harness itself is created by infra/harness.py (the provider has no hooks).

locals {
  # Tool schemas copied from docs/DESIGN.md ("Tool schemas").
  bank_tools = {
    list_bills = {
      description = "List this household's bills with amount due and status."
      properties  = {}
    }
    list_payees = {
      description = "List approved payees (masked accounts) and when each can first be paid."
      properties  = {}
    }
    pay_bill = {
      description = "Pay one bill from the bill list. amount_inr must equal the amount due."
      properties = {
        bill_id    = { type = "string", description = "bill_id from list_bills", required = true }
        amount_inr = { type = "integer", description = "whole rupees", required = true }
      }
    }
    request_new_payee = {
      description = "Ask the trusted contact to approve paying someone new. Nothing is paid until they approve."
      properties = {
        payee_name = { type = "string", description = null, required = true }
        account    = { type = "string", description = "UPI ID or bank account number", required = true }
        amount_inr = { type = "integer", description = null, required = true }
        reason     = { type = "string", description = null, required = true }
      }
    }
    payment_status = {
      description = "Today's spending against limits, recent payments, pending requests, freeze status."
      properties  = {}
    }
  }

  # Unconditional permits: the validator calls these "Overly Permissive", so they
  # need IGNORE_ALL_FINDINGS. Conditional permits use the stricter mode.
  cedar_policies = {
    permit_list_bills = {
      file = "list_bills.cedar"
      mode = "IGNORE_ALL_FINDINGS"
      desc = "A1: list bills"
    }
    permit_list_payees = {
      file = "list_payees.cedar"
      mode = "IGNORE_ALL_FINDINGS"
      desc = "A1: list payees"
    }
    permit_payment_status = {
      file = "payment_status.cedar"
      mode = "IGNORE_ALL_FINDINGS"
      desc = "A4: payment status"
    }
    permit_pay_bill = {
      file = "pay_bill.cedar"
      mode = var.conditional_policy_validation_mode
      desc = "R3: pay_bill amount 1 to per-payment max"
    }
    permit_request_new_payee = {
      file = "request_new_payee.cedar"
      mode = var.conditional_policy_validation_mode
      desc = "A3: request_new_payee amount 1 to 50000"
    }
  }
}

resource "aws_bedrockagentcore_policy_engine" "p" {
  name        = "trustedhand_policies"
  description = "TrustedHand Cedar policies (default deny)"
}

# ---- Gateway role ----
data "aws_iam_policy_document" "agentcore_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account]
    }
  }
}

resource "aws_iam_role" "gateway" {
  name               = "th-gateway-role"
  assume_role_policy = data.aws_iam_policy_document.agentcore_trust.json
}

resource "aws_iam_role_policy" "gateway" {
  name = "inline"
  role = aws_iam_role.gateway.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = [
          aws_lambda_function.fn["tools"].arn,
          aws_lambda_function.fn["interceptor"].arn,
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:AuthorizeAction",
          "bedrock-agentcore:PartiallyAuthorizeActions",
          "bedrock-agentcore:GetPolicyEngine",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock-agentcore:GetWorkloadAccessToken"]
        Resource = "*"
      },
    ]
  })
}

# IAM is eventually consistent; the gateway checks the role at create time.
resource "time_sleep" "iam_settle" {
  create_duration = "20s"
  triggers = {
    gateway_role = aws_iam_role_policy.gateway.id
  }
}

# ---- Gateway ----
resource "aws_bedrockagentcore_gateway" "g" {
  name            = "th-gateway"
  description     = "TrustedHand bank tools behind a request interceptor, Cedar policy and a response interceptor"
  role_arn        = aws_iam_role.gateway.arn
  protocol_type   = "MCP"
  authorizer_type = "AWS_IAM"
  # exception_level is left unset on purpose: DEBUG would put details in errors.

  interceptor_configuration {
    interception_points = ["REQUEST", "RESPONSE"]

    input_configuration {
      pass_request_headers = true
    }

    interceptor {
      lambda {
        arn = aws_lambda_function.fn["interceptor"].arn
      }
    }
  }

  policy_engine_configuration {
    arn  = aws_bedrockagentcore_policy_engine.p.policy_engine_arn
    mode = "ENFORCE"
  }

  depends_on = [time_sleep.iam_settle, aws_lambda_permission.agentcore]
}

resource "aws_bedrockagentcore_gateway_target" "bank" {
  name               = "bank"
  gateway_identifier = aws_bedrockagentcore_gateway.g.gateway_id
  description        = "Bank tools (Lambda th-tools)"

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.fn["tools"].arn

        tool_schema {
          dynamic "inline_payload" {
            for_each = local.bank_tools
            content {
              name        = inline_payload.key
              description = inline_payload.value.description

              input_schema {
                type = "object"

                dynamic "property" {
                  for_each = inline_payload.value.properties
                  content {
                    name        = property.key
                    type        = property.value.type
                    description = property.value.description
                    required    = property.value.required
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

# ---- Cedar policies (loaded after the target so the validator sees the tools) ----
resource "aws_bedrockagentcore_policy" "p" {
  for_each = local.cedar_policies

  name             = each.key
  description      = each.value.desc
  policy_engine_id = aws_bedrockagentcore_policy_engine.p.policy_engine_id
  validation_mode  = each.value.mode

  definition {
    cedar {
      statement = templatefile("${path.module}/policies/${each.value.file}", {
        gateway_arn         = aws_bedrockagentcore_gateway.g.gateway_arn
        per_payment_max_inr = var.per_payment_max_inr
        new_payee_max_inr   = var.new_payee_max_inr
      })
    }
  }

  depends_on = [aws_bedrockagentcore_gateway_target.bank]
}

# ---- Harness execution role (harness itself: infra/harness.py) ----
resource "aws_iam_role" "harness" {
  name               = "th-harness-role"
  assume_role_policy = data.aws_iam_policy_document.agentcore_trust.json
}

locals {
  # Inference profiles route across US regions, so foundation-model ARNs use a
  # region wildcard. Llama 4 Maverick is only used by the stress test.
  model_families   = ["amazon.nova-2-lite-*", "amazon.nova-pro-*", "amazon.nova-micro-*", "meta.llama4-maverick-*"]
  profile_families = ["us.amazon.nova-2-lite-*", "us.amazon.nova-pro-*", "us.amazon.nova-micro-*", "us.meta.llama4-maverick-*"]
}

resource "aws_iam_role_policy" "harness" {
  name = "inline"
  role = aws_iam_role.harness.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ModelInvoke"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:Converse",
          "bedrock:ConverseStream",
        ]
        Resource = concat(
          [for m in local.model_families : "arn:aws:bedrock:us-*::foundation-model/${m}"],
          [for m in local.profile_families : "arn:aws:bedrock:us-*:${local.account}:inference-profile/${m}"],
        )
      },
      {
        Sid      = "Gateway"
        Effect   = "Allow"
        Action   = "bedrock-agentcore:InvokeGateway"
        Resource = aws_bedrockagentcore_gateway.g.gateway_arn
      },
      {
        Sid      = "Hooks"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = aws_lambda_function.fn["hook"].arn
      },
      {
        Sid    = "WorkloadIdentity"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:GetWorkloadAccessToken",
          "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
          "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
        ]
        Resource = "*"
      },
      {
        Sid    = "Logs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = [
          "arn:aws:logs:${local.region}:${local.account}:log-group:/aws/bedrock-agentcore/*",
          "arn:aws:logs:${local.region}:${local.account}:log-group:/aws/bedrock-agentcore/*:log-stream:*",
        ]
      },
      {
        Sid      = "LogGroups"
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      },
      {
        Sid      = "Xray"
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      },
      {
        Sid      = "Metrics"
        Effect   = "Allow"
        Action   = "cloudwatch:PutMetricData"
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "bedrock-agentcore" }
        }
      },
    ]
  })
}
