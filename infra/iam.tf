# One role per Lambda, least privilege. Tables are named in `local.tarn`.

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

locals {
  ddb_read = ["dynamodb:GetItem", "dynamodb:Query"]

  fn_statements = {
    # Tool Lambda. No access to approvals; no writes to payees or households.
    tools = [
      { actions = ["dynamodb:GetItem"], resources = [local.tarn.households, local.tarn.sessions] },
      { actions = local.ddb_read, resources = [local.tarn.payees] },
      { actions = concat(local.ddb_read, ["dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]), resources = [local.tarn.bills] },
      { actions = concat(local.ddb_read, ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]), resources = [local.tarn.ledger] },
      { actions = concat(local.ddb_read, ["dynamodb:PutItem", "dynamodb:ConditionCheckItem"]), resources = [local.tarn.requests] },
      { actions = ["dynamodb:PutItem"], resources = [local.tarn.receipts] },
    ]

    # Approval API. The only role (with notifier) that writes approvals and payees.
    approval = [
      { actions = ["dynamodb:GetItem", "dynamodb:UpdateItem"], resources = [local.tarn.approvals] },
      { actions = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:UpdateItem"], resources = [local.tarn.requests] },
      { actions = ["dynamodb:GetItem", "dynamodb:PutItem"], resources = [local.tarn.payees] },
      { actions = ["dynamodb:GetItem", "dynamodb:PutItem"], resources = [local.tarn.bills] },
      { actions = ["dynamodb:GetItem", "dynamodb:UpdateItem"], resources = [local.tarn.households] },
      { actions = ["dynamodb:PutItem"], resources = [local.tarn.receipts] },
      { actions = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], resources = [local.tarn.ratelimit] },
    ]

    notifier = [
      { actions = ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream", "dynamodb:ListStreams"], resources = [aws_dynamodb_table.t["requests"].stream_arn] },
      { actions = ["dynamodb:PutItem"], resources = [local.tarn.approvals, local.tarn.inbox, local.tarn.receipts] },
      { actions = ["dynamodb:GetItem"], resources = [local.tarn.households] },
      { actions = ["sns:Publish"], resources = [aws_sns_topic.approvals.arn] },
    ]

    # Chat proxy. Creates demo households and seeds, sets freezes, alerts the contact.
    chat = [
      { actions = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], resources = [local.tarn.households] },
      { actions = ["dynamodb:GetItem", "dynamodb:PutItem"], resources = [local.tarn.sessions] },
      { actions = concat(local.ddb_read, ["dynamodb:PutItem", "dynamodb:BatchWriteItem"]), resources = [local.tarn.payees, local.tarn.bills] },
      { actions = local.ddb_read, resources = [local.tarn.ledger, local.tarn.requests] },
      { actions = concat(local.ddb_read, ["dynamodb:PutItem"]), resources = [local.tarn.inbox, local.tarn.receipts] },
      { actions = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], resources = [local.tarn.ratelimit] },
      { actions = ["bedrock:ApplyGuardrail"], resources = [aws_bedrock_guardrail.g.guardrail_arn, aws_bedrock_guardrail.out.guardrail_arn] },
      { actions = ["bedrock-agentcore:InvokeHarness", "bedrock-agentcore:InvokeAgentRuntime"], resources = [local.harness_arn_pattern] },
    ]

    interceptor = [
      { actions = ["dynamodb:GetItem"], resources = [local.tarn.sessions] },
      { actions = ["dynamodb:PutItem"], resources = [local.tarn.receipts] },
      { actions = ["bedrock:ApplyGuardrail"], resources = [aws_bedrock_guardrail.g.guardrail_arn] },
    ]

    hook = [
      { actions = ["dynamodb:GetItem"], resources = [local.tarn.sessions, local.tarn.households] },
      { actions = ["dynamodb:GetItem", "dynamodb:UpdateItem"], resources = [local.tarn.strikes] },
      { actions = ["dynamodb:PutItem"], resources = [local.tarn.inbox, local.tarn.receipts] },
    ]
  }
}

resource "aws_iam_role" "fn" {
  for_each           = local.fn_names
  name               = "th-${each.key}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "fn" {
  for_each = local.fn_names
  name     = "inline"
  role     = aws_iam_role.fn[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.fn[each.key].arn}:*"
      }],
      [for s in local.fn_statements[each.key] : {
        Effect   = "Allow"
        Action   = s.actions
        Resource = s.resources
      }]
    )
  })
}
