# Six Lambdas (python3.13, arm64, 256 MB). Zips are built by the Makefile into
# build/<name>.zip (src/trustedhand + lambdas/<name>/handler.py).

locals {
  fn_names = toset(["tools", "interceptor", "hook", "chat", "approval", "notifier"])

  fn_timeout = {
    tools       = 15
    interceptor = 15
    hook        = 10
    chat        = 120
    approval    = 15
    notifier    = 30
  }

  fn_env = {
    tools = {}
    interceptor = {
      GUARDRAIL_ID      = aws_bedrock_guardrail.g.guardrail_id
      GUARDRAIL_VERSION = aws_bedrock_guardrail_version.v.version
    }
    hook = {}
    chat = {
      GUARDRAIL_ID          = aws_bedrock_guardrail.g.guardrail_id
      GUARDRAIL_VERSION     = aws_bedrock_guardrail_version.v.version
      OUT_GUARDRAIL_ID      = aws_bedrock_guardrail.out.guardrail_id
      OUT_GUARDRAIL_VERSION = aws_bedrock_guardrail_version.out.version
      HARNESS_ARN           = local.harness_arn
      WEB_ORIGIN            = local.web_origin
      GLOBAL_DAILY_RUNS     = tostring(var.global_daily_runs)
    }
    approval = {
      WEB_ORIGIN = local.web_origin
    }
    notifier = {
      WEB_ORIGIN    = local.web_origin
      SNS_TOPIC_ARN = aws_sns_topic.approvals.arn
    }
  }
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each          = local.fn_names
  name              = "/aws/lambda/th-${each.key}"
  retention_in_days = 14
}

# Latest boto3 (the runtime copy has no InvokeHarness). Built by `make build`.
data "archive_file" "layer" {
  type        = "zip"
  source_dir  = "${path.module}/../build/layer"
  output_path = "${path.module}/../build/layer.zip"
}

resource "aws_lambda_layer_version" "boto3" {
  layer_name               = "th-boto3-latest"
  filename                 = data.archive_file.layer.output_path
  source_code_hash         = data.archive_file.layer.output_base64sha256
  compatible_runtimes      = ["python3.13"]
  compatible_architectures = ["arm64"]
  description              = "Latest boto3 and botocore"
}

resource "aws_lambda_function" "fn" {
  for_each = local.fn_names

  function_name    = "th-${each.key}"
  role             = aws_iam_role.fn[each.key].arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  memory_size      = 256
  timeout          = local.fn_timeout[each.key]
  filename         = "${path.module}/../build/${each.key}.zip"
  source_code_hash = filebase64sha256("${path.module}/../build/${each.key}.zip")
  layers           = each.key == "chat" ? [aws_lambda_layer_version.boto3.arn] : []

  environment {
    variables = merge({ TABLE_PREFIX = var.table_prefix }, local.fn_env[each.key])
  }

  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy.fn]
}

# AgentCore calls these: the gateway (tools, interceptor) and the harness (hook).
resource "aws_lambda_permission" "agentcore" {
  for_each = toset(["tools", "interceptor", "hook"])

  statement_id   = "agentcore"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.fn[each.key].function_name
  principal      = "bedrock-agentcore.amazonaws.com"
  source_account = local.account
}

# Notifier reads the requests table stream.
resource "aws_lambda_event_source_mapping" "notifier" {
  event_source_arn                   = aws_dynamodb_table.t["requests"].stream_arn
  function_name                      = aws_lambda_function.fn["notifier"].arn
  starting_position                  = "LATEST"
  batch_size                         = 10
  maximum_retry_attempts             = 2
  maximum_record_age_in_seconds      = 3600
  maximum_batching_window_in_seconds = 0

  # New requests only. Status changes (approve, deny, expire) do not notify.
  filter_criteria {
    filter {
      pattern = jsonencode({ eventName = ["INSERT"] })
    }
  }
}

# Function URL for /chat: HTTP API integrations stop at 30 s, harness turns can
# take longer. Auth is NONE (the page is public); the chat Lambda does its own
# token and rate-limit checks. CORS is handled by the URL, so the handler must
# not add its own CORS headers.
resource "aws_lambda_function_url" "chat" {
  function_name      = aws_lambda_function.fn["chat"].function_name
  authorization_type = "NONE"
  invoke_mode        = "BUFFERED"

  cors {
    allow_origins = [local.web_origin, var.local_dev_origin]
    allow_methods = ["POST"]
    allow_headers = ["content-type"]
    max_age       = 3600
  }
}

# Public function URLs need both permissions since late 2025.
resource "aws_lambda_permission" "chat_url" {
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.fn["chat"].function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "chat_url_invoke" {
  statement_id             = "FunctionURLAllowInvoke"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.fn["chat"].function_name
  principal                = "*"
  invoked_via_function_url = true
}
