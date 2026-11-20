# HTTP API th-api. Routes per docs/DESIGN.md.

resource "aws_apigatewayv2_api" "api" {
  name          = "th-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = [local.web_origin, var.local_dev_origin]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["content-type", "x-approval-token", "x-chat-token"]
    max_age       = 3600
  }
}

locals {
  routes = {
    "POST /demo/start"            = "chat"
    "POST /chat"                  = "chat"
    "GET /demo/state"             = "chat"
    "GET /approval/{request_id}"  = "approval"
    "POST /approval/{request_id}" = "approval"
  }
}

resource "aws_apigatewayv2_integration" "fn" {
  for_each = toset(["chat", "approval"])

  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.fn[each.key].invoke_arn
  payload_format_version = "2.0"
  # HTTP APIs cut off at 30 seconds, whatever the Lambda timeout is.
  timeout_milliseconds = 30000
}

resource "aws_apigatewayv2_route" "r" {
  for_each = local.routes

  api_id    = aws_apigatewayv2_api.api.id
  route_key = each.key
  target    = "integrations/${aws_apigatewayv2_integration.fn[each.value].id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = 5
    throttling_burst_limit = 10
  }

  route_settings {
    route_key              = "POST /chat"
    throttling_rate_limit  = 2
    throttling_burst_limit = 5
  }

  route_settings {
    route_key              = "POST /demo/start"
    throttling_rate_limit  = 1
    throttling_burst_limit = 2
  }

  depends_on = [aws_apigatewayv2_route.r]
}

resource "aws_lambda_permission" "apigw" {
  for_each = toset(["chat", "approval"])

  statement_id  = "apigw"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn[each.key].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}
