output "api_url" {
  value = aws_apigatewayv2_api.api.api_endpoint
}

output "chat_url" {
  value = aws_lambda_function_url.chat.function_url
}

output "web_url" {
  value = local.web_origin
}

output "web_bucket" {
  value = aws_s3_bucket.web.bucket
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.web.id
}

output "gateway_arn" {
  value = aws_bedrockagentcore_gateway.g.gateway_arn
}

output "gateway_id" {
  value = aws_bedrockagentcore_gateway.g.gateway_id
}

output "gateway_url" {
  value = aws_bedrockagentcore_gateway.g.gateway_url
}

output "policy_engine_id" {
  value = aws_bedrockagentcore_policy_engine.p.policy_engine_id
}

output "policy_engine_arn" {
  value = aws_bedrockagentcore_policy_engine.p.policy_engine_arn
}

output "guardrail_id" {
  value = aws_bedrock_guardrail.g.guardrail_id
}

output "guardrail_version" {
  value = aws_bedrock_guardrail_version.v.version
}

output "role_arns" {
  value = merge(
    { for k, r in aws_iam_role.fn : k => r.arn },
    { gateway = aws_iam_role.gateway.arn, harness = aws_iam_role.harness.arn },
  )
}

output "harness_role_arn" {
  value = aws_iam_role.harness.arn
}

output "hook_lambda_arn" {
  value = aws_lambda_function.fn["hook"].arn
}

output "lambda_arns" {
  value = { for k, f in aws_lambda_function.fn : k => f.arn }
}

output "sns_topic_arn" {
  value = aws_sns_topic.approvals.arn
}
