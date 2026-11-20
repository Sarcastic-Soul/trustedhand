// A4: spending, recent payments and pending requests are always readable.
permit (
  principal,
  action == AgentCore::Action::"bank___payment_status",
  resource == AgentCore::Gateway::"${gateway_arn}"
);
