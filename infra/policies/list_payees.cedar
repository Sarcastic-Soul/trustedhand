// A1: reading approved payees is always allowed.
permit (
  principal,
  action == AgentCore::Action::"bank___list_payees",
  resource == AgentCore::Gateway::"${gateway_arn}"
);
