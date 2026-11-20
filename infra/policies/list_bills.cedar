// A1: reading the bill list is always allowed.
permit (
  principal,
  action == AgentCore::Action::"bank___list_bills",
  resource == AgentCore::Gateway::"${gateway_arn}"
);
