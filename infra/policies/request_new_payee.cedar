// A3: a request for a new payee is allowed for 1 to 50,000 rupees.
// Nothing moves until the trusted contact approves (R6).
permit (
  principal,
  action == AgentCore::Action::"bank___request_new_payee",
  resource == AgentCore::Gateway::"${gateway_arn}"
)
when {
  context.input.amount_inr >= 1 &&
  context.input.amount_inr <= ${new_payee_max_inr}
};
