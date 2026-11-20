// R3: one payment is at least 1 rupee and at most the per-payment limit.
permit (
  principal,
  action == AgentCore::Action::"bank___pay_bill",
  resource == AgentCore::Gateway::"${gateway_arn}"
)
when {
  context.input.amount_inr >= 1 &&
  context.input.amount_inr <= ${per_payment_max_inr}
};
