"""Gateway Lambda target for the `bank` tools.

Event = the tool arguments map. The tool name comes from the Gateway client
context. `_session_id` is set by the REQUEST interceptor; any household_id the
model sends is ignored (identity comes only from the session).

Read-only tools write an "info" receipt here, so every tool call leaves a record
even when the harness hooks are off (the hooks ablation showed reads otherwise
left no trace). Money tools write their own receipts in `payments`.
"""
from trustedhand import db, payments, receipts, sessions

_GENERIC_ERROR = {"status": "error", "message": "Something went wrong. Nothing was paid."}


def _tool_name(context):
    try:
        full = context.client_context.custom["bedrockAgentCoreToolName"]
        return str(full).split("___")[-1]
    except Exception:
        return ""


READS = {
    "list_bills": lambda hh, now: payments.list_bills(hh),
    "list_payees": payments.list_payees,
    "payment_status": payments.status,
}


def _read_summary(tool, out):
    if tool == "list_bills":
        return f"Read {len(out.get('bills') or [])} bills."
    if tool == "list_payees":
        return f"Read {len(out.get('payees') or [])} approved payees."
    return "Read today's spending, limits and pending requests."


def handler(event, context):
    try:
        args = dict(event) if isinstance(event, dict) else {}
        session_id = args.pop("_session_id", None)
        household_id = sessions.household_for_session(session_id)
        if not household_id:
            return {"status": "error", "message": "Session not recognised."}
        tool = _tool_name(context)
        now = db.now()
        if tool in READS:
            out = READS[tool](household_id, now)
            receipts.write(household_id, "tool", "info", _read_summary(tool, out), tool=tool, session_id=session_id)
            return out
        if tool == "pay_bill":
            return payments.pay(household_id, session_id, args.get("bill_id"), args.get("amount_inr"), now)
        if tool == "request_new_payee":
            return payments.request_payee(household_id, session_id, args.get("payee_name"), args.get("account"),
                                          args.get("amount_inr"), args.get("reason"), now)
        return {"status": "error", "message": "Unknown tool."}
    except Exception as e:  # never leak details to the model
        print(f"tool error: {type(e).__name__}")
        return dict(_GENERIC_ERROR)
