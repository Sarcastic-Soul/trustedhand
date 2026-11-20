import importlib.util
import json
import pathlib

import pytest

from trustedhand import config, db, receipts

HANDLER = pathlib.Path(__file__).resolve().parents[1] / "lambdas" / "hook" / "handler.py"
SESSION = "hh-abc123def456-" + "b" * 32
HH = "hh-abc123def456"


@pytest.fixture
def hook(aws):
    spec = importlib.util.spec_from_file_location("th_hook", HANDLER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    db.tbl("sessions").put_item(Item={"pk": "S#" + SESSION, "household_id": HH, "ttl": db.now() + 1000})
    db.tbl("households").put_item(Item={"household_id": HH, "elder_name": "Amma", "demo": True})
    return mod


def before(tool, tool_input=None, session=SESSION):
    return {"hookEventId": "e1", "name": "h", "event": "before_tool_call", "harnessArn": "arn", "sessionId": session,
            "context": {"toolName": tool, "toolType": "agentcore_gateway", "toolInput": tool_input or {}, "toolUseId": "t1"}}


def after(tool, text, is_error=False):
    return {"hookEventId": "e2", "name": "h", "event": "after_tool_call", "harnessArn": "arn", "sessionId": SESSION,
            "context": {"toolName": tool, "toolType": "agentcore_gateway", "toolUseId": "t1",
                        "toolResult": {"status": "error" if is_error else "success", "toolUseId": "t1",
                                       "content": [{"text": text}], "isError": is_error}}}


REFUSED = json.dumps({"status": "refused", "rule": "R2", "message": "too much"})


def test_allow_writes_intent_receipt(hook):
    out = hook.handler(before("bank___pay_bill", {"bill_id": "b1", "amount_inr": 100}), None)
    assert out["decision"] == "allow"
    r = receipts.recent(HH)
    assert len(r) == 1 and r[0]["layer"] == "hook" and r[0]["decision"] == "allow" and r[0]["tool"] == "pay_bill"


def test_intent_receipt_masks_account(hook):
    hook.handler(before("bank___request_new_payee", {"payee_name": "Ravi", "account": "123456789012", "amount_inr": 5, "reason": "x"}), None)
    s = receipts.recent(HH)[0]["summary"]
    assert "123456789012" not in s and "XXXX9012" in s


def test_unknown_tool_denied(hook):
    for name in ("bank___add_payee", "shell", "pay_bill"):
        out = hook.handler(before(name), None)
        assert out["decision"] == "deny" and len(out["reason"]) <= 1024
    assert all(r["decision"] == "deny" for r in receipts.recent(HH))


def test_unknown_session_denied(hook):
    assert hook.handler(before("bank___list_bills", session="nope"), None)["decision"] == "deny"


def test_freeze_denies_new_payee_but_not_bills(hook):
    db.tbl("households").update_item(Key={"household_id": HH}, UpdateExpression="SET frozen_until = :f",
                                     ExpressionAttributeValues={":f": db.now() + 500})
    out = hook.handler(before("bank___request_new_payee", {"payee_name": "x", "account": "1", "amount_inr": 1, "reason": "r"}), None)
    assert out["decision"] == "deny" and "scam" in out["reason"]
    assert any(r.get("rule") == "R9" for r in receipts.recent(HH))
    assert hook.handler(before("bank___pay_bill", {"bill_id": "b", "amount_inr": 1}), None)["decision"] == "allow"
    assert hook.handler(before("bank___list_bills"), None)["decision"] == "allow"


def test_expired_freeze_allows(hook):
    db.tbl("households").update_item(Key={"household_id": HH}, UpdateExpression="SET frozen_until = :f",
                                     ExpressionAttributeValues={":f": db.now() - 5})
    assert hook.handler(before("bank___request_new_payee"), None)["decision"] == "allow"


def test_three_refusals_lock_session_and_alert(hook):
    for i in range(config.STRIKE_LIMIT):
        assert hook.handler(after("bank___pay_bill", REFUSED), None)["decision"] == "allow"
    row = db.tbl("strikes").get_item(Key={"session_id": SESSION})["Item"]
    assert int(row["count"]) == 3 and int(row["locked_until"]) > db.now()
    alerts = db.tbl("inbox").query(KeyConditionExpression="household_id = :h", ExpressionAttributeValues={":h": HH})["Items"]
    assert len(alerts) == 1 and alerts[0]["kind"] == "alert"
    assert any(r.get("rule") == "R12" for r in receipts.recent(HH))
    for tool in ("bank___pay_bill", "bank___request_new_payee"):
        out = hook.handler(before(tool), None)
        assert out["decision"] == "deny" and "paused" in out["reason"]
    assert hook.handler(before("bank___list_bills"), None)["decision"] == "allow"
    # a fourth refusal does not raise a second alert
    hook.handler(after("bank___pay_bill", REFUSED), None)
    alerts = db.tbl("inbox").query(KeyConditionExpression="household_id = :h", ExpressionAttributeValues={":h": HH})["Items"]
    assert len(alerts) == 1


def test_two_refusals_do_not_lock(hook):
    for _ in range(2):
        hook.handler(after("bank___pay_bill", REFUSED), None)
    assert hook.handler(before("bank___pay_bill"), None)["decision"] == "allow"


def test_success_and_other_tools_do_not_count(hook):
    hook.handler(after("bank___pay_bill", json.dumps({"status": "paid"})), None)
    hook.handler(after("bank___list_bills", REFUSED), None)
    assert db.tbl("strikes").get_item(Key={"session_id": SESSION}).get("Item") is None


def test_policy_denied_and_error_count_as_strikes(hook):
    hook.handler(after("bank___request_new_payee", "Tool Execution Denied: Tool call not allowed due to policy enforcement [x]", True), None)
    hook.handler(after("bank___pay_bill", "boom", True), None)
    assert int(db.tbl("strikes").get_item(Key={"session_id": SESSION})["Item"]["count"]) == 2


def test_after_never_denies_on_internal_error(hook, monkeypatch):
    monkeypatch.setattr(hook, "_after", lambda e: 1 / 0)
    assert hook.handler(after("bank___pay_bill", REFUSED), None)["decision"] == "allow"


def test_before_fails_closed(hook, monkeypatch):
    monkeypatch.setattr(hook.sessions, "household_for_session", lambda s: 1 / 0)
    out = hook.handler(before("bank___list_bills"), None)
    assert out["decision"] == "deny" and "Nothing was paid" in out["reason"]
