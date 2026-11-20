"""Approval channel tests (moto)."""
import importlib.util
import json
from pathlib import Path

import pytest

from trustedhand import config, db, hashing, ratelimit

_spec = importlib.util.spec_from_file_location(
    "th_approval_handler", Path(__file__).resolve().parents[1] / "lambdas" / "approval" / "handler.py")
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)

HID = "hh-test00000001"
RID = "rq-abc12345def"
TOKEN = "approve-token-" + "z" * 30
IP = "7.7.7.7"


@pytest.fixture
def setup(aws):
    now = db.now()
    db.tbl("households").put_item(Item={
        "household_id": HID, "elder_name": "Amma", "contact_name": "Ravi", "demo": True,
        "limits": config.DEMO_LIMITS, "ttl": now + 5000})
    rh = hashing.request_hash(HID, RID, "Suresh Traders", "1234567890", 4500)
    db.tbl("requests").put_item(Item={
        "household_id": HID, "request_id": RID, "payee_name": "Suresh Traders", "account": "1234567890",
        "amount_inr": 4500, "reason": "Pay for the new fan", "status": "pending", "request_hash": rh,
        "created_at": now, "expires_at": now + 3600, "ttl": now + 5000})
    db.tbl("approvals").put_item(Item={
        "request_id": RID, "household_id": HID, "token_hash": hashing.sha256(TOKEN), "request_hash": rh,
        "expires_at": now + 3600, "used": False, "attempts": 0})
    return now


def ev(method, token=TOKEN, body=None, rid=RID, ip=IP, header=True):
    e = {"routeKey": f"{method} /approval/{{request_id}}", "pathParameters": {"request_id": rid},
         "requestContext": {"http": {"sourceIp": ip}}, "headers": {}}
    if method == "GET" and header:
        e["headers"]["X-Approval-Token"] = token
    if body is not None:
        e["body"] = json.dumps(body)
    return e


def call(e):
    r = a.handler(e)
    return r["statusCode"], json.loads(r["body"]), r["body"]


def post(decision="approve", token=TOKEN, **kw):
    return call(ev("POST", body={"token": token, "decision": decision}, **kw))


def row(table, **key):
    return db.tbl(table).get_item(Key=key).get("Item")


def receipts_for():
    from trustedhand import receipts
    return receipts.recent(HID)


def test_get_details(setup):
    code, out, raw = call(ev("GET"))
    assert code == 200
    assert out["payee_name"] == "Suresh Traders" and out["account_masked"] == "XXXX7890"
    assert out["amount_inr"] == 4500 and out["status"] == "pending"
    assert out["contact_name"] == "Ravi" and out["elder_name"] == "Amma"
    assert "1234567890" not in raw and TOKEN not in raw
    assert out["created_at"].endswith("+00:00") and out["expires_at"].endswith("+00:00")


def test_approve_happy_path(setup):
    code, out, raw = post("approve")
    assert code == 200 and out["status"] == "approved" and TOKEN not in raw
    ap = row("approvals", request_id=RID)
    assert ap["used"] is True and ap["decision"] == "approve" and "decided_at" in ap
    assert row("requests", household_id=HID, request_id=RID)["status"] == "approved"
    p = row("payees", household_id=HID, payee_id="np-" + RID[3:11])
    assert p["name"] == "Suresh Traders" and p["account"] == "1234567890" and p["account_masked"] == "XXXX7890"
    assert p["source"] == "approval" and p["request_id"] == RID
    assert setup + 110 <= int(p["usable_from"]) <= db.now() + 125  # demo cool-off 120 s
    b = row("bills", household_id=HID, bill_id="tr-" + RID[3:11])
    assert b["kind"] == "transfer" and b["biller"] == "Suresh Traders" and int(b["amount_due_inr"]) == 4500
    assert b["status"] == "unpaid" and b["payee_id"] == p["payee_id"] and "Ravi" in b["memo"] and "ttl" in b
    rc = [r for r in receipts_for() if r["layer"] == "approval"]
    assert rc and rc[-1]["rule"] == "R6" and rc[-1]["decision"] == "allow"
    assert "1234567890" not in json.dumps(rc, default=str)
    notes = row("households", household_id=HID)["notices"]
    assert len(notes) == 1 and "Suresh Traders" in notes[0] and "XXXX7890" in notes[0] and "1234567890" not in notes[0]


def test_double_use_409(setup):
    assert post("approve")[0] == 200
    code, out, _ = post("approve")
    assert code == 409
    assert post("deny")[0] == 409
    assert row("requests", household_id=HID, request_id=RID)["status"] == "approved"


def test_deny_path(setup):
    code, out, _ = post("deny")
    assert code == 200 and out["status"] == "denied"
    assert row("requests", household_id=HID, request_id=RID)["status"] == "denied"
    ap = row("approvals", request_id=RID)
    assert ap["used"] is True and ap["decision"] == "deny"
    assert row("payees", household_id=HID, payee_id="np-" + RID[3:11]) is None
    assert row("bills", household_id=HID, bill_id="tr-" + RID[3:11]) is None
    assert post("approve")[0] == 409


def test_wrong_token_locks_after_five(setup):
    for i in range(4):
        assert post("approve", token="wrong-" + "q" * 20)[0] == 401
    assert row("approvals", request_id=RID)["attempts"] == 4
    assert post("approve", token="wrong-" + "q" * 20)[0] == 403  # 5th wrong: locked
    # even the right token is refused now
    assert post("approve")[0] == 403
    assert call(ev("GET"))[0] == 403
    assert row("payees", household_id=HID, payee_id="np-" + RID[3:11]) is None
    assert row("requests", household_id=HID, request_id=RID)["status"] == "pending"


def test_expired_410_and_marked(setup):
    db.tbl("approvals").update_item(Key={"request_id": RID}, UpdateExpression="SET expires_at = :e",
                                    ExpressionAttributeValues={":e": db.now() - 5})
    assert post("approve")[0] == 410
    assert row("requests", household_id=HID, request_id=RID)["status"] == "expired"
    assert call(ev("GET"))[0] == 410
    assert row("payees", household_id=HID, payee_id="np-" + RID[3:11]) is None


def test_bait_and_switch_409(setup):
    # amount changed in the table after the notifier hashed the request
    db.tbl("requests").update_item(Key={"household_id": HID, "request_id": RID},
                                   UpdateExpression="SET amount_inr = :a", ExpressionAttributeValues={":a": 90000})
    code, out, _ = post("approve")
    assert code == 409
    assert row("approvals", request_id=RID)["used"] is False
    assert row("requests", household_id=HID, request_id=RID)["status"] == "pending"
    assert row("payees", household_id=HID, payee_id="np-" + RID[3:11]) is None
    assert any(r["layer"] == "approval" and r["decision"] == "deny" for r in receipts_for())


def test_switched_account_409(setup):
    db.tbl("requests").update_item(Key={"household_id": HID, "request_id": RID},
                                   UpdateExpression="SET account = :a", ExpressionAttributeValues={":a": "9999999999"})
    assert post("approve")[0] == 409


def test_unknown_request_404_and_missing_token_401(setup):
    assert call(ev("GET", rid="rq-nothere000"))[0] == 404
    assert call(ev("GET", token=""))[0] == 401
    assert call(ev("GET", header=False))[0] == 401
    assert post("maybe")[0] == 400


def test_rate_limit_per_ip(setup):
    for _ in range(30):
        assert ratelimit.hit(f"approval-ip#{IP}", 30, 600)
    assert call(ev("GET"))[0] == 429
    assert call(ev("GET", ip="6.6.6.6"))[0] == 200


def test_token_in_header_for_post_fallback(setup):
    e = ev("POST", body={"decision": "deny"})
    e["headers"]["x-approval-token"] = TOKEN
    assert call(e)[0] == 200


def test_unhandled_error_generic(setup, monkeypatch):
    monkeypatch.setattr(a, "_decide", lambda *x, **k: (_ for _ in ()).throw(RuntimeError("secret")))
    code, out, raw = post("approve")
    assert code == 500 and "secret" not in raw


def test_transaction_blocks_race_with_stale_rows(setup):
    """Two clicks at once: both read 'unused', the transaction lets only one win."""
    appr = row("approvals", request_id=RID)
    req = row("requests", household_id=HID, request_id=RID)
    hh = row("households", household_id=HID)
    r1 = a._decide(HID, RID, appr, req, hh, "approve", db.now())
    r2 = a._decide(HID, RID, appr, req, hh, "deny", db.now())  # stale view: still looks unused
    assert r1["statusCode"] == 200 and r2["statusCode"] == 409
    assert row("requests", household_id=HID, request_id=RID)["status"] == "approved"
