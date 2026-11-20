import importlib.util
import pathlib
from types import SimpleNamespace

import pytest

from trustedhand import config, db, seeds

_spec = importlib.util.spec_from_file_location(
    "tools_handler", pathlib.Path(__file__).resolve().parents[1] / "lambdas" / "tools" / "handler.py")
tools_handler = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tools_handler)

HH = "hh-abc123def456"
SESS = HH + "-" + "b" * 32
OTHER = "hh-other0000000"
OTHER_SESS = OTHER + "-" + "c" * 32


def ctx(tool):
    return SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": f"bank___{tool}"}))


def call(tool, **args):
    return tools_handler.handler(args, ctx(tool))


@pytest.fixture
def hh(aws):
    now = db.now()
    seeds.create_demo_household(HH, now)
    seeds.create_demo_household(OTHER, now)
    for h, s in ((HH, SESS), (OTHER, OTHER_SESS)):
        db.tbl("sessions").put_item(Item={"pk": "S#" + s, "household_id": h, "created_at": now, "ttl": now + 3600})
    return HH


def test_list_bills_and_payees(hh):
    bills = call("list_bills", _session_id=SESS)["bills"]
    assert len(bills) == 5 and all(b["bill_id"].startswith("bill-") for b in bills)
    payees = call("list_payees", _session_id=SESS)["payees"]
    assert len(payees) == 5
    assert "301245678901" not in repr(payees)


def test_pay_bill_and_status(hh):
    r = call("pay_bill", _session_id=SESS, bill_id="bill-jio", amount_inr=719)
    assert r["status"] == "paid" and r["spent_today_inr"] == 719
    s = call("payment_status", _session_id=SESS)
    assert s["today"]["spent_inr"] == 719 and s["today"]["count"] == 1
    assert call("pay_bill", _session_id=SESS, bill_id="bill-jio", amount_inr=719)["rule"] == "R5"


def test_refusal_is_a_normal_return(hh):
    r = call("pay_bill", _session_id=SESS, bill_id="bill-bescom", amount_inr=99999)
    assert r["status"] == "refused" and r["rule"] in ("R2", "R3")


def test_missing_args_refused_not_crash(hh):
    assert call("pay_bill", _session_id=SESS)["status"] == "refused"
    assert call("request_new_payee", _session_id=SESS)["status"] == "refused"


def test_request_new_payee(hh):
    r = call("request_new_payee", _session_id=SESS, payee_name="Shop", account="shop@ybl",
             amount_inr=1000, reason="gift")
    assert r["status"] == "sent_to_trusted_contact"
    assert "shop@ybl" not in repr(r)


@pytest.mark.parametrize("sess", [None, "", "nope", "hh-" + "z" * 300, 12345, "S#" + SESS])
def test_unknown_session(hh, sess):
    args = {} if sess is None else {"_session_id": sess}
    r = tools_handler.handler(args, ctx("list_bills"))
    assert r == {"status": "error", "message": "Session not recognised."}


def test_expired_session(hh):
    db.tbl("sessions").put_item(Item={"pk": "S#old", "household_id": HH, "ttl": db.now() - 5})
    assert call("list_bills", _session_id="old")["status"] == "error"


def test_model_supplied_household_id_ignored(hh):
    # Model tries to act on another household: only the session decides.
    r = call("pay_bill", _session_id=SESS, bill_id="bill-jio", amount_inr=719,
             household_id=OTHER, HOUSEHOLD_ID=OTHER)
    assert r["status"] == "paid"
    other_bill = db.tbl("bills").get_item(Key={"household_id": OTHER, "bill_id": "bill-jio"})["Item"]
    assert other_bill["status"] == "unpaid"
    mine = db.tbl("bills").get_item(Key={"household_id": HH, "bill_id": "bill-jio"})["Item"]
    assert mine["status"] == "paid"
    bills = call("list_bills", _session_id=OTHER_SESS, household_id=HH)["bills"]
    assert [b for b in bills if b["bill_id"] == "bill-jio"][0]["status"] == "unpaid"


def test_injected_memo_returned_as_is(hh):
    bills = {b["bill_id"]: b for b in call("list_bills", _session_id=SESS)["bills"]}
    assert bills["bill-bwssb"]["memo"] == seeds.INJECTED_MEMO


def test_no_cross_household_payment_by_bill_id(hh):
    db.tbl("bills").put_item(Item={"household_id": OTHER, "bill_id": "only-other", "payee_id": "bescom",
                                   "amount_due_inr": 10, "status": "unpaid", "kind": "bill"})
    assert call("pay_bill", _session_id=SESS, bill_id="only-other", amount_inr=10)["rule"] == "R1"


def test_unknown_tool_and_missing_context(hh):
    assert call("delete_everything", _session_id=SESS)["status"] == "error"
    r = tools_handler.handler({"_session_id": SESS}, SimpleNamespace(client_context=None))
    assert r["status"] == "error"


def test_tool_name_without_prefix(hh):
    c = SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": "list_bills"}))
    assert "bills" in tools_handler.handler({"_session_id": SESS}, c)


def test_exception_returns_generic_error(hh, monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("arn:aws:dynamodb:us-east-1:123456789012:table/secret Traceback")
    monkeypatch.setattr(tools_handler.payments, "list_bills", boom)
    r = call("list_bills", _session_id=SESS)
    assert r == {"status": "error", "message": "Something went wrong. Nothing was paid."}
    out = capsys.readouterr().out
    assert "RuntimeError" in out and "arn:aws" not in out and "secret" not in out


def test_non_dict_event(hh):
    assert tools_handler.handler(None, ctx("list_bills"))["status"] == "error"


def test_seed_shape(aws):
    out = seeds.create_demo_household("hh-seed", 1_800_000_000)
    assert out == {"household_id": "hh-seed", "elder_name": "Amma", "contact_name": "Ravi"}
    h = db.tbl("households").get_item(Key={"household_id": "hh-seed"})["Item"]
    assert h["demo"] is True and int(h["ttl"]) == 1_800_000_000 + config.DEMO_TTL_S
    assert {k: int(v) for k, v in h["limits"].items()} == config.DEMO_LIMITS
    bills = {b["bill_id"]: b for b in
             db.tbl("bills").query(KeyConditionExpression=boto3_key("hh-seed"))["Items"]}
    amounts = sorted(int(b["amount_due_inr"]) for b in bills.values())
    assert amounts[0] >= 300 and amounts[-1] == 6500
    assert all(b["status"] == "unpaid" for b in bills.values())
    plain = [b["memo"] for k, b in bills.items() if k != "bill-bwssb"]
    assert all("SYSTEM" not in m for m in plain)


def test_create_household_non_demo(aws):
    seeds.create_household("hh-real", 1_800_000_000, demo=False, limits=config.DEFAULT_LIMITS,
                           contact_email="ravi@example.com")
    h = db.tbl("households").get_item(Key={"household_id": "hh-real"})["Item"]
    assert h["demo"] is False and "ttl" not in h and h["contact_email"] == "ravi@example.com"


def boto3_key(hh):
    from boto3.dynamodb.conditions import Key
    return Key("household_id").eq(hh)
