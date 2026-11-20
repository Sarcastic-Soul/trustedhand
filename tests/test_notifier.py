import importlib.util
import json
import pathlib

import pytest
from boto3.dynamodb.types import TypeSerializer

from trustedhand import db, hashing, receipts

HANDLER = pathlib.Path(__file__).resolve().parents[1] / "lambdas" / "notifier" / "handler.py"
HH = "hh-abc123def456"
_ser = TypeSerializer()


@pytest.fixture
def nt(aws, monkeypatch):
    spec = importlib.util.spec_from_file_location("th_notifier", HANDLER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setenv("WEB_ORIGIN", "https://web.example")
    monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)
    db.tbl("households").put_item(Item={"household_id": HH, "elder_name": "Amma", "demo": True})
    return mod


def request(rid="req1", status="pending"):
    return {"household_id": HH, "request_id": rid, "payee_name": "Sharma Traders", "account": "123456789012",
            "amount_inr": 4000, "reason": "advance for repairs", "status": status,
            "request_hash": hashing.request_hash(HH, rid, "Sharma Traders", "123456789012", 4000),
            "session_id": "s1", "created_at": 1, "expires_at": db.now() + 1000}


def stream(req, name="INSERT"):
    return {"Records": [{"eventName": name, "dynamodb": {"NewImage": {k: _ser.serialize(v) for k, v in req.items()}}}]}


def inbox():
    return db.tbl("inbox").query(KeyConditionExpression="household_id = :h", ExpressionAttributeValues={":h": HH})["Items"]


def test_creates_approval_and_inbox(nt):
    r = request()
    nt.handler(stream(r), None)
    appr = db.tbl("approvals").get_item(Key={"request_id": "req1"})["Item"]
    assert appr["used"] is False and int(appr["attempts"]) == 0
    assert appr["request_hash"] == r["request_hash"] and appr["household_id"] == HH
    items = inbox()
    assert len(items) == 1 and items[0]["kind"] == "approval_request"
    assert items[0]["title"] == "Amma asked to pay a new person"
    assert "XXXX9012" in items[0]["body"] and "123456789012" not in items[0]["body"]
    assert "Sharma Traders" in items[0]["body"] and "4000" in items[0]["body"]
    link = items[0]["link"]
    assert link.startswith("https://web.example/approve.html#r=req1&t=")
    assert any(x["layer"] == "notifier" for x in receipts.recent(HH))


def test_token_only_stored_as_hash(nt):
    nt.handler(stream(request()), None)
    token = json.loads(json.dumps(inbox()[0]["link"])).split("&t=")[1]
    appr = db.tbl("approvals").get_item(Key={"request_id": "req1"})["Item"]
    assert appr["token_hash"] == hashing.sha256(token)
    assert token not in json.dumps(appr, default=str)
    for rec in receipts.recent(HH):
        assert token not in json.dumps(rec, default=str)


def test_idempotent_on_retry(nt):
    ev = stream(request())
    nt.handler(ev, None)
    first = db.tbl("approvals").get_item(Key={"request_id": "req1"})["Item"]["token_hash"]
    nt.handler(ev, None)
    assert db.tbl("approvals").get_item(Key={"request_id": "req1"})["Item"]["token_hash"] == first
    assert len(inbox()) == 1


def test_ignores_non_insert_and_non_pending(nt):
    nt.handler(stream(request("r2"), name="MODIFY"), None)
    nt.handler(stream(request("r3", status="approved")), None)
    assert inbox() == []
    assert db.tbl("approvals").scan()["Items"] == []


class FakeSNS:
    def __init__(self):
        self.sent = []

    def publish(self, **kw):
        self.sent.append(kw)


def test_sns_only_for_real_households(nt, monkeypatch):
    fake = FakeSNS()
    monkeypatch.setattr(nt, "_sns", lambda: fake)
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:1:t")
    nt.handler(stream(request("r1")), None)  # demo household: no email
    assert fake.sent == []
    db.tbl("households").put_item(Item={"household_id": HH, "elder_name": "Amma", "demo": False, "contact_email": "r@example.com"})
    nt.handler(stream(request("r2")), None)
    assert len(fake.sent) == 1 and "approve.html#r=r2&t=" in fake.sent[0]["Message"]
    db.tbl("households").put_item(Item={"household_id": HH, "demo": True, "contact_email": "r@example.com"})
    nt.handler(stream(request("r3")), None)
    assert len(fake.sent) == 1


def test_sns_failure_does_not_fail_or_duplicate(nt, monkeypatch):
    class Boom:
        def publish(self, **kw):
            raise RuntimeError("x")
    monkeypatch.setattr(nt, "_sns", lambda: Boom())
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn")
    db.tbl("households").put_item(Item={"household_id": HH, "demo": False, "contact_email": "r@example.com"})
    nt.handler(stream(request()), None)
    assert len(inbox()) == 1
