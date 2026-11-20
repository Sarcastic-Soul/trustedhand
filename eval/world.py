"""Fresh demo households written straight into DynamoDB (the eval runner is trusted), and state snapshots."""
import secrets
import threading

from boto3.dynamodb.conditions import Key

from . import common

_seed_lock = threading.Lock()


def new_ids():
    hh = "hh-" + secrets.token_hex(6)
    return {"household_id": hh, "session_id": hh + "-" + secrets.token_hex(16), "chat_token": secrets.token_urlsafe(32)}


def create_world(setup=None, now=None, ids=None):
    """Seed a demo household and write the S# and T# session items (DESIGN: Session identity)."""
    from trustedhand import config, db, hashing, seeds
    now = int(now if now is not None else db.now())
    ids = ids or new_ids()
    with _seed_lock:  # seeds use the shared boto3 resource
        seeds.create_demo_household(ids["household_id"], now)
    ttl = now + config.DEMO_TTL_S
    db.tbl("sessions").put_item(Item={"pk": "S#" + ids["session_id"], "household_id": ids["household_id"],
                                      "created_at": now, "ttl": ttl})
    db.tbl("sessions").put_item(Item={"pk": "T#" + hashing.sha256(ids["chat_token"]), "household_id": ids["household_id"],
                                      "runtime_session_id": ids["session_id"], "ttl": ttl})
    if (setup or {}).get("frozen"):
        db.tbl("households").update_item(
            Key={"household_id": ids["household_id"]},
            UpdateExpression="SET frozen_until = :f, freeze_reason = :r",
            ExpressionAttributeValues={":f": now + 3600, ":r": "eval setup: household starts frozen"})
    return ids


def _query_all(table, key_cond):
    from trustedhand import db
    items, kw = [], {"KeyConditionExpression": key_cond, "ConsistentRead": True}
    while True:
        r = db.tbl(table).query(**kw)
        items += r.get("Items", [])
        if "LastEvaluatedKey" not in r:
            return common.plain(items)
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def snapshot(household_id):
    """Everything the checker and the report need, as plain JSON."""
    from trustedhand import db
    hh = db.tbl("households").get_item(Key={"household_id": household_id}, ConsistentRead=True).get("Item") or {}
    ledger = _query_all("ledger", Key("household_id").eq(household_id))
    return {
        "household": common.plain(hh),
        "bills": _query_all("bills", Key("household_id").eq(household_id)),
        "payees": _query_all("payees", Key("household_id").eq(household_id)),
        "requests": _query_all("requests", Key("household_id").eq(household_id)),
        "payments": [r for r in ledger if str(r.get("sk", "")).startswith("PAY#")],
        "days": [r for r in ledger if str(r.get("sk", "")).startswith("DAY#")],
    }


def receipts(household_id):
    return _query_all("receipts", Key("household_id").eq(household_id))
