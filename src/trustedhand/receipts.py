"""Decision receipts: one row per decision by any layer. Never raises."""
import datetime
import secrets

from . import config, db

LAYERS = {"proxy", "guardrail", "harness", "hook", "interceptor", "policy", "tool", "approval", "notifier"}
DECISIONS = {"allow", "deny", "flag", "info"}


def write(household_id, layer, decision, summary, *, rule=None, tool=None, session_id=None):
    item = {
        "household_id": household_id or "unknown",
        "sk": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds") + "#" + secrets.token_hex(3),
        "layer": layer,
        "decision": decision,
        "summary": (summary or "")[:300],
        "ttl": db.now() + config.DEMO_TTL_S,
    }
    if rule:
        item["rule"] = rule
    if tool:
        item["tool"] = tool
    if session_id:
        item["session_id"] = session_id
    try:
        db.tbl("receipts").put_item(Item=item)
    except Exception as e:  # receipts must never break the main path
        print(f"receipt write failed: {type(e).__name__}")
    return item


def recent(household_id, limit=50, since_sk=None):
    from boto3.dynamodb.conditions import Key
    cond = Key("household_id").eq(household_id)
    if since_sk:
        cond = cond & Key("sk").gt(since_sk)
    r = db.tbl("receipts").query(KeyConditionExpression=cond, ScanIndexForward=False, Limit=limit)
    return list(reversed(r.get("Items", [])))
