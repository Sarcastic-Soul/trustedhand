"""L7 approval channel: GET and POST /approval/{request_id}.

Only the trusted contact holds the one-time token. The token is stored only as
a SHA-256 hash, bound to the request hash, usable once, and expires in 72 h.
Never log or return the token.
"""
import base64
import hmac
import json
import re
from decimal import Decimal

from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError

from trustedhand import config, db, hashing, ratelimit, receipts

MAX_ATTEMPTS = 5
_ID = re.compile(r"^[A-Za-z0-9_-]{4,64}$")
_ser = TypeSerializer()


def _clean(v):
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_clean(x) for x in v]
    return v


def _resp(status, obj):
    return {"statusCode": status, "headers": {"content-type": "application/json"},
            "body": json.dumps(_clean(obj))}


def _log(msg):
    print(msg[:200])


def _ip(event):
    return (event.get("requestContext", {}).get("http", {}) or {}).get("sourceIp") or "unknown"


def _ts(v):
    return db.iso(int(v)) if isinstance(v, (int, float, Decimal)) else v


def _num(v):
    return int(v) if v is not None else 0


def _hdr(event, name):
    for k, v in (event.get("headers") or {}).items():
        if k.lower() == name:
            return v
    return None


def handler(event, context=None):
    try:
        route = event.get("routeKey", "")
        rid = (event.get("pathParameters") or {}).get("request_id")
        if route not in ("GET /approval/{request_id}", "POST /approval/{request_id}"):
            return _resp(404, {"error": "Not found."})
        if not isinstance(rid, str) or not _ID.match(rid):
            return _resp(404, {"error": "This approval link is not valid."})
        return _handle(event, rid, route.startswith("POST"))
    except Exception as e:
        _log(f"unhandled {type(e).__name__}")
        return _resp(500, {"error": "Something went wrong. Please try again."})


def _handle(event, rid, is_post):
    if not ratelimit.hit(f"approval-ip#{_ip(event)}", 30, 600):
        return _resp(429, {"error": "Too many tries. Please wait a few minutes."})

    token, decision = _hdr(event, "x-approval-token"), None
    if is_post:
        try:
            raw = event.get("body") or ""
            if event.get("isBase64Encoded"):
                raw = base64.b64decode(raw).decode("utf-8", "replace")
            data = json.loads(raw) if raw and len(raw) < 4000 else {}
        except (ValueError, TypeError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        token = data.get("token") or token
        decision = data.get("decision")
        if decision not in ("approve", "deny"):
            return _resp(400, {"error": "decision must be approve or deny."})
    if not isinstance(token, str) or not token or len(token) > 200:
        return _resp(401, {"error": "This approval link is not valid."})

    appr = db.tbl("approvals").get_item(Key={"request_id": rid}, ConsistentRead=True).get("Item")
    if not appr:
        return _resp(404, {"error": "This approval link is not valid."})
    hid = appr["household_id"]

    if _num(appr.get("attempts")) >= MAX_ATTEMPTS:
        return _resp(403, {"error": "This link is locked after too many wrong tries."})

    # Constant-time compare of hashes.
    ok = hmac.compare_digest(hashing.sha256(token), str(appr.get("token_hash") or ""))
    if not ok:
        r = db.tbl("approvals").update_item(
            Key={"request_id": rid}, UpdateExpression="ADD attempts :one",
            ExpressionAttributeValues={":one": 1}, ReturnValues="UPDATED_NEW",
        )
        n = _num(r["Attributes"].get("attempts"))
        receipts.write(hid, "approval", "deny", f"Wrong approval token (attempt {n} of {MAX_ATTEMPTS})"
                       + ("; link locked." if n >= MAX_ATTEMPTS else "."), rule="R6")
        if n >= MAX_ATTEMPTS:
            return _resp(403, {"error": "This link is locked after too many wrong tries."})
        return _resp(401, {"error": "This approval link is not valid."})

    req = db.tbl("requests").get_item(Key={"household_id": hid, "request_id": rid}, ConsistentRead=True).get("Item")
    if not req:
        return _resp(404, {"error": "This approval link is not valid."})
    now = db.now()

    if _num(appr.get("expires_at")) < now:
        try:
            db.tbl("requests").update_item(
                Key={"household_id": hid, "request_id": rid},
                UpdateExpression="SET #s = :e", ConditionExpression="#s = :p",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":e": "expired", ":p": "pending"},
            )
            receipts.write(hid, "approval", "info", "Approval request expired without an answer.", rule="R6")
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
        return _resp(410, {"error": "This request has expired. Nothing was paid."})

    hh = db.tbl("households").get_item(Key={"household_id": hid}).get("Item") or {}
    if not is_post:
        status = req.get("status")
        return _resp(200, {
            "request_id": rid, "payee_name": req.get("payee_name"),
            "account_masked": hashing.mask_account(req.get("account")),
            "amount_inr": req.get("amount_inr"), "reason": req.get("reason"),  # reason is untrusted text
            "created_at": _ts(req.get("created_at")), "expires_at": _ts(appr.get("expires_at")),
            "status": status, "used": bool(appr.get("used")),
            "elder_name": hh.get("elder_name"), "contact_name": hh.get("contact_name"),
        })
    return _decide(hid, rid, appr, req, hh, decision, now)


def _decide(hid, rid, appr, req, hh, decision, now):
    if appr.get("used") or req.get("status") != "pending":
        return _resp(409, {"error": "already used", "status": req.get("status")})

    # Bait-and-switch guard: the approval covers exactly what the contact was shown.
    current = hashing.request_hash(hid, rid, req.get("payee_name"), req.get("account"), req.get("amount_inr"))
    if not hmac.compare_digest(current, str(appr.get("request_hash") or "")):
        receipts.write(hid, "approval", "deny", "Request changed after the approval link was sent. Nothing approved.",
                       rule="R6")
        return _resp(409, {"error": "This request changed after the link was sent. Nothing was approved."})

    approve = decision == "approve"
    S = _ser.serialize
    tbl = lambda n: config.table(n)
    tx = [
        {"Update": {
            "TableName": tbl("approvals"), "Key": {"request_id": S(rid)},
            "UpdateExpression": "SET #u = :t, #d = :dec, #at = :now",
            "ConditionExpression": "#u = :f AND token_hash = :h AND expires_at > :now",
            "ExpressionAttributeNames": {"#u": "used", "#d": "decision", "#at": "decided_at"},
            "ExpressionAttributeValues": {":t": S(True), ":f": S(False), ":dec": S(decision), ":now": S(now),
                                          ":h": S(appr["token_hash"])},
        }},
        {"Update": {
            "TableName": tbl("requests"), "Key": {"household_id": S(hid), "request_id": S(rid)},
            "UpdateExpression": "SET #s = :new",
            "ConditionExpression": "#s = :p AND request_hash = :rh AND amount_inr = :amt "
                                   "AND payee_name = :pn AND #a = :acct",
            "ExpressionAttributeNames": {"#s": "status", "#a": "account"},
            "ExpressionAttributeValues": {
                ":new": S("approved" if approve else "denied"), ":p": S("pending"), ":rh": S(appr["request_hash"]),
                ":amt": S(req["amount_inr"]), ":pn": S(req["payee_name"]), ":acct": S(req["account"]),
            },
        }},
    ]
    usable_from = None
    if approve:
        limits = {**config.DEFAULT_LIMITS, **(hh.get("limits") or {})}
        usable_from = now + int(limits["cooloff_s"])
        suffix = rid[3:11]
        ttl = int(hh.get("ttl") or (now + config.DEMO_TTL_S))
        payee = {
            "household_id": hid, "payee_id": "np-" + suffix, "name": req["payee_name"], "account": req["account"],
            "account_masked": hashing.mask_account(req["account"]), "usable_from": usable_from,
            "source": "approval", "request_id": rid, "ttl": ttl,
        }
        bill = {
            "household_id": hid, "bill_id": "tr-" + suffix, "kind": "transfer", "biller": req["payee_name"],
            "payee_id": "np-" + suffix, "amount_due_inr": req["amount_inr"], "status": "unpaid",
            "due_date": db.today_ist(now), "ttl": ttl,
            "memo": f"One-time transfer approved by {hh.get('contact_name', 'the trusted contact')}",
        }
        tx.append({"Put": {"TableName": tbl("payees"), "Item": {k: S(v) for k, v in payee.items()},
                           "ConditionExpression": "attribute_not_exists(payee_id)"}})
        tx.append({"Put": {"TableName": tbl("bills"), "Item": {k: S(v) for k, v in bill.items()},
                           "ConditionExpression": "attribute_not_exists(bill_id)"}})
    # Tell the agent on Amma's next turn, so it checks again instead of repeating
    # "waiting for Ravi" from its own memory. Advisory only: the tools still decide.
    if approve:
        note = (f"{hh.get('contact_name', 'The trusted contact')} approved {req['payee_name']} "
                f"({hashing.mask_account(req['account'])}) for ₹{int(req['amount_inr'])}. "
                f"It can be paid from {db.ist(usable_from)}.")
    else:
        note = (f"{hh.get('contact_name', 'The trusted contact')} said no to paying {req['payee_name']}. "
                f"Do not ask again for this payee.")
    tx.append({"Update": {
        "TableName": tbl("households"), "Key": {"household_id": S(hid)},
        "UpdateExpression": "SET notices = list_append(if_not_exists(notices, :e), :n)",
        "ConditionExpression": "attribute_exists(household_id)",
        "ExpressionAttributeValues": {":e": S([]), ":n": S([note])},
    }})
    try:
        db.client().transact_write_items(TransactItems=tx)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("TransactionCanceledException", "ConditionalCheckFailedException"):
            receipts.write(hid, "approval", "deny", "Approval refused: link already used, expired or request changed.",
                           rule="R6")
            return _resp(409, {"error": "already used"})
        raise

    masked = hashing.mask_account(req.get("account"))
    amt = int(req["amount_inr"])
    if approve:
        receipts.write(hid, "approval", "allow",
                       f"Trusted contact approved ₹{amt} to {req['payee_name']} ({masked}); "
                       f"payable after cool-off, from {db.ist(usable_from)}.", rule="R6")
        return _resp(200, {"status": "approved", "usable_from": db.iso(usable_from)})
    receipts.write(hid, "approval", "deny", f"Trusted contact denied ₹{amt} to {req['payee_name']} ({masked}).",
                   rule="R6")
    return _resp(200, {"status": "denied"})
