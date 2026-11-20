"""DynamoDB Streams consumer on `requests` (NEW_IMAGE), layer L7 (sending side).

For each new pending request: make a one-time token, store only its SHA-256 in
`approvals`, put the approval link in the trusted contact's inbox, and (for real
households with an email and an SNS topic) publish the same text to SNS.
Safe to retry: the `approvals` put is conditional, so a second delivery does nothing.
The token is never logged and never stored in plain.
"""
import datetime
import functools
import json
import secrets

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from trustedhand import config, db, hashing, receipts

_deser = TypeDeserializer()


@functools.lru_cache(maxsize=None)
def _sns():
    import boto3
    return boto3.client("sns")


def _log(**kw):
    print(json.dumps(kw, default=str))


def _plain(image):
    return {k: _deser.deserialize(v) for k, v in image.items()}


def _num(v, default=0):
    return int(v) if v is not None else default


def _process(req):
    household = req["household_id"]
    request_id = req["request_id"]
    now = db.now()
    expires_at = _num(req.get("expires_at"), now + config.REQUEST_TTL_S)

    token = secrets.token_urlsafe(32)
    try:
        db.tbl("approvals").put_item(
            Item={
                "request_id": request_id,
                "household_id": household,
                "token_hash": hashing.sha256(token),
                "request_hash": req.get("request_hash", ""),
                "expires_at": expires_at,
                "used": False,
                "attempts": 0,
                "ttl": expires_at + config.DEMO_TTL_S,
            },
            ConditionExpression="attribute_not_exists(request_id)",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            _log(stage="notifier", decision="already_done")
            return
        raise

    try:
        hh = db.tbl("households").get_item(Key={"household_id": household}).get("Item") or {}
        elder = hh.get("elder_name") or "Your family member"
        masked = hashing.mask_account(req.get("account"))
        link = f"{(config.env('WEB_ORIGIN') or '').rstrip('/')}/approve.html#r={request_id}&t={token}"
        title = f"{elder} asked to pay a new person"
        body = (f"{elder} asked to pay {str(req.get('payee_name'))[:80]} (account {masked}) "
                f"{_num(req.get('amount_inr'))} rupees. Reason given: {str(req.get('reason') or '')[:200]}")
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
        db.tbl("inbox").put_item(Item={
            "household_id": household,
            "sk": ts + "#" + secrets.token_hex(3),
            "kind": "approval_request",
            "title": title,
            "body": body,
            "link": link,
            "ttl": now + config.DEMO_TTL_S,
        })
        receipts.write(household, "notifier", "info", f"Approval request sent to the trusted contact for {str(req.get('payee_name'))[:60]}.",
                       tool="request_new_payee", session_id=req.get("session_id"))
    except Exception:
        # The token is lost if we stop here, so remove the row and let the stream retry with a new one.
        try:
            db.tbl("approvals").delete_item(Key={"request_id": request_id})
        finally:
            raise

    topic = config.env("SNS_TOPIC_ARN")
    if topic and not hh.get("demo") and hh.get("contact_email"):
        try:
            _sns().publish(TopicArn=topic, Subject=title[:100],
                           Message=f"{body}\n\nOpen this link to approve or deny:\n{link}")
        except Exception as e:  # inbox row exists already; do not retry (it would make a second token)
            _log(stage="notifier", sns_error=type(e).__name__)


def handler(event, context):
    failed = 0
    for rec in (event or {}).get("Records", []):
        try:
            if rec.get("eventName") != "INSERT":
                continue
            image = (rec.get("dynamodb") or {}).get("NewImage")
            if not image:
                continue
            req = _plain(image)
            if req.get("status") != "pending":
                continue
            _process(req)
        except Exception as e:
            failed += 1
            _log(stage="notifier", error=type(e).__name__)
    if failed:  # retry the batch; _process is idempotent
        raise RuntimeError(f"{failed} record(s) failed")
    return {"processed": True}
