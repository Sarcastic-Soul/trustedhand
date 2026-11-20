"""AgentCore harness hook Lambda (beforeToolCall and afterToolCall), layer L2.

before: intent receipt for every tool call; strike lock (R12); freeze check for
request_new_payee (R9); unknown tools are denied. Any internal error denies
(fail closed). The reason text is shown to the model as the tool error, so it is
written in plain English for an older person.

after: counts refused payment attempts per household per day (R12), across every
chat session, so starting a new chat does not reset the count. Always allows,
because a deny here would stop the whole reply. Errors are logged only.
"""
import datetime
import json
import secrets

from botocore.exceptions import ClientError

from trustedhand import config, db, hashing, receipts, sessions

KNOWN_TOOLS = {"list_bills", "list_payees", "pay_bill", "request_new_payee", "payment_status"}
MONEY_TOOLS = {"pay_bill", "request_new_payee"}

MSG_LOCKED = ("Too many payments were refused today, so payments are paused for a little while to keep your "
              "money safe. Your trusted contact has been told.")
MSG_FROZEN = ("New people cannot be paid right now, because this chat showed signs of a known scam. Your regular "
              "bills can still be paid. Your trusted contact has been told.")
MSG_UNKNOWN = "That is not something I am allowed to do. I can only help with your bills and approved payees."
MSG_NO_SESSION = "I could not tell which chat this belongs to, so I did not do it. Nothing was paid."
MSG_ERROR = "I could not safely check this step, so I did not do it. Nothing was paid. Please try again in a moment."


def _log(**kw):
    print(json.dumps(kw, default=str))


def _short(name):
    """'bank___pay_bill' -> 'pay_bill'; anything not in that form -> None."""
    name = str(name or "")
    if name.startswith("bank___") and name[7:] in KNOWN_TOOLS:
        return name[7:]
    return None


def _dict(v):
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            return {}
    return v if isinstance(v, dict) else {}


def _intent_summary(tool, tool_input):
    if tool == "pay_bill":
        return f"Agent asked to pay bill {str(tool_input.get('bill_id'))[:60]} for {str(tool_input.get('amount_inr'))[:12]} rupees."
    if tool == "request_new_payee":
        return (f"Agent asked to add payee '{str(tool_input.get('payee_name'))[:60]}' "
                f"(account {hashing.mask_account(tool_input.get('account'))}) and pay {str(tool_input.get('amount_inr'))[:12]} rupees.")
    return f"Agent asked to run {tool}."


def _strike_key(household, session_id, now):
    """R12 counts per household per day in India, not per chat, so a new chat does not reset it.
    The strikes table key is still named session_id; it holds this string."""
    if household:
        return f"HH#{household}#{db.today_ist(now)}"
    return f"S#{session_id}"


def _reply(decision, reason):
    return {"decision": decision, "reason": reason[:1024]}


# ---------------------------------------------------------------- before

def _before(event):
    ctx = event.get("context") or {}
    session_id = event.get("sessionId")
    raw_name = ctx.get("toolName")
    tool = _short(raw_name)
    household = sessions.household_for_session(session_id)
    now = db.now()

    if not household:
        receipts.write(None, "hook", "deny", f"Call to {str(raw_name)[:60]} had no known session.", tool=tool, session_id=session_id)
        return _reply("deny", MSG_NO_SESSION)
    if tool is None:
        receipts.write(household, "hook", "deny", f"Agent asked for a tool that is not allowed: {str(raw_name)[:60]}.",
                       rule="A1", session_id=session_id)
        return _reply("deny", MSG_UNKNOWN)

    summary = _intent_summary(tool, _dict(ctx.get("toolInput")))

    if tool in MONEY_TOOLS:
        strikes = db.tbl("strikes").get_item(Key={"session_id": _strike_key(household, session_id, now)}).get("Item") or {}
        if int(strikes.get("locked_until", 0)) > now:
            receipts.write(household, "hook", "deny", summary + " Denied: payments locked after repeated refusals today.",
                           rule="R12", tool=tool, session_id=session_id)
            return _reply("deny", MSG_LOCKED)
    if tool == "request_new_payee":
        hh = db.tbl("households").get_item(Key={"household_id": household}).get("Item") or {}
        if int(hh.get("frozen_until", 0) or 0) > now:
            receipts.write(household, "hook", "deny", summary + " Denied: household is frozen for new payees.",
                           rule="R9", tool=tool, session_id=session_id)
            return _reply("deny", MSG_FROZEN)

    receipts.write(household, "hook", "allow", summary, tool=tool, session_id=session_id)
    return _reply("allow", "ok")


# ---------------------------------------------------------------- after

def _is_failure(result):
    if result.get("isError"):
        return True
    for c in result.get("content") or []:
        text = c.get("text") if isinstance(c, dict) else None
        if not isinstance(text, str):
            continue
        if "Tool Execution Denied" in text or "policy enforcement" in text:
            return True
        try:
            data = json.loads(text)
        except ValueError:
            continue
        if isinstance(data, dict) and data.get("status") == "refused":
            return True
    return False


def _after(event):
    ctx = event.get("context") or {}
    session_id = event.get("sessionId")
    tool = _short(ctx.get("toolName"))
    if tool not in MONEY_TOOLS or not session_id:
        return
    if not _is_failure(_dict(ctx.get("toolResult"))):
        return
    household = sessions.household_for_session(session_id)
    now = db.now()
    key = _strike_key(household, session_id, now)
    r = db.tbl("strikes").update_item(
        Key={"session_id": key},
        UpdateExpression="ADD #c :one SET #t = :ttl",
        ExpressionAttributeNames={"#c": "count", "#t": "ttl"},
        ExpressionAttributeValues={":one": 1, ":ttl": now + config.DEMO_TTL_S},
        ReturnValues="UPDATED_NEW",
    )
    count = int(r["Attributes"]["count"])
    _log(stage="after", tool=tool, strikes=count)
    if count < config.STRIKE_LIMIT:
        return
    try:  # only the call that sets the lock raises the alert
        db.tbl("strikes").update_item(
            Key={"session_id": key},
            UpdateExpression="SET locked_until = :lu",
            ConditionExpression="attribute_not_exists(locked_until) OR locked_until <= :now",
            ExpressionAttributeValues={":lu": now + config.STRIKE_LOCK_S, ":now": now},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return
        raise
    receipts.write(household, "hook", "deny",
                   f"{count} payment attempts were refused today. Payments and new requests are locked for "
                   f"{config.STRIKE_LOCK_S // 60} minutes.", rule="R12", tool=tool, session_id=session_id)
    if household:
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
        db.tbl("inbox").put_item(Item={
            "household_id": household,
            "sk": ts + "#" + secrets.token_hex(3),
            "kind": "alert",
            "title": "Payments paused",
            "body": (f"{count} payment attempts were refused today, across all chats. As a safety step, payments and new payee "
                     f"requests are paused for {config.STRIKE_LOCK_S // 60} minutes. Please check in with the family member."),
            "ttl": now + config.DEMO_TTL_S,
        })


def handler(event, context):
    kind = (event or {}).get("event")
    if kind == "after_tool_call":
        try:
            _after(event)
        except Exception as e:
            _log(stage="after", error=type(e).__name__)
        return _reply("allow", "ok")
    try:
        out = _before(event or {})
    except Exception as e:
        _log(stage="before", error=type(e).__name__)
        try:
            receipts.write(None, "hook", "deny", "Hook error; call denied (fail closed).", session_id=(event or {}).get("sessionId"))
        except Exception:
            pass
        return _reply("deny", MSG_ERROR)
    _log(stage="before", tool=_short(((event or {}).get("context") or {}).get("toolName")), decision=out["decision"])
    return out
