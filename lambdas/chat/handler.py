"""L0 chat proxy: POST /demo/start, POST /chat, GET /demo/state.

API Gateway HTTP API (payload v2.0). CORS is set on the API, not here.
The browser never picks the model, tools, system prompt or session: this
Lambda builds the InvokeHarness call itself.

Packaging note: the build copies `infra/system_prompt.md` next to this file
as `system_prompt.md` (the base prompt, used only when the household is
frozen and we must add the safety addendum).
"""
import base64
import datetime
import functools
import json
import re
import secrets
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

from botocore.exceptions import ClientError

from trustedhand import config, db, hashing, ratelimit, receipts, rules, textscan

MAX_MESSAGE = 1000
MAX_BODY = 16000
HISTORY_TURNS = 6

BLOCKED_REPLY = (
    "I can't act on that message. I'm here to help you pay your bills. "
    "Tell me which bill you would like to look at and we can start there."
)
SCAM_BLOCKED_REPLY = (
    "This looks like a known scam. Real police, CBI or bank officers never ask you to pay money "
    "or move it to a safe account over a call. Please hang up and call {contact}, or the cyber "
    "crime helpline 1930. New payees and transfers are paused for now. Your regular bills can still be paid."
)
FRIENDLY_ERROR = (
    "Sorry, something went wrong on my side. Please try again in a moment. "
    "If you asked me to pay something, please check your bills list before trying again."
)
EMPTY_REPLY = "I could not finish that. Please try again, or ask me about a bill."

SAFETY_ADDENDUM = """\
SAFETY MODE (added by the system, not by the user).
Signs of a known scam were seen in this chat, so this household is in safety mode.
New payees and one-time transfers are frozen. Do not try to set up a new payee or
transfer, and do not offer to.
In your reply, calmly tell the person that this looks like a known scam. Real police,
CBI, customs or court officers never ask for money transfers, never put people under
"digital arrest" on a video call, and never ask them to keep it secret from family.
Suggest they hang up, talk to Ravi, and call 1930 (the India cyber-crime helpline).
Stay kind and short. You can still help with ordinary bills from the bill list.
"""


# ---------------------------------------------------------------- plumbing

@functools.lru_cache(maxsize=None)
def _clients():
    """Bedrock clients. Tests replace this function."""
    import boto3
    from botocore.config import Config
    return SimpleNamespace(
        runtime=boto3.client("bedrock-runtime"),
        agentcore=boto3.client(
            "bedrock-agentcore",
            config=Config(read_timeout=120, connect_timeout=10, retries={"max_attempts": 1}),
        ),
    )


@functools.lru_cache(maxsize=None)
def _base_prompt():
    try:
        return Path(__file__).with_name("system_prompt.md").read_text(encoding="utf-8")
    except OSError:
        return None


def _create_household(household_id, now):
    """Lazy import: seeds.py is written by another owner. Tests replace this."""
    import importlib
    return importlib.import_module("trustedhand.seeds").create_demo_household(household_id, now)


def _log(msg):
    print(msg[:400])


def _clean(v):
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_clean(x) for x in v]
    return v


def _resp(status, obj):
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(_clean(obj)),
    }


def _body(event):
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    if len(raw) > MAX_BODY:
        raise ValueError("too big")
    data = json.loads(raw) if raw else {}
    if not isinstance(data, dict):
        raise ValueError("not an object")
    return data


def _ip(event):
    return (event.get("requestContext", {}).get("http", {}) or {}).get("sourceIp") or "unknown"


def _ts(v):
    if isinstance(v, (int, float, Decimal)):
        return db.iso(int(v))
    return v


def _query_all(table, cond, **kw):
    out, start = [], None
    while True:
        args = dict(KeyConditionExpression=cond, **kw)
        if start:
            args["ExclusiveStartKey"] = start
        r = db.tbl(table).query(**args)
        out.extend(r.get("Items", []))
        start = r.get("LastEvaluatedKey")
        if not start:
            return out


def _session_from_token(token):
    """Return the T# session item, or None if unknown or expired."""
    if not isinstance(token, str) or not 8 <= len(token) <= 200:
        return None
    item = db.tbl("sessions").get_item(Key={"pk": "T#" + hashing.sha256(token)}).get("Item")
    if not item or int(item.get("ttl", 0)) < db.now():
        return None
    return item


# ---------------------------------------------------------------- routes

def handler(event, context=None):
    try:
        route = event.get("routeKey", "")
        if route == "$default":
            # Lambda Function URL (used for /chat: API Gateway cuts requests at 30 s).
            method = (event.get("requestContext", {}).get("http", {}) or {}).get("method", "")
            route = "POST /chat" if method == "POST" else ""
        if route == "POST /demo/start":
            return demo_start(event)
        if route == "POST /chat":
            return chat(event)
        if route == "GET /demo/state":
            return demo_state(event)
        return _resp(404, {"error": "Not found."})
    except Exception as e:  # never leak details
        _log(f"unhandled {type(e).__name__}")
        return _resp(500, {"error": "Something went wrong. Please try again."})


def demo_start(event):
    ip = _ip(event)
    if not ratelimit.hit(f"start-ip#{ip}", 5, 3600):
        return _resp(429, {"error": "Too many demo starts from your network. Please try again in an hour."})
    if not ratelimit.hit("start-global", 200, 86400):
        return _resp(429, {"error": "The demo is very busy today. Please try again tomorrow."})

    now = db.now()
    household_id = "hh-" + secrets.token_hex(6)
    runtime_session_id = household_id + "-" + secrets.token_hex(16)
    chat_token = secrets.token_urlsafe(32)
    ttl = now + config.DEMO_TTL_S

    info = _create_household(household_id, now) or {}
    db.tbl("sessions").put_item(Item={
        "pk": "S#" + runtime_session_id, "household_id": household_id, "created_at": now, "ttl": ttl,
    })
    db.tbl("sessions").put_item(Item={
        "pk": "T#" + hashing.sha256(chat_token), "household_id": household_id,
        "runtime_session_id": runtime_session_id, "ttl": ttl,
    })
    return _resp(200, {
        "chat_token": chat_token,
        "household_id": household_id,
        "elder_name": info.get("elder_name", "Amma"),
        "contact_name": info.get("contact_name", "Ravi"),
    })


# ---------------------------------------------------------------- chat

def _guard_settings(source="INPUT"):
    # The reply goes through its own guardrail (masking only). The main one would
    # block the agent's own scam warnings, since they talk about the same topics.
    if source == "OUTPUT" and config.env("OUT_GUARDRAIL_ID"):
        return config.env("OUT_GUARDRAIL_ID"), config.env("OUT_GUARDRAIL_VERSION", "DRAFT")
    gid, ver = config.env("GUARDRAIL_ID"), config.env("GUARDRAIL_VERSION", "DRAFT")
    return (gid, ver) if gid else None


def _apply_guardrail(source, text):
    g = _guard_settings(source)
    if not g:
        return None
    t = {"text": text}
    if source == "INPUT":
        t["qualifiers"] = ["guard_content"]  # prompt-attack filter checks tagged content
    return _clients().runtime.apply_guardrail(
        guardrailIdentifier=g[0], guardrailVersion=g[1], source=source, content=[{"text": t}],
    )


def _read_assessment(resp):
    """-> (scam topic names, prompt_attack flag)."""
    topics, attack = [], False
    for a in (resp or {}).get("assessments", []) or []:
        for t in (a.get("topicPolicy") or {}).get("topics", []) or []:
            if t.get("type", "DENY") == "DENY":
                topics.append(str(t.get("name", "topic")))
        for f in (a.get("contentPolicy") or {}).get("filters", []) or []:
            if f.get("type") == "PROMPT_ATTACK" and f.get("action", "BLOCKED") != "NONE":
                attack = True
    return topics, attack


def _any_blocked(resp):
    def walk(x):
        if isinstance(x, dict):
            return x.get("action") == "BLOCKED" or any(walk(v) for v in x.values())
        if isinstance(x, list):
            return any(walk(v) for v in x)
        return False
    return walk((resp or {}).get("assessments", []))


def _freeze(household_id, until, reason):
    """Set or extend the freeze. Never shortens an existing one. True if written."""
    try:
        db.tbl("households").update_item(
            Key={"household_id": household_id},
            UpdateExpression="SET frozen_until = :u, freeze_reason = :r",
            ConditionExpression="attribute_exists(household_id) AND "
                                "(attribute_not_exists(frozen_until) OR frozen_until < :u)",
            ExpressionAttributeValues={":u": int(until), ":r": reason[:200]},
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def _clear_notices(household_id, seen):
    """Remove the notices that were passed to the agent (only if none were added since)."""
    try:
        db.tbl("households").update_item(
            Key={"household_id": household_id}, UpdateExpression="REMOVE notices",
            ConditionExpression="notices = :n", ExpressionAttributeValues={":n": seen},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            _log(f"clear notices failed {e.response['Error']['Code']}")


def _set_asked_amounts(rsid, amounts):
    """Store the rupee amounts Amma named this turn, for the pay tool (R2 / E7). Cleared every turn."""
    try:
        db.tbl("sessions").update_item(
            Key={"pk": "S#" + rsid}, UpdateExpression="SET asked_amounts = :a",
            ConditionExpression="attribute_exists(pk)", ExpressionAttributeValues={":a": amounts})
    except Exception as e:
        _log(f"asked amounts not saved {type(e).__name__}")


def _inbox_alert(household_id, title, body):
    item = {
        "household_id": household_id,
        "sk": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
              + "#" + secrets.token_hex(3),
        "kind": "alert", "title": title[:120], "body": body[:600],
        "ttl": db.now() + config.DEMO_TTL_S,
    }
    db.tbl("inbox").put_item(Item=item)


CHAT_OK_PATTERNS = {"pay_command", "payee_command", "upi_handle"}
SCAM_COMBO = {"secrecy", "pay_command", "payee_command"}
SECRET_WORDS = re.compile(r"\b(otp|pin|cvv|password|passcode)\b", re.I)


def _typed_secrets(message):
    """Short codes Amma typed next to OTP/PIN words. The reply must never repeat them (E6)."""
    if not SECRET_WORDS.search(message):
        return set()
    return set(re.findall(r"(?<!\d)\d{4,8}(?!\d)", message))


def _mask_digits(text):
    return re.sub(r"(?<!\d)\d{9,}(?!\d)", lambda m: hashing.mask_account(m.group()), text)


def _err_msg(e):
    """Short error message for logs only (never returned to the browser)."""
    resp = getattr(e, "response", None)
    if isinstance(resp, dict):
        return str((resp.get("Error") or {}).get("Message", ""))[:300]
    return str(e)[:300]


def _stream_reply(stream):
    """-> (text, stop_reason, error_name or None)."""
    parts, stop, err = [], None, None
    try:
        for ev in stream:
            if "contentBlockDelta" in ev:
                t = (ev["contentBlockDelta"].get("delta") or {}).get("text")
                if t:
                    parts.append(t)
            elif "messageStop" in ev:
                stop = ev["messageStop"].get("stopReason")
            else:
                for k in ev:
                    if k.endswith("Exception") or k == "runtimeClientError":
                        err = k
                        _log(f"stream event {k}: {str((ev[k] or {}).get('message', ''))[:300]}")
    except Exception as e:  # modeled stream errors and network errors
        err = type(e).__name__
        _log(f"stream error {err}: {_err_msg(e)}")
    return "".join(parts), stop, err


def _last_sk(household_id):
    r = receipts.recent(household_id, limit=1)
    return r[-1]["sk"] if r else None


def _trim_receipts(household_id, since_sk):
    out = []
    for r in receipts.recent(household_id, since_sk=since_sk):
        out.append({k: r[k] for k in ("layer", "rule", "decision", "tool", "summary", "sk") if k in r})
    return out


def chat(event):
    ip = _ip(event)
    try:
        data = _body(event)
    except (ValueError, json.JSONDecodeError):
        return _resp(400, {"error": "Bad request."})
    message = data.get("message")
    if not isinstance(message, str) or not message.strip() or len(message) > MAX_MESSAGE:
        return _resp(400, {"error": f"Please send a message of 1 to {MAX_MESSAGE} characters."})

    # R11: per-IP first, so token guessing also burns the IP budget.
    if not ratelimit.hit(f"chat-ip#{ip}", 60, 3600):
        return _resp(429, {"error": "Too many messages from your network. Please wait a bit and try again."})
    sess = _session_from_token(data.get("chat_token"))
    if not sess:
        return _resp(401, {"error": "This chat session is not valid or has expired. Please start a new demo."})
    household_id, rsid = sess["household_id"], sess["runtime_session_id"]
    if not ratelimit.hit(f"chat-sess#{rsid}", 20, 600):
        receipts.write(household_id, "proxy", "deny", "Chat rate limit reached for this session (20 per 10 min).",
                       rule="R11", session_id=rsid)
        return _resp(429, {"error": "You are sending messages too fast. Please wait a few minutes."})
    if not ratelimit.hit(f"chat-global#{db.today_ist()}", int(config.env("GLOBAL_DAILY_RUNS", "1000")), 86400):
        return _resp(429, {"error": "The demo has reached its daily limit. Please try again tomorrow."})

    hh = db.tbl("households").get_item(Key={"household_id": household_id}).get("Item")
    if not hh:
        return _resp(401, {"error": "This demo household has expired. Please start a new demo."})
    limits = {**config.DEFAULT_LIMITS, **(hh.get("limits") or {})}
    now = db.now()
    frozen_until = int(hh.get("frozen_until") or 0)
    was_frozen = frozen_until > now
    since_sk = _last_sk(household_id)

    # Deterministic scan: receipt only, never blocks.
    # Amma asking to pay or add someone is normal here, so only injection-style
    # signs count in her own message (tool results are scanned in full).
    raw_hits = textscan.find_injection(message)
    hits = [x for x in raw_hits if x not in CHAT_OK_PATTERNS]
    if hits:
        receipts.write(household_id, "proxy", "flag",
                       "Instruction-like text in the chat message: " + ", ".join(hits), rule="R7", session_id=rsid)

    # Input guardrail.
    try:
        gres = _apply_guardrail("INPUT", message)
    except Exception as e:
        _log(f"input guardrail failed {type(e).__name__}")
        gres = None
    topics, attack = _read_assessment(gres)
    # Deterministic backup for R9: threat words plus secrecy or a money command.
    # The guardrail missed an "ED officer, hawala case, bail guarantee" message in testing.
    if "urgency_threat" in raw_hits and set(raw_hits) & SCAM_COMBO:
        topics.append("threat-plus-money-words")

    if topics:
        until = now + int(limits.get("freeze_s", 600))
        reason = "Scam signs in chat: " + ", ".join(sorted(set(topics)))
        _freeze(household_id, until, reason)
        frozen_until = max(frozen_until, until)
        receipts.write(household_id, "guardrail", "flag",
                       f"{reason}. Household frozen for new payees and transfers until {db.ist(frozen_until)}.",
                       rule="R9", session_id=rsid)
        if not was_frozen:
            elder = hh.get("elder_name", "The elder")
            _inbox_alert(
                household_id,
                f"Possible scam: {elder} may be being coached",
                f"TrustedHand saw signs of a known scam in {elder}'s chat ({', '.join(sorted(set(topics)))}). "
                f"New payees and transfers are frozen until {db.ist(frozen_until)}. "
                f"Please call {elder} now. Known bills can still be paid.",
            )
    frozen = frozen_until > now

    # Prompt attack: the agent is not called. Runs after the freeze so a message that
    # is both a prompt attack and a scam sign still freezes and alerts the contact.
    if attack:
        receipts.write(household_id, "guardrail", "deny",
                       "Guardrail blocked the message as a prompt attack. The agent was not called.",
                       rule="R10", session_id=rsid)
        reply = SCAM_BLOCKED_REPLY.format(contact=hh.get("contact_name", "your family")) if topics else BLOCKED_REPLY
        return _resp(200, {"reply": reply, "blocked": True, "frozen": frozen,
                           "receipts": _trim_receipts(household_id, since_sk)})

    # Harness call: fixed shape. No model, tools, allowedTools or skills from anywhere.
    history_on = config.env("SEND_HISTORY") == "1"
    messages = []
    if history_on:
        for h in sess.get("history") or []:
            if h.get("role") in ("user", "assistant") and h.get("text"):
                messages.append({"role": h["role"], "content": [{"text": str(h["text"])}]})
    notices = [str(n) for n in (hh.get("notices") or [])][:5]
    note = f"[Note from TrustedHand, not from Amma. Time now: {db.ist(now)}."
    if notices:
        note += " Updates since last message: " + " ".join(notices)
    note += " Earlier answers may be out of date, so check with the tools before saying something cannot be done.]"
    user_text = note + "\n" + message
    kwargs = {"harnessArn": config.env("HARNESS_ARN")}
    if frozen:
        base = _base_prompt()
        if base:
            kwargs["systemPrompt"] = [{"text": base.rstrip() + "\n\n" + SAFETY_ADDENDUM}]
        else:  # no packaged base prompt: do not replace it, put the notice in the message
            _log("system_prompt.md missing; sending safety notice inside the message")
            user_text = "[Notice from TrustedHand, not from the user]\n" + SAFETY_ADDENDUM + "\n" + user_text
    messages.append({"role": "user", "content": [{"text": user_text}]})
    _set_asked_amounts(rsid, rules.asked_amounts(message))
    kwargs.update(runtimeSessionId=rsid, messages=messages)

    text, stop, err = "", None, None
    try:
        out = _clients().agentcore.invoke_harness(**kwargs)
        text, stop, err = _stream_reply(out.get("stream", []))
    except Exception as e:
        err = type(e).__name__
        _log(f"invoke_harness error {err}: {_err_msg(e)}")
    if notices and not err:
        _clear_notices(household_id, hh.get("notices"))
    if err:
        receipts.write(household_id, "harness", "info", f"Agent run problem: {err}", session_id=rsid)
        _log(f"harness problem {err}")
        reply = (text.strip() + "\n\n" + FRIENDLY_ERROR) if text.strip() else FRIENDLY_ERROR
    else:
        reply = text.strip() or EMPTY_REPLY

    # Output guardrail and account masking (R8).
    blocked = False
    try:
        gout = _apply_guardrail("OUTPUT", reply)
        if gout and gout.get("action") == "GUARDRAIL_INTERVENED":
            outs = gout.get("outputs") or []
            if outs and outs[0].get("text"):
                reply = outs[0]["text"]
            blocked = _any_blocked(gout)
            receipts.write(household_id, "guardrail", "flag",
                           "Output guardrail changed the reply" + (" (blocked)." if blocked else " (masked)."),
                           rule="R8", session_id=rsid)
    except Exception as e:
        _log(f"output guardrail failed {type(e).__name__}")
    for code in _typed_secrets(message):
        hidden = re.sub(rf"(?<!\d){code}(?!\d)", "[hidden]", reply)
        if hidden != reply:
            receipts.write(household_id, "proxy", "flag", "A code Amma typed (OTP or PIN) was hidden from the reply.",
                           rule="R8", session_id=rsid)
            reply = hidden
    masked = _mask_digits(reply)
    if masked != reply:
        receipts.write(household_id, "proxy", "flag", "Long number masked in the reply.", rule="R8", session_id=rsid)
        reply = masked

    if history_on and not err:
        hist = list(sess.get("history") or [])
        hist += [{"role": "user", "text": message[:MAX_MESSAGE]}, {"role": "assistant", "text": reply[:2000]}]
        hist = hist[-2 * HISTORY_TURNS:]
        try:
            db.tbl("sessions").update_item(
                Key={"pk": "T#" + hashing.sha256(data["chat_token"])},
                UpdateExpression="SET history = :h", ExpressionAttributeValues={":h": hist},
            )
        except Exception as e:
            _log(f"history save failed {type(e).__name__}")

    return _resp(200, {"reply": reply, "blocked": blocked, "frozen": frozen,
                       "receipts": _trim_receipts(household_id, since_sk)})


# ---------------------------------------------------------------- demo state

def demo_state(event):
    ip = _ip(event)
    if not ratelimit.hit(f"state-ip#{ip}", 200, 600):
        return _resp(429, {"error": "Too many refreshes. Please wait a moment."})
    # Header only: a token in the URL would land in access logs and browser history.
    headers = {str(k).lower(): v for k, v in (event.get("headers") or {}).items()}
    token = headers.get("x-chat-token")
    sess = _session_from_token(token)
    if not sess:
        return _resp(401, {"error": "This chat session is not valid or has expired."})
    from boto3.dynamodb.conditions import Key
    hid = sess["household_id"]
    now = db.now()
    hh = db.tbl("households").get_item(Key={"household_id": hid}).get("Item") or {}
    limits = {**config.DEFAULT_LIMITS, **(hh.get("limits") or {})}

    bills = [
        {k: b.get(k) for k in ("bill_id", "biller", "payee_id", "amount_due_inr", "due_date", "status", "memo", "kind")}
        for b in _query_all("bills", Key("household_id").eq(hid))
    ]
    payees = [
        {"payee_id": p["payee_id"], "name": p.get("name"), "account_masked": p.get("account_masked"),
         "usable_from": _ts(p.get("usable_from")), "source": p.get("source")}
        for p in _query_all("payees", Key("household_id").eq(hid))  # `account` is never copied
    ]
    day = db.tbl("ledger").get_item(Key={"household_id": hid, "sk": "DAY#" + db.today_ist()}).get("Item") or {}
    pays = _query_all("ledger", Key("household_id").eq(hid) & Key("sk").begins_with("PAY#"))
    pays.sort(key=lambda p: str(p.get("created_at", "")), reverse=True)
    payments_today = {
        "spent_inr": day.get("spent_inr", 0), "count": day.get("count", 0),
        "daily_limit_inr": limits["daily"], "count_limit": limits["daily_count"],
        "per_payment_limit_inr": limits["per_payment"],
        "recent": [{k: p.get(k) for k in ("bill_id", "payee_id", "amount_inr", "created_at")} for p in pays[:10]],
    }
    reqs = [
        {"request_id": r["request_id"], "payee_name": r.get("payee_name"),
         "account_masked": hashing.mask_account(r.get("account")), "amount_inr": r.get("amount_inr"),
         "reason": r.get("reason"), "status": r.get("status"),
         "created_at": _ts(r.get("created_at")), "expires_at": _ts(r.get("expires_at"))}
        for r in _query_all("requests", Key("household_id").eq(hid))
    ]
    # Demo convenience: the "Ravi's phone" panel shows his inbox, approval links included.
    # In a real deployment this would be email/SMS to Ravi, never visible to the chat user.
    inbox = [
        {k: m.get(k) for k in ("sk", "kind", "title", "body", "link")}
        for m in db.tbl("inbox").query(
            KeyConditionExpression=Key("household_id").eq(hid), ScanIndexForward=False, Limit=50
        ).get("Items", [])
    ]
    rec = [
        {k: r[k] for k in ("sk", "layer", "rule", "decision", "tool", "summary") if k in r}
        for r in receipts.recent(hid, limit=50)  # oldest first
    ]
    fu = int(hh.get("frozen_until") or 0)
    return _resp(200, {
        "bills": bills, "payees": payees, "payments_today": payments_today, "requests": reqs,
        "inbox": inbox, "receipts": rec,
        "frozen": fu > now, "frozen_until": db.iso(fu) if fu else None,
        "elder_name": hh.get("elder_name"), "contact_name": hh.get("contact_name"),
    })
