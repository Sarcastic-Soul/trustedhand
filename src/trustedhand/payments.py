"""Tool logic on DynamoDB. The source of truth for R1-R6 and R9.

`pay` moves money (in the simulated ledger) with ONE TransactWriteItems so the
daily cap, the payment count and the "bill is unpaid" check cannot be raced.
"""
import secrets
import time

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from . import config, db, hashing, receipts, rules, sessions

_TXN_RETRIES = 4


# ---------------------------------------------------------------- small helpers

def _int(v, default=0):
    return int(v) if v is not None else default


def _n(v):
    return {"N": str(int(v))}


def _s(v):
    return {"S": str(v)}


def _household(household_id):
    return db.tbl("households").get_item(Key={"household_id": household_id}).get("Item")


def _read_day(household_id, day, consistent=True):
    item = db.tbl("ledger").get_item(
        Key={"household_id": household_id, "sk": "DAY#" + day}, ConsistentRead=consistent
    ).get("Item") or {}
    return {"spent_inr": _int(item.get("spent_inr")), "count": _int(item.get("count"))}


def _deny(household_id, session_id, tool, ref, summary):
    receipts.write(household_id, "tool", "deny", summary, rule=ref["rule"], tool=tool, session_id=session_id)
    return ref


def _error(message="Something went wrong. Nothing was paid."):
    return {"status": "error", "message": message}


# ---------------------------------------------------------------- reads

def list_bills(household_id):
    items = db.tbl("bills").query(KeyConditionExpression=Key("household_id").eq(household_id)).get("Items", [])
    bills = [{
        "bill_id": b["bill_id"],
        "biller": b.get("biller"),
        "payee_id": b.get("payee_id"),
        "amount_due_inr": _int(b.get("amount_due_inr")),
        "due_date": b.get("due_date"),
        "status": b.get("status"),
        "memo": b.get("memo", ""),   # untrusted biller text; another layer scans it
    } for b in items]
    bills.sort(key=lambda b: (str(b["due_date"]), b["bill_id"]))
    return {"bills": bills}


def list_payees(household_id, now):
    items = db.tbl("payees").query(KeyConditionExpression=Key("household_id").eq(household_id)).get("Items", [])
    payees = []
    for p in items:
        uf = _int(p.get("usable_from"))
        payees.append({
            "payee_id": p["payee_id"],
            "name": p.get("name"),
            "account_masked": p.get("account_masked") or hashing.mask_account(p.get("account")),
            "usable_from": db.iso(uf) if uf > 0 else None,
        })
    payees.sort(key=lambda p: p["payee_id"])
    return {"payees": payees}


def _pending_requests(household_id, now):
    items = db.tbl("requests").query(KeyConditionExpression=Key("household_id").eq(household_id)).get("Items", [])
    return [r for r in items if r.get("status") == "pending" and _int(r.get("expires_at")) > int(now)]


def status(household_id, now):
    hh = _household(household_id) or {}
    lim = rules.limits_of(hh)
    day = _read_day(household_id, db.today_ist(now))
    pay_rows = db.tbl("ledger").query(
        KeyConditionExpression=Key("household_id").eq(household_id) & Key("sk").begins_with("PAY#")
    ).get("Items", [])
    pay_rows.sort(key=lambda r: _int(r.get("created_at")), reverse=True)
    recent = [{
        "payment_id": r["sk"][4:],
        "bill_id": r.get("bill_id"),
        "payee": r.get("payee_name") or r.get("payee_id"),
        "amount_inr": _int(r.get("amount_inr")),
        "created_at": db.iso(_int(r.get("created_at"))),
    } for r in pay_rows[:5]]
    pending = [{
        "request_id": r["request_id"],
        "payee_name": r.get("payee_name"),
        "account_masked": hashing.mask_account(r.get("account")),
        "amount_inr": _int(r.get("amount_inr")),
        "reason": r.get("reason"),
        "created_at": db.iso(_int(r.get("created_at"))),
        "expires_at": db.iso(_int(r.get("expires_at"))),
    } for r in _pending_requests(household_id, now)]
    return {
        "today": {
            "spent_inr": day["spent_inr"],
            "count": day["count"],
            "daily_limit_inr": lim["daily"],
            "count_limit": lim["daily_count"],
            "per_payment_limit_inr": lim["per_payment"],
        },
        "recent_payments": recent,
        "pending_requests": pending,
        "frozen_until": db.iso(hh["frozen_until"]) if rules.is_frozen(hh, now) else None,
    }


# ---------------------------------------------------------------- pay

def _txn_reason_to_refusal(reasons, household_id, day, hh):
    """Map CancellationReasons (order: PAY put, DAY update, bill update) to R5 / R4."""
    def failed(i):
        return i < len(reasons) and reasons[i].get("Code") == "ConditionalCheckFailed"

    if failed(2) or failed(0):
        return rules.refuse("R5", "This bill has already been paid. I will not pay it twice.")
    if failed(1):
        lim = rules.limits_of(hh)
        cur = _read_day(household_id, day)
        if cur["count"] >= lim["daily_count"]:
            return rules.refuse("R4", f"I can make at most {lim['daily_count']} payments in one day, "
                                      "and that number is reached for today.")
        left = max(lim["daily"] - cur["spent_inr"], 0)
        return rules.refuse("R4", f"This would go over today's limit of {rules.inr(lim['daily'])}. "
                                  f"You can still pay up to {rules.inr(left)} today.")
    return None


def pay(household_id, session_id, bill_id, amount_inr, now):
    tool = "pay_bill"
    bad = rules.validate_pay_input(bill_id, amount_inr)
    if bad:
        return _deny(household_id, session_id, tool, bad, "Payment refused: invalid input.")

    hh = _household(household_id)
    if not hh:
        return _error("Household not found.")
    lim = rules.limits_of(hh)
    bill = db.tbl("bills").get_item(
        Key={"household_id": household_id, "bill_id": bill_id}, ConsistentRead=True).get("Item")
    payee = None
    if bill and bill.get("payee_id"):
        payee = db.tbl("payees").get_item(
            Key={"household_id": household_id, "payee_id": bill["payee_id"]}, ConsistentRead=True).get("Item")
    day = db.today_ist(now)
    ref = rules.check_pay(hh, bill, payee, amount_inr, now, _read_day(household_id, day),
                          sessions.asked_amounts(session_id))
    if ref:
        return _deny(household_id, session_id, tool, ref,
                     f"Refused payment of {rules.inr(amount_inr)} on bill {bill_id[:40]}: {ref['rule']}.")

    payment_id = "pay-" + secrets.token_hex(5)
    ledger = config.table("ledger")
    pay_item = {
        "household_id": _s(household_id), "sk": _s("PAY#" + payment_id),
        "bill_id": _s(bill_id), "payee_id": _s(bill["payee_id"]),
        "payee_name": _s(payee.get("name", bill["payee_id"])),
        "amount_inr": _n(amount_inr), "session_id": _s(session_id or ""),
        "created_at": _n(now),
    }
    day_update = "ADD spent_inr :amt, #count :one"
    day_names = {"#count": "count"}
    day_values = {
        ":amt": _n(amount_inr), ":one": _n(1),
        ":daily_minus_amt": _n(lim["daily"] - amount_inr), ":daily_count": _n(lim["daily_count"]),
    }
    if hh.get("ttl") is not None:   # demo households: ledger rows expire with the household
        pay_item["ttl"] = _n(hh["ttl"])
        day_update = "SET #ttl = if_not_exists(#ttl, :ttl) " + day_update
        day_names["#ttl"] = "ttl"
        day_values[":ttl"] = _n(hh["ttl"])

    items = [
        {"Put": {
            "TableName": ledger, "Item": pay_item,
            "ConditionExpression": "attribute_not_exists(household_id)",
        }},
        {"Update": {
            "TableName": ledger, "Key": {"household_id": _s(household_id), "sk": _s("DAY#" + day)},
            "UpdateExpression": day_update,
            "ConditionExpression": "(attribute_not_exists(spent_inr) OR spent_inr <= :daily_minus_amt) "
                                   "AND (attribute_not_exists(#count) OR #count < :daily_count)",
            "ExpressionAttributeNames": day_names, "ExpressionAttributeValues": day_values,
        }},
        {"Update": {
            "TableName": config.table("bills"), "Key": {"household_id": _s(household_id), "bill_id": _s(bill_id)},
            "UpdateExpression": "SET #status = :paid",
            "ConditionExpression": "#status = :unpaid",
            "ExpressionAttributeNames": {"#status": "status"},
            "ExpressionAttributeValues": {":paid": _s("paid"), ":unpaid": _s("unpaid")},
        }},
    ]

    for attempt in range(_TXN_RETRIES):
        try:
            db.client().transact_write_items(TransactItems=items)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            reasons = e.response.get("CancellationReasons") or []
            ref = _txn_reason_to_refusal(reasons, household_id, day, hh)
            if ref:
                return _deny(household_id, session_id, tool, ref,
                             f"Refused payment of {rules.inr(amount_inr)} on bill {bill_id[:40]}: {ref['rule']} (atomic check).")
            # Only transaction conflicts (another payment in flight): retry briefly.
            time.sleep(0.02 * (attempt + 1) + secrets.randbelow(20) / 1000)
    else:
        receipts.write(household_id, "tool", "deny", "Payment not made: busy, nothing was paid.",
                       rule="BUSY", tool=tool, session_id=session_id)
        return _error("The system was busy. Nothing was paid. Please try again.")

    spent = _read_day(household_id, day)["spent_inr"]
    receipts.write(household_id, "tool", "allow",
                   f"Paid {rules.inr(amount_inr)} to {payee.get('name', bill['payee_id'])[:60]} for bill {bill_id[:40]}.",
                   rule="A2", tool=tool, session_id=session_id)
    return {
        "status": "paid", "payment_id": payment_id, "bill_id": bill_id,
        "payee": payee.get("name", bill["payee_id"]), "amount_inr": int(amount_inr),
        "spent_today_inr": spent, "daily_limit_inr": lim["daily"],
    }


# ---------------------------------------------------------------- request_payee

def request_payee(household_id, session_id, payee_name, account, amount_inr, reason, now):
    tool = "request_new_payee"
    hh = _household(household_id)
    if not hh:
        return _error("Household not found.")

    ref = rules.check_freeze_for_request(hh, now)
    if ref:
        return _deny(household_id, session_id, tool, ref, "Refused new payee request: household is frozen.")
    bad, clean = rules.validate_request_input(payee_name, account, amount_inr, reason)
    if bad:
        return _deny(household_id, session_id, tool, bad, f"Refused new payee request: {bad['rule']} invalid input.")
    ref = rules.check_pending_requests(len(_pending_requests(household_id, now)))
    if ref:
        return _deny(household_id, session_id, tool, ref, "Refused new payee request: too many pending.")

    request_id = "rq-" + secrets.token_hex(5)
    expires_at = int(now) + config.REQUEST_TTL_S
    item = {
        "household_id": household_id, "request_id": request_id,
        "payee_name": clean["payee_name"], "account": clean["account"],
        "amount_inr": int(amount_inr), "reason": clean["reason"],
        "status": "pending",
        "request_hash": hashing.request_hash(household_id, request_id, clean["payee_name"],
                                             clean["account"], amount_inr),
        "session_id": session_id or "", "created_at": int(now),
        "expires_at": expires_at, "ttl": expires_at + 86400,
    }
    db.tbl("requests").put_item(Item=item, ConditionExpression="attribute_not_exists(request_id)")
    contact = hh.get("contact_name") or "your trusted contact"
    receipts.write(
        household_id, "tool", "allow",
        f"New payee request {request_id} for {rules.inr(amount_inr)} to {clean['payee_name'][:40]} "
        f"({hashing.mask_account(clean['account'])}) sent for approval.",
        rule="R6", tool=tool, session_id=session_id)
    cool = rules.duration_text(rules.limits_of(hh)["cooloff_s"])
    return {
        "status": "sent_to_trusted_contact", "request_id": request_id,
        "message": f"I have asked {contact} to approve this. Nothing is paid unless {contact} approves, "
                   f"and even then there is a {cool} waiting period before any money moves.",
    }
