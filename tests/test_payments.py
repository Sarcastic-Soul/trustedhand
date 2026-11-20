import threading

import boto3
import pytest

from trustedhand import config, db, hashing, payments, receipts, seeds

NOW = 1_800_000_000
HH = "hh-test"
SESS = HH + "-" + "a" * 32


def setup_hh(limits=None, *, frozen=False, n_extra_bills=0, demo=True):
    lim = limits or config.DEFAULT_LIMITS
    if demo:
        seeds.create_demo_household(HH, NOW)
        db.tbl("households").update_item(
            Key={"household_id": HH}, UpdateExpression="SET limits = :l",
            ExpressionAttributeValues={":l": dict(lim)})
    else:
        seeds.create_household(HH, NOW, demo=False, limits=lim)
    if frozen:
        freeze()
    return HH


def freeze(until=NOW + 600):
    db.tbl("households").update_item(
        Key={"household_id": HH}, UpdateExpression="SET frozen_until = :f", ExpressionAttributeValues={":f": until})


def add_bill(bill_id, payee_id="bescom", amount=1000, kind="bill", status="unpaid"):
    db.tbl("bills").put_item(Item={
        "household_id": HH, "bill_id": bill_id, "biller": bill_id, "payee_id": payee_id,
        "amount_due_inr": amount, "due_date": "2026-12-01", "status": status, "memo": "", "kind": kind})


def add_payee(payee_id, usable_from=0, account="newguy@ybl"):
    db.tbl("payees").put_item(Item={
        "household_id": HH, "payee_id": payee_id, "name": payee_id, "account": account,
        "account_masked": hashing.mask_account(account), "usable_from": usable_from, "source": "approval"})


def day_row():
    item = db.tbl("ledger").get_item(Key={"household_id": HH, "sk": "DAY#" + db.today_ist(NOW)}).get("Item") or {}
    return int(item.get("spent_inr", 0)), int(item.get("count", 0))


def bill_status(b):
    return db.tbl("bills").get_item(Key={"household_id": HH, "bill_id": b})["Item"]["status"]


def pay(bill_id, amount, now=NOW):
    return payments.pay(HH, SESS, bill_id, amount, now)


def last_receipt():
    return receipts.recent(HH, 1)[-1]


# ------------------------------------------------------------------ happy path

def test_pay_ok(aws):
    setup_hh()
    r = pay("bill-bescom", 1840)
    assert r["status"] == "paid" and r["payment_id"].startswith("pay-")
    assert r["amount_inr"] == 1840 and r["spent_today_inr"] == 1840 and r["daily_limit_inr"] == 25000
    assert bill_status("bill-bescom") == "paid"
    assert day_row() == (1840, 1)
    rc = last_receipt()
    assert rc["layer"] == "tool" and rc["decision"] == "allow" and rc["session_id"] == SESS


def test_partial_payment_refused_then_full_then_r5(aws):
    setup_hh()
    r = pay("bill-bescom", 1)
    assert r["status"] == "refused" and r["rule"] == "R2"
    assert pay("bill-bescom", 1840)["status"] == "paid"
    r = pay("bill-bescom", 1840)
    assert r["status"] == "refused" and r["rule"] == "R5"


# ------------------------------------------------------------------ rules

def test_r1_unknown_bill(aws):
    setup_hh()
    r = pay("bill-rbi-safe-acct", 250000)
    assert r["rule"] == "R1"
    assert last_receipt()["decision"] == "deny" and last_receipt()["rule"] == "R1"


def test_r1_bill_with_unapproved_payee(aws):
    setup_hh()
    add_bill("b-ghost", payee_id="ghost")
    assert pay("b-ghost", 100)["rule"] == "R1"
    assert bill_status("b-ghost") == "unpaid"


def test_r1_other_household_bill_not_visible(aws):
    setup_hh()
    db.tbl("bills").put_item(Item={"household_id": "hh-other", "bill_id": "other-bill", "payee_id": "x",
                                   "amount_due_inr": 5, "status": "unpaid", "kind": "bill"})
    assert pay("other-bill", 5)["rule"] == "R1"


def test_r2_more_than_due(aws):
    setup_hh()
    r = pay("bill-bescom", 1841)
    assert r["rule"] == "R2" and "₹1,840" in r["message"]
    assert bill_status("bill-bescom") == "unpaid" and day_row() == (0, 0)


def test_r3_per_payment_limit(aws):
    setup_hh()
    add_bill("big", amount=10001)
    add_bill("max", amount=10000)
    assert pay("big", 10001)["rule"] == "R3"
    assert pay("max", 10000)["status"] == "paid"


def test_r3_limit_from_household(aws):
    setup_hh({**config.DEFAULT_LIMITS, "per_payment": 1000})
    assert pay("bill-bescom", 1001)["rule"] == "R3"


def test_r4_daily_cap_reached_exactly(aws):
    setup_hh({**config.DEFAULT_LIMITS, "daily": 3000, "per_payment": 3000})
    add_bill("a", amount=1000)
    add_bill("b", amount=1000)
    add_bill("c", amount=1000)
    add_bill("d", amount=1)
    for b in ("a", "b", "c"):
        assert pay(b, 1000)["status"] == "paid"
    assert day_row() == (3000, 3)
    r = pay("d", 1)
    assert r["rule"] == "R4"
    assert day_row() == (3000, 3) and bill_status("d") == "unpaid"


def test_r4_would_exceed(aws):
    setup_hh({**config.DEFAULT_LIMITS, "daily": 3000, "per_payment": 3000})
    add_bill("a", amount=2000)
    add_bill("b", amount=1000)
    assert pay("a", 2000)["status"] == "paid"
    r = pay("b", 1001)
    assert r["rule"] == "R4" and "₹1,000" in r["message"]
    assert pay("b", 1000)["status"] == "paid"


def test_r4_count_cap(aws):
    setup_hh()
    for i in range(6):
        add_bill(f"c{i}", amount=10)
    for i in range(5):
        assert pay(f"c{i}", 10)["status"] == "paid"
    r = pay("c5", 10)
    assert r["rule"] == "R4" and "5 payments" in r["message"]
    assert day_row() == (50, 5)


def test_r4_atomic_path_maps_to_r4(aws, monkeypatch):
    """Hide today's counters from the pre-check so the transaction itself must refuse."""
    setup_hh({**config.DEFAULT_LIMITS, "daily": 1000, "per_payment": 1000})
    add_bill("a", amount=1000)
    add_bill("b", amount=1000)
    assert pay("a", 1000)["status"] == "paid"
    real = payments._read_day
    calls = {"n": 0}

    def stale(household_id, day, consistent=True):
        calls["n"] += 1
        return {"spent_inr": 0, "count": 0} if calls["n"] == 1 else real(household_id, day, consistent)

    monkeypatch.setattr(payments, "_read_day", stale)
    r = pay("b", 1000)
    assert r["rule"] == "R4"
    assert bill_status("b") == "unpaid" and day_row() == (1000, 1)
    assert len(db.tbl("ledger").query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key("household_id").eq(HH)
        & boto3.dynamodb.conditions.Key("sk").begins_with("PAY#"))["Items"]) == 1


def test_r5_atomic_path_maps_to_r5(aws, monkeypatch):
    """Two payers pass the pre-check on the same bill; the transaction lets only one through."""
    setup_hh()
    real_get = payments._household  # untouched
    assert real_get(HH)
    orig = payments.rules.check_pay
    # Pre-check blind to status: simulate the race.
    monkeypatch.setattr(payments.rules, "check_pay", lambda *a, **k: None)
    assert pay("bill-bescom", 1840)["status"] == "paid"
    r = pay("bill-bescom", 1840)
    assert r["rule"] == "R5"
    assert day_row() == (1840, 1)  # the second attempt did not touch the day row
    payments.rules.check_pay = orig


def test_r6_cooloff_before_and_after(aws):
    setup_hh()
    add_payee("newguy", usable_from=NOW + 120)
    add_bill("nb", payee_id="newguy", amount=500)
    r = pay("nb", 500, now=NOW + 119)
    assert r["rule"] == "R6"
    assert bill_status("nb") == "unpaid"
    assert pay("nb", 500, now=NOW + 120)["status"] == "paid"


def test_r9_freeze_blocks_transfer_not_bill(aws):
    setup_hh(frozen=True)
    add_payee("friend")
    add_bill("tr", payee_id="friend", amount=500, kind="transfer")
    r = pay("tr", 500)
    assert r["rule"] == "R9"
    assert pay("bill-bescom", 1840)["status"] == "paid"
    # freeze over: transfer goes through
    assert pay("tr", 500, now=NOW + 601)["status"] == "paid"


def test_invalid_inputs(aws):
    setup_hh()
    for bill, amt in [("bill-bescom", 0), ("bill-bescom", -1), ("bill-bescom", 1.5), ("bill-bescom", "100"),
                      ("", 5), ("x" * 65, 5), (None, 5)]:
        assert pay(bill, amt)["rule"] == "INPUT"
    assert day_row() == (0, 0)


def test_unknown_household_is_error(aws):
    r = payments.pay("hh-nope", SESS, "b", 5, NOW)
    assert r["status"] == "error"


def test_rows_expire_with_demo_household(aws):
    setup_hh()
    pay("bill-bescom", 1840)
    item = db.tbl("ledger").get_item(Key={"household_id": HH, "sk": "DAY#" + db.today_ist(NOW)})["Item"]
    assert int(item["ttl"]) == NOW + config.DEMO_TTL_S


def test_non_demo_household_no_ttl(aws):
    setup_hh(demo=False)
    add_payee("p")
    add_bill("b", payee_id="p", amount=10)
    assert pay("b", 10)["status"] == "paid"
    item = db.tbl("ledger").get_item(Key={"household_id": HH, "sk": "DAY#" + db.today_ist(NOW)})["Item"]
    assert "ttl" not in item


# ------------------------------------------------------------------ reads

def test_list_bills_memo_returned_as_is(aws):
    setup_hh()
    bills = {b["bill_id"]: b for b in payments.list_bills(HH)["bills"]}
    assert len(bills) == 5
    assert bills["bill-bwssb"]["memo"] == seeds.INJECTED_MEMO
    assert "SYSTEM:" in bills["bill-bwssb"]["memo"] and "rbi-safe-acct" in bills["bill-bwssb"]["memo"]
    assert bills["bill-bescom"]["memo"].startswith("Meter reading 4521 kWh")
    assert set(bills["bill-bescom"]) == {"bill_id", "biller", "payee_id", "amount_due_inr", "due_date", "status", "memo"}
    assert isinstance(bills["bill-bescom"]["amount_due_inr"], int)


def test_list_payees_masked_only(aws):
    setup_hh()
    out = payments.list_payees(HH, NOW)
    assert {p["payee_id"] for p in out["payees"]} == {"bescom", "bwssb", "jio", "indane", "apollo"}
    blob = repr(out)
    for _, _, acct in seeds.PAYEES:
        assert acct not in blob
    for p in out["payees"]:
        assert set(p) == {"payee_id", "name", "account_masked", "usable_from"}
        assert p["account_masked"].startswith("XXXX") or "***@" in p["account_masked"]
        assert p["usable_from"] is None


def test_list_payees_usable_from_iso(aws):
    setup_hh()
    add_payee("newguy", usable_from=NOW + 100)
    p = [p for p in payments.list_payees(HH, NOW)["payees"] if p["payee_id"] == "newguy"][0]
    assert p["usable_from"] == db.iso(NOW + 100)


def test_status(aws):
    setup_hh()
    pay("bill-bescom", 1840)
    pay("bill-jio", 719)
    s = payments.status(HH, NOW)
    assert s["today"] == {"spent_inr": 2559, "count": 2, "daily_limit_inr": 25000, "count_limit": 5,
                          "per_payment_limit_inr": 10000}
    assert len(s["recent_payments"]) == 2 and s["pending_requests"] == [] and s["frozen_until"] is None
    assert {p["amount_inr"] for p in s["recent_payments"]} == {1840, 719}


def test_status_recent_max_5_and_freeze(aws):
    setup_hh({**config.DEFAULT_LIMITS, "daily_count": 50})
    for i in range(7):
        add_bill(f"x{i}", amount=10)
        pay(f"x{i}", 10, now=NOW + i)
    freeze(NOW + 1000)
    s = payments.status(HH, NOW + 10)
    assert len(s["recent_payments"]) == 5
    assert s["recent_payments"][0]["created_at"] == db.iso(NOW + 6)  # newest first
    assert s["frozen_until"] == db.iso(NOW + 1000)
    assert payments.status(HH, NOW + 2000)["frozen_until"] is None


# ------------------------------------------------------------------ request_payee

def req(**kw):
    a = dict(payee_name="New Shop", account="new.shop@okicici", amount_inr=2500, reason="Buy a gift")
    a.update(kw)
    return payments.request_payee(HH, SESS, a["payee_name"], a["account"], a["amount_inr"], a["reason"], NOW)


def test_request_ok(aws):
    setup_hh()
    r = req()
    assert r["status"] == "sent_to_trusted_contact" and r["request_id"].startswith("rq-")
    assert len(r["request_id"]) == 13 and "Ravi" in r["message"]
    item = db.tbl("requests").get_item(Key={"household_id": HH, "request_id": r["request_id"]})["Item"]
    assert item["status"] == "pending" and int(item["expires_at"]) == NOW + config.REQUEST_TTL_S
    assert item["request_hash"] == hashing.request_hash(HH, r["request_id"], "New Shop", "new.shop@okicici", 2500)
    assert item["account"] == "new.shop@okicici"  # stored in full, never returned
    assert "new.shop@okicici" not in repr(r)
    rc = last_receipt()
    assert rc["decision"] == "allow" and rc["rule"] == "R6" and "new.shop@okicici" not in rc["summary"]


def test_request_account_digits_normalised(aws):
    setup_hh()
    r = req(account="3012 4567 8901")
    item = db.tbl("requests").get_item(Key={"household_id": HH, "request_id": r["request_id"]})["Item"]
    assert item["account"] == "301245678901"


def test_request_refused_when_frozen(aws):
    setup_hh(frozen=True)
    r = req()
    assert r["rule"] == "R9"
    assert db.tbl("requests").scan()["Items"] == []
    assert last_receipt()["rule"] == "R9"


def test_request_pending_cap(aws):
    setup_hh()
    for _ in range(config.MAX_PENDING_REQUESTS):
        assert req()["status"] == "sent_to_trusted_contact"
    assert req()["status"] == "refused"
    assert len(db.tbl("requests").scan()["Items"]) == config.MAX_PENDING_REQUESTS


def test_request_pending_cap_ignores_decided_and_expired(aws):
    setup_hh()
    ids = [req()["request_id"] for _ in range(3)]
    db.tbl("requests").update_item(Key={"household_id": HH, "request_id": ids[0]},
                                   UpdateExpression="SET #s = :d", ExpressionAttributeNames={"#s": "status"},
                                   ExpressionAttributeValues={":d": "denied"})
    db.tbl("requests").update_item(Key={"household_id": HH, "request_id": ids[1]},
                                   UpdateExpression="SET expires_at = :e", ExpressionAttributeValues={":e": NOW - 1})
    assert req()["status"] == "sent_to_trusted_contact"


@pytest.mark.parametrize("kw", [
    dict(payee_name=""), dict(payee_name="x" * 61), dict(account="12345"), dict(account="x" * 65),
    dict(amount_inr=0), dict(amount_inr=-5), dict(amount_inr=1.5), dict(reason=""), dict(reason="r" * 201),
])
def test_request_invalid(aws, kw):
    setup_hh()
    assert req(**kw)["status"] == "refused"
    assert db.tbl("requests").scan()["Items"] == []


def test_request_amount_cap(aws):
    setup_hh()
    assert req(amount_inr=config.REQUEST_MAX_AMOUNT)["status"] == "sent_to_trusted_contact"
    assert req(amount_inr=config.REQUEST_MAX_AMOUNT + 1)["rule"] == "R3"


def test_status_shows_pending_masked(aws):
    setup_hh()
    rid = req()["request_id"]
    s = payments.status(HH, NOW)
    assert [p["request_id"] for p in s["pending_requests"]] == [rid]
    assert "new.shop@okicici" not in repr(s)
    assert s["pending_requests"][0]["account_masked"] == "ne***@okicici"
    assert payments.status(HH, NOW + config.REQUEST_TTL_S + 1)["pending_requests"] == []


# ------------------------------------------------------------------ concurrency

def _serialize_moto_calls():
    """moto's in-memory backend is not thread-safe, so run each AWS call under one lock.
    Calls from different threads still interleave between operations (read, then transaction),
    which is the race the transaction has to survive."""
    lock = threading.Lock()

    def acquire(**kw):
        lock.acquire()

    def release(**kw):
        if lock.locked():
            lock.release()

    for c in (db.client(), db.ddb().meta.client):
        c.meta.events.register("before-call.dynamodb", acquire)
        c.meta.events.register("after-call.dynamodb", release)
        c.meta.events.register("after-call-error.dynamodb", release)


def _run_threads(bill_ids, amount, now=NOW):
    _serialize_moto_calls()
    results = []
    lock = threading.Lock()
    start = threading.Barrier(len(bill_ids))

    def work(b):
        start.wait()
        try:
            r = payments.pay(HH, SESS, b, amount, now)
        except Exception as e:  # must not happen
            r = {"status": "crash", "error": type(e).__name__ + str(e)[:300]}
        with lock:
            results.append(r)

    ts = [threading.Thread(target=work, args=(b,)) for b in bill_ids]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return results


def _paid_rows():
    from boto3.dynamodb.conditions import Key
    return db.tbl("ledger").query(
        KeyConditionExpression=Key("household_id").eq(HH) & Key("sk").begins_with("PAY#"))["Items"]


def test_concurrent_count_cap(aws):
    setup_hh()
    ids = [f"t{i}" for i in range(30)]
    for b in ids:
        add_bill(b, amount=1000)
    res = _run_threads(ids, 1000)
    assert not [r for r in res if r["status"] == "crash"]
    paid = [r for r in res if r["status"] == "paid"]
    spent, count = day_row()
    assert count <= 5 and spent <= 25000
    assert len(paid) == count == len(_paid_rows())
    assert spent == sum(int(p["amount_inr"]) for p in _paid_rows())
    assert sum(1 for b in ids if bill_status(b) == "paid") == len(paid)
    for r in res:
        assert r["status"] in ("paid", "refused", "error")
        if r["status"] == "refused":
            assert r["rule"] == "R4"


def test_concurrent_daily_cap(aws):
    setup_hh({**config.DEFAULT_LIMITS, "daily_count": 100})
    ids = [f"t{i}" for i in range(30)]
    for b in ids:
        add_bill(b, amount=1000)
    res = _run_threads(ids, 1000)
    assert not [r for r in res if r["status"] == "crash"]
    paid = [r for r in res if r["status"] == "paid"]
    spent, count = day_row()
    assert spent <= 25000 and count <= 100
    assert len(paid) == count == len(_paid_rows()) and spent == 1000 * count
    assert sum(1 for b in ids if bill_status(b) == "paid") == len(paid)
    # With no conflicts reported as errors, the cap is hit exactly.
    if not [r for r in res if r["status"] == "error"]:
        assert spent == 25000


def test_concurrent_same_bill_pays_once(aws):
    setup_hh()
    res = _run_threads(["bill-bescom"] * 10, 1840)
    assert sum(1 for r in res if r["status"] == "paid") == 1
    assert day_row() == (1840, 1) and len(_paid_rows()) == 1


def set_asked(amounts):
    db.tbl("sessions").put_item(Item={"pk": "S#" + SESS, "household_id": HH, "ttl": NOW + 10**9,
                                      "asked_amounts": amounts})


def test_e7_amount_named_by_user_must_match(aws):
    setup_hh()
    add_bill("b1", amount=6500)
    set_asked([10001])  # "Pay ₹10,001 to Apollo": the model must not quietly pay ₹6,500
    r = pay("b1", 6500)
    assert r["status"] == "refused" and r["rule"] == "R2" and "₹10,001" in r["message"] and "₹6,500" in r["message"]
    assert bill_status("b1") == "unpaid"
    set_asked([])  # next turn, "yes, pay it"
    assert pay("b1", 6500)["status"] == "paid"


def test_e7_named_amount_that_matches_is_paid(aws):
    setup_hh()
    add_bill("b1", amount=1840)
    set_asked([1840, 1])
    assert pay("b1", 1840)["status"] == "paid"
