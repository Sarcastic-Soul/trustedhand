import pytest

from trustedhand import config, rules

NOW = 1_800_000_000
HH = {"limits": dict(config.DEFAULT_LIMITS), "contact_name": "Ravi"}
BILL = {"status": "unpaid", "amount_due_inr": 1840, "payee_id": "bescom", "kind": "bill"}
PAYEE = {"payee_id": "bescom", "usable_from": 0}


def rule_of(r):
    return r["rule"] if r else None


def test_inr_grouping():
    assert rules.inr(1840) == "₹1,840"
    assert rules.inr(250000) == "₹2,50,000"
    assert rules.inr(25000) == "₹25,000"
    assert rules.inr(50) == "₹50"


def test_all_ok():
    assert rules.check_pay(HH, BILL, PAYEE, 1840, NOW) is None


def test_refusal_shape():
    r = rules.check_pay(HH, BILL, PAYEE, 1841, NOW)
    assert r["status"] == "refused" and r["rule"] == "R2" and "₹1,840" in r["message"]


def test_r1_missing_payee_and_bill():
    assert rule_of(rules.check_pay(HH, BILL, None, 100, NOW)) == "R1"
    assert rule_of(rules.check_pay(HH, None, PAYEE, 100, NOW)) == "R1"


def test_r2_over_due():
    assert rules.check_amount_vs_due(BILL, 1840) is None
    assert rule_of(rules.check_amount_vs_due(BILL, 1)) == "R2"  # no partial payments (E2)
    assert rule_of(rules.check_amount_vs_due(BILL, 1841)) == "R2"


def test_r3_per_payment():
    assert rules.check_pay(HH, {**BILL, "amount_due_inr": 10000}, PAYEE, 10000, NOW) is None
    assert rule_of(rules.check_pay(HH, {**BILL, "amount_due_inr": 10001}, PAYEE, 10001, NOW)) == "R3"


def test_r4_daily_total_and_count():
    assert rules.check_daily(HH, 1000, 24000, 2) is None
    assert rules.check_daily(HH, 1001, 24000, 2) is not None
    assert rule_of(rules.check_daily(HH, 1001, 24000, 2)) == "R4"
    assert rule_of(rules.check_daily(HH, 10, 0, 5)) == "R4"
    assert rules.check_daily(HH, 10, 0, 4) is None


def test_r5_paid():
    assert rule_of(rules.check_pay(HH, {**BILL, "status": "paid"}, PAYEE, 100, NOW)) == "R5"


def test_r6_cooloff_boundary():
    p = {"usable_from": NOW + 1}
    assert rule_of(rules.check_cooloff(p, NOW)) == "R6"
    assert rules.check_cooloff({"usable_from": NOW}, NOW) is None
    assert rules.check_cooloff({}, NOW) is None


def test_r9_freeze():
    frozen = {**HH, "frozen_until": NOW + 60}
    assert rules.is_frozen(frozen, NOW) and not rules.is_frozen(frozen, NOW + 60)
    assert rule_of(rules.check_freeze_for_request(frozen, NOW)) == "R9"
    assert rules.check_freeze_for_request(HH, NOW) is None
    assert rule_of(rules.check_pay(frozen, {**BILL, "kind": "transfer"}, PAYEE, 100, NOW)) == "R9"
    assert rules.check_pay(frozen, BILL, PAYEE, 1840, NOW) is None  # normal bills still payable


def test_limits_defaults_and_decimals():
    from decimal import Decimal
    h = {"limits": {"per_payment": Decimal(500)}}
    lim = rules.limits_of(h)
    assert lim["per_payment"] == 500 and lim["daily"] == 25000
    assert rule_of(rules.check_per_payment(h, 501)) == "R3"


def test_pending_cap():
    assert rules.check_pending_requests(config.MAX_PENDING_REQUESTS - 1) is None
    assert rule_of(rules.check_pending_requests(config.MAX_PENDING_REQUESTS)) == "R6"


@pytest.mark.parametrize("bill_id,amt", [
    (None, 5), (123, 5), ("", 5), ("x" * 65, 5), ("ok", 0), ("ok", -5), ("ok", 1.5), ("ok", "5"), ("ok", True), ("ok", None),
])
def test_pay_input_invalid(bill_id, amt):
    assert rule_of(rules.validate_pay_input(bill_id, amt)) == "INPUT"


def test_pay_input_valid():
    assert rules.validate_pay_input("x" * 64, 1) is None


@pytest.mark.parametrize("acct,ok", [
    ("ravi@okhdfcbank", True), ("a.b-c_d@ybl", True), ("301245678901", True), ("3012 4567 8901", True),
    ("12345678", False), ("1" * 19, False), ("1" * 18, True), ("abc", False), ("@ybl", False),
    ("a@", False), ("12345678a", False), ("x" * 65, False), ("12345\n6789", False), (None, False), (123456789, False),
])
def test_account_format(acct, ok):
    assert (rules.normalize_account(acct) is not None) == ok


def test_normalize_removes_spaces():
    assert rules.normalize_account("3012 4567 8901") == "301245678901"


def test_request_validation():
    ok, clean = rules.validate_request_input("  Shop  ", "ravi@ybl", 500, " rent ")
    assert ok is None and clean == {"payee_name": "Shop", "account": "ravi@ybl", "reason": "rent"}
    assert rule_of(rules.validate_request_input("", "ravi@ybl", 500, "r")[0]) == "INPUT"
    assert rule_of(rules.validate_request_input("x" * 61, "ravi@ybl", 500, "r")[0]) == "INPUT"
    assert rules.validate_request_input("x" * 60, "ravi@ybl", 500, "r")[0] is None
    assert rule_of(rules.validate_request_input("A", "bad", 500, "r")[0]) == "INPUT"
    assert rule_of(rules.validate_request_input("A", "ravi@ybl", 0, "r")[0]) == "INPUT"
    assert rule_of(rules.validate_request_input("A", "ravi@ybl", 500, "")[0]) == "INPUT"
    assert rule_of(rules.validate_request_input("A", "ravi@ybl", 500, "r" * 201)[0]) == "INPUT"
    assert rules.validate_request_input("A", "ravi@ybl", 500, "r" * 200)[0] is None
    assert rules.validate_request_input("A", "ravi@ybl", config.REQUEST_MAX_AMOUNT, "r")[0] is None
    assert rule_of(rules.validate_request_input("A", "ravi@ybl", config.REQUEST_MAX_AMOUNT + 1, "r")[0]) == "R3"
    assert rule_of(rules.validate_request_input("A\nB", "ravi@ybl", 5, "r")[0]) == "INPUT"


def test_ist_format_and_r6_says_when():
    from trustedhand import rules
    assert rules.ist(0) == "1 Jan, 5:30 AM IST"
    r = rules.check_cooloff({"usable_from": 1000 + 120}, 1000)
    assert r["rule"] == "R6" and "about 2 minutes" in r["message"] and "IST" in r["message"]


@pytest.mark.parametrize("text,want", [
    ("Please pay Rs.12,000 to Indane", [12000]),
    ("Pay ₹10,001 to Apollo Pharmacy.", [10001]),
    ("pay 500 rupees and INR 20 and 1,840/-", [20, 500, 1840]),
    ("Pay bill-bescom-2 for 2026-12-01, call 9876543210", []),
    ("pay the BESCOM bill", []),
    ("₹0 and Rs 99.50", [99]),
])
def test_asked_amounts(text, want):
    assert sorted(rules.asked_amounts(text)) == sorted(want)


def test_check_asked_amount():
    assert rules.check_asked_amount(BILL, 1840, None) is None
    assert rules.check_asked_amount(BILL, 1840, [1840]) is None
    r = rules.check_asked_amount(BILL, 1840, [905])
    assert r["rule"] == "R2" and "₹905" in r["message"] and "₹1,840" in r["message"]
    assert rule_of(rules.check_pay(HH, BILL, PAYEE, 1840, NOW, asked=[12000])) == "R2"
