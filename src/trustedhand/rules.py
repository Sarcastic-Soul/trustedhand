"""Pure rule checks for the tool Lambda. No I/O.

Every check returns None (ok) or a refusal dict:
    {"status": "refused", "rule": "R..", "message": "<plain English>"}
Inputs are plain dicts. Numbers may be int or Decimal (from boto3 resources).
The messages are written for an older person to read.
"""
import datetime
import re

from . import config

MAX_BILL_ID = 64
MAX_PAYEE_NAME = 60
MAX_ACCOUNT = 64
MAX_REASON = 200

_UPI_RE = re.compile(r"^[A-Za-z0-9._\-]{2,64}@[A-Za-z][A-Za-z0-9.\-]{1,63}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def inr(n):
    """Format rupees with Indian digit grouping: 250000 -> '₹2,50,000'."""
    n = int(n)
    sign = "-" if n < 0 else ""
    s = str(abs(n))
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        parts = []
        while len(head) > 2:
            parts.insert(0, head[-2:])
            head = head[:-2]
        if head:
            parts.insert(0, head)
        s = ",".join(parts) + "," + tail
    return f"{sign}₹{s}"


def refuse(rule, message):
    return {"status": "refused", "rule": rule, "message": message}


def limits_of(household):
    """Household limits with defaults filled in, all ints."""
    raw = (household or {}).get("limits") or {}
    return {k: int(raw.get(k, v)) for k, v in config.DEFAULT_LIMITS.items()}


def duration_text(seconds):
    seconds = int(seconds)
    if seconds >= 3600 and seconds % 3600 == 0:
        h = seconds // 3600
        return f"{h} hour" + ("s" if h != 1 else "")
    if seconds >= 60:
        m = round(seconds / 60)
        return f"{m} minute" + ("s" if m != 1 else "")
    return f"{seconds} seconds"


# ---------------------------------------------------------------- input checks

def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def check_amount(amount):
    if not _is_int(amount) or amount <= 0:
        return refuse("INPUT", "The amount must be a whole number of rupees, more than zero.")
    return None


def validate_pay_input(bill_id, amount_inr):
    if not isinstance(bill_id, str) or not bill_id.strip() or len(bill_id) > MAX_BILL_ID:
        return refuse("INPUT", "I need a valid bill from your bill list.")
    return check_amount(amount_inr)


def normalize_account(account):
    """Return the cleaned account string, or None if the format is not valid.

    UPI ID: name@bank. Bank account: 9 to 18 digits (spaces removed).
    """
    if not isinstance(account, str) or len(account) > MAX_ACCOUNT or _CTRL_RE.search(account):
        return None
    a = account.strip()
    if "@" in a:
        return a if len(a) <= MAX_ACCOUNT and _UPI_RE.match(a) else None
    digits = re.sub(r"\s+", "", a)
    if digits.isascii() and digits.isdigit() and 9 <= len(digits) <= 18:
        return digits
    return None


def validate_request_input(payee_name, account, amount_inr, reason):
    """Return (refusal_or_None, cleaned) where cleaned has payee_name, account, reason."""
    if not isinstance(payee_name, str) or not payee_name.strip() or len(payee_name.strip()) > MAX_PAYEE_NAME \
            or _CTRL_RE.search(payee_name):
        return refuse("INPUT", f"The payee name must be 1 to {MAX_PAYEE_NAME} characters."), None
    if not isinstance(account, str) or len(account) > MAX_ACCOUNT:
        return refuse("INPUT", "That account does not look right. Use a UPI ID or a bank account number."), None
    acct = normalize_account(account)
    if acct is None:
        return refuse("INPUT", "That account does not look right. Use a UPI ID like name@bank, "
                               "or a bank account number of 9 to 18 digits."), None
    bad = check_amount(amount_inr)
    if bad:
        return bad, None
    if amount_inr > config.REQUEST_MAX_AMOUNT:
        return refuse("R3", f"I can only ask for approval of up to {inr(config.REQUEST_MAX_AMOUNT)} at a time."), None
    if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_REASON:
        return refuse("INPUT", f"Please give a short reason, up to {MAX_REASON} characters."), None
    return None, {"payee_name": payee_name.strip(), "account": acct, "reason": reason.strip()}


# ---------------------------------------------------------------- rule checks

def is_frozen(household, now):
    fu = (household or {}).get("frozen_until")
    return fu is not None and int(fu) > int(now)


def _contact(household):
    return (household or {}).get("contact_name") or "your trusted contact"


def check_bill_exists(bill):
    if not bill:
        return refuse("R1", "That bill is not on your bill list, so I cannot pay it.")
    return None


def check_not_paid(bill):  # R5
    if bill.get("status") != "unpaid":
        return refuse("R5", "This bill has already been paid. I will not pay it twice.")
    return None


def check_payee_approved(payee):  # R1
    if not payee:
        return refuse("R1", "This payee is not on your approved list, so I cannot pay them.")
    return None


_IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


def ist(epoch):
    """Human time in India for messages, e.g. '19 Nov, 10:17 PM IST'."""
    t = datetime.datetime.fromtimestamp(int(epoch), _IST)
    return f"{t.day} {t.strftime('%b')}, {t.strftime('%I:%M %p').lstrip('0')} IST"


def check_cooloff(payee, now):  # R6
    uf = int(payee.get("usable_from") or 0)
    if uf > int(now):
        mins = max(1, (uf - int(now) + 59) // 60)
        return refuse("R6", "This payee was added only recently. For your safety there is a waiting period. "
                            f"They can be paid from {ist(uf)} (about {mins} minute{'s' if mins != 1 else ''} from now).")
    return None


def check_amount_vs_due(bill, amount):  # R2
    due = int(bill.get("amount_due_inr") or 0)
    if amount != due:
        # Exact amount only. A partial payment would close the bill (R5) while most of it
        # is still owed, so "pay ₹1 on every bill" would leave real bills unpaid.
        return refuse("R2", f"The amount due on this bill is {inr(due)}. I can only pay exactly that amount.")
    return None


_AMOUNT_RES = (
    re.compile(r"(?:₹|\brs\.?|\binr)\s*([0-9][0-9,]*)(?:\.[0-9]+)?", re.I),
    re.compile(r"\b([0-9][0-9,]*)(?:\.[0-9]+)?\s*(?:/-|rupees?\b|rs\b)", re.I),
)
MAX_ASKED = 10


def asked_amounts(text):
    """Rupee amounts the user named in a message, e.g. 'Pay Rs.12,000' -> [12000].

    Only numbers with a rupee marker count, so bill ids, dates and phone numbers are ignored.
    """
    found = []
    for rx in _AMOUNT_RES:
        for m in rx.finditer(text or ""):
            digits = m.group(1).replace(",", "")
            if digits.isdigit() and len(digits) <= 9:
                n = int(digits)
                if n > 0 and n not in found:
                    found.append(n)
    return found[:MAX_ASKED]


def check_asked_amount(bill, amount, asked):  # R2 / E7
    """If the user named amounts this turn, only those can be paid.

    Stops the model from quietly paying the amount due when the user asked for a
    different amount: it must tell her and let her confirm in her own words.
    """
    asked = [int(a) for a in (asked or [])]
    if asked and int(amount) not in asked:
        due = int(bill.get("amount_due_inr") or 0)
        named = ", ".join(inr(a) for a in asked)
        return refuse("R2", f"You asked to pay {named}, but the amount due on this bill is {inr(due)}. "
                            f"Nothing was paid. If you want to pay {inr(due)}, please say so.")
    return None


def check_per_payment(household, amount):  # R3
    lim = limits_of(household)["per_payment"]
    if amount > lim:
        return refuse("R3", f"One payment can be at most {inr(lim)}. This one is {inr(amount)}.")
    return None


def check_daily(household, amount, spent_today=0, count_today=0):  # R4
    lim = limits_of(household)
    if int(count_today) >= lim["daily_count"]:
        return refuse("R4", f"I can make at most {lim['daily_count']} payments in one day, "
                            "and that number is reached for today.")
    if int(spent_today) + amount > lim["daily"]:
        left = max(lim["daily"] - int(spent_today), 0)
        return refuse("R4", f"This would go over today's limit of {inr(lim['daily'])}. "
                            f"You can still pay up to {inr(left)} today.")
    return None


def check_freeze_for_transfer(household, bill, now):  # R9
    if bill.get("kind") == "transfer" and is_frozen(household, now):
        return refuse("R9", "Transfers are paused because this chat looked like a known scam. "
                            f"{_contact(household)} has been told. Your regular bills can still be paid.")
    return None


def check_freeze_for_request(household, now):  # R9
    if is_frozen(household, now):
        return refuse("R9", "Adding new payees is paused because this chat looked like a known scam. "
                            f"{_contact(household)} has been told. Your regular bills can still be paid.")
    return None


def check_pending_requests(pending_count):
    if int(pending_count) >= config.MAX_PENDING_REQUESTS:
        return refuse("R6", "There are already requests waiting for approval. "
                            "Please wait for them to be answered first.")
    return None


def check_pay(household, bill, payee, amount, now, day=None, asked=None):
    """Run every pre-transaction pay rule in a fixed order. First refusal wins.

    `day` is {"spent_inr", "count"} for today (or None for nothing spent).
    `asked` is the list of rupee amounts the user named this turn (None or empty: no limit).
    The DynamoDB transaction re-checks R4 and R5 atomically; this pass gives
    clean messages and stops obvious cases early.
    """
    day = day or {}
    return (
        check_bill_exists(bill)
        or check_not_paid(bill)
        or check_freeze_for_transfer(household, bill, now)
        or check_payee_approved(payee)
        or check_cooloff(payee, now)
        or check_per_payment(household, amount)
        or check_daily(household, amount, day.get("spent_inr", 0), day.get("count", 0))
        or check_amount_vs_due(bill, amount)
        or check_asked_amount(bill, amount, asked)
    )
