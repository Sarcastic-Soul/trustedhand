"""Load and validate attack JSONL files."""
import json
import re

from . import common
from .checker import EXPECT_KEYS, bad_expect_keys

REQUIRED = ("id", "category", "turns", "tries", "targets", "expect")
INJECTION_CATEGORIES = {"indirect_injection", "injection_tool_format"}
REQUIRED_CATEGORIES = {
    "direct_override", "false_authority", "digital_arrest", "indirect_injection", "injection_tool_format",
    "limit_pushing", "bill_splitting", "duplicate_payment", "new_payee_coercion", "approval_forgery",
    "bait_and_switch", "freeze_bypass", "data_leakage", "tool_escape", "role_play", "bulk_action",
    "otp_sharing", "benign",
}
SETUP_KEYS = {"frozen"}


def validate_attack(a):
    """Return a list of problems (empty = valid)."""
    errs = []
    if not isinstance(a, dict):
        return ["not an object"]
    for k in REQUIRED:
        if k not in a:
            errs.append(f"missing {k}")
    if errs:
        return errs
    if not isinstance(a["id"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", a["id"]):
        errs.append("bad id")
    if not isinstance(a["category"], str) or not a["category"]:
        errs.append("bad category")
    t = a["turns"]
    if not (isinstance(t, list) and 1 <= len(t) <= 8 and all(isinstance(x, str) and x.strip() for x in t)):
        errs.append("turns must be 1-8 non-empty strings")
    elif any(len(x) > 1000 for x in t):
        errs.append("a turn is longer than 1000 chars")
    if not isinstance(a["tries"], str) or not a["tries"].strip():
        errs.append("bad tries")
    if not (isinstance(a["targets"], list) and all(isinstance(x, str) for x in a["targets"])):
        errs.append("targets must be a list of strings")
    ex = a["expect"]
    if not isinstance(ex, dict):
        errs.append("expect must be an object")
    else:
        for k in ex:
            if k not in EXPECT_KEYS:
                errs.append(f"unknown expect key {k}")
        for k in bad_expect_keys({k: v for k, v in ex.items() if k in EXPECT_KEYS}):
            errs.append(f"wrong value type for expect key {k}")
        for k in ("reply_must_not_contain", "reply_must_contain"):
            for pat in ex.get(k, []) or []:
                try:
                    re.compile(pat)
                except (re.error, TypeError):
                    errs.append(f"bad regex in {k}: {pat!r}")
    su = a.get("setup", {})
    if not isinstance(su, dict) or set(su) - SETUP_KEYS:
        errs.append("bad setup")
    return errs


def load_jsonl(path, validate=True):
    attacks = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        a = json.loads(line)
        if validate:
            errs = validate_attack(a)
            if errs:
                raise ValueError(f"{path.name}:{n} {a.get('id')}: {'; '.join(errs)}")
        attacks.append(a)
    return attacks


def load_set(name):
    """name: own | heldout | all. Each attack gets a `set` field."""
    out = []
    for n in ("own", "heldout"):
        if name in (n, "all"):
            p = common.ATTACKS / f"{n}.jsonl"
            if not p.exists():
                if name == "all":
                    continue
                raise FileNotFoundError(f"{p} not found (run eval/gen_heldout.py first for heldout)")
            for a in load_jsonl(p):
                out.append({**a, "set": n})
    ids = [a["id"] for a in out]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate attack ids across sets")
    return out
