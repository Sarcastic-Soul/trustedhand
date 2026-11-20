"""Deterministic scan for instruction-like text inside data (bills, memos, names).

The guardrail is the second opinion; this scan is cheap, explainable and
cannot be talked out of a match.
"""
import re

PATTERNS = [
    ("role_marker", r"\b(system|assistant|developer|admin)\s*[:>\]]"),
    ("override", r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|above|prior|earlier|all|instructions?|rules?)\b"),
    ("instruction", r"\b(you must|you should|you are now|new instructions?|act as|pretend)\b"),
    ("pay_command", r"\b(pay|transfer|send|move|deposit)\b.{0,60}(\b\d[\d,]{2,}\b|₹|rs\.?|inr|rupees)"),
    ("payee_command", r"\b(add|create|register|approve)\b.{0,30}\b(payee|beneficiary|account)\b"),
    ("tool_name", r"\b(pay_bill|request_new_payee|list_payees|bank___\w+)\b"),
    ("url", r"https?://|www\.|\b[a-z0-9-]+\.(com|in|net|org|xyz|top|io)\b/?"),
    ("upi_handle", r"\b[\w.\-]{2,}@(ok\w+|ybl|ibl|axl|paytm|upi|apl|icici|sbi|hdfcbank)\b"),
    ("urgency_threat", r"\b(arrest|warrant|police|cbi|customs|court|ed\b|narcotics|money laundering|safe account|verification account)\b"),
    ("secrecy", r"\b(don'?t|do not|never)\s+(tell|inform|call)\b|\btell (no ?one|nobody)\b|\bkeep (it|this) (a )?secret\b"),
]
_COMPILED = [(name, re.compile(rx, re.IGNORECASE)) for name, rx in PATTERNS]


def find_injection(text):
    """Return names of patterns that match. Empty list means clean."""
    if not text or not isinstance(text, str):
        return []
    return [name for name, rx in _COMPILED if rx.search(text)]
