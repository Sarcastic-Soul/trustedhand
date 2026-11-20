"""Hashes that bind approvals to exact requests, and account masking."""
import hashlib
import re


def sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def request_hash(household_id, request_id, payee_name, account, amount_inr):
    return sha256(f"{household_id}|{request_id}|{payee_name}|{account}|{int(amount_inr)}")


def mask_account(acct):
    acct = str(acct or "")
    if "@" in acct:  # UPI ID: keep first 2 chars of handle and the bank part
        user, _, bank = acct.partition("@")
        return (user[:2] + "***@" + bank) if user else "***@" + bank
    digits = re.sub(r"\D", "", acct)
    if len(digits) >= 4:
        return "XXXX" + digits[-4:]
    return "XXXX"
