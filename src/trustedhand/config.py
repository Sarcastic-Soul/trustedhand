"""Settings read from the environment, plus default limits."""
import os

DEFAULT_LIMITS = {
    "per_payment": 10000,   # R3, rupees
    "daily": 25000,         # R4, rupees
    "daily_count": 5,       # R4, payments per day
    "cooloff_s": 86400,     # R6, new payee cool-off
    "freeze_s": 86400,      # R9, freeze length after scam signs
}
DEMO_LIMITS = {**DEFAULT_LIMITS, "cooloff_s": 120, "freeze_s": 600}

REQUEST_MAX_AMOUNT = 50000      # request_new_payee upper bound (also in Cedar)
MAX_PENDING_REQUESTS = 3
REQUEST_TTL_S = 72 * 3600       # E3
STRIKE_LIMIT = 3                # R12
STRIKE_LOCK_S = 1800            # R12
DEMO_TTL_S = 48 * 3600


def env(name, default=None):
    return os.environ.get(name, default)


def table(name):
    return env("TABLE_PREFIX", "th-") + name
