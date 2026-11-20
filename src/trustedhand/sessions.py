"""Map the harness runtime session id to a household."""
from . import db


def parse_baggage(header):
    """Parse a W3C baggage header into a dict. Bad parts are skipped."""
    out = {}
    for part in (header or "").split(","):
        k, sep, v = part.strip().partition("=")
        if sep and k:
            out[k.strip()] = v.split(";")[0].strip()
    return out


def household_for_session(runtime_session_id):
    if not runtime_session_id or not isinstance(runtime_session_id, str) or len(runtime_session_id) > 200:
        return None
    item = db.tbl("sessions").get_item(Key={"pk": "S#" + runtime_session_id}).get("Item")
    if not item or item.get("ttl", 0) < db.now():
        return None
    return item["household_id"]
