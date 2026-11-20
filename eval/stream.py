"""Parse the InvokeHarness event stream into a plain dict.

Follows the parser that worked in spikes/day1/spike.py `invoke()`:
  contentBlockStart.start.toolUse    -> a tool call begins (name, toolUseId)
  contentBlockStart.start.toolResult -> a tool result begins (toolUseId, status)
  contentBlockDelta.delta.text       -> assistant text
  contentBlockDelta.delta.toolUse    -> tool input JSON text, in pieces
  contentBlockDelta.delta.toolResult -> tool result content, in pieces
  hookEvent, messageStop, and the exception members.
"""
import json

KNOWN = {"messageStart", "contentBlockStart", "contentBlockDelta", "contentBlockStop", "messageStop", "metadata", "hookEvent"}
THROTTLE_WORDS = ("throttl", "rate exceeded", "too many requests", "serviceunavailable", "service unavailable", "limit exceeded")


def _texts(node):
    """Collect every text-like string inside a toolResult delta, whatever its nesting."""
    out = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for k, v in node.items():
            if k in ("text", "json") and isinstance(v, (str, int, float)):
                out.append(str(v))
            elif k == "json":
                out.append(json.dumps(v))
            else:
                out.extend(_texts(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_texts(v))
    return out


def _loads(s):
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return None


def parse_stream(events):
    text, calls, hooks, errors = [], [], [], []
    by_id, by_index = {}, {}
    stop = None
    last_call = None
    for ev in events:
        if "contentBlockStart" in ev:
            cb = ev["contentBlockStart"]
            start = cb.get("start") or {}
            idx = cb.get("contentBlockIndex")
            if "toolUse" in start:
                tu = start["toolUse"]
                call = {"id": tu.get("toolUseId"), "tool": tu.get("name"), "input_raw": "", "result_raw": "", "status": None}
                calls.append(call)
                last_call = call
                if call["id"]:
                    by_id[call["id"]] = call
                by_index[idx] = ("use", call)
            elif "toolResult" in start:
                tr = start["toolResult"]
                call = by_id.get(tr.get("toolUseId"))
                if call is None:  # fall back to the oldest call with no result yet
                    call = next((c for c in calls if c["status"] is None and not c["result_raw"]), None)
                if call is not None:
                    call["status"] = tr.get("status") or "unknown"
                by_index[idx] = ("result", call)
        elif "contentBlockDelta" in ev:
            cb = ev["contentBlockDelta"]
            d = cb.get("delta") or {}
            kind, call = by_index.get(cb.get("contentBlockIndex"), (None, None))
            if "text" in d and isinstance(d["text"], str):
                text.append(d["text"])
            if "toolUse" in d:
                target = call if kind == "use" and call is not None else last_call
                if target is not None:
                    target["input_raw"] += d["toolUse"].get("input", "") or ""
            if "toolResult" in d:
                target = call if kind == "result" and call is not None else next(
                    (c for c in reversed(calls) if c["status"] is not None), last_call)
                if target is not None:
                    target["result_raw"] += "".join(_texts(d["toolResult"]))
        elif "hookEvent" in ev:
            hooks.append(ev["hookEvent"])
        elif "messageStop" in ev:
            stop = ev["messageStop"].get("stopReason")
        else:
            for k, v in ev.items():
                if k not in KNOWN and (k.endswith("Exception") or k == "runtimeClientError"):
                    errors.append({"type": k, "message": json.dumps(v, default=str)[:500]})
    for c in calls:
        c["input"] = _loads(c["input_raw"]) if c["input_raw"] else {}
        c["result"] = _loads(c["result_raw"]) if c["result_raw"] else None
        c["input_raw"] = c["input_raw"][:2000]
        c["result_raw"] = c["result_raw"][:3000]
    return {"text": "".join(text).strip(), "tool_calls": calls, "hooks": hooks, "stop_reason": stop, "errors": errors}


def is_throttle(message):
    m = str(message).lower()
    return any(w in m for w in THROTTLE_WORDS)
