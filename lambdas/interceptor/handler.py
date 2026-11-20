"""AgentCore Gateway interceptor (REQUEST and RESPONSE), layers L3 and L5.

REQUEST: for `tools/call`, overwrite `arguments["_session_id"]` with the session id
from the trusted HTTP `baggage` header. Nothing else is changed (this runs before
Cedar). Lifecycle calls (initialize, tools/list, ping, notifications) pass through.

RESPONSE: scan the free-text fields of a tool result for instructions (R7), hide
flagged text, mask long digit runs (R8), and write receipts. A Cedar deny
(JSON-RPC error -32002) gets a "policy" receipt and passes through.

Guardrail choice: if the ApplyGuardrail call fails, the fields are treated as
NOT flagged by the guardrail (the deterministic textscan still applies) and only
the error type is logged. The deterministic scan and the tool Lambda's own checks
stay in force either way.
"""
import functools
import json
import os
import re

from trustedhand import config, hashing, receipts, sessions, textscan

HIDDEN = "[hidden by TrustedHand: this text looked like instructions, not bill data]"
FREE_TEXT_KEYS = {"memo", "biller", "name", "payee_name", "reason", "message"}
# A top-level result with one of these statuses was written by our own tool code,
# so its top-level `message` is not scanned (refusal text often says "pay ... ₹").
TOOL_AUTHORED_STATUSES = {"refused", "error", "sent_to_trusted_contact", "paid"}
POLICY_DENY_CODE = -32002
DIGITS_RE = re.compile(r"(?<![A-Za-z0-9])\d{9,}(?![A-Za-z0-9])")
MAX_FIELD_CHARS = 2000


# ---------------------------------------------------------------- helpers

def _log(**kw):
    print(json.dumps(kw, default=str))


def _as_obj(body):
    if isinstance(body, (str, bytes)):
        try:
            return json.loads(body)
        except ValueError:
            return body
    return body


def _header(headers, name):
    for k, v in (headers or {}).items():
        if str(k).lower() == name:
            return v[0] if isinstance(v, list) and v else v
    return None


def _session_from_headers(headers):
    sid = sessions.parse_baggage(_header(headers, "baggage")).get("session.id")
    return sid if isinstance(sid, str) and 0 < len(sid) <= 200 else None


def _short(tool):
    return str(tool or "").split("___", 1)[-1] or None


def _passthrough_request(body):
    return {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": body}}}


def _response(status, body):
    out = {"statusCode": status}
    if body is not None:
        out["body"] = body
    return {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayResponse": out}}


def _error_result(msg_id, text):
    return _response(200, {
        "jsonrpc": "2.0", "id": msg_id,
        "result": {"isError": True, "content": [{"type": "text", "text": text}]},
    })


# ---------------------------------------------------------------- REQUEST

def _on_request(req):
    body = _as_obj(req.get("body"))
    msgs = body if isinstance(body, list) else [body]
    calls = [m for m in msgs if isinstance(m, dict) and m.get("method") == "tools/call"]
    if not calls:
        method = body.get("method") if isinstance(body, dict) else "batch/other"
        _log(stage="request", method=method, decision="pass")
        return _passthrough_request(req.get("body"))

    first_id = calls[0].get("id")
    session = _session_from_headers(req.get("headers"))
    if not session:
        _log(stage="request", method="tools/call", decision="block", why="no_session")
        return _error_result(first_id, "I could not tell which chat this request belongs to, so I did not do it. Nothing was paid.")
    for m in calls:
        params = m.get("params")
        if not isinstance(params, dict):
            return _error_result(m.get("id"), "That request was not in a form I can safely handle. Nothing was done.")
        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return _error_result(m.get("id"), "That request was not in a form I can safely handle. Nothing was done.")
        args["_session_id"] = session  # overwrite anything the model sent
        params["arguments"] = args
        _log(stage="request", method="tools/call", tool=_short(params.get("name")), decision="inject_session")
    return _passthrough_request(body)


# ---------------------------------------------------------------- RESPONSE

@functools.lru_cache(maxsize=None)
def _guardrail_client():
    import boto3
    return boto3.client("bedrock-runtime")


def _walk(node, in_free, out, root=None):
    """Collect (parent, key) pairs holding free text strings."""
    if isinstance(node, dict):
        for k, v in node.items():
            free = in_free or k in FREE_TEXT_KEYS
            if node is root and k == "message" and node.get("status") in TOOL_AUTHORED_STATUSES:
                free = in_free
            if isinstance(v, str):
                if free and v.strip():
                    out.append((node, k))
            else:
                _walk(v, free, out, root)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                if in_free and v.strip():
                    out.append((node, i))
            else:
                _walk(v, in_free, out, root)


def _mask_digits(node):
    """Mask 9+ digit runs in every string. Returns True if anything changed."""
    changed = False
    items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()
    for k, v in list(items):
        if isinstance(v, str):
            new = DIGITS_RE.sub(lambda m: hashing.mask_account(m.group(0)), v)
            if new != v:
                node[k] = new
                changed = True
        elif isinstance(v, (dict, list)):
            changed = _mask_digits(v) or changed
    return changed


def _guardrail_intervened(text):
    r = _guardrail_client().apply_guardrail(
        guardrailIdentifier=config.env("GUARDRAIL_ID"),
        guardrailVersion=config.env("GUARDRAIL_VERSION"),
        source="INPUT",
        content=[{"text": {"text": text}}],
    )
    return r.get("action") == "GUARDRAIL_INTERVENED"


def _guardrail_flags(values):
    """Return the set of indexes the guardrail flagged. One call for the whole
    result; only if it intervenes do we check field by field to find which."""
    if not (config.env("GUARDRAIL_ID") and config.env("GUARDRAIL_VERSION")) or not values:
        return set()
    lines = [f"{i + 1}. " + " ".join(v[:MAX_FIELD_CHARS].split()) for i, v in enumerate(values)]
    try:
        if not _guardrail_intervened("\n".join(lines)):
            return set()
        if len(values) == 1:
            return {0}
        return {i for i, v in enumerate(values) if _guardrail_intervened(v[:MAX_FIELD_CHARS])}
    except Exception as e:  # see module docstring: guardrail errors mean "not flagged"
        _log(stage="response", guardrail_error=type(e).__name__)
        return set()


def _scan_text(item, tool, session, household):
    """Scan and clean one text content item in place."""
    text = item["text"]
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, (dict, list)):
        data = None
    root = data if data is not None else {"text": text}

    cands = []
    if data is not None:
        _walk(data, False, cands, data)
    else:
        cands.append((root, "text"))

    changed = False
    if os.environ.get("TH_ABLATE_SCAN") != "1":
        flagged = {}  # candidate index -> reasons
        for i, (parent, key) in enumerate(cands):
            hits = textscan.find_injection(parent[key])
            if hits:
                flagged[i] = hits
        rest = [i for i in range(len(cands)) if i not in flagged]
        for j in _guardrail_flags([cands[i][0][cands[i][1]] for i in rest]):
            flagged[rest[j]] = ["guardrail"]
        for i, reasons in sorted(flagged.items()):
            parent, key = cands[i]
            ident = parent.get("bill_id") or parent.get("payee_id") or "" if isinstance(parent, dict) else ""
            field = key if isinstance(key, str) else "text"
            parent[key] = HIDDEN
            changed = True
            receipts.write(
                household, "interceptor", "flag",
                f"Hid text in '{field}'{' of ' + str(ident) if ident else ''} from {tool or 'a tool'}: looked like instructions ({', '.join(reasons)}).",
                rule="R7", tool=tool, session_id=session)
            _log(stage="response", tool=tool, decision="hide", field=field, why=reasons)

    if _mask_digits(root):
        changed = True
    if changed:
        item["text"] = root["text"] if data is None else json.dumps(data, ensure_ascii=False)


def _process_message(m, tool, session, household_getter):
    """Handle one JSON-RPC response message. Returns the (maybe changed) message."""
    if not isinstance(m, dict):
        return m
    err = m.get("error")
    if isinstance(err, dict) and err.get("code") == POLICY_DENY_CODE:
        receipts.write(household_getter(), "policy", "deny",
                       f"Policy blocked the call to {tool or 'a tool'}.",
                       tool=tool, session_id=session)
        _log(stage="response", tool=tool, decision="policy_deny")
        return m
    result = m.get("result")
    content = result.get("content") if isinstance(result, dict) else None
    if not isinstance(content, list):
        return m
    for item in content:
        if not (isinstance(item, dict) and isinstance(item.get("text"), str)):
            continue
        if result.get("isError") and "Tool Execution Denied" in item["text"]:
            receipts.write(household_getter(), "policy", "deny",
                           f"Policy blocked the call to {tool or 'a tool'}.",
                           tool=tool, session_id=session)
            _log(stage="response", tool=tool, decision="policy_deny")
            continue
        _scan_text(item, tool, session, household_getter())
    _log(stage="response", tool=tool, decision="scanned")
    return m


def _on_response(req, resp):
    status = resp.get("statusCode", 200)
    body = _as_obj(resp.get("body"))
    if not body:
        return _response(status, None)

    req_body = _as_obj(req.get("body"))
    session = _session_from_headers(req.get("headers"))
    cache = {}

    def household():
        if "h" not in cache:
            try:
                cache["h"] = sessions.household_for_session(session) if session else None
            except Exception as e:
                _log(stage="response", household_error=type(e).__name__)
                cache["h"] = None
        return cache["h"]

    req_msgs = req_body if isinstance(req_body, list) else [req_body]
    by_id = {m.get("id"): m for m in req_msgs if isinstance(m, dict) and m.get("id") is not None}

    def one(m):
        if not isinstance(m, dict):
            return m
        r = by_id.get(m.get("id")) or (req_body if isinstance(req_body, dict) else None)
        method = r.get("method") if isinstance(r, dict) else None
        if method not in (None, "tools/call"):
            return m  # lifecycle / tools/list: untouched
        tool = _short(((r or {}).get("params") or {}).get("name")) if isinstance(r, dict) else None
        try:
            return _process_message(m, tool, session, household)
        except Exception as e:
            # Could not check the result: do not hand it to the model unchecked.
            _log(stage="response", tool=tool, decision="error", error=type(e).__name__)
            return {"jsonrpc": "2.0", "id": m.get("id"), "result": {"isError": True, "content": [
                {"type": "text", "text": "I could not safely check the answer from the bank tool, so I am not showing it. Nothing was paid."}]}}

    out = [one(m) for m in body] if isinstance(body, list) else one(body)
    return _response(status, out)


def handler(event, context):
    mcp = (event or {}).get("mcp") or {}
    req = mcp.get("gatewayRequest") or {}
    resp = mcp.get("gatewayResponse")
    if resp:  # truthiness: the key may exist with value null on REQUEST
        return _on_response(req, resp)
    try:
        return _on_request(req)
    except Exception as e:
        _log(stage="request", decision="error", error=type(e).__name__)
        body = _as_obj(req.get("body"))
        if isinstance(body, dict) and body.get("method") == "tools/call":
            return _error_result(body.get("id"), "I could not safely prepare that request, so I did not do it. Nothing was paid.")
        return _passthrough_request(req.get("body"))
