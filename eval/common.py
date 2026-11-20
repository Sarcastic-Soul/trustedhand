"""Shared helpers for the stress-test suite: paths, AWS session, infra discovery."""
import json
import pathlib
import sys
import time
from decimal import Decimal

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"
RESULTS = EVAL / "results"
ATTACKS = EVAL / "attacks"
REGION = "us-east-1"
DEFAULT_AWS_PROFILE = "sarcastic-soul"

for _p in (str(ROOT / "src"), str(ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def plain(x):
    """Turn DynamoDB Decimals and sets into plain JSON types."""
    if isinstance(x, Decimal):
        return int(x) if x == x.to_integral_value() else float(x)
    if isinstance(x, dict):
        return {k: plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [plain(v) for v in x]
    if isinstance(x, (set, frozenset)):
        return sorted(plain(v) for v in x)
    return x


def utc_stamp():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def aws_session(profile=DEFAULT_AWS_PROFILE, region=REGION):
    import boto3
    return boto3.Session(profile_name=profile, region_name=region)


def use_default_session(profile=DEFAULT_AWS_PROFILE, region=REGION):
    """Point trustedhand.db (which uses boto3's default session) at the admin profile."""
    import boto3
    boto3.setup_default_session(profile_name=profile, region_name=region)
    from trustedhand import db
    db.clear_caches()


def _first(d, *keys):
    for k in keys:
        if d.get(k):
            return d[k]
    return None


def load_infra(session=None, gateway_name="th-gateway"):
    """Find harness ARN, gateway id/url and policy engine. Reads infra/harness.json first,
    then looks the gateway up by name. Missing pieces stay None (callers check)."""
    info = {"harness_arn": None, "harness_id": None, "gateway_id": None, "gateway_url": None,
            "gateway_arn": None, "policy_engine_arn": None, "web_origin": None, "raw": {}}
    f = ROOT / "infra" / "harness.json"
    if f.exists():
        try:
            raw = json.loads(f.read_text())
        except ValueError:
            raw = {}
        info["raw"] = raw
        info["harness_arn"] = _first(raw, "harness_arn", "harnessArn", "arn")
        info["harness_id"] = _first(raw, "harness_id", "harnessId", "id")
        info["gateway_id"] = _first(raw, "gateway_id", "gatewayId")
        info["gateway_url"] = _first(raw, "gateway_url", "gatewayUrl")
        info["gateway_arn"] = _first(raw, "gateway_arn", "gatewayArn")
        info["policy_engine_arn"] = _first(raw, "policy_engine_arn", "policyEngineArn", "engine_arn")
        info["web_origin"] = _first(raw, "web_origin", "webOrigin")
    if session is not None and not (info["gateway_id"] and info["gateway_url"]):
        try:
            gw = find_gateway(session.client("bedrock-agentcore-control"), gateway_name, info["gateway_id"])
            info["gateway_id"] = gw.get("gatewayId")
            info["gateway_url"] = info["gateway_url"] or gw.get("gatewayUrl")
            info["gateway_arn"] = info["gateway_arn"] or gw.get("gatewayArn")
            pe = gw.get("policyEngineConfiguration") or {}
            info["policy_engine_arn"] = info["policy_engine_arn"] or pe.get("arn")
        except Exception as e:  # discovery is best effort
            info["discovery_error"] = f"{type(e).__name__}: {e}"
    return info


def find_gateway(ctl, name="th-gateway", gateway_id=None):
    if gateway_id:
        return ctl.get_gateway(gatewayIdentifier=gateway_id)
    token = None
    while True:
        kw = {"nextToken": token} if token else {}
        r = ctl.list_gateways(**kw)
        for g in r.get("items", []):
            if g.get("name") == name:
                return ctl.get_gateway(gatewayIdentifier=g["gatewayId"])
        token = r.get("nextToken")
        if not token:
            raise RuntimeError(f"gateway {name} not found")


def http_event(route, body, ip, path_params=None, headers=None):
    """Synthetic API Gateway HTTP API v2 event."""
    method, path = route.split(" ", 1)
    ev = {
        "version": "2.0",
        "routeKey": route,
        "rawPath": path,
        "rawQueryString": "",
        "headers": {"content-type": "application/json", "user-agent": "th-eval", **(headers or {})},
        "requestContext": {
            "http": {"method": method, "path": path, "protocol": "HTTP/1.1", "sourceIp": ip, "userAgent": "th-eval"},
            "requestId": "eval-" + ip,
            "stage": "$default",
        },
        "body": json.dumps(body) if body is not None else None,
        "isBase64Encoded": False,
    }
    if path_params:
        ev["pathParameters"] = path_params
    return ev
