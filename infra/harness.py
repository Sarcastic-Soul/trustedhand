"""Create, update, show or delete the TrustedHand AgentCore harness.

The harness is not in Terraform because the AWS provider has no `hooks`
attribute. Run after `terraform apply`:

    uv run python infra/harness.py apply [--no-hooks]
    uv run python infra/harness.py show
    uv run python infra/harness.py destroy

Reads `terraform -chdir=infra output -json`, writes infra/harness.json (only the
harness id and ARN) and sets HARNESS_ARN on the th-chat Lambda (other env vars
are kept). Uses the `sarcastic-soul` profile unless --profile is given.
"""
import argparse
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

INFRA = Path(__file__).resolve().parent
OUT_FILE = INFRA / "harness.json"
PROMPT_FILE = INFRA / "system_prompt.md"
NAME = "trustedhand"
MODEL_ID = "us.amazon.nova-2-lite-v1:0"
CHAT_FN = "th-chat"
REGION = "us-east-1"


def tf_outputs() -> dict:
    r = subprocess.run(["terraform", f"-chdir={INFRA}", "output", "-json"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"terraform output failed: {r.stderr.strip()}")
    out = {k: v["value"] for k, v in json.loads(r.stdout).items()}
    missing = [k for k in ("gateway_arn", "hook_lambda_arn", "harness_role_arn") if not out.get(k)]
    if missing:
        sys.exit(f"terraform outputs missing {missing}: run terraform apply first")
    return out


def find_harness(ctl) -> dict | None:
    token = None
    while True:
        kw = {"nextToken": token} if token else {}
        r = ctl.list_harnesses(**kw)
        for h in r.get("harnesses", []):
            if h.get("harnessName") == NAME:
                return h
        token = r.get("nextToken")
        if not token:
            return None


def wait_ready(ctl, harness_id: str) -> dict:
    for _ in range(120):
        h = ctl.get_harness(harnessId=harness_id)["harness"]
        s = h["status"]
        if s == "READY":
            return h
        if s.endswith("FAILED"):
            sys.exit(f"harness {s}: {h.get('failureReason')}")
        time.sleep(5)
    sys.exit("timed out waiting for READY")


def wait_deleted(ctl, harness_id: str) -> None:
    for _ in range(120):
        try:
            h = ctl.get_harness(harnessId=harness_id)["harness"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if h["status"] == "DELETE_FAILED":
            sys.exit(f"delete failed: {h.get('failureReason')}")
        time.sleep(5)
    sys.exit("timed out waiting for delete")


def set_chat_env(lam, harness_arn: str) -> None:
    """Set HARNESS_ARN on th-chat, keeping the other variables."""
    try:
        cfg = lam.get_function_configuration(FunctionName=CHAT_FN)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print(f"{CHAT_FN} not found, skipping env update")
            return
        raise
    env = dict(cfg.get("Environment", {}).get("Variables", {}))
    if env.get("HARNESS_ARN") == harness_arn:
        return
    env["HARNESS_ARN"] = harness_arn
    lam.update_function_configuration(FunctionName=CHAT_FN, Environment={"Variables": env})
    lam.get_waiter("function_updated_v2").wait(FunctionName=CHAT_FN)
    print(f"{CHAT_FN}: HARNESS_ARN set")


def config(out: dict, hooks: bool) -> dict:
    hook_target = {"lambda": {"arn": out["hook_lambda_arn"], "timeoutSeconds": 10, "failureMode": "deny"}}
    return {
        "executionRoleArn": out["harness_role_arn"],
        "model": {"bedrockModelConfig": {"modelId": MODEL_ID, "maxTokens": 1000, "temperature": 0}},
        "systemPrompt": [{"text": PROMPT_FILE.read_text().strip()}],
        "tools": [{"type": "agentcore_gateway", "name": "bank",
                   "config": {"agentCoreGateway": {"gatewayArn": out["gateway_arn"]}}}],
        "allowedTools": ["@bank/*"],
        "memory": {"disabled": {}},
        "maxIterations": 8,
        "timeoutSeconds": 90,
        # An empty list clears hooks on update (--no-hooks for the stress test).
        "hooks": [{"beforeToolCall": {"name": "pre", "target": hook_target}},
                  {"afterToolCall": {"name": "post", "target": hook_target}}] if hooks else [],
    }


def apply(ctl, lam, hooks: bool) -> None:
    out = tf_outputs()
    cfg = config(out, hooks)
    h = find_harness(ctl)
    if h:
        hid = h["harnessId"]
        # UpdateHarness wraps memory in optionalValue.
        cfg["memory"] = {"optionalValue": cfg["memory"]}
        ctl.update_harness(harnessId=hid, clientToken=str(uuid.uuid4()), **cfg)
        print(f"updating {hid}")
    else:
        if not hooks:
            cfg.pop("hooks")
        r = ctl.create_harness(harnessName=NAME, clientToken=str(uuid.uuid4()),
                               tags={"project": "trustedhand"}, **cfg)["harness"]
        hid = r["harnessId"]
        print(f"creating {hid}")
    ready = wait_ready(ctl, hid)
    OUT_FILE.write_text(json.dumps({"harness_id": ready["harnessId"], "harness_arn": ready["arn"]}, indent=2) + "\n")
    set_chat_env(lam, ready["arn"])
    print(f"READY {ready['arn']} hooks={'on' if hooks else 'off'}")


def show(ctl) -> None:
    h = find_harness(ctl)
    if not h:
        sys.exit("no harness named trustedhand")
    full = ctl.get_harness(harnessId=h["harnessId"])["harness"]
    print(json.dumps(full, indent=2, default=str))


def destroy(ctl, lam) -> None:
    h = find_harness(ctl)
    if h:
        ctl.delete_harness(harnessId=h["harnessId"], clientToken=str(uuid.uuid4()))
        wait_deleted(ctl, h["harnessId"])
        print(f"deleted {h['harnessId']}")
    else:
        print("no harness to delete")
    OUT_FILE.unlink(missing_ok=True)
    set_chat_env(lam, "")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["apply", "destroy", "show"])
    ap.add_argument("--no-hooks", action="store_true", help="leave hooks off (stress test ablation)")
    ap.add_argument("--profile", default="sarcastic-soul")
    a = ap.parse_args()
    s = boto3.Session(profile_name=a.profile, region_name=REGION)
    ctl, lam = s.client("bedrock-agentcore-control"), s.client("lambda")
    if a.cmd == "apply":
        apply(ctl, lam, hooks=not a.no_hooks)
    elif a.cmd == "show":
        show(ctl)
    else:
        destroy(ctl, lam)


if __name__ == "__main__":
    main()
