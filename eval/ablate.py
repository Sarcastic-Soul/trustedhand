"""Ablation switches for the stress test. Each is a context manager that ALWAYS restores
the live setting, also on Ctrl-C or SIGTERM (run.py turns SIGTERM into KeyboardInterrupt).

  cedar  -> gateway policy engine mode LOG_ONLY (restored to the original mode, ENFORCE)
  scan   -> env TH_ABLATE_SCAN=1 on th-interceptor (RESPONSE scanning off; identity stays on)
  hooks  -> `infra/harness.py apply --no-hooks` (restored with `apply`)
"""
import contextlib
import os
import subprocess
import sys
import time

from . import common

NAMES = ("cedar", "scan", "hooks")


def wait_gateway(ctl, gateway_id, timeout=300, sleep=time.sleep):
    end = time.time() + timeout
    while time.time() < end:
        g = ctl.get_gateway(gatewayIdentifier=gateway_id)
        if g.get("status") == "READY":
            return g
        if "FAILED" in str(g.get("status")):
            raise RuntimeError(f"gateway update failed: {g.get('statusReasons')}")
        sleep(4)
    raise RuntimeError("timeout waiting for gateway READY")


def set_policy_mode(ctl, gateway_id, mode, log=print, sleep=time.sleep):
    """Same approach as spikes/day1/spike.py set_mode: update_gateway needs name, roleArn, protocolType,
    authorizerType and the interceptor config sent again."""
    g = ctl.get_gateway(gatewayIdentifier=gateway_id)
    pe = g.get("policyEngineConfiguration") or {}
    keep = {k: g[k] for k in ("name", "roleArn", "protocolType", "authorizerType") if k in g}
    for k in ("interceptorConfigurations", "exceptionLevel", "description", "protocolConfiguration", "authorizerConfiguration"):
        if g.get(k):
            keep[k] = g[k]
    ctl.update_gateway(gatewayIdentifier=gateway_id, policyEngineConfiguration={"arn": pe["arn"], "mode": mode}, **keep)
    wait_gateway(ctl, gateway_id, sleep=sleep)
    log(f"[ablate] gateway policy mode -> {mode}")


@contextlib.contextmanager
def cedar_log_only(session, infra=None, log=print, sleep=time.sleep):
    ctl = session.client("bedrock-agentcore-control")
    gw = common.find_gateway(ctl, gateway_id=(infra or {}).get("gateway_id"))
    gid = gw["gatewayId"]
    original = (gw.get("policyEngineConfiguration") or {}).get("mode") or "ENFORCE"
    try:
        set_policy_mode(ctl, gid, "LOG_ONLY", log, sleep)
        yield
    finally:
        log(f"[ablate] restoring gateway policy mode {original}")
        set_policy_mode(ctl, gid, original, log, sleep)


@contextlib.contextmanager
def scan_off(session, function="th-interceptor", log=print):
    lam = session.client("lambda")
    waiter = lam.get_waiter("function_updated_v2")
    cfg = lam.get_function_configuration(FunctionName=function)
    original = dict((cfg.get("Environment") or {}).get("Variables") or {})
    try:
        lam.update_function_configuration(FunctionName=function, Environment={"Variables": {**original, "TH_ABLATE_SCAN": "1"}})
        waiter.wait(FunctionName=function)
        log("[ablate] th-interceptor: TH_ABLATE_SCAN=1")
        yield
    finally:
        log("[ablate] restoring th-interceptor env")
        lam.update_function_configuration(FunctionName=function, Environment={"Variables": original})
        waiter.wait(FunctionName=function)


def _harness_apply(args, aws_profile, log):
    env = {**os.environ, "AWS_PROFILE": aws_profile, "AWS_DEFAULT_REGION": common.REGION}  # scoped to this subprocess
    cmd = [sys.executable, str(common.ROOT / "infra" / "harness.py"), "apply", *args]
    log("[ablate] " + " ".join(cmd[1:]))
    subprocess.run(cmd, cwd=common.ROOT, env=env, check=True)


@contextlib.contextmanager
def hooks_off(aws_profile=common.DEFAULT_AWS_PROFILE, log=print, runner=None):
    run = runner or (lambda args: _harness_apply(args, aws_profile, log))
    try:
        run(["--no-hooks"])
        yield
    finally:
        log("[ablate] restoring harness hooks")
        run([])


@contextlib.contextmanager
def ablations(names, session, infra=None, aws_profile=common.DEFAULT_AWS_PROFILE, log=print):
    """Apply all named ablations; restore in reverse order on exit."""
    bad = [n for n in names if n not in NAMES]
    if bad:
        raise ValueError(f"unknown ablation {bad}; choose from {NAMES}")
    with contextlib.ExitStack() as stack:
        if "hooks" in names:
            stack.enter_context(hooks_off(aws_profile, log))
        if "scan" in names:
            stack.enter_context(scan_off(session, log=log))
        if "cedar" in names:
            stack.enter_context(cedar_log_only(session, infra, log))
        yield
