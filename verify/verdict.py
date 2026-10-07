"""Combine the authorities into one verdict: allow, block, or route to a human.

The decision logic lives in `policy/fixjack.rego` and is evaluated with OPA
when the `opa` binary is on PATH. The Python engine below implements the same
rules so the gate runs without OPA; both must stay in sync, and
`tests/test_policy.py` pins the shared cases.

Modes map to the adoption ladder: report-only (Level 2), validate (Level 3),
prevent (Level 4). The rules are the same at every mode except that the two
escalating reasons route to a human below prevent and block at prevent.
Enforcement (the exit code) is the CLI's job; the verdict is computed
identically so report-only shows exactly what validate would have done.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .authorities import attestation, cooldown, lockfile_policy, osv_range
from .inputs import Inputs
from .versions import direction

MODES = ("report-only", "validate", "prevent")

R_AFFECTED = "chosen version inside affected range"
R_NOT_FIXED = "chosen version not in fixed set"
R_NO_ATTESTATION = "no registry attestation"           # package attests, this version does not
R_ATT_NONE = "package publishes no attestations"       # informational; counts against provenance coverage
R_COOLDOWN = "cooldown not satisfied"
R_HOST = "registry host outside allowlist"
R_UNDECLARED = "undeclared packages changed"
R_DOWNGRADE = "downgrade outside fixed set"
R_DOWNGRADE_NO_ADVISORY = "downgrade with no reviewed advisory"
R_SUPPRESSION = "agent-authored suppression"
R_UNAVAILABLE = "authority unavailable"

ALWAYS_BLOCK = {R_AFFECTED, R_NOT_FIXED, R_NO_ATTESTATION, R_COOLDOWN, R_HOST, R_DOWNGRADE, R_DOWNGRADE_NO_ADVISORY}
ESCALATING = {R_UNDECLARED, R_SUPPRESSION}

POLICY_DIR = Path(__file__).resolve().parent / "policy"


@dataclass
class Verdict:
    verdict: str                      # allow | block | route_to_human
    mode: str
    enforced: bool
    reasons: list[str]
    blocking: list[str]
    routing: list[str]
    engine: str                       # opa | python
    facts: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)


def gather_facts(inp: Inputs, cooldown_days: int = 3) -> dict:
    errors: list[str] = [f"advisory resolution: {e}" for e in inp.resolution_errors]
    ranges = [osv_range.check(a, inp.ecosystem, inp.package, inp.chosen_version) for a in inp.advisory_ids]
    for r in ranges:
        if r.error:
            errors.append(f"{r.advisory_id}: {r.error}")
    authoritative = [r for r in ranges if r.package_matched and r.reviewed is not False and not r.error]
    unreviewed = [r.advisory_id for r in ranges if r.reviewed is False]
    in_affected = any(r.in_affected for r in authoritative)
    is_fixed = bool(authoritative) and all(r.is_fixed for r in authoritative)
    aliases = sorted({a for r in ranges for a in r.aliases} | {a for a in inp.advisory_ids if a.upper().startswith("CVE-")})

    att = attestation.check(inp.ecosystem, inp.package, inp.chosen_version)
    if att.error:
        errors.append(f"attestation: {att.error}")
    cd = cooldown.evaluate(inp.ecosystem, inp.package, inp.chosen_version, aliases, cooldown_days, inp.kev_human_approval)
    if cd.error:
        errors.append(f"cooldown: {cd.error}")
    lf = lockfile_policy.evaluate(inp.lockfile_diff, inp.ecosystem, (inp.package,), inp.allowed_hosts)
    try:
        dirn = direction(inp.ecosystem, inp.prior_version, inp.chosen_version)
    except ValueError as exc:
        dirn = "unknown"
        errors.append(f"version parse: {exc}")

    return {
        "package": inp.package,
        "ecosystem": inp.ecosystem,
        "chosen_version": inp.chosen_version,
        "prior_version": inp.prior_version,
        "direction": dirn,
        "advisories": [asdict(r) for r in ranges],
        "osv": {
            "advisory_count": len(ranges),
            "authoritative_count": len(authoritative),
            "unreviewed": unreviewed,
            "in_affected": in_affected,
            "is_fixed": is_fixed,
            "no_authority": not authoritative,
        },
        "attestation": asdict(att),
        "cooldown": asdict(cd),
        "lockfile": asdict(lf),
        "kev_human_approval": inp.kev_human_approval,
        "is_suppression": inp.is_suppression,
        "actor_type": inp.actor_type,
        "errors": errors,
    }


def reasons_for(facts: dict) -> list[str]:
    osv = facts["osv"]
    out: list[str] = []
    if osv["in_affected"]:
        out.append(R_AFFECTED)
    if not osv["no_authority"] and not osv["in_affected"] and not osv["is_fixed"]:
        out.append(R_NOT_FIXED)
    att = facts["attestation"]
    # A failed attestation lookup says nothing about the package; it is
    # reported as an unavailable authority, never as "publishes no attestations".
    if att["supported"] and not att["present"] and not att.get("error"):
        out.append(R_NO_ATTESTATION if att.get("package_attests") else R_ATT_NONE)
    if not facts["cooldown"]["satisfied"]:
        out.append(R_COOLDOWN)
    if facts["lockfile"]["disallowed_hosts"]:
        out.append(R_HOST)
    if facts["lockfile"]["undeclared_packages"]:
        out.append(R_UNDECLARED)
    if facts["direction"] == "downgrade" and not osv["no_authority"] and not osv["is_fixed"]:
        out.append(R_DOWNGRADE)
    if facts["direction"] == "downgrade" and osv["no_authority"]:
        out.append(R_DOWNGRADE_NO_ADVISORY)
    if facts["is_suppression"] and facts["actor_type"] != "human":
        out.append(R_SUPPRESSION)
    if facts.get("errors"):
        out.append(R_UNAVAILABLE)
    return out


def decide_python(facts: dict, mode: str) -> tuple[str, list[str], list[str], list[str]]:
    reasons = reasons_for(facts)
    blocking = [r for r in reasons if r in ALWAYS_BLOCK]
    if mode == "prevent":
        blocking += [r for r in reasons if r in ESCALATING]
        routing = []
    else:
        routing = [r for r in reasons if r in ESCALATING]
    if R_UNAVAILABLE in reasons:
        routing.append(R_UNAVAILABLE)   # fail closed to a human, never open
    if blocking:
        verdict = "block"
    elif routing:
        verdict = "route_to_human"
    else:
        verdict = "allow"
    return verdict, reasons, blocking, routing


def decide_opa(facts: dict, mode: str, policy_dir: Path) -> tuple[str, list[str], list[str], list[str]] | None:
    opa = shutil.which("opa")
    if not opa:
        return None
    payload = dict(facts, mode=mode)
    with tempfile.TemporaryDirectory() as tmp:
        inp = Path(tmp) / "input.json"
        inp.write_text(json.dumps(payload, default=str))
        proc = subprocess.run(
            [opa, "eval", "--format", "json", "-i", str(inp), "-d", str(policy_dir), "data.fixjack.result"],
            capture_output=True, text=True, timeout=60,
        )
    if proc.returncode != 0:
        return None
    try:
        value = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, ValueError):
        return None
    return value["verdict"], sorted(value["reasons"]), sorted(value["blocking"]), sorted(value["routing"])


def decide(facts: dict, mode: str = "report-only", policy_dir: Path | None = None) -> Verdict:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    engine = "python"
    result = None
    if os.environ.get("FIXJACK_ENGINE", "auto") != "python":
        result = decide_opa(facts, mode, policy_dir or POLICY_DIR)
        if result:
            engine = "opa"
    if result is None:
        result = decide_python(facts, mode)
    verdict, reasons, blocking, routing = result
    return Verdict(verdict, mode, mode != "report-only", reasons, blocking, routing, engine, facts)


def verify(inp: Inputs, mode: str = "report-only", cooldown_days: int = 3, policy_dir: Path | None = None) -> Verdict:
    return decide(gather_facts(inp, cooldown_days), mode, policy_dir)
