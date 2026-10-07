"""Shared decision cases. The Python engine is exercised directly; when the
`opa` binary is available the Rego policy is run on the same cases and must
agree."""
import shutil

import pytest

from verify.verdict import (
    R_AFFECTED, R_ATT_NONE, R_COOLDOWN, R_DOWNGRADE, R_DOWNGRADE_NO_ADVISORY, R_HOST, R_NO_ATTESTATION,
    R_NOT_FIXED, R_SUPPRESSION, R_UNAVAILABLE, R_UNDECLARED, decide_opa, decide_python, POLICY_DIR,
)


def facts(**over):
    base = {
        "direction": "upgrade",
        "osv": {"no_authority": False, "in_affected": False, "is_fixed": True, "unreviewed": []},
        "attestation": {"supported": True, "present": True, "package_attests": True},
        "cooldown": {"satisfied": True},
        "lockfile": {"disallowed_hosts": [], "undeclared_packages": []},
        "is_suppression": False,
        "actor_type": "agent",
        "errors": [],
    }
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = {**base[k], **v}
        else:
            base[k] = v
    return base


CASES = [
    ("legitimate fix", facts(), "validate", "allow", []),
    ("decoy inside affected range", facts(osv={"in_affected": True, "is_fixed": False}), "validate", "block", [R_AFFECTED]),
    ("decoy below range, not fixed", facts(osv={"is_fixed": False}), "validate", "block", [R_NOT_FIXED]),
    ("attestation regression", facts(attestation={"present": False}), "validate", "block", [R_NO_ATTESTATION]),
    ("package never attested is reported, not blocked", facts(attestation={"present": False, "package_attests": False}), "validate", "allow", [R_ATT_NONE]),
    ("too new", facts(cooldown={"satisfied": False}), "validate", "block", [R_COOLDOWN]),
    ("registry swap", facts(lockfile={"disallowed_hosts": ["mirror.example.net"]}), "validate", "block", [R_HOST]),
    ("transitive bump, validate", facts(lockfile={"undeclared_packages": ["x"]}), "validate", "route_to_human", [R_UNDECLARED]),
    ("transitive bump, prevent", facts(lockfile={"undeclared_packages": ["x"]}), "prevent", "block", [R_UNDECLARED]),
    ("downgrade outside fixed set", facts(direction="downgrade", osv={"is_fixed": False}), "validate", "block", [R_NOT_FIXED, R_DOWNGRADE]),
    ("downgrade with no advisory", facts(direction="downgrade", osv={"no_authority": True, "is_fixed": False}), "validate", "block", [R_DOWNGRADE_NO_ADVISORY]),
    ("agent suppression, validate", facts(is_suppression=True), "validate", "route_to_human", [R_SUPPRESSION]),
    ("agent suppression, prevent", facts(is_suppression=True), "prevent", "block", [R_SUPPRESSION]),
    ("human suppression", facts(is_suppression=True, actor_type="human"), "prevent", "allow", []),
    ("authority down fails closed to a human", facts(errors=["osv fetch: timeout"]), "validate", "route_to_human", [R_UNAVAILABLE]),
    ("attestation lookup failed is unavailable, not 'never attested'",
     facts(attestation={"present": False, "package_attests": False, "error": "registry timeout"}, errors=["attestation: registry timeout"]),
     "validate", "route_to_human", [R_UNAVAILABLE]),
    ("alert lookup failed routes to a human",
     facts(osv={"no_authority": True, "is_fixed": False}, errors=["advisory resolution: alert lookup failed: HTTP 403"]),
     "validate", "route_to_human", [R_UNAVAILABLE]),
    ("report-only computes the same verdict", facts(attestation={"present": False}), "report-only", "block", [R_NO_ATTESTATION]),
]


@pytest.mark.parametrize("name,f,mode,expected,expected_reasons", CASES, ids=[c[0] for c in CASES])
def test_python_engine(name, f, mode, expected, expected_reasons):
    verdict, reasons, blocking, routing = decide_python(f, mode)
    assert verdict == expected
    assert sorted(reasons) == sorted(expected_reasons)


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed")
@pytest.mark.parametrize("name,f,mode,expected,expected_reasons", CASES, ids=[c[0] for c in CASES])
def test_rego_agrees_with_python(name, f, mode, expected, expected_reasons):
    result = decide_opa(f, mode, POLICY_DIR)
    assert result is not None, "opa eval failed"
    verdict, reasons, blocking, routing = result
    py = decide_python(f, mode)
    assert verdict == py[0] == expected
    assert sorted(reasons) == sorted(py[1])
    assert sorted(blocking) == sorted(py[2])
    assert sorted(routing) == sorted(py[3])
