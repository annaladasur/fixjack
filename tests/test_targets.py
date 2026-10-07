"""Target selection and alert-lookup failures (review finding R3-03).

A version change with no open alert must still be verified, and a failed
alert lookup must route to a human rather than read as "no alert".
"""
import httpx

from verify import inputs
from verify.cli import build_targets
from verify.inputs import Inputs
from verify.verdict import R_UNAVAILABLE, decide_python

DIFF = """\
--- a/package-lock.json
+++ b/package-lock.json
@@ -10,6 +10,6 @@
     "node_modules/left-pad": {
-      "version": "1.2.0",
+      "version": "1.3.0",
     },
@@ -20,6 +20,6 @@
     "node_modules/tiny-helper": {
-      "version": "0.0.8",
+      "version": "0.0.9",
     },
"""


def test_auto_verifies_unalerted_packages():
    resolver = lambda name: (["GHSA-aaaa-bbbb-cccc"] if name == "left-pad" else [], None)  # noqa: E731
    targets = build_targets(DIFF, "npm", None, [], resolver, auto=True)
    assert [t[0] for t in targets] == ["left-pad", "tiny-helper"]
    assert targets[0][1] == ["GHSA-aaaa-bbbb-cccc"]
    assert targets[1] == ("tiny-helper", [], [])


def test_lookup_failure_is_carried_not_dropped():
    resolver = lambda name: ([], f"alert lookup for {name} failed: HTTP 403")  # noqa: E731
    targets = build_targets(DIFF, "npm", None, [], resolver, auto=True)
    assert all(t[2] and "HTTP 403" in t[2][0] for t in targets)


def test_explicit_mode_merges_ids():
    resolver = lambda name: (["GHSA-2", "GHSA-1"], None)  # noqa: E731
    targets = build_targets(DIFF, "npm", "left-pad", ["GHSA-1"], resolver, auto=False)
    assert targets == [("left-pad", ["GHSA-1", "GHSA-2"], [])]


def test_no_version_change_means_no_targets():
    assert build_targets("", "npm", None, [], None, auto=True) == []


def test_resolve_advisories_captures_http_errors(monkeypatch):
    request = httpx.Request("GET", "https://api.github.com/x")

    def boom(*a, **k):
        raise httpx.HTTPStatusError("forbidden", request=request, response=httpx.Response(403, request=request))

    monkeypatch.setattr(inputs, "advisories_from_dependabot", boom)
    ids, err = inputs.resolve_advisories("o", "r", "left-pad", "npm")
    assert ids == [] and "HTTP 403" in err and "FIXJACK_ALERTS_TOKEN" in err


def test_resolution_error_routes_to_human(monkeypatch):
    # gather_facts must turn a resolution error into an unavailable authority.
    from verify import verdict
    from verify.authorities import attestation, cooldown

    monkeypatch.setattr(attestation, "check", lambda *a, **k: attestation.AttestationResult(True, True, True, True, True, "1.3.0", "ok"))
    monkeypatch.setattr(cooldown, "evaluate", lambda *a, **k: cooldown.CooldownResult("2026-01-01", 200.0, 3, True, False, False, "old"))
    inp = Inputs("npm", "left-pad", "1.3.0", DIFF, "1.2.0", [], actor_type="agent",
                 resolution_errors=["alert lookup for left-pad failed: HTTP 403"])
    facts = verdict.gather_facts(inp)
    v, reasons, blocking, routing = decide_python(facts, "validate")
    assert R_UNAVAILABLE in reasons and v == "route_to_human"
