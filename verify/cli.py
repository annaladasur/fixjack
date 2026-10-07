"""fixjack-verify: run the gate on one dependency change.

    fixjack-verify --ecosystem npm --package left-pad --version 1.3.0 \
        --advisory GHSA-xxxx-xxxx-xxxx --lockfile-diff pr.patch --mode validate

    # in CI, verify every package whose version the diff sets, resolving
    # advisory ids from the repository's own alert records:
    fixjack-verify --ecosystem npm --auto --resolve-alerts owner/repo \
        --lockfile-diff pr.patch --mode report-only --actor-type bot

Packages without an open alert are still verified (attestation regression,
cooldown, lockfile policy; a downgrade with no reviewed advisory blocks). A
failed alert lookup routes to a human instead of counting as "no alert".

Exit codes when the mode enforces (validate, prevent): 0 allow, 1 block,
2 route to human. In report-only the exit code is always 0 and the verdict is
what validate would have decided.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path
from typing import Callable

from . import diffparse
from .inputs import Inputs, allowed_hosts_from_env, resolve_advisories
from .verdict import MODES, Verdict, verify

WORKSHEET_COLUMNS = [
    "date", "repo", "pr_id", "author_type", "advisory_id", "chosen_version",
    "semver_relation_to_fix", "attestation_present", "age_days", "verdict",
    "reason", "human_override", "override_reason", "time_to_merge_hours",
]


Resolver = Callable[[str], "tuple[list[str], str | None]"]


def build_targets(
    diff_text: str,
    ecosystem: str,
    package: str | None,
    explicit_ids: list[str],
    resolver: Resolver | None,
    auto: bool,
) -> list[tuple[str, list[str], list[str]]]:
    """Decide which packages to verify. Returns (name, advisory_ids, resolution_errors).

    In --auto mode every package whose version the diff sets is verified, with
    or without an open alert. Skipping unalerted packages would let a version
    change through unexamined. A package with no advisory is still checked
    for attestation regression, cooldown and lockfile policy, and a downgrade
    with no reviewed advisory blocks. A failed alert lookup is carried as a
    resolution error, so the verdict routes to a human instead of treating the
    failure as "no alert".
    """
    targets: list[tuple[str, list[str], list[str]]] = []
    if auto:
        names = sorted(
            n for n in diffparse.packages_in_diff(diff_text, ecosystem)
            if diffparse.versions_for(diff_text, n, ecosystem)[1] is not None
        )
    else:
        names = [package] if package else []
    for name in names:
        ids = list(explicit_ids) if not auto else []
        errors: list[str] = []
        if resolver is not None:
            found, err = resolver(name)
            ids += [i for i in found if i not in ids]
            if err:
                errors.append(err)
        targets.append((name, ids, errors))
    return targets


def _read_diff(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text()


def _relation(v: Verdict) -> str:
    osv = v.facts.get("osv", {})
    if osv.get("in_affected"):
        return "inside_affected"
    if osv.get("is_fixed"):
        return "at_or_above_fixed"
    if osv.get("no_authority"):
        return "no_advisory"
    return "below_range"


def _append_worksheet(path: str, v: Verdict, repo: str, pr_id: str) -> None:
    exists = Path(path).exists()
    with open(path, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=WORKSHEET_COLUMNS)
        if not exists:
            w.writeheader()
        w.writerow({
            "date": date.today().isoformat(),
            "repo": repo,
            "pr_id": pr_id,
            "author_type": v.facts.get("actor_type"),
            "advisory_id": ";".join(a["advisory_id"] for a in v.facts.get("advisories", [])),
            "chosen_version": v.facts.get("chosen_version"),
            "semver_relation_to_fix": _relation(v),
            "attestation_present": v.facts.get("attestation", {}).get("present"),
            "age_days": v.facts.get("cooldown", {}).get("age_days"),
            "verdict": v.verdict,
            "reason": ";".join(v.blocking + v.routing),
            "human_override": "",
            "override_reason": "",
            "time_to_merge_hours": "",
        })


def _print(v: Verdict) -> None:
    f = v.facts
    print(f"fixjack verify: {v.verdict.upper()}  mode={v.mode} enforced={v.enforced} engine={v.engine}")
    print(f"  {f['ecosystem']} {f['package']} {f.get('prior_version') or '?'} -> {f['chosen_version']} ({f['direction']})")
    for adv in f.get("advisories", []):
        rev = {True: "reviewed", False: "UNREVIEWED", None: "n/a"}[adv["reviewed"]]
        print(f"  advisory {adv['advisory_id']} [{rev}]: {adv['detail']}")
    print(f"  attestation: {f['attestation']['detail']}")
    print(f"  cooldown: {f['cooldown']['detail']}")
    print(f"  lockfile: {f['lockfile']['detail']}")
    if v.blocking:
        print("  BLOCKING: " + "; ".join(v.blocking))
    if v.routing:
        print("  ROUTE TO HUMAN: " + "; ".join(v.routing))
    for e in f.get("errors", []):
        print(f"  error: {e}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fixjack-verify", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ecosystem", required=True, help="npm or PyPI")
    p.add_argument("--package", help="package the change is for; omit with --auto")
    p.add_argument("--version", dest="chosen_version", help="chosen version; parsed from the diff if omitted")
    p.add_argument("--prior-version", help="version before the change; parsed from the diff if omitted")
    p.add_argument("--advisory", action="append", default=[], help="GHSA or CVE id; repeatable")
    p.add_argument("--resolve-alerts", metavar="OWNER/REPO",
                   help="resolve advisory ids from the repository's Dependabot alerts")
    p.add_argument("--auto", action="store_true",
                   help="verify every alerted package that appears in the diff (needs --resolve-alerts)")
    p.add_argument("--lockfile-diff", required=True, help="unified diff path, or - for stdin")
    p.add_argument("--mode", choices=MODES, default="report-only")
    p.add_argument("--cooldown-days", type=int, default=3)
    p.add_argument("--kev-human-approval", action="store_true", help="a human approved a KEV cooldown exception")
    p.add_argument("--suppression", action="store_true", help="the change dismisses or suppresses an alert")
    p.add_argument("--actor-type", choices=["human", "bot", "agent", "unknown"], default="unknown")
    p.add_argument("--allow-host", action="append", help="registry host allowlist entry; repeatable")
    p.add_argument("--policy-dir", help="Rego policy directory (default: bundled)")
    p.add_argument("--json", dest="json_out", help="write the full verdict JSON here")
    p.add_argument("--worksheet", help="append a row to this CSV (worksheet schema)")
    p.add_argument("--repo", default="", help="repository label for the worksheet row")
    p.add_argument("--pr", default="", help="PR id for the worksheet row")
    args = p.parse_args(argv)

    diff_text = _read_diff(args.lockfile_diff)
    allowed = tuple(args.allow_host or ()) or allowed_hosts_from_env() or Inputs.allowed_hosts

    if args.auto and not args.resolve_alerts:
        p.error("--auto needs --resolve-alerts OWNER/REPO")
    if not args.auto and not args.package:
        p.error("--package is required unless --auto is used")
    resolver = None
    if args.resolve_alerts:
        owner, repo = args.resolve_alerts.split("/", 1)
        resolver = lambda name: resolve_advisories(owner, repo, name, args.ecosystem)  # noqa: E731
    targets = build_targets(diff_text, args.ecosystem, args.package, args.advisory, resolver, args.auto)
    if not targets:
        print("fixjack verify: no dependency version changed in this diff; nothing to verify")
        return 0

    worst: Verdict | None = None
    order = {"allow": 0, "route_to_human": 1, "block": 2}
    results = []
    for name, ids, resolution_errors in targets:
        prior, chosen = diffparse.versions_for(diff_text, name, args.ecosystem)
        chosen = args.chosen_version or chosen
        prior = args.prior_version or prior
        if not chosen:
            print(f"fixjack verify: could not determine the chosen version of {name} from the diff; pass --version")
            return 2 if args.mode != "report-only" else 0
        inp = Inputs(
            ecosystem=args.ecosystem, package=name, chosen_version=chosen, lockfile_diff=diff_text,
            prior_version=prior, advisory_ids=ids, kev_human_approval=args.kev_human_approval,
            is_suppression=args.suppression, actor_type=args.actor_type, allowed_hosts=allowed,
            resolution_errors=list(resolution_errors),
        )
        v = verify(inp, args.mode, args.cooldown_days, Path(args.policy_dir) if args.policy_dir else None)
        _print(v)
        results.append(v)
        if args.worksheet:
            _append_worksheet(args.worksheet, v, args.repo, args.pr)
        if worst is None or order[v.verdict] > order[worst.verdict]:
            worst = v

    if args.json_out:
        payload = [json.loads(r.to_json()) for r in results]
        Path(args.json_out).write_text(json.dumps(payload if len(payload) > 1 else payload[0], indent=2))

    assert worst is not None
    if not worst.enforced:
        return 0
    return {"allow": 0, "block": 1, "route_to_human": 2}[worst.verdict]


if __name__ == "__main__":
    sys.exit(main())
