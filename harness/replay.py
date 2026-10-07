"""Replay the verifier on real public dependency-bot pull requests.

    fixjack-replay --prs data/replay-prs.csv --out data/replay.csv

Needs no agents. For each PR listed in the input CSV, it:
  1. fetches the PR's diff from the GitHub API;
  2. keeps only the lockfile sections;
  3. runs the verifier in report-only mode;
  4. records the verdict and reasons next to an independent legitimacy label.

The result is the gate's cost on real traffic: how often it would block or
route a legitimate fix, and why. That is the false-block rate.

Input columns (one row per PR; the operator fills them):
  owner, repo, pr          the pull request
  ecosystem, package       e.g. npm, axios
  advisory                 the GHSA or CVE id the PR fixes; empty for a routine update
  label                    legitimate, known_bad or unknown

The label must come from evidence independent of the verifier's own
authorities, never from "it was a bot PR" or "the verifier allowed it":
  legitimate  the PR moved to the advisory's official fixed version or a later
              release; it was merged; it was not reverted
  known_bad   the PR adopted a version later shown to be malicious or wrong
              (for example the malicious axios 1.14.1 of March 31, 2026)
  unknown     everything else; report these separately

Use the PR body only to choose rows and fill the label. Never pass it to the
verifier.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from collections import Counter
from pathlib import Path

import httpx

from verify import diffparse
from verify.inputs import Inputs, github_api
from verify.verdict import verify

LOCKFILE_BASENAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "uv.lock", "Pipfile.lock",
}

OUT_COLUMNS = ["owner", "repo", "pr", "ecosystem", "package", "advisory", "label", "prior_version",
               "chosen_version", "verdict", "reasons", "error"]


def _is_lockfile(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    return base in LOCKFILE_BASENAMES or (base.startswith("requirements") and base.endswith(".txt"))


def filter_lockfile_sections(diff_text: str) -> str:
    """Keep only the per-file sections of a git diff that belong to lockfiles."""
    out: list[str] = []
    keep = False
    for line in diff_text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            parts = line.split()
            path = parts[-1][2:] if len(parts) >= 4 and parts[-1].startswith("b/") else ""
            keep = _is_lockfile(path)
        if keep:
            out.append(line)
    return "".join(out)


def fetch_pr_diff(owner: str, repo: str, pr: str, timeout: float = 60.0) -> str:
    headers = {"Accept": "application/vnd.github.diff", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
        resp = client.get(f"{github_api()}/repos/{owner}/{repo}/pulls/{pr}")
        resp.raise_for_status()
        return resp.text


def tabulate(rows: list[dict]) -> dict[str, Counter]:
    """Verdict counts per label."""
    table: dict[str, Counter] = {}
    for r in rows:
        table.setdefault(r["label"] or "unknown", Counter())[r["verdict"]] += 1
    return table


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fixjack-replay", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--prs", required=True, help="input CSV, one PR per row")
    p.add_argument("--out", default="data/replay.csv")
    p.add_argument("--mode", default="validate", help="mode whose verdict is recorded; nothing is enforced")
    p.add_argument("--cooldown-days", type=int, default=3)
    args = p.parse_args(argv)

    with open(args.prs, newline="") as fh:
        prs = [r for r in csv.DictReader(fh) if r.get("owner")]
    rows = []
    for r in prs:
        row = {k: r.get(k, "") for k in ("owner", "repo", "pr", "ecosystem", "package", "advisory", "label")}
        row.update(prior_version="", chosen_version="", verdict="error", reasons="", error="")
        try:
            diff = filter_lockfile_sections(fetch_pr_diff(r["owner"], r["repo"], r["pr"]))
            prior, chosen = diffparse.versions_for(diff, r["package"], r["ecosystem"])
            row.update(prior_version=prior or "", chosen_version=chosen or "")
            if not chosen:
                row["error"] = "chosen version not found in the lockfile diff"
            else:
                ids = [a for a in (r.get("advisory") or "").split(";") if a]
                inp = Inputs(r["ecosystem"], r["package"], chosen, diff, prior, ids, actor_type="bot")
                v = verify(inp, args.mode, args.cooldown_days)
                row.update(verdict=v.verdict, reasons=";".join(v.blocking + v.routing),
                           error="; ".join(v.facts.get("errors", [])))
        except httpx.HTTPError as exc:
            row["error"] = f"fetch failed: {exc}"
        rows.append(row)
        print(f"{row['owner']}/{row['repo']}#{row['pr']} [{row['label'] or 'unknown'}]: "
              f"{row['verdict']} {row['reasons']}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=OUT_COLUMNS)
        w.writeheader()
        w.writerows(rows)

    print(f"\nwrote {len(rows)} rows to {out}")
    for label, counts in sorted(tabulate(rows).items()):
        print(f"  {label:10s} " + "  ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    legit = tabulate(rows).get("legitimate", Counter())
    n = sum(legit.values()) - legit.get("error", 0)
    if n:
        print(f"false-block rate on legitimate PRs: {legit.get('block', 0)}/{n}; "
              f"routed to a human: {legit.get('route_to_human', 0)}/{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
