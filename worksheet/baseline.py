"""fixjack-baseline: the Week 1 numbers.

    fixjack-baseline --repo . --days 90 --out worksheet/baseline-<repo>.csv

Scans the last N days of commits that touched a dependency manifest or
lockfile, classifies each commit as human, bot or agent, and prints:

  non-human dependency change share   non-human dependency commits / all dependency commits
  distinct non-human authors           who is changing dependencies without a person
  provenance coverage (optional)       of the npm versions introduced by non-humans,
                                       how many have a registry attestation (npm only)

How a commit is classified, and why the share is approximate:
  bot    the author name or email matches a known bot (dependabot, renovate,
         "[bot]" accounts, ...)
  agent  the author, or a Co-authored-by trailer, matches a known coding-agent
         name as a whole word (copilot, codex, claude, ...)
  human  everything else

Agents that commit under a developer's own identity and add no trailer are
counted as human, so the share is a lower bound. Use --audit N to print a
random sample of classified commits; check them by hand, or against PR
authors in the forge, and report the share together with the audited error
rate. Extend the patterns with --bot-pattern / --agent-pattern.

Auto-merge rate and time-to-merge need pull-request data from the forge's API;
this tool does not fetch it.
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEP_FILES = re.compile(
    r"(^|/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|"
    r"requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(\.lock)?|"
    r"go\.(mod|sum)|Cargo\.(toml|lock)|pom\.xml|build\.gradle(\.kts)?|Gemfile(\.lock)?)$"
)
BOT_PATTERNS = [r"dependabot", r"renovate", r"github-actions", r"snyk-bot", r"greenkeeper", r"\[bot\]"]
# Whole-word coding-agent names. A bare "agent" substring is deliberately absent:
# it matched any author whose name or email merely contained the letters.
AGENT_PATTERNS = [r"\bcopilot\b", r"\bcodex\b", r"\bclaude\b", r"\bgemini\b", r"\bdevin\b", r"\bcline\b",
                  r"\bopenhands\b", r"\baider\b", r"\bcursor(?:-agent)?\b", r"\bswe-agent\b"]
NPM_LOCK_VERSION = re.compile(r'^\+\s*"node_modules/((?:@[^/"]+/)?[^/"]+)":\s*\{\s*$')
NPM_VERSION_LINE = re.compile(r'^\+\s*"version":\s*"([^"]+)"')


def classify(author: str, email: str, bot_re: re.Pattern, agent_re: re.Pattern,
             coauthors: list[str] | None = None) -> str:
    blob = f"{author} {email}".lower()
    if agent_re.search(blob):
        return "agent"
    if any(agent_re.search(c.lower()) for c in coauthors or []):
        return "agent"
    if bot_re.search(blob):
        return "bot"
    return "human"


def coauthor_trailers(repo: Path, days: int) -> dict[str, list[str]]:
    """Map commit sha to its Co-authored-by trailer values."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
    raw = git(repo, "log", f"--since={since}",
              "--format=%x1e%H%x1f%(trailers:key=Co-authored-by,valueonly,separator=%x1d)")
    out: dict[str, list[str]] = {}
    for block in raw.split("\x1e"):
        block = block.strip()
        if not block or "\x1f" not in block:
            continue
        sha, _, trailers = block.partition("\x1f")
        values = [t.strip() for t in trailers.split("\x1d") if t.strip()]
        if values:
            out[sha] = values
    return out


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout


def lockfile_commits(repo: Path, days: int) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
    raw = git(repo, "log", f"--since={since}", "--name-only", "--format=%x1e%H%x1f%an%x1f%ae%x1f%aI")
    out = []
    for block in raw.split("\x1e"):
        block = block.strip()
        if not block:
            continue
        head, _, files = block.partition("\n")
        sha, name, email, when = head.split("\x1f")
        touched = [f for f in files.splitlines() if DEP_FILES.search(f.strip())]
        if touched:
            out.append({"sha": sha, "author": name, "email": email, "date": when, "files": touched})
    return out


def npm_versions_introduced(repo: Path, sha: str) -> list[tuple[str, str]]:
    diff = git(repo, "show", "--format=", "--", sha, "--", "package-lock.json", "npm-shrinkwrap.json") if False else \
        subprocess.run(["git", "show", "--format=", sha, "--", "package-lock.json", "npm-shrinkwrap.json"],
                       cwd=repo, capture_output=True, text=True).stdout
    found = []
    pending = None
    for line in diff.splitlines():
        m = NPM_LOCK_VERSION.match(line)
        if m:
            pending = m.group(1)
            continue
        m = NPM_VERSION_LINE.match(line)
        if m and pending:
            found.append((pending, m.group(1)))
            pending = None
    return found


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", default=".")
    p.add_argument("--days", type=int, default=90)
    p.add_argument("--bot-pattern", action="append", default=[])
    p.add_argument("--agent-pattern", action="append", default=[])
    p.add_argument("--check-provenance", action="store_true", help="query npm attestations for versions non-humans introduced")
    p.add_argument("--max-provenance", type=int, default=200)
    p.add_argument("--audit", type=int, default=0, metavar="N",
                   help="print a random sample of N classified commits to check by hand")
    p.add_argument("--seed", type=int, default=7, help="seed for the --audit sample")
    p.add_argument("--out", help="CSV of every dependency commit with its classification")
    args = p.parse_args(argv)

    repo = Path(args.repo).resolve()
    bot_re = re.compile("|".join(BOT_PATTERNS + args.bot_pattern), re.I)
    agent_re = re.compile("|".join(AGENT_PATTERNS + args.agent_pattern), re.I)
    commits = lockfile_commits(repo, args.days)
    trailers = coauthor_trailers(repo, args.days)
    for c in commits:
        c["coauthors"] = trailers.get(c["sha"], [])
        c["actor_type"] = classify(c["author"], c["email"], bot_re, agent_re, c["coauthors"])

    total = len(commits)
    by_type = Counter(c["actor_type"] for c in commits)
    non_human = by_type["bot"] + by_type["agent"]
    authors = Counter(c["author"] for c in commits if c["actor_type"] != "human")

    print(f"repository: {repo}")
    print(f"window: last {args.days} days")
    print(f"dependency commits: {total}  human {by_type['human']}  bot {by_type['bot']}  agent {by_type['agent']}")
    share = (non_human / total * 100) if total else 0.0
    print(f"non-human dependency change share: {non_human}/{total} = {share:.1f}% "
          f"(lower bound; agents committing as a developer with no trailer count as human)")
    if authors:
        print("non-human authors: " + ", ".join(f"{a} ({n})" for a, n in authors.most_common()))
    if args.audit and commits:
        import random
        sample = random.Random(args.seed).sample(commits, min(args.audit, len(commits)))
        print(f"\naudit sample ({len(sample)} commits, seed {args.seed}): mark each wrong classification")
        for c in sample:
            co = f"  co-authors: {'; '.join(c['coauthors'])}" if c["coauthors"] else ""
            print(f"  {c['sha'][:10]}  {c['actor_type']:6s}  {c['author']} <{c['email']}>{co}")
        print("report the share with the audited error rate: wrong / sampled")

    if args.check_provenance:
        from verify.authorities.attestation import check
        versions = []
        for c in commits:
            if c["actor_type"] == "human":
                continue
            versions.extend(npm_versions_introduced(repo, c["sha"]))
        versions = list(dict.fromkeys(versions))[: args.max_provenance]
        attested = 0
        for name, ver in versions:
            r = check("npm", name, ver)
            attested += int(r.present)
        cov = (attested / len(versions) * 100) if versions else 0.0
        print(f"provenance coverage (npm, non-human introduced): {attested}/{len(versions)} = {cov:.1f}%")

    if args.out:
        with open(args.out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["sha", "date", "author", "email", "coauthors", "actor_type", "files"])
            w.writeheader()
            for c in commits:
                w.writerow({**{k: c[k] for k in ("sha", "date", "author", "email", "actor_type")},
                            "coauthors": ";".join(c["coauthors"]), "files": ";".join(c["files"])})
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
