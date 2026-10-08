"""What the verifier is allowed to see.

Every field here comes from a source the PR author cannot write: the diff
itself, the organization's own alert records, and command-line flags set by
the pipeline. Nothing is parsed out of the PR title, body or comments.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx

GITHUB_API = "https://api.github.com"


def github_api() -> str:
    """The forge API used for alert lookups.

    On GitHub Enterprise Server set FIXJACK_GITHUB_API to https://<host>/api/v3;
    the GitHub workflow passes `github.api_url`, which is already right.
    """
    return (os.environ.get("FIXJACK_GITHUB_API") or GITHUB_API).rstrip("/")


def allowed_hosts_from_env() -> tuple[str, ...]:
    """FIXJACK_ALLOW_HOSTS: comma-separated registry hosts, e.g. an internal mirror.

    When set, it replaces the default allowlist, so list the public registries
    too if lockfiles still resolve from them.
    """
    raw = os.environ.get("FIXJACK_ALLOW_HOSTS", "")
    return tuple(h.strip().lower() for h in raw.split(",") if h.strip())


@dataclass
class Inputs:
    ecosystem: str                     # "npm" or "PyPI"
    package: str
    chosen_version: str
    lockfile_diff: str                 # unified diff text
    prior_version: str | None = None
    advisory_ids: list[str] = field(default_factory=list)
    kev_human_approval: bool = False   # a human approved a cooldown exception
    is_suppression: bool = False       # the change dismisses or suppresses an alert
    actor_type: str = "unknown"        # "human", "bot" or "agent"
    # Errors met while resolving advisory ids. A failed lookup is never the
    # same as "no open alert": it becomes an unavailable authority and routes
    # the change to a human.
    resolution_errors: list[str] = field(default_factory=list)
    allowed_hosts: tuple[str, ...] = (
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
    )


def advisories_from_dependabot(
    owner: str,
    repo: str,
    package: str,
    ecosystem: str,
    token: str | None = None,
    timeout: float = 20.0,
) -> list[str]:
    """Resolve advisory ids from the repository's own Dependabot alerts.

    This is the organization's record of what is open against the package,
    not anything the PR says. The token needs the "Dependabot alerts: read"
    permission; the default workflow GITHUB_TOKEN does not carry it, so use a
    fine-grained token or an app installation token in FIXJACK_ALERTS_TOKEN.
    """
    token = token or os.environ.get("FIXJACK_ALERTS_TOKEN") or os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{github_api()}/repos/{owner}/{repo}/dependabot/alerts"
    ids: list[str] = []
    page = 1
    with httpx.Client(timeout=timeout, headers=headers) as client:
        while True:
            resp = client.get(url, params={"state": "open", "per_page": 100, "page": page})
            resp.raise_for_status()
            alerts = resp.json()
            if not alerts:
                break
            for alert in alerts:
                dep = alert.get("dependency", {}).get("package", {})
                if dep.get("name", "").lower() != package.lower():
                    continue
                if dep.get("ecosystem", "").lower() not in (ecosystem.lower(), "pip" if ecosystem.lower() == "pypi" else ecosystem.lower()):
                    continue
                ghsa = alert.get("security_advisory", {}).get("ghsa_id")
                if ghsa and ghsa not in ids:
                    ids.append(ghsa)
            page += 1
    return ids


def resolve_advisories(
    owner: str,
    repo: str,
    package: str,
    ecosystem: str,
    token: str | None = None,
) -> tuple[list[str], str | None]:
    """Resolve advisory ids, capturing any failure instead of raising.

    Returns (ids, error). An under-scoped token, a network failure or an API
    error yields ([], "<reason>"), which the verifier treats as an
    unavailable authority (route to a human). Only a successful lookup that
    finds no open alert yields ([], None).
    """
    try:
        return advisories_from_dependabot(owner, repo, package, ecosystem, token), None
    except httpx.HTTPStatusError as exc:
        hint = ""
        if exc.response.status_code in (401, 403, 404):
            hint = " (check that FIXJACK_ALERTS_TOKEN has 'Dependabot alerts: read')"
        return [], f"alert lookup for {package} failed: HTTP {exc.response.status_code}{hint}"
    except httpx.HTTPError as exc:
        return [], f"alert lookup for {package} failed: {exc}"
