"""Release age against a cooldown, with a KEV exception that needs a human.

Dependabot's own three-day cooldown applies to version updates only; security
updates, the path remediation agents act on, are exempt by default. This gate
applies the cooldown to every non-human version choice and lets a KEV entry
plus an explicit human approval override it, because a three-day wait on a
known-exploited vulnerability is the wrong trade.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from ..versions import osv_ecosystem

NPM_METADATA = "https://registry.npmjs.org/{name}"
PYPI_RELEASE = "https://pypi.org/pypi/{name}/{version}/json"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache: dict[str, object] = {"fetched": 0.0, "ids": set()}


@dataclass
class CooldownResult:
    published_at: str | None
    age_days: float | None
    cooldown_days: int
    satisfied: bool
    kev: bool
    kev_exception_applied: bool
    detail: str = ""
    error: str | None = None


def publish_time(ecosystem: str, package: str, version: str, timeout: float = 20.0) -> datetime | None:
    eco = osv_ecosystem(ecosystem)
    with httpx.Client(timeout=timeout) as client:
        if eco == "npm":
            resp = client.get(NPM_METADATA.format(name=package))
            resp.raise_for_status()
            stamp = resp.json().get("time", {}).get(version)
        else:
            resp = client.get(PYPI_RELEASE.format(name=package, version=version))
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            urls = resp.json().get("urls", [])
            stamp = min((u.get("upload_time_iso_8601") for u in urls if u.get("upload_time_iso_8601")), default=None)
    if not stamp:
        return None
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def kev_ids(timeout: float = 30.0, max_age_seconds: int = 6 * 3600) -> set[str]:
    now = time.time()
    if now - float(_kev_cache["fetched"]) < max_age_seconds and _kev_cache["ids"]:
        return _kev_cache["ids"]  # type: ignore[return-value]
    with httpx.Client(timeout=timeout) as client:
        resp = client.get(os.environ.get("FIXJACK_KEV_FEED", KEV_FEED))
        resp.raise_for_status()
        ids = {v.get("cveID", "").upper() for v in resp.json().get("vulnerabilities", [])}
    _kev_cache.update(fetched=now, ids=ids)
    return ids


def evaluate(
    ecosystem: str,
    package: str,
    version: str,
    aliases: list[str],
    cooldown_days: int = 3,
    kev_human_approval: bool = False,
) -> CooldownResult:
    try:
        published = publish_time(ecosystem, package, version)
    except httpx.HTTPError as exc:
        return CooldownResult(None, None, cooldown_days, False, False, False,
                              detail="publish time unavailable", error=str(exc))
    if published is None:
        return CooldownResult(None, None, cooldown_days, False, False, False,
                              detail=f"{package} {version} has no publish record on the registry")
    age = (datetime.now(timezone.utc) - published).total_seconds() / 86400.0
    try:
        in_kev = any(a.upper() in kev_ids() for a in aliases if a.upper().startswith("CVE-"))
    except httpx.HTTPError:
        in_kev = False
    exception = in_kev and kev_human_approval
    satisfied = age >= cooldown_days or exception
    detail = f"published {published.date().isoformat()}, {age:.1f} days old, cooldown {cooldown_days}d"
    if exception:
        detail += "; KEV exception applied with human approval"
    elif in_kev:
        detail += "; advisory is in KEV, a human may approve an exception"
    return CooldownResult(published.isoformat(), round(age, 2), cooldown_days, satisfied, in_kev, exception, detail)
