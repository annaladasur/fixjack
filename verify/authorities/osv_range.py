"""Reviewed advisory range by id.

Fetches the OSV record for an advisory id and decides whether the chosen
version sits inside an affected range or inside the fixed set. For GHSA ids it
also asks the GitHub Advisory Database whether the record is reviewed;
unreviewed and malware-type records are not treated as authority.

Residual to admit on stage: reviewed status is curation by GitHub staff, not a
signature. OSV schema 1.9 has no record-level signature field.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx

from ..versions import compare, normalize_name, osv_ecosystem

OSV_URL = "https://api.osv.dev/v1/vulns/{id}"
# The global advisory database is public and lives on github.com even for
# GitHub Enterprise Server users, so this lookup does not follow FIXJACK_GITHUB_API.
GH_ADVISORY_URL = "https://api.github.com/advisories/{id}"


@dataclass
class RangeResult:
    advisory_id: str
    reviewed: bool | None            # None when not a GHSA id or status unknown
    in_affected: bool
    is_fixed: bool
    fixed_versions: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    package_matched: bool = False
    detail: str = ""
    error: str | None = None


def fetch_osv(advisory_id: str, timeout: float = 20.0) -> dict:
    with httpx.Client(timeout=timeout) as client:
        resp = client.get(OSV_URL.format(id=advisory_id))
        resp.raise_for_status()
        return resp.json()


def reviewed_status(advisory_id: str, timeout: float = 20.0) -> bool | None:
    """True if the GitHub Advisory Database lists the GHSA as 'reviewed'."""
    if not advisory_id.upper().startswith("GHSA-"):
        return None
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(timeout=timeout, headers=headers) as client:
        resp = client.get(GH_ADVISORY_URL.format(id=advisory_id))
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json().get("type") == "reviewed"


def _intervals(events: list[dict]) -> list[tuple[str, str | None, bool]]:
    """Turn OSV range events into (introduced, bound, inclusive) intervals."""
    out: list[tuple[str, str | None, bool]] = []
    introduced: str | None = None
    for ev in events:
        if "introduced" in ev:
            if introduced is not None:
                out.append((introduced, None, False))
            introduced = ev["introduced"]
        elif "fixed" in ev and introduced is not None:
            out.append((introduced, ev["fixed"], False))
            introduced = None
        elif "last_affected" in ev and introduced is not None:
            out.append((introduced, ev["last_affected"], True))
            introduced = None
    if introduced is not None:
        out.append((introduced, None, False))
    return out


def evaluate_record(record: dict, ecosystem: str, package: str, version: str) -> RangeResult:
    eco = osv_ecosystem(ecosystem)
    target = normalize_name(ecosystem, package)
    result = RangeResult(
        advisory_id=record.get("id", ""),
        reviewed=None,
        in_affected=False,
        is_fixed=False,
        aliases=list(record.get("aliases", [])),
    )
    fixed: list[str] = []
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "") != eco:
            continue
        if normalize_name(ecosystem, pkg.get("name", "")) != target:
            continue
        result.package_matched = True
        if version in aff.get("versions", []):
            result.in_affected = True
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for introduced, bound, inclusive in _intervals(rng.get("events", [])):
                if bound and not inclusive:
                    fixed.append(bound)
                try:
                    lower_ok = introduced == "0" or compare(ecosystem, version, introduced) >= 0
                    if bound is None:
                        upper_ok = True
                    elif inclusive:
                        upper_ok = compare(ecosystem, version, bound) <= 0
                    else:
                        upper_ok = compare(ecosystem, version, bound) < 0
                except ValueError as exc:
                    result.error = f"version parse: {exc}"
                    continue
                if lower_ok and upper_ok:
                    result.in_affected = True
    result.fixed_versions = sorted(set(fixed), key=lambda v: _sort_key(ecosystem, v))
    if result.package_matched and not result.in_affected:
        try:
            result.is_fixed = any(compare(ecosystem, version, f) >= 0 for f in result.fixed_versions)
        except ValueError as exc:
            result.error = f"version parse: {exc}"
    if not result.package_matched:
        result.detail = f"{record.get('id')} does not list {package} ({eco})"
    elif result.in_affected:
        result.detail = f"{version} is inside the affected range of {record.get('id')}"
    elif result.is_fixed:
        result.detail = f"{version} is at or beyond a fixed version of {record.get('id')}"
    else:
        result.detail = f"{version} is outside the affected range but no fixed boundary confirms it"
    return result


def _sort_key(ecosystem: str, v: str):
    from functools import cmp_to_key
    return cmp_to_key(lambda a, b: compare(ecosystem, a, b))(v)


def check(advisory_id: str, ecosystem: str, package: str, version: str) -> RangeResult:
    try:
        record = fetch_osv(advisory_id)
    except httpx.HTTPError as exc:
        return RangeResult(advisory_id, None, False, False, error=f"osv fetch: {exc}",
                           detail="advisory record unavailable")
    result = evaluate_record(record, ecosystem, package, version)
    try:
        result.reviewed = reviewed_status(advisory_id)
    except httpx.HTTPError as exc:
        result.error = (result.error or "") + f" reviewed-status: {exc}"
    return result
