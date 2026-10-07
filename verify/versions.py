"""Version comparison for the ecosystems the verifier supports.

npm uses semver 2.0.0 (a small parser here, no dependency). PyPI uses PEP 440
through `packaging`. Anything the parser rejects is treated as an error by the
caller, never as "fine".
"""
from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)

OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "pip": "PyPI"}


def osv_ecosystem(ecosystem: str) -> str:
    try:
        return OSV_ECOSYSTEM[ecosystem.lower()]
    except KeyError as exc:
        raise ValueError(f"unsupported ecosystem: {ecosystem}") from exc


def _pre_part(part: str) -> tuple[int, int | str]:
    return (0, int(part)) if part.isdigit() else (1, part)


def parse_npm(version: str) -> tuple[int, int, int, tuple | None]:
    match = _SEMVER.match(version.strip())
    if not match:
        raise ValueError(f"not semver: {version!r}")
    major, minor, patch, pre = match.groups()
    pre_key = tuple(_pre_part(p) for p in pre.split(".")) if pre else None
    return int(major), int(minor), int(patch), pre_key


def compare(ecosystem: str, a: str, b: str) -> int:
    """Return -1, 0 or 1 as a is lower than, equal to, or higher than b."""
    if osv_ecosystem(ecosystem) == "npm":
        ka, kb = parse_npm(a), parse_npm(b)
        base = (ka[:3] > kb[:3]) - (ka[:3] < kb[:3])
        if base:
            return base
        if ka[3] is None and kb[3] is None:
            return 0
        if ka[3] is None:  # a release sorts after its own prereleases
            return 1
        if kb[3] is None:
            return -1
        return (ka[3] > kb[3]) - (ka[3] < kb[3])
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion as exc:
        raise ValueError(str(exc)) from exc
    return (va > vb) - (va < vb)


def direction(ecosystem: str, prior: str | None, chosen: str) -> str:
    """'upgrade', 'downgrade', 'same' or 'unknown' (no prior version)."""
    if not prior:
        return "unknown"
    cmp = compare(ecosystem, chosen, prior)
    return {1: "upgrade", -1: "downgrade", 0: "same"}[cmp]


def normalize_name(ecosystem: str, name: str) -> str:
    """PyPI names compare case-insensitively with - _ . folded; npm is exact."""
    if osv_ecosystem(ecosystem) == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name
