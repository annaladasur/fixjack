"""What the lockfile diff changed, and whether any registry host moved.

Reads only the unified diff. Records every URL host introduced on an added
line, every package whose entry gained an added line, and which of those were
not declared as part of the fix. A transitive bump is expected on a
legitimate upgrade, so in validate mode undeclared packages route to a human
rather than block; a registry host outside the allowlist blocks at every
level above report-only.

The package's own key line is usually an unchanged context line in a real
dependency-bot diff, so the parser tracks the current package from any line
and attributes added lines beneath it to that package.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..versions import normalize_name

_URL = re.compile(r"https?://[^\s\"'<>)]+")
_NPM_LOCK_PKG = re.compile(r'^[ +-]\s*"node_modules/((?:@[^/"]+/)?[^/"]+)"\s*:')
_YARN_HEADER = re.compile(r'^[ +-]"?((?:@[^/@"]+/)?[^@/"\s]+)@[^:]*:\s*$')
_PNPM_PKG = re.compile(r"^[ +-]\s*/?((?:@[^/@\s]+/)?[^@/\s]+)@[\w.+-]+.*:\s*$")
_REQ_LINE = re.compile(r"^\+\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==|===|~=|>=|<=|!=|>|<)")
_TOML_NAME = re.compile(r'^[ +-]\s*name\s*=\s*"([^"]+)"')

LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
             "requirements", "poetry.lock", "uv.lock", "Pipfile.lock")


@dataclass
class LockfileResult:
    files: list[str] = field(default_factory=list)
    hosts_added: list[str] = field(default_factory=list)
    disallowed_hosts: list[str] = field(default_factory=list)
    packages_touched: list[str] = field(default_factory=list)
    undeclared_packages: list[str] = field(default_factory=list)
    detail: str = ""


def _key_regex(base: str):
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        return _NPM_LOCK_PKG
    if base == "yarn.lock":
        return _YARN_HEADER
    if base == "pnpm-lock.yaml":
        return _PNPM_PKG
    if base in ("poetry.lock", "uv.lock"):
        return _TOML_NAME
    return None


def evaluate(
    diff_text: str,
    ecosystem: str,
    declared: tuple[str, ...],
    allowed_hosts: tuple[str, ...],
) -> LockfileResult:
    result = LockfileResult()
    base = ""
    current_pkg: str | None = None
    hosts: set[str] = set()
    touched: set[str] = set()
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            base = path.rsplit("/", 1)[-1]
            current_pkg = None
            if path != "/dev/null" and path not in result.files:
                result.files.append(path)
            continue
        if raw.startswith("--- ") or raw.startswith("@@"):
            current_pkg = None
            continue
        key_re = _key_regex(base)
        if key_re:
            m = key_re.match(raw)
            if m:
                current_pkg = m.group(1)
                if raw.startswith("+"):
                    touched.add(current_pkg)
                continue
        if not raw.startswith("+"):
            continue
        for url in _URL.findall(raw):
            host = urlparse(url).hostname
            if host:
                hosts.add(host.lower())
        if key_re and current_pkg:
            touched.add(current_pkg)
        elif base.startswith("requirements") or base == "Pipfile.lock":
            m = _REQ_LINE.match(raw)
            if m:
                touched.add(m.group(1))
    result.hosts_added = sorted(hosts)
    allowed = {h.lower() for h in allowed_hosts}
    result.disallowed_hosts = sorted(h for h in hosts if h not in allowed)
    result.packages_touched = sorted(touched)
    declared_norm = {normalize_name(ecosystem, d) for d in declared}
    result.undeclared_packages = sorted(
        p for p in touched if normalize_name(ecosystem, p) not in declared_norm
    )
    parts = [f"{len(result.files)} lockfile(s)", f"{len(touched)} package(s) touched"]
    if result.disallowed_hosts:
        parts.append(f"registry host(s) outside allowlist: {', '.join(result.disallowed_hosts)}")
    if result.undeclared_packages:
        parts.append(f"undeclared: {', '.join(result.undeclared_packages[:8])}"
                     + (" ..." if len(result.undeclared_packages) > 8 else ""))
    result.detail = "; ".join(parts)
    return result
