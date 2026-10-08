"""Pull a package's chosen and prior versions out of a lockfile diff.

The diff is the one thing about a PR the verifier reads. The package name
comes from the organization's alert record or from the pipeline, never from
the PR text. Supported: package-lock.json / npm-shrinkwrap.json,
requirements*.txt, poetry.lock, uv.lock. yarn.lock and pnpm-lock.yaml report
the package as touched (see lockfile_policy) but need a manifest diff for the
exact version; pass --version explicitly for those.

Diff shape matters: in a real dependency-bot diff the package's key line
("node_modules/<name>": { or name = "<name>") is usually an unchanged context
line, and only the version and resolved lines below it carry + or -. The
parsers therefore track the current package from any line, whatever its
prefix, and attribute changed version lines to it.
"""
from __future__ import annotations

import re

from .versions import normalize_name

_NPM_KEY = re.compile(r'^[ +-]\s*"node_modules/((?:@[^/"]+/)?[^/"]+)"\s*:')
_NPM_VERSION = re.compile(r'^([+-])\s*"version"\s*:\s*"([^"]+)"')
_REQ = re.compile(r"^([+-])\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9.+!*-]+)")
_TOML_NAME = re.compile(r'^[ +-]\s*name\s*=\s*"([^"]+)"')
_TOML_VERSION = re.compile(r'^([+-])\s*version\s*=\s*"([^"]+)"')


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def versions_for(diff_text: str, package: str, ecosystem: str) -> tuple[str | None, str | None]:
    """Return (prior_version, chosen_version) for `package`, or Nones."""
    target = normalize_name(ecosystem, package)
    prior: str | None = None
    chosen: str | None = None
    base = ""
    current_pkg: str | None = None
    for raw in diff_text.splitlines():
        if raw.startswith("+++ ") or raw.startswith("--- "):
            base = _basename(raw[4:].strip())
            current_pkg = None
            continue
        if raw.startswith("@@"):
            current_pkg = None
            continue
        if base in ("package-lock.json", "npm-shrinkwrap.json"):
            m = _NPM_KEY.match(raw)
            if m:
                current_pkg = normalize_name(ecosystem, m.group(1))
                continue
            m = _NPM_VERSION.match(raw)
            if m and current_pkg == target:
                if m.group(1) == "+":
                    chosen = chosen or m.group(2)
                else:
                    prior = prior or m.group(2)
        elif base.startswith("requirements") or base.endswith(".txt"):
            m = _REQ.match(raw)
            if m and normalize_name(ecosystem, m.group(2)) == target:
                if m.group(1) == "+":
                    chosen = chosen or m.group(3)
                else:
                    prior = prior or m.group(3)
        elif base in ("poetry.lock", "uv.lock"):
            m = _TOML_NAME.match(raw)
            if m:
                current_pkg = normalize_name(ecosystem, m.group(1))
                continue
            m = _TOML_VERSION.match(raw)
            if m and current_pkg == target:
                if m.group(1) == "+":
                    chosen = chosen or m.group(2)
                else:
                    prior = prior or m.group(2)
    return prior, chosen


def packages_in_diff(diff_text: str, ecosystem: str) -> set[str]:
    """Names whose entries gained an added line, for intersecting with alert records."""
    found: set[str] = set()
    base = ""
    current_pkg: str | None = None
    for raw in diff_text.splitlines():
        if raw.startswith("+++ ") or raw.startswith("--- "):
            base = _basename(raw[4:].strip())
            current_pkg = None
            continue
        if raw.startswith("@@"):
            current_pkg = None
            continue
        if base in ("package-lock.json", "npm-shrinkwrap.json"):
            m = _NPM_KEY.match(raw)
            if m:
                current_pkg = m.group(1)
                if raw.startswith("+"):
                    found.add(current_pkg)
                continue
            if raw.startswith("+") and current_pkg:
                found.add(current_pkg)
        elif base.startswith("requirements") or base.endswith(".txt"):
            m = _REQ.match(raw)
            if m and m.group(1) == "+":
                found.add(m.group(2))
        elif base in ("poetry.lock", "uv.lock"):
            m = _TOML_NAME.match(raw)
            if m:
                current_pkg = m.group(1)
                if raw.startswith("+"):
                    found.add(current_pkg)
                continue
            if raw.startswith("+") and current_pkg:
                found.add(current_pkg)
    return found
