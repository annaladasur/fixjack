from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

_REGISTRY: dict[str, type["Adapter"]] = {}


def register(cls: type["Adapter"]) -> type["Adapter"]:
    _REGISTRY[cls.name] = cls
    return cls


def get_adapter(name: str) -> "Adapter":
    try:
        return _REGISTRY[name]()
    except KeyError as exc:
        raise SystemExit(f"unknown agent {name!r}; known: {', '.join(sorted(_REGISTRY))}") from exc


@dataclass
class RunResult:
    agent: str
    model_id: str
    temperature: float | None
    started_at: float
    duration_s: float
    exit_code: int | None
    refused: bool                      # no lockfile change; score.py splits this into outcome classes
    lockfile_diff: str                 # unified diff of lockfiles after the run
    stdout_tail: str = ""
    notes: list[str] = field(default_factory=list)
    manifest_diff: str = ""            # unified diff of manifests (package.json, pyproject.toml, ...)
    changed_files: list[str] = field(default_factory=list)  # every path the agent changed, if the workspace is a git repo

    def write(self, run_dir: Path) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "result.json").write_text(json.dumps(asdict(self), indent=2))
        (run_dir / "lockfile.patch").write_text(self.lockfile_diff)


class Adapter:
    """Drive one agent on one workspace.

    Subclasses set `name`, `model_env` (the environment variable that names
    the model so it is logged, never guessed) and `command`, a template with
    {task_file} and {workspace} placeholders. The task file is the alert
    context the harness assembled for the scenario.
    """

    name = "base"
    model_env = "FIXJACK_MODEL"
    temperature_env = "FIXJACK_TEMPERATURE"
    command: str | None = None
    lockfiles = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "uv.lock")
    manifests = ("package.json", "pyproject.toml", "requirements.in", "setup.cfg", "Pipfile")

    def run(self, workspace: Path, task_file: Path, timeout_s: int = 900) -> RunResult:
        if not self.command:
            raise NotImplementedError(
                f"{self.name}: set `command` to the agent's non-interactive invocation "
                f"(see harness/README.md); nothing is assumed about a CLI's flags."
            )
        model = os.environ.get(self.model_env, "unset")
        temp = os.environ.get(self.temperature_env)
        before = self._snapshot(workspace, self.lockfiles)
        before_manifests = self._snapshot(workspace, self.manifests)
        cmd = shlex.split(self.command.format(task_file=task_file, workspace=workspace))
        started = time.time()
        try:
            proc = subprocess.run(cmd, cwd=workspace, capture_output=True, text=True, timeout=timeout_s)
            exit_code: int | None = proc.returncode
            tail = (proc.stdout or "")[-4000:]
        except subprocess.TimeoutExpired as exc:
            exit_code = None
            tail = (exc.stdout or b"")[-4000:].decode(errors="replace") if isinstance(exc.stdout, bytes) else str(exc.stdout or "")[-4000:]
        duration = time.time() - started
        diff = self._diff(workspace, before, self.lockfiles)
        return RunResult(
            agent=self.name, model_id=model, temperature=float(temp) if temp else None,
            started_at=started, duration_s=round(duration, 1), exit_code=exit_code,
            refused=not diff.strip(), lockfile_diff=diff, stdout_tail=tail,
            manifest_diff=self._diff(workspace, before_manifests, self.manifests),
            changed_files=self._changed_files(workspace),
        )

    def _snapshot(self, workspace: Path, files: tuple[str, ...]) -> dict[str, str]:
        return {f: (workspace / f).read_text() for f in files if (workspace / f).exists()}

    def _changed_files(self, workspace: Path) -> list[str]:
        proc = subprocess.run(["git", "status", "--porcelain"], cwd=workspace, capture_output=True, text=True)
        if proc.returncode != 0:
            return []
        return sorted(line[3:].strip() for line in proc.stdout.splitlines() if len(line) > 3)

    def _diff(self, workspace: Path, before: dict[str, str], files: tuple[str, ...]) -> str:
        proc = subprocess.run(["git", "diff", "--", *files], cwd=workspace, capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout
        # workspace is not a git repo: fall back to a unified diff of the snapshots
        import difflib
        out = []
        for lf, old in before.items():
            new = (workspace / lf).read_text() if (workspace / lf).exists() else ""
            if old != new:
                out.append("".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                                        fromfile=f"a/{lf}", tofile=f"b/{lf}")))
        return "".join(out)
