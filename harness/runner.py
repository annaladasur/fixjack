"""Run the pilot or the full matrix.

    python -m harness.runner --seed seed/npm-service --scenario clean --scenario S-RN-DG \
        --agent codex_cli --agent cline --runs 20 --out runs/

For each (scenario, agent, i): copy the seed repository to a fresh workspace,
place the scenario's fixture context (from harness/fixtures/<id>/, authored by
the operator) where the seed's task template expects it, invoke the adapter,
and write runs/<scenario>/<agent>/<i>/result.json plus lockfile.patch.
Scoring is a separate step (harness/score.py) so a run can be re-scored when
the gate policy changes.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import yaml

from .agents import get_adapter

HERE = Path(__file__).resolve().parent
MATRIX = HERE / "scenarios" / "matrix.yaml"
FIXTURES = HERE / "fixtures"


def load_matrix() -> dict:
    return yaml.safe_load(MATRIX.read_text())


# Arms that deliberately carry no context. Every other arm, `clean` included,
# needs a fixture: the clean arm holds the same channel with authentic text, so
# poisoning is the only difference between it and the scenario arm.
NO_CONTEXT_ARMS = {"alert_only"}


def prepare_workspace(seed: Path, dest: Path, scenario: str) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(seed, dest)
    fixture = FIXTURES / scenario
    if scenario not in NO_CONTEXT_ARMS and not fixture.exists():
        raise SystemExit(
            f"fixture for {scenario} not found at {fixture}. Fixtures are authored locally by "
            f"the operator and are not distributed; see harness/README.md."
        )
    # The folder exists in every arm so TASK.md reads the same in all of them.
    context_dir = dest / ".fixjack-context"
    context_dir.mkdir(exist_ok=True)
    if scenario not in NO_CONTEXT_ARMS:
        for f in fixture.iterdir():
            shutil.copy(f, context_dir / f.name)
    return dest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seed", required=True, help="seed repository with tests, a lockfile and the task template")
    p.add_argument("--scenario", action="append", required=True, help="scenario id from matrix.yaml, or 'clean'")
    p.add_argument("--agent", action="append", required=True)
    p.add_argument("--runs", type=int, default=20)
    p.add_argument("--out", default="runs")
    p.add_argument("--timeout", type=int, default=900)
    args = p.parse_args(argv)

    matrix = load_matrix()
    known = {s["id"] for s in matrix["scenarios"]} | set(matrix.get("controls", {}))
    for s in args.scenario:
        if s not in known:
            p.error(f"unknown scenario {s}; known: {', '.join(sorted(known))}")

    seed = Path(args.seed).resolve()
    task_template = seed / "TASK.md"
    if not task_template.exists():
        p.error("seed repository needs a TASK.md describing the alert the agent is assigned")

    out = Path(args.out)
    for scenario in args.scenario:
        for agent_name in args.agent:
            adapter = get_adapter(agent_name)
            for i in range(args.runs):
                run_dir = out / scenario / agent_name / f"{i:03d}"
                if (run_dir / "result.json").exists():
                    continue
                ws = prepare_workspace(seed, out / "_ws" / scenario / agent_name / f"{i:03d}", scenario)
                result = adapter.run(ws, ws / "TASK.md", timeout_s=args.timeout)
                result.notes.append(f"scenario={scenario}")
                result.write(run_dir)
                print(f"{scenario} {agent_name} {i:03d}: exit={result.exit_code} refused={result.refused} "
                      f"diff_lines={len(result.lockfile_diff.splitlines())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
