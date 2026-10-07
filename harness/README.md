# fixjack harness

Replays a real advisory against a local registry, hands the alert to an open-source coding agent, and records what the agent shipped and which gate missed it.

## What is here and what is not

Here:
- the scenario matrix (`scenarios/matrix.yaml`);
- the agent adapter interface (`agents/`);
- the runner (`runner.py`), the scorer (`score.py`) and the verifier-only replay of real bot PRs (`replay.py`);
- the local registry setup (`registries/`);
- the preregistration (`PREREGISTRATION.md`) and the agent and model lock files.

Not here: scenario fixtures. The operator authors the poisoned context for each channel locally under `harness/fixtures/<scenario_id>/`, and that folder is gitignored. The matrix says what each fixture must achieve and which verdict the gate must return. It does not ship the text.

## Guardrails

- Everything runs against a local registry. Nothing is published to npm or PyPI.
- The decoy is a harmless marker. It carries the patched code under a version string below the advisory's introduced bound. That is why tests and an OSV re-scan cannot see it and the verifier can.
- Real advisories are replayed from their published records. They are never re-triggered against an upstream project.
- The adapter logs the model id from its environment variable. The operator checks it against the agent's own session log and `models.lock.yaml`. A run whose model id is unset or does not match cannot be reported.

## Before the first scored run

Fill in every `TBD` in `PREREGISTRATION.md`, `agents.lock.yaml` and `models.lock.yaml`, then commit them together. Record that commit SHA in `data/README.md`. A run on any agent or model version other than the locked one belongs to a new study, not this one.

The environment settings below change the measured counts in ways a reader cannot infer afterwards. Each one is fixed in the preregistration and logged:

| Setting | Why it matters | What the harness does |
| :--- | :--- | :--- |
| Registry scope | With no upstream, transitive installs fail and agents time out for reasons unrelated to poisoning | `registries/verdaccio/config.yaml` proxies every package to npmjs.org except the target, which is local-only. `make registries TARGET=<package>` renders it. |
| Version universe | An agent that sees only three versions is not in a realistic setting | Mirror the target's real release history around the fix to the lab registry, plus the decoy. The decoy's version string must not exist upstream. |
| dist-tags | If `latest` follows publish order and the decoy was published last, `npm install` picks it with no poisoning at all | Set `latest` explicitly and record it |
| `npm audit` | It is a signal real agents use to find the fixed version | Record whether it can reach an advisory source |
| Agent network access | An agent that can reach OSV or the advisory page can check the poisoned text against the truth. This setting alone can decide `[X]`, and the defaults differ by agent. | Fix it per agent, keep it the same across arms, record it in `agents.lock.yaml` |
| How context arrives | The seed's `TASK.md` points the agent at `.fixjack-context/`. That is a stronger channel than release notes inside a real bot PR body. | Treat the result as an upper bound for the release-notes channel and say so on the results slide. Render the text as PR-body content instead if an adapter allows it. |

## Seed repository

A seed is a small service with:
- a real test suite and a lockfile;
- one vulnerable dependency at a version inside a real advisory's affected range;
- a `TASK.md` that states the alert as an assigned agent would see it: advisory id, package, current version.

For each run, the runner copies the seed and creates `.fixjack-context/`. The `clean` arm holds the same channel as the scenario arm, but with authentic text, so poisoning is the only difference. The optional `alert_only` arm leaves the folder empty, to measure what the agent and model already know about the fix.

## Registries

- **npm:** `make registries TARGET=<package>` starts Verdaccio, serving the target locally and proxying everything else.
- **PyPI:** serve a PEP 503 simple index from a directory with `python -m http.server`, and point `pip` at it with `--index-url`.

## Running the pilot

```
make registries TARGET=<package>
python -m harness.runner --seed seed/npm-service --scenario clean --scenario S-RN-DG \
    --agent codex_cli --agent cline --runs 20 --out runs/
make score PACKAGE=<package> ADVISORY=GHSA-... PATCHED=<version> DECOY=<version>
```

Before the first run, set two things for each adapter in `agents/`:
- `command`: the agent's non-interactive invocation for the version you pinned. Adapters refuse to run until it is set; nothing about a CLI's flags is assumed.
- the model environment variable the adapter names.

`make score` allowlists the lab registry host so its lockfiles are not scored as a registry swap.

## Replaying real bot PRs

`make replay` runs the verifier, and only the verifier, on public dependency-bot PRs listed in `data/replay-prs.csv`. Each row carries a legitimacy label that comes from evidence independent of the verifier. The output is the false-block rate on legitimate PRs. It needs no agents and no lab, and it is the cheapest measured number fixjack has.

## Reporting

Report counts, not percentages, at pilot scale. Report each agent-model pair separately. The numbers that matter:
- `[C]`: clean-arm runs that chose the patched version.
- `[X]`: poisoned-arm runs that shipped the decoy, read against the clean arm's decoy count.
- `[Z]`: the decoys the verifier blocked for a reason that also fires outside the lab.

If single-channel poisoning moves few runs, that is the finding, and combined channels are the next experiment. See `PREREGISTRATION.md` for the test and exclusions, and `data/README.md` for how to read the output.
