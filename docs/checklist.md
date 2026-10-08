# Implementation checklist

The path from "bots and agents choose dependency versions" to "they cannot choose one from text an attacker can write". Each step names the command or file that does it. Where no tool exists yet, the step says so.

## Week 1: observe (Level 1)

- [ ] List every bot and agent that can change a dependency manifest or lockfile: Dependabot, Renovate, assigned coding agents, SCA autofix, internal scripts.
- [ ] For each one, write down what it reads (the six channels in `control-matrix.md`) and whether it can auto-merge.
- [ ] Run `fixjack-baseline --repo <path> --days 90 --out baseline.csv`. It tags each dependency commit as human, bot or agent and reports the non-human change share.
  - The share is a lower bound: an agent that commits under a developer's identity with no `Co-authored-by` trailer counts as human.
  - Add `--audit 20` and check the sampled rows by hand to get an error rate.
- [ ] Add `--check-provenance` to measure provenance coverage. Coverage is npm only today.
- [ ] Put the last 50 non-human dependency PRs in a CSV with the columns of `data/replay-prs.csv`, then run `fixjack-replay --prs <file> --out replay.csv`. Take the advisory ids from your own alert records, never from the PR. The output is what the verifier would have blocked, and why.
- [ ] Take the auto-merge rate and median time-to-merge from your forge's PR list. fixjack does not fetch these yet.

## Weeks 2 to 4: recommend (Level 2)

- [ ] Add `.github/workflows/verify.yml` (or `.gitlab-ci.yml`) to one repository with real bot traffic, with `FIXJACK_MODE=report-only`.
- [ ] Give the job a token with "Dependabot alerts: read" (`FIXJACK_ALERTS_TOKEN`). If the alert lookup fails, the job routes to a human; it never allows.
- [ ] On GitHub Enterprise Server or behind a registry mirror, set the variables listed under "Enterprise setup" in the README.
- [ ] Verdicts post as PR comments. Nothing blocks yet.
- [ ] Send block and route events to ticketing, so each one becomes a task with its reason.

## Month 2: validate (Level 3)

- [ ] Review every would-be block with the owning team. Compute the false-block rate (`worksheet/metrics.md`).
- [ ] Tune for your estate: internal registries, ecosystems without attestations, and the cooldown against your SLA tiers (see `failure-modes.md`).
- [ ] Assign owners: AppSec owns the policy, platform owns the job, developers own overrides and give a reason for each.
- [ ] Set `FIXJACK_MODE=validate` and make the job a required check on that one repository. It blocks on out-of-range versions, provenance regressions, cooldown and registry swaps. Transitive bumps and suppressions route to a human.

## Month 3: prevent and expand (Level 4)

- [ ] Compare the metrics to the Week 1 baseline.
- [ ] Set `FIXJACK_MODE=prevent` where the false-block rate allows it, and make sure no agent token can bypass branch protection.
- [ ] Expand to the repositories with the highest non-human change share.

## Later: continuously validate (Level 5)

- [ ] Replay `harness/scenarios/matrix.yaml` against the live gate on a schedule. Any scenario that passes is a bug in the policy. Today this needs agents and locally authored fixtures (`harness/README.md`). A replay of stored lockfile diffs that needs no agents is planned.
