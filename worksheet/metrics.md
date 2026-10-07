# Metrics

Defined before implementation. Every number the talk reports maps to one line here.

## Baseline (Level 1, Week 1)

| Metric | Definition |
| :--- | :--- |
| Non-human dependency change share | Lockfile or manifest commits by bots or agents divided by all such commits, last 90 days. `fixjack-baseline` computes it. |
| Auto-merge rate | Non-human dependency PRs merged with no human review event divided by all non-human dependency PRs. |
| Median time-to-merge, non-human PRs | The cost baseline the gate must not blow up. |
| Provenance coverage | Bot- or agent-chosen versions with a registry attestation divided by all such versions. `fixjack-baseline --check-provenance`. |
| Context surface inventory | For each bot or agent, the count of writable channels it reads (advisory prose, release notes, README and registry metadata, third-party SARIF, VEX and SBOM fields, CI output). |

## Control (Levels 2 to 4)

| Metric | Definition | Target |
| :--- | :--- | :--- |
| Verification rate | Non-human version decisions that passed through the verifier divided by all non-human version decisions. | 100% at Level 3 |
| Block rate and reason distribution | Blocks divided by verdicts, and the count per reason. | Reported, not targeted |
| False-block rate | Blocks a human overturned as legitimate divided by all blocks. | Under 5% at 90 days, under 2% at 180 |
| Human escalation rate | Verdicts routed to a human divided by all verdicts. | Reported |
| Time-to-merge delta | Median time-to-merge for non-human dependency PRs minus the baseline. | Under one business day at 90 days |

## Validation (Level 5)

| Metric | Definition | Target |
| :--- | :--- | :--- |
| Context poisoning success rate | Scenarios in the replayed matrix that ship the attacker's decision divided by scenarios run, before and after the gate. | 0 after, nightly |
| Policy bypass rate | Scenarios that pass the gate through a path the policy did not anticipate. | 0 |
| Unsafe action rate | Downgrades into the affected range, registry swaps and agent suppressions per 100 non-human PRs. | Reported |

## Outcome (90 and 180 days)

| Metric | Definition | Target |
| :--- | :--- | :--- |
| Unsafe versions reaching main | Count. | 0 |
| MTTR for real advisories | Must not regress against baseline; report it so the cost is visible. | No regression |

## Worksheet schema

`fixjack-verify --worksheet` appends rows with these columns:

`date, repo, pr_id, author_type, advisory_id, chosen_version, semver_relation_to_fix, attestation_present, age_days, verdict, reason, human_override, override_reason, time_to_merge_hours`

`human_override`, `override_reason` and `time_to_merge_hours` are filled in by the reviewing team; they are what the false-block rate and the time-to-merge delta are computed from.
