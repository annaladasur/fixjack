# One page: gating agent-chosen dependency versions

## The exposure
Bots and AI agents now change dependency versions in your repositories. They decide which version from advisory text, release notes, READMEs and CI logs. Every one of those inputs can be written by an attacker. Your gates check that the code compiles and that the version is not in a vulnerability database; they do not check where the version came from. In March 2026 a malicious release of a widely used package was picked up by dependency bots within five minutes; most of the resulting bot PRs were merged, a third of them by bots with no human involved.

## The number to ask for this week
Non-human dependency change share: of all dependency changes in the last 90 days, how many were authored by a bot or an agent, and what does each of them read. Most organizations do not know. It takes a week with git and a spreadsheet.

## The control
A separate verifier between the PR and merge that never reads the PR text. It confirms the chosen version from sources an attacker cannot write: the reviewed advisory record by id, the registry's provenance attestation where the package publishes one, the version's age, and a lockfile policy. It allows, blocks with a reason, or routes to a human. Deterministic where it decides. Vendor-neutral. Open source. The verifier covers npm and PyPI today. Level 1 measurement covers every ecosystem; provenance coverage is npm only.

## The path
Level 1, observe (week 1): measure the share and provenance coverage. Level 2, recommend (weeks 2 to 4): the verifier comments, nothing blocks. Level 3, validate (month 2): required check on one repository, human override with a reason. Level 4, prevent (month 3): no agent override. Level 5: replay the attack matrix nightly against the live gate.

## The metrics
Verification rate (target 100% at Level 3). False-block rate (under 5% at 90 days). Time-to-merge cost (under one business day). Poisoning success on the replayed matrix (0 after the gate). Unsafe versions reaching main (0).

## What it costs
A CI job, a policy engine, a token that can read your alert records, and one AppSec owner for the policy. No platform replacement. No new agents. The bots keep running; they stop being able to choose.
