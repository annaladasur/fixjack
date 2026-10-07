# fixjack

A merge gate that takes the dependency-version decision away from text an attacker can write. When a bot or AI agent picks the version for a vulnerability fix, fixjack re-derives that decision from sources the attacker cannot write, and blocks or routes to a human when they disagree.

Status:
- A working verifier: 85 tests pass locally with OPA installed, including the cases that check the Rego policy and the Python engine agree. `.github/workflows/test.yml` fails if any test is skipped.
- The Level 1 baseline tool, the measurement worksheet, the scenario matrix and the pilot harness, with a preregistration that is not yet frozen.
- A verifier-only replay of real bot PRs.
- No pilot or replay data yet. Results will land in `data/`.

Coverage: the verifier handles npm and PyPI today. Level 1 counts dependency changes in every ecosystem; provenance coverage is measured for npm only.

Built for the RSAC 2027 session "The Fix Is In: Rigging the AI Agents That Remediate Your CVEs".

## If you only have an hour

1. Read `docs/one-pager.md`.
2. Run `fixjack-baseline --repo <path> --days 90` on one repository. It reports how many dependency changes a bot or agent made (a lower bound).
3. Do Week 1 of `docs/checklist.md`.
4. Open a commitment in `CHALLENGE.md`.

## The problem

Teams assign a vulnerability alert to a bot or a coding agent. It reads the advisory, the release notes surfaced in the PR, the README and the CI log, picks a version, rewrites the lockfile and opens a PR. Tests pass. The scanner re-scan passes. A reviewer sees a routine bot PR. An attacker can write every one of the inputs that informed the version choice, and nothing in that pipeline asks where the version came from.

## The rule

The Write-Access Test: if an attacker can write it, it can inform the fix but never choose it.

Version, downgrade and suppression decisions draw authority only from sources the attacker cannot write. fixjack implements that as a separate verifier between the PR and merge. The verifier never reads the PR title, body, comments, release notes or CI log. It takes the advisory id, the chosen version and the lockfile diff, and it asks four authorities:

| Check | Authority | Residual to admit |
| :--- | :--- | :--- |
| Is the chosen version inside the reviewed affected range, or inside the fixed set? | The OSV record for the advisory id; GHSA reviewed status | Reviewed status is curation, not a signature; unreviewed records exist |
| Does the registry hold a provenance attestation for the chosen version? | npm attestations endpoint; PyPI PEP 740 integrity API (Sigstore). Blocks when the package's latest release is attested and the chosen one is not; a package that has never attested is reported and counts against provenance coverage | Provenance from compromised CI proves origin, not intent; most versions published before 2025 carry no attestation at all |
| Is the version old enough? | Registry publish time vs a cooldown; KEV exception needs a human | A cooldown can delay a real fix; the KEV path exists for that |
| What else did the lockfile change? | The diff itself: registry hosts, undeclared packages, direction | Transitive bumps are normal; they route to a human below prevent |

Provenance is enforced only where the package publishes it. For a package that has never attested, the second row reports and counts against coverage, and the other three authorities carry the decision.

## What it covers, and what it does not

fixjack removes attacker-writable text as the authority for the version decision. It is not a detector for malicious packages.

| Decision hijack | Authority that catches it | Real-world strength |
| :--- | :--- | :--- |
| Downgrade to a version outside the fixed set | OSV range by advisory id, plus direction | Deterministic |
| Upgrade into a version still inside the affected range | OSV range by advisory id | Deterministic, provided the advisory id resolves. A failed lookup routes to a human; it never allows. |
| Registry swap in the lockfile | Registry host allowlist | Deterministic |
| Suppress or dismiss the alert | Actor rule: a suppression by a bot or agent needs a human | Deterministic once the change is flagged as a suppression (`--suppression`). Detecting suppressions automatically is not built yet. |
| Upgrade to an attacker-published version beyond the fix | Cooldown, plus an attestation regression where the package attests | Partial. For a freshly published version with valid provenance, the cooldown is the only authority, and a KEV exception can lift it. |

The boundary in one sentence: fixjack does not by itself stop a maliciously published, semver-valid version of a package that does not attest once the cooldown has passed, or one whose provenance comes from a compromised CI system. Cooldown, the attestation regression and the undeclared-package check are partial mitigations for that class.

In the lab, the decoy exists only on the local registry. The cooldown and attestation checks therefore fire on it because it is missing from the public registry, not because of anything a real attacker's version would carry. The harness scores those blocks separately (`real_world_block` in `data/pilot.csv`).

## Standards

- OWASP AISVS 1.0 requirement 9.3.7 asks that external resources named in model output be verified against an approved registry before install. fixjack implements it for dependency versions.
- Requirements 9.3.5 and 9.3.6 ask that the agent keep untrusted-data processing apart from tool calls. fixjack does not change the agent. It enforces the same separation outside the agent, at merge.
- AISVS is an incubator project. Re-check these ids and their wording against the release current at the time of any talk.
- Provenance follows SLSA.
- Lockfile and package-source integrity follow OWASP SCVS.

## Quick start

```
pip install -e ".[dev]"
make test

fixjack-verify --ecosystem npm --package left-pad --version 1.3.0 --prior-version 1.2.0 \
    --advisory GHSA-xxxx-xxxx-xxxx --lockfile-diff pr.patch --mode validate
```

Output is a verdict (allow, block, route_to_human), the reasons, and every authority's detail line so a human can read a block without re-running anything. `--json` writes the full facts; `--worksheet` appends a measurement row.

In CI, use `.github/workflows/verify.yml` or `.gitlab-ci.yml`. The GitHub workflow resolves advisory ids from the repository's own Dependabot alerts and the package from the diff; the PR text is never an input. If the alert lookup fails, the verdict routes to a human; it never allows. The GitLab job verifies only the package and advisory ids the pipeline passes it.

## Enterprise setup

| Setting | When you need it |
| :--- | :--- |
| `FIXJACK_GITHUB_API` | GitHub Enterprise Server: `https://<host>/api/v3`. The workflow sets it from `github.api_url`. The public advisory database is still read from api.github.com. |
| `FIXJACK_ALLOW_HOSTS` | Internal registry mirror: a comma-separated host list. It replaces the default allowlist (`--allow-host` does the same per run). |
| `FIXJACK_ALERTS_TOKEN` | Always on GitHub: a token with "Dependabot alerts: read". The default `GITHUB_TOKEN` lacks it. |
| `FIXJACK_KEV_FEED` | A mirrored copy of the CISA KEV feed |
| Runner egress | api.osv.dev, api.github.com, the npm or PyPI metadata and attestation endpoints, and the KEV feed. An authority the runner cannot reach routes the PR to a human. |
| Install | Pin fixjack to a release commit, never a branch. With no egress, vendor the wheel. |

`docs/prerequisites.md` and `docs/failure-modes.md` cover the rest: GitLab, ecosystems without attestations, outages, SLA collisions with the cooldown, and overrides.

## Adoption ladder

| Level | What runs | `--mode` |
| :--- | :--- | :--- |
| 1 Observe | `fixjack-baseline` on your repositories: non-human dependency change share (a lower bound), provenance coverage | none |
| 2 Recommend | Verifier comments on every non-human dependency PR | `report-only` |
| 3 Validate | Required check; blocks on range, attestation, cooldown, registry swap; transitive bumps and suppressions route to a human | `validate` |
| 4 Prevent | Everything blocks; agent tokens cannot bypass branch protection | `prevent` |
| 5 Continuously validate | Nightly replay of `harness/scenarios/matrix.yaml` against the live gate | harness |

Start at Level 1 on Monday: `fixjack-baseline --repo . --days 90`.

## Layout

```
verify/       the gate: inputs, authorities, policy (Rego and a Python engine that must agree), verdict, CLI
harness/      scenario matrix, agent adapters, runner, scorer, bot-PR replay, local registries,
              preregistration and lock files (fixtures not distributed)
worksheet/    Level 1 baseline tool, metric definitions, worksheet schema
data/         pilot, replay and study results
docs/         the take-home kit (below), threats to validity, related work
```

| Kit file | Use it for |
| :--- | :--- |
| `docs/one-pager.md` | The page for a CISO or a change board |
| `docs/checklist.md` | Week 1 to Month 3, step by step, with commands |
| `docs/first-30-days.md` | The short version |
| `docs/prerequisites.md` | What a team needs before each level |
| `docs/decision-matrix.md` | What the verifier does with each signal at each level |
| `docs/control-matrix.md` | Each writable channel, its unwritable counterpart, and the residual |
| `docs/failure-modes.md` | Where it does not fit, and what not to do |
| `worksheet/metrics.md` | Metric definitions and the worksheet schema |
| `CHALLENGE.md` | The 30/90/180-day reports |

## Architecture note

The verifier is deterministic where it decides. The reference implementation is a CI job; an orchestrated deployment can wrap the same four checks as tools behind an A2A-compatible verifier agent whose only inputs are the advisory id, the version and the diff. If any LLM sits in that path, it explains a block; it never reads the writable channels and it never chooses.

## Related work

The Write-Access Test is the remediation-specific case of a known design rule: untrusted data may inform a decision but must not authorize it. Two strands of earlier work stand behind it:
- Indirect prompt injection framed the problem: data that acquires instruction authority.
- Capability-tracking designs separate a privileged planner from untrusted data.

Earlier work also shows that untrusted text can steer coding agents into vulnerable version pins. What fixjack adds is narrower:
- the security fix itself as the target;
- six remediation-specific channels;
- which existing gate misses each hijack;
- a deployable verifier, with its false-block rate measured on real bot PRs.

See `docs/related-work.md`.

`agent-trust-plane`, by the same author, is a different layer. It gates an agent's write actions on where the agent's context came from, using a taint ledger and a signed decision record. fixjack ignores the agent's process and judges only the outcome: what the chosen version is, according to external authorities. In short, the trust plane decides from where the context came from, and fixjack decides from what the version is. The two compose.

## What the harness measures

`harness/scenarios/matrix.yaml` names 24 scenarios (six attacker-writable channels, four decision hijacks) and the verdict the gate must return for each.

Each run records:
- the outcome class (patched, decoy, other version, manifest only, no change, timeout or crash);
- whether tests and an OSV re-scan passed;
- the verifier's verdict, and whether it blocked for a reason that also fires outside the lab.

Tests and the re-scan are blind to a harmless decoy by construction. The verifier is the gate that is not.

The pilot design, arms, outcomes and statistical test are fixed in `harness/PREREGISTRATION.md` before any scored run. `docs/threats-to-validity.md` states what the results can and cannot support.

## License

MIT. See `LICENSE`.
