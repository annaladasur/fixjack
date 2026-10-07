# Failure modes: when this does not fit, and what not to do

## Where fixjack does not fit as is

| Situation | What happens | What to do |
| :--- | :--- | :--- |
| Ecosystems other than npm and PyPI (Maven, NuGet, Go, Cargo, RubyGems) | The verifier does not cover them. `fixjack-baseline` still counts their dependency commits. | Use Level 1 for the share. For enforcement, apply the same rule with your own tooling: range by advisory id, cooldown and a lockfile policy. Claim no provenance coverage you do not have. |
| Internal registry mirror | Lockfiles resolve from the mirror host, which the default allowlist rejects, so every PR is flagged as a registry swap | Set `FIXJACK_ALLOW_HOSTS` (README, "Enterprise setup"). Attestation and publish-time lookups still go to the public registry. |
| CI runners with no internet egress | OSV, the advisory database, the registry metadata and the KEV feed are unreachable, so every PR routes to a human | Allow egress to those hosts, or stay at Level 2 until you can. Vendor the fixjack wheel instead of installing from GitHub. |
| GitHub Enterprise Server | Alert lookups must go to your server | The workflow passes `github.api_url` as `FIXJACK_GITHUB_API`. The public advisory database is still read from api.github.com. |
| GitLab | There is no GitLab resolver: the job verifies only the package and advisory ids the pipeline passes it | Set `FIXJACK_PACKAGE` and `FIXJACK_ADVISORIES` from your vulnerability records, never from the MR |
| No lockfiles | There is nothing to diff | Fix that first |
| Vendored or monorepo dependencies | "Declared" means something repository-specific | Map what "declared" means for the repository before applying the default lockfile policy |
| An authority is down (OSV, registry, KEV feed) | At Level 3 and above, every dependency PR routes to a human until it recovers. The gate fails closed, never open. | Name an owner for the job and an alert for the outage. Do not answer an outage by switching to fail-open; that becomes the standing exception. A degraded mode with a local cache is planned. |
| Emergency fixes and severity SLAs | The default three-day cooldown applies to every non-human choice. The only exception today is KEV plus a human approval. Most Critical advisories are not in KEV, so a 72-hour Critical SLA will collide with the cooldown. | Lower `--cooldown-days` for the repositories or tiers that need it, with a human approving each change, and record why. Do not set it to zero globally. |
| Overrides | On GitHub, the practical override of a required check is an admin bypass, which records no reason | Until a label-based override lands, record every override and its reason in the worksheet by hand. Without them, the false-block rate cannot be computed. |
| A package adopted attestations after the fixed version was published | An older but fixed choice looks like a provenance regression and is blocked | Prefer the latest fixed version. If the team has a reason to stay older, the override records it (`decision-matrix.md`). |

## Do not do this

- Do not block on day one. You do not know your false-block rate yet, and developers route around a gate that blocks legitimate fixes.
- Do not make the verifier an LLM that reads the PR. It would read the same poisoned text it defends against.
- Do not treat a provenance attestation as proof of intent. Compromised CI mints valid attestations; provenance verifies build origin.
- Do not treat advisory prose or community-edited ranges as authority. Use the reviewed structured record by id, and admit that unreviewed records exist.
- Do not exempt security updates from the cooldown without a KEV-plus-human path. That exemption is the default today, and it is the path agents act on.
- Do not measure success as "PRs blocked". Measure the false-block rate and unsafe versions reaching main.
- Do not ban the agents. The goal is bounded autonomy with an authority channel, not less automation.
- Do not put the gate only in the agent's own workflow. Put it on branch protection, so no token can bypass it.
- Do not let a suppression be a one-line agent action. It needs a human, and a VEX statement you generated yourself.
- Do not claim more standards than the control implements. fixjack implements AISVS 1.0 9.3.7 and enforces 9.3.5 and 9.3.6 outside the agent. Its provenance check follows SLSA, and its lockfile checks follow SCVS.
