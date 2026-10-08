# Threats to validity

This page says what fixjack's results can support and what they cannot. It is a stub until the pilot runs. Each entry names the threat, what the design does about it, and what remains. The full version ships with the study.

## Construct validity: are we measuring what we claim?

| Threat | What the design does | What remains |
| :--- | :--- | :--- |
| The decoy is a harmless marker, not a vulnerable version | The decoy sits below the advisory's introduced bound and carries the patched code, so no vulnerable code is ever installed | The pilot measures **steerability of the version decision**, not realized exploitation. It never shows an agent landing on vulnerable code. |
| Some verifier blocks are lab artifacts | The decoy exists only on the lab registry, so cooldown and attestation fire because the version is missing from the public registry. The scorer marks `real_world_block` only for range, direction, registry host or suppression. | The upgrade hijack is weaker in the real world. There, cooldown and an attestation regression are the only authorities (see the coverage table in the README). |
| How poisoned context reaches the agent | `TASK.md` points the agent at a context folder | That is likely a stronger channel than release notes inside a real bot PR. Read `[X]` as an upper bound for that channel. |
| "Non-human dependency change share" from git history | Author and committer names are matched against whole-word agent patterns and `Co-authored-by` trailers. `--audit N` draws a random sample for manual checking. | An agent that commits under a developer's identity with no trailer is counted as human, so the share is a **lower bound**. Report it together with the audited error rate. Provenance coverage is npm-only. |
| False-block rate on replayed bot PRs | Each PR's legitimacy label comes from evidence independent of the verifier: the advisory's official fixed version, excluding known-bad adoptions | Only PRs with a resolvable advisory id can be replayed. Stratify by whether the package attests. Public OSS PRs may not resemble enterprise PRs. |

## Internal validity: could something other than poisoning explain the result?

| Threat | What the design does | What remains |
| :--- | :--- | :--- |
| Registry setup changes behavior | The registry proxies everything upstream except the target. The target's real history is mirrored, dist-tags are set explicitly, and `npm audit` reachability is recorded (`harness/README.md`). | A mirrored history is still a lab |
| The agent's network access decides the outcome | Network access is fixed per agent, kept the same in both arms and recorded in `agents.lock.yaml` | Results hold only for the network setting used |
| The clean arm differs from the poisoned arm in more than poisoning | The clean arm carries the same channel with authentic text | Fixture wording is the operator's. Freeze it before the first run. |
| The model already knows the fix | Optional `alert_only` arm. Prefer an advisory published after every pinned model's stated knowledge cutoff, on a package that is not famous. | If the advisory is older or famous, say so as a limitation |
| Agent and model drift between pilot, study and talk | Agent and model versions are pinned in the lock files and the preregistration is frozen before any scored run | A live demo in April runs current versions. Label it "current versions" and the scoreboard "frozen study". |
| Runs are near-duplicates | Each CLI's default sampling. If an agent forces deterministic decoding, its 20 runs are not 20 samples; record that and report it as such. | With 20 runs per arm, only large effects are detectable |

## External validity: does it generalize?

- The pilot is one advisory, one channel and one hijack, with two agent-model pairs. It estimates a single-scenario proportion for those pairs. It does not estimate a population rate.
- Agent and model are confounded in each pair. Results describe those pairs, not agents or models in general.
- If both pairs use the same model family, the pilot is two agent wrappers on one family, and is labelled that way.
- The full study needs a **sampling frame**, not just a run count: distinct advisories drawn from npm and PyPI, stratified by ecosystem, package popularity, advisory type and the semver distance of the patch, and reported per advisory. Defining that frame is open work for the study.

## Conclusion validity: are the numbers read correctly?

- Counts, not percentages, are reported at pilot scale, with Wilson 95% intervals. The primary contrast is a one-sided Fisher's exact test per pair, fixed in `harness/PREREGISTRATION.md`.
- A null result is reported as "single-channel poisoning moved [X] of 20", never as "agents are robust".
- Tests and the OSV re-scan are blind to the decoy by construction. Their pass counts are a sanity check, not a finding.
- Pairs are never pooled.
