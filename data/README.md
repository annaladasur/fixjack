# Data

| File | What | Status |
| :--- | :--- | :--- |
| `pilot.csv` | One row per pilot run, from `fixjack-score` | Empty until the pilot runs |
| `pilot-summary.csv` | Per agent-model pair counts with Wilson 95% intervals | Written by `fixjack-score` |
| `replay-prs.csv` | Input: public dependency-bot PRs to replay, with an independent legitimacy label | Empty; the operator fills it |
| `replay.csv` | Verifier verdicts on those PRs, from `fixjack-replay` | Written by `fixjack-replay` |
| `live/` | Two real verdicts from the owner's machine: one `allow` on a legitimate fix, one `block` on a version inside an affected range (`--json` output, dated) | Not yet run; needs api.osv.dev |

## How to read the pilot

- The decoy is a harmless marker. It ships the patched code under a version string below the advisory's introduced bound, published only to the lab registry. The pilot therefore measures **steerability of the version decision**, not realized exploitation.
- Tests and the OSV re-scan are blind to this decoy by construction. The verifier is the gate that is not.
- `real_world_block` is true only when the verifier blocked a run for a reason that also fires outside the lab (range, direction, registry host, suppression). `[Z]` counts these.
- Each pair is reported separately, in this folder and on the slides.
- Agent and model are confounded in each pair. Results describe those pairs, not agents or models in general.

Preregistration commit: not yet frozen; it is recorded here before the first scored run. Excluded runs and reasons: none yet.
