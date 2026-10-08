# Decision matrix

What the verifier does with each signal at each adoption level. Implemented in `verify/policy/fixjack.rego` and mirrored in `verify/verdict.py`.

| Signal | Level 2 report-only | Level 3 validate | Level 4 prevent |
| :--- | :--- | :--- | :--- |
| Chosen version inside the reviewed affected range | Comment | Block | Block |
| Chosen version outside the range but not at or beyond a fixed boundary | Comment | Block | Block |
| No attestation for the chosen version while the package's latest release is attested (regression) | Comment | Block | Block |
| Package has never published attestations | Comment | Comment; counts against provenance coverage | Comment |
| Version younger than the cooldown | Comment | Block unless KEV and a human approved | Same |
| Lockfile diff introduces a registry host outside the allowlist | Comment | Block | Block |
| Lockfile diff touches packages not named in the advisory | Comment | Route to human | Block |
| Change dismisses or suppresses an alert, authored by a bot or agent | Comment | Route to human | Block |
| Downgrade to a version not in the fixed set | Comment | Block | Block |
| Downgrade with no reviewed advisory for the package | Comment | Block | Block |
| Downgrade to a version in the fixed set, with attestation | Allow | Allow | Allow, logged |
| An authority could not answer (OSV, registry, KEV feed down) | Comment | Route to human | Route to human |

Known false-block source: a package that adopted attestations after the fixed version was published (React's 19.1.0 is unattested while 19.3.0 is) makes an older-but-fixed choice look like a regression. For a security fix the latest fixed version is the right pick anyway; when a team has a reason to stay on the older one, the human override records why, and the false-block rate reports it.

Report-only computes the same verdict as validate and never fails the check; the comment shows exactly what validate would have done. Human overrides at Level 3 are recorded in the worksheet with a reason; the false-block rate is computed from them.
