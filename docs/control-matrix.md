# Control matrix: writable input, unwritable counterpart, residual

One row per remediation-context channel. The left column is what the agent reads and an attacker can write. The middle column is what the verifier uses instead. The right column is the gap that remains, said out loud.

| Channel (attacker-writable) | Unwritable counterpart the verifier uses | Residual to admit |
| :--- | :--- | :--- |
| Advisory prose and community-edited ranges | Reviewed structured range fetched by advisory id | Unreviewed advisory records exist; reviewed status is curation, not a signature; OSV records are unsigned |
| Release notes and changelog surfaced in bot PRs | Registry provenance attestation (where the package attests) plus release-age cooldown | Provenance minted from compromised CI verifies origin, not intent; for a package that never attests, the cooldown is the only check here |
| Package README and registry metadata | Nothing; inform only, never authority | README injection success rates are high in published benchmarks |
| Third-party scanner output (SARIF) | A scanner the organization runs in its own pinned CI job | Requires owning the scanner job |
| VEX statements and SBOM fields from upstream | An SBOM the organization generates at build time | Upstream VEX is still an assertion by someone else |
| CI and test log text | Exit codes from pinned jobs, never log text | Any dependency can print to the log |

Prioritization context (runtime package-in-use, attack path, data sensitivity) decides how urgently a fix ships. It never decides which version, so it is not in this table.

The README's coverage table gives the other view: for each decision hijack, which authority catches it and how strong that is outside the lab.
