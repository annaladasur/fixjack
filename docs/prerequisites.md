# Organizational prerequisites

What a team needs before each level. A change board will ask for this page.

| Need | Specifically |
| :--- | :--- |
| Data | 90 days of dependency PR history, lockfiles in git, advisory ids on your alerts |
| Network | Runner egress to api.osv.dev, api.github.com (the public advisory database), npm or PyPI metadata and attestation endpoints, and the CISA KEV feed. Your forge API for alert lookups. |
| Permissions | A token that can read your alert records (on GitHub, "Dependabot alerts: read"). For Level 3 and up: branch protection administration, required status checks, and the ability to stop agent tokens from bypassing checks. |
| Infrastructure | A CI runner and Python 3.10 or later. OPA is optional: the verifier uses it when `opa` is on PATH, and otherwise falls back to its Python engine. The two return the same verdicts, and the test suite checks that they agree. |
| Skills | CI/CD, policy as code, package ecosystem semantics (semver, lockfile formats), reading attestations |
| Integrations | GitHub or GitLab checks; ticketing for block events. Your existing SCA tool stays as it is. |
| Ownership | AppSec owns the policy. Platform or DevEx owns the job and its uptime. Developers own overrides and give a reason for each. Security operations owns the alerts for authority outages and, at Level 5, for replay failures. |
| Regulated environments | Verdict JSON and worksheet rows are change-management evidence. Keep them with the change records, for the same retention period. |
| Change management | Announce each level change with its exit criteria. A rollback is a policy change with an owner and an expiry, not a silent switch to fail-open. |
