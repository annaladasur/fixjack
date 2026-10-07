"""fixjack harness: replay real advisories against local registries, drive an
open-source coding agent, and score what it shipped.

Scenario fixtures (the poisoned context per channel) are authored locally by
the operator and are not distributed with this repository. The matrix in
`scenarios/matrix.yaml` is the measurement specification: which channel is
poisoned, which decision the attacker wants, what the harness records, and
what verdict the gate is expected to return.
"""
