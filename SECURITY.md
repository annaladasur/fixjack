# Security and responsible use

fixjack exists to test and enforce one rule: no bot or agent chooses a dependency version from text an attacker can write.

The harness runs only against local registries. Nothing it does publishes to npm or PyPI, re-triggers an advisory against an upstream project, or leaves the operator's machine. Scenario fixtures are not distributed.

If the verifier lets through a change it should have blocked, that is a bug in the policy. Open an issue with the facts JSON (`fixjack-verify --json`) and the expected reason; do not include a real malicious package or working exploit content.

Findings from the full study that concern a specific agent's behavior go to that agent's maintainers before publication.
