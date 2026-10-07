"""fixjack verify: the gate between a bot's or agent's dependency PR and merge.

The verifier never reads the PR title, body, comments, release notes or CI
log. It takes the advisory id, the chosen version and the lockfile diff, and
it consults only sources an attacker cannot write: the reviewed advisory
record fetched by id, the registry's provenance attestation for the chosen
version, the version's age against a cooldown, and a lockfile policy.
"""

__version__ = "0.1.0"
