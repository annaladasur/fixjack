"""Authorities: the sources the verifier trusts to decide.

Each module answers one question from a source the PR author cannot write.
Each returns a small dataclass with a `detail` string so a block reason can be
read by a human without re-running anything.

osv_range        Is the chosen version inside the reviewed affected range for
                 the advisory id, or inside its fixed set?
attestation      Does the registry hold a provenance attestation for the chosen
                 version?
cooldown         How old is the chosen version, and does a KEV exception apply?
lockfile_policy  What did the lockfile diff change beyond the declared package,
                 and did any registry host change?
"""
