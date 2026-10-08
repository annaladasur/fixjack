# fixjack decision policy (OPA, Rego v1 syntax).
#
# Input is the facts object produced by verify/verdict.py plus "mode".
# Output is data.fixjack.result = {verdict, reasons, blocking, routing}.
# The Python engine in verify/verdict.py implements the same rules; keep both
# in sync and pin shared cases in tests/test_policy.py.

package fixjack

import rego.v1

mode := input.mode

# ---------------------------------------------------------------- reasons

reasons contains "chosen version inside affected range" if input.osv.in_affected

reasons contains "chosen version not in fixed set" if {
	not input.osv.no_authority
	not input.osv.in_affected
	not input.osv.is_fixed
}

# A missing attestation blocks only when the package's latest release is
# attested (a regression). A package that has never attested is reported;
# the reason is informational and carries no weight in the verdict.
reasons contains "no registry attestation" if {
	input.attestation.supported
	not input.attestation.present
	input.attestation.package_attests
	not attestation_lookup_failed
}

reasons contains "package publishes no attestations" if {
	input.attestation.supported
	not input.attestation.present
	not input.attestation.package_attests
	not attestation_lookup_failed
}

# A failed lookup is an unavailable authority (see "authority unavailable"),
# never evidence that the package publishes no attestations.
attestation_lookup_failed if {
	err := object.get(input.attestation, "error", null)
	err != null
	err != ""
}

reasons contains "cooldown not satisfied" if not input.cooldown.satisfied

reasons contains "registry host outside allowlist" if count(input.lockfile.disallowed_hosts) > 0

reasons contains "undeclared packages changed" if count(input.lockfile.undeclared_packages) > 0

reasons contains "downgrade outside fixed set" if {
	input.direction == "downgrade"
	not input.osv.no_authority
	not input.osv.is_fixed
}

reasons contains "downgrade with no reviewed advisory" if {
	input.direction == "downgrade"
	input.osv.no_authority
}

reasons contains "agent-authored suppression" if {
	input.is_suppression
	input.actor_type != "human"
}

reasons contains "authority unavailable" if count(input.errors) > 0

# ---------------------------------------------------------------- severity

always_block := {
	"chosen version inside affected range",
	"chosen version not in fixed set",
	"no registry attestation",
	"cooldown not satisfied",
	"registry host outside allowlist",
	"downgrade outside fixed set",
	"downgrade with no reviewed advisory",
}

escalating := {"undeclared packages changed", "agent-authored suppression"}

blocking contains r if {
	some r in reasons
	r in always_block
}

blocking contains r if {
	mode == "prevent"
	some r in reasons
	r in escalating
}

routing contains r if {
	mode != "prevent"
	some r in reasons
	r in escalating
}

# An authority that could not answer never fails open; a human decides.
routing contains "authority unavailable" if "authority unavailable" in reasons

# ---------------------------------------------------------------- verdict

verdict := "block" if count(blocking) > 0

verdict := "route_to_human" if {
	count(blocking) == 0
	count(routing) > 0
}

verdict := "allow" if {
	count(blocking) == 0
	count(routing) == 0
}

result := {
	"verdict": verdict,
	"reasons": reasons,
	"blocking": blocking,
	"routing": routing,
}
