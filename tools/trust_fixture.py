"""
The single evaluation trust context used by the 0.3.0-alpha vectors (TEST KEYS ONLY — public seeds).

    TRUST_STATE            canonical object; its hash is bound into d.trust_state_hash and p.trust_state_hash
    SCORING_PROFILE_V030   coverage-v0.3.0-alpha arithmetic; its hash is d.scoring_profile_hash

Ownership of rules (each rule has exactly one committing object):
    control profile   ManualOnly, Δτ_max, reusable authority classes          -> d.control_profile_hash
    scoring profile   Ω, T_base, T_base_manual, β, κ, gate, Γ, material types -> d.scoring_profile_hash
    trust state       key registry (all six domains, owners, epochs, scopes, authorised atom types),
                      revocations, atom registry + aliases, per-type caps, attester independence,
                      conflict types, clock authorities                        -> d.trust_state_hash
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reference"))
import prc_ref as R              # noqa: E402
import prc_scoring as S          # noqa: E402
import prc_coverage_v030 as C30  # noqa: E402
import coverage_v021_cases as V21  # noqa: E402  (atom registry and aliases carried forward)
import scoring_cases as J        # noqa: E402

EPOCH = "epoch-2026-01"
bits = J.bits

# --- keys (same seeds as earlier vector sets, plus the membership domain) -----------------
K_PROFILE = R.TestKey.derive("profile", "k1")
K_APPROVAL = R.TestKey.derive("approval", "k1")
K_DECISION = R.TestKey.derive("decision", "k1")
K_RECEIPT = R.TestKey.derive("receipt", "k1")
K_AUD, K_AUD_SRC, K_VENDOR_A, K_UNREG = V21.K_AUD, V21.K_AUD_SRC, V21.K_VENDOR_A, V21.K_UNREG
K_MEMB = R.TestKey.derive("membership", "ingest-gateway-1")        # scope F-*
K_MEMB_PARTNER = R.TestKey.derive("membership", "partner-gateway")  # scope F-partner-* only
K_MEMB_UNREG = R.TestKey.derive("membership", "not-registered")
AUD, AUD_SRC, VENDOR_A = V21.AUD, V21.AUD_SRC, V21.VENDOR_A
GATEWAY, PARTNER = "org:ingest-gateway", "org:partner-gateway"


def entry(key, owner, **extra):
    e = {"domain": key.domain, "public_key": key.public_hex, "epochs": [EPOCH], "owner": owner}
    e.update(extra)
    return e


CLOCK_IDEAL = "clk:test-ideal"      # zero uncertainty — keeps the pre-0.3.0 boundary vectors exact
CLOCK_PTP = "clk:exec-ptp"          # 1 ms
CLOCK_NTP = "clk:ntp-pool"          # 500 ms

TRUST_STATE = {
    "trust_state_id": "ts-2026-01",
    "schema_ver": R.SPEC_VERSION,
    "key_registry": {
        K_PROFILE.key_id: entry(K_PROFILE, "org:policy-office"),
        K_APPROVAL.key_id: entry(K_APPROVAL, "org:treasury-approvals", authority_classes=["STANDING", "SUPERVISOR"]),
        K_DECISION.key_id: entry(K_DECISION, "org:pdp"),
        K_RECEIPT.key_id: entry(K_RECEIPT, "org:executor"),
        K_AUD.key_id: entry(K_AUD, AUD, authorized_atom_types=sorted(S.DEPENDENCY_TYPES)),
        K_AUD_SRC.key_id: entry(K_AUD_SRC, AUD_SRC, authorized_atom_types=["SOURCE"]),
        K_VENDOR_A.key_id: entry(K_VENDOR_A, VENDOR_A, authorized_atom_types=sorted(S.DEPENDENCY_TYPES)),
        K_MEMB.key_id: entry(K_MEMB, GATEWAY, membership_scopes=["F-*"]),
        K_MEMB_PARTNER.key_id: entry(K_MEMB_PARTNER, PARTNER, membership_scopes=["F-partner-*"]),
    },
    "revoked_attestation_ids": [],
    "revoked_manifest_ids": [],
    "atom_registry": {"mode": "closed", "atoms": V21.REGISTERED, "aliases": V21.ALIASES},
    "max_atoms_per_type": V21.PROFILE["max_atoms_per_type"],
    "attester_independence_required": True,
    "conflict_types": ["AMOUNT_MISMATCH", "BENEFICIARY_NAME_MISMATCH", "SANCTIONS_HIT", "SOURCE_RETRACTION"],
    "clock_authorities": {
        CLOCK_IDEAL: {"max_uncertainty_us": 0},
        CLOCK_PTP: {"max_uncertainty_us": 1_000},
        CLOCK_NTP: {"max_uncertainty_us": 500_000},
    },
}
TRUST_STATE_HASH = R.H(TRUST_STATE)

SCORING_PROFILE_V030 = {
    "id": C30.PROFILE_ID,
    "status": "experimental",
    **C30.COMPONENTS,
    "material_dependency_types": J.PROFILE["material_dependency_types"],
    "omega_bits": bits(1.0), "t_base_bits": bits(0.5), "t_base_manual_bits": bits(0.5), "beta_bits": bits(0.2156),
    "kappa_unknown_bits": bits(0.5), "kappa_degraded_bits": bits(0.5), "unknown_gate_t_bits": bits(0.92),
    "consequence_gamma_bits": J.PROFILE["consequence_gamma_bits"],
}
SCORING_PROFILE_HASH = R.H(SCORING_PROFILE_V030)
