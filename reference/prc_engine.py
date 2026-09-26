"""
prc_engine — base evaluation engine: input guard, then scoring-profile dispatch.

The guard runs *before* any profile code (proposed normative rule E-1):

    Every binary64 value that enters evaluation — every `*_bits` field of the scoring
    profile, every consequence Γ, and every `value_bits` of every evidence member
    (representative or optional) — MUST be finite. If any is NaN or ±Inf the engine
    returns DENY with SAFE_STATE_LOCK | NONFINITE_INPUT and does not invoke the profile.

This makes the fail-closed behaviour independent of how carefully a profile handles
exceptional values (jaccard-v0.1.0-alpha needed its own guard to stop exp(-Inf) = 0
from producing C = 1).
"""
from __future__ import annotations

import math
from typing import List

import prc_ref as R
import prc_scoring as S
import prc_coverage as COV
import prc_coverage_v021 as COV21
import prc_coverage_v030 as COV30

PROFILES = {S.PROFILE_ID: S.evaluate, COV.PROFILE_ID: COV.evaluate}
TRUST_AWARE = {COV21.PROFILE_ID: COV21.evaluate,   # profiles that take the provenance trust state
               COV30.PROFILE_ID: COV30.evaluate}


def _nonfinite(bits_hex: str) -> bool:
    x = S.f(bits_hex)
    return math.isnan(x) or math.isinf(x)


def nonfinite_inputs(families: List[dict], profile: dict) -> List[str]:
    """Return the location of every non-finite input, in a deterministic order."""
    bad = []
    for k in sorted(profile):
        if k.endswith("_bits") and isinstance(profile[k], str) and _nonfinite(profile[k]):
            bad.append(f"profile.{k}")
    for a in sorted(profile.get("consequence_gamma_bits", {})):
        if _nonfinite(profile["consequence_gamma_bits"][a]):
            bad.append(f"profile.consequence_gamma_bits.{a}")
    fams = [f for f in families if isinstance(f, dict)] if isinstance(families, list) else []
    for fam in sorted(fams, key=lambda x: str(x.get("family_id"))):
        mem = fam.get("members") if isinstance(fam.get("members"), list) else []
        for m in sorted(mem, key=lambda x: str(x.get("evidence_id")) if isinstance(x, dict) else ""):
            vb = m.get("value_bits") if isinstance(m, dict) else None
            if isinstance(vb, str) and len(vb) == 16 and all(ch in "0123456789abcdef" for ch in vb) and _nonfinite(vb):
                bad.append(f"{fam['family_id']}/{m['evidence_id']}.value_bits")
    return bad


def evaluate(request: dict, families: List[dict], profile: dict, trust: dict = None) -> dict:
    """Total evaluation boundary (V-1): for coverage-v0.3.0-alpha a fault inside the engine or
    profile is returned as DENY | SAFE_STATE_LOCK | VERIFIER_FAULT, never raised."""
    if profile.get("id") == COV30.PROFILE_ID:
        try:
            return _evaluate(request, families, profile, trust)
        except Exception as ex:  # noqa: BLE001
            reason = R.RC["SAFE_STATE_LOCK"] | R.RC["VERIFIER_FAULT"]
            return {"stage": "VERIFIER_FAULT", "scoring_profile": profile.get("id"), "fault": type(ex).__name__,
                    "M_bits": S.hx(0.0), "C_bits": S.hx(0.0), "T_bits": None, "safe_state_lock": True,
                    "decision": "DENY", "reason_bitfield": reason, "reason_codes": R.reason_names(reason)}
    return _evaluate(request, families, profile, trust)


def _evaluate(request: dict, families: List[dict], profile: dict, trust: dict = None) -> dict:
    bad = nonfinite_inputs(families, profile)
    if bad:
        reason = R.RC["SAFE_STATE_LOCK"] | R.RC["NONFINITE_INPUT"]
        return {
            "stage": "ENGINE_GUARD",
            "scoring_profile": profile.get("id"),
            "profile_fingerprint": R.H(profile),
            "action": request.get("action"),
            "nonfinite_inputs": bad,
            "M_bits": S.hx(0.0), "C_bits": S.hx(0.0), "T_bits": None,
            "safe_state_lock": True,
            "decision": "DENY",
            "reason_bitfield": reason,
            "reason_codes": R.reason_names(reason),
        }
    if profile.get("id") in TRUST_AWARE:
        return TRUST_AWARE[profile["id"]](request, families, profile, trust)
    fn = PROFILES.get(profile.get("id"))
    if fn is None:
        raise S.ProfileError(f"unknown scoring profile {profile.get('id')!r}")
    return fn(request, families, profile)
